#!/usr/bin/env python3
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
"""Opt-in Docker/CLI regression; run only on a disposable BPF LSM host."""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=60, check=True).stdout.strip()


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ig", required=True, help="host ig binary built from this branch")
    parser.add_argument("--image", required=True, help="locally built enforce_exec gadget image")
    parser.add_argument("--runtime", default="runc", help="Docker runtime name (also recorded)")
    args = parser.parse_args()
    check(os.environ.get("IG_EXEC_KERNEL_TEST") == "1" and os.geteuid() == 0,
          "requires root and IG_EXEC_KERNEL_TEST=1 on a disposable host")
    print(run("uname", "-a"))
    print(run("docker", "version"))
    print("Docker runtime:", args.runtime)
    containers = []
    try:
        for _ in range(2):
            containers.append(run("docker", "run", "-d", "--runtime", args.runtime,
                                  "alpine:3.21", "sleep", "600"))
        target, control = containers
        # Copy before enforcement so a failed command cannot be confused with cp failing.
        for container in containers:
            run("docker", "exec", container, "cp", "/bin/busybox", "/tmp/busybox")
            run("docker", "exec", container, "cp", "/bin/busybox", "/runc")
        with tempfile.TemporaryDirectory(prefix="ig-bootstrap-") as directory:
            root = Path(directory)
            for revision, mode in enumerate(("audit", "enforce"), 1):
                policy = root / "policy.yaml"
                policy.write_text(f'''version: 1
binding:
  container:
    runtime: docker
    id: {target}
policy:
  mode: {mode}
  exec:
    default: deny
    rules:
      - name: system-binaries
        target:
          path: ["/bin/**", "/sbin/**", "/usr/bin/**", "/usr/sbin/**"]
        action: allow
''')
                output, errors = root / f"{mode}.jsonl", root / f"{mode}.stderr"
                with output.open("w") as stdout, errors.open("w") as stderr:
                    process = subprocess.Popen([
                        args.ig, "enforce-exec", args.image, "--runtimes=docker",
                        "--allow-enforcement", "--verify-image=false", "--pull=never",
                        f"--policy={policy}", f"--revision={revision}",
                    ], stdout=stdout, stderr=stderr)
                    try:
                        deadline = time.monotonic() + 30
                        while "bindings=1" not in errors.read_text():
                            check(process.poll() is None and time.monotonic() < deadline,
                                  "IG failed readiness:\n" + errors.read_text())
                            time.sleep(0.1)
                        run("docker", "exec", target, "ls", "/")
                        denied = subprocess.run(
                            ["docker", "exec", target, "/tmp/busybox", "echo", "workload-ok"],
                            capture_output=True, text=True, timeout=30)
                        if mode == "audit":
                            check(denied.returncode == 0 and "workload-ok" in denied.stdout,
                                  f"audit workload failed: {denied}")
                        else:
                            check(denied.returncode != 0 and "workload-ok" not in denied.stdout,
                                  f"enforce workload unexpectedly ran: {denied}")
                        # A workload-controlled runtime-looking filename gets no exemption.
                        spoof = subprocess.run(
                            ["docker", "exec", target, "/runc", "echo", "spoof-ok"],
                            capture_output=True, text=True, timeout=30)
                        check((spoof.returncode == 0 and "spoof-ok" in spoof.stdout)
                              if mode == "audit" else
                              (spoof.returncode != 0 and "spoof-ok" not in spoof.stdout),
                              f"unexpected runtime-name spoof result: {spoof}")
                        check(run("docker", "exec", control, "/tmp/busybox", "echo", "control-ok")
                              == "control-ok", "unbound control failed")
                        # Reports are asynchronous; require the actual workload verdict,
                        # not merely a bootstrap denial with the same exit status.
                        deadline = time.monotonic() + 5
                        while True:
                            events = []
                            for line in output.read_text().splitlines():
                                try:
                                    events.append(json.loads(line))
                                except json.JSONDecodeError:
                                    pass  # A concurrent final line may be incomplete.
                            workload = [e for e in events if e.get("path") == "/tmp/busybox"
                                        and e.get("deny") == 1
                                        and e.get("generation") == revision
                                        and e.get("mode") == revision]
                            if workload or time.monotonic() >= deadline:
                                break
                            time.sleep(0.1)
                        check(workload, f"missing {mode} workload verdict:\n{output.read_text()}")
                        # Keep every other denial visible. Do not assume /runc is the
                        # helper's only spelling, or that a path proves its identity.
                        other = [e for e in events if e.get("deny") == 1
                                 and e.get("path") != "/tmp/busybox"]
                        print(f"{mode}: other denials (possible bootstrap): {json.dumps(other)}")
                    finally:
                        if process.poll() is None:
                            process.send_signal(signal.SIGTERM)
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                            raise
                        print(errors.read_text())
                    check(process.returncode == 0, "IG did not shut down cleanly")
                check(run("docker", "exec", target, "/tmp/busybox", "echo", "released")
                      == "released", "enforcement remained after shutdown")
                print(f"PASS: {mode}, revision {revision}, release verified")
    finally:
        for container in containers:
            subprocess.run(["docker", "rm", "-f", container], timeout=30, check=True)


if __name__ == "__main__":
    main()
