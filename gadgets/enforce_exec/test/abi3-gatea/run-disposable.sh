#!/usr/bin/env bash
set -euo pipefail
# Log to a regular file, never a pipe: descendants may inherit stdout and BPF
# FDs after the runner exits. No reader may postpone the EXIT cleanup trap.
run_logged() {
  local log=$1
  shift
  timeout --signal=TERM --kill-after=10s 180s "$@" > "$log" 2>&1
}
# Unprivileged regression uses the exact launcher above and a harmless child.
# The Python subreaper owns/reaps the orphan, so the test leaves no process behind.
if [[ ${1:-} == --self-test-supervision ]]; then
  exec python3 - "$0" <<'PYTEST'
import ctypes
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
    raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
with tempfile.TemporaryDirectory(prefix="abi3-gatea-supervision-") as directory:
    root = pathlib.Path(directory)
    process = subprocess.Popen(["bash", sys.argv[1], "--supervision-test-worker", directory])
    child = None
    started = time.monotonic()
    try:
        status = process.wait(timeout=5)
        child = int((root / "child.pid").read_text())
        assert status == 42, f"runner status not preserved: {status}"
        assert (root / "cleanup").read_text() == "cleanup reached\n"
        deadline = time.monotonic() + 5
        while True:
            reaped, child_status = os.waitpid(child, os.WNOHANG)
            if reaped:
                child = None
                assert os.WIFSIGNALED(child_status), "child was not terminated"
                assert os.WTERMSIG(child_status) == signal.SIGTERM
                break
            assert time.monotonic() < deadline, "descendant cleanup did not terminate child"
            time.sleep(0.01)
        assert "failure after first child" in (root / "runner.log").read_text()
        print(f"PASS: early runner failure reached cleanup and descendant reaped in {time.monotonic()-started:.3f}s")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if child is None and (root / "child.pid").exists():
            # If the wait timed out, discover only the child of this owned fixture.
            candidate = int((root / "child.pid").read_text())
            try:
                waited, _ = os.waitpid(candidate, os.WNOHANG)
                if not waited:
                    child = candidate
            except ChildProcessError:
                pass
        if child is not None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
PYTEST
fi
if [[ ${1:-} == --supervision-test-worker ]]; then
  test_out=${2:?test directory required}
  test_cleanup() {
    local status=$?
    trap - EXIT
    kill -TERM "$(cat "$test_out/child.pid")"
    printf 'cleanup reached\n' > "$test_out/cleanup"
    exit "$status"
  }
  trap test_cleanup EXIT
  run_logged "$test_out/runner.log" bash -c '
    exec 9> "$1/inherited-fd"
    sleep 300 &
    echo $! > "$1/child.pid"
    echo "failure after first child"
    exit 42
  ' _ "$test_out"
  exit 1 # The deliberate failure above must exit through the cleanup trap.
fi
[[ ${IG_ABI3_GATE_A_DISPOSABLE:-} == 1 && $EUID == 0 ]] || {
  echo 'Refusing: disposable root host and IG_ABI3_GATE_A_DISPOSABLE=1 required' >&2; exit 2;
}
[[ $(uname -m) == x86_64 ]] || { echo 'amd64 fixture only' >&2; exit 2; }
here=$(cd -- "$(dirname -- "$0")" && pwd)
build=$(realpath -- "${1:?usage: run-disposable.sh BUILD_DIRECTORY NEW_EVIDENCE_DIRECTORY}")
out=$(realpath -m -- "${2:?new evidence directory required}")
[[ ! -e $out ]] || { echo 'Evidence directory must be new' >&2; exit 2; }
mkdir -p -- "$out"
# Refuse accidental unrelated-kernel proof. Diagnostic execution on other kernels
# must be an explicit separately-reviewed change, never silently qualified.
actual=$(sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1)
case "$actual" in
  12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b|759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51) ;;
  *) printf 'Unsupported BTF: %s\n' "$actual" | tee "$out/refused.txt"; exit 2 ;;
esac
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || { echo 'cgroup2 required' >&2; exit 2; }
# Require provisioned delegation. This fixture does not change ancestor controllers.
grep -qw pids /sys/fs/cgroup/cgroup.subtree_control || { echo 'Provision pids controller in disposable root cgroup first' >&2; exit 2; }
grep -qw bpf /sys/kernel/security/lsm || { echo 'BPF LSM required' >&2; exit 2; }
cg=$(mktemp -d /sys/fs/cgroup/ig-abi3-gatea.XXXXXXXX)
cleanup() {
  rc=$?
  trap - EXIT
  if [[ -d $cg ]]; then
    # This exact mktemp-created group is the only owned workload scope.
    if [[ -e $cg/cgroup.kill ]]; then echo 1 > "$cg/cgroup.kill"; fi
    for _ in {1..100}; do if rmdir -- "$cg" 2>/dev/null; then break; fi; sleep .05; done
    if [[ -d $cg ]]; then echo "CLEANUP FAILED $cg" | tee -a "$out/cleanup.log"; if (( rc == 0 )); then rc=1; fi;
    else echo "CGROUP_REMOVED $cg" >> "$out/cleanup.log"; fi
  fi
  if [[ -e $out/runner.log ]]; then
    if ! python3 "$here/cleanup-programs.py" "$out"; then
      if (( rc == 0 )); then rc=1; fi
    fi
  fi
  printf 'EXIT_STATUS %s\n' "$rc" >> "$out/cleanup.log"
  exit "$rc"
}
trap cleanup EXIT
{
  date -u --iso-8601=seconds
  uname -a
  printf 'BTF_SHA256 %s\n' "$actual"
  cat /sys/kernel/security/lsm
  sha256sum "$build/fixture.bpf.o" "$build/runner" "$here/fixture.bpf.c" "$here/fixture.h" "$here/runner.c" "$here/cleanup-programs.py"
  bpftool version
  printf 'CGROUP %s\n' "$cg"
} > "$out/identity.log"
# Only the new child enters the dedicated scope; controller/cleanup remain out.
run_logged "$out/runner.log" bash -c 'echo $$ > "$1/cgroup.procs"; exec "$2/runner" "$2/fixture.bpf.o" "$3" "$1"' _ "$cg" "$build" "$out"
