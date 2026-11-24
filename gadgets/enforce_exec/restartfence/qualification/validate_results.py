#!/usr/bin/env python3
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
"""Validate returned VM artifacts, distinguishing mutant kills from failures."""
import argparse
import json
import pathlib
import re

KERNELS = {
    "debian12": "6.1.0-54-amd64",
}
CASES = ["graceful", "sigkill", "partial-move", "abi-skew", "cgroup-exit",
         "selfexec", "thread-selfexec", "failed-selfexec", "uninstall",
         "load-failure", "nonce"]
KILLS = {
    "no-exit-arm": r"FAIL sigkill: (?:.*target=denied errno=0 want=1|live incarnation=[1-9][0-9]* want=0)",
    "no-nonce": r"FAIL nonce: unauthorized nonce changed live owner: live incarnation=[1-9][0-9]* want=0",
    "never-move": r"FAIL graceful: target=allowed errno=1 want=0 policy=0",
    "restart-lift": r"FAIL graceful: .*target=denied errno=0 want=1",
}


def validate(root, variant):
    manifest = json.loads((root / "run-manifest.json").read_text())
    assert manifest["distro"] in KERNELS, "unexpected distro"
    assert manifest["guest_uname_r"] == KERNELS[manifest["distro"]], "wrong kernel"
    assert manifest["accel"] == "kvm", "not KVM"
    assert manifest["timed_out"] == 0, "VM timed out"
    guest = root / "guest"
    log = (guest / "oracle.log").read_text()
    assert "SKIP" not in log, "SKIP is failure"
    code = int((guest / "oracle.exit").read_text())
    assert int((guest / "payload.exit").read_text()) == manifest["exit_code"], "payload exit mismatch"
    if variant != "baseline":
        assert variant in KILLS, "unknown mutant"
        assert manifest["exit_code"] == code == 1, "mutant failed outside behavioral oracle"
        match = re.search(KILLS[variant], log)
        assert match, f"not an expected {variant} kill: {log}"
        return {"variant": variant, "kernel": manifest["guest_uname_r"],
                "expected_mutant_failure": True, "assertion": match.group(0)}
    assert manifest["exit_code"] == code == 0, "nonzero baseline exit"
    assert log.splitlines() == [f"PASS {name}" for name in CASES], "missing/extra baseline result"
    total = 0
    coverage = 0
    for case in CASES:
        events = [json.loads(line) for line in (guest / case / "lifecycle.jsonl").read_text().splitlines()]
        retire = next((e["monotonic_ns"] for e in events if e["event"] == "uninstall-retired"), None)
        assert (retire is not None) == (case == "uninstall"), "unexpected retirement"
        covers = [e["value"] for e in events if e["event"] == "transition-coverage"]
        assert len(covers) == (8 if case == "partial-move" else 4), "missing transition observations"
        for c in covers:
            assert c["first_ns"] < c["action_start_ns"] <= c["action_end_ns"] < c["last_ns"], "no observed overlap"
            assert c["samples"] >= 400, "insufficient transition observations"
        coverage += len(covers)
        assert sum(e["event"] == "outage-counters-attested" for e in events) == 1, "counter assertion absent"
        for index in range(4):
            rows = [json.loads(line) for line in (guest / case / f"probe-{index}.jsonl").read_text().splitlines()]
            assert rows[0]["ready_pid"] > 0, "probe never ready"
            assert len(rows) >= 601, "insufficient observations"
            for row in rows[1:]:
                assert row["start_ns"] <= row["end_ns"] and row["signal"] == 0, "invalid observation"
                assert row["errno"] in (0, 1), "unexpected errno"
                assert row["exit"] == (100 if row["errno"] else 0), "observation failure"
                if index == 3:
                    assert row["errno"] == 0, "Audit blocked"
                elif row["target"] == "denied" and row["errno"] == 0:
                    assert retire is not None and row["start_ns"] > retire, "denied exec succeeded before uninstall"
                total += 1
    return {"variant": variant, "kernel": manifest["guest_uname_r"], "cases_passed": len(CASES),
            "observations": total, "transition_coverage_records": coverage,
            "unexpected_denied_successes": 0, "audit_blocks": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("row", type=pathlib.Path)
    parser.add_argument("--variant", default="baseline", choices=["baseline", *KILLS])
    args = parser.parse_args()
    print(json.dumps(validate(args.row, args.variant), indent=2))
