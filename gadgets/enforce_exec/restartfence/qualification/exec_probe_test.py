#!/usr/bin/env python3
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
"""Host-only probe protocol tests: no BPF, root, namespaces, or VM required."""
import errno
import json
import pathlib
import subprocess
import sys
import unittest

PROBE = pathlib.Path(sys.argv.pop(1)).resolve()


class ProbeTest(unittest.TestCase):
    def run_probe(self, denied, allowed, commands):
        return subprocess.run(
            [str(PROBE), "serve", str(denied), str(allowed)],
            input=commands, text=True, capture_output=True, timeout=10,
            check=False,
        )

    def test_success_is_observed_for_each_path_and_batch(self):
        result = self.run_probe(PROBE, PROBE, "42 2\n43 1\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertGreater(records[0]["ready_pid"], 0)
        self.assertEqual(len(records), 7)
        for record, batch, sample, target in zip(
            records[1:], [42] * 4 + [43] * 2, [0, 0, 1, 1, 0, 0],
            ["denied", "allowed"] * 3,
        ):
            self.assertEqual((record["batch"], record["sample"], record["target"]),
                             (batch, sample, target))
            self.assertEqual((record["errno"], record["exit"], record["signal"]),
                             (0, 0, 0))
            self.assertGreaterEqual(record["end_ns"], record["start_ns"])

    def test_missing_target_reports_exact_enoent_not_shell_status(self):
        result = self.run_probe(PROBE.parent / "not-a-target", PROBE, "1 1\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(records[1]["errno"], errno.ENOENT)
        self.assertEqual(records[1]["exit"], 100)
        self.assertEqual(records[2]["errno"], 0)

    def test_nonzero_target_exit_is_infrastructure_failure(self):
        result = self.run_probe("/bin/false", PROBE, "1 1\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unexpected probe child status", result.stderr)

    def test_malformed_or_empty_batches_fail(self):
        for commands in ["1 0\n", "1 1000001\n", "broken\n", "1 1 extra\n"]:
            with self.subTest(commands=commands):
                self.assertEqual(self.run_probe(PROBE, PROBE, commands).returncode, 2)


if __name__ == "__main__":
    unittest.main()
