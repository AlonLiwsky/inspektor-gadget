#!/usr/bin/env python3
"""Pure host formatter regression. No BPF calls or runner execution."""
import json
import subprocess
import sys
raw = subprocess.check_output([sys.argv[1]], text=True)
record = json.loads(raw)
fields = '''inventory prefix_missing history_unknown inflight allocs births errors
serial writers retained next_cookie frees failed unowned enabled barrier
initial_started initial_done inventory_serial inventory_generation refusals
refusal_serial refusal_inventory refusal_barrier strict_ready held diagnostic_task
diagnostic_nonce diagnostic_enter diagnostic_exit diagnostic_timeout
diagnostic_release diagnostic_cpu admin_cpu diagnostic_child diagnostic_used'''.split()
actual = dict.fromkeys(fields, 0)
actual.update(inventory=3, prefix_missing=3, history_unknown=3, serial=2**64-1,
              diagnostic_exit=1, diagnostic_timeout=1, diagnostic_cpu=17,
              admin_cpu=19, diagnostic_child=0x12345678)
expected = dict(inventory=2, prefix_missing=2, history_unknown=2,
                inflight=0, allocs=0, births=0, errors=0)
assert record == dict(event='initial_counts_failure', actual=actual,
                      expected_assertion=expected)
print('PASS failure-only JSON formatting: complete fields, full-width values, unchanged snapshot')
