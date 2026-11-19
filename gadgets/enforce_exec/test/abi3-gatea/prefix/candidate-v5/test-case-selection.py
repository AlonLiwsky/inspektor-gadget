#!/usr/bin/env python3
"""Execute ONLY the wrapper's pure argument-selection block; never the wrapper."""
from pathlib import Path
import subprocess
source = Path(__file__).with_name('run-disposable.sh').read_text()
block = source.split('shift 2\n', 1)[1].split('actual=$(sha256sum', 1)[0]
assert 'mkdir' not in block and 'runner' not in block and 'bpf' not in block
script = 'set -euo pipefail\n' + block + '\nprintf "%s\\n" "${cases[@]}"\n'
def select(*args):
    return subprocess.run(['bash', '-c', script, 'selection-test', *args],
                          text=True, capture_output=True)
assert select().stdout.splitlines() == ['core', 'unarmed-entry', 'preexec']
assert select('missed-entry').stdout.splitlines() == ['missed-entry']
assert select('preexec', 'unarmed-entry').stdout.splitlines() == ['preexec', 'unarmed-entry']
for args in [('bad',), ('core', 'core'), ('unarmed-entry;echo injected',), ('',)]:
    assert select(*args).returncode == 2
print('PASS reviewed wrapper selection: strict cases, no duplicates/injection, legacy opt-in only')
