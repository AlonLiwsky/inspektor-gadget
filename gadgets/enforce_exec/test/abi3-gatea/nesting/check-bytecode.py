#!/usr/bin/env python3
"""Build artifact assertions only: never loads BPF or proves verifier safety."""
import re
import subprocess
import sys
raw = subprocess.check_output(['llvm-objdump', '-dr', '--no-show-raw-insn', sys.argv[1]], text=True)
assert 'lsm.s/file_open' in raw and 'lsm/inode_permission' in raw
assert 'bpf_get_file_xattr' in raw
inner = raw.split('<nest_inner>:', 1)[1].split('Disassembly of section', 1)[0]
outer = raw.split('<nest_outer>:', 1)[1].split('Disassembly of section', 1)[0]
assert 'bpf_get_file_xattr' not in inner
assert 'bpf_get_file_xattr' in outer
for body, offsets in [(inner, ['0x8', '0x10', '0x18']), (outer, ['0x0', '0x8'])]:
    for off in offsets:
        assert re.search(r'r\d+ = \*\(u64 \*\)\(r\d+ \+ '+off+r'\)', body), off
    assert 's>>= 0x20' in body and 's>= -0xfff' in body, 'signed bounded LSM return'
print('PASS: emitted hook slots, signed errno bounds and outer-only real xattr relocation')
