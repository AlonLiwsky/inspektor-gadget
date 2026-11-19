#!/usr/bin/env python3
"""Artifact-only signed LSM errno regression; no BPF load."""
import re
import subprocess
import sys
raw = subprocess.check_output(['llvm-objdump', '-dr', '--no-show-raw-insn', sys.argv[1]], text=True)
body = raw.split('<px_alloc>:', 1)[1].split('Disassembly of section', 1)[0]
assert re.search(r'r(\d+) <<= 0x20\n\s*\d+:\s*r\1 s>>= 0x20', body), 'signed 64-bit extension'
assert 's> 0x0' in body and 's>= -0xfff' in body, 'signed errno clamp'
assert not re.search(r'\bw0\s*=(?!=)', body), '32-bit return would zero-extend prior denial'
assert re.search(r'\br0 = r\d+', body), '64-bit return register move'
print('PASS actual px_alloc bytecode signed extension/bounds/64-bit return')
