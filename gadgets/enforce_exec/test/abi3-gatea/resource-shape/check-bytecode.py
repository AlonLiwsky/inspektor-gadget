#!/usr/bin/env python3
"""Offline emitted shape checks, not verifier/dataflow/lifetime evidence."""
import importlib.util
import pathlib
import re
import subprocess
import sys

spec = importlib.util.spec_from_file_location('publication_checks', pathlib.Path(__file__).parent.parent / 'publication/check-bytecode.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.check_line_info(sys.argv[1])
text = subprocess.check_output(['llvm-objdump-21', '-d', '--no-show-raw-insn', sys.argv[1]], text=True)

def check(text):
    region = re.search(r'<rs_commit_begin>:\n(.*?)\n[^\n]*<rs_commit_end>:', text, re.S)
    assert region, 'missing commit labels'
    body = region[1]
    assert not re.search(r'\b(call|goto|if|exit)\b', body), 'fallible/branch/helper in commit'
    epochs = re.findall(r'\*\(u64 \*\)\(r(?:8|2) \+ 0x8\) = r1', body)
    assert len(epochs) == 8, 'not eight epoch stores'
    for offset in range(0xf0, 0x161, 0x10):
        assert f'r1 = *(u64 *)(r9 + {offset:#x})' in body, 'missing distinct sealed epoch load'
    assert len(re.findall(r'\*\(u(?:64|32) \*\).* = [rw]\d+', body)) == 14, 'unexpected authority store count'
check(text)
for injection in ['call 0x1', 'goto +0x1', 'if r0 == 0x0 goto +0x1', 'exit']:
    try:
        check(text.replace('<rs_commit_begin>:', '<rs_commit_begin>:\n0:\t'+injection))
    except AssertionError:
        pass
    else:
        raise AssertionError('negative mutation accepted')
print('PASS raw BTF.ext and MAX8 emitted 8 epoch/6 scope stores, no branch/helper; negative mutations rejected')
