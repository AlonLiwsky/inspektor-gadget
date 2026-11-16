#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../../../.." && pwd)
out=${1:?usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
clang -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
  -I"$root/include/gadget/amd64" -I"$root/include" \
  -c "$here/fixture.bpf.c" -o "$out/fixture.bpf.o"
# A misplaced __kptr compiles successfully but emits an ordinary pointer. Check
# the actual held_ref.task BTF chain before shipping the fixture for kernel load.
python3 - "$out/fixture.bpf.o" <<'PYBTF'
import re
import subprocess
import sys

raw = subprocess.check_output(["bpftool", "btf", "dump", "file", sys.argv[1], "format", "raw"], text=True)
records = {}
for match in re.finditer(r"^\[(\d+)\] (.*(?:\n(?!\[).*)*)", raw, re.MULTILINE):
    records[int(match[1])] = match[2]
held = next(value for value in records.values() if value.startswith("STRUCT 'held_ref' "))
member = re.search(r"'task' type_id=(\d+) bits_offset=0", held)
assert member, "held_ref.task missing or moved"
pointer = records[int(member[1])]
assert pointer.startswith("PTR "), "held_ref.task is not a pointer"
tag = records[int(re.search(r"type_id=(\d+)", pointer)[1])]
assert tag.startswith("TYPE_TAG 'kptr' "), "held_ref.task lacks a verifier-visible kptr tag"
pointee = records[int(re.search(r"type_id=(\d+)", tag)[1])]
assert pointee.startswith("STRUCT 'task_struct' "), "held_ref.task kptr has wrong pointee"
print("PASS: held_ref.task BTF is PTR -> TYPE_TAG kptr -> task_struct")
PYBTF
cc -O2 -g -Wall -Wextra -Werror "$here/runner.c" -o "$out/runner" $(pkg-config --cflags --libs libbpf)
sha256sum "$out/fixture.bpf.o" "$out/runner"
