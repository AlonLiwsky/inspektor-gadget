#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../../../../.." && pwd)
out=${1:?usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
clang -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
  -I"$root/include/gadget/amd64" -I"$root/include" \
  -c "$here/ingress.bpf.c" -o "$out/ingress.bpf.o"
# Verify actual BPF lowering, not merely equivalent host-C behavior.
python3 - "$out/ingress.bpf.o" <<'PYDISASM'
import re
import subprocess
import sys

raw = subprocess.check_output(["llvm-objdump", "-d", "--no-show-raw-insn", sys.argv[1]], text=True)
body = raw.split("<in_permission>:\n", 1)[1].split("\n\n", 1)[0]
code = "\n".join(line.split(":\t", 1)[1].strip() for line in body.splitlines() if ":\t" in line)
pattern = (r"(?P<reg>r\d+) <<= 0x20\n(?P=reg) s>>= 0x20\n"
           r"if (?P=reg) s> 0x0 goto \+0x1[^\n]*\n"
           r"if (?P=reg) s>= -0xfff goto \+0x1[^\n]*\n(?P=reg) = -0x1")
assert re.search(pattern, code), "LSM result lacks same-64-bit-register sign extension and bounds"
for offset in ["0x8", "0x10", "0x18"]:
    assert re.search(r"r\d+ = \*\(u64 \*\)\(r1 \+ " + offset + r"\)", code), "LSM inode/mask/prior context slots changed"
print("PASS: emitted BPF uses inode/mask/prior context offsets 8/16/24")
print("PASS: emitted BPF clamps signed errno on one 64-bit register")
PYDISASM
# Destination kptr annotation must survive compilation (a misplaced __kptr
# previously compiled successfully but failed the actual kernel verifier).
python3 - "$out/ingress.bpf.o" <<'PYBTF'
import json
import subprocess
import sys
types = json.loads(subprocess.check_output(["bpftool", "-j", "btf", "dump", "file", sys.argv[1]], text=True))["types"]
by_id = {item["id"]: item for item in types}
ref = next(item for item in types if item.get("name") == "cancellation_ref")
member = next(item for item in ref["members"] if item["name"] == "task")
ptr = by_id[member["type_id"]]
assert ptr["kind"] == "PTR", "cancellation task must be pointer"
tag = by_id[ptr["type_id"]]
assert tag["kind"] == "TYPE_TAG" and tag["name"] == "kptr", "cancellation task lost kptr BTF tag"
print("PASS: cancellation task destination retains kptr BTF tag")
PYBTF
cc -O2 -g -Wall -Wextra -Werror "$here/runner.c" -o "$out/runner" $(pkg-config --cflags --libs libbpf)
cc -O2 -g -Wall -Wextra -Werror "$here/return_test.c" -o "$out/return_test"
"$out/return_test"
sha256sum "$out/ingress.bpf.o" "$out/runner"
