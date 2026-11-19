#!/usr/bin/env bash
# Build/open-only: never loads BPF or creates a kernel map.
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../../../../.." && pwd)
out=${1:?usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
TMPDIR="$(realpath "$out")" PYTHONDONTWRITEBYTECODE=1 python3 "$here/test-supervise.py" > "$out/supervisor-tests.txt" 2>&1
"${CLANG:-clang-21}" --version > "$out/compiler.txt"
"${CLANG:-clang-21}" -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
 -I"$root/include/gadget/amd64" -I"$root/include" \
 -c "$here/shape.bpf.c" -o "$out/shape.bpf.o"
cc -O2 -g -Wall -Wextra -Werror "$here/check.c" -o "$out/check" $(pkg-config --cflags --libs libbpf)
cc -O2 -g -Wall -Wextra -Werror "$here/runner.c" -o "$out/runner" $(pkg-config --cflags --libs libbpf)
"$out/check" "$out/shape.bpf.o" | tee "$out/layout-map-report.txt"
bpftool btf dump file "$out/shape.bpf.o" format raw > "$out/btf.txt"
PYTHONDONTWRITEBYTECODE=1 python3 "$here/check-bytecode.py" "$out/shape.bpf.o" | tee "$out/bytecode-check.txt"
llvm-objdump-21 -dr "$out/shape.bpf.o" > "$out/disassembly.txt"
(cd "$here"; sha256sum *.c *.h *.sh *.md *.json *.py ../../../fullpolicy/bpf/{evaluator,matcher}.h ../publication/check-bytecode.py ../cleanup-programs.py) > "$out/source.sha256"
(cd "$out"; sha256sum shape.bpf.o check runner supervisor-tests.txt compiler.txt layout-map-report.txt bytecode-check.txt btf.txt disassembly.txt source.sha256) > "$out/build.sha256"
