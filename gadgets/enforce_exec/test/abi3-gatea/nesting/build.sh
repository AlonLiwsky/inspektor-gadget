#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../../../../.." && pwd)
out=${1:?usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
clang --version | head -1 | grep -F '21.1.8'
clang -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 -I"$root/include/gadget/amd64" -I"$root/include" -c "$here/nesting.bpf.c" -o "$out/nesting.bpf.o"
cc -O2 -g -Wall -Wextra -Werror "$here/runner.c" "$here/check-abi.c" -o "$out/runner" $(pkg-config --cflags --libs libbpf)
cc -O2 -g -Wall -Wextra -Werror "$here/return_test.c" -o "$out/return_test"
"$out/return_test" # pure host arithmetic only; NEVER execute the BPF runner here
python3 "$here/check-bytecode.py" "$out/nesting.bpf.o"
llvm-objdump -dr "$out/nesting.bpf.o" > "$out/disassembly.txt"
bpftool btf dump file "$out/nesting.bpf.o" format raw > "$out/object-btf.txt"
sha256sum "$out/nesting.bpf.o" "$out/runner" "$out/return_test"

cc -O2 -g -Wall -Wextra -Werror -DNEST_ABI_MAIN "$here/check-abi.c" -o "$out/check-abi" $(pkg-config --cflags --libs libbpf)
sha256sum /btf/{original,k8s}/vmlinux.btf > "$out/kernel-btf-sha256.txt"
for kernel in original k8s; do "$out/check-abi" "/btf/$kernel/vmlinux.btf"; done
