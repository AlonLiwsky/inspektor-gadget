#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../../../../.." && pwd)
out=${1:?usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
clang --version | head -1 | grep -F '21.1.8'
clang -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 -I"$root/include/gadget/amd64" -I"$root/include" -c "$here/prefix.bpf.c" -o "$out/prefix.bpf.o"
cc -O2 -g -Wall -Wextra -Werror "$here/runner.c" "$here/check-abi.c" -o "$out/runner" $(pkg-config --cflags --libs libbpf)
clang --analyze -Wall -Wextra -Werror $(pkg-config --cflags libbpf) "$here/runner.c" -o "$out/runner-analysis.plist"
clang --analyze -Wall -Wextra -Werror $(pkg-config --cflags libbpf) "$here/check-abi.c" -o "$out/abi-analysis.plist"
cc -O2 -g -Wall -Wextra -Werror "$here/log_test.c" -o "$out/log_test"
"$out/log_test" # Pure host logger only.
cc -O2 -g -Wall -Wextra -Werror "$here/format_test.c" -o "$out/format_test"
python3 "$here/test-format.py" "$out/format_test"
python3 "$here/test-case-selection.py"
cc -O2 -g -Wall -Wextra -Werror "$here/state_test.c" -o "$out/state_test"
"$out/state_test" # Pure host arithmetic ONLY; never run the BPF runner here.
cc -O2 -g -Wall -Wextra -Werror -DPX_ABI_MAIN "$here/check-abi.c" -o "$out/check-abi" $(pkg-config --cflags --libs libbpf)
for kernel in original k8s; do "$out/check-abi" "/btf/$kernel/vmlinux.btf"; done
sha256sum /btf/{original,k8s}/vmlinux.btf > "$out/kernel-btf-sha256.txt"
python3 "$here/check-bytecode.py" "$out/prefix.bpf.o"
llvm-objdump -dr "$out/prefix.bpf.o" > "$out/disassembly.txt"
bpftool btf dump file "$out/prefix.bpf.o" format raw > "$out/object-btf.txt"
sha256sum "$out/prefix.bpf.o" "$out/runner" "$out/check-abi" "$out/state_test"
