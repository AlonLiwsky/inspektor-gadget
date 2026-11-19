#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../../../../.." && pwd)
out=${1:?usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
"${CLANG:-clang}" -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
 -I"$root/include/gadget/amd64" -I"$root/include" \
 -c "$here/publication.bpf.c" -o "$out/publication.bpf.o"
python3 "$here/check-bytecode.py" "$out/publication.bpf.o" --self-test
cc -O2 -g -Wall -Wextra -Werror -pthread "$here/runner.c" -o "$out/runner" $(pkg-config --cflags --libs libbpf)
"$out/runner" --self-test-consent
"$out/runner" --self-test-arm-receipt
sha256sum "$out/publication.bpf.o" "$out/runner"
