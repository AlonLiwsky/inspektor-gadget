#!/usr/bin/env bash
# Test-only build of the default-off exec-capsule exact-kernel fixture.
set -euo pipefail
cd "$(dirname "$0")"
: "${VMLINUX_DIR:?directory containing the reviewed target vmlinux.h}"
: "${OUTPUT:?absolute output object path outside the source tree}"
[[ "$OUTPUT" = /* ]]
"${CLANG:-clang-19}" -target bpf -O2 -g -D__TARGET_ARCH_x86 -Wall -Werror \
  -I "$VMLINUX_DIR" -c probe.bpf.c -o "$OUTPUT"
sha256sum "$OUTPUT"
