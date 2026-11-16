#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
: "${VMLINUX_DIR:?directory containing the reviewed target vmlinux.h}"
: "${OUTPUT:?absolute output object path outside the source tree}"
[[ "$OUTPUT" = /* ]]
extra=()
case "${HOOKS:-control}" in
 control) ;;
 exec) extra+=(-DROUTE_PIN_EXEC_HOOKS=1) ;;
 publication) extra+=(-DROUTE_PIN_PUBLICATION_HOOKS=1) ;;
 *) echo "unsupported HOOKS" >&2; exit 1 ;;
esac
"${CLANG:-clang-19}" "${extra[@]}" -target bpf -O2 -g -D__TARGET_ARCH_x86 \
  -DENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE=1 -I "$VMLINUX_DIR" \
  -c probe.bpf.c -o "$OUTPUT"
sha256sum "$OUTPUT"
