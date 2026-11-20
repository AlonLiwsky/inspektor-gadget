#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
# Host-only compilation. No BPF is loaded by this script.
# Use the clang/llvm-strip alternatives from the repository-pinned
# gadget-builder image. A compiler override produces a distinct artifact
# that must be qualified; host compiler availability is not provenance.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../../../.." && pwd)
[[ $# == 1 || $# == 2 ]] || { echo 'usage: build.sh ABSOLUTE_NEW_PAYLOAD [baseline|no-exit-arm|no-nonce|never-move|restart-lift]' >&2; exit 2; }
OUT=$1; variant=${2:-baseline}
[[ $OUT == /* && ! -e $OUT ]] || { echo 'payload must be an absolute, new path' >&2; exit 2; }
case $variant in baseline|no-exit-arm|no-nonce|never-move|restart-lift) ;; *) echo 'unknown variant' >&2; exit 2;; esac
mkdir -p "$OUT"
args=(); case $variant in no-exit-arm|no-nonce) args=("$variant");; esac
"$HERE/../bpf/build.sh" "$OUT/fence.bpf.o" "${args[@]}"
"${CLANG:-clang}" -target bpfel -mcpu=v3 -O2 -g -Wall -Werror \
  -D__TARGET_ARCH_x86 -I "$REPO/include/gadget/amd64" -I "$REPO/include/gadget" \
  -c "$HERE/bpf/backend.bpf.c" -o "$OUT/backend.bpf.o"
gcc -std=c11 -static -O2 -Wall -Wextra -Werror "$HERE/exec_probe.c" -o "$OUT/exec-probe"
(cd "$REPO" && CGO_ENABLED=0 go build -trimpath -o "$OUT/fence-oracle" ./gadgets/enforce_exec/restartfence/qualification/oracle)
cp "$HERE/run-in-guest.sh" "$OUT/run-in-guest.sh"
printf '%s\n' "$variant" > "$OUT/variant"
case $variant in
 baseline) printf 'all\n' ;;
 no-exit-arm) printf 'sigkill\n' ;;
 no-nonce) printf 'nonce\n' ;;
 never-move) printf 'graceful\n' ;;
 restart-lift) printf 'graceful\n' ;;
esac > "$OUT/scenario"
{
 "${CLANG:-clang}" --version | head -n 1
 gcc --version | head -n 1
 go version
 git -C "$REPO" rev-parse HEAD
} > "$OUT/toolchain.txt"
(cd "$OUT" && sha256sum fence.bpf.o backend.bpf.o exec-probe fence-oracle run-in-guest.sh variant scenario toolchain.txt > SHA256SUMS)
cat "$OUT/SHA256SUMS"
