#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
# Use the clang/llvm-strip alternatives from the repository-pinned
# gadget-builder image. A compiler override produces a distinct artifact
# that must be qualified; host compiler availability is not provenance.
set -euo pipefail
[[ $# == 1 || $# == 2 ]] || { echo "usage: $0 OUTPUT [no-exit-arm|no-nonce]" >&2; exit 2; }
out="$(realpath -m -- "$1")"
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
variant=()
case ${2:-} in
  '') ;;
  no-exit-arm) variant=(-DFENCE_TEST_NO_EXIT_ARM) ;;
  no-nonce) variant=(-DFENCE_TEST_NO_NONCE) ;;
  *) echo "unknown qualification variant: $2" >&2; exit 2 ;;
esac
case ${FENCE_ARCH:-$(uname -m)} in
  amd64|x86_64) arch=amd64 target=x86 syscall=157 ;;
  arm64|aarch64) arch=arm64 target=arm64 syscall=167 ;;
  *) echo "unsupported fence architecture" >&2; exit 2 ;;
esac
"${CLANG:-clang}" -target bpfel -mcpu=v3 -O2 -g -Wall -Werror \
  -fdebug-compilation-dir=. -I "../../../../include/gadget/$arch" \
  -I ../../../../include/gadget -D"__TARGET_ARCH_$target" -D"FENCE_NR_PRCTL=$syscall" \
  "${variant[@]}" -c fence.bpf.c -o "$out"
"${LLVM_STRIP:-llvm-strip}" -g "$out"
