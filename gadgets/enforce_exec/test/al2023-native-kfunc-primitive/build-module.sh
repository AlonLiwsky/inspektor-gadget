#!/usr/bin/env bash
# Build-only. Never installs, loads, signs, or unloads a module.
set -euo pipefail
if [[ $# != 4 ]]; then
  echo 'usage: build-module.sh EXACT_KERNEL_DIR EXACT_BTF RESOLVE_BTFIDS OUTPUT_DIR' >&2
  exit 2
fi
src=$(cd -- "$(dirname -- "$0")" && pwd)
kdir=$(realpath "$1")
btf=$(realpath "$2")
resolver=$(realpath "$3")
release=$(cat "$kdir/include/config/kernel.release")
case "$release" in
  6.12.113-138.209.amzn2023.x86_64) expected=0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82 ;;
  6.18.56-125.164.amzn2023.x86_64) expected=d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee ;;
  *) echo "unsupported vendor release: $release" >&2; exit 2 ;;
esac
[[ $(sha256sum "$btf" | cut -d' ' -f1) == "$expected" ]] || { echo 'exact BTF hash mismatch' >&2; exit 2; }
[[ -x "$resolver" && -s "$kdir/Module.symvers" ]]
for option in CONFIG_BPF_SYSCALL CONFIG_BPF_LSM CONFIG_DEBUG_INFO_BTF_MODULES; do
  grep -qx "$option=y" "$kdir/.config"
done
# Caller prepares the isolated extracted vendor tree, never the host build tree.
[[ -e "$kdir/vmlinux" && "$kdir/vmlinux" -ef "$btf" ]] || { echo 'vendor tree vmlinux must reference exact BTF' >&2; exit 2; }
mkdir -p "$4"
out=$(realpath "$4")
[[ "$out" != "$src" && "$out" != "$kdir" ]]
cp "$src/ig_argv_kfunc.c" "$src/argv_wire.h" "$src/Makefile" "$out/"
make -C "$kdir" M="$out" RESOLVE_BTFIDS="$resolver" modules
ko="$out/ig_argv_kfunc.ko"
# Vendor Kbuild expects in-place resolution; modern host tools emit sidecars.
# Resolve a fresh coherent BTF/base/ID set and embed all three, never just IDs.
rm -f "$ko.BTF" "$ko.BTF.base" "$ko.BTF_ids"
"$resolver" --fatal_warnings --distill_base -b "$btf" "$ko"
for section in BTF BTF.base BTF_ids; do
  [[ -s "$ko.$section" ]] || { echo "missing resolver sidecar: $section" >&2; exit 2; }
done
objcopy --update-section ".BTF=$ko.BTF" --update-section ".BTF.base=$ko.BTF.base" "$ko"
"$resolver" --patch_btfids "$ko.BTF_ids" "$ko"
python3 "$src/check-module.py" "$ko"
sha256sum "$ko"
