#!/usr/bin/env bash
# Prepared only; NOT executed as part of the build-only assignment.
set -euo pipefail
[[ ${IG_ABI3_GATE_A_DISPOSABLE:-} == 1 && $EUID == 0 ]] || exit 2
[[ $(uname -m) == x86_64 ]] || exit 2
here=$(cd -- "$(dirname -- "$0")" && pwd)
build=$(realpath -- "${1:?BUILD_DIRECTORY}")
out=$(realpath -m -- "${2:?NEW_EVIDENCE_DIRECTORY}")
[[ ! -e $out ]] || exit 2
actual=$(sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1)
case "$actual" in
12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b|759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51) ;;
*) echo 'Unsupported BTF' >&2; exit 2;;
esac
grep -qw bpf /sys/kernel/security/lsm || exit 2
mkdir -p "$out"
printf 'BTF_SHA256 %s\n' "$actual" > "$out/identity.log"
uname -a >> "$out/identity.log"
sha256sum "$build/nesting.bpf.o" "$build/runner" "$here"/*.{c,h,sh} "$here/../ingress/lsm_result.h" "$here/../cleanup-programs.py" >> "$out/identity.log"
# Private newly-created ordinary readable inode. Runner retains FD until detach.
printf 'nesting fixture\n' > "$out/target"
chmod 600 "$out/target"
current=
cleanup() {
 rc=$?; trap - EXIT
 if [[ -n $current && -f $current/runner.log ]]; then
  if ! python3 "$here/../cleanup-programs.py" "$current"; then rc=1; fi
 fi
 printf 'EXIT_STATUS %s\n' "$rc" >> "$out/cleanup.log"
 exit "$rc"
}
trap cleanup EXIT
for spec in '2 normal' '1 audit' '1 strict' '2 boundary-audit' '2 boundary-strict' '2 exhausted'; do
 read -r capacity kind <<< "$spec"
 current="$out/$kind";mkdir "$current"
 timeout --signal=TERM --kill-after=10s 60s "$build/runner" "$build/nesting.bpf.o" "$out/target" "$current" "$capacity" "$kind" > "$current/runner.log" 2>&1
 python3 "$here/../cleanup-programs.py" "$current"
 current=
done
