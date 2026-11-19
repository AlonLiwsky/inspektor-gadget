#!/usr/bin/env bash
# PREPARED ONLY. Requires independent source/build review before any live use.
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
*) echo 'NOTRUN unsupported BTF' >&2; exit 2;;
esac
grep -qw bpf /sys/kernel/security/lsm || exit 2
mkdir -p "$out"
printf 'BTF_SHA256 %s\n' "$actual" > "$out/identity.log"
uname -a >> "$out/identity.log"
sha256sum "$build/prefix.bpf.o" "$build/runner" "$here"/*.{c,h,sh,py} "$here/../ingress/lsm_result.h" "$here/../cleanup-programs.py" >> "$out/identity.log"
# This check only parses BTF, before any BPF load. Unsupported is NOTRUN.
"$build/check-abi" /sys/kernel/btf/vmlinux > "$out/live-abi.log" || { echo 'NOTRUN required hook prototype unsupported'; exit 2; }
current= target= control= target_owned=0 control_owned=0
cleanup() {
 rc=$?;trap - EXIT
 for which in target control; do
  group=${!which};owned_name="${which}_owned"
  if [[ ${!owned_name} == 1 && -n $group && -d $group ]]; then
   # Exact newly-created cgroups only; no foreign pid enumeration or broad kill.
   [[ -e $group/cgroup.kill ]] && echo 1 > "$group/cgroup.kill" || rc=1
   for ((i=0;i<100;i++)); do rmdir "$group" 2>/dev/null && break; sleep .05; done
   [[ ! -d $group ]] || rc=1
  fi
 done
 if [[ -n $current && -f $current/runner.log ]]; then
  python3 "$here/../cleanup-programs.py" "$current" || rc=1
 fi
 printf 'EXIT_STATUS %s\n' "$rc" >> "$out/cleanup.log"
 exit "$rc"
}
trap cleanup EXIT
for kind in core missed-entry preexec; do
 current="$out/$kind";mkdir "$current"
 suffix="$(cat /proc/sys/kernel/random/uuid)"
 target="/sys/fs/cgroup/ig15-prefix-target-$suffix";control="/sys/fs/cgroup/ig15-prefix-control-$suffix"
 mkdir "$target";target_owned=1
 mkdir "$control";control_owned=1 # Ownership only follows each successful creation.
 printf 'OWNED_TARGET %s\nOWNED_CONTROL %s\n' "$target" "$control" > "$current/cgroups.log"
 timeout --signal=TERM --kill-after=10s 60s "$build/runner" "$build/prefix.bpf.o" "$target" "$control" "$current" "$kind" > "$current/runner.log" 2>&1
 python3 "$here/../cleanup-programs.py" "$current"
 rmdir "$target" "$control"
 printf 'REMOVED %s\nREMOVED %s\n' "$target" "$control" >> "$current/cgroups.log"
 target= control= current= target_owned=0 control_owned=0
done
