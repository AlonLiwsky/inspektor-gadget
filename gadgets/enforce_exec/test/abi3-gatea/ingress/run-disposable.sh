#!/usr/bin/env bash
set -euo pipefail
[[ ${IG_ABI3_GATE_A_DISPOSABLE:-} == 1 && $EUID == 0 ]] || {
  echo 'Refusing: disposable root host and IG_ABI3_GATE_A_DISPOSABLE=1 required' >&2; exit 2;
}
[[ $(uname -m) == x86_64 ]] || { echo 'amd64 only' >&2; exit 2; }
here=$(cd -- "$(dirname -- "$0")" && pwd)
build=$(realpath -- "${1:?BUILD_DIRECTORY required}")
out=$(realpath -m -- "${2:?NEW_EVIDENCE_DIRECTORY required}")
[[ ! -e $out ]] || { echo 'Evidence directory must be new' >&2; exit 2; }
mkdir -p -- "$out"
actual=$(sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1)
case "$actual" in
  12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b|759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51) ;;
  *) printf 'Unsupported BTF: %s\n' "$actual" > "$out/refused.txt"; exit 2 ;;
esac
python3 "$here/check-abi.py" /sys/kernel/btf/vmlinux > "$out/hook-abi.log"
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || { echo 'cgroup2 required' >&2; exit 2; }
grep -qw bpf /sys/kernel/security/lsm || { echo 'BPF LSM required' >&2; exit 2; }
cg=$(mktemp -d /sys/fs/cgroup/ig-ingress-gatea.XXXXXXXX)
cleanup() {
  rc=$?
  trap - EXIT
  if [[ -e $cg/cgroup.kill ]]; then echo 1 > "$cg/cgroup.kill"; fi
  for path in "$cg/target" "$cg/other" "$cg"; do
    for _ in {1..100}; do [[ ! -d $path ]] && break; if rmdir -- "$path" 2>/dev/null; then break; fi; sleep .05; done
    if [[ -d $path ]]; then printf 'CGROUP_CLEANUP_FAILED %s\n' "$path" >> "$out/cleanup.log"; if (( rc == 0 )); then rc=1; fi;
    else printf 'CGROUP_REMOVED %s\n' "$path" >> "$out/cleanup.log"; fi
  done
  if [[ -e $out/runner.log ]]; then
    if ! python3 "$here/../cleanup-programs.py" "$out"; then
      if (( rc == 0 )); then rc=1; fi
    fi
  fi
  echo "EXIT_STATUS $rc" >> "$out/cleanup.log"
  exit "$rc"
}
trap cleanup EXIT
mkdir "$cg/target" "$cg/other"
{
  date -u --iso-8601=seconds
  uname -a
  printf 'BTF_SHA256 %s\n' "$actual"
  cat /sys/kernel/security/lsm; printf '\n'
  sha256sum "$build/ingress.bpf.o" "$build/runner" "$here/ingress.bpf.c" "$here/ingress.h" "$here/runner.c" "$here/lsm_result.h" "$here/return_test.c" "$here/build.sh" "$here/run-disposable.sh" "$here/check-abi.py" "$here/../cleanup-programs.py"
  bpftool version
  printf 'CGROUP %s\n' "$cg"
} > "$out/identity.log"
# A regular log file cannot keep this launcher waiting on inherited stdout.
# The EXIT trap runs immediately on runner exit and kills only our cgroup tree.
timeout --signal=TERM --kill-after=10s 180s bash -c \
  'echo $$ > "$1/cgroup.procs"; exec "$2/runner" "$2/ingress.bpf.o" "$3" "$1"' _ "$cg" "$build" "$out" \
  > "$out/runner.log" 2>&1
