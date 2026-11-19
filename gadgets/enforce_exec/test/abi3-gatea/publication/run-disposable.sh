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
actual=$(sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1)
case "$actual" in
  12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b|759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51) ;;
  *) printf 'Unsupported BTF: %s\n' "$actual" >&2; exit 2 ;;
esac
# This and bytecode validation happen before any cgroup/BPF resource exists.
python3 "$here/check-abi.py" /sys/kernel/btf/vmlinux
python3 "$here/check-bytecode.py" "$build/publication.bpf.o"
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || { echo 'cgroup2 required' >&2; exit 2; }
mkdir -p -- "$out"
cg=$(mktemp -d /sys/fs/cgroup/ig-publication-gatea.XXXXXXXX)
cleanup() {
  rc=$?
  trap - EXIT
  if [[ -e $cg/cgroup.kill ]]; then echo 1 > "$cg/cgroup.kill"; fi
  for _ in {1..100}; do
    [[ ! -d $cg ]] && break
    if rmdir -- "$cg" 2>/dev/null; then break; fi
    sleep .05
  done
  if [[ -d $cg ]]; then echo "CGROUP_CLEANUP_FAILED $cg" >> "$out/cleanup.log"; if (( rc == 0 )); then rc=1; fi;
  else echo "CGROUP_REMOVED $cg" >> "$out/cleanup.log"; fi
  if [[ -e $out/runner.log ]]; then
    if ! python3 "$here/../cleanup-programs.py" "$out"; then
      if (( rc == 0 )); then rc=1; fi
    fi
  fi
  echo "EXIT_STATUS $rc" >> "$out/cleanup.log"
  exit "$rc"
}
trap cleanup EXIT
{
  date -u --iso-8601=seconds
  uname -a
  printf 'BTF_SHA256 %s\n' "$actual"
  sha256sum "$build/publication.bpf.o" "$build/runner" "$here"/*.c "$here"/*.h "$here"/*.py "$here"/*.sh "$here/README.md" "$here/../cleanup-programs.py"
  bpftool version
  printf 'CGROUP %s\n' "$cg"
} > "$out/identity.log"
# Regular output file: no tee/pipe can delay EXIT cleanup on failure.
timeout --signal=TERM --kill-after=10s 180s bash -c \
 'echo $$ > "$1/cgroup.procs"; exec "$2/runner" "$2/publication.bpf.o" "$3" "$1"' _ "$cg" "$build" "$out" \
 > "$out/runner.log" 2>&1
