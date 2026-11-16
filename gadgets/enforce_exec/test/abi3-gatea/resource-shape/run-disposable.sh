#!/usr/bin/env bash
# No implicit build or cloud action. Run only after independent fixture review.
set -euo pipefail
[[ ${IG_ABI3_RESOURCE_SHAPE_DISPOSABLE:-} == 1 ]] || { echo 'explicit disposable consent required' >&2; exit 2; }
build=$(realpath "${1:?usage: run-disposable.sh BUILD NEW_EVIDENCE_DIR}")
evidence=${2:?new evidence directory required}
[[ $(uname -m) == x86_64 ]] || exit 2
btf=$(sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1)
case "$btf" in
 12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b|759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51) ;;
 *) echo 'unadmitted exact kernel BTF' >&2; exit 2;;
esac
grep -qx 'CONFIG_NR_CPUS=64' "/boot/config-$(uname -r)"
[[ ! -e "$evidence" ]] || { echo 'evidence path already exists' >&2; exit 2; }
mkdir "$evidence"
(cd "$build"; sha256sum -c build.sha256) > "$evidence/build-check.txt"
printf '%s\n' "$btf" > "$evidence/kernel-btf.sha256"
uname -a > "$evidence/uname.txt"
cp "/boot/config-$(uname -r)" "$evidence/kernel-config.txt"
cat /sys/devices/system/cpu/possible > "$evidence/possible-cpus.txt"
cat /sys/devices/system/cpu/online > "$evidence/online-cpus-context-only.txt"
here=$(cd -- "$(dirname -- "$0")" && pwd)
set +e
PYTHONDONTWRITEBYTECODE=1 python3 "$here/supervise.py" "$build/runner" "$build/shape.bpf.o" "$evidence"
status=$?
set -e
(cd "$evidence"; sha256sum ./* > SHA256SUMS)
exit "$status"
