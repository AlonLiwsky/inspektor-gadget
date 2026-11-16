#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build-context contract only: no compiler, BPF load or kernel proof.
set -euo pipefail
owner=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export CAPTURE=$work/capture
cat > "$work/ig" <<'IG'
#!/usr/bin/env bash
set -eu
mkdir -p "$CAPTURE"
cp "${@: -1}/gadget.yaml" "${@: -1}/program.bpf.c" "$CAPTURE/"
printf '%s\n' "$@" > "$CAPTURE/args"
IG
chmod +x "$work/ig"
original=$(sha256sum "$owner/gadget.yaml")
make -s -C "$owner" build IG="$work/ig"
grep -q 'enforce-exec-owner-abi: "2"' "$CAPTURE/gadget.yaml"
! grep -q 'ABI3_DEVELOPMENT' "$CAPTURE/program.bpf.c"
grep -qx 'enforce-exec-owner:experimental' "$CAPTURE/args"
if make -s -C "$owner" build IG="$work/ig" ABI3_DEVELOPMENT=1; then
    echo 'FAIL: development accepted default image' >&2; exit 1
fi
if make -s -C "$owner" build IG="$work/ig" ABI3_DEVELOPMENT=1 IMAGE=localhost/owner:stable; then
    echo 'FAIL: development accepted stable image' >&2; exit 1
fi
make -s -C "$owner" build IG="$work/ig" ABI3_DEVELOPMENT=1 IMAGE=localhost/owner:abi3-development
grep -q 'enforce-exec-owner-abi: "3"' "$CAPTURE/gadget.yaml"
grep -q 'enforce-exec-owner-development: "true"' "$CAPTURE/gadget.yaml"
grep -qx '#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1' "$CAPTURE/program.bpf.c"
[[ $(sha256sum "$owner/gadget.yaml") == "$original" ]]
for value in 2 true; do
    if make -s -C "$owner" build IG="$work/ig" ABI3_DEVELOPMENT="$value"; then
        echo 'FAIL: invalid selector accepted' >&2; exit 1
    fi
done
echo 'PASS: default ABI2 and isolated explicit ABI3 development build contexts'
# Archive development selection must fail before tool/BTF work, not silently
# overwrite the ordinary output. An existing explicit development output is immutable.
reject_archive() {
    local image=$1 output=$2 expected=$3
    if ABI3_DEVELOPMENT=1 "$owner/build-archive.sh" /missing/btf /missing/clang /missing/bpftool "$image" "$output" > "$work/error" 2>&1; then
        echo 'FAIL: unsafe development archive accepted' >&2; exit 1
    fi
    grep -q "$expected" "$work/error"
}
reject_archive enforce-exec-owner:experimental "$work/owner.tar" 'explicit IMAGE'
reject_archive localhost/owner:abi3-development "$work/owner.tar" 'separate ARCHIVE'
touch "$work/owner.abi3-development.tar"
reject_archive localhost/owner:abi3-development "$work/owner.abi3-development.tar" 'must not replace'
echo 'PASS: unsafe development archive contexts rejected before BTF/compiler work'
