#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Inspektor Gadget authors
# Build only: never load BPF. Requires Bash, GNU tar/coreutils, jq, bpftool and
# Clang 21.1.8. Supply a trusted BTF artifact matching the supported kernel;
# this archive is amd64-only, not a general kernel or arm64 support claim.
set -euo pipefail
umask 022
export LC_ALL=C
export SOURCE_DATE_EPOCH=0
fail() { printf 'owner archive: %s\n' "$*" >&2; exit 1; }
[[ $# == 5 ]] || fail 'usage: build-archive.sh VMLINUX_BTF CLANG BPFTOOL IMAGE ARCHIVE'
btf=$1 clang=$2 bpftool=$3 image=$4 archive=$5
case ${SHARED_RECOVERY_DEVELOPMENT:-0} in
    0) [[ "$image" != *:abi3-recovery-development ]] || fail 'recovery IMAGE requires SHARED_RECOVERY_DEVELOPMENT=1' ;;
    1)
        [[ ${SHARED_DEVELOPMENT:-0} == 1 && ${ABI3_DEVELOPMENT:-0} == 1 ]] || fail 'recovery requires shared ABI3 development'
        [[ "$image" == *:abi3-recovery-development ]] || fail 'recovery requires explicit IMAGE ending :abi3-recovery-development'
        [[ "$archive" == *.abi3-recovery-development.tar ]] || fail 'recovery requires separate ARCHIVE ending .abi3-recovery-development.tar'
        ;;
    *) fail 'SHARED_RECOVERY_DEVELOPMENT must be 0 or 1' ;;
esac
case ${ABI3_DEVELOPMENT:-0} in
    0) development_flags=() ;;
    1)
        if [[ ${SHARED_RECOVERY_DEVELOPMENT:-0} != 1 ]]; then
            [[ "$image" == *:abi3-development ]] || fail 'development requires explicit IMAGE ending :abi3-development'
            [[ "$archive" == *.abi3-development.tar ]] || fail 'development requires separate ARCHIVE ending .abi3-development.tar'
        fi
        [[ ! -e "$archive" ]] || fail 'development ARCHIVE must not replace an existing output'
        development_flags=(-DENFORCE_EXEC_ABI3_DEVELOPMENT=1)
        ;;
    *) fail 'ABI3_DEVELOPMENT must be 0 or 1' ;;
esac
profile_script=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/shared-build-profile.sh
shared_flags=()
profile_flags=$("$profile_script" flags)
if [[ -n "$profile_flags" ]]; then
    mapfile -t shared_flags <<< "$profile_flags"
fi
development_flags+=("${shared_flags[@]}")
[[ -f "$btf" && -r "$btf" ]] || fail 'VMLINUX_BTF must be a readable regular file'
[[ -n "$archive" && "$archive" != */ ]] || fail 'ARCHIVE must name an output file'
[[ "$image" =~ ^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,254}$ ]] || fail 'IMAGE must be a bounded image reference'
for tool in "$clang" "$bpftool" jq sha256sum stat realpath mktemp tar; do
    command -v "$tool" >/dev/null || fail "missing tool: $tool"
done
version=$("$clang" --version)
[[ "$version" =~ clang\ version\ 21\.1\.8([^0-9.]|$) ]] || fail 'the proved owner requires Clang 21.1.8'
[[ $(stat -Lc %s -- "$btf") -le 134217728 ]] || fail 'BTF exceeds 128 MiB'
# Keep aligned with fullruntime kernel_matrix.go; additions require kernel proof.
expected_btf=12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b
kubernetes_btf=759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51
owner=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$owner/../../../.." && pwd)
archive=$(realpath -m -- "$archive")
if [[ ${ABI3_DEVELOPMENT:-0} == 1 ]]; then
    if [[ ${SHARED_RECOVERY_DEVELOPMENT:-0} == 1 ]]; then
        [[ "$archive" == *.abi3-recovery-development.tar ]] || fail 'canonical recovery ARCHIVE must end .abi3-recovery-development.tar'
    else
        [[ "$archive" == *.abi3-development.tar ]] || fail 'canonical development ARCHIVE must end .abi3-development.tar'
    fi
fi
[[ -d $(dirname -- "$archive") && ! -d "$archive" ]] || fail 'ARCHIVE parent must exist and output must not be a directory'
[[ "$archive" != "$(realpath -- "$btf")" && "$archive" != "$repo/"* ]] || fail 'ARCHIVE must be outside the source tree and must not replace BTF'
work=$(mktemp -d -- "$(dirname -- "$archive")/.owner-archive.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Snapshot before checking: compilation must use the bytes whose digest was checked.
head -c 134217729 -- "$btf" > "$work/vmlinux.btf"
[[ $(stat -c %s -- "$work/vmlinux.btf") -le 134217728 ]] || fail 'BTF exceeds 128 MiB'
case $(sha256sum "$work/vmlinux.btf" | cut -d ' ' -f1) in
    "$expected_btf"|"$kubernetes_btf") ;;
    *) fail 'BTF is outside the proved amd64 owner matrix' ;;
esac
"$bpftool" btf dump file "$work/vmlinux.btf" format c > "$work/vmlinux.h"
"$clang" -target bpf -O2 -g -D__TARGET_ARCH_x86 -DENFORCE_EXEC_PERSISTENT_OWNER "${development_flags[@]}" \
    -Wno-missing-declarations -fdebug-compilation-dir=/src \
    "-ffile-prefix-map=$work=/build" "-ffile-prefix-map=$repo=/src" \
    -I"$work" -I"$repo/include" -I"$owner/../../fullpolicy/bpf" \
    -c "$owner/../program.bpf.c" -o "$work/program.o"
[[ -s "$work/program.o" ]] || fail 'compiler produced no object'
layout=$work/layout
mkdir -p "$layout/blobs/sha256"
# Return an OCI descriptor while storing exact bytes in the content-addressed layout.
blob() {
    local file=$1 media=$2 digest size
    digest=$(sha256sum "$file" | cut -d ' ' -f1)
    size=$(stat -c %s -- "$file")
    cp -- "$file" "$layout/blobs/sha256/$digest"
    jq -cnS --arg media "$media" --arg digest "sha256:$digest" --argjson size "$size" \
        '{mediaType:$media,digest:$digest,size:$size}'
}
cp -- "$owner/gadget.yaml" "$work/gadget.yaml"
if [[ ${ABI3_DEVELOPMENT:-0} == 1 ]]; then
    sed -i 's/enforce-exec-owner-abi: "2"/enforce-exec-owner-abi: "3"\n  enforce-exec-owner-development: "true"/; s/^description:.*/description: "Stage A ABI3 development only; incomplete lifecycle, not production-ready"/' "$work/gadget.yaml"
fi
if [[ ${SHARED_RECOVERY_DEVELOPMENT:-0} == 1 ]]; then
    sed -i 's/^description:.*/description: "Shared ABI3 recovery development only; native supervisor and enforcement unavailable"/' "$work/gadget.yaml"
fi
"$profile_script" metadata > "$work/shared-annotations"
sed -i '/^annotations:/r '"$work/shared-annotations" "$work/gadget.yaml"
config=$(blob "$work/gadget.yaml" application/vnd.gadget.config.v1+yaml)
program=$(blob "$work/program.o" application/vnd.gadget.ebpf.program.v1+binary)
jq -cnS --argjson config "$config" --argjson program "$program" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",config:$config,layers:[$program]}' > "$work/manifest.json"
manifest=$(blob "$work/manifest.json" application/vnd.oci.image.manifest.v1+json)
jq -cnS --argjson manifest "$manifest" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json",manifests:[$manifest + {platform:{architecture:"amd64",os:"linux"}}]}' > "$work/image-index.json"
index=$(blob "$work/image-index.json" application/vnd.oci.image.index.v1+json)
jq -cnS --argjson index "$index" --arg image "$image" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json",manifests:[$index + {annotations:{"org.opencontainers.image.ref.name":$image}}]}' > "$layout/index.json"
printf '%s\n' '{"imageLayoutVersion":"1.0.0"}' > "$layout/oci-layout"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=ustar \
    -C "$layout" -cf "$work/archive.tar" blobs index.json oci-layout
if [[ ${ABI3_DEVELOPMENT:-0} == 1 ]]; then
    # The temporary directory is on the output filesystem. Hardlink publication
    # is atomic and fails if any output appeared after preflight; never replace it.
    ln -T -- "$work/archive.tar" "$archive" || fail 'development ARCHIVE appeared before publication'
else
    mv -f -- "$work/archive.tar" "$archive"
fi
printf 'Built amd64 owner archive: %s (%s)\n' "$archive" "$image"
