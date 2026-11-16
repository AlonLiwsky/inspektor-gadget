#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Inspektor Gadget authors
# Packaging/validation tests ONLY, using fake compiler and BTF dumper. This is
# not verifier proof. Supply the supported BTF artifact as the sole argument.
set -euo pipefail
[[ $# == 1 ]] || { echo "usage: $0 /trusted/vmlinux.btf" >&2; exit 1; }
owner=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cat > "$work/clang" <<'CLANG'
#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == --version ]]; then echo 'Ubuntu clang version 21.1.8'; exit; fi
[[ ${FAIL_COMPILE:-0} != 1 ]] || exit 7
printf '%s\n' "$@" > "$COMPILER_ARGS"
if [[ -n ${INTERVENING_ARCHIVE:-} ]]; then printf 'intervening owner output\n' > "$INTERVENING_ARCHIVE"; fi
while [[ $# -gt 0 ]]; do
    if [[ $1 == -o ]]; then printf 'fake ELF: packaging test only\n' > "$2"; exit; fi
    shift
done
exit 1
CLANG
cat > "$work/bpftool" <<'BPFTOOL'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == btf && $2 == dump && $3 == file && $5 == format && $6 == c ]]
printf '/* fake header: packaging test only */\n'
BPFTOOL
chmod +x "$work/clang" "$work/bpftool"
export COMPILER_ARGS=$work/compiler-args
build() { "$owner/build-archive.sh" "$1" "$work/clang" "$work/bpftool" localhost/enforce-exec-owner:test "$work/owner.tar"; }
build "$1"
cp "$work/owner.tar" "$work/first.tar"
(umask 077; make --no-print-directory -s -C "$owner" archive VMLINUX_BTF="$1" CLANG="$work/clang" BPFTOOL="$work/bpftool" IMAGE=localhost/enforce-exec-owner:test ARCHIVE="$work/owner.tar")
cmp "$work/first.tar" "$work/owner.tar"
for arg in -DENFORCE_EXEC_PERSISTENT_OWNER -D__TARGET_ARCH_x86; do
    grep -Fx -- "$arg" "$COMPILER_ARGS" >/dev/null
done
mkdir "$work/extract"
tar -xf "$work/owner.tar" -C "$work/extract"
layout=$work/extract
index=$(jq -r '.manifests[0].digest | sub("sha256:"; "")' "$layout/index.json")
jq -e '.manifests[0].annotations["org.opencontainers.image.ref.name"] == "localhost/enforce-exec-owner:test"' "$layout/index.json" >/dev/null
jq -e '.manifests[0].platform == {architecture:"amd64",os:"linux"}' "$layout/blobs/sha256/$index" >/dev/null
manifest=$(jq -r '.manifests[0].digest | sub("sha256:"; "")' "$layout/blobs/sha256/$index")
config=$(jq -r '.config.digest | sub("sha256:"; "")' "$layout/blobs/sha256/$manifest")
cmp "$owner/gadget.yaml" "$layout/blobs/sha256/$config"
jq -e '.config.mediaType == "application/vnd.gadget.config.v1+yaml" and .layers[0].mediaType == "application/vnd.gadget.ebpf.program.v1+binary"' "$layout/blobs/sha256/$manifest" >/dev/null
for blob in "$layout"/blobs/sha256/*; do
    [[ $(sha256sum "$blob" | cut -d ' ' -f1) == "${blob##*/}" ]]
done
# Verify the exact reader used by the native node-agent backend, not only tar.
cat > "$work/resolve.go" <<'GO'
package main
import (
    "context"
    _ "crypto/sha256"
    "encoding/json"
    "fmt"
    "os"
    v1 "github.com/opencontainers/image-spec/specs-go/v1"
    "oras.land/oras-go/v2/content/oci"
)
func main() {
    ctx := context.Background()
    store, err := oci.NewFromTar(ctx, os.Args[1]); if err != nil { panic(err) }
    desc, err := store.Resolve(ctx, "localhost/enforce-exec-owner:test"); if err != nil { panic(err) }
    if desc.MediaType != v1.MediaTypeImageIndex { panic(desc.MediaType) }
    reader, err := store.Fetch(ctx, desc); if err != nil { panic(err) }; defer reader.Close()
    var index v1.Index
    if err := json.NewDecoder(reader).Decode(&index); err != nil { panic(err) }
    if len(index.Manifests) != 1 || index.Manifests[0].Platform.Architecture != "amd64" { panic("bad platform") }
    fmt.Println("PASS: native ORAS NewFromTar resolves full IMAGE to amd64 image index")
}
GO
(cd "$owner/../../../.." && GOWORK=off GOFLAGS=-mod=readonly go run "$work/resolve.go" "$work/owner.tar")
if FAIL_COMPILE=1 build "$1"; then echo 'compiler failure accepted' >&2; exit 1; fi
cmp "$work/first.tar" "$work/owner.tar"
printf invalid > "$work/bad.btf"
if build "$work/bad.btf"; then echo 'unsupported BTF accepted' >&2; exit 1; fi
cmp "$work/first.tar" "$work/owner.tar"
[[ -z $(find "$work" -maxdepth 1 -name '.owner-archive.*' -print -quit) ]]
echo 'PASS: deterministic packaging, metadata, platform, digests, rejection, atomic output and cleanup (fake compiler; no kernel proof)'
# Development uses a separate output and temporary metadata, never default YAML.
original=$(sha256sum "$owner/gadget.yaml")
ABI3_DEVELOPMENT=1 "$owner/build-archive.sh" "$1" "$work/clang" "$work/bpftool" localhost/enforce-exec-owner:abi3-development "$work/owner.abi3-development.tar"
grep -Fx -- '-DENFORCE_EXEC_ABI3_DEVELOPMENT=1' "$COMPILER_ARGS" >/dev/null
mkdir "$work/development"
tar -xf "$work/owner.abi3-development.tar" -C "$work/development"
layout=$work/development
index=$(jq -r '.manifests[0].digest | sub("sha256:"; "")' "$layout/index.json")
manifest=$(jq -r '.manifests[0].digest | sub("sha256:"; "")' "$layout/blobs/sha256/$index")
config=$(jq -r '.config.digest | sub("sha256:"; "")' "$layout/blobs/sha256/$manifest")
grep -q 'enforce-exec-owner-abi: "3"' "$layout/blobs/sha256/$config"
grep -q 'enforce-exec-owner-development: "true"' "$layout/blobs/sha256/$config"
if grep -q 'enforce-exec-shared-recovery:' "$layout/blobs/sha256/$config"; then echo 'ordinary development gained recovery annotation' >&2; exit 1; fi
[[ $(sha256sum "$owner/gadget.yaml") == "$original" ]]
cmp "$work/first.tar" "$work/owner.tar"
echo 'PASS: development archive metadata/macro isolated from untouched default source and archive'

# Publication must not overwrite an output created after the initial check.
raced=$work/raced.abi3-development.tar
if ABI3_DEVELOPMENT=1 INTERVENING_ARCHIVE="$raced" "$owner/build-archive.sh" "$1" "$work/clang" "$work/bpftool" localhost/enforce-exec-owner:abi3-development "$raced"; then
    echo 'FAIL: development publication replaced intervening output' >&2; exit 1
fi
[[ $(cat "$raced") == 'intervening owner output' ]]
ln -s "$work/ordinary.tar" "$work/alias.abi3-development.tar"
if ABI3_DEVELOPMENT=1 "$owner/build-archive.sh" "$1" "$work/clang" "$work/bpftool" localhost/enforce-exec-owner:abi3-development "$work/alias.abi3-development.tar"; then
    echo 'FAIL: development archive accepted ordinary canonical destination' >&2; exit 1
fi
[[ ! -e "$work/ordinary.tar" ]]
echo 'PASS: development publication is no-replace and canonical-name isolated'

# Recovered development is a third, explicit and still-unavailable image. The
# fake compiler verifies selector packaging only, not emitted BPF or admission.
recovery=(ABI3_DEVELOPMENT=1 SHARED_DEVELOPMENT=1 SHARED_RECOVERY_DEVELOPMENT=1 SHARED_BINDINGS=2 SHARED_SLOTS_256=2 SHARED_SLOTS_1024=0 SHARED_SLOTS_4096=0 SHARED_SLOTS_16384=0 SHARED_TASKS=128 SHARED_SCRATCH=32 SHARED_ACCEPTED_UIDS=32 SHARED_TASK_QUOTA=64 SHARED_SCRATCH_QUOTA=16 SHARED_INODE_FACTS=1024 SHARED_INODE_QUOTA=512 SHARED_IMAGES=65536 SHARED_IMAGE_QUOTA=32768)
recovered=$work/owner.abi3-recovery-development.tar
env "${recovery[@]}" "$owner/build-archive.sh" "$1" "$work/clang" "$work/bpftool" localhost/enforce-exec-owner:abi3-recovery-development "$recovered"
grep -Fx -- '-DENFORCE_EXEC_SHARED_RECOVERY=1' "$COMPILER_ARGS" >/dev/null
grep -Fx -- '-DENFORCE_EXEC_SHARED_NODE=1' "$COMPILER_ARGS" >/dev/null
mkdir "$work/recovered"
tar -xf "$recovered" -C "$work/recovered"
layout=$work/recovered
index=$(jq -r '.manifests[0].digest | sub("sha256:"; "")' "$layout/index.json")
manifest=$(jq -r '.manifests[0].digest | sub("sha256:"; "")' "$layout/blobs/sha256/$index")
config=$(jq -r '.config.digest | sub("sha256:"; "")' "$layout/blobs/sha256/$manifest")
grep -q 'enforce-exec-shared-recovery: "1"' "$layout/blobs/sha256/$config"
grep -q 'native supervisor and enforcement unavailable' "$layout/blobs/sha256/$config"
if env "${recovery[@]}" "$owner/build-archive.sh" "$1" "$work/clang" "$work/bpftool" localhost/enforce-exec-owner:abi3-development "$work/wrong.abi3-recovery-development.tar" > "$work/recovery-error" 2>&1; then exit 1; fi
if env "${recovery[@]}" "$owner/build-archive.sh" "$1" "$work/clang" "$work/bpftool" localhost/enforce-exec-owner:abi3-recovery-development "$work/wrong.abi3-development.tar" > "$work/recovery-error" 2>&1; then exit 1; fi
[[ $(sha256sum "$owner/gadget.yaml") == "$original" ]]
cmp "$work/first.tar" "$work/owner.tar"
echo 'PASS: recovered selector archive is distinct, explicit, and default-isolated (fake compiler)'
