#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Local build-context tests only: no compiler or kernel load.
set -euo pipefail
owner=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d);trap 'rm -rf -- "$work"' EXIT
export CAPTURE=$work/capture
cat > "$work/ig" <<'IG'
#!/usr/bin/env bash
set -eu
mkdir -p "$CAPTURE"
cp "${@: -1}/gadget.yaml" "${@: -1}/program.bpf.c" "$CAPTURE/"
if test -f "${@: -1}/full/shared_control.h";then touch "$CAPTURE/shared-header";fi
IG
chmod +x "$work/ig"
reject() {
 rm -rf "$CAPTURE"
 if make -s -C "$owner" build IG="$work/ig" "$@" > "$work/error" 2>&1;then echo 'unsafe shared selector accepted' >&2;exit 1;fi
 test ! -e "$CAPTURE"
}
reject ABI3_DEVELOPMENT=1 IMAGE=local/owner:abi3-development SHARED_DEVELOPMENT=1
reject SHARED_DEVELOPMENT=1
reject SHARED_DEVELOPMENT=2
profile=(SHARED_BINDINGS=2 SHARED_SLOTS_256=2 SHARED_SLOTS_1024=0 SHARED_SLOTS_4096=0 SHARED_SLOTS_16384=0 SHARED_TASKS=128 SHARED_SCRATCH=32 SHARED_ACCEPTED_UIDS=32 SHARED_TASK_QUOTA=64 SHARED_SCRATCH_QUOTA=16 SHARED_INODE_FACTS=1024 SHARED_INODE_QUOTA=512 SHARED_IMAGES=65538 SHARED_IMAGE_QUOTA=32769)
recovery_profile=(SHARED_BINDINGS=2 SHARED_SLOTS_256=2 SHARED_SLOTS_1024=0 SHARED_SLOTS_4096=0 SHARED_SLOTS_16384=0 SHARED_TASKS=128 SHARED_SCRATCH=32 SHARED_ACCEPTED_UIDS=32 SHARED_TASK_QUOTA=64 SHARED_SCRATCH_QUOTA=16 SHARED_INODE_FACTS=1024 SHARED_INODE_QUOTA=512 SHARED_IMAGES=65536 SHARED_IMAGE_QUOTA=32768)
reject SHARED_RECOVERY_DEVELOPMENT=1 IMAGE=local/owner:abi3-recovery-development "${recovery_profile[@]}"
reject ABI3_DEVELOPMENT=1 SHARED_RECOVERY_DEVELOPMENT=1 IMAGE=local/owner:abi3-recovery-development "${recovery_profile[@]}"
reject ABI3_DEVELOPMENT=1 SHARED_DEVELOPMENT=1 SHARED_RECOVERY_DEVELOPMENT=1 IMAGE=local/owner:abi3-development "${recovery_profile[@]}"
reject ABI3_DEVELOPMENT=1 SHARED_DEVELOPMENT=1 IMAGE=local/owner:abi3-recovery-development "${recovery_profile[@]}"
reject ABI3_DEVELOPMENT=1 SHARED_DEVELOPMENT=1 SHARED_RECOVERY_DEVELOPMENT=2 IMAGE=local/owner:abi3-recovery-development "${recovery_profile[@]}"
reject ABI3_DEVELOPMENT=1 SHARED_DEVELOPMENT=1 SHARED_RECOVERY_DEVELOPMENT=1 IMAGE=local/owner:abi3-recovery-development "${profile[@]}"
reject ABI3_DEVELOPMENT=1 IMAGE=local/owner:abi3-development SHARED_DEVELOPMENT=1 "${profile[@]}" SHARED_SLOTS_16384=4294967295
reject ABI3_DEVELOPMENT=1 IMAGE=local/owner:abi3-development SHARED_DEVELOPMENT=1 "${profile[@]}" SHARED_INODE_QUOTA=513
# Image units are key cells, independent of snapshot handle cardinality.
for bad in SHARED_IMAGES= SHARED_IMAGE_QUOTA= SHARED_IMAGES=0 SHARED_IMAGE_QUOTA=0 SHARED_IMAGES=4294967296 SHARED_IMAGE_QUOTA=4294967296 SHARED_IMAGES=-1 SHARED_IMAGES=065538 SHARED_IMAGE_QUOTA=32770; do
 reject ABI3_DEVELOPMENT=1 IMAGE=local/owner:abi3-development SHARED_DEVELOPMENT=1 "${profile[@]}" "$bad"
done
original=$(sha256sum "$owner/gadget.yaml")
make -s -C "$owner" build IG="$work/ig" ABI3_DEVELOPMENT=1 IMAGE=local/owner:abi3-development SHARED_DEVELOPMENT=1 "${profile[@]}"
test -f "$CAPTURE/shared-header"
grep -qx '#define ENFORCE_EXEC_SHARED_NODE 1' "$CAPTURE/program.bpf.c"
if grep -qx '#define ENFORCE_EXEC_POOL_REAPER_CANDIDATE 1' "$CAPTURE/program.bpf.c"; then echo 'ordinary shared build selected the unqualified reaper' >&2; exit 1; fi
grep -qx '#define SE_PROFILE_BINDINGS 2' "$CAPTURE/program.bpf.c"
grep -q 'enforce-exec-shared-profile: "1"' "$CAPTURE/gadget.yaml"
if grep -q 'enforce-exec-shared-recovery:' "$CAPTURE/gadget.yaml"; then echo 'ordinary shared build gained recovery annotation' >&2; exit 1; fi
if grep -q 'ENFORCE_EXEC_SHARED_RECOVERY' "$CAPTURE/program.bpf.c"; then echo 'ordinary shared build gained recovery macro' >&2; exit 1; fi
grep -q 'enforce-exec-shared-slots-256: "2"' "$CAPTURE/gadget.yaml"
grep -qx '#define SE_PROFILE_IMAGES 65538' "$CAPTURE/program.bpf.c"
grep -qx '#define SE_PROFILE_IMAGE_QUOTA 32769' "$CAPTURE/program.bpf.c"
grep -q 'enforce-exec-shared-images: "65538"' "$CAPTURE/gadget.yaml"
grep -q 'enforce-exec-shared-image-quota: "32769"' "$CAPTURE/gadget.yaml"
test "$(sha256sum "$owner/gadget.yaml")" = "$original"
rm -rf "$CAPTURE"
make -s -C "$owner" build IG="$work/ig" ABI3_DEVELOPMENT=1 SHARED_DEVELOPMENT=1 SHARED_RECOVERY_DEVELOPMENT=1 IMAGE=local/owner:abi3-recovery-development "${recovery_profile[@]}"
test -f "$CAPTURE/shared-header"
grep -qx '#define ENFORCE_EXEC_SHARED_RECOVERY 1' "$CAPTURE/program.bpf.c"
if grep -qx '#define ENFORCE_EXEC_POOL_REAPER_CANDIDATE 1' "$CAPTURE/program.bpf.c"; then echo 'recovery-only build selected the unqualified reaper' >&2; exit 1; fi
grep -q 'enforce-exec-shared-recovery: "1"' "$CAPTURE/gadget.yaml"
grep -q 'native supervisor and enforcement unavailable' "$CAPTURE/gadget.yaml"
grep -qx '#define SE_PROFILE_IMAGES 65536' "$CAPTURE/program.bpf.c"
test "$(sha256sum "$owner/gadget.yaml")" = "$original"
# Missing shared geometry must fail before archive BTF/compiler access.
if SHARED_DEVELOPMENT=1 ABI3_DEVELOPMENT=1 "$owner/build-archive.sh" /missing/btf /missing/clang /missing/bpftool local/owner:abi3-development "$work/shared.abi3-development.tar" > "$work/error" 2>&1;then exit 1;fi
grep -q 'SHARED_BINDINGS' "$work/error"
if env SHARED_RECOVERY_DEVELOPMENT=1 SHARED_DEVELOPMENT=1 ABI3_DEVELOPMENT=1 "${recovery_profile[@]}" "$owner/build-archive.sh" /missing/btf /missing/clang /missing/bpftool local/owner:abi3-recovery-development "$work/recovery.abi3-development.tar" > "$work/error" 2>&1;then exit 1;fi
grep -q 'ARCHIVE ending .abi3-recovery-development.tar' "$work/error"
echo 'PASS: explicit shared geometry and development-only build contexts'
