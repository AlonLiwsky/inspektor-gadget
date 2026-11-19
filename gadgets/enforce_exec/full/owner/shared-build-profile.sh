#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Explicit shared DEVELOPMENT image geometry only; no inferred capacities.
set -euo pipefail
fail(){ printf 'shared profile: %s\n' "$*" >&2; exit 1; }
[[ $# == 1 ]] || fail 'output mode required'
case ${SHARED_RECOVERY_DEVELOPMENT:-0} in
 0) ;;
 1) [[ ${SHARED_DEVELOPMENT:-0} == 1 && ${ABI3_DEVELOPMENT:-0} == 1 ]] || fail 'SHARED_RECOVERY_DEVELOPMENT requires shared ABI3 development';;
 *) fail 'SHARED_RECOVERY_DEVELOPMENT must be 0 or 1';;
esac
case ${SHARED_DEVELOPMENT:-0} in
 0) exit 0;;
 1) [[ ${ABI3_DEVELOPMENT:-0} == 1 ]] || fail 'SHARED_DEVELOPMENT requires ABI3_DEVELOPMENT=1';;
 *) fail 'SHARED_DEVELOPMENT must be 0 or 1';;
esac
names=(SHARED_BINDINGS SHARED_SLOTS_256 SHARED_SLOTS_1024 SHARED_SLOTS_4096 SHARED_SLOTS_16384 SHARED_TASKS SHARED_SCRATCH SHARED_ACCEPTED_UIDS SHARED_TASK_QUOTA SHARED_SCRATCH_QUOTA SHARED_INODE_FACTS SHARED_INODE_QUOTA SHARED_IMAGES SHARED_IMAGE_QUOTA)
for name in "${names[@]}";do
 value=${!name:-}
 [[ $value =~ ^(0|[1-9][0-9]{0,9})$ ]] || fail "$name must be an explicit canonical integer"
 (( value <= 4294967295 )) || fail "$name exceeds uint32"
done
(( SHARED_BINDINGS > 0 && SHARED_BINDINGS <= 268435455 )) || fail 'binding/ticket geometry exceeds uint32'
objects=$((SHARED_SLOTS_256 + SHARED_SLOTS_1024 + SHARED_SLOTS_4096 + SHARED_SLOTS_16384))
cells=$((256 * SHARED_SLOTS_256 + 1024 * SHARED_SLOTS_1024 + 4096 * SHARED_SLOTS_4096 + 16384 * SHARED_SLOTS_16384))
(( objects > 0 && objects <= 4294967295 && cells <= 4294967295 )) || fail 'arena geometry exceeds uint32'
(( SHARED_TASKS > 0 && SHARED_SCRATCH > 0 && SHARED_ACCEPTED_UIDS > 0 && SHARED_TASK_QUOTA > 0 && SHARED_SCRATCH_QUOTA > 0 )) || fail 'task/scratch/catalogue geometry must be positive'
(( SHARED_BINDINGS * SHARED_TASK_QUOTA <= SHARED_TASKS && SHARED_BINDINGS * SHARED_SCRATCH_QUOTA <= SHARED_SCRATCH )) || fail 'reserved task/scratch quotas exceed pools'
(( SHARED_INODE_FACTS > 0 && SHARED_INODE_QUOTA > 0 && SHARED_BINDINGS * SHARED_INODE_QUOTA <= SHARED_INODE_FACTS )) || fail 'reserved inode quotas exceed fixed pool'
# Key-cell units include active/candidate/retiring evidence, not handle count.
(( SHARED_IMAGES > 0 && SHARED_IMAGE_QUOTA > 0 && SHARED_BINDINGS * SHARED_IMAGE_QUOTA <= SHARED_IMAGES )) || fail 'reserved image key-cell quotas exceed fixed pool'
if [[ ${SHARED_RECOVERY_DEVELOPMENT:-0} == 1 ]];then
 # Initial emitted-object fixture only. A broader recovered profile needs a
 # separately reviewed native budget and loaded-resource admission revision.
 (( SHARED_BINDINGS == 2 && SHARED_SLOTS_256 == 2 && SHARED_SLOTS_1024 == 0 && SHARED_SLOTS_4096 == 0 && SHARED_SLOTS_16384 == 0 && SHARED_TASKS == 128 && SHARED_SCRATCH == 32 && SHARED_ACCEPTED_UIDS == 32 && SHARED_TASK_QUOTA == 64 && SHARED_SCRATCH_QUOTA == 16 && SHARED_INODE_FACTS == 1024 && SHARED_INODE_QUOTA == 512 && SHARED_IMAGES == 65536 && SHARED_IMAGE_QUOTA == 32768 )) || fail 'recovery requires exact B2/T128/W32 source-only fixture profile'
fi
case $1 in
 defines)
  echo '#define ENFORCE_EXEC_SHARED_NODE 1'
  if [[ ${SHARED_RECOVERY_DEVELOPMENT:-0} == 1 ]];then echo '#define ENFORCE_EXEC_SHARED_RECOVERY 1';fi
  for name in "${names[@]}";do printf '#define SE_PROFILE_%s %s\n' "${name#SHARED_}" "${!name}";done;;
 flags)
  echo '-DENFORCE_EXEC_SHARED_NODE=1'
  if [[ ${SHARED_RECOVERY_DEVELOPMENT:-0} == 1 ]];then echo '-DENFORCE_EXEC_SHARED_RECOVERY=1';fi
  for name in "${names[@]}";do printf '%s\n' "-DSE_PROFILE_${name#SHARED_}=${!name}";done;;
 metadata)
  echo '  enforce-exec-shared-profile: "1"'
  if [[ ${SHARED_RECOVERY_DEVELOPMENT:-0} == 1 ]];then echo '  enforce-exec-shared-recovery: "1"';fi
  for name in "${names[@]}";do key=${name#SHARED_};key=${key,,};key=${key//_/-};printf '  enforce-exec-shared-%s: "%s"\n' "$key" "${!name}";done;;
 *) fail 'unknown output mode';;
esac
