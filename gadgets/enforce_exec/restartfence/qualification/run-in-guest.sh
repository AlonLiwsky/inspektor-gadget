#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${UK_PAYLOAD:?}" "${UK_OUT:?}" "${UK_WORK:?}"
(cd "$UK_PAYLOAD" && sha256sum -c SHA256SUMS) > "$UK_OUT/payload-verification.log" 2>&1
{
 uname -a
 cat /sys/kernel/security/lsm
 cat /proc/cmdline
 stat -fc %T /sys/fs/cgroup
 sha256sum /sys/kernel/btf/vmlinux
} > "$UK_OUT/facts.txt" 2>&1
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || { echo 'FAIL cgroup v2 absent' >&2; exit 1; }
if [[ $(stat -fc %T /sys/fs/bpf) != bpf_fs ]]; then mount -t bpf bpf /sys/fs/bpf; fi
cp "$UK_PAYLOAD/exec-probe" "$UK_PAYLOAD/fence-oracle" "$UK_WORK/"
chmod 0755 "$UK_WORK/exec-probe" "$UK_WORK/fence-oracle"
export FENCE_GUEST=1 FENCE_OBJECT="$UK_PAYLOAD/fence.bpf.o" FENCE_BACKEND="$UK_PAYLOAD/backend.bpf.o" FENCE_PROBE="$UK_WORK/exec-probe"
variant=$(cat "$UK_PAYLOAD/variant"); scenario=$(cat "$UK_PAYLOAD/scenario")
export FENCE_MUTANT="$variant"
if [[ $scenario != all ]]; then export FENCE_CASE="$scenario"; fi
set +e
timeout --signal=KILL 1000 "$UK_WORK/fence-oracle" > "$UK_OUT/oracle.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" > "$UK_OUT/oracle.exit"
dmesg > "$UK_OUT/dmesg-oracle.txt" 2>&1 || true
cat "$UK_OUT/oracle.log"
if [[ $rc != 0 ]]; then exit "$rc"; fi
if grep -Eq '(^|[[:space:]])(FAIL|SKIP)([[:space:]]|:)' "$UK_OUT/oracle.log"; then exit 1; fi
if [[ $scenario == all ]]; then
 for expected in graceful sigkill partial-move abi-skew cgroup-exit selfexec thread-selfexec failed-selfexec uninstall load-failure nonce; do
  [[ $(grep -cx "PASS $expected" "$UK_OUT/oracle.log") == 1 ]] || { echo "FAIL missing/duplicate $expected"; exit 1; }
 done
else
 [[ $(grep -cx "PASS $scenario" "$UK_OUT/oracle.log") == 1 ]] || { echo "FAIL missing/duplicate $scenario"; exit 1; }
fi
