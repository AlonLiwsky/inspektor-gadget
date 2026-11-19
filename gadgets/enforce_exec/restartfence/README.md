# Exec restart fence

This independent IG object is not part of the exact-pinned product ELF.
It guards host cgroup-v2 **pod** subtrees when the agent has not attested
takeover. A fenced Strict exec returns EPERM. Audit execs are not blocked
by this guard and are counted. No timeout releases the fence.

## Integration order

1. Open and attest the fence before attaching the product engine. Use the
   embedded ELF from `Object` on a supported target. An unavailable object,
   missing/unsupported hook, pin mismatch, or failed registration is a
   readiness refusal, not a signal to continue without the fence.
2. Register the agent with a one-use kernel challenge. A new incarnation
   does not un-fence existing pods. Resolve the real host pod cgroup
   directory; `Bind` derives its kernel ID from the cgroup-v2 descriptor
   instead of accepting a numeric ID from the caller.
3. Move each bound pod only after the product backend has attested
   protection for that exact pod and committed generation. The caller
   serializes engine publication/withdrawal with this handover. A snapshot
   of the live incarnation alone does not attest product protection.
4. Arm and verify the fence **before** withdrawing any product route, not
   just before closing its links. The product hook must attach after the
   fence hook so that it evaluates first on the supported kernels. Close
   agent descriptors after teardown; close is not an uninstall.
5. Report cumulative per-pod outage counters and ring-buffer loss; reading
   them does not clear counters. Remove an exec-only row only after proving
   the pod cgroup ceased to exist. A stale container is not that proof.

The pinned exit hook arms on the authenticated process's last thread
(`signal->live == 0`), ahead of descriptor release. The LSM hook also
pre-arms on authenticated self-exec before CLOEXEC, and the exec tracepoint
arms idempotently. Once pre-armed, even an unsuccessful attempt can leave
Strict pods fenced; the same thread group cannot register itself again to
resume. The engine's link FDs must be close-on-exec, must not be passed
to other processes (including by pidfd or independent pins), and agent
threads must not unshare their FD table.

## Pins and uninstall

The standard path is `/sys/fs/bpf/kubescape/fence-v1/` (owner-only 0700
directories; use the host bpffs mount). The frozen manifest is published
last, and load verifies current boot, expected object, attached
links/programs and map identities. Pending or incompatible pins remain
in place; do not infer that an unknown set protects anything, or detach
it on an adoption refusal.

`Lift` is reserved for an explicitly authorized Helm pre-delete hook.
It latches retirement in the pinned state even if the running agent still
has open link FDs; the normal start/restart path cannot undo that decision.
The retired graph stays pinned as a tombstone. A subsequent installation
needs an explicit, separate retired-graph recovery procedure; normal
`Open` never treats retirement as permission to replace a pin set.

## Build and qualification

The AMD64 object is in `bpf/fence_amd64.elf`. Regenerate with
`go generate .` in this directory (clang-19, libbpf headers and
`llvm-strip`; see `bpf/build.sh`). The build is separate from, and
does not rotate, the product object's pins. Non-AMD64 embedded use
is currently refused.

The VM oracle under `qualification/` uses an independently selective
fixture backend, not the actual node-agent. It does not qualify product
integration, Helm publication, NRI start-gate hooks, or cloud behavior.
