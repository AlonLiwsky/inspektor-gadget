# Runtime bootstrap investigation

## Findings (2026-10-26)

Alon's [arm64 report](https://github.com/kubescape/inspektor-gadget/pull/15#issuecomment-6399479960)
shows `/runc` denied in the bound cgroup before successful workload execution.
The following source evidence is pinned to runc v1.5.2 commit
`29dd3dc2b13b4123162e5fe132504bb4b15569f1`:

- [`prepareCgroupFD` and `startWithCgroupFD`](https://github.com/opencontainers/runc/blob/29dd3dc2b13b4123162e5fe132504bb4b15569f1/libcontainer/process_linux.go#L369-L458)
  start the helper inside the container cgroup. Any startup error can trigger a
  retry without `UseCgroupFD`, including an exec EPERM.
- [`setnsProcess.start`](https://github.com/opencontainers/runc/blob/29dd3dc2b13b4123162e5fe132504bb4b15569f1/libcontainer/process_linux.go#L460-L493)
  subsequently performs namespace setup and cgroup placement.
- [`newParentProcess`](https://github.com/opencontainers/runc/blob/29dd3dc2b13b4123162e5fe132504bb4b15569f1/libcontainer/container_linux.go#L502-L543)
  executes a sealed runtime copy through a file descriptor.
- [`CloneSelfExe`](https://github.com/opencontainers/runc/blob/29dd3dc2b13b4123162e5fe132504bb4b15569f1/libcontainer/exeseal/cloned_binary_linux.go#L215-L249)
  tries a readonly overlay before copying the executable. The
  [overlay implementation](https://github.com/opencontainers/runc/blob/29dd3dc2b13b4123162e5fe132504bb4b15569f1/libcontainer/exeseal/overlayfs_linux.go#L42-L108)
  opens the runtime basename at the root of a detached mount.

This supports both the fallback explanation and a host helper appearing as
`/runc`. It does not prove Alon's exact syscall sequence, nor establish that a
container's own `/runc` was executed. Reproduction should retain runtime debug
logs or syscall tracing alongside verdicts before calling that sequence confirmed.

## Decision

Keep enforcement unchanged. No safe generic exemption has been established:

| Candidate discriminator | Why it is insufficient today |
| --- | --- |
| Path, basename, argv or comm | Workloads can supply matching names; names do not authenticate host helpers. |
| Host executable inode | runc executes sealed copies using different mechanisms; the installed inode is not a sufficient model. |
| Namespace mismatch | Useful diagnostic, but not proven as an authorization boundary through every bootstrap stage and container configuration. |
| Cgroup membership | This is precisely the overlap between helpers and workloads. |

A possible future design is a trusted runtime handoff identifying the exact task
and permitted executable object, with authorization retired before workload exec.
It requires authenticated registration, task/object lifetime handling, bounded
cleanup, and adversarial tests for reuse, forks and repeated execs. This is an
option to investigate, not an implemented or proven exemption. IG's ordinary
post-discovery container cache does not provide that handoff.

## Regression boundary

`docker-bootstrap.py` checks audit/enforce behavior, allowed system commands,
denied copied workload executables, an unaffected container, and release on
shutdown. It also checks that a workload-owned `/runc` receives no name-based
exemption. It reports other denied paths separately; those events are candidates
for tracing, not authenticated helper identities. The `/runc` workload test can
produce the same path as a real helper, so path alone cannot distinguish them.

Repeat on each runtime/version and sealing mode of interest. Rootless operation,
crun and Kubernetes/CRI exec remain unvalidated. Passing through a runtime's
fallback is not evidence that the underlying compatibility problem is solved.

## Mount-namespace experiment (2026-10-26)

The [disposable-host spike](../mntns-spike/results.md) observed runc 1.5.2's
helper exec in the host mount namespace and workload execs in the container
namespace. Skipping mismatches removed helper denials and preserved normal
workload denials, including a workload-owned `/runc`. However, a privileged
workload bypassed that filter using `unshare --mount`, so it is not suitable
as a general exemption. Production enforcement remains unchanged.

The [host-only follow-up](../mntns-spike/host-only-results.md) closes that specific
new-namespace bypass and removes the observed helper denial. A workload given
access to the actual host mount namespace still bypasses the exception, as
demonstrated with `--privileged --pid=host` and `nsenter`. Any production proposal
must define and enforce that host-access boundary; the experiment does not add
an exception to production bindings.

The [admission-boundary matrix](../mntns-spike/admission-results.md) now validates
direct setns refusal without SYS_ADMIN despite a supplied namespace descriptor,
child user namespace behavior, effective-capability restoration and a later
privileged runtime exec counterexample. The [candidate owner contract](../mntns-spike/admission-contract.md)
requires durable capability restrictions and coverage of all workload entrants;
init-only inspection and `privileged: false` alone are insufficient.
