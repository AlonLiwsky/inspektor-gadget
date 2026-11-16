# Restricted-workload admission validation (2026-10-26)

## Environment and method

Disposable Debian 13 amd64 droplet, Linux `6.12.111+deb13-amd64`, BPF LSM,
Docker 26.1.5, containerd 1.7.24 and upstream runc 1.5.2. The host-only diagnostic
rule (mode 2) is used; production enforcement is unchanged. The Go harness is
built with the race detector. AppArmor and seccomp are explicitly unconfined in
these test containers, so their denials do not hide the capability boundary.
All profiles have no_new_privs; restricted init profiles assert SYS_ADMIN absent
from all five capability sets. The matrix is not a recommended deployment profile.

For the FD cases, a host-side test server passes an already-open host mount
namespace descriptor using SCM_RIGHTS. This deliberately removes procfs access
as a barrier. The server only passes a descriptor: it does not perform setns or
execute anything for the workload. The receiver keeps its container root usable
across the namespace switch. Its payload is a static diagnostic executable at
`/tmp/busybox`, not Alpine's dynamic busybox; this avoids missing host/container
ELF interpreters being mistaken for a policy denial.

## Outcomes

| Profile | Direct host-namespace entry and denied payload |
| --- | --- |
| Default Docker capabilities, received namespace FD | setns rejects with EPERM |
| Drop ALL, add SYS_CHROOT, host PID visibility | nsenter cannot access/enter the host namespace; this case also has procfs access checks |
| Drop ALL, add SYS_CHROOT, received namespace FD | FD receipt succeeds; setns rejects with EPERM |
| Add SYS_ADMIN + SYS_CHROOT + SYS_PTRACE, host PID visibility | Enters host namespace; payload bypasses the exception |
| Add SYS_ADMIN + SYS_CHROOT, received namespace FD, no host PID sharing | Enters host namespace; payload bypasses the exception |
| Same capabilities, clear effective set before another exec | Capabilities become usable again; payload bypasses |
| Restricted init, then docker exec --privileged | Runtime grants an entrant that reaches host namespace; payload bypasses |
| Non-root UID 1000, no SYS_ADMIN, child user+mount namespace, received host FD | Child namespaces are created; setns into host rejects with EPERM; denied payload remains blocked in the child namespace |

Every profile first requires a real denied payload verdict in its container
namespace, and verifies release after unbinding. Successful bypasses require the
payload's verdict in the **same cgroup** and host mount namespace. Restricted FD
cases require explicit descriptor receipt plus setns EPERM, so a failed socket or
missing test executable cannot count as a successful boundary. The child case
also requires telemetry proving the receiver ran in distinct user/mount namespaces
and that a separate payload exec there was denied.

## Interpretation

The result gives a concrete boundary for direct namespace entry: durable lack of
host SYS_ADMIN authority works even when the namespace descriptor is available.
Child user namespaces do not supply authority over the host's user namespace.

It also rejects three tempting admission shortcuts: checking only `privileged`,
checking only effective capabilities, and checking only container init state.
The trusted owner must control final workload privileges for later execs and
exclude delegation through host services/processes. These tests do not prove a
complete host-isolation policy or cover arbitrary runtime configurations.

See the [candidate admission contract](admission-contract.md) for proposed owner
requirements and unsupported cases. No production exemption or automatic
eligibility checker is implemented here.

## Validation evidence

The strengthened admission matrix passed three times with the Go race detector,
all eight profiles each time and no reported data races. The previous host-only
matrix also passed once with the updated event layout. Go vet, scoped lint,
strict static C compilation, and amd64/arm64 diagnostic BPF compilation passed.
No arm64 runtime or Kubernetes/CRI runtime test was performed in this spike.

Logs: [complete first strengthened run](admission-verified.txt),
[repeat outcomes](admission-repeat-summary.txt). The earlier exploratory setup
failures were fixed before these runs; they are not counted as passing evidence.

The disposable droplet and temporary cloud/local SSH keys were deleted after validation.
