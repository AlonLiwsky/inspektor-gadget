# Candidate admission contract for a host mount namespace exception

This records the supported-scope proposal from the diagnostic spike. The
subsequent [native binding API](../../README.md#opt-in-restricted-bindings) now
implements the descriptor/credential checks for explicit owner-admitted bindings.
It does not discover or enforce future-entry/delegation guarantees. Strict cgroup
scope remains the default; there is no automatic helper exemption.

## Kernel boundary

Linux's mount namespace installation check requires `CAP_SYS_ADMIN` in the user
namespace owning the target mount namespace, plus `CAP_SYS_ADMIN` and
`CAP_SYS_CHROOT` in the caller's user namespace. Receiving a namespace descriptor
does not grant that authority. Creating a child user namespace grants capabilities
there, not in its ancestors.

Primary references:

- Linux v6.12 [`mntns_install`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/namespace.c#L5747-L5759).
- Linux v6.12 [`cap_capable`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/security/commoncap.c#L67-L100)
  and [`userns_install`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/kernel/user_namespace.c#L1338-L1364).
- [Capability sets and transitions](https://man7.org/linux/man-pages/man7/capabilities.7.html),
  [setns permission checks](https://man7.org/linux/man-pages/man2/setns.2.html),
  and [no_new_privs](https://docs.kernel.org/userspace-api/no_new_privs.html).

## Conservative initial scope

An opt-in implementation should require a trusted owner to establish all of the
following before enabling the exception for a binding:

1. The actual node host mount namespace is identified from trusted host procfs,
   held open, and distinct from the workload's mount namespace. A containerized
   agent's own PID 1 is not sufficient evidence of host identity. Keep namespace
   references for the binding lifetime; do not treat an inode as permanent identity.
2. Workload `CAP_SYS_ADMIN` is absent from **effective, permitted, inheritable,
   ambient and bounding** sets, and `no_new_privs` is set before workload execution.
   For the first supported profile, use rootful workloads initially in the node's
   user namespace; remapped/rootless initial layouts need separate validation.
   Creating descendant user namespaces does not itself require rejection under
   the kernel model, and the spike exercises one such transition.
3. Those conditions cover **every workload entrant**, including later runtime exec
   requests. Runtime bootstrap tasks are trusted setup code and may legitimately
   retain privileges before the runtime applies the final workload credentials.
   Reading the container init's `/proc/.../status` alone cannot establish the
   condition for future workload processes.
4. The workload cannot control privileged host processes or ask a privileged
   host service/runtime management API to create an unrestricted entrant or act
   on its behalf. This is part of the trusted-owner boundary, not something the
   mount namespace comparison authenticates.

This is a conservative sufficient candidate for the tested direct-entry path,
not a proof against every way to affect a host. `no_new_privs` prevents new
exec-derived privilege; it does not remove existing capabilities. Removing only
`CapEff` is inadequate because permitted capabilities can become effective again.
The bounding set alone is also not a complete admission decision; existing
permitted/inheritable capabilities and subsequent runtime-created tasks matter.

## Owner checks and unsupported cases

The owner needs trusted runtime process configuration and control over workload
entry. OCI exposes all five capability sets and `process.noNewPrivileges` in the
[process configuration](https://github.com/opencontainers/runtime-spec/blob/92249139eea7161e13745abd4cb6d0ea02a3227a/config.md#L286-L301).
Inspect live credentials as corroboration, not as a substitute for that contract.

For an initial supported profile, reject the **exception** when any of these
conditions apply:

| Input | Initial handling | Reason |
| --- | --- | --- |
| Privileged workload or `SYS_ADMIN` in any workload capability set | Reject | The tests demonstrate host entry without `privileged: true` when `SYS_ADMIN` is supplied. |
| Privilege escalation allowed or no_new_privs unknown | Reject | Capability restrictions must survive future executable changes. |
| Workload mount namespace equals the host, or host identity is uncertain | Reject | There is no distinct workload/host boundary to exempt. |
| Host-process control or runtime API delegation is possible | Reject | Direct namespace-entry checks do not constrain a privileged deputy. |
| Host PID sharing, host-userns `SYS_PTRACE`, or host management sockets | Exclude from the first supported profile | These complicate proving the preceding boundary; the spike does not prove all delegation paths. |
| Unknown final workload credentials or later exec privileges | Reject | The privileged-exec counterexample defeats init-only admission. |
| Rootless/remapped initial namespaces or unvalidated runtime layouts | Defer | No initial-layout runtime validation in this spike. |

Rejecting this exception does not require removing the ordinary binding: strict
cgroup-only enforcement remains available, with its documented bootstrap
compatibility limitations. An owner must not silently unbind a target or report
it protected under the restricted profile when eligibility is unknown.

Host PID visibility or a namespace descriptor alone does **not** grant permission
to join the host mount namespace. The stronger exclusions above are conservative
initial admission choices, not claims that every excluded setting directly causes
a bypass. Namespace handles were deliberately supplied to the restricted test
profiles and direct entry still failed.

[Kubernetes security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
can express capability drops and `allowPrivilegeEscalation: false`; it is useful
owner input, not proof that all conditions above hold. Docker's documented
[`exec --privileged`](https://docs.docker.com/reference/cli/docker/container/exec/#options)
requires explicit consideration: the spike successfully used it to override the
restricted init profile despite no_new_privs on the container.

## Integration decision

The evidence supports proceeding with an **opt-in restricted-workload prototype**
under this explicit owner contract, not enabling the exception by default. Before
production integration, define the owner-to-binding eligibility interface and
validate actual CRI/Kubernetes exec behavior. IG must remain independent of
Kubescape: node-agent can supply verified runtime/CRD facts, while standalone IG
needs an equally explicit supported-runtime contract. A boolean derived only
from `privileged: false` or init credentials would be misleading.

The diagnostic experiment itself added no production exception. The subsequent
native prototype accepts owner-admitted bindings with validated credentials and
namespace references; automatic owner eligibility, Kubernetes admission and
per-exec credential enforcement remain unimplemented. See [measured results](admission-results.md).
