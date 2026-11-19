# Restricted binding integration validation — 2026-10-26

## Result

The native opt-in binding interface is integrated into the actual OCI-loaded
`enforce_exec` gadget and instance manager. Strict binding/CLI behavior remains
the default. This validates the IG integration; it does not implement node-agent's
SandboxPolicy adapter or automatically enforce the owner's future-entry contract.

## Environment

Disposable DigitalOcean amd64 droplet, Debian 13, Linux
`6.12.111+deb13-amd64`, BPF LSM enabled, Docker `26.1.5+dfsg1`, containerd
`1.7.24~ds1`, upstream runc `1.5.2` (`29dd3dc`), crictl `v1.32.0`.
Namespace ioctl validation ran on the real kernel, with production BPF objects
and native host code. BPF objects also compiled for arm64; no arm64 runtime test
of the new interface was performed.

The CRI plugin was enabled in the disposable containerd configuration. Sandbox
networking is NODE mode to avoid CNI, while workload PID/mount namespaces are
separate. Both test workload profiles use no_new_privs and drop all capabilities
except SYS_CHROOT. Seccomp/AppArmor are unconfined in these disposable profiles,
allowing a real child user/mount namespace transition rather than counting an
unshare setup failure as successful enforcement.

## Checks and observations

| Case | Result |
| --- | --- |
| Strict baseline on runc 1.5.2 | Helper `/runc` denial reproduced; allowed workload still runs. |
| Ineligible restricted candidate | Admission fails and old strict instance remains active. |
| Strict-to-restricted replacement | Both policies enforce during overlap; old instance removed only after readiness. |
| Allowed command after handoff | Workload verdict received; helper denial absent. |
| Denied copied executable | Actual workload denial in both Docker and CRI. |
| Workload-owned `/runc` | Denied verdict; no filename-based exception. |
| Child user/mount namespace | Namespace identity recorded before workload exec; actual blocked payload verdict required. |
| Unbound control in child namespace | Payload succeeds, establishing the setup works without policy. |
| Live second-container binding | Control becomes enforced, then is released by unbind; original target stays enforced. |
| Final cleanup | Denied payload runs again after StopGadget returns. |
| Namespace FD ownership | Original caller descriptors close after admission; controller retains one workload namespace FD; count returns to baseline after cleanup. |
| Actual runtime exec credentials | Both Docker and CRI execs report all five sets without SYS_ADMIN/SYS_PTRACE and no_new_privs set. |

The complete kernel suite passed three consecutive race-enabled runs after the
capability and descriptor assertion fixes. The production child-namespace test
was then added and the Docker/CRI integration cases passed three further
race-enabled runs. No races, failures or skips occurred in these passing runs.
Earlier exploratory test failures are not counted as successful validation.

Local runtime/kernel/CLI race tests, vet, scoped golangci-lint and diff checks
passed. The original kernel policy, reporting saturation, frozen-map, binding
churn and trace_lsm coexistence tests remain covered.

## Boundaries

The test owner controls container creation and every subsequent exec it issues.
Credential snapshots corroborate that contract; they do not establish it for
future external requests. No privileged exec request is allowed by that owner.
The separate admission spike demonstrated why such requests violate the contract.

Passing containerd CRI exec does not establish all Kubernetes RBAC/runtime paths,
all containerd versions, crun/rootless layouts, or the node-agent cache adapter.
No first-exec discovery guarantee, crash persistence, or generic runtime-helper
authentication is claimed. The actual node host namespace and container/namespace
association remain authenticated owner inputs.

Reproduce using [the kernel test guide](README.md#restricted-binding-integration).

[Passing run summaries](restricted-validation.txt) record the suite and final
child-namespace cases. Temporary cloud/local SSH keys and the disposable droplet
were deleted after validation; no enforcement program/map remained before deletion.
