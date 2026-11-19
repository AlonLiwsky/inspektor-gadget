# Host-mount-namespace-only experiment (2026-10-26)

## Question and rule

Can we avoid runc bootstrap denials without exempting every new namespace a
workload creates? Mode 2 exempts only a nonzero, separately recorded host mount
namespace. It enforces in the bound namespace and every other namespace. If the
bound namespace is the host namespace itself, the exemption is disabled.
Production enforcement is unchanged.

## Environment and validation

Disposable DigitalOcean amd64 VM, Debian 13, Linux `6.12.111+deb13-amd64`, BPF
LSM enabled, Docker 26.1.5 / containerd 1.7.24. The race-enabled Go harness ran
with distribution runc `1.1.15+ds1`, then upstream runc `1.5.2` (`29dd3dc`).
The upstream executable is the same SHA256-checked release used for the first
spike. Local vet/lint and amd64/arm64 diagnostic BPF compilation passed.
The final harness passed once with distribution runc and three times with runc
1.5.2, with no reported Go data races. Only amd64 runtime behavior was tested.
Full logs: [distribution](host-only-distro.txt), [runc 1.5.2](host-only-runc152.txt),
[two repeat runs](host-only-repeat.txt).

Three container profiles are tested: default Docker settings, `--privileged`,
and `--privileged --pid=host`. All remain in their original bound cgroup during
namespace changes. A host `/usr/bin/true` copy under a temporary `/tmp` directory
provides a real executable outside the four allowed directory prefixes.

## Outcomes

| Exec case | Cgroup-only (0) | Skip every mismatch (1) | Skip host namespace only (2) |
| --- | --- | --- | --- |
| Allowed command in container namespace | Runs | Runs | Runs |
| `/tmp/busybox` in container namespace | Denied | Denied | Denied |
| Workload-owned `/runc` in container namespace | Denied | Denied | Denied |
| Observed runc 1.5.2 helper in host namespace | Denied; requested allowed command still runs | Allowed | Allowed |
| Privileged `unshare --mount /tmp/busybox ...` | Denied | Runs (bypass) | **Denied** |
| Host-access workload enters host mount namespace and root, then execs denied host binary | Denied | Runs (bypass) | **Runs (bypass)** |
| Configure bound namespace equal to host, then attempt that host exec | — | — | Denied: exemption disabled |
| Unbind then exec copied workload binary | Runs | Runs | Runs |

The namespace-changing cases require the actual workload event, original cgroup,
namespace identity and expected decision. Exit status alone does not count as
successful enforcement. In particular, a failed `unshare` or `nsenter` setup
cannot masquerade as a denied workload. The host-target guard is a map-level
configuration test, not a full shared-mount-namespace deployment test.

The host-access attack uses:

```sh
# Container explicitly launched with --privileged --pid=host.
nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root /tmp/ig-hostns-denied-.../true
```

In mode 2 its exec is allowed in the host mount namespace while its cgroup is
still the bound container cgroup. The same exec is denied in mode 0. This proves
that the exception identifies a namespace, not a trusted runtime helper.

## Interpretation

**This closes the tested fresh-namespace bypass and removes the observed helper
denial. It is a stronger candidate than skipping every mismatch.**

It is not a universal helper-authentication mechanism. It requires a security
contract that protected workloads cannot enter the host mount namespace or
already share it. We demonstrated a violation with an explicitly host-accessible
privileged container; we did not demonstrate it for default restricted Docker
containers. Privileged host access is a substantially stronger prerequisite than
merely creating a new mount namespace.

A production proposal would need explicit scope/admission rules, trustworthy host
namespace identification from the actual node (not blindly an agent's PID 1),
namespace lifetime handling, tests for alternate runtime layouts and rootless/CRI
paths, and a defined behavior for unsupported targets. An optional restricted
workload mode may be viable; the experiment does not establish that contract or
justify silently adding the exception to all bindings.

The BPF and Go code remain an isolated diagnostic, with mutable test maps and no
changes to production gadget interfaces. See the harness README for reproduction.

The disposable droplet and temporary cloud/local SSH keys were deleted after testing.
