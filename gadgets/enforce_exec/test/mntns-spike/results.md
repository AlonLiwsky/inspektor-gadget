# Results: 2026-10-26

## Environment

- Disposable DigitalOcean amd64 droplet, Debian 13, kernel `6.12.111+deb13-amd64`.
- BPF LSM enabled; Docker 26.1.5 / containerd 1.7.24.
- Distribution runc `1.1.15+ds1`: one complete successful run.
- Upstream runc `1.5.2`, commit `29dd3dc`: three complete successful runs.
- Alpine image: `alpine@sha256:ee16d92f96db08d9d2d07da48555a27f3a69d8f0759021dbc601195ed0d2b5bd`.
- amd64 runtime tested; amd64 and arm64 diagnostic BPF compilation passed.
- Local Go build/vet and scoped golangci-lint passed. The harness has no Go unit tests.

## Observed outcomes

| Case | Cgroup only | Skip mismatched mount namespace |
| --- | --- | --- |
| Allowed container command | Runs | Runs |
| Container `/tmp/busybox` | Denied | Denied |
| Workload-owned `/runc` | Denied | Denied |
| runc 1.5.2 helper `/runc` in host mount namespace | Denied; requested allowed command still succeeds | Allowed |
| Privileged workload: `unshare --mount /tmp/busybox echo namespace-bypass` | Denied | **Runs: bypass** |
| Unbind then execute `/tmp/busybox` | Runs | Runs |

The runc 1.5.2 runs observed the helper in the host mount namespace and the
requested executable in the bound container namespace. This directly supports
the namespace-separation hypothesis for this environment. Continued command
execution after helper denial is consistent with the source-level fallback;
this experiment did not capture a syscall trace of the retry.

Representative events from the first runc 1.5.2 run:

```json
{"cgroup": 6791, "denied": 1, "expected": 4026532381, "mismatch": 1, "mntns": 4026531841, "path": "/runc", "path_result": 6, "pid": 2470}
{"cgroup": 6791, "denied": 0, "expected": 4026532381, "mismatch": 1, "mntns": 4026531841, "path": "/runc", "path_result": 6, "pid": 2544}
{"cgroup": 6791, "denied": 1, "expected": 4026532381, "mismatch": 0, "mntns": 4026532381, "path": "/runc", "path_result": 6, "pid": 2522}
{"cgroup": 6863, "denied": 0, "expected": 4026532381, "mismatch": 1, "mntns": 4026532444, "path": "/tmp/busybox", "path_result": 13, "pid": 3023}
```

## Decision

**Do not promote the unconditional mismatch exemption.** It removes the observed
helper denial but lets a privileged workload escape the path policy simply by
creating another mount namespace, without leaving the bound cgroup.

A narrower next experiment could exempt only the known host mount namespace,
enforce normally in the bound container namespace, and enforce or deny in every
other namespace. That would address the demonstrated new-namespace bypass, but
would still need tests for workloads able to join host namespaces, shared host
mount namespaces, namespace lifecycle, runtime variations and safe admission of
unsupported configurations. Mount-namespace identity is context, not proof of
trusted runtime identity. No general safe exemption has been established.

For restricted containers that cannot change/join mount namespaces, the observed
separation is promising. The spike did not establish all ways to enforce that
restriction, so it is not yet a supported production security contract.

The distribution-runc run did not show the same helper exec pattern as 1.5.2;
runtime version changes matter. No claim is made for crun, rootless or CRI exec.

The disposable droplet and temporary SSH key were deleted after validation.

Full logs: [distribution runtime](distro.txt), [runc 1.5.2](runc152.txt),
[two repeat runs](runc152-repeat.txt).
