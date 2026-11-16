# Exact persistent-owner kernel matrix

The amd64 runtime and archive builder admit exact BTF artifacts only. Both still
require the existing architecture, BPF LSM, ftrace, sysfs provenance, size and
trusted-owner checks. A release string, Linux source SHA or similar configuration
is not an admission substitute. No arbitrary-kernel or arm64 support is claimed.

This is the persistent-owner matrix only. The shared engine's kernel builds
(two AL2023 kernels, identified by BTF sha256, release and GNU build-id) and
its identity check, exported for other sections as `VerifyKernel` and
`CheckKernelRuntime`, are in README.md, "Shared engine: supported kernels".

## Original artifact (preserved)

BTF SHA-256: `12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b`.
The original isolated proof and restrictions remain unchanged. Exact membership
and archive packaging tests continue to accept its archived BTF. The following
new runs do not claim that the original kernel was booted again.

## Kubernetes-capable configuration artifact, 2026-10-27

Linux source: `6b4b543fa18757297ac756a6fe6e64f506b7844a`, without source patches.
Release: `7.3.0-sandbox-exec-k8s+`, x86_64. Relative to the original configuration,
only FANOTIFY, FANOTIFY_ACCESS_PERMISSIONS, CFS_BANDWIDTH,
GROUP_SCHED_BANDWIDTH, IP_NF_TARGET_REDIRECT, NETFILTER_XT_TARGET_REDIRECT,
NFT_REDIR, NF_NAT_REDIRECT and LOCALVERSION changed. The resolved config diff,
build environment and complete artifacts were archived. The booted sysfs BTF
matched the built artifact; BPF LSM and ftrace were active.

| Artifact | SHA-256 |
| --- | --- |
| BTF | `759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51` |
| Resolved config | `689c3926be7a452047c3244baf7f6c0fabd734474ba79d588c7a13aedd3d3444` |
| bzImage | `bf9f302aa31dc438ef336f4ea1cef3ee4445569fcb963502f6a520788d017aec` |
| Boot/modules archive | `e0bce2772162785baea65ed5c3723ee23e9e5e257c2eb679c33a676730506edb` |

### Executed isolated upstream proof

The current source, exact BTF and Clang 21.1.8 built the actual BPF objects and
owner OCI archives. Repeating the same archive build produced identical bytes.
All selected tests below passed without Go test skips or verify-only substitution:

- Legacy `TestExecKernel`, `TestExecRuntime` and `TestExecTraceLSMCoexistence`:
  128 paths, final-rule allow/deny, mode/overlap/churn, actual OCI lifecycle and
  trace-LSM attachment ordering.
- `TestFullExecKernel`: **29/29** attached-image cases, including path, UID,
  argv, actor path, ancestor, stdin, image origin, filesystem classes, positive
  and negative controls, mixed audit/enforce ordering and default deny.
- `TestFullExecRuntime` and `TestFullExecRuntimeImage`: actual immutable OCI
  lifecycle, frozen maps, candidate refusal/last-good retention and fault state.
- Stdin, image-origin, filesystem ABI/runtime, root identity, role ABI/lifecycle,
  bootstrap gate ABI/runtime and inventory fixtures: real kernel-sensitive
  observation and lifecycle primitives, not merely compilation.
- `TestOwnerControlKernel`, `TestFullOwnerImageKernel` and
  `TestFullOwnerOCIRuntime`: qualified nonmutating cgroup barrier, real assembled
  persistent hooks, role histories, more than eight paths, capacity refusal,
  retained enforcement, reload/re-attestation and joined OCI teardown.
- `TestGateKernel`, `TestEpochRolesKernel` and `TestProgramSlotKernel`: real
  verifier/test-run coverage for publication, admission/drain and frozen slots.
- Public node-agent `TestFullBackendContainerdKernel`: authenticated containerd
  1.7.30/runc 1.3.4 lease with all **13 paths**, deny/audit/role inheritance,
  same-owner reload, **256-rule boundary including bitmap bit255**, actual strict
  CRI helper refusal and withdrawal. Final kernel counters were submitted=24,
  ringLost=0, observationErrors=0. Only this fixture's exact returned container
  and sandbox IDs were removed afterward; the CRI container list was empty.

The private Kubernetes watcher and actual OTLP exporter proof is **separate and
pending**. These upstream results do not establish private integration, general
runtime compatibility or daemon-outage behavior on this artifact. The optional
runtime outage test was not enabled. A supplemental filesystem run enabled actual hugetlb execution with a
cloud-provisioned hugepage pool: `hugetlb-memfd-exec mask=2 known=15 errno=1`
passed, in addition to the creation marker and backing checks.

### Evidence identifiers

The staged IG source was based on `f9467312a221885cf144aa3289df3b0260af25e9`
with only this exact matrix extension; BPF sources were unchanged. Public
node-agent source was `ed7151b10fc48f3e0bcfcc39181c20b6d11824f5`. Its candidate
proof binary used a separately archived temporary modfile pointing at the staged
IG checkout. No product module file acquired a local replacement. Published
consumers must use the subsequent canonical revision, not that proof modfile.

Evidence is archived under `/tmp/sandbox-gh-review/kernel-matrix-extension`,
with kernel provenance under the isolated proof's `kernel-k8s-artifact` directory.
These hashes identify the captured bytes; local artifact paths are not public
artifact hosting or substitutes for the actual logs.

| Evidence | SHA-256 |
| --- | --- |
| Candidate IG source archive | `242d3c8f7b25b9c016884f2a82976c296460c19679077479b8006fd8256d0579` |
| Full29 log | `edbd534f820552c450fd821be651dfec4e99dc97048127134adbd573bce2dd61` |
| Immutable runtime log | `3dc41b4155aea62f3be4e8b82a4a88d523c8f95c789ec4513c90b5cf2d3810da` |
| Legacy log | `3524a38f07c360638f1f4634057098ff3d7eea21054b21546b9a29c72c46f8fd` |
| Primitive log | `3a96bec71cb038faabee6e2c9450086b31a83b7db73a1a705c8c4d69c1243080` |
| Supplemental hugetlb exec log | `a85de4d8bf02e5d802133edc0386d3e672423413382f5657966d98721d550e75` |
| Persistent owner log | `44e9f9d16c14645cc1261110fa239873198d9ad09bf6aad9b7fb483a6615c72f` |
| Publication primitive log | `8ff22015cb647370b400ea2d6c964fd6b030e829ce288732e18bda42a5df32f5` |
| Public CRI log | `cdae9f42436954fc5b7cc157bef0340a11abae9b7eb22c2cea06a7c40713d5c1` |
| Public proof owner OCI archive | `aab9cb0ed88f1b287ef2673f8a5e5949c787ab09fa65ba5cec94ab50326f37c1` |

Local targeted race/vet checks and full pinned lint also passed. Packaging tests
against both archived BTF files exercise deterministic output and rejection using
a fake compiler; they are not the kernel execution proof described above.
