---
title: enforce_exec shared engine kernels
sidebar_position: 910
description: >
  The exact kernel builds the experimental enforce_exec shared engine
  enforces on, and why every other kernel is refused.
---

The experimental `enforce_exec` shared engine (the product shared node) is an
allowlist: it enforces only on the exact AL2023 kernel builds it was qualified
on, and refuses every other kernel at agent start with a reported reason.

| Release | Plain AL2023 AMI release | EKS-optimized AMI release |
|---|---|---|
| `6.12.113-138.209.amzn2023.x86_64` | `al2023-ami-2023.12.20261026.1-kernel-6.12-x86_64` | `amazon-eks-node-al2023-x86_64-standard-1.35-v20261031` |
| `6.18.56-125.164.amzn2023.x86_64` | `al2023-ami-2023.12.20261102.0-kernel-6.18-x86_64` | `amazon-eks-node-al2023-x86_64-standard-1.36-v20261031` |

A build is identified by its vmlinux BTF sha256, GNU build-id and release
together. The build-ids come from the vmlinux of the AL2023 repo kernel RPMs
and were confirmed live from `/sys/kernel/notes` in G011 pass 2 (plain AMIs) and pass 2b (EKS AMIs). The outer failure-frame
symbol (`do_execveat_common.isra.0`) was first recorded by the 2026-11-09 preflight on the same AMIs; it was confirmed in the kallsyms symbol list on both pinned kernels in G011 pass 2 (`outer-symbol` rows) and pass 2b (identity `symbols` rows). Pass 1 ran the
qualification build; product-build admission and Ready on both pinned kernels
of the plain AMIs are proven (G011 pass 2, run g011p2-20261115t143731-5a41, 116 PASS / 0 FAIL).
The EKS AMIs carry the same kernel builds as qualified; EKS product Ready is
proven (G011 pass 2b, run g011eks-20261115t163442-6da1, 120 PASS / 0 FAIL): a default-build node-agent reached product Ready True on both.
Limits of that evidence: SELinux was Permissive, and the EKS AMIs carry taint
12288 (out-of-tree or unsigned modules), which is allowed (only the livepatch
bit is gated).

The rule is to keep nodes on these kernel builds: pin the AMI releases, with no
in-place kernel update, no automatic AMI upgrade and no livepatch. Any newer or
other kernel is refused until it is qualified and pinned in a new release.

The full statement, the reasons for the allowlist, the operational limits
(including that an agent crash leaves enforcement off until the agent
restarts, and the unproven configurations) and the future approaches are in
the
[shared engine README](https://github.com/kubescape/inspektor-gadget/blob/main/gadgets/enforce_exec/fullruntime/README.md#shared-engine-supported-kernels).
