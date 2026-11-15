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
and are not yet confirmed on a live boot; the pass 2 preflight will confirm them. The outer failure-frame
symbol (`do_execveat_common.isra.0`) has a single source, the 2026-11-09
preflight on the same AMIs; pass 2 logs the resolved symbol. Pass 1 ran the
qualification build: product-build Ready on the plain AMIs is pending pass 2.
The EKS AMIs carry the same kernel builds as qualified; EKS product Ready is
pending the EKS qualification pass (pass 2b).

The rule is to keep nodes on these kernel builds: pin the AMI releases, with no
in-place kernel update, no automatic AMI upgrade and no livepatch. Any newer or
other kernel is refused until it is qualified and pinned in a new release.

The full statement, the reasons for the allowlist, the operational limits
(including that an agent crash leaves enforcement off until the agent
restarts, and the unproven configurations) and the future approaches are in
the
[shared engine README](https://github.com/kubescape/inspektor-gadget/blob/main/gadgets/enforce_exec/fullruntime/README.md#shared-engine-supported-kernels).
