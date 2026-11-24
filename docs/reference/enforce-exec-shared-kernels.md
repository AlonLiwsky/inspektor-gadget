---
title: enforce_exec shared engine kernels
sidebar_position: 910
description: >
  How the experimental enforce_exec shared engine admits a kernel, and what
  that admission does and does not prove.
---

The experimental `enforce_exec` shared engine (the product shared node) is
one CO-RE object per profile for every kernel. It admits every x86_64 kernel
the same way, on probes run at agent start and while the agent runs, and
refuses any other kernel at agent start with a reported reason
(`ErrSharedNativeUnavailable`).

Admission checks (`fullruntime.SharedProductKernel`, exported for other
sections as `AdmitKernel`):

- architecture amd64;
- a readable identity: the vmlinux BTF sha256 (lowercase hex), a non-empty
  release and a lowercase-hex GNU build-id from `/sys/kernel/notes`. The
  identity is reported for status and logs; it is never matched against a
  list;
- `bpf` in the active LSM list;
- `kernel.ftrace_enabled=1` and no livepatch (`TAINT_LIVEPATCH` clear). Both
  are re-read at every readiness check (`CheckKernelRuntime`). Other taints,
  such as out-of-tree or unsigned modules, are allowed.

At start and while it runs, the node also proves:

- the object's own load checks every type, field, kfunc and attach target
  it uses (CO-RE relocation and the verifier);
- `FMODE_BACKING` and the overlay layout are probed live; a failed
  `FMODE_BACKING` probe refuses (image-origin facts are unavailable and the
  node is Degraded);
- a startup canary proves every attached program runs;
- a live witness latches NotReady when an exec or fork reaches its
  tracepoint without its LSM hook's mark, or when ftrace goes off.

What is not proved: hook ordering and verdict semantics across the exec
paths on a given kernel. There is no startup deny self-test: a test binding
would hold one of the node's two route slots. The manual product-load run
(`gadgets/enforce_exec/test/product-load`) checks Strict and Audit verdicts on
a chosen machine.

The root barrier (`gadgets/common/root_barrier.h`, wired into the product
objects) adds a start check of its own: `rootbarrier.Verify` checks each
barrier hook's signature and live link, then runs a self-test that sees
real `chroot`, `mount` and namespace operations denied, before the startup
canary. A failure leaves the node NotReady. It adds three preconditions:
the agent needs `CAP_SYS_ADMIN` and `CAP_SYS_CHROOT`, and the kernel needs
the `userns_create` LSM hook (Linux 6.1 and later). The admission checks
above do not probe that hook; without it the barrier program cannot attach
and the node does not start. The fullruntime README, "Root barrier", has
the details.

The product objects can be rebuilt from the repository:
`make enforce-exec-product-objects` rebuilds them in a pinned Debian trixie
container with the pinned toolchain (Debian `clang-21` `1:21.1.8-3~bpo13+2`,
`libbpf-dev` `1:1.5.0-3`, from one snapshot.debian.org timestamp) and
compares their sha256 with the pins; a CI job runs the same scripts. The
build compiles at fixed neutral paths (`/src/...`), so the objects are
byte-identical from any checkout and carry no build-host path.
`make enforce-exec-product-images` also packages each object into its
product gadget image (one image per profile) and compares the manifest and
index digests with `fullruntime.SharedProductImagePins()`. The images are
not published to a registry: the node-agent image build rebuilds them into
its `tracers.tar` and checks the manifest digest; the builder fails on any
digest that differs from the pins.

Limits every host must plan for (details in the README sections "Geometry
limits" and "Host contract"):

- at most 64 possible CPUs per host (hard limit): on a host with more (for
  example a 96- or 192-vCPU instance) the shared node is not started and the
  refusal is reported as `ErrSharedNativeUnavailable` (fail closed), so
  there is no shared enforcement on it;
- at most 2 enforced containers per node, and a fixed TASK quota per
  container (128 in the `g19pkg128` object node-agent uses). Threads count
  against it. A third binding is refused with `ErrSharedBindingCapacity`;
  TASK exhaustion is reported only node-wide, through the fail-closed rate
  witness;
- bind and publish before the container's init forks or execs; a Strict
  adoption refusal must fail the container start or report the binding
  unprotected (NotReady);
- withdrawal (including `Remove`) is terminal for that cgroup on the node,
  and the Audit/Strict mode cannot change on a running container: both need
  a new container;
- Strict needs the agent in the host pid and time namespaces;
- a mount over a path inside the container's root after adoption is not
  prevented (accepted residual; it needs `CAP_SYS_ADMIN` in the container).

After `kernel.ftrace_enabled` was set to 0, even briefly, the node can stay
Degraded (NotReady, "shared candidate credit at exit degraded", `stale=N`)
until the agent restarts: the `lsm/task_free` trampolines missed frees while
ftrace was off, and a later exit at a reused task address counts a stale
tombstone (`REAL_OWNER_EXIT_STALE`; `exit_credit.go`, `sharedLiveExitCredit.check`
in `shared_host.go`). This is expected and fail closed; recovery is to restart
the node-agent. `StopNode` reports the same error after a complete teardown.

The full statement, the operational limits (including that an agent crash
leaves enforcement off until the agent restarts, and the unproven
configurations) and the future approaches are in the
[shared engine README](https://github.com/kubescape/inspektor-gadget/blob/main/gadgets/enforce_exec/fullruntime/README.md#shared-engine-supported-kernels).
