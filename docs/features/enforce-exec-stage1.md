---
type: feature
status: draft
owner: "enforce_exec maintainers"
scope: repo
---

# enforce_exec stage 1: single CO-RE object with LSM-only exec outcome

## Purpose

Make the enforce_exec product engine less tied to one kernel build. One CO-RE object per size profile replaces the per-kernel objects. The exec outcome no longer depends on exec failure-frame kprobes, fentry or fexit. The fail-closed contract is unchanged: a Strict deny is EPERM, Audit never blocks once classified, a fault before classification denies, and an unknown kernel is refused (NotReady).

Status: draft PR (branch `universal/stage1-pr`, on main). It is qualified but not merged.

## Behavior

- **Exec outcome:**
  - begin: `lsm/bprm_creds_for_exec`;
  - success: `lsm/bprm_committed_creds`;
  - failure: a single `tp_btf/sys_exit` program that does the expensive work only on execve and execveat exits.

  There are 11 exec and fork links (6 BPF LSM, 5 tracepoint).
- **Kernel witness:** a sticky NotReady when any BPF LSM program is silenced, for example by `kernel.ftrace_enabled=0`.
  - It uses per-task marks in task storage.
  - StartNode refuses when the `ftrace_enabled` ksym does not resolve.
  - A mark that cannot be allocated refuses only Strict-bound forks/execs (`-ENOMEM`) and latches the node NotReady (Audit and unbound tasks are never blocked).
  - A startup canary must see every program run.
- **Admission:** exact per (kernel, object) pair. Each pinned kernel lists the product objects qualified on it. The probed-kernel override exists only in qualification builds (`enforce_exec_shared_qualification`).
- **Requirements:** `bpf` in the active LSM list (`/sys/kernel/security/lsm`), BTF, x86_64. The BPF source refuses to build for other architectures.
- **Cost:** about +63 ns per syscall node-wide over the base engine (AL2023 6.12, getppid median); fork+exec median measured +3.6% (337,401 vs 325,739 ns).
- **Qualified on** Fedora 43 6.17 and AL2023 6.12/6.18 in Strict and Audit; on Debian 13 6.12 and Rocky 10 6.12, exec allow/deny is qualified and image-origin facts are refused (fail closed because the `FMODE_BACKING` probe fails).
- **Known limits:**
  - the attach-order change in `nativeattach` is global;
  - a fork can get EPERM after a recursion-skipped sys_exit (Strict bindings only; Audit and unbound tasks never get EPERM). `NodeEnforcer.SysExitRecursionMisses` exports the kernel `RecursionMisses` counter;
  - some qualification steps run on test twins of the product object.

## Code

- `gadgets/enforce_exec/fullruntime/bpf/opaque_real_owner_child_candidate.bpf.c`
- `gadgets/enforce_exec/fullruntime/kernel_matrix.go`, `kernel_probe.go`, `shared_kernel_witness.go`, `shared_host.go`
- `gadgets/enforce_exec/fullruntime/README.md` (design detail, sizing, retry contract)
- `pkg/operators/ebpf/nativeattach/nativeattach.go`
