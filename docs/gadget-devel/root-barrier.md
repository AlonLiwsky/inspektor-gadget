---
title: 'Root Barrier for Enforcement Gadgets'
sidebar_position: 320
description: 'Shared BPF LSM programs that stop a covered task from changing its root or mount tree'
---

An enforcement gadget that decides by path must keep a covered task from
changing what a path means. `gadgets/common/root_barrier.h` adds BPF LSM
programs that deny these operations for a covered task:

- `chroot` and `pivot_root`
- a new user namespace
- a new mount namespace: `clone`/`clone3` with `CLONE_NEWNS`,
  `unshare(CLONE_NEWNS)`, and `setns` into a mount or user namespace
- changes to the mount tree: `mount`, `move_mount`, `umount`, and the new
  mount API (`fsopen`, `fsconfig`, `fsmount`, `fspick`, `open_tree`,
  `mount_setattr`)

A 32-bit (compat) task uses other syscall numbers. For such a task, the
barrier denies every `CAP_SYS_ADMIN` use.

## Using the barrier

The gadget defines `ROOT_BARRIER_COVERED(task)` and includes the header.
The predicate returns one of four values:

| Value | Meaning | Result |
|---|---|---|
| `ROOT_BARRIER_TASK_NOT_COVERED` | the gadget does not enforce for the task | allowed |
| `ROOT_BARRIER_TASK_COVERED` | the gadget enforces for the task | denied |
| `ROOT_BARRIER_TASK_FAULT_STRICT` | the predicate cannot decide, Strict class | denied, counted |
| `ROOT_BARRIER_TASK_FAULT_AUDIT` | the predicate cannot decide, Audit class | allowed, counted |

Any other value counts as `ROOT_BARRIER_TASK_FAULT_STRICT`.

The header defines one program per hook (`rb_<name>`). A gadget that already
has a program on one of these hooks defines `ROOT_BARRIER_NO_<NAME>_PROGRAM`
and calls the hook body first in its own program, right after the check of
the previous verdict:

```c
__s64 prior = ROOT_BARRIER_PRIOR(2);
if (prior)
	return prior;
ret = root_barrier_task_alloc(ctx, clone_flags);
if (ret)
	return ret;
```

The barrier then denies before the gadget allocates any state.

## Checks in Go

The `gadgets/common/rootbarrier` package proves that the barrier works before
the gadget reports Ready:

- `Verify` (or `VerifyMaps` for the maps of an instance) checks that every
  barrier program has a live LSM link and that BPF LSM is active, then runs a
  self-test that sees the barrier deny real operations. An error must refuse
  activation.
- `Hooks` lists the programs. `WithProgram` names the gadget's own program for
  a hook. `WithProgramID` matches it by kernel program ID, for a program whose
  15-character kernel name is not unique.
- `Denials` and `Faults` read the counters. A gadget reports a fault increase
  as degraded, and a `Faults` error as unknown, never as zero.

`gadgets/common/rootbarrier/kerneltest` is an opt-in kernel test for a
disposable BPF LSM node.
