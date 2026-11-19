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
- a new mount namespace: `clone`/`clone3` with `CLONE_NEWNS`, and
  `unshare(CLONE_NEWNS)`
- `setns` into a mount or user namespace, or with type 0 (any namespace)
- changes to the mount tree: `mount`, `move_mount`, `umount`, and the new
  mount API (`fsopen`, `fsconfig`, `fsmount`, `fspick`, `open_tree`,
  `open_tree_attr`, `mount_setattr`)

A 32-bit (compat) task uses other syscall numbers. For such a task, the
barrier denies every `CAP_SYS_ADMIN` use.

The barrier needs every hook, so it needs the `userns_create` LSM hook in
the kernel BTF (mainline Linux 6.1). It also needs BPF LSM in the active LSM
list and `kernel.ftrace_enabled=1`.

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
has a program on one of these hooks defines `ROOT_BARRIER_NO_<NAME>_PROGRAM`,
where `<NAME>` is the part after `rb_` in upper case (for example
`ROOT_BARRIER_NO_SB_MOUNT_PROGRAM` for `rb_sb_mount`). It then calls the hook
body first in its own program, right after the check of the previous verdict:

```c
__s64 prior = ROOT_BARRIER_PRIOR(2);
if (prior)
	return prior;
ret = root_barrier_task_alloc(ctx, clone_flags);
if (ret)
	return ret;
```

The barrier then denies before the gadget allocates any state.
`ROOT_BARRIER_NO_PROGRAMS` removes every `rb_*` program.

## Checks in Go

The `gadgets/common/rootbarrier` package proves that the barrier works before
the gadget reports Ready:

- `Verify` (or `VerifyMaps` for the maps of an instance) checks that every
  barrier program has a live LSM link, that BPF LSM is active and that ftrace
  is enabled, then runs a self-test that sees the barrier deny real
  operations. An error must refuse activation, and the gadget reports it as
  not ready, never only as degraded. The hook-signature check is not a kernel
  support claim: call `Verify` only after the gadget's own kernel check
  admitted the kernel.
- `Attest` repeats the link, BPF LSM and ftrace checks without the self-test,
  so a gadget can call it on each status read. It sees the state only when it
  runs: ftrace turned off and on again between two reads is not seen, so a
  covered task must not be able to write `/proc/sys`. It does not check the
  livepatch taint or the kernel build; the gadget's own kernel check must run
  on each status read too.
- `Hooks` lists the programs. `WithProgram` names the gadget's own program for
  a hook (a kernel name of at most 15 characters). `WithProgramID` matches it
  by kernel program ID, for a program whose name is longer than 15 characters
  or shares its first 15 characters with other programs. A gadget that has
  only the instance's maps calls `ProgramIDs` once after a verification
  passed, then attests by program ID on each status read.
- `Denials` and `Faults` read the counters. A nonzero fault count means the
  predicate could not decide for some task. The gadget should report a fault
  increase as degraded, and a `Faults` error as unknown, never as zero.

`gadgets/common/rootbarrier/kerneltest` is an opt-in kernel test for a
disposable BPF LSM node.
