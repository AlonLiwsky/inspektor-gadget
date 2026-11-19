# Generic shared-scratch real-nesting fixture — BUILD ONLY

**Not Gate A completion. No BPF program has been loaded, attached or run for
this fixture. Both admitted exact kernels remain pending. Production integration
is not authorized by these files.** This fixture does not prove reentry through
the unchanged production bprm helper closure; that question remains UNKNOWN.

## Contract and trigger

Source-backed trigger (pinned Linux commit
`6b4b543fa18757297ac756a6fe6e64f506b7844a`, authenticated report
`/home/mbertschy/ig15-kernel-source-evidence-20261028/REPORT.md`):
`sleepable file_open -> bpf_get_file_xattr -> inode_permission -> ordinary
non-sleepable inode_permission LSM`. Inner never calls the trigger. The accepted
name is `user.ig15_probe`; missing xattr is fine because the permission callback
precedes retrieval. The inode must be ordinary, readable and non-private.
Earlier LSM/DAC denial can prevent the witness and is a failed test, not a pass.

Each fresh object authenticates exact pid/tid and nonce once in a syscall
program, records the physical current-task pointer and exact inode pointer from
a retained readable FD **before attachments**, and issues cookie 1 as its first
and only task cookie. The single runner thread stays alive and retains that FD
until links detach; no pointer survives this fixture lifetime. PID or timestamps
are not lifetime authority. Frozen config and nonce maps cannot be retargeted.
The inner also requires live outer-active state, matching physical task/cookie,
exact inode, nonce and MAY_READ. No generic injection hook or admin exemption.

Both callbacks use one non-LRU preallocated HASH, key `{cookie, sequence}`.
Sequence increments under the task-state spinlock with explicit MAX refusal;
no helper executes while locked. Only successful BPF_NOEXIST insertion creates
a local ownership token. Only that token permits deleting its exact key.
The outer keeps its row live through the kfunc. Dynptr descriptor is on stack;
**data is the writable outer HASH map value**, fixed 32-byte length, flags zero.
Outer/inner ownership sentinel checks and ordered event nibbles prove the
intended witness *only if the future runtime assertions pass*. Ordered nibbles:
outer acquired 1, inner entered 2, inner acquired 3/refused 4, inner finished 5,
outer resumed 6, outer released 7. The outer is looked up again after return.

Cumulative `uncertain` is diagnostic only. `op_fault` is reset for each affected
outer invocation; inner faults propagate within that still-active transaction.
Strict uncertainty denies that operation, audit preserves incoming LSM results.
The existing ingress signed-64-bit bounded errno helper is reused. Host arithmetic
tests cover every valid prior errno (-4095 through 0), both classes and faults;
this is **not** actual stacked-LSM prior-denial runtime proof.

## Prepared cases, not executed

- capacity 2: distinct active inner/outer identities, both releases, zero rows;
- capacity 1 audit and strict: recorded inner insertion error must be E2BIG,
  not an unexplained failure; failed inner insertion cannot overwrite,
  release or delete the live outer; exact final cleanup; audit allows, strict denies;
- fresh seed MAX-1: outer owns MAX, inner refuses increment, never wraps;
- fresh seed MAX: outer refuses before acquisition; audit allows, no rows.

No live reseed/reset: a second init is rejected. Boundary seeds are immutable
pre-attachment controls in a new object. There is no production history mutation.
The native runner requires root plus explicit disposable consent, checks actual
map-info HASH type, exact capacity, key size and zero flags (preallocated), and
validates live hook/kfunc BTF prototypes before load. The same standalone C ABI
checker passed against both archived exact BTF artifacts during build.
The wrapper restricts execution to the existing two exact BTF hashes and joins
only runner-recorded program IDs via `../cleanup-programs.py` after link/object
release, including runner failure. It does not delete unrelated resources.

## Local validation

Run `./build-local.sh`: adapts the approved local build wrapper, pins the installed
`ig15-local-build-only:clang21.1.8` image ID, non-root uid/gid, network none,
read-only root/source, all capabilities dropped, no-new-privileges. Writes only
ignored `build-output/`. Compiles BPF and runner with warnings as errors, executes
only the pure host return test, checks bytecode hook slots/return clamps/trigger
relocation, and records disassembly, object BTF, image identity and hashes.
**The runtime runner is never executed by either build script.**

Still required before any qualification claim: independent source review;
actual kfunc registration/allowlisting on both exact kernels (archived argument
ABI checks passed; live runner repeats the prototype check before loading);
verifier acceptance (including sleepable HASH-value dynptr lifetime and spinlock
use); load/attach; genuine nested event/order evidence and zero rows; exact owned
program absence; real prior-result and subsequent unaffected-operation regression
coverage. Build/static/source feasibility cannot substitute for any of these.
