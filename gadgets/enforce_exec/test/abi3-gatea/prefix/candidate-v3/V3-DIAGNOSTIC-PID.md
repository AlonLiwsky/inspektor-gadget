# v3: diagnostic PID finalization after failed run5

This is a narrow fixture repair, not a runtime pass or G018 closure. The existing
v2 snapshot and failed run5 archive are unchanged.

## Evidence and dataflow

Authenticated Linux commit: `6b4b543fa18757297ac756a6fe6e64f506b7844a`.
Pinned source archive: `/home/mbertschy/ig15-kernel-source-evidence-20261028/prefix-20261029/`.
`kernel/fork.c` SHA-256:
`12e7d2d92ce22aab7cb0ff83b5f7fb4052c7e6fbb1acbd9626f109a88d172c9e`.

* `fork.c:2141` duplicates the current task. x86 `process.c:105–114` copies
  the task structure, including its then-current diagnostic PID.
* `fork.c:2299` invokes `security_task_alloc`; `2328` invokes `copy_thread`.
* PID allocation occurs at `2335`, and `p->pid = pid_nr(pid)` at `2394`.
* The typed-child `trace_task_newtask(p, clone_flags)` occurs at `2584`.
* Fixture `insert()` recorded `task->pid` during task_alloc. v2 `px_birth`
  finalized the correct pointer-keyed, cookie-matched row but never refreshed
  its diagnostic PID. Runner `row(born)` selects a snapshot by that diagnostic
  PID, so it could not find the newly assigned child PID.

The original/core runner log records actual child PID 1405 blocked in read,
parent PID 1404 blocked in wait4(1405), then three successful row reads followed
by `FAIL expected protected physical task row`. There is no raw row-value dump
proving the exact stale numeric PID in that run; the source ordering independently
establishes the stale diagnostic field defect. The three read rows are consistent
with retained physical ownership, not proof that all later assertions passed.

Unmodified failure archive:
`/home/mbertschy/ig15-gatea-proof-20261029-run5-prefix/proof/original-prefix-attempt1.tar.gz`
SHA-256: `6a5eb632d7784856ca2c656522a2c5a4c691905fafdd03772055781920528271`.

## Repair and regression

Read the typed child's finalized PID before taking its row lock. Update only the
row's diagnostic PID inside the already-existing exact physical-key, owned-cookie,
OWNED_BIRTH and alloc_seen match. The shared pure helper checks the nonzero cookie
again and writes no other field. PID remains diagnostic, never an ownership key,
qualification input, lineage certificate or root. No runner lookup fallback or
weakened assertion was added. Unowned birth retains its existing sticky UNKNOWN
path; late insertion already observes the assigned PID and requires no repair.

Host regressions exercise zero/inherited preallocation PID, mismatched cookie,
matching finalization, byte-for-byte preservation of physical key, cookie,
ownership, qualification and history, and no update for unowned cookie zero.
Clang21 build/static analysis, both archived BTF checks and emitted signed-errno
bytecode tests pass. BPF load/runtime remains NOTRUN for v3. Independent source
review is required before any fresh both-kernel retry.
