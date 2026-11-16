# v5: separately named `unarmed-entry` case

Build-only candidate pending independent source and runtime review. This case
proves nothing merely by compilation. It does not relabel the legacy
`missed-entry` failures from run7/run8 as passes.

## Exact tested shape

All eight main links, including task_alloc, attach before the fork while
observation is disabled. The existing one-shot copy_thread diagnostic is attached
and authenticated to the held creator, nonce and distinct CPU. The target ID is
statted and the exact control write FD opened/compared to its pinned inode before
the trigger. An early release command is rejected with every state/row byte
unchanged before the worker is released from its actual blocked read.

The actual successful copy_thread entry must show disabled observation, the
same held creator/nonce, nonzero child identity, correct creator CPU, no exit,
timeout or release, and zero ownership/retained/error counts. On the pinned
kernel, task_alloc precedes copy_thread; the attached task_alloc observer returns
the prior result without mutation while disabled. This is **unarmed-entry
ownership-state equivalence**, not physical observer registration coverage.

Within the unchanged diagnostic bound (65,536 iterations AND 10 ms), the runner
retains the enable → real exact-EINVAL/fresh-live-barrier → sole initial inventory
(two INITIAL/UNKNOWN workers, zero owned counts) → fresh stable inventory and
exact refusal plus whole-row preservation → authenticated release sequence.
All checks, state reads and return-value checks remain executed. Only successful
printf diagnostics are suppressed from the pre-trigger switch through successful
release; no assertion is suppressed. Failure prints immediately with the last
actually read state snapshot, without an extra map read. The original initial-
count failure also dumps its exact snapshot. A summary of executed successful
checks is emitted after the interval. No retry or bound expansion occurs.

After real child-read and parent-wait witnesses, assertions require:

* physical row key equals the diagnostic child pointer;
* creator diagnostic key equals the inventoried parent key;
* fresh nonzero child cookie distinct from both initial cookies;
* LATE origin, sticky birth_uncertain, no alloc_seen/parent-cookie/owned birth,
  no false inflight decrement or refund, exactly one unowned completion;
* parent retains its cookie with no child/child_cookie token;
* child's own first syscall-exit has no preceding child syscall entry;
* prefix/history stay UNKNOWN, including byte preservation across re-inventory
  and a new strict refusal.

A replayed release is rejected with complete state/row preservation after the
child and parent are held. The existing core post-arming owned-fork positive and
preexec cases retain their assertions and behavior. BPF source and object are
unchanged, including every diagnostic limit and ownership gate.

## Reviewed wrapper selection

`run-disposable.sh BUILD NEW_EVIDENCE [CASE ...]` defaults to
`core unarmed-entry preexec`. Explicit selection accepts only `core`,
`unarmed-entry`, `preexec`, or legacy `missed-entry`; unknown and duplicate names
are rejected before evidence/cgroup mutation. Legacy `missed-entry` is opt-in,
not renamed, retried automatically or included in the default run. There is no
transport-side case substitution.

## Validation and limitations

Clang21 build/static analysis, both admitted archived BTF checks, host
qualification/receipt/PID/format tests and emitted errno-bytecode checks pass.
A pure host logger regression proves 1,000 quiet successes emit zero bytes while
failure output remains visible. A pure parser test executes only the wrapper's
argument-selection block and verifies defaults, explicit legacy selection,
duplicates and invalid/injection-like arguments. It never runs the wrapper.

The BPF object remains byte-identical to v3/v4:
`4622e66a216709cedd52bdb709b2aad154ada2659a39613cb56d03dbaf937f09`.
No BPF load/runtime, cloud operation, commit or goal-state mutation was performed
for v5. Existing snapshots and failed proof archives remain unchanged.

Still excluded/unproved: physical live-attachment latency/registration coverage,
dynamic CSS-visible-before-task_newtask race, kernel_exec coverage, complete role
history, and G018 closure. Failure within the fixed bound remains a failure.
