# Conditional role bootstrap protocol — not implemented or proven

This note is a proposed next isolated proof slice, not a production readiness
claim. No freezer, repeated-scan convergence assumption, or root-on-missing-role
fallback is permitted. Existing roles spike proves particular storage/lifecycle
operations, not this coverage protocol.

## Source anchors and current gaps

Pinned Linux `6b4b543fa18757297ac756a6fe6e64f506b7844a`:
- `security_task_alloc` precedes fallible copies and tasklist publication.
- `copy_process` publishes task/thread PID links, then calls `cgroup_post_fork`
  and `trace_task_newtask`; success returns afterward.
- `kernel_clone` subsequently calls `trace_sched_process_fork` and wakes the child.
- `create_io_thread` calls `copy_process` directly, returning an inactive task;
  it bypasses `sched_process_fork`.

Source: https://github.com/torvalds/linux/blob/6b4b543fa18757297ac756a6fe6e64f506b7844a/kernel/fork.c

Therefore a `sched_process_fork`-only success protocol has incomplete coverage.
Propose `tp_btf/task_newtask(child, clone_flags)` for before-runnable inheritance,
using current task as creator. Its BTF ABI exists in the inspected header, but
attachment, trusted child pointer/task-storage operations and all caller paths
still require real verifier/lifecycle proof. `fexit/copy_process` must handle
error returns; do not release success admission before inheritance finishes.

A gate does not retroactively count a fork already past its admission hook when
tracking starts. Nor does hook attachment retroactively instrument an already
running function's entry. The late static task-newtask observer is essential.

## Counterexample to ungated scans

Pass A obtains a task-list snapshot containing unseeded P. Before P's seed is
published, P forks C; C's observer completes without an authorized parent seed.
P remains alive and is subsequently seeded successfully. Pass B snapshots C;
before C is seeded, C forks D, whose observer likewise completes empty. C is
then seeded successfully, but D was absent from B's snapshot. There are no scan
errors or exits. Any fixed number of ungated passes permits another frontier.
Capturing a parent later does not retroactively repair its existing child.

Also, userspace must not root-seed an absent **already activated** UID on a child
visible before inheritance completes. Merge-only inheritance would preserve the
wrong root rather than the creator's committed role. Only explicitly authorized,
not-yet-activated UID staging is eligible for bootstrap defaults.

## Conditional gated A/B protocol

The following is a proof candidate, conditional on the obligations below:

1. Attach mandatory task-newtask observer, task-alloc gate, failed-copy completion
   and task-exit cleanup before seeding. Keep a persistent binding owner/cookie.
   Publish closed exec and fork admissions. New owner-scoped task allocations
   fail explicitly while closed; preserve earlier LSM denials.
2. Drain all **tracked** exec transactions and tracked fork role writers. A fork
   token belongs to the original owner/cookie, not whatever cgroup is observed
   at completion. Successful token release follows child inheritance at newtask;
   failed copy_process releases once at fexit. No vfork-child exec wait is needed.
3. Authorize the exact runtime init task and prove the rooted identity of every
   inventory task. Stage only newly introduced UID roots under a unique attempt
   epoch. Existing activated UID values are never reset by userspace.
4. Inventory A must cover every qualifying task that remains alive throughout A,
   including every thread. Pin exact PIDFD_THREAD identities; reject incomplete
   listings, unexplained identity swaps, leader-death ambiguity, or inability to
   validate lineage. Task exits may conservatively abort the attempt. A PID/TID
   number or current cgroup membership alone is not authority.
5. Publish all A seeds, then an acquire/release **A-complete epoch barrier**.
   Inventory B stages all currently visible qualifying tasks. A fork observer
   which read an old parent seed necessarily had a child already tasklist-visible
   before that read, hence before the A barrier; B must cover that child.
6. Any child first visible after the A barrier has a pre-gate creator covered by
   A: a newly born child cannot create another child while fork admission is
   closed. Its observer must acquire the A barrier and merge the creator's
   matching staged seed before inheritance. Old-seed reads must not be silently
   accepted under a newer barrier. Preserve existing accepted child roles.
7. Validate coverage, identity and sticky fault conditions, publish the immutable
   candidate program/activation epochs, then reopen admissions. Missing authority
   is quarantine/failure, never inferred root. Ordinary fork/clone helpers can
   fail during this gate; document that disruption.

This is NOT a claim that existing `/proc` or BPF iteration already satisfies A/B.
It makes the remaining inventory theorem explicit. Arbitrary task-list snapshots,
PID recycling, nonleader exec/de_thread, disappearing thread leaders and cgroup
migration must be addressed before implementation can call Ready. Initial
untracked execs also require coverage analysis; a drain counter cannot count
pre-admission transactions retroactively.

## RootEpoch assessment

Proposed frozen policy `RootEpoch` at unused offset 24 plus task slots
`(UID, scalarRoleID, epoch)` addresses failed-candidate root contamination, if:
- Every candidate attempt uses a nonzero nonwrapping epoch. Staged entries confer
  no authority unless that exact UID/epoch is selected by the immutable program.
- A UID's first successful activation epoch is preserved across revisions,
  withdrawal/re-addition and any owner recovery retaining task state. Changing
  RootRole never reroots an already activated UID.
- A new attempt may replace an unactivated same-UID epoch, not a historical
  accepted epoch. Current-policy absence alone does NOT prove an epoch was never
  activated. The native historical activation registry must retain that fact.
- Forks may carry tagged staged entries, but actor matching ignores them until
  publication authorizes their epoch. Pending exec grants are never inherited.
- Semantic commit is explicitly defined at the irreversible publication/open
  boundary. A postcommit cleanup/status error cannot make an activated epoch
  appear unactivated. Crash/recovery must read authoritative published state or
  refuse recovery; never invent a new epoch over retained roles.

This epoch mechanism does not itself solve bootstrap coverage. Failed attempts
with different UIDs can also consume finite slots: reclaim only proven never-
activated entries, or report capacity failure. Do not evict accepted histories.
Roles in the full IR are stable **scalar IDs**: use UID-local equality/OR, never
the spike's `(roles & actor) == actor` bitmask predicate.

## Cgroup ingress is a separate boundary

An external creator, cgroup migration, CLONE_INTO_CGROUP, or runtime exec helper
must not acquire root merely by entering the bound cgroup. Record actual creator
lineage; quarantine unknown ingress. User-controlled migration must be excluded
or synchronously mediated. Trusted-runtime ingress needs a separate authenticated
admission protocol. Returning success from a fork observer cannot veto a child;
unknown state must cause subsequent enforcement denial and sticky NotReady.
Do not claim that task_alloc sees the eventual clone-into-cgroup target.

## Next proof slice and finite limits

Build only an isolated gate/newtask/fexit fixture first. Suggested bounds:
4096 tracked tasks per owner, 16 UID slots/task, 8 active UIDs, 128 lineage steps,
64 CAS retries and a 5-second bootstrap deadline. Physical deferred task-storage
reclamation requires separate allocation accounting; live-task counts alone are
not a memory bound. Limit/fault/timeout never publishes partial coverage.

Required adversarial cases:
1. Hold fork after task_alloc but before PID visibility across hook installation,
   A barrier and B; verify either authorized before-runnable inheritance or refusal.
2. Hold observer after reading old seed while B stages the visible child; verify
   no accepted-role overwrite and no lost newly activated epoch.
3. Reproduce the ungated P/C/D frontier; prove fork closure prevents continuation.
4. All copy_process failure paths after admission: signals, PID/pidfd/cgroup
   rejection and allocation failure. Prove exactly-once token/credit release.
5. fork/vfork/clone threads/io_uring workers; no success caller bypass, no vfork
   drain deadlock. Budget exhaustion must be observable and remain enforced.
6. PID reuse, leader pthread_exit, nonleader exec/de_thread, thread enumeration
   races and task exit at every pin/seed boundary. No quiet-run coverage claims.
7. Unknown cgroup ingress and clone-into-cgroup: never root by membership.
8. Candidate UID root A staged, publication fails, retry same UID root B: only B
   can become authoritative. Then activate A successfully, revise root to B:
   existing accepted role must remain A. Include postcommit error and re-add.

Stop condition for this slice: a reviewed coverage argument plus verifier and
controlled-race evidence for the exact hooks. Until then, no production bootstrap
or Ready claim is warranted.
