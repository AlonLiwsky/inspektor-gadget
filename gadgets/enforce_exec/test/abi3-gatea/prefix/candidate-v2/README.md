# Attachment-prefix fixture — test-only, build-only evidence

**Not verifier/load/attach/runtime proof. Independent source/build review is
required before running `run-disposable.sh`. G018 remains incomplete.**

The fresh-object runner has three cases, with at most eight retained task rows:

* `core`: two actual pipe-blocked workers predate attachment. `/proc/PID/syscall`
  witnesses their exact blocked read FD, not elapsed sleep. Frozen nonce/admin
  identity and exact pinned target/control `cgroup.procs` nodes authenticate a
  one-shot session. Held task kptrs protect pre-existing physical identities.
  Observers attach unarmed, then enable; a successful-live-return
  `fexit/cgroup_kn_lock_live` receipt paired with **exact EINVAL** from the admin's
  negative-PID write precedes the single initial CSS all-thread inventory.
  Initially zero owned counts still fail the actual qualification predicate.
  Releasing only one worker qualifies only that task's same-cookie prefix, leaves
  the withheld worker unchanged and preserves UNKNOWN history bytes. A subsequent
  real fork must show allocation/reservation, owned `task_newtask`, child
  `ret_from_fork(fn == NULL)`, and the child's first actual `sys_exit`, with zero
  intervening child syscall entries. A later syscall cannot substitute for it.
* `missed-entry`: all programs load first. Main observers except `task_alloc`
  attach unarmed. An authenticated held creator on a distinct CPU enters a real
  fork; a one-shot successful `fexit/copy_thread` diagnostic stalls it after the
  missed allocation hook but before `cgroup_can_fork`. The admin attaches the
  genuinely missing link, enables, obtains the initial barrier, inventories and
  records actual negative qualification before release. The diagnostic waits
  **at most 65,536 iterations AND 10 ms**, without a spinlock held. Timeout is
  FAIL and lets audit progress; no automatic bound expansion or retry. Diagnostic
  child pointers never grant ownership. Unowned birth sets sticky uncertainty,
  including if a CSS-visible child already had an initial-inventory row; neither
  its own sys_exit nor re-inventory can repair it. Counts cannot falsely refund.
* `preexec`: an exact owned `PTRACE_EVENT_EXEC` stop precedes observer attachment.
  Inventory is UNKNOWN; resuming to a syscall-exit boundary can qualify a prefix
  but never reconstruct the missing exec history. This is a negative case only.

`boundary_seen`, `prefix_qualified`, and `history_complete` are separate fields.
No code here creates complete history, roots, roles or lineage certificates.
Every relevant UNKNOWN still refuses strict readiness. The first inventory alone
may assign `INITIAL`; subsequent discoveries are `LATE`. Only exact owned
`task_free` deletion refunds a retained slot. User-space never resets counters.
The barrier is a cgroup-mutex receipt, **not universal fork quiescence**; ordinary
forks do not universally hold that mutex. `sys_exit` is the kernel trace boundary,
not proof of physical userspace return (ptrace/task work can follow it).

## Validation and limits

`build-local.sh` uses the existing local Clang **21.1.8** image, source read-only,
`--network=none`, read-only container root, no capabilities and no privilege
escalation. It compiles the BPF object and host runner with warnings as errors,
runs only a pure host eligibility truth table, parses both archived admitted BTF
artifacts for typed `copy_thread` and `ret_from_fork` prototypes, and archives
object BTF, disassembly and hashes. It **never executes the BPF runner**.

The live wrapper is prepared, not executed. It admits only the two exact BTF
hashes, records owned program IDs, uses fresh private cgroups and bounds runner
execution; cleanup targets only those cgroups and joins owned program absence
using the existing bounded cleanup utility. Unsupported required BTF hooks mean
NOTRUN, not a weakened substitute. Verifier acceptance and the feasibility of
completing the real missed-entry setup within the fixed bound remain unproved.

Pinned source provenance: `/home/mbertschy/ig15-kernel-source-evidence-20261028/prefix-20261029/REPORT.md`.
The actual x86 `ret_from_fork` source is lines 151–168, with syscall exit at 167.
UFFD and FUSE are disabled in both archived configurations; those proposals are
retracted. No kernel changes or new dependencies are used. Kernel-exec failure
coverage is explicitly **UNKNOWN/NOTRUN**: there is no approved trigger in this
fixture and no history-completeness claim. Broader Gate A/production integration
and full real-history qualification are still open.

## v2 review repair (v1 remains rejected)

`rejected-v1/` preserves the rejected source, manifest and build artifacts. Its
prior build success did not establish runtime readiness. The v2 repair adds:

* A permanently consumed INITIAL-origin window and a distinct successful-first-
  inventory gate. Failed initial scanning cannot be repaired by later inventory.
  Early boundaries are diagnostic only; INITIAL tasks may qualify at a later
  eligible boundary. Outstanding row-owned child/cookie blocks qualification.
  OWNED_BIRTH still requires its first exit, never a later syscall substitute.
* Nonwrapping mutation serial and active-writer bracketing across lifecycle,
  ownership, entry/exit and qualification. Mutation invalidates both receipts
  before row changes. Inventory is one bounded writer and publishes only if its
  serial is unchanged and no other writer overlaps. Overflow marks sticky error
  and refuses observation/certification without denying audit.
* Exact inventory-generation/serial/barrier refusal receipts. Every runner
  refusal obtains a fresh inventory, snapshots the ledger immediately before,
  checks exactly one new refusal (no overflow), unchanged strict-ready=false,
  ownership and history preservation. Diagnostic release must match the exact
  current refusal argument and all receipt stamps with zero writers.
* Signed 64-bit prior-LSM preservation using the already-proved ingress clamp;
  host errno cases plus actual emitted-bytecode regression checks. A child's
  actual blocked read and its parent's blocked wait precede stable snapshots.
* Wrapper cleanup ownership is recorded separately only after each successful
  cgroup creation; failed mkdir never authorizes cleanup of an existing path.

The dynamic CSS-visible-before-task_newtask INITIAL-row race remains code-covered
but runtime-untested. Pure regression predicates and artifact checks are not
substitutes for runtime interleaving evidence or independent v2 source approval.
