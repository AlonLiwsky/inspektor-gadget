# Persistent binding owner — experimental implementation contract

## Legacy ABI2 reference and shared Go boundary

**The lifetime, publication, withdrawal and isolated-proof descriptions below
refer to the legacy per-binding ABI2 owner, not the shared-node replacement.**
The published shared Go foundation provides preparation, ownership/accounting,
receipt cleanup and bounded clean retry only. Its default startup/Ready paths
refuse activation, and the legacy publisher rejects development ABI3 activation.
See the [published-source boundaries](README.md#legacy-abi2-reference-and-shared-go-boundary).
No new wire ABI, accepted-generation shared publication/reload, native withdrawal
integration, physical Ready or shared kernel qualification follows from this
reference. Legacy allocation credits are not proof of shared kernel reclamation.

The [audit contract](README.md#audit-never-blocks-once-the-binding-is-classified)
applies: once the generation is classified, Audit never blocks the faulting exec.
Data faults are recorded against the generation and admission stays open; a
proposal quarantine or a failure to store the generation fault sets the
owner-wide fault, which closes admission until recovery. Admission failures
before the generation is known, including a publication's drained gate, still
deny. The `Owner.Check` heartbeat is read-only and never closes the gate.
No uncertain role grants and preservation of earlier LSM denials remain required.
These requirements are not evidence of shared kernel behavior. Enforcement
remains fail-closed, with last-good state and truthful failure/NotReady on
precommit refusal; recovery must respect the documented commit boundary.

One gadget/map lifetime owns one exact runtime container/cgroup identity. Policy
revisions do not replace that gadget. No production Ready claim follows from the
isolated fixtures or from this document.

## Publication and lifetime

- A native owner serializes all commands. Each attempt consumes a unique nonzero
  nonwrapping generation, including failed attempts.
- Active program is one frozen HASH inner map (key4/value288, max16384,
  NO_PREALLOC|RDONLY_PROG) referenced by an ARRAY_OF_MAPS slot. A second staging
  slot may expose the prepared immutable candidate to bootstrap commands.
- One shared mmap gate word counts BOTH admitted whole-exec transactions and
  fork-state writers. Preserve original owner/cookie/slot across migration.
  Successful fork release follows task_newtask inheritance; copy_process fexit
  releases failures. Exec completion follows role commit, never precedes it.
- Prepare/validate/freeze candidate maps and reserve historical names before
  closing admission. Close/drain before staging new UID roots. Abort keeps the
  old active map and accepted UID roles. Staged roots carry unique RootEpoch and
  confer no authority under another epoch.
- Atomic active-slot replacement is the commit boundary. Record successful UID
  epochs immediately, even if subsequent reopening/cleanup/status fails. Do not
  reinterpret a postcommit error as rollback. First binding publication occurs
  only after complete bootstrap/readiness; failed first-start owners are removed.
- Retain first successful UID epochs across revisions and removal/re-addition in
  this owner. RootRole edits do not reroot accepted state. Never reuse failed
  epochs. Identity history and task storage are not recreated on revision.
- Withdrawal closes/drains first, then atomically removes exact membership,
  retires admission, and only then stops the native gadget. A timeout reopens old
  admission unchanged and retains ownership. PreStop failure is NOT a hook-retention
  mechanism: do not call StopGadget before the drain succeeds.
- Native lifetime pins cgroup, proc/PID identity, mount namespace and any image
  backing evidence until hooks/state are retired. A changed root/image identity
  needs a new binding owner, never an in-place origin-index swap.

## Conservative lineage boundary

Initial historical adoption authorizes only the exact trusted runtime init
threadgroup and descendants whose actual creator lineage this owner observed at
task_newtask. Unknown pre-existing non-init-group tasks cause NotReady, not root
inference from cgroup membership, current PPid or namespace membership. This is an
explicit supported-matrix restriction, not a general existing-pod adoption claim.
An accepted UID's missing state remains unknown; root fallback is never implicit.

Use physical kernel task-storage cookies, not PID-ordered enumeration. Root
initialization requires the trusted init's exact physical cookie and proc lease
bookends. A kernel-only opaque group identity may be the TGID struct-pid object:
bpf_task_from_pid uses init_pid_ns, native proc directory holds that allocation,
and de_thread preserves its process-group identity. The pin prevents object-memory
reuse, NOT numeric PID reuse. Verify the native pin corresponds to the authorized
leader, retain it for the entire token lifetime, invalidate token before closing.
The kernel command must refuse a cookie mismatch rather than authorize another
root. Actual root-handshake/namespace/lifecycle fixture proof remains required.

## Bootstrap inventory

Use the proven syscall-program css-task iterator (flags0), not generic iter/task
or /proc's numeric ordering. Every identity is kernel-created, lifetime-unique,
and userspace update/delete is prohibited by map Freeze before commands/hooks.
Cookies prove identity only, not lineage.

Movement monitoring brackets cgroup_migrate and cgroup_update_dfl_csses. Arm once
through an authorized successful cgroup_kn_lock_live barrier while cgroup_mutex
is held, draining pre-attachment operations. Begin/end equal even nonwrapping
sequence is required around the entire css-task iterator, including destroy.
This detects controller reconfiguration, failed staging cleanup and ordinary
migration; css_set_move_task alone is insufficient.

With fork admission closed, phase A initializes eligible original tasks; publish
an acquire/release A-complete barrier; phase B covers already-visible late
children. Children first visible after A must merge the creator's authorized A
state before runnable. No ungated fixed-pass convergence assumption. Concurrent
foreign bootstrap and creator writes need version-checked whole-state merges;
never publish a stale working copy over accepted roles. Missing lineage, limit,
identity swap, movement or timeout refuses the revision without inventing Ready.
CLONE_INTO_CGROUP and external/runtime helper ingress are separately quarantined.

## Bounds and public events

At most8 active UIDs,16 retained UID slots/task,4096 lifetime task allocations,
128 lineage steps and a bounded bootstrap deadline are initial ceilings. Never
recycle credits on task exit merely from live counts: deferred reclamation is not
physical memory release. Native aggregate owner/map/history budgets are also
mandatory before production activation; a per-owner bound alone is insufficient.

Events keep the same owner/ring across revisions. Retain bounded generation
provenance or explicitly drop unknown retired-generation events; never decode
an old bitmap using a new plan. Public aggregate Revision remains plan revision;
PolicySet/Matches contain exact policy revisions, with incomplete fault matches
marked. Telemetry does not grant roles, alter enforcement, or become a process
creation event. Private OTel implementation remains out of scope.

## Assembled profile proof and state-map layout

The isolated assembled profile now exercises the real qualified native worker,
publication coordinator, all production hooks and the shared full fact reader.
Its bounded fixture covers a 13-path rule, role-gated fork/exec transitions,
retained epochs through RootRole edits, refusal of the seventeenth retained UID
with last-good enforcement, and resumption after a postcommit verification error.
Separate native OCI and embedding-specific containerd/CRI fixtures now exercise
lifecycle, shared budgets, a compound full-predicate policy and public verdict
provenance. These are pinned supported-environment proofs, not arbitrary
predicate combinations, runtime/kernel compatibility or production readiness.

The kernel rejected Freeze on TASK_STORAGE values containing a spin lock. The
owner therefore stores only a globally frozen 64-bit physical cookie in
`eo_task_ids`; a kernel-owned lifetime HASH contains the spin-locked `eo_task`
rows. Its native descriptor is read-only to UAPI. A frozen raw-byte zero source
initializes a fresh NOEXIST hash row before CAS publishes its identity cookie.
A competing initializer retains its unused row and consumed credit; neither can
reset the winner. A published cookie with a missing hash row is failure, never a
reason to reconstruct accepted state. Rows/credits never recycle, including task
exit and losing allocations. The 4,096-credit bound includes those rows.

Native code exclusively retains the operator-created handles; it must not reopen
maps through privileged alternate handles or install a writer program. UAPI
restrictions are not a boundary against a privileged administrator who can
replace the enforcer itself. Tests assert update/delete refusal on the actual
native task identity/state descriptors and immutable zero source.

## Native lifecycle ABI2 extension — isolated OCI validation

Owner ABI2 requires the native lifecycle and active-only EO_REATTEST command.
Re-attestation is legal only in IDLE for the exact committed active generation,
with closed/drained admission, zero new-UID mask and healthy structural state.
It validates physical membership/accepted rows without lineage adoption, root
initialization or successful-history mutation. Failed inventory clears readiness
but retains the active immutable map. Global movement receipts can be renewed
without allocating a replacement gadget or inventing new UID epochs. The native
Owner no longer sends EO_REATTEST from its `Check` heartbeat, because the drained
gate refused Audit execs and forks; publications renew the receipt instead.

The native Owner reserves aggregate capacity and exclusive scope before load,
verifies actual attachment receipts and candidate marker activity, and separates
IG startup from explicit policy activation. Pins and budget are released only
after the caller joins actual teardown and borrowed handles are closed. A failed
PreStop does not prevent IG from detaching: BeforeStop is a mandatory native
caller barrier, not an optional lifecycle hook. The ABI2 native OCI fixture passed four isolated runs, including real event
bitmaps, unknown-ingress refusal/recovery and late-start teardown. Its runtime
lease is synthetic: containerd/CRI validation and the connected node-agent
backend remain separate requirements. Historical ABI1 proofs alone do not
establish ABI2 behavior.

## Fault-preserving retirement

A rejected unknown-lineage runtime exec helper may quarantine this owner.
Structural faults remain sticky across policy revisions; do not infer an
exemption or re-bootstrap accepted roles. Exact-once exec/fork completion still
releases its claimed gate count even when a fault is latched. The fault remains
visible and admission/publication remains refused, but explicit retirement can
drain and detach safely. Kernel regression covers actual CRI helper refusal,
zero outstanding admissions, new-revision refusal and successful withdrawal.
