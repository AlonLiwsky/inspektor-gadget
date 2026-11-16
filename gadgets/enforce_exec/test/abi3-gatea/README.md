# ABI3 Gate A — isolated feasibility fixture

**Test only. No production owner, evaluator, default image or consumer pin uses
these files.** Compilation is not verifier approval or a kernel execution result.
The fixture does not certify the proposed full ScopeSession architecture.

## Purpose and boundary

Exercise the kernel primitives before attempting the proposed ABI3 integration:

- One bounded, **preallocated** task-address HASH shared by sleepable
  `lsm/task_alloc`, `task_newtask`, non-sleepable `lsm/task_free`, a syscall
  command and the cgroup CSS task iterator. A lock protects each row.
- `BPF_NOEXIST` reservation before successful child creation, nonwrapping cookies,
  scalar-only parent transactions, and allocation-free `task_newtask` handling.
  `task_free` owns child-row deletion/refund. Failed `copy_process` releases only
  its parent's transaction; it never dereferences the possibly-freed child.
- Genuine later-LSM denial and post-security-hook `pids.max` failure, each requiring
  a new cookie, one cleanup and one failed-parent transaction completion.
- Deterministic 64-row saturation with local refusal, reap/reuse without clearing
  faults, an acquired kernel task reference held past child reap, and 512 fork/reap
  cycles requiring **observed** address reuse with increasing cookies.
- Iterator-protected row reads, invalid-flags iterator-creation failure with
  unconditional destroy-before-cgroup-release, and two fixed history/catalogue banks. Admissions
  and ARM share a dispatch lock, with no helper or nested lock in its critical
  section. A fork invalidates the staged serial receipt; failed ARM preserves the
  descriptor. Successful ARM selects one bank, immutable program tag and attempt;
  readback recovers the committed result and duplicate ARM cannot toggle it.
- Explicit scratch ownership: a second token cannot acquire or release another
  token's scratch; strict collision refuses the affected fork, audit collision
  allows it without corrupting the existing owner. Reverse LSM attachment order
  proves that a prior LSM denial stays effective with audit attached and no child
  reservation. The pinned trampoline short-circuits on denial; this does **not**
  prove that the later audit callback receives a nonzero incoming result.

The two frozen `programs` entries are **tags**, not policy evaluators or actual
map-in-map program payloads. The bank fixture uses one synthetic known UID/epoch/
role, not the production role catalogue, an unknown-history certification
algorithm, concurrent candidate leasing, or an exec completion state machine.
The stale-receipt test uses a completed real fork between staging and ARM; it is
not an exhaustive simultaneous-admission race test. Scratch collision is driven
by an explicit held token, not an induced nested LSM call. These limitations must
remain explicit in any proof report. They cannot replace the full architecture
review and integration qualification.

Only the seeded harness task and its successfully tracked descendants are
observed. The wrapper creates a dedicated cgroup and does not change ancestor
controller enablement. Audit tracking failure records taint; it does not invent
history or create an enforcement exception. No readiness claim is made.

## Build (unprivileged)

From the repository root, with Clang's BPF backend, libbpf development headers,
`pkg-config`, bpftool, Python 3 and a C compiler:

```sh
gadgets/enforce_exec/test/abi3-gatea/build.sh /tmp/abi3-gatea-build
```

The build checks that the compiled `held_ref.task` BTF is a pointer to a `kptr`
type tag and then `task_struct`; a silently ignored annotation fails the build.
The build uses the repository's amd64 vmlinux declarations. CO-RE relocation and
all kfunc/hook verification still happen on the actual test kernel. Local build
success on a different kernel does not expand the supported matrix.

## Launcher cleanup regression (unprivileged)

```sh
gadgets/enforce_exec/test/abi3-gatea/run-disposable.sh --self-test-supervision
```

This starts a harmless child inheriting the runner log and an open file descriptor,
then deliberately exits its parent with status 42. It uses the actual launcher
function, requires the EXIT trap to run promptly, and uses a Linux subreaper to
prove the child was terminated and reaped. It loads no BPF and creates no cgroup.
Runner output goes directly to a regular log file: an inherited stdout cannot keep
a `tee` pipeline open and prevent cleanup. Inspect `runner.log` for live output
from a separate terminal if needed.

## Run (disposable host only)

Prerequisites: root, amd64, cgroup v2 with `pids` already enabled in the root's
`cgroup.subtree_control`, BPF LSM, kernel BTF, bpftool, libbpf compatible with the
built runner, Bash and coreutils. **Never run this on a production host.**

The wrapper accepts only the two BTF SHA-256 identities in
[`KERNEL-MATRIX.md`](../../fullruntime/KERNEL-MATRIX.md). Recover their exact
archived boot/config/module artifacts; a newly rebuilt kernel with a different
BTF hash is not one of those artifacts. There is no hash-bypass option.

```sh
IG_ABI3_GATE_A_DISPOSABLE=1 \
  gadgets/enforce_exec/test/abi3-gatea/run-disposable.sh \
  /tmp/abi3-gatea-build /var/tmp/abi3-gatea-evidence-NEW
```

Repeat separately on **each exact kernel artifact**. The evidence directory must
not already exist. Execution is bounded by a 180-second timeout. The wrapper
records source/object/binary and running-BTF hashes, kernel identity, verifier
output for every BPF program, assertions and counters. Failed verifier loading is
an architecture result, not a skipped test or permission to weaken the fixture.
The final trap kills only its newly-created cgroup, removes that cgroup, and
checks that every recorded BPF program ID has disappeared. No maps/programs are
pinned. Preserve the complete evidence directory and cloud ownership/cleanup
receipts before destroying the disposable machine.

## Current evidence

All six current isolated Gate A cases passed actual verifier/load/attach/runtime assertions and owned-program/cgroup cleanup on both exact admitted kernels. Durable evidence: `/home/mbertschy/ig15-gatea-proof-20261028-run2-215027Z/{README.md,matrix-results.json,FINAL-SHA256SUMS}` and `proof/final-all-proof/proof/`. Initial and ingress use `cleanup-v2`; publication uses `lineinfo-v4`. Each matrix entry reports wrapper status 0 and all owned program IDs absent. Proof applies to the archived source/build snapshots, not arbitrary later working-tree bytes. Exact live BTFs are original `12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b` and Kubernetes-capable `759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51`. Archived builds used actual pinned Ubuntu Clang 21.1.8. `cleanup-receipt.json` and exact API-404 logs confirm deletion of the newly owned droplet/key/tag by 22:29:39Z. Earlier failed attempts remain failed; later retries do not reclassify them.

G018 remains incomplete and production integration remains blocked pending real stalled audit-era ingress/ARM overlap, initial attachment-prefix qualification, real nested scratch ownership, narrow audit-fault/nonwrap regressions, maximum-eight publication proof and concrete resource ceilings. Full real-history semantic qualification remains required before production approval. These bounded primitive results do not certify full ScopeSession, owner, lineage, policy or consumer integration.

**Working-tree boundary additions are build-only, not covered by run2.**
The optional `IG_ABI3_GATE_A_BOUNDARY` cases `capacity-audit`, `cookie-max`,
`cookie-last`, `serial-max`, and `serial-last` each require a fresh object and
separate disposable wrapper run. Cookie/serial profiles inject boundary values
only through the authenticated one-shot seed; they never reset a live instance.
Capacity uses actual retained children. The cases exercise real fork reservation,
completion and owned task-free cleanup, check strict refusal versus audit success
with sticky uncertainty, nonwrap, preserved parent history/descriptor, and denied
certification. These are deterministic fault boundaries, not actual concurrent
or nested execution evidence. Observer-storage refusal and owned-delete failure
injection remain deferred pending a safe owned-cleanup design. Independent review
and fresh exact-kernel execution remain required for these changed bytes.

### Historical attempts (not reclassified)

The following records describe the evidence available at each earlier attempt;
pending/no-success statements are superseded only for the archived isolated cases
above, not for remaining architecture obligations or current working-tree edits.

Local compile, nonprivileged-run refusal, and the launcher early-failure cleanup
regression have been checked. **The first privileged
load on the exact Kubernetes-capable artifact failed in `ga_new`: the original
trailing `__kptr` annotation emitted no BTF type tag, so `bpf_kptr_xchg` correctly
reported `R1 has no valid kptr`. Moving the annotation to the pointee type fixes
the emitted BTF and is now build-regression checked. At that attempt, no successful privileged
load, attach, lifecycle test or supported-kernel proof was available.**

The actual failed cloud object was retrieved and checked, not inferred from the
locally built object: SHA-256
`c1d0665e212bf0b382895be5c32d940289dd3fa03a85b1475a9e40c3a9cebbf0`.
Its `held_ref.task` is BTF type 28, a plain pointer directly to `task_struct`
(type 51), with no `kptr` tag. It fails the new BTF regression as expected.
The replacement local object has the explicit pointer → `kptr` → `task_struct`
chain; it then required independent review and a fresh actual-kernel load.
The historical `/tmp/sandbox-policy-cloud/private-k8s-20261027-124021` and
`/tmp/sandbox-gh-review/kernel-matrix-extension` artifacts were absent when this
fixture was prepared. The first retry used a recovered, exact-BTF Kubernetes
artifact; this does not imply qualification on either artifact or recovery of the
second one. Old documentation is not substituted for new execution evidence.

The next exact-kernel load accepted `ga_new` but rejected `ga_command`: its
iterator-creation failure path released the cgroup without destroying the
verifier-owned iterator. Inventory now joins a common iterator-destroy path even
on creation error, matching the pinned kernel's [initialization/destruction
contract](https://github.com/torvalds/linux/blob/6b4b543fa18757297ac756a6fe6e64f506b7844a/kernel/bpf/task_iter.c#L1061-L1105).
The native harness now deliberately supplies invalid iterator flags, requires
`-EINVAL`, then requires a successful unchanged inventory. At that stage this error-path
regression was compiled but not yet executed on a kernel; the archived run2 initial
fixtures subsequently passed it on both exact kernels.

After the iterator fix, all six programs loaded and attached on the exact
Kubernetes-capable artifact. Preallocation, NOEXIST, CSS inventory, invalid-flags
cleanup, and successful fork/final-reference cleanup passed. The next assertion
failed because the fixture incorrectly assumed attachment order equals execution
order: the pinned [trampoline prepends links](https://github.com/torvalds/linux/blob/6b4b543fa18757297ac756a6fe6e64f506b7844a/kernel/bpf/trampoline.c#L918),
then executes them head-first. The denial must therefore be attached **before**
the allocator to exercise later-denial reclamation. The fixture now does so and
retains the same exactly-once cookie/free/failed-transaction assertions. Every
assertion logs the previous/current assertion snapshots (read with `BPF_F_LOCK`);
failure-path fork scenarios also log explicit pre-fork/post-cleanup snapshots.
This ordering correction then required a fresh kernel run; the archived run2
initial fixtures subsequently passed on both exact kernels.

### Program-release cleanup join

All three disposable wrappers use `cleanup-programs.py` after their existing
owned-cgroup cleanup. It polls only validated `PROGRAM_ID` records from that
run's three-field `PROGRAM_ID ID NAME` records in `runner.log`, sharing one monotonic 10-second deadline across all IDs and
queries. Only exit status 255, empty stdout, and the exact C-locale bpftool stderr
`Error: get by id (ID): No such file or directory` diagnostic proves absence.
Present programs are retried; timeout, malformed IDs, permission failures, and
other query failures fail closed. Queries never delete programs. Every attempt
is appended to `program-ID-after.txt` (stderr) and
`program-ID-after-stdout.txt` (stdout); cleanup results remain in `cleanup.log`.
The helper is included in each identity hash manifest. A cleanup failure makes
a successful runner fail but does not replace an already nonzero runner status.

Unprivileged checks (no actual bpftool or kernel access):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test-cleanup-programs.py
bash run-disposable.sh --self-test-supervision
bash -n run-disposable.sh ingress/run-disposable.sh publication/run-disposable.sh
```

The original run's one-shot cleanup failure remains evidence; delayed later
absence does not by itself prove its cause. The bounded join is a harness fix,
not a replacement for a separately reviewed real-fixture rerun. The reviewed
cleanup join subsequently passed the run2 initial, publication and ingress reruns
on both exact kernels. The original immediate program-115 cleanup failure remains
failed evidence despite later absence.

Classifier provenance: the separately captured `owned-115-absence-classifier`
query reports bpftool v7.7.0/libbpf v1.7, status 255, empty stdout, and exact
ENOENT stderr. The initial implementation's status-1 assumption was incorrect;
status 1 with identical text is now a failing negative control. The tests replay
all six actual initial PROGRAM_ID records; other-family records use synthetic
IDs and source-derived names/format, not claimed guest observations.
