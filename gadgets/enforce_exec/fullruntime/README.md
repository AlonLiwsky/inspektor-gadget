# Experimental persistent exec owner

## Legacy ABI2 reference and shared Go boundary

**The legacy per-binding ABI2 lifecycle below is not the shared-node activation
contract.** [Commit `dabee7d08`](https://github.com/kubescape/inspektor-gadget/commit/dabee7d08345752cada90c326e25cd7b6855d62d)
publishes ordinary-Go shared preparation, ownership/accounting, receipt cleanup
and bounded clean retry. Those paths and their selected Go tests do not establish
kernel reclamation, accepted-generation publication/reload or native withdrawal
integration for the shared replacement.

The published [`StartNode`](https://github.com/kubescape/inspektor-gadget/blob/dabee7d08345752cada90c326e25cd7b6855d62d/gadgets/enforce_exec/fullruntime/shared_node.go#L67-L72)
refuses startup; binding inspection cannot report protection.
[Full-image admission and `Ready`](https://github.com/kubescape/inspektor-gadget/blob/dabee7d08345752cada90c326e25cd7b6855d62d/gadgets/enforce_exec/fullruntime/shared_host.go#L64-L74)
also refuse shared activation (`Ready` is defined at
[lines 191–199](https://github.com/kubescape/inspektor-gadget/blob/dabee7d08345752cada90c326e25cd7b6855d62d/gadgets/enforce_exec/fullruntime/shared_host.go#L191-L199)).
The [legacy publisher](https://github.com/kubescape/inspektor-gadget/blob/dabee7d08345752cada90c326e25cd7b6855d62d/gadgets/enforce_exec/fullruntime/publication.go#L70-L74)
rejects development ABI3 activation rather than treating ABI2 publication as a
shared receipt. This boundary defines no new wire ABI. Shared native integration,
physical Ready and kernel qualification remain unavailable or unproved; the
legacy isolated matrix and lifetime-credit rules below do not qualify them.

This package contains the **legacy per-binding `Owner` profile** and the unfinished
shared-node `NodeEnforcer` replacement. The legacy profile provides the native
persistent owner, bounded whole-exec gate, publication coordinator and isolated
tests for frozen policy-map revisions. Its embedding supplies authenticated
runtime leases and public event provenance; readiness requires the explicitly
supported kernel/runtime environment. Its proofs do not qualify the shared-node
replacement.

## Shared-node implementation status and API contracts

`NodeEnforcer.Ready` depends on how the node was started:

- **Product node** (`WithSharedNodeHost`, a build without the
  `enforce_exec_shared_qualification` tag): `StartNode` admits only the exact
  pinned kernel builds and their pinned product objects (see
  [Shared engine: supported kernels](#shared-engine-supported-kernels)) and
  refuses everything else with `ErrSharedNativeUnavailable` and the reason.
  `Ready` returns nil, also with zero bindings, unless an attach receipt, the
  product reaper, a witness (credit at exit, exec capsule, birth park, facts),
  a fail-closed NotReady or Unknown, stopped health, a refused Strict namespace
  (the agent is outside the initial pid/time namespaces) or a kernel control
  re-read at each call (ftrace off, livepatch) fails it; every such error wraps
  `ErrSharedNodeNotReady`. The same NotReady inputs also gate product startup:
  a product node whose agent is outside the initial pid/time namespaces does
  not start at all (no Strict and no Audit bindings), rather than starting
  NotReady. `NodeEnforcer.Degraded` reports the Degraded inputs
  (fail-closed Degraded window, image ledger, refused adoption, revision
  reports, verdict loss, overlay layout); they never fail `Ready`. A binding is
  protected only if node `Ready` is nil and
  `SharedBindingStatus.Protected(committedGeneration)` is nil: not removed, no
  `Fault`, `Attached`, `RoutePublished` and not `WithdrawPending`, the
  committed `Generation`, and no refused adoption.
- **Qualification node** (`WithSharedNodeQualification`, tag only) and every
  other node: `Ready` **never reports Ready**. It returns a startup error when
  the host is absent, mismatched, incomplete or closing/closed, and otherwise
  returns `ErrSharedNativeUnavailable`. On the protocol-only path, routing,
  union evaluator adaptation, qualified history publication and required
  attachment receipts are not integrated, and protocol preparation and Go tests
  do not establish protected workloads.

The two start paths are mutually exclusive: a qualification build refuses
`WithSharedNodeHost`, and a product build ignores the qualification seam.
`se_publication_arm` is the only shared commit/withdrawal producer, and only from
an authenticated `cgroup_kn_lock_live` barrier. A syscall receipt is not that
producer. `se_arm_frame` is per-CPU scratch, not epoch authority. Shared exec
reads `se_epoch_bank` through the kernel-owned `se_epoch_index`. `SE_ARM_BIND`
reserves that index on an earlier barrier; commit only accepts an index that
already names the cell. The unread `se_accepted_epochs` hash is not that
catalogue. An isolated Clang 19 load of the arm, including index bind and bank lookup,
was accepted by local kernel `7.1.13+parrot7-amd64`. That is not the admitted
BTF/Clang 21.1.8 matrix, not Ready, reload integration, or kernel qualification.

- Private shared-object preparation uploads compiler-owned content only. It
  grants no root, snapshot or image qualification.
- `fullpolicy.CompileSharedPolicyCompact` and
  `fullpolicy.NewSharedSnapshotCompact` provide scalar/compact diagnostics, not
  memory admission or activation guarantees. The Limited compiler and private
  worker have conditional logical accounting, but complete producing-artifact
  qualification remains unavailable; see the scope below.
- The private operation context deliberately has `context.Cause(op) == op.Err()`;
  it does not propagate a custom parent cause. Providers must not retain it beyond
  the synchronous, joined operation. Joining retires logical ownership, not
  allocator/GC or scheduler resources.

### Product predicate admission (G020)

The product evaluator produces only some of the facts a `fullpolicy.Rule` can
test. A predicate whose fact is missing would evaluate UNKNOWN on every exec
(Strict denies, Audit reports unknown), so the product path refuses it at
admission. `BindingSession.Publish` (`SharedBindingPolicy.compile`) checks
every rule and exception against one table, `SharedProductFactSupport`
(`shared_product_facts.go`), before compiling anything. It refuses the first
unsupported predicate with `ErrSharedPredicateUnsupported`. The wrapped
`*SharedPredicateUnsupportedError` names the policy, the rule index (and the
exception index, if the predicate is in one) and the predicate kind. The
legacy per-binding engine (`fullpolicy.CompileKernel`, `Owner`) does not use
this table.

| Predicate (kind) | Kernel fact | Product support |
|---|---|---|
| `Actor.Role` (`actor.role`) | roles from the exact exec history (`se_exec_fill_roles_preclassified`) | supported |
| `Actor.UID` (`actor.uid`) | effective UID (`cred->euid`) | supported |
| `Actor.Container` (`actor.container`) | binding container name, staged in the snapshot metadata | supported |
| `Actor.Path` (`actor.path`) | actor path (UNKNOWN when deleted, not UTF-8, longer than 255 bytes or not under the binding root) | supported |
| `Target.Path` (`target.path`) | target path, per pass (same UNKNOWN rules; a memfd target is UNKNOWN with its own reason) | supported |
| `Actor.Ancestor` (`actor.ancestor`) | up to 16 ancestor paths, complete at the binding's init or the workload's edge | supported |
| `Target.FSType` (`target.fsType`) | filesystem class | supported |
| `Target.Argv.StdinIsPipe` (`target.stdinIsPipe`) | stdin is a pipe | supported |
| `Actor.FromImage` / `Target.FromImage` (`actor.fromImage` / `target.fromImage`) | image origin (`actor_image`/`target_image`) from the binding's sealed image index: 1 the file is backed by an indexed read-only lower layer of the container's own overlay; 0 not from the image (an upper or copied-up file, another filesystem, a foreign overlay); -1 UNKNOWN (no index, unauthenticated backing file, writable layer, memfd, overlay layout unavailable, any read fault). A FromImage policy is refused at publish without a sealed index | supported |
| `Target.Argv.Contains` / `Prefix` (`target.argv`) | argv | **refused for the PoC**: the stock-kernel product evaluator has no authoritative argv fact (documented limitation, follow-up issue) |

`Target.SetRole` is an effect, not a predicate, and is admitted. The table is
the only switch: the work that adds a fact producer changes its entry to
supported. `TestSharedProductFactProducerPins` fails when an entry is
supported but no producer source pin exists for it.

### Verdict events (G020, event ABI 1)

Every product object emits one event per evaluated exec pass (the first
pass and each `#!`/binfmt_misc interpreter pass), and one per fail-closed
fault, on the `verdict` datasource (ring `opaque_real_verdict_events`,
`SharedProfile.VerdictRing`, annotation `enforce-exec-shared-verdict-ring`;
image annotation `enforce-exec-shared-event-abi: "1"`). The layout is
`full/shared_verdict_event.h`: the legacy `enforce_exec_full` event byte for
byte up to `error`, then `exec_class`, `scope`, `exec_id`, `pass`,
`uncertain`, `facts_unknown`, `task_cookie` and `load_epoch`.

- **Correlation contract.** Consumers key an exec on `(load_epoch,
  task_cookie, exec_id)`, unique per node: `load_epoch` is the random
  nonzero epoch the agent sets per collection load (`task_cookie` restarts
  on every load), `task_cookie` is the
  exec'ing TASK's identity cookie (a node-wide sequence), `exec_id` that
  TASK's exec sequence, equal on every pass of one exec (`pass` 0, 1, ...).
  `exec_id` alone is NOT unique (each new task starts at 1). `host_pid` is
  informational only (pids are reused). `generation` and `scope` name the
  route publication (`SharedCompiled.Generation`); bit i of `matched_rules`
  is `SharedCompiled.Program.Rules[i]`. A fault event carries the exec's
  identity when its receipt is still present, 0 otherwise.
- **Verdict.** `deny && mode == 2` is exactly the LSM denial. `error` is
  0..3: an Audit UNKNOWN fact is `error 0` with `uncertain 1`; a Strict
  UNKNOWN fact (`error 2`) or role conflict (`error 3`) reports the class
  verdict `deny 1 mode 2`. Faults (user decision D1): Strict `deny 1 mode 2
  error 1`, Audit `deny 1 mode 1 error 1`, `pass` 4294967295, every
  `facts_unknown` bit. A prior LSM denial emits nothing.
- **Delivery never decides a verdict.** The verdict is computed before the
  event is reserved; a full ring loses the event (`KernelEventCounters`
  `Lost`), which labels the node Degraded only (D2), never NotReady.

### Conditional shared-worker qualification

The private worker covers only a **never-staged, generation-zero binding**. It
uses one joined operation for object compilation, union compilation and staging;
it does not establish accepted history, general reload or activation.

On the exact reviewed Go 1.27.3 Linux/amd64 source/tool/profile pins, the
[conditional composition](../fullpolicy/qualification/worker_composition.go)
derives these logical operation-owned terms:

| Term | Bytes |
|---|---:|
| Bootstrap `B` | 536 |
| Project phase maximum | 1,310,800 |
| Selected dependency maximum | 1,454 |
| Combined tail `T` | 1,312,254 |

The fixed reservation would be `B + T = 1,312,790`; object and union compiler
debits remain cumulative and separate. Package/library startup owners, including
the carrier and warmed type caches, are not charged again per operation. These
terms are not an allocator, stack, RSS or complete node-resource bound.

**Complete worker evidence remains unavailable.** `deriveWorkerTail` still
refuses, so the conditional calculation cannot issue a positive PREBUILD or
carrier. Both producer phases generate fresh lowering and typed-Go sentinel
checks bound to the selected snapshot, exports, profile/tools and runner
identity. The typed check does not certify arbitrary unsafe or assembly writes;
opaque-input disposition and final published-consumer/release provenance remain
separate requirements. Diagnostic checks against older published consumer pins
do not qualify the unpublished shared-runtime changes.

The [qualification tooling](../fullpolicy/qualification/README.md) keeps runner
source linkage `UNPROVEN` and native activation `NOT_QUALIFIED`. Approved
signed-image digest verification remains the external release/deployment trust
requirement; these tools do not establish it, and hashes alone are not
authentication. No positive descriptor or Ready state follows from these local
tools or their tests.

## Shared engine: supported kernels

### Statement

The shared engine (product node) enforces only on the same kernel builds that
were qualified:

| Release | vmlinux BTF sha256 | GNU build-id | Failure-frame symbols |
|---|---|---|---|
| `6.12.113-138.209.amzn2023.x86_64` | `0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82` | `1d135d67e6d0ea8f77d60a2984915eadd28a5fcf` | `do_execveat_common.isra.0`, `search_binary_handler` |
| `6.18.56-125.164.amzn2023.x86_64` | `d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee` | `884ed4548406a1461ac5fb658c0dffdd87f1b3b2` | `do_execveat_common.isra.0`, `exec_binprm` |

Sources: the build-ids come from the vmlinux of the AL2023 repo kernel RPMs
(the same packages the qualified AMIs carry); they were confirmed live from
`/sys/kernel/notes` in G011 pass 2 (plain AMIs) and pass 2b (EKS AMIs). The handler symbols come from the pass-1
runner. The outer symbol `do_execveat_common.isra.0` was first recorded by the 2026-11-09 preflight on the same AMIs (pass 1 resolved it from `/proc/kallsyms` without logging it). It was then confirmed in the kallsyms symbol list on both pinned kernels: the `outer-symbol` PASS rows in G011 pass 2, and the identity `symbols` rows in G011 pass 2b.

These builds ship in these AMI releases (the AMI IDs are the ones the
qualification runs used; IDs differ per region, the release names do not):

- plain AL2023 `al2023-ami-2023.12.20261026.1-kernel-6.12-x86_64`
  (`ami-0e8550404ae6ca4c6`) and `al2023-ami-2023.12.20261102.0-kernel-6.18-x86_64`
  (`ami-0516089d963059a51`): qualified (G011 pass 1, with the qualification
  build); product-build admission and Ready on both pinned kernels are proven
  (G011 pass 2, run g011p2-20261115t143731-5a41, 116 PASS / 0 FAIL);
- EKS-optimized `amazon-eks-node-al2023-x86_64-standard-1.35-v20261031`
  (`ami-0c50b8c0d6d72c152`, 6.12) and
  `amazon-eks-node-al2023-x86_64-standard-1.36-v20261031`
  (`ami-07ef7f0d9b6d0f123`, 6.18): the same kernel builds as qualified (the
  same BTF was recorded on both; the agent still checks the build-id and
  release at start). **EKS product Ready is proven** (G011 pass 2b, run g011eks-20261115t163442-6da1, 120 PASS / 0 FAIL):
  a default-build node-agent (one DaemonSet, the per-kernel image map) reached
  product Ready True ("Selected containers have active enforcement") on both
  AMIs. The EKS AMIs carry taint 12288 (out-of-tree or unsigned modules),
  which is allowed: only the livepatch bit is gated.

Identity is the BTF sha256 **and** the GNU build-id (`/sys/kernel/notes`)
**and** the release (`uname -r`); the BTF alone does not identify a build. The
node also requires x86_64, `bpf` in the active LSM list, `ftrace_enabled=1` and
no livepatch (`TAINT_LIVEPATCH` clear). Ftrace and livepatch are re-read at
every `Ready`. Ftrace is detected, not guarded: on both pinned kernels
`sysctl kernel.ftrace_enabled=0` is accepted while the node runs (no EBUSY),
and `Ready` reports NotReady ("ftrace is not enabled") at its next call
(G011 pass 2). On both pinned kernels, under a Strict Deny policy, a uid-1000
exec that returns 126 with ftrace on returned 0 (allowed) after
`ftrace_enabled=0`, and returned 126 again once ftrace was re-enabled and
Ready was nil (G011 pass 2, run g011p2-20261115t160735-f9e2). Ready had
already gone NotReady before that exec. Only this one exec was measured
(uid 1000, Deny fallback); nothing else about enforcement with ftrace off is
known, so treat a NotReady node as unprotected. This is an accepted, detected
limitation: only root can change the sysctl. The image is bound to the build as well: its failure-frame
`attach_to` targets must equal the pinned symbols and the loaded eBPF object's
sha256 (recorded by the eBPF operator for native owners,
`operators.NativeProgramDigestKey`) must be one of the pinned product objects
(`g19pkg64/128/256/512` of that kernel). Every other kernel or image is refused
at agent start (`StartNode`, `SelectSharedProductImage`) with an error that
wraps `ErrSharedNativeUnavailable` and names the reason. The pins live in
`kernel_matrix.go` (`sharedProductPins`) and `testdata/shared_product_pins.tsv`.

After ftrace has been disabled, even briefly, the node can stay Degraded until
the agent restarts. While ftrace was off the `lsm/task_free` trampolines did
not run, so frees were missed; a later exit at a reused task address then finds
an earlier lifetime's tombstone and credit at exit counts it stale
(`REAL_OWNER_EXIT_STALE` in `bpf/opaque_real_owner_child_candidate.bpf.c`).
`ExitCredit` (`exit_credit.go`) treats any stale tombstone as a fault, and
`sharedLiveExitCredit.check` (`shared_host.go`) keeps that fault until the
node stops: `Ready` stays NotReady ("shared candidate credit at exit
degraded", `stale=N`) and `StopNode` reports the same error after a complete
teardown. This is expected and fail closed (task tracking is incomplete after
an ftrace-off window); recovery is to restart the node-agent. It does not
always happen: it needs an address freed in the window to be reused before
the node stops (in about a quarter of the G035 QEMU runs).

**Rebuilding the pinned objects.** `bpf/build-product.sh`
rebuilds the eight product objects (`g19pkg64/128/256/512` for each kernel)
with the exact flag set of the qualification build, and `--check` compares
each sha256 with `testdata/shared_product_pins.tsv`. Build it in the pinned
Debian trixie container: the CI job `test-enforce-exec-product-objects`
does, and `make enforce-exec-product-objects` runs the same image and
scripts with docker. `bpf/install-product-toolchain.sh` installs every
package from one snapshot.debian.org timestamp, and checks the packages
that decide the bytes against `bpf/product-toolchain-debs.sha256`:
`clang-21` `1:21.1.8-3~bpo13+2` (its version string is in the object) and
its libraries, and `libbpf-dev`/`libbpf1` `1:1.5.0-3` (the headers).
`build-product.sh` refuses another Clang or libbpf-dev version. The
`vmlinux.h` of each kernel is committed xz-compressed in
`testdata/al2023-vmlinux/`; the decompressed sha256 is checked.

The current pins embed the absolute paths of the build that produced them
(a historical developer path for the repository and one for the headers),
in DWARF and BTF; the BTF line text and FWD type order depend on them. The
script therefore compiles at those exact paths, as real directories, which
it creates in the container (an existing tree there must have identical
source directories). Both paths are in one commented block of the script.
The next pin rotation (new objects, new pins, new qualification) moves to
neutral paths created in the container: `/src/inspektor-gadget` and
`/src/btf/<kernel>`.

The job only builds: **loading the objects on the two AL2023 kernels stays
a manual EC2 gate** (the product attached tests with
`IG_SHARED_PRODUCT_OBJECT`), because there are no AL2023 CI runners.

### Exported kernel check (other enforcement sections)

The identity check that gates the shared engine is exported for other BPF
LSM sections (`kernel_identity.go`), so they do not keep a copy of it:

- `QualifiedKernels() []KernelIdentity`: the pinned builds above
  (`Arch`, `Release`, `BTF`, `BuildID`), sorted by release.
- `VerifyKernel(qualified []KernelIdentity) (KernelIdentity, error)`: the
  start check. It admits the running kernel only if it is exactly one entry
  of `qualified` (architecture, BTF sha256, release and GNU build-id), `bpf`
  is in the active LSM list, `ftrace_enabled=1` and `TAINT_LIVEPATCH` is
  clear. The shared engine's own gate runs the same code over its pins.
- `CheckKernelRuntime() error`: re-reads ftrace and the livepatch taint.
  Call it at every status computation; it is never cached.

Every failure is a `*KernelCheckError` whose `Check` names the failed check
(`qualified-list`, `arch`, `btf`, `release`, `build-id`, `bpf-lsm`, `ftrace`,
`livepatch`) and whose message gives the reason. A read failure is a failed
check, and so is an empty list, a malformed entry (an empty field, a BTF
digest that is not 64 lowercase hex characters such as `"*"`, a non-hex
build-id) or a BTF digest listed twice. There is no wildcard and no way to
pass a check without a listed build. A section passes its own compiled-in
list, built from `QualifiedKernels()` or from entries with its own posted
evidence; configuration must never add an entry. If `VerifyKernel` fails, the
section must not load. If `CheckKernelRuntime` fails, the section is NotReady
and counts as unprotected: ftrace off stops BPF trampolines, so it is
detected, not guarded (see the measurement above).

### Why an allowlist

CO-RE relocates field offsets but cannot verify:

- hook semantics and ordering across the exec paths;
- the kprobe failure-frame symbols (`do_execveat_common.isra.N`, the handler);
- verifier acceptance of the 16-link, spin-lock object;
- exec-path behaviour changed by AL2023 backports under the same version
  string.

The costs are asymmetric. On an unproven kernel, Strict either fails closed
node-wide (an exec outage) or silently misses an exec path while reporting
Ready. A reported refusal is better than either.

### Support window and AMI pinning

The rule, not a calendar date: support covers exactly the builds above.
Nodes must stay on them. Pin the AMI releases listed above: no in-place
`dnf` kernel update, no automatic node AMI upgrade, no livepatch. A node that
moves to any other kernel build, newer or not, is refused until that build is
qualified and pinned in a new IG release. Support for a node ends when its
operator moves it to another AMI or kernel.

### Operational facts and unproven items

- An agent crash or restart leaves enforcement **off until the agent is
  restarted**: the in-kernel state dies with the agent's BPF objects. The gap
  is reported as Ready False. Enforcement is off between agent processes during
  a restart: about 85 s (6.12) and 88 s (6.18) observed on EKS (G011 pass 2b; the new agent needed about 77-78 s to reach Ready). A graceful stop reports `AgentStopping`; a crash restart was not exercised.
- **Unproven:** SELinux enforcing (the qualification ran Permissive);
  lockdown modes other than none; other BPF users beyond the synthetic
  coexistence tests; unsigned or out-of-tree kernel modules beyond the EKS AMIs'
  taint 12288 (allowed); arm64; any other AMI.
- Argv predicates are refused (D1). The AT_EXECVE_CHECK and RETIRING residuals
  (D3/D4) and the migration-out residual (`MigrationOutUnenforced`) apply.
- Limits of the G011 evidence: in-pod reads cover verdicts and self-status
  only, facts are shown by outcome, and the default build has no fact counters.
  The restart ordering of Ready versus re-protection is ordered by code but not
  decidable from the evidence at 1 s resolution. SELinux was Permissive. Selection of the per-kernel image map entry is evidenced only through the wrong-digest negative; the positive run shows the selected entry works, not which entry was chosen.

### Geometry limits

The geometry is fixed when the object is built; changing it needs a new
product object, new pins and a new qualification.

- **2 bindings per node** in every product object (`SE_PROFILE_BINDINGS=2`):
  at most two enforced containers per node. A third `Bind` is refused with
  `ErrSharedBindingCapacity`. A removed binding still counts until its route
  is recycled (its TASK credits returned), so a slot can be busy for a short
  time after `Remove`.
- **TASK and WORK per binding**: `g19pkg64` 64 / 8, `g19pkg128` 128 / 32,
  `g19pkg256` 256 / 32, `g19pkg512` 512 / 16. The manual EC2 product runs
  used `g19pkg128`. WORK bounds concurrent evaluations: 32 WORK give a burst of
  15 concurrent births without a fail-closed refusal
  (`ConcurrentBirthCapacity`).
- **A TASK is one task, so threads count.** Adoption adopts every thread
  in `cgroup.threads`; a container with more threads than the TASK quota at
  its first `Publish` is refused at adoption (`AdoptionIdentity`). After
  adoption, a fork or thread creation past the quota fails closed: under
  Strict the clone fails with `EPERM`, under Audit the new task runs
  unevaluated. So a Strict container at its TASK quota cannot start another
  thread or process.

How the host sees it:

- binding capacity: `Bind` returns `ErrSharedBindingCapacity`; report it as
  the container's NotReady reason.
- TASK capacity: there is **no per-binding reason**. Each refused (Strict) or
  unevaluated (Audit) birth is counted in the node's fail-closed rate witness
  (`quota-limit`), which `FailClosedHealth` turns into Degraded on any count
  in 60 s and NotReady above 0.1 % over 5 min, node-wide. A per-binding
  TASK-capacity reason would need a per-account witness; it is not
  implemented.

### Host contract: binding, mode and withdrawal

Every host must follow these rules; the node enforces them by refusal.

- **Bind and publish before the workload starts.** Adoption refuses any fork
  or exec of the cgroup while it runs, and each attempt fails the adoption
  (`AdoptionCloneRefused`). Bind and publish while the container's init has
  not yet forked or exec'd its workload (for example from the runtime's
  create hook), not after the container started.
- **A refused adoption.** Strict (`ErrSharedAdoptionRefused`, `Audit`
  false): the host must fail the container start or report the binding
  unprotected (NotReady). Audit: the start must not fail, but the route is
  withdrawn, so that container has no audit coverage for its lifetime; there
  is no retry.
- **Withdrawal is terminal per cgroup.** `Remove` withdraws the route too.
  A withdrawn cgroup is never bound or published again on this node: `Bind`
  and `Publish` return `ErrSharedBindingWithdrawn`. Report it as a terminal
  reason; coverage needs a new container (a new cgroup).
- **The mode is fixed per binding.** A revision that changes Audit to
  Strict or back is refused with `ErrSharedClassChange`. Changing the mode
  needs a new container; never switch a running container's mode.
- **Strict needs the host pid and time namespaces.** Unless the agent runs
  in the initial pid and time namespaces, Strict publication is refused and
  product `Ready` reports NotReady ("strict publication refused").

### Future work (not implemented)

1. **Startup self-test on an unlisted kernel:** load, probe execs, check hook
   firing and ordering, then enable.
   - Pro: broad coverage.
   - Cons: proves only the exercised paths (races, binfmt_misc, ptrace and rare
     paths stay unproven); needs a test cgroup on production nodes; adds startup
     latency; a false pass is a silent bypass.
2. **Audit-first, promoted to Strict after a clean period.**
   - Pro: no outage risk; reuses the fail-closed witness thresholds.
   - Cons: missed hooks look clean; the clean period is arbitrary; no protection
     meanwhile; promotion needs an operator.
3. **Targeted BTF matching** of the functions and types the object depends on,
   instead of the whole-vmlinux hash.
   - Pro: survives unrelated backports.
   - Cons: types do not prove semantics or call order; the dependency set must
     be complete and maintained; a gap is a silent bypass.
4. **Bulk kernel-family qualification** (stock-kernel matrix,
   kubescape/inspektor-gadget#27).
   - Pro: today's proof strength.
   - Cons: about an hour of EC2 per kernel; needs a pipeline that tracks vendor
     updates; the allowlist lags new AMIs.

The likely combination is (4) for support claims, with (3) and (1) only as a
pre-check, never as a Ready claim.

The remaining sections describe the **legacy per-binding `Owner` profile**,
including its lifecycle and historical isolated proofs, not `NodeEnforcer`.

## Legacy per-binding Owner support and security limits

This is the **legacy full persistent-owner profile**, not the
[simple path-only engine](../README.md). It currently admits only the two exact
custom **amd64** kernel artifacts in [KERNEL-MATRIX.md](KERNEL-MATRIX.md). Stock
distribution kernels and arm64 are not supported by this profile. BPF LSM and
ftrace availability alone do not satisfy its admission checks.

**The legacy owner does not target AL2023.** Its kernel matrix
(`SupportedKernelBTF`, `SupportedKubernetesKernelBTF`) and the archive
builder (`full/owner/build-archive.sh`) list only those two custom proof
kernels. On AL2023, or any other kernel, `NewOwner` still returns a handle,
but the owner refuses the gadget at start (`verifySupportedKernel`, before
it claims the binding), so the run fails and nothing is enforced: it fails
closed. AL2023 is served only by the shared product node (`StartNode` with
`WithSharedNodeHost`). A host that selects the legacy owner on AL2023 gets
that refusal. The legacy matrix will not be widened without qualifying the
legacy owner on those kernels.

### Audit never blocks once the binding is classified

**Audit never blocks once the generation is known.** After admission, the owner
classifies the exec by its generation's policies (`fe_execution_class`). For an
Audit-only generation, an evaluator error, a role-proposal error or a
post-admission observation fault never denies that exec. The verdict comes from
`fe_lsm_verdict`, the same rule as the ABI3 owner and the shared node. A fault
never trusts the partially merged decision mode. Audit also never grants
uncertain roles and keeps earlier LSM denials.

Every such fault is counted (`count(2)`). For an evaluator or proposal error, the
verdict event is a would-deny operational error: `error` is nonzero, `deny` is 1
and `mode` is 1. An observation-allocation fault emits no event. What happens
next depends on the fault:

- **Recorded against the generation; admission stays open.** An evaluator error,
  an observation fault, an errored decision and an authored role conflict are
  data faults: they set a bit in the generation's fault row. `Owner.Check` then
  reports the binding NotReady until a new generation is published, but the
  owner-wide fault stays clear and later execs are still admitted.
- **Counted and evented only.** Proposal work-buffer exhaustion (no `eo_work`
  buffer), or a missing task record at proposal time (practically unreachable
  after admission found the task), records no generation fault, so it causes
  no NotReady.
- **Owner-wide fault; admission closes.** A proposal state inconsistency
  quarantines the task and sets `EO_FAULT_STATE`. A failure to store the
  generation fault row sets `EO_FAULT_STORAGE`. The faulting Audit exec still
  runs, but admission closes for the owner until recovery, so later execs deny.

**Admission failures before the generation is known still deny.** Examples are
tracking, gate or storage faults, an owner-wide fault, and closed admission
during a publication (`Activate`, `Update`, `Resume`) or retirement. An
owner-wide fault set by an earlier
proposal quarantine or by a failure to store a generation fault (above) is one
such cause of later denials. With no generation there is no class, so these
stay fail-closed, even for an Audit-only binding. The shared node uses the same
rule. Strict, mixed and unclassifiable (invalid header or policy) generations
remain fail-closed on every fault. Do not fall open to hide an operational
fault.

**The heartbeat never closes admission.** `Owner.Check` is read-only: it never
closes the gate and never re-attests. A closed gate denies a not-yet-owned exec
and fails a fork in the bound cgroup with `EAGAIN` in every mode, Audit
included, so a same-plan refresh must not close it. `Check` re-verifies the
lease, pins, hooks and root, and reads the kernel state. It reports NotReady
on an owner-wide or generation fault, a movement-observer fault, a lost
readiness generation, a non-idle publication phase or a closed gate. The
movement receipt goes stale on any cgroup migration on the node; that is not
drift and `Check` does not renew it. No admission hook reads the receipt: exec
and fork in the bound cgroup validate the task's roles on every operation, and
an invalid task is denied and quarantined, which sets the owner-wide fault.
Physical re-attestation, under a drained gate, runs only inside a publication:
before the commit and again after the swap.

Follow-ups:

- Tests that need a new test binary and a VM run: a mixed Audit/Strict
  proposal-error case, an `Owner.Check` NotReady assertion after a data fault,
  and an injected observation-allocation fault.
- Classification timing: the legacy owner classifies after `eo_exec_begin`, in a
  separate read of the generation's policies. Classify inside `eo_exec_begin`, as
  ABI3 does, so one read admits and classifies.
- Work-buffer exhaustion and a missing task record at proposal time should
  record a generation fault. That is a BPF change
  and needs new archives and a VM run.

On a precommit candidate refusal, retain the last-good active policy and accepted
history. The embedding must report failure/NotReady rather than advertise the
rejected revision as active. Reopen admission only after safe rollback and phase
cleanup; failed rollback retains pending ownership and the closed gate until
recovery. Do not discard trusted state to force admission. A postcommit error
requires resuming the same committed generation, not rolling back to the old
policy.

The legacy mocked Go regression `TestLegacyOwnerUpdateBestEffortAdmission`
covers precommit refusal, drain cancellation and rollback failure/recovery
through `Owner.Update` with fake maps/control and a heap admission word. This is
protocol coverage, not native bootstrap, ABI3/shared activation, physical Ready,
Kubernetes status propagation or kernel qualification.

### Scope, runtime helpers and operator consent

An owner covers one **exact cgroup**, not its descendants. Creating or moving
into a child cgroup does not extend policy coverage. A trusted embedding must
exclude unsupported cgroup delegation and authenticate its runtime lease; the
node-agent strict admission contract includes cgroup-mount, capability,
namespace and seccomp restrictions. Movement observation detects changes and
invalidates the publication receipt; it is not a general mechanism that
prevents migration.

This profile has no `BindRestricted` host-namespace exception and no inferred
runtime-helper exemption. A `kubectl exec`/`docker exec` helper entering from an
unobserved creator can fail lineage checks and leave the owner NotReady once it
execs or forks, or refuse the next publication. A dormant one is not reported
by the read-only heartbeat. A closed gate can also reject exec or fork during
publication and retirement, never during a heartbeat. Allowing a
`/runc` path does not establish creator lineage or authenticate that binary.
Treat helper disruption as an explicit cost of opting into strict enforcement,
not as a reason to infer an exemption or reset trusted state.

Enforcement consent belongs to the host operator: global
`operator.oci.allow-enforcement` defaults to false. Image behavior metadata
declares what an image requests; it cannot enable that host setting. Image
verification, runtime admission and policy validation remain separate checks.

### Role-entry authoring and isolation

The current compiler requires a `setRole` rule to be an allow, but does **not**
require an actor constraint. An omitted actor (or an empty actor object) places
no restriction on who may enter the role: any matching successful exec can
propose that transition. For example, a rule targeting `bwrap` and assigning
`sandbox-helper` without an actor restriction can let the agent launch `bwrap`
itself to obtain that role. The executable's name is not an authorization proof.

Review each role-entry rule as a grant of future authority. Constrain the actual
authorized actor using meaningful role/path/image predicates where appropriate,
and check that untrusted code cannot first enter or control that actor. An empty
actor object is not a mitigation. This is authoring guidance, not a claim that
the current validator rejects broad grants. Role changes are policy-local and
commit only after successful exec; role labels received through telemetry do
not grant authority.

A constrained grant in the native `fullpolicy` Go IR can look like this (not CLI
YAML or a complete deployment policy):

```go
fromImage := true
policy := fullpolicy.Policy{
    ID: "sandbox-policy", Revision: "1", Mode: fullpolicy.Enforce,
    RootRole: "agent", Default: fullpolicy.Deny,
    Rules: []fullpolicy.Rule{{
        Name: "enter-sandbox-helper", Action: fullpolicy.Allow,
        Actor: fullpolicy.Actor{
            Role: []string{"trusted-launcher"},
            Path: []string{"/usr/libexec/sandbox-launcher"},
            FromImage: &fromImage,
        },
        Target: fullpolicy.Target{
            Path: []string{"/usr/bin/bwrap"}, FromImage: &fromImage,
            SetRole: "sandbox-helper",
        },
    }},
}
```

All three actor constraints must match. This assumes the launcher already has
authenticated `trusted-launcher` role history in this policy and cannot be
controlled or invoked as a confused deputy by untrusted code. The example does
not grant that initial role: its default root role stays `agent`, and missing
history is not authority. The image-origin predicate describes admitted backing
files; it does not prove that the process or its inputs are trustworthy. Review
how the launcher role is established and what it permits before using the grant.
A wildcard-only actor such as `Path: []string{"/**"}` still admits arbitrary
actor paths; its mere presence is not meaningful authorization.

The compiler currently accepts broad grants without an actor-warning API.
`TestRoleEntryAuthoring` and the ordinary Go/C parity cases document this behavior,
including deny/conflict suppression. They are not proof of kernel fact acquisition
or of the runtime's successful-exec role commit.

Roles are **not hostile-code isolation boundaries**. Processes can delegate work
through shared files, IPC, signals or services; containers in a pod commonly
share networking and may share storage. The combined authority reachable through
those channels is a threat-model upper bound, not a literal union performed by
the rule evaluator. Separate pods are a starting point for stronger separation,
but also require appropriate network, storage and service-access controls.

### Restart and recovery

Policy reload retains the same live owner's hooks and history; restarting the
gadget or its owning process does not. Maps and links are not pinned for crash
persistence. Once those resources close, enforcement and retained role history
are lost; a fresh owner cannot reconstruct them from event labels or current
cgroup membership.

Fresh bootstrap authorizes the exact trusted init threadgroup and descendants
whose creator lineage the owner actually observed. Arbitrary already-running
multiprocess containers are not generally re-adoptable; unknown pre-existing
tasks refuse readiness rather than receive inferred root roles. See the
[conservative lineage contract](OWNER-ABI.md#conservative-lineage-boundary).
Withdrawing a faulted owner removes protection; it is not recovery of protected
state. Pinning alone would not supply the missing recovery protocol.

## Word and ownership

One aligned 64-bit word in a writable `BPF_F_MMAPABLE` ARRAY holds a closed high
bit and a low-bit admission count (maximum 4,096). The map has 65,536 lifetime
slots. `GateMap` allocates monotonically; retired slots stay closed and are never
reused. At most 1,024 allocated, nonretired slots may coexist. Exhaustion is an
explicit refusal, not recycling: this avoids a stale pre-admission reader
admitting against a different binding after slot ABA.

Use one Go allocator/publisher owner per map. No ordinary store or
`bpf_map_update_elem` may replace an activated word. Both BPF and Go use aligned
64-bit atomic operations. The first actual BPF exec transaction calls `fg_enter`,
then latches its original binding, slot and transaction identity before looking
up policy. A successful admission owns exactly one release. Do not copy admission
or pending-transition ownership to forked/cloned children.

`BeginUpdate(ctx)` atomically closes admission while retaining the count, waits
for zero and returns an exclusive publication lease. Publish a fully prepared,
frozen inner map before `Reopen`; on precommit preparation/publication failure,
retain the old map and reopen only after safe candidate cleanup. A timeout reopens
only the closure this owner acquired, preserving outstanding admissions. A stale
lease cannot reopen a later
publisher's closure. `Retire` permanently closes a drained slot. `GateMap.Close`
refuses unmapping until all slots have been retired.

Admission and the generic `Leave` helper use bounded CAS loops (64 attempts).
Contention is explicit: failed admission grants nothing; failed generic release
retains ownership/count and must be retried or reported stuck. The role-lifecycle
fixture instead uses `fg_leave_owned`: it claims and clears transaction ownership
under the task lock, finishes all owned writes, then performs one final atomic
subtraction. Duplicate cleanup without a claim never subtracts. Underflow is a
sticky corruption fault, never a reset or compensating write.

## Whole-exec integration boundary

The caller must commit roles and clear pending transaction state **before** its
final count decrement. It must match completion to the original `bprm` and slot,
not the current PID/cgroup (nonleader exec and migration can change these).

Syscall-exit cleanup alone is insufficient: failed `kernel_execve` can return to
a kernel caller without a syscall-exit event. The proposed full runtime requires
verified `fexit/bprm_execve` completion plus task-exit fallback, attached before
admitting LSM transactions. Successful `sched_process_exec` can commit roles, but
release must follow all transaction-owned writes. A separate isolated role fixture has passed all five required hook attachments
and 14 lifecycle cases on the pinned custom kernel, including scripts, failures,
nonleader exec, fork/vfork and an explicitly injected missing-fexit task-exit
fallback. This does not prove persistent production-owner publication, bootstrap
lineage, cgroup migration during active admission, ptrace drain behavior, or
production shutdown ordering. This package does not supply that owner.

Closed-gate exec attempts need an explicit, observable operational failure policy;
never bypass authored enforcement while publication is underway. This can disrupt
runtime helpers and even explicitly audited workloads during a reload. The gate
library does not silently choose this product behavior or claim that it is wired.

The opaque verdict candidate fails closed when a bounded TASK or WORK quota
(`SE_PROFILE_TASK_QUOTA`, `SE_PROFILE_SCRATCH_QUOTA`), the deferred storage, or
the source/target handoff is exhausted: Strict refuses the birth or exec and
Audit leaves the child unevaluated. Building with
`ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE` adds the
`opaque_real_fail_closed_rates` counters (quota LIMIT, source refusal, missing
target, evaluation WORK refusal, storage quarantine, other constructor
failure, and since G019 M0: first-exec qualification fault, pending-receipt
quarantine, birth-target parent open failure, and a reserved gap-refusal
class), and `FailClosedRate` maps two snapshots to a degraded verdict for a
threshold. Its eleventh counter reports WORK start retry-bound exhaustions
(`SE_PROFILE_WORK_RETRIES`, default min(16, WORK quota)),
a subset of those refusals. A live product node polls these counters
(`shared_fail_closed_health.go`, see the fail-closed runtime section below);
a qualification node's `Ready` stays unavailable; on a product node a
fail-closed NotReady or Unknown fails `Ready` (`ErrSharedNodeNotReady`) and a
Degraded window is reported by `NodeEnforcer.Degraded`.

The G019 M0 classes count the outcomes G025 excluded:

- qualification fault: an owned exec refused because `real_owner_birth_qualify`
  faulted at `bprm_check_security` (the same fault at `task_alloc` is a source
  refusal);
- pending-receipt quarantine: an owned exec refused while a prior terminal
  receipt is pending (`real_owner_reader_begin_core` result `& 8`,
  `real_owner_reader_quarantine_pending`);
- `real_owner_child_open_parent` failure in `real_owner_child_finish`;
- gap refusal: interpreter continuation refusals only (see Class [9]
  below). Since G019 gap 4 (review H1) a #! script or binfmt_misc interpreter pass of an
  owned exec is continued (`ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE`,
  every product object): it is evaluated for its own file under the exec's
  frozen original class, and its role proposal accumulates into the same
  exec transaction that the terminal commits once. A refused continuation
  (receipt or failure frames, reader classification or recovery, the
  suspended terminal WORK, exec_binprm depth beyond 5, the WORK rebind, or
  a missing continuation/prepare graph entry) counts here, with its reason
  in `opaque_real_interp_stats`; Strict denies, Audit allows and
  quarantines. A later pass that carries a terminal fault (first-exec
  qualification or terminal drain) is refused before any continuation
  with the same verdict and cleanup, counted once as QUALIFY `[6]` or
  PENDING `[7]` like a first pass, never also here. Before gap 4 that exec was refused as a pending receipt
  (`[7]`); a real pending receipt still is. Residual by construction: an
  `AT_EXECVE_CHECK` (6.18) runs no `bprm_check` and is never evaluated (user
  decision D4, a documented residual: the flag only asks whether the file
  could be executed, nothing runs; `execveat(AT_EXECVE_CHECK)` returns what
  the kernel says, 0 for an executable file even when a Strict policy
  denies it, with no event and no counter; the real exec of the same file
  is evaluated and denied as usual: EPERM and one decision event. 6.12
  rejects the flag with `EINVAL`. Live:
  `TestSharedNodeExecveCheckAttached`); a
  binfmt_misc `F` (fix-binary) interpreter, opened at registration and
  possibly outside the container's mount namespace, is evaluated like any
  file, and a path that does not resolve for the policy denies under Strict.
  Every pass is evaluated, but the candidate evaluator has no per-file
  (path or image) facts yet: its target image is always unknown and a pass
  differs from the previous one only through the roles proposed so far and
  the credentials. A policy of "allowed script, denied interpreter" is
  therefore not expressible yet; it becomes so when target facts are
  collected per pass, with no change to the continuation itself. Until then
  product admission refuses path, image and other predicates that need those
  facts (see Product predicate admission).

The live verdict test checks each class against an exact test-only witness
(`opaque_real_exec_exclusions` for the G019 M0 classes). Remaining exclusion:
an exec of a task that carries no TASK (born before the binding, or a birth
already counted as refused or unconstructed) fails the exec reader's parent
open and is not counted a second time. A zero rate is therefore evidence for
managed, TASK-carrying births and execs only.

First-exec qualification (`real_owner_birth_qualify`, the birth receipts and
their issue, stamp, observe and retire path) is built with
`ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE`;
`ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC` only adds test-only
witness counters and the `task_kill` signal-0 diagnostic.

The final-free physical-reuse fix (`se_of_withdraw_directory` in
`lsm/task_free`) is part of every build of the candidate's final-free program,
not of the rate witness: the object refuses to compile without it.

User-approved G025 capacity thresholds:

- **128/16 is the qualified default profile for the opaque candidate build**
  (TASK/WORK quota per binding, two bindings; WORK start retries
  min(16, WORK quota)). 64/8 and 256/32 are qualified alternatives; 256/32 has
  no stack headroom. The candidate source has no default: the build passes
  every value as `-D` flags, all with `-DSE_PROFILE_BINDINGS=2`:
  - 64/8: `-DSE_PROFILE_TASKS=128 -DSE_PROFILE_TASK_QUOTA=64
    -DSE_PROFILE_SCRATCH=16 -DSE_PROFILE_SCRATCH_QUOTA=8
    -DSE_PROFILE_WORK_RETRIES=8`
  - 128/16 (default): `-DSE_PROFILE_TASKS=256 -DSE_PROFILE_TASK_QUOTA=128
    -DSE_PROFILE_SCRATCH=32 -DSE_PROFILE_SCRATCH_QUOTA=16`
    (`SE_PROFILE_WORK_RETRIES` defaults to 16)
  - 256/32: `-DSE_PROFILE_TASKS=512 -DSE_PROFILE_TASK_QUOTA=256
    -DSE_PROFILE_SCRATCH=64 -DSE_PROFILE_SCRATCH_QUOTA=32
    -DSE_PROFILE_WORK_RETRIES=16`

  The in-repo product shared build profile is separate: the product object
  (`g19pkg128`, `candidate/gadget.yaml`) is **128/32** (G019 burst gate,
  user decision: 8 burst streams zero-gated). `(W − 1) / 2 ≥ 8` needs
  `W ≥ 17` and the verdict source requires a power-of-two WORK quota, so 32
  (capacity 15) is the smallest; it costs 32 more WORK slots per node
  (`se_opaque_work_payload` 19,456 B each: about +614 KiB of map values),
  no stack and at most +15 static instructions per root.
- **Steady-state gate** (test reaper at 2 ms): 0 Strict fail-closed refusals
  and 0 Audit unevaluated children at a sustained 400 births/s per node,
  3 streams, at least 10,000 paced births per exact kernel and class, at
  128/16. 800/s and 1600/s are exploratory ceiling points only.
- **Burst gate** (G019/G020, product reaper; user decision "gate at
  capacity"). The burst capacity of a binding is
  `ConcurrentBirthCapacity(W, syncReturn)` concurrent births for a
  per-binding WORK quota `W` (`fail_closed_rate.go`); the test computes it
  from the object's WORK quota and the presence of `opaque_real_work_sync`.
  An in-flight child holds at most its birth WORK and its exec evaluation
  WORK at once and the binding's managed parent retains one WORK, so the
  static bound is `(W − 1) / 2`.
  - **With the synchronous WORK return** (option C, below): `(W − 1) / 2`,
    3 at 64/8, 7 at 128/16, **15 at the product's 128/32**, 15 at 256/32
    (8 streams are zero-gated on the product; user decision: gate the
    conservative static bound). A WORK credit is held only from its charge
    until its settling program returns, never waiting for the userspace
    reaper. A child then holds at most one WORK at a time, so the bound per
    forking parent thread is about `W − retained − 1`; it is measured as
    information only (`work_peak`), never gated.
  - **Without it** (`(W − 3) / 2`, option A): 2 at 64/8, 6 at 128/16, 14 at
    256/32. The WORK credits of an exited child come back asynchronously
    through the product reaper and nothing throttles forks meanwhile; the
    capacity reserves one late child. Refusals at 6 streams still happened
    under reaper stalls (G019 chain7: 1 of 48; chain15 fs6x20: 4 of 160 on
    both kernels at 1-3 ms reap latency), so it is advisory and test only
    (lead decision (b)): the product object requires the synchronous return
    (`#error` + NEG `pkg-without-sync-return`, and product admission refuses
    an image without `opaque_real_work_sync`), and non-sync bursts are
    measured, never zero-gated (the burst gate counts every refusal). Sizing rule (option B):
    `W ≥ 1 + 2 · (concurrent births + λ · D)`, with `λ` the binding's
    birth rate and `D` the reap-latency tail (`λ · D`: births whose credits
    are still in the reaper).
  - At or below capacity: 0 refusals for 1,000 back-to-back births (witness
    `fail_closed=0`, evaluated == births, no reaper `Faulted`), Strict and
    Audit, on both kernels. With the synchronous return at 3, 6 and 7
    streams, plus: every settled WORK `returned` or `claim-lost`, no
    synchronous slow path (pending, fault, stuck), settled birth WORKs ==
    constructed births and settled evaluation WORKs == completed execs, and
    a WORK peak ≤ retained + 1 + streams + threads. Evidence: 10 runs per
    kernel per class at capacity (40 runs, `ONLY=s7x10 run-g19dec2.sh`;
    `ONLY=s6x10` for objects without the synchronous return).
  - Above capacity (8 streams; 32 streams designed to overflow, with
    `IG_OPAQUE_REAL_VERDICT_EXPECT_REFUSALS=1`, which requires at least one
    refusal): a measured over-capacity run, not a zero gate. It passes only
    if every unevaluated birth (user-space births minus the evaluator's own
    count) is exactly one counted witness class, Strict user-space refusals
    equal the witness total, every class equals its test-only witness (a
    self-consistency check: those witnesses sit at the same BPF sites),
    `Degraded` is set whenever a refusal was counted, no reaper fault, and
    the accounts drain back to the baseline afterwards.
  - Attribution: every burst line prints the round period, the slowest reap
    (`reap_max`), the exact WORK high-water of the binding (`work_peak`, on
    objects built with the test-only
    `ENFORCE_EXEC_POOL_OPAQUE_WORK_HIGH_WATER_DIAGNOSTIC`; never in a
    product object) and the synchronous return's outcomes (`sync=`) next to
    the reaper's `claim-held` count.
- **Synchronous WORK return at settle** (G019 option C,
  `ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE`, requires the reap
  events and credit at exit; in the product object). The program that moves
  a WORK to DONE returns it at its own top level
  (`real_owner_work_sync_return`): the `task_alloc` target for the birth WORK
  (owned by the parent, DONE at construction), the `sched_process_exec` and
  `bprm_execve` fexit terminals for the evaluation WORK, and the exit program
  and the `task_free` fallback for a WORK still suspended at death. Returning
  only at exit would hold the birth and evaluation WORKs for the child's
  whole life.
  - The settling call returns its result in the low and the WORK slot + 1 in
    the high 32 bits of R0 (no stack in the 512-byte chains); the
    synchronous return reads the cookie from the charge and visits only a
    meta still DONE/ABORTED under that cookie. It runs the reaper's own
    seven stages unchanged (`bpf_loop`, or `SE_OWK_SYNC_STRAIGHT_LINE` if the
    load spike `run-g19sync-spike.sh` refuses spin locks in its callback):
    every stage before the account return is required, because the account
    bit is the WORK slot and a charge meeting a non-FREE meta faults the
    account.
  - Zero once: with the flag the charge-time payload zero is skipped; the
    return-time zero (stage 3, which every path to `META_FREE` passes) is
    the only one, and the header-is-zero check at charge verifies it.
  - Visit claim (`se_owk_visit_claims`): the synchronous return claims a WORK
    for its whole sequence, tried once; the reap command claims per step and
    answers `SE_OWK_CLAIM_HELD` (6) while it is held, which the reaper treats
    as final for that cookie (as STALE and ALREADY_RETURNED). Every
    synchronous exit other than returned or claim-lost emits a recovery
    `WORK_DONE`, and the reaper resumes a WORK from `CLEANING`,
    `REFUND_PENDING` or `META_FREE` with its cookie (also after a restart). A
    claim still held a second later counts `stuck` once. TASK keeps the
    single-reaper rule.
  - Witness `opaque_real_work_sync` (`work_sync.go`): settled per site, and
    returned / claim-lost / stale (benign) / pending / fault / stuck
    (Degraded: that WORK waits for the reaper).
  - Stack: the deepest chain of every root is unchanged (the `task_alloc`
    target stays 512 at 256/32); the synchronous path is root frame +
    `real_owner_work_sync_return` + its callback (`build-g19pkg.sh`
    SYNCSTACK, ≤ 512 at 64/8, 128/16 and 256/32).
  - Cost (chain11, `run-g19sync-latency.sh`: kernel `bpf_stats` sampled every
    50 ms by `build-g19sync/prog-stats` during the 7-stream, 1000-birth Strict
    burst; mean ns per run, synchronous return on vs off, the high-water
    objects `g19dec2sync128` vs `g19dec2hw128`):

    | Settle program | 6.12 / 6.18, on | 6.12 / 6.18, off |
    |---|---|---|
    | `child_exit_candidate` (death) | ≈ 3.8k | 3.7k–3.8k |
    | `child_final_free_candidate` (`task_free`) | 0.7k–1.0k | 0.6k–0.8k |
    | `failure_fexit_probe` (failed exec) | 0.35k–0.39k | 0.34k–0.37k |
    | `reader_success_probe` (exec success) | 47k–51k | 56k–58k |

    No measurable cost. Two caveats:
    - The `task_alloc` target is a tail call of the source; the kernel
      charges its time to the source and never samples it separately, so the
      birth settle is measured as `child_source_candidate` (sampled from the
      next run on; chain11 reported "4 of 5").
    - `reader_success_probe` is dominated by the test-only terminal-race
      rendezvous (`real_owner_terminal_auth_enter`: up to 4096
      `bpf_ktime_get_ns` spins, about 50 µs, on every exec completion), which
      the product object does not have (`build-g19pkg.sh` SPIN). The
      latency runs therefore also measure `g19dec2{sync,hw}ns128`, the same
      objects built with `SE_TERMINAL_RACE_NO_SPIN`.
- **Reuse-aware WORK reserve and reap** (every object, unconditional since
  chain15). A WORK slot can be returned by the reaper and by the synchronous
  return, and reused before a late returner or reserver runs. Reserve treats a
  FREE charge whose `last_returned` is not older than the new cookie as
  `SE_OL_CONTENDED` (retry another slot) instead of faulting the account;
  reap treats an already-FREE charge that was recharged or returned under
  another cookie as `SE_OWK_STALE`; only an exact unexpected shape still
  faults the account (fail-closed).
  - Root cause of the chain15 `burst-nosync-s6` account fault (dec2, a
    non-synchronous object; the product objects already had the reuse-aware
    branches): the reserve cookie-order race in `se_owk_begin`, established
    by elimination plus the post-fix fault-site witness run
    (`run-g19dec2.sh` `ONLY=fs6x20`: `burst-nosync-s6` ×20 on both kernels,
    0 faults and a zero witness expected; any site that fires is a second
    bug).
  - The IDENT baselines were refreshed once for this change, with evidence
    that every changed object equals the old source built with
    `-DSE_OWK_REUSE_AWARE=1` (all non-debug sections and the canonical BTF
    graph).
  - Fault-site witness (`ENFORCE_EXEC_POOL_OPAQUE_WORK_FAULT_SITE_DIAGNOSTIC`,
    test only; `#error` with `SE_PRODUCT_NO_TEST_RUN`): each of the nine
    account-fault sites ORs its own bit (1..9) into the account's fault word,
    so the attached test's `faulted (fault word …)` names the site. It adds
    no map; `g19dec2fs128` omits the WORK high-water witness to stay within
    the 512-byte stack.
- **Exec capsule store in task local storage** (G019 M4, user decision
  (ii); every object with the source capsule). The capsule that freezes an
  exec's original class (`full/shared_exec_capsule.h`) and its entry marker
  live in `BPF_MAP_TYPE_TASK_STORAGE` on the executing task
  (`se_exec_capsules` 104 B, `se_exec_markers` 16 B, `BPF_F_NO_PREALLOC`),
  no longer in ARRAYs that a loader had to size to `pid_max` (the operator
  never did: every product lookup missed, so Strict denied every exec and
  Audit allowed every exec unevaluated, both uncounted).
  - Storage is created only for an exec that can matter: its cgroup has a
    route-index entry or its task holds a TASK key (at entry and begin), or
    at the exec's first selected admission. Lookups never create; an exec
    that never matters has no storage and costs one failed lookup.
  - A failed create where storage is needed is a capsule fault: the
    admission degrades through the current route and the reader counts it
    as ADMISSION (Strict denies, Audit allows, both counted).
  - Per-task proof: entry, begin, every admission and the terminal of one
    exec run in the executing task, so another thread of the TGID can never
    touch its capsule; a non-FREE capsule at the task's next begin is a
    missed terminal and is retired.
  - Death retire: `real_owner_capsule_free` (its own `lsm/task_free`
    program, lookup only, 32-byte stack; the product task_free chain is
    untouched) retires a capsule still OPEN or FROZEN when its task dies,
    releasing the original-route pin before the kernel frees the storage.
    Counted in `se_exec_capsule_stats` [14] (DEATH_RETIRED, 15 cells).
    Attach it before the capsule terminal and detach it after.
    `CapsuleHealth` reports a death retire as Degraded (also in `Ready` and
    `Inspect`) for 60 s after it is observed (the fail-closed witness's
    Degraded window, `FailClosedRateDegradedWindow`), then it clears. It is
    never benign in steady state: the attach order leaves no window where a
    capsule exists without its terminal, the final reading is taken before
    detach, and every exec returns through `bprm_execve`'s fexit, so a
    retire means the terminal program did not run (a trampoline recursion
    miss). It is not sticky: the retire released the pin (a failed release
    is a sticky release fault) and the exec's admission was evaluated.
  - Uncovered exec (security review M2): when begin-time coverage is lost
    (the exec did not matter at begin, or the tracing helper's trylock made
    the create miss), the first selected admission freezes uncovered and
    records the original route's identity; a `#!`/binfmt_misc re-check (or
    a migrated admission) re-claims exactly that route and payload
    (`se_route_claim_ident_locked`) instead of faulting. A republish in
    between faults (counted). Test-only object `g19dec2unc128`
    (`ENFORCE_EXEC_POOL_OPAQUE_CAPSULE_UNCOVERED_DIAGNOSTIC`, NEG'd in
    product) and `run-g19dec2.sh ONLY=recheck`.
  - Ownership: a capsule is the current exec's only if that exec opened it
    (consumed its entry marker); a pending marker for the same task/bprm
    marks a matching capsule as an earlier exec's (stale, retired). In
    product objects (`SE_CAP_ENTRY_MARKS_LIVE_CAPSULE`) an exec entry marks
    itself whenever the task's capsule is not FREE, even if the exec does not
    matter yet: after a missed terminal and a missed begin, an exec at a
    reused bprm address that migrates into a selected cgroup retires the
    earlier exec's capsule as stale instead of re-claiming its route by
    identity (review OQ; `stale-ident-reused-bprm`).
  - Host contracts: `testdata/opaque_exec_capsule_contract.c` (the ARRAY
    adapter) and `testdata/opaque_exec_capsule_task_storage_contract.c`
    (storage gating, failed create, migration in, identity re-claim and its
    faults, per-task isolation, death retire, stale retire, stale capsule at
    a reused bprm).
- **Birth park and cross-generation qualification** (G019 gaps 1 and 2,
  product-publisher objects only; `full/shared_birth_receipt.h`, host
  contract `testdata/birth_park_contract.c`):
  - Gap 1: the fork source parks its route claim in per-task storage
    (`se_birth_parks`, 80 B) instead of releasing it; the constructor
    target takes exactly that claim (re-checked under the route lock)
    instead of re-admitting the cgroup. The parked early claim holds its
    record (ACTIVE, then RETIRING once a revision commits past it: gap 3)
    and blocks only the withdrawal and reuse of that record, so a revision
    can no longer leave a straddling child unconstructed (CONSTRUCT): the
    target builds from the claim's own record. A failure before construction abandons the park
    (Strict: deny), `lsm/task_free` (`real_owner_capsule_free`) releases a
    park no target took, and a release failure latches the route.
  - Gap 2: a child born under generation g whose first exec is admitted
    under a later generation of the same route (scope, slot, incarnation,
    class) qualifies (`se_birth_receipt_admits`); a receipt newer than its
    route is a QUALIFY fault. The receipt carries the birth class.
  - Witness `opaque_real_birth_park` [0] parked, [1] taken, [2] abandoned,
    [3] stale, [4] put failed, [5] latched, [6] take failed, [7]
    cross-generation qualified. `BirthParkHealth`, `Ready` and `Inspect`:
    a latched park is a sticky Degraded fault; a stale park or a failed
    take is Degraded for 60 s (`FailClosedRateDegradedWindow`).
- **Per-record route holders** (G019 gap 3, product-publisher objects only;
  host contract `testdata/route_holders_contract.c`):
  - The route anchor keeps its holder totals (`early_claims`,
    `source_pins`) and mirrors them per snapshot record
    (`struct se_route_rec rec[2]`: serial, generation, holders, phase; anchor
    112 → 176 B). Every claim, pinned re-claim, release, transfer and pin
    updates the total and its own record.
  - A revision commits while the previous record still has holders: the
    commit requires only the candidate record free of holders; the previous
    record turns RETIRING and keeps its holders, which validate, read and
    release against it. Fresh claims always stamp the ACTIVE record and the
    identity (unpinned) re-claim requires it, so a RETIRING record's holder
    set only shrinks. Readers may release on RETIRING; a claim bound to a
    RETIRING record transfers to a reader of it. The birth constructor
    builds from the RETIRING record of its claim's identity.
  - Drop: `real_owner_snapshot_drop` checks, under the route lock, no early
    claim, source pin or reader on the record before its ticket is released
    (1: holders remain, retryable). The revision drops the old record right
    after its commit (best effort); `opaque_real_route_drop_retired`
    {slot, scope, generation} drops it later (0 dropped, 1 holders remain,
    -1 invariant). No timeout ever clears a holder count.
  - Agent: a revision whose candidate record is still RETIRING with holders
    drops it as soon as they are gone, retrying with a 1 ms → 250 ms
    backoff up to `RevisionDrainTimeout` (`SharedNodeConfig`, default 10 s,
    at most 60 s); on timeout the staged object is discarded, the refusal is
    retryable (`ErrSharedRevisionDraining`) and the binding is Degraded
    `RevisionDrainTimeout` with the record's early claims, pins and readers
    (`Inspect().Revision`, `Ready`; never NotReady), cleared by the next
    committed revision. A stage refused retryably (every spare object held
    by a RETIRING record) past the timeout is Degraded
    `RevisionObjectStarved`. Stale objects drop their RETIRING record first.
  - Residual (accepted, fail-safe): an exec blocked indefinitely between
    passes or inside exec (a fanotify permission event, a FUSE-backed file,
    a ptrace stop) keeps its claim, pin or reader on the RETIRING record,
    so that record and its object stay held. The slot's next revision that
    needs the record waits `RevisionDrainTimeout`, is refused retryably
    (`ErrSharedRevisionDraining`) and the binding is Degraded
    `RevisionDrainTimeout` while the last good revision stays enforced. It
    never allows: the held exec is still judged under the record it holds,
    and no timeout clears a holder. User decision D3: this RETIRING-holder
    residual is accepted and documented, not closed: an exec blocked
    forever keeps the old record, so every later revision of that slot
    times out (Degraded `RevisionDrainTimeout`, retryable refusal), the
    last good revision stays enforced, and nothing ever allows. No policy
    kills or quarantines the holder.
  - Sizing (user decision D3): policy objects > bindings stays the
    admission floor (one spare for make-before-break; the product control
    refuses objects <= bindings). A held RETIRING record keeps its object,
    so with `Bindings + 1` objects one long-held record (a traced or
    stopped exec) starves every other binding's revision until it drains
    (`RevisionObjectStarved`). The PoC default product profile is therefore
    `2 × Bindings` objects: `-DSE_PROFILE_SLOTS_256=4` for the two bindings
    in the product build (compile-pkg; was 3) and
    `enforce-exec-shared-slots-256: "4"` in `candidate/gadget.yaml`. A held
    record then only affects its own slot (the residual above); the other
    binding keeps revising (`TestProductCommanderNotStarvedAtDefault`).
    Cost: one more 256-cell policy object per node, one 80-byte
    `se_objects` entry and 256 288-byte `se_arena` cells: +74,836 bytes of
    map keys and values (g19pkg128: 2,375,132 -> 2,449,968), independent of
    the TASK/WORK profile; every program of every product object still
    loads under the verifier budget on both AL2023 kernels.
  - Open point (to verify on the VM): a reader of the RETIRING record
    evaluates under its own snapshot while the accepted-epoch catalogue may
    already carry the next generation's root epoch (the catalogue invariant
    of `se_exec_reader_authority_locked` assumed a held reader blocks the
    commit).
- **Credit at exit** (G019, `ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE`,
  requires the reap events): the exact death settlement runs in
  `tp_btf/sched_process_exit` instead of `lsm/task_free`, so the TASK
  credit no longer waits ~160 ms for the RCU-deferred free. The tombstone
  HASH `se_exit_tombstones` (`SE_PROFILE_EXIT_TOMBSTONES` entries) carries
  the exact identity to `task_free`.
  - Sizing rule: the tombstone table is sized for the **exit burst** (exit
    rate × exit-to-free latency), never by TASK count. Every product profile
    uses 8192 entries whatever its TASK quota: the measured live-tombstone
    peak of the G019 burst (1000 births), steady (400/s) and churn runs is
    824 node-wide (an older build without exit-time birth-receipt retirement
    held about 4.3k), far below the 75 % high mark (6144), and each of two
    bindings owns 4096. The 32 × `SE_PROFILE_TASKS` default when the macro is
    unset exists only so the pre-existing qualification objects stay
    byte-identical. The Go profile carries the same value
    (`SharedProfile.ExitTombstones`, annotation
    `enforce-exec-shared-exit-tombstones`), and qualified admission pins the
    map size to it exactly. A refused tombstone insert (overflow, stale) or
  exit withdrawal takes the slow path: `task_free` settles or resumes as
  before, never earlier. A free-time resume that is refused again leaves the
  withdrawal and the tombstone to the reaper. The witness
  `opaque_real_exit_credit` (`exit_credit.go`) counts every path; any slow
  path or fault is Degraded. `TASK_FREED` wakeups are counted, never reaped.
  - Lifetime: a tombstone an earlier lifetime at the same address left
    behind (failed delete, missed `task_free`) is never trusted. At exit any
    tombstone at the key is an earlier lifetime's (the exit fires once per
    task). At free the tombstone is this lifetime's only if its stored
    `start_time` matches and the directory names no other charge at the key:
    `start_time` alone can repeat, since a non-leader exec (`de_thread`)
    takes the leader's `start_time`, `start_boottime` and pid. A stale one is
    finished as its own free would have (counted `stale`, Degraded) and the
    task at hand takes its normal path. `task_free` consumes a tombstone even
    when the image gate was disarmed after the exit. Link order: attach the
    exit program after `lsm/task_free` and detach it before (the operator
    detaches in exact reverse of `nativeattach.Rank`), so no tombstone is
    created without its consumer. A `FREED` or
    `RESERVED` tombstone whose delete failed at an address never reused
    again is not swept (bounded by the counted `tomb-fault`s; no credit).
  - Reaper: a visit of a DEAD charge whose death lease is still held (an
    exit or free between withdrawal stages, a `DIR_PENDING` exit awaiting
    its free) is PENDING, never a reap fault: `se_or_task_visit` reads
    `active_leases` in the same lock section as its stage snapshot (every
    build, credit at exit or not), and every reaper directory stage needs
    the lease released. A held lease that stays held with no tombstone of
    its own accounting for it (`DIR_PENDING`/`FREE_PENDING`), still found so
    1 s after a visit first found it, counts `held-stuck` once (Degraded), so
    an endless "not yet" cannot hide a lost holder. A directory stage whose
    exact recheck fails (`CORRUPT`) is a fault only if `directory_state` is
    still the snapshot that selected it; a state another visit already
    moved on is PENDING. A reap fault quarantines only that exact charge
    (`ReaperStats.Faulted`, `Degraded()`, `Reaper.Faults`): its slot stays
    charged (fail-closed) until it carries another cookie, and every other
    charge is still reaped; only infrastructure errors (ringbuf, map read,
    reap command run, malformed wakeup) stop the node Reaper. A
    `FREE_PENDING` tombstone is retired only once its lease is released, by
    the reap visit that wins its `FREE_PENDING -> RETIRING` CAS and
    re-checks its exact identity, so concurrent reapers never delete a later
    lifetime's tombstone. A free that cannot rebuild the exit's exact lease
    or release it counts `lease-fault` and leaves it held: the slot stays
    charged (fail-closed, Degraded). Every TASK refund goes through
    `se_or_task_visit` (`se_oc_refund_step` has no other caller; the
    recovery commands `se_rm_*`/`se_command` touch no opaque TASK charge),
    so this pre-step guards every refund path.
  - Accounting: a zombie holds no TASK credit; the quota bounds live tasks,
    the tombstones bound exited-but-unfreed ones. Each binding may hold an
    equal share (`SE_EXIT_TOMBSTONE_ENTRIES / SE_PROFILE_BINDINGS`,
    `opaque_real_exit_accounts`), so one workload keeping its children as
    zombies overflows only its own binding to the slow path (counted
    `account-overflow`, Degraded node-wide: the witness is per node). The
    shares sum to the map size, so the map itself does not fill.
  - Health: `ExitCreditCheck` maps two witness snapshots, the read error and
    the capacity to Healthy, Degraded (a non-benign slow path, a fault, a
    stale tombstone, or the tombstones at 75 % of the map: `live` crossed it
    within the window (`high-crossed`, counted per upward crossing, so a
    repeat peak below the lifetime high-water is seen), the high-water gauge
    rose to it, or `live` is at it now; a peak of an earlier window does not
    degrade later ones) or Unknown
    (unreadable witness, unknown capacity, counter reset: NotReady). A
    `CONTENDED` exit settlement (`unsettled`: the task never owned the
    charge) is a slow path but benign; `LIMIT`/`CORRUPT`/`STALE`
    (`unsettled-fault`) are faults. Wiring it into node health is M6.
  - Birth receipts: `opaque_birth_receipts` is retired at exit too (an exited
    task never execs again and its address cannot be reused before its
    free), so the receipts are bounded by live tasks, not by tasks awaiting
    the RCU-deferred free; under the burst they were the remaining
    bottleneck. Exit retirements are not failed births; `task_free` and
    `free_task` stay the retirement for failed births and for exits before
    the exit link was attached.

Runtime reporting rule for a future `Ready` gate built on the witness
(`FailClosedRateDegradedWindow`, `FailClosedRateNotReadyWindow` and their
thresholds in `fail_closed_rate.go`):

- **Degraded** on any fail-closed refusal (Strict) or unevaluated child
  (Audit) within 60 s.
- **NotReady** when the fail-closed rate is above 0.1% over 5 min.
- An unreadable or missing witness, or a counter that moved backwards, is
  **unknown**, never a zero rate.
- Product-publisher objects (G019 M4) have a 13-cell witness:
  - cell 11 is **ENTRY**: an exec on an OWNED route by a task that has no
    TASK at all, such as a runtime exec entry or a migration into the cgroup.
    It is reported apart, like the WORK retry subset, and is never added to
    Total. A failed open while a TASK exists stays class 8 (open-parent) and
    counts in Total.
  - cell 12 is **ADMISSION**: every exec admission fault of the exec reader
    (a latched, adopting or reserved route, a degraded exec-capsule
    admission, a frozen-class mismatch). Strict and invariant faults deny,
    Audit faults allow, and each is counted as one exec attempt and one
    ADMISSION. It is outside Total, but an ADMISSION rate above the
    threshold degrades the node. (Before this cell such faults were
    uncounted: an Audit route could allow execs unevaluated and invisibly.)
    A fork's admission fault counts ADMISSION too: at the task_alloc source
    (one birth attempt [0] plus ADMISSION), or at the constructor target's
    re-admission (ADMISSION against the birth attempt the source counted;
    a non-fault target re-admission stays CONSTRUCT). One class per attempt.
  - `opaque_real_attempts` counts OWNED birth claims [0] and exec admissions
    [1] (OWNED or ADMISSION faults); their sum is the shared denominator
    (`FailClosedProductRate`).
  - Other objects keep 11 cells (`FailClosedRateCells`).

Root-task adoption (G019 M4, product publisher): a first publication marks
the route as adopting, adopts the cgroup's tasks (`cgroup.threads`, init
leader first), then finishes. Any failure quarantines every adopted entry
and fails the container start with `ErrSharedAdoptionRefused`. Each reason
is counted and reported with the container identity:

- `AdoptionIdentity`: the init identity, its tasks or the cgroup do not
  match.
- `AdoptionTaskRefused`: a present task was refused.
- `AdoptionThreadExited`: an adopted thread exited mid-adoption.
- `AdoptionCloneRefused`: a fork or clone was refused while adopting, for
  example a Go init creating threads.
- `AdoptionFinishRefused`: finish refused the adoption for any other reason.
- `AdoptionAuthentication`: a product command failed authentication.
- `AdoptionDeadline`: the start deadline expired.
- `AdoptionQuarantineIncomplete`: the quarantine still missed entries after
  3 attempts. **Degraded**, with the marked and missed counts. The route then
  stays latched until node teardown and is never withdrawn, in Strict or
  Audit. A latched Audit route claims `AUDIT_FAULT`, which allows the exec
  and counts it.

A quarantine entry whose TASK is already gone has nothing left to mark and
does not make the quarantine incomplete. Only an entry that is found but
cannot be marked does.

The refusal error (`ErrSharedAdoptionRefused`) carries `Audit`. A Strict
refusal must fail the container start or report the binding unprotected
(NotReady). An Audit refusal must not fail the start: Audit
never blocks a workload.

A first publication whose outcome is unknown (a lost reply or a failed
undo, and a route read back that is not this node's) latches the slot until
node teardown (`PublishUnconfirmed`, Degraded). Its error
(`ErrSharedPublishUnknown`) carries the slot, the cgroup and the route
scope the commander minted for the request. That scope is unconfirmed: a
caller may use it only to tombstone the latched route's late events after
unbinding, never to attribute an event. The binding still fails as before.

Refused adoptions are reported in three places, until the slot is recycled:
`SharedBindingStatus.Adoption`, `NodeEnforcer.AdoptionReport` (the slots and
per-node counters by reason, `AdoptionStuck` included) and `Ready`
(Degraded).

`Remove` never withdraws a slot whose adoption was refused: a withdrawn route
allows every remaining task. It reports withdraw pending, and only the
slot's poller releases it.

A normal `Remove` withdraws the route, then recycles it in the background,
retrying while TASK credits are still held, and frees the slot for reuse.
A refused recycle keeps the slot reserved and is a sticky node fault.

Strict publication is refused unless the agent runs in the initial pid and
time namespaces (design 13.8).

After a complete quarantine, Strict keeps the route latched until the cgroup
is empty. After 30 s it reports `AdoptionStuck` (Degraded); once the cgroup
is empty the route is withdrawn and recycled. Audit withdraws at once. A
withdrawn cgroup is never bound or published again on the node.

Migrate-in residual (known limit): the empty poll and the withdrawal are not
atomic. A task that migrates into the cgroup between them runs under the
WITHDRAWN route, which allows it unevaluated; a withdrawal cannot be undone
from userspace. The poller therefore re-reads the cgroup after the
withdrawal, bounded: 3 reads over 250 ms (at 0, 125 and 250 ms), then once
more immediately before every recycle attempt (a contended recycle retries
each second). The first non-empty (or unreadable, not gone) read is
reported `MigratedAfterRelease` (Degraded, counted once per release) in
`AdoptionReport` and `Ready`, kept until node teardown (the slot itself is
still recycled and may be reused). Residual, precisely: a task that
migrates in after the withdrawal and leaves again before the next read is
never seen (it ran unevaluated); a task that migrates in after the last
read before the successful recycle is not detected either, and it then
runs under a free (UNSELECTED) slot, unevaluated, like any task in an
unbound cgroup. Such a cgroup is never bound or published again on this
node. Audit is not checked: it withdraws with its tasks present by design.
Live: `TestSharedNodeM4MigratedAfterReleaseAttached` migrates a task in
(a privileged `cgroup.procs` write) the moment the route is seen
withdrawn, after the empty poll, and requires the report, Degraded `Ready`
and the sticky report after the recycle.

Product publication takes a compiled policy (`SharedBindingPolicy.Source`
and `Container`, compiled by `CompileKernelWithRoleEpochs`):

- one policy per binding;
- `init_role` is the compiled root role, never a default, and a policy
  without a root role is refused before any command runs.

The BPF side of the product publisher (`bpf/opaque_real_owner_product_publisher.h`,
`ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE`, product objects and
the `g19pkgpub128` twin only; every other object is byte-identical without
it):

- Commands: `opaque_real_policy_stage`, `opaque_real_route_publish`,
  `_withdraw`, `_recycle`, and `opaque_real_adopt_verify`, `_task`,
  `_finish`, `_quarantine`. Each authenticates (the profile, the caller's
  `se_admin` nonce, the node cookie and a strictly increasing sequence,
  consumed once in `opaque_real_cmd_receipt`) before it changes anything;
  a refusal is code 5 and changes nothing.
- G019 limits: one policy object and one policy UID per snapshot (a
  revision to a different UID is refused, code 2, not retryable); the
  staged object's own policy prefix must carry the request's UID, init
  role and class and a zero root epoch. Multiple policies per binding are
  M8.
- A committed revision drops the previous (RETIRING) record at once, best
  effort, so its policy object unpins and `productCommander` can release it
  (revision deadlock fix: with `Bindings + 1` objects the old object used to
  stay pinned until that slot's next revision, which could never be
  staged). A record with reader claims is never dropped: the drop and the
  `RELEASE` ticket command both refuse it. A refused drop leaves the old
  object stale; stages then refuse retryably until the slot's next
  revision start, withdraw or recycle drops it again.
- Every failed publication undoes its steps in reverse (cgroup locator,
  epoch index, candidate snapshot, route open); the test-only
  `ENFORCE_EXEC_POOL_OPAQUE_PUBLISH_FAULT_DIAGNOSTIC` injects a failure at
  three points for the VM tests.
- A cgroup that was any binding's last published cgroup is refused (code 4).
  `last_cgroup` survives withdraw and recycle; only the slot's next
  successful first publication overwrites it.
- Recycle is idempotent (a FREE route only repeats the cleanup). Code 6
  means the route is FREE but its cleanup could not run: the slot's next
  first publication is refused until a retried recycle cleans it.
- The adopted set (`opaque_real_adopted`) is shared by the bindings and
  capped at the TASK quota per slot; every TASK that may exist after a
  charge attempt is recorded, so quarantine covers it.

## Verification

Ordinary tests exercise concurrency, timeout preservation, publisher ownership,
limits, slot retirement and BPF compilation. Privileged testing is opt-in:

```sh
IG_EXEC_GATE_KERNEL_TEST=1 \
IG_EXEC_GATE_BPF_SOURCE=/absolute/path/bpf/gate_test.bpf.c \
./sandbox-exec-gate-kernel.test -test.run '^TestGateKernel$' -test.v
```

Run only on the explicitly selected disposable x86_64 fixture. The kernel test
loads a socket-filter program and uses `BPF_PROG_TEST_RUN`; it attaches nothing.
It tests actual mmap/BPF atomic interoperability, not LSM facts or full exec roles.

**Fork transaction next to another task_alloc program.**
`TestSharedNodeTaskAllocCompositionAttached` (qualification build,
`-tags enforce_exec_shared_qualification`, VM only, the environment of
`TestSharedNodeFailClosedInjectAttached`: `IG_SHARED_M4_OBJECT` set to the
product object, `IG_SHARED_M4_CGROUP_ROOT`, `IG_SHARED_M4_HANDLER_SYMBOL`
and `IG_SHARED_FC_HELPER`) attaches a second `lsm/task_alloc` program that
denies forks of the bound cgroup, in both attach orders, for a Strict and an
Audit binding. It requires the denied fork to fail with `EPERM`, TASK/WORK
credits back at the post-adoption baseline, no early claim on the route,
every birth park taken or abandoned, no fail-closed count, the fail-closed
witness Healthy, and the next fork of the same parent to succeed. The
product source must run before the denier in exactly one of the two orders
(read from `opaque_real_attempts[0]`, which counts every owned birth claim
whatever the class), and in that order the target must have taken the
parked claim, i.e. constructed the child TASK that the cleanup must
release. It passed on EC2 on both pinned AL2023 kernels (6.12.113-138.209
and 6.18.56-125.164), 4/4 leaves on each kernel (EC2 run `a3-20261115t215407-70bd`). It remains a manual EC2 gate because CI
has no AL2023 runners.

## Historical identities

`IdentityRegistry` reserves compiler-validated policy/role hashes before any
candidate seeding or publication. It retains successful reservations even when
subsequent publication fails. Older task state may still carry those hashes;
policy deletion and reload must never free or rename them. Collision and lifetime
capacity failures leave the registry unchanged. The registry is scoped to one
persistent task-state owner and must not be recreated on every revision. It is
not a substitute for production bootstrap, admission, or publication wiring.

## Prepared program publication

`ProgramSlot` is the native frozen-map publication building block for one future
persistent binding owner. `Begin` drains the shared gate and exposes immutable
staging slot1. Native bootstrap must establish its own proof before `Commit`
atomically replaces active slot0 and permanently records successful UID epochs.
Admission remains closed until native phase cleanup and `Finish`. Precommit
`Abort` preserves the last-good map. Failed staging/epoch cleanup is retained and
blocks new allocation, without restarting the old program. Shared handles cannot
complete another publisher's transaction. Every candidate attempt is monotonic;
removed/re-added UIDs retain their original successful epoch.

The native owner must exclusively control the borrowed maps/gate, enforce
aggregate budgets and retain the binding identity leases. It must clear bootstrap
phase before Finish/Abort, drain before StopGadget, and call CloseAfterDetach only
after actual runtime teardown. This building block neither attaches hooks nor
authorizes lineage or reports a production binding Ready. Its ordinary tests use
failure-injected maps; real map-in-map/freeze proof is separately opt-in.

`epoch_roles.h` is the work-copy merge helper, not a task-storage owner. Its caller
provides complete immutable accepted history and verified lineage, and publishes
only under the task lock after both task and authority versions still match.
Accepted scalar roles are not rerooted, and unactivated failed epochs cannot
become authoritative in another attempt. Kernel socket parity proof is separate
from the native C matrix and from production lifecycle wiring.

## Experimental assembled owner and native publication coordinator

**Legacy ABI2 reference:** this section and the native OCI lifecycle below do not
implement or qualify the shared-node replacement; see the
[shared Go boundary](#legacy-abi2-reference-and-shared-go-boundary).

The shared full source now has an explicit `ENFORCE_EXEC_PERSISTENT_OWNER`
profile. `../full/owner/Makefile` packages it separately; its metadata does **not**
advertise the incompatible immutable full-runtime capability. The profile shares
actual fact acquisition with the immutable evaluator, uses active frozen slot0,
and includes persistent role/control hooks. Compilation/BTF checks are not
verifier acceptance or a production activation claim.

`OwnerControl` borrows loaded maps and the operator's `program/eo_command` handle.
It freezes kernel-owned identity maps before activating the exact configuration,
and runs nonce-qualified commands on one dedicated OS thread. Accepted commands
are joined even when their context is canceled. Closing the worker joins calls
and destroys that physical thread; it never detaches hooks or releases pins.
The rejected negative-PID cgroup.procs write must produce both EINVAL and an
authenticated movement-arm receipt. A path parsing error alone proves nothing.

`Publisher` composes the shared gate, A/B inventory, root-group continuity checks,
immutable slot replacement, successful-only epoch flush, committed revalidation,
and phase clear. First startup must call ProgramSlot.Begin **before** activating
configuration, retain that prepared handle, authorize the exact root, then pass
it to NewPublisher and Resume. It must not briefly reopen an empty active slot.
Precommit refusals attempt bounded rollback; failed rollback retains the closed
handle. A map swap is irreversible even if history flush or a command's result
fails. Resume inspects kernel phase receipts and completes the same generation;
it never reroots accepted state or starts a replacement owner.

PublicationResult.Committed refers to the attempted revision, while Generation
identifies the currently active revision (which can still be last-good on a
refused attempt). Admitting means the gate is open, **not** production Ready.
Runtime leases, hook coverage, image evidence, aggregate budgets, OCI startup and
shutdown integration, and public decoder provenance remain native-owner duties.
Retire must succeed before StopGadget; identity pins remain held until confirmed
teardown. The opt-in assembled-kernel fixture is separate from OCI integration.

The assembled fixture has now passed with real hooks and the qualified worker,
including retained-role capacity refusal/last-good and postcommit recovery. It
also verifies native UAPI write/delete refusal on physical IDs and state. The
kernel does not support Freeze on a TASK_STORAGE value containing a spin lock;
see OWNER-ABI.md for the frozen-cookie + read-only-native-hash layout and its
lifetime/privileged-handle assumptions. Native OCI integration and the embedding's persistent backend are now connected
and have isolated pinned-kernel proof; production/general-environment readiness
is not implied.

## Native OCI lifecycle (isolated pinned-environment proof)

`NewOwner` reserves a **shared** aggregate Budget and exclusive cgroup scope
before the OCI collection can load. All owners in one embedding must share that
budget. Native owner images must contain exactly one eBPF layer and no WASM or other
layers. OCI admission enforces this before initializing any image operators,
including when a supplied native owner encounters missing/rewritten ABI metadata.
Additional collections (including duplicate names) also invalidate native resource
admission.
Resource manifests are checked both at admission and again immediately before
allocation, after parameter, context-variable and enricher rewrites:
map payload capacities,
physical local-storage credits, encoded instruction ceilings and two frozen
program slots are accounted. This is bounded capacity accounting, **not** a
measurement or guarantee of kernel/Go RSS, allocator overhead or JIT expansion.
Reservations remain held until confirmed teardown, including failed startup.

### Attach capacity, readiness and the owner cap (G009)

There is no source-derived owner ceiling. The capacity is the measured
per-trampoline link limit, probed with no-op fillers on both exact AL2023
kernels (`test/al2023-trampoline-cap`):

| hook (trampoline) | kind | 6.12.113-138.209 | 6.18.56-125.164 | preexisting |
|---|---|---|---|---|
| bprm_check_security, task_alloc, task_free, socket_connect, inode_init_security_anon | LSM | 38 | 38 | 0 |
| file_open | LSM | 37 | 37 | 1 (stock VM) |
| bprm_execve, cgroup_migrate, copy_process | fentry, fexit | 38 | 38 | 0 |
| bprm_execve, bprm_check_security | mixed fentry/fexit(/LSM) | 38 | 38 | 0 |

That is **38 links per hook on both kernels** (`BPF_MAX_TRAMP_LINKS`; the
limit hit is `E2BIG` from the link count, not the trampoline image size),
shared by fentry, fexit, fmod_ret and LSM programs on the same trampoline (an
LSM hook `X` uses the trampoline of `bpf_lsm_X`). The 38 is shared with every
other BPF consumer on the node, as the preexisting `file_open` link shows.

* **K/R policy.** Each enforcement family may use at most `K` links per hook
  and must leave `R` free for third parties. `R` defaults to **8**
  (`nativeattach.DefaultReservePerHook`; `operators.NativeAttachReserveKey`
  overrides it), so at most 30 per hook are usable by enforcement families
  together. `K` is the family's own need per hook, derived from its packaged
  attach set, and must be **at most 8** (`nativeattach.MaxFamilyLinksPerHook`).
  The exec candidate needs at most **3** on any hook: bprm_execve 3, and 1
  each on task_free, task_alloc, security_bprm_creds_for_exec and
  bprm_check_security.
* **Packaged attach set.** The candidate's ELF has 13 programs on
  bprm_check_security; 11 are tail-call targets and must never be attached.
  `bpf/opaque_real_owner_child_candidate.programs.yaml` is the gadget.yaml
  `programs:` block that marks every trampoline program outside the steady
  state `attach_to: gadget_program_disabled` (tail-call targets, the two
  bootstrap programs, two diagnostics). The eBPF operator skips those programs
  and leaves them out of `K`. `TestCandidateAttachSetDeclaration` and
  `TestCandidateAttachSetObjects` (with `IG_ENFORCE_EXEC_CANDIDATE_OBJECTS`)
  derive the attach set from that block plus the object and pin it.
  The shared-node qualification path (Phase A, `shared_host.go`) pins the
  steady state at **16 links**: 8 trampoline links
  (`sharedCandidateAttachSet`: 2 on task_free (the product release and the
  exec capsule's death retire), task_alloc, 3 on bprm_execve,
  creds_for_exec, bprm_check_security) and 8 probe links that take no
  trampoline slot (`sharedCandidateProbeSet`: the credit-at-exit
  `tp_btf/sched_process_exit`, the four exec failure-frame kprobes, the
  `free_task` birth kprobe, the `sched_process_fork` raw_tp and the
  `sched_process_exec` tp_btf). It also pins one enabled syscall command,
  `opaque_real_reap` (`sharedCandidateCommandSet`), which is never attached:
  `startLiveCandidate` borrows it and runs the product reaper (`NewReaper`)
  over it with BPF_PROG_TEST_RUN. Every other syscall program stays
  disabled.
* **Product object and diagnostic twins (G019 section 8).** The same
  source builds both. Their enabled set is identical (the 16 links and the
  one command above); they differ in what is compiled in:

  | | Product object | Diagnostic twin (M3, qualified loader) |
  |---|---|---|
  | Build | no `REAL_RECOVERY`, `PRCTL_ARM`, `REAL_LIVE_BOOTSTRAP`; `REAP_EVENTS`, `EXIT_CREDIT`, `-DSE_PRODUCT_NO_TEST_RUN=1` | recovery, live bootstrap (route migration, reload), `REAP_EVENTS`, `EXIT_CREDIT`, `-DSE_PRODUCT_NO_POOL_REAPER=1` |
  | TC (SchedCLS) programs | none | bootstrap, seed, reap, recovery (`se_rm_*`, `se_command`) and TEST_RUN probes: loaded, all disabled |
  | `se_rm_*` programs and maps | not compiled | TC, disabled |
  | Pool reaper (`se_pool_reaper_*`, `se_pool_reap_*`) | not compiled | not compiled |
  | `se_command` | protocol-only `syscall` (`full/shared_control.h`), disabled | TC, disabled |
  | `se_publication_arm` | `fexit/cgroup_kn_lock_live`, disabled | `lsm/task_prctl`, disabled |
  | TEST_RUN probes (`terminal_race_complete`, `work_completion_probe`, `work_retry_probe`) and their gate/selector maps | not compiled (`SE_PRODUCT_NO_TEST_RUN`) | TC, disabled |
  | Terminal-race rendezvous (`opaque_real_terminal_race_witness`, the bounded `bpf_ktime` spin in every WORK completion) | not compiled (`SE_TERMINAL_RACE_RENDEZVOUS` needs `!SE_PRODUCT_NO_TEST_RUN`); only the retain tail-call target stays | compiled |
  | Synchronous WORK return (`ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE`: `se_owk_visit_claims`, `opaque_real_work_sync`) | compiled | the burst twins (`g19dec2sync128`, `g19pkgm3sync128`) only; the recovery/OFF identity objects stay without it |
  | Reaper | product reaper: `opaque_real_reap` + `opaque_real_reap_events` (the visit helpers are built for `REAP_EVENTS` without recovery) | the same |
  | Metadata | `candidate/gadget.yaml` + `bpf/…programs.yaml` | + `candidate/gadget.diagnostic.yaml` + `bpf/…programs.diagnostic.yaml` |

  `SE_PRODUCT_NO_TEST_RUN` refuses to compile with recovery, PRCTL_ARM,
  live bootstrap, the abort injector, the deferred storage witness, the
  pending-receipt diagnostic or the fail-closed injectors, and without the
  reap events; reap events without recovery are refused outside the
  product object, and without credit at exit (its `held-stuck` witness is
  the only counter of a death lease left held on a DEAD charge, which the
  reaper otherwise sees as PENDING forever). Reap-event profiles without
  credit at exit (the `off` objects) are recovery builds for qualification
  only, never a product. `TestOpaqueRealVerdictCandidateCompileGuards` pins those
  guards and classifies every TC entrypoint of the source;
  `IG_ENFORCE_EXEC_PRODUCT_OBJECTS` runs `TestCandidateAttachSetObjects`
  and `TestSharedCandidateMergedMetadataObjects` on product objects (no
  SchedCLS program, no `se_rm_*`, no `se_pool_reap*`). The product object
  needs syscall programs that take spin locks (`opaque_real_reap`), so it
  needs kernel ≥ 5.14 (qualified on AL2023 6.12 and 6.18); stock Rocky 4.18
  is not supported by it.
* **Legacy Owner cap.** `NewBudget` refuses more than `LegacyOwnerHardCap`
  (**2**) owners and `NewOwner` refuses a third owner, both with
  `ErrLegacyOwnerCap`, before anything of it is loaded or attached. Each
  owner attaches 10 trampoline links of its own. One Budget must be shared
  per node.
* **No support claim for owner concurrency.** Neither the legacy Owner cap nor
  the 38-link measurement is a supported concurrency figure. Running more
  than one owner per node, or any number of owners next to other BPF
  consumers, is not claimed to be supported; per-owner concurrency is G019.
* **Transactional attach.** Every collection admitted by a native resource
  validator (and only those; ordinary gadgets are unchanged) is attached by
  `pkg/operators/ebpf/nativeattach`: in a fixed order (`nativeattach.Rank`:
  task_free first (the release and the exec capsule's death retire), then the
  `sched_process_exit` tp_btf, task_alloc, movement/cgroup/other hooks, then
  decision hooks: bprm_execve fexit, fentry, creds_for_exec,
  bprm_check_security), all-or-nothing. Stop closes the links in exact
  reverse, so every "attached before" also holds as "detached after": the
  task_free programs detach last, the exit link before task_free (exit credit
  never runs without its task_free consumer), task_alloc before both. Any attach error
  closes this collection's links in reverse order before Start returns, and
  `E2BIG` is a typed `*nativeattach.ErrAttachCapacity{Target, Attached, Err}`
  naming the trampoline. Receipts are published only after every link is
  attached, and a missing receipt fails the transaction.
* **Reserve (hint).** Before attaching, the live links per trampoline are
  counted (`BPF_LINK_GET_NEXT_ID` plus link info). The family refuses with
  `ErrAttachCapacity` unless `K + R` links are free. The hint is not the
  authority; the attach and rollback are.
* **Automatic retry (default).** Every native family retries by default
  (`nativeattach.DefaultRetry`: 500ms doubling to a 30s cap, no attempt
  bound). A capacity refusal does not fail Start: Start blocks, retrying,
  until the family attaches or the gadget context is canceled. While it
  waits the family is NotReady, and each refusal is logged as a typed
  `ErrAttachCapacity` that names the target trampoline. Each attempt re-runs
  the hint and the whole transaction, and a refused attempt leaves no link or
  receipt, so there is never a partial hook set. Errors other than capacity
  (for example a failed link count) are returned at once. A family may
  install its own `nativeattach.Retry` under `operators.NativeAttachRetryKey`
  (`State` then receives every NotReady, Ready and a final non-capacity
  error), or `false` to opt out. `Retry.Budget` bounds the total time from
  the first attempt (0: no time bound).
* **The shared node retries a bounded number of times.**
  `WithNodeEnforcer` sets an explicit `nativeattach.Retry`
  (`sharedNodeAttachRetry`): at most 8 attempts, 500 ms doubling to a 5 s
  cap, and no wait that would end past 30 s from the first attempt, so
  Start returns within about 30 s plus the final attempt. Admission refuses
  the node unless the effective `NativeAttachRetryKey` is a
  `nativeattach.Retry` with `MaxAttempts > 0` and `Budget > 0`. While
  `StartNode` is blocked in the retry, `SharedNodeConfig.AttachState` (if
  set) receives every `*nativeattach.ErrAttachCapacity` (the host shows the
  node NotReady with it) and then nil once attached; `Ready` itself is only
  reachable after `StartNode` returns. When the retry runs out, nothing
  stays attached and `StartNode` returns `ErrSharedNodeNotReady` wrapping
  the last refusal; it never falls open. **Limits:** the retry runs inside
  the gadget's Start, under the manager's lifecycle lock. It can only help
  when the links that fill the trampoline belong to something outside this
  manager. Within the same manager it only adds delay: a stop or replace
  that would free links waits for the lock. Moving the retry out of the
  lock, so that the host retries `StartGadget`, is a follow-up: it changes
  the instance-manager contract that other gadgets share.
* **Legacy Owner refuses at once.** `WithOwner` sets
  `operators.NativeAttachRetryKey` to `false`: the legacy per-cgroup Owner
  does not retry and its Start returns the capacity refusal immediately.
* **Link-based programs only.** Rollback closes bpf links only. A native
  family is therefore refused, before anything is attached and without
  retry, if an enabled program would attach without a bpf link or with side
  effects rollback cannot undo (kprobes/uprobes, tracepoints, perf events,
  socket filters, TC, sockmap programs, iterators). Admitted are LSM and
  fentry/fexit/tp_btf links, syscall commands and admitted recovery TEST_RUN
  programs, which covers the exec candidate and owner families.
* **Readiness component.** In the native path each receipt's `Check` also
  verifies, by link ID, that the link still exists and references the same
  program. A missing or replaced link returns `*nativeattach.ErrNotReady`
  naming the target; a stale Ready is never reported. This is a component
  check of the product node's `Ready` (a failed receipt fails it with
  `ErrSharedNodeNotReady`); a qualification node's `Ready` stays unavailable.

The native data operator verifies live, operator-owned attachment receipts for
all required hooks, not just image annotations/program FDs. It validates the
trusted transferred lease's proc/cgroup/namespace pins, independently refuses a
root cgroup or the host mount namespace, initializes immutable origins and probes
its own filesystem marker before activating scope. The lease must authenticate
runtime ownership, genuine host identity, stable root/mount constraints and any
complete image-origin evidence. It must not reenter Owner methods.

The exact x86_64 kernel matrix retains the original archived BTF digest
`12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b`.
The additional individually proved artifact has BTF digest
`759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51`:
same Linux source `6b4b543fa18757297ac756a6fe6e64f506b7844a`, with fanotify,
redirect/NAT and CPU bandwidth configuration needed by Kubernetes, plus a
separate local version. Its complete isolated upstream proof and artifact hashes
are recorded in [KERNEL-MATRIX.md](KERNEL-MATRIX.md); private Kubernetes/OTLP
integration remains separate and pending. Both exact gates require
active BPF LSM and enabled ftrace. Unknown digests refuse; neither a matching
release string nor the same source commit establishes support. No general
released-kernel or arm64 support is claimed.

Lifecycle ordering is deliberate:
1. Construct Owner; pass WithOwner and the native data operator to the manager.
2. StartGadget prepares only: scope remains gated and no policy is committed.
3. **After StartGadget succeeds**, explicitly Activate and verify Owner.Check.
4. Update/Resume use the same hooks/maps/task histories, never ReplaceGadget.
5. **Before StopGadget**, successfully drain/retire with BeforeStop. A timeout
   retains old admission/enforcement; do not cancel the runtime in that case.
6. Wait for manager teardown, then ReleaseAfterDetach. Operator Close joins the
   qualified command thread but intentionally does not release identity pins or
   the reservation before eBPF FDs/links are confirmed closed.

Internal owner ABI **2** adds active-only, same-generation physical re-attestation.
ABI1 development artifacts are rejected; the chart version is unchanged.
Movement invalidates the inventory receipt. Only a publication renews it, behind
a closed/drained gate, with no new roots or epoch writes; unknown ingress refuses
that publication. `Owner.Check` is read-only and does not renew or require it
(see "The heartbeat never closes admission"). Publication pauses can disrupt
exec/runtime helpers; there are no inferred exemptions. The native Owner no
longer issues `EO_REATTEST`; the command stays in the ABI.
The native OCI fixture and ABI2 re-attestation passed isolated runs (before the
read-only heartbeat change) with controlled synthetic leases, real datasource
bitmaps and confirmed teardown. After the change, the OCI fixture's new
expectations and the heartbeat churn test passed on the k8s proof kernel
(2026-11-16); the other owner kernel suites passed on the same change before the
heartbeat test's fork count was reduced.
This is not proof of containerd/CRI authenticity, all persistent-profile predicate
combinations, real runtime-helper churn, or the connected node-agent backend.
Those integration prerequisites remain before default activation.

## Reproducible supported owner artifact

The default upstream builder is not proof for this experimental profile. Build an
explicit amd64 archive with the tested compiler and exact supported kernel BTF:

```sh
make -C gadgets/enforce_exec/full/owner archive \
  VMLINUX_BTF=/trusted/vmlinux.btf CLANG=clang-21 BPFTOOL=bpftool \
  IMAGE=localhost/enforce-exec-owner:abi2 ARCHIVE=/tmp/owner.tar
```

This requires Clang 21.1.8 and an exact admitted BTF digest; it never loads BPF.
The archive contains the unchanged owner metadata and a single amd64 platform.
Its compiler/BTF/input bytes are trusted build inputs, not policy-provided code.
Compilation alone is not verifier proof: Clang 19 produced a refused object on
the tested kernel. The embedding's combined fixture accepts the resulting archive
through the same native ORAS tar path as its service configuration.

**H1 root anchor recorded at Bind (accepted residual, review 2026-11-13).**
Every path fact is anchored to the binding's root, recorded by the kernel at
the adoption finish from the adopted init (its fs root: mount id, inode,
device, and its mount namespace); an exec whose root differs, or whose
`fs_struct` root changes while the pass's paths are read (a sibling thread or
`CLONE_FS` task calling `chroot`), has every path fact UNKNOWN
(`SE_PF_ROOT_MISMATCH`). The anchor is whatever root the init has at that
moment: a workload that chroots BEFORE Bind chooses its own anchor. Accepted:
code running before Bind is the container runtime and the container's init,
trusted at adoption (the same trust boundary as the D3/D4 residuals above);
everything after adoption is held to the recorded anchor.

**Mount over a path after adoption (accepted residual).** The
anchor detects a root change; it does not prevent a mount. A mount over a
path inside the same root after adoption (for example over `/usr/bin`)
leaves the root's mount, inode, device and mount namespace unchanged, so
the anchor stays valid and path facts describe the mounted content.
Precondition: `CAP_SYS_ADMIN` over the container's mount namespace (a
privileged container, or one granted `CAP_SYS_ADMIN`). A new mount
namespace does not help the workload: it differs from the anchor, so every
path fact of its execs is UNKNOWN. Accepted for now: run enforced
containers without `CAP_SYS_ADMIN`. The legacy owner delegates the same
question to the pod's seccomp profile (its root contract). Follow-up:
accept an attested shared root barrier (kubescape/inspektor-gadget#26) as
an input on both paths,
so the host can drop the seccomp and capability preconditions.

## Shared-node live health: fail-closed rate witness and accepted G019 residuals

This section supersedes the earlier statements that nothing reads the
fail-closed rate witness at runtime.

**Fail-closed rate witness (G019/G025).** A live qualified node polls
`opaque_real_fail_closed_rates` and `opaque_real_attempts`
(`sharedLiveFailClosed`, `shared_fail_closed_health.go`) every
`SharedNodeConfig.FailClosedPollInterval` (default 5 s, bounded to
[100 ms, 30 s]) into a bounded ring that covers the 5 min window. Each sample
reads the rate cells before the attempts (BPF counts an attempt before its
failure). The runtime reporting rule of `fail_closed_rate.go` is applied
through `FailClosedProductRate`:

| State | Rule | Node health |
|---|---|---|
| Healthy | none of the below | - |
| Degraded (`ErrSharedFailClosedDegraded`) | any fail-closed refusal (Strict), unevaluated child (Audit) or ADMISSION fault within 60 s (threshold 0); clears after a quiet window | `Ready`, `Inspect` (binding `Fault`), qualified operator readiness |
| NotReady (`ErrSharedFailClosedNotReady`) | Total or ADMISSION rate above 0.1% over 5 min (over the node's age while it is younger) | as Degraded |
| Unknown (wraps NotReady) | unreadable witness, a counter moving backwards, or counts `FailClosedProductRate` refuses (ENTRY + ADMISSION + Total above the attempts); sticky until node teardown. A poller with no sample for 3 intervals is Unknown while stalled | as Degraded, and the `StopNode` result |

ENTRY [11] and ADMISSION [12] are outside Total; the denominator of Total is
the attempts minus ENTRY minus ADMISSION, and every rate is per attempt.
ENTRY never degrades. A window's attempts start one sample before its base
sample, so an attempt counted before the base read whose failure lands after
it (a fork's target re-admission) never reads as an inconsistent witness; the
rate is diluted by at most one interval per window. `NodeEnforcer.FailClosedHealth`
reports the state, both window verdicts and the counters since node start.
Only a product object served by its own product publisher is gated (it must
carry the 13-cell witness with `opaque_real_attempts`, or startup is
refused). An object behind a qualification publisher override (the bootstrap
publisher, whose untracked tasks are refused by design) is reported only, and
a legacy 11-cell witness has no denominator: its failures are reported and its
state is Unknown, never a node health input. A refusal rate is never a teardown
failure; only a sticky Unknown is. `NodeEnforcer.Ready` still returns
`ErrSharedNativeUnavailable`.

Class [9] (GAP) counts only the interpreter continuation's refusals (G019
gap 4, H1): `REAL_OWNER_RATE_GAP` is incremented at the one continuation
refusal site (`real_owner_continue_refuse`), with its reason in
`opaque_real_interp_stats`. A later pass refused for a terminal fault before
any continuation counts QUALIFY [6] or PENDING [7], as a first pass does,
never also GAP. Migration relabel (gap 5) is a binding status
(`MigrationOutUnenforced`), never a counted refusal. The G019 gaps 1-3
refusals land in CONSTRUCT [5], QUALIFY [6] and OPEN_PARENT [8], not in
GAP.

**Ancestor membership is node-wide (accepted residual, G020 re-review).** The
ancestor walk ends complete at the workload's edge: the first parent without a
TASK in `se_opaque_keys`. That map holds the TASKs of every binding, so a task
of ANOTHER enforced binding counts as a member and the walk continues through
it; its executable must then be reachable from this binding's anchored root,
else the whole ancestor fact is UNKNOWN. Over-inclusion therefore needs both a
root shared by the two bindings and a cross-binding parent, which only cgroup
migration produces (the migration relabel residual below). Scoping membership
to the pass's binding would need the TASK's lease/open per ancestor (its scope
lives only in the TASK payload), too heavy for the walk.

**Gap 5, migration relabel (accepted residual, D1/U3).** A TASK-carrying task
moved out of a Strict binding's cgroup into an unrouted cgroup is not
enforced there: admission follows the current cgroup and the migration is not
relabelled. Every published Strict binding reports
`SharedBindingStatus.MigrationOutUnenforced` until the gap is closed. The
label is a status, never a `Fault`. Admission's refusal of privileged and
cgroup-writable pods (U3) narrows who can migrate.

**Gap 6, reload class (accepted).** A route's execution class is frozen at
its first publication, and in-flight execs carry it (the frozen-class
ADMISSION check). A revision that changes the class (Audit to Strict or
back) is refused, terminal, with `ErrSharedClassChange` (wrapping
`ErrSharedNativeUnavailable`). `BindingSession.Publish` refuses it before
any command. The product publisher also names a kernel-refused revise whose
route holds another class. The binding keeps its last-good route. A class
change needs a new binding. Withdrawal is terminal for the cgroup (D5), so
that means a new container bound with the new class.
`TestSharedNodeClassChangeRefusedAttached` (M4 environment:
`IG_SHARED_M4_OBJECT`, `IG_SHARED_M4_CGROUP_ROOT`,
`IG_SHARED_M4_HANDLER_SYMBOL`) asserts the refusal on the isolated VM. It
checks both the Go path and the kernel path. After each refusal it checks
last-good, that no policy object leaks, that the witness is unchanged, and
that a same-class revision commits.
