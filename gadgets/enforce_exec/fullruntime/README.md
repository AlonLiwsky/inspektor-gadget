# Shared exec enforcement engine

This package is the shared CO-RE exec enforcement engine: one node-wide
`NodeEnforcer` per node, started with `StartNode`, that loads one product
object per profile (`g19pkg64/128/256/512`, one CO-RE object for every
kernel), binds up to two containers and publishes their compiled policies.
`New()` is the data operator (`enforce-exec-owner`) that claims the shared
node's host gadget; every other gadget gets no instance from it.

Every kernel is admitted the same way, on probes run at start and while the
node runs (see [Shared engine: supported kernels](#shared-engine-supported-kernels)).

## Shared-node implementation status and API contracts

`NodeEnforcer.Ready` depends on how the node was started:

- **Product node** (`WithSharedNodeHost`, a build without the
  `enforce_exec_shared_qualification` tag): `StartNode` admits every x86_64
  kernel that passes the product kernel gate (`SharedProductKernel`: bpf
  LSM, ftrace on, no livepatch, readable identity), with a product object of
  this release (see
  [Shared engine: supported kernels](#shared-engine-supported-kernels)), and
  refuses everything else with `ErrSharedNativeUnavailable` and the reason.
  Startup also verifies the root barrier (see [Root barrier](#root-barrier));
  a failure there is NotReady and the node does not start.
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
In the product, commit and withdrawal are `SEC("syscall")` commands run by the
agent's admin thread and authenticated by profile, admin nonce, node cookie and
sequence: `opaque_real_route_publish` commits and `opaque_real_route_withdraw`
withdraws (`fullruntime/bpf/opaque_real_owner_product_publisher.h`).
`se_publication_arm` (the `cgroup_kn_lock_live` fexit) is
`gadget_program_disabled` there
(`fullruntime/bpf/opaque_real_owner_child_candidate.programs.yaml`); it is the
commit/withdrawal producer only on the protocol (qualification) path, where a
syscall receipt is not a producer. `se_arm_frame` is per-CPU scratch, not
epoch authority. Shared exec
reads `se_epoch_bank` through the kernel-owned `se_epoch_index`. `SE_ARM_BIND`
reserves that index on an earlier barrier; commit only accepts an index that
already names the cell. The unread `se_accepted_epochs` hash is not that
catalogue.

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
exception index, if the predicate is in one) and the predicate kind.

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
| `Actor.FromImage` / `Target.FromImage` (`actor.fromImage` / `target.fromImage`) | image origin (`actor_image`/`target_image`) from the binding's sealed image index: 1 the file is backed by an indexed read-only lower layer of the container's own overlay; 0 not from the image (an upper or copied-up file, another filesystem, a foreign overlay); -1 UNKNOWN (no index, backing file failing the pointer-chain check, writable layer, memfd, overlay layout unavailable, any read fault). A FromImage policy is refused at publish without a sealed index | supported |
| `Target.Argv.Contains` / `Prefix` (`target.argv`) | argv | **refused for the PoC**: the stock-kernel product evaluator has no authoritative argv fact (documented limitation, follow-up issue) |

`FromImage` is layer classification, not content authentication. The
classifier (`full/shared_image_classify.h`) validates the overlay pointer chain
from the exec file to its backing real file; no digest, fs-verity or IMA check
runs, so someone who can modify a lower layer on the host defeats it:

| Level | Name | What it proves | Product |
|---|---|---|---|
| L1 | Pathname match | the resolved path matches a pattern | `Actor.Path`, `Target.Path` |
| L2 | Layer classification | the file is backed by an indexed read-only lower layer of the container's own overlay, not the writable layer | `FromImage` |
| L3 | Authenticated image provenance | the file's content matches a digest tied to the image (fs-verity, IMA or a verified layer) | not offered |

The header comment's "authenticated backing real file" means this pointer-chain
check (L2), not L3.

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
  identity when its receipt is still present, 0 otherwise. An owned exec
  pass that never reaches a policy program (ENTRY, a failed open or reader
  begin, a pending or terminal fault, a failed transfer) emits its one fault
  event from the `bprm_check_security` program; it usually has no receipt,
  so its `generation` and `scope` are 0 and the consumer attributes it by
  `cgroup` to the binding's committed publication (SUB-10297). It carries
  the exec file's path when known (best effort, for the report only:
  `bpf_path_d_path` of `bprm->file`, absolute, at most 255 bytes, not
  anchored or walked to the root like the pass facts; a deleted file keeps
  the " (deleted)" suffix), else `path_result` -1. A fork refusal emits no
  event.
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

The shared engine (product node) admits every x86_64 kernel the same way,
on its probes (`SharedProductKernel`, re-run by `StartNode` and at image
instantiation): `bpf` in the active LSM list, `ftrace_enabled=1`, no
livepatch (`TAINT_LIVEPATCH` clear), and a readable identity (a
lowercase-hex vmlinux BTF sha256, a non-empty release, a lowercase-hex GNU
build-id). Anything else is refused. No kernel build list takes part in the
admission: the node reads the identity of every kernel (the BTF sha256 of
`/sys/kernel/btf/vmlinux`, the GNU build-id from `/sys/kernel/notes` and the
release from `uname -r`), refuses one it cannot read, and reports it (status
and logs); it never matches it against a list.

What is proved on every admitted kernel, at start and while it runs:

- the product object's own load checks every type, field, kfunc and attach
  target it uses (CO-RE relocation and the verifier);
- `FMODE_BACKING` and the overlay `private_data` layout are probed live; a
  failed `FMODE_BACKING` probe refuses (FromImage facts are unavailable and
  the node is Degraded); it is never cached;
- the startup canary proves every attached program runs;
- the live witness latches NotReady when an exec or fork reaches its
  tracepoint without its LSM hook's mark, or when ftrace goes off.

What is not proved: hook ordering and verdict semantics across the exec
paths (see [What the probes cannot prove](#what-the-probes-cannot-prove)).
There is no startup deny self-test: a test binding would hold one of the
node's two route slots until teardown.

Ftrace and livepatch are re-read at every `Ready` (`CheckKernelRuntime`).
Ftrace is detected, not guarded: `sysctl kernel.ftrace_enabled=0` is
accepted while the node runs, and `Ready` reports NotReady ("ftrace is not
enabled") at its next call. With ftrace off the BPF trampolines stop, so a
Strict deny can become an allow; treat a NotReady node as unprotected. Only
root can change the sysctl.

**D1 (LSM-only exec outcome).** The image carries no failure-frame
`attach_to` target; the exec frame is `lsm/bprm_creds_for_exec` ..
`lsm/bprm_committed_creds` (success) or `tp_btf/sys_exit` (failure) on every
kernel, and an `attach_to` override on any probe is refused. The loaded
eBPF object's sha256 (recorded by the eBPF operator for native owners,
`operators.NativeProgramDigestKey`) must be one of this release's product
objects (`sharedProductObjects`, `testdata/shared_product_objects.tsv`), on
every kernel alike; a rebuilt object with another digest is refused. Every
other kernel or image is refused at agent start (`StartNode`) with an error
that wraps `ErrSharedNativeUnavailable` and names the reason.

**Qualification builds.** A build with the `enforce_exec_shared_qualification`
tag admits the qualified candidate (`WithSharedNodeQualification`) on the
same checks (`verifySharedCandidateKernel`). There,
`IG_ENFORCE_EXEC_SKIP_LSM_LIST_GATE=1` skips only the LSM-list check, so the
canary negative test shows that the startup canary alone refuses a kernel
without the bpf LSM. A shared node that is neither a product nor a
qualification node is refused at instantiation.

**Kernel witness and startup canary (stage 1, `shared_kernel_witness.go`).**
StartNode makes every attached program prove it runs (the canary forks, execs
and exits; a silent program refuses the start), then requires the
`ftrace_enabled` weak ksym to have resolved, then judges the `d1_witness`
cells. Live, the node latches NotReady until restart when the syscall exit
reads `kernel.ftrace_enabled == 0`, or when an exec or fork reaches its
tracepoint (`sched_process_exec`, `sched_process_fork`) without the mark its
LSM hook (`bprm_committed_creds`, `task_alloc`) leaves in the task's own BPF
task storage. A mark dies with its task, so no number of io_uring workers or
zombies can exhaust anything. **Start refusals and retry:** an exec or fork in
flight while the links attach reaches its tracepoint unmarked; StartNode
refuses with `ErrSharedKernelWitness` wrapping
`ErrSharedKernelWitnessRetryable`, and the agent retries StartNode with
backoff (a fresh load counts from zero; `StartNodeRetrying` bounds the
attempts and doubles the wait up to a cap). A refusal with ftrace seen off, the
ksym unresolved or a failed mark creation is not retryable for this boot.
The canary is also public as `RunAttachCanary(ctx, receipts, canaryCmd)` for
programs outside this engine (node-agent's privilege, network and file
sections run it with their own child). A silent program is
`ErrAttachCanarySilent` (`*AttachCanarySilentError` names the programs); any
other canary failure says nothing about the hooks and is not marked.

**Witness memory (DaemonSet sizing).** A mark lives in BPF task storage,
allocated with `GFP_ATOMIC` from the BPF memory allocator and charged to the
agent's memory cgroup. On a 6.12 kernel an element is `sizeof(struct
bpf_local_storage_elem)` (128 bytes, cache-line aligned) plus the 16-byte mark,
taken from the 192-byte size class; a task's first task-storage element also
allocates its `struct bpf_local_storage` (about 176 bytes, 192-byte class),
shared with the engine's other task-storage maps. So each live task that forked
(its own fork mark) and exec'd (its exec mark) since the agent loaded holds at
most 2 x 192 + 192 = 576 bytes, freed with the task: about 58 MB per 100,000
live tasks in the worst case. Size the node-agent DaemonSet memory limit with
headroom for `576 B * max_live_tasks` above the agent's baseline (for example,
about 58 MiB for 100,000 live tasks). A creation that fails (memory limit) is
counted in cell [10] and latches the node NotReady (`ErrSharedKernelWitness`);
it refuses with `-ENOMEM` only when the task is in a Strict-bound cgroup, so
Audit, unbound, and host tasks are never blocked.

**One syscall-exit program.** `real_owner_capsule_terminal`
(`tp_btf/sys_exit`) carries the ftrace witness and, for exec syscalls only
(x86_64, ia32 and x32 `execve`/`execveat`), the failure terminal and the
capsule terminal (there were two `sys_exit` programs). Every syscall of every
task on the node still pays for the syscall-tracepoint slow path that any
`sys_exit` program enables.

**One CO-RE object per profile.** The product objects are not built per
kernel: per-kernel builds had identical instructions after CO-RE relocation
and differed only in unrelocated placeholders and in the BTF/DWARF copied
from each kernel's `vmlinux.h`. `sharedProductObjects` (`kernel_matrix.go`,
`testdata/shared_product_objects.tsv`) pins four sha256 per release
(`g19pkg64/128/256/512`), for every kernel. The overlay `private_data`
layout is derived from the overlay BTF shape and relocated by the object
(`struct ovl_file___se_image`), and `FMODE_BACKING`, a preprocessor constant
that BTF does not carry and that changed inside the 6.12 stable series, is
probed live (`kernel_probe.go`) on every kernel: a failed probe refuses.
Every path refuses a kernel without the bpf LSM, with ftrace off, or
livepatched. The objects are built with `ENFORCE_EXEC_D1_LSM_ONLY`: there are
no failure-frame symbols to resolve.

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
the node stops.

**Rebuilding the pinned objects.** `bpf/build-product.sh`
rebuilds the four product objects (`g19pkg64/128/256/512`; one CO-RE
object per profile for every kernel) with the exact flag set of the
qualification build plus `ENFORCE_EXEC_D1_LSM_ONLY` (at neutral paths, see
below), and `--check` compares
each sha256 with `testdata/shared_product_objects.tsv`. Build it in the pinned
Debian trixie container: the CI job `test-enforce-exec-product-objects`
does, and `make enforce-exec-product-objects` runs the same image and
scripts with docker. `bpf/install-product-toolchain.sh` installs every
package from one snapshot.debian.org timestamp, and checks the packages
that decide the bytes against `bpf/product-toolchain-debs.sha256`:
`clang-21` `1:21.1.8-3~bpo13+2` (its version string is in the object) and
its libraries, and `libbpf-dev`/`libbpf1` `1:1.5.0-3` (the headers).
`build-product.sh` refuses another Clang or libbpf-dev version. The one
CO-RE `vmlinux.h` (a `bpftool btf dump` of a 6.18 kernel BTF; only its types
are used, every access is relocated at load) is committed xz-compressed as
`testdata/core-vmlinux/vmlinux.h.xz`; the decompressed sha256 is checked.

**Neutral build paths (pinset p1).** The objects carry, in DWARF and BTF,
the absolute paths of the build (the BTF line text and FWD type order depend
on them). The script therefore always compiles at fixed real directories it
creates in the container, `/src/inspektor-gadget` (a copy of the BPF sources)
and `/src/btf/6.18` (the header directory name is part of the object bytes), never at the checkout path, and refuses an object
that embeds `/home/`, `/root/` or the checkout path. The objects are
byte-identical from any checkout path (measured for stage 1: the pinned
toolchain image and the CI image with `install-product-toolchain.sh`, at two
checkout paths, built the same four sha256). Prefix maps are not used: a
measured `-fdebug-prefix-map` build changed the FWD order of the objects.

### Product images

Each pinned object is packaged into one product gadget image per profile, built in the default build by `BuildSharedProductImage`
(`shared_product_oci.go`): an index holding exactly one `linux/amd64`
manifest, whose config is the merged product metadata
(`candidate/gadget.yaml`, the packaged attach declaration, the geometry
annotations and the event ABI; stage 1 has no failure-frame attach target)
and whose one layer is the object. Nothing time- or host-dependent is
written (no annotations, no timestamps, the platform is fixed), so the
digests are a function of the object and this source. The images are
**never pushed to a registry**: the node-agent image build rebuilds them from
source into its `tracers.tar` and must reproduce the pinned digests. The same
image runs on every kernel the product gate admits.

| Profile | Image (local reference) | Manifest digest | Index digest |
|---|---|---|---|
| `g19pkg64` | `enforce-exec-shared:g19pkg64` | `sha256:c81ec63b28c6ae895ce67fe64254d5fee2ba67b3fed500d7e6e44278d1d52c95` | `sha256:501be35185c1882713093c18d6c72f008166843046c32e407ef661849c361c0f` |
| `g19pkg128` | `enforce-exec-shared:g19pkg128` | `sha256:746c11ace33245d2357ebb216b5eb7ce6115cdcec8687a4d4ae573dd7db20e6e` | `sha256:1b8adc5e586849d2d6e00270c4597afee0afd91f3d51513b4760360c017383a0` |
| `g19pkg256` | `enforce-exec-shared:g19pkg256` | `sha256:1e243b0328c7f087aec1b6ee1655cdbd8016aec4e6ff93b71c58fbac8b12dfe9` | `sha256:83b18f853c55b25a448134191c4fb5d441d75f79dc2e3696dab7d694fb9a77e3` |
| `g19pkg512` | `enforce-exec-shared:g19pkg512` | `sha256:31a7a4f852ed2db88065edef0408ee4d618db5b158ecf8d8dee64e8dcc474fa0` | `sha256:411432979608b026451e0d08b162592e2f7985cef1b19dd288fd383e9ad32d09` |

The reference (tag) is not part of either digest.

- **Pins.** `testdata/shared_product_images.tsv` (profile, image, object
  sha256, manifest and index digest) mirrors `sharedProductImagePins`
  (`TestSharedProductImagePinsMatchTestdata`). `SharedProductImagePins()`
  exports them, one per profile in profile order (`g19pkg64`, `128`, `256`,
  `512`), with the object's `SharedProfile`. Its geometry is compiled into
  the object and annotated on the image (the geometry the qualification ran
  with, `TestSharedProductImageProfileMatchesQualification`). Its budget
  fields are host-side runtime limits, not in the object or the digests; the
  values are the qualification sizes: CompileBytes 8 MiB, TelemetryBytes
  4096, CandidateBytes 1 MiB, RolloutBytes 4096, PossibleCPUs 64 (see
  "Geometry limits" for the 64-CPU host limit). node-agent compiles in
  `g19pkg128`.
- **Names.** `enforce-exec-shared:<profile>`, tagged in a layout under its
  normalized name (`ghcr.io/inspektor-gadget/gadget/enforce-exec-shared:...`,
  like any short gadget name). The manifest-digest check is node-agent's,
  not IG's: the agent resolves the name in `tracers.tar` and pins the
  manifest digest, so a re-wrapped index (`ig image export`) is harmless. IG
  has no manifest or index check at run time; its runtime binding of an
  image is the loaded object's sha256 (one of this release's product
  objects), the probe targets (no `attach_to` override) and the geometry
  annotations.
- **Build.** `make enforce-exec-product-images` rebuilds the objects in the
  pinned container, then runs `cmd/productimages` on the host: it writes the
  OCI layout `enforce-exec-product-objects/layout` and
  `product-images.json`, prints one OK/FAIL line per image with the built
  (and, on FAIL, the pinned) digests, and fails unless every digest equals
  the pins. The CI job `test-enforce-exec-product-objects` runs the same
  steps and uploads the layout, the JSON and the check output
  (`check.log`) as the artifact `enforce-exec-product-images`.
- **The digest check is not optional.** `BuildSharedProductImage` itself
  compares the built manifest and index digests with the pin and returns an
  error wrapping `ErrSharedProductImageMismatch` (with both digests) on any
  difference. So the drift check applies to whoever builds the images: IG CI
  and node-agent's image build alike. The digests depend on this source (the
  metadata, the packaging, the emitter switch, the profile) and on the
  modules that encode the metadata (viper, yaml.v3, oras, image-spec) **as
  resolved by the building module**: node-agent's go.mod may select other
  versions than IG's, and IG's `replace` directives (for example
  `github.com/cilium/ebpf => github.com/matthyx/ebpf`) are not inherited by
  a module that imports IG. A build that resolves differently fails instead
  of shipping other digests. A change that is intended needs new pins (read
  the built digests from the FAIL lines or `product-images.json`) and a
  requalification.

The job only builds: loading the objects on a kernel is the manual
product-load run (`test/product-load`: build a bundle on a workstation, run
its guest script as root on any machine, judge the results).

### Exported kernel check (other enforcement sections)

The product kernel gate is exported for other BPF LSM sections
(`kernel_identity.go`, `kernel_matrix.go`), so they do not keep a copy of it:

- `SharedProductKernel() (KernelIdentity, error)`: the shared engine's
  product kernel gate on the running kernel, in order: architecture amd64, a
  readable lowercase-hex BTF digest, a non-empty release, a lowercase-hex
  build-id, then `bpf` in the active LSM list, `ftrace_enabled=1` and no
  livepatch. It returns the running identity (for status reporting). A
  refusal wraps both the `*KernelCheckError` (`errors.As`) and
  `ErrSharedNativeUnavailable`. `StartNode` and the product image admission
  run the same gate.
- `AdmitKernel() (KernelIdentity, error)`: the same checks, for the other
  BPF LSM sections; a refusal is a bare `*KernelCheckError` (it does not
  wrap `ErrSharedNativeUnavailable`). Every kernel is admitted the same way.
- `CheckKernelRuntime() error`: re-reads ftrace and the livepatch taint.
  Call it at every status computation; it is never cached.

Every failure is a `*KernelCheckError` whose `Check` names the failed check
(`arch`, `btf`, `release`, `build-id`, `bpf-lsm`, `ftrace`, `livepatch`)
and whose message gives the reason. A read failure is a failed check, never
a pass. If `AdmitKernel` fails, the section must not load. If
`CheckKernelRuntime` fails, the section is NotReady and counts as
unprotected: ftrace off stops BPF trampolines, so it is detected, not
guarded.

### What the probes cannot prove

CO-RE relocates field offsets and the verifier accepts or refuses the
object, but neither can verify:

- hook semantics and ordering across the exec paths;
- exec-path behaviour changed by distribution backports under the same
  version string.

The costs are asymmetric: if a kernel changed hook semantics or ordering,
Strict either fails closed node-wide (an exec outage) or silently misses an
exec path while reporting Ready. The startup canary and the live witness
reduce that risk (an unattached or silent hook refuses the start or latches
NotReady) but do not remove it: they prove the hooks run, not that the
verdicts are right. The product-load run (`test/product-load`) checks the
verdicts (Strict 126, Audit 0) on a given kernel.

### Support window

The rule, not a calendar date: every kernel that passes the product gate is
admitted. A livepatch, a missing bpf LSM, ftrace off or an unreadable
identity is refused on every build. A failed `FMODE_BACKING` probe does not
refuse the node: image-origin facts are then unavailable (the node reports
image facts Degraded and `fromImage` policies are refused), while exec
allow and deny by path keep working.

### Operational facts and unproven items

- An agent crash or restart leaves enforcement **off until the agent is
  restarted**: the in-kernel state dies with the agent's BPF objects. The gap
  is reported as Ready False. Enforcement is off between agent processes during
  a restart. A graceful stop reports `AgentStopping`.
- Out-of-tree or unsigned module taints are allowed: only the livepatch bit
  is gated.
- **Unproven:** SELinux enforcing; lockdown modes other than none; other BPF
  users beyond the synthetic coexistence tests; arm64.
- Argv predicates are refused (D1). The AT_EXECVE_CHECK and RETIRING residuals
  (D3/D4) and the migration-out residual (`MigrationOutUnenforced`) apply.

### Geometry limits

The geometry is fixed when the object is built; changing it needs a new
product object, new pins and a new qualification.

- **At most 64 possible CPUs per host** (hard limit). `SharedProfile.Validate`
  refuses `PossibleCPUs` above 64, and the shared node refuses a host whose
  possible CPU count (`ebpf.PossibleCPU`) is above 64 or above the profile's
  `PossibleCPUs` when the image is instantiated
  (`checkSharedPossibleCPUs`). The refusal is reported as
  `ErrSharedNativeUnavailable` ("actual possible CPUs N exceed shared
  profile (limit L, hard limit 64)"): the node is not started (fail closed),
  so there is **no shared enforcement** on such hosts (for example 96- or
  192-vCPU instances). The product profiles set `PossibleCPUs` to 64.

- **2 bindings per node** in every product object (`SE_PROFILE_BINDINGS=2`):
  at most two enforced containers per node. A third `Bind` is refused with
  `ErrSharedBindingCapacity`. A removed binding still counts until its route
  is recycled (its TASK credits returned), so a slot can be busy for a short
  time after `Remove`.
- **TASK and WORK per binding**: `g19pkg64` 64 / 8, `g19pkg128` 128 / 32,
  `g19pkg256` 256 / 32, `g19pkg512` 512 / 16. node-agent uses
  `g19pkg128`. WORK bounds concurrent evaluations: 32 WORK give a burst of
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

### Root barrier

The shared candidate's D1 objects (the product objects included) carry the
root barrier of `gadgets/common/root_barrier.h`
(kubescape/inspektor-gadget#26). It stops a covered task from changing its
root or its mount tree: `chroot`, `pivot_root`, a new user namespace, a clone
or `unshare` with `CLONE_NEWNS`, `setns` into a mount or user namespace (or
with type 0), `mount`, `move_mount`, `umount` and the new mount API.

- **Who is covered.** The barrier reads the exec verdict's own route state:
  a task is covered when its cgroup has an ACTIVE **Strict** route (an
  adopting or latched one included). An Audit route, no route, or a route
  that is withdrawn or being prepared covers nothing: Audit never blocks. A
  route invariant fault (a locator outside the route slots, a route with no
  valid class) is a Strict barrier fault: denied and counted. The route is
  per exact cgroup, like the exec verdict
  ([Scope, runtime helpers and operator consent](#scope-runtime-helpers-and-operator-consent)).
- **Programs.** Seven `rb_*` programs are in the pinned attach set
  (`sharedCandidateAttachSet`, 13 trampoline links in all). The barrier's
  `task_alloc` body runs inline in `opaque_real_owner_child_source_candidate`,
  right after the previous verdict check and before the birth claim: a
  denied clone takes no birth claim, TASK or WORK (only the D1 witness mark,
  created before the check, which the kernel frees with the task).
- **Start check.** After the kernel gate admitted the kernel and every attach
  receipt is present, a product node runs `rootbarrier.Verify`: BPF LSM
  active, ftrace enabled, each hook signature, a live LSM link for each
  barrier program (the inline `task_alloc` body matched by its program ID),
  then a self-test that sees real operations denied. A failure is NotReady
  (`ErrSharedNodeNotReady`): the node does not start. The attach canary does
  not wait for the seven `rb_*` programs (their hooks do not fire during a
  fork, exec and exit); the self-test proves each of them ran. After start,
  each `rb_*` link is an attach receipt, checked on every `Ready`, and the
  ftrace and livepatch re-read at every `Ready` covers the barrier too.
  The start check adds preconditions to a product node: the agent needs
  `CAP_SYS_ADMIN` and `CAP_SYS_CHROOT` (the self-test runs real `chroot`,
  `mount` and namespace operations on one of its own threads), user
  namespaces enabled (`CONFIG_USER_NS`, `user.max_user_namespaces` > 0: the
  self-test creates one and needs it denied by the barrier), BPF LSM,
  `kernel.ftrace_enabled=1` (`CONFIG_FUNCTION_TRACER`) and the
  `userns_create` hook (Linux 6.1 and later; the kernel gate does not probe
  it, but without it `rb_userns` cannot attach and the node does not start).
  A qualification node
  attaches the barrier but does not run the start check: it never reports
  Ready.
- **Faults.** The barrier's fault counter (`root_barrier_faults`) is a
  fail-closed class of its own, like ADMISSION: never part of Total, its rate
  per exec plus birth attempt (see
  [Shared-node live health](#shared-node-live-health-fail-closed-rate-witness-and-accepted-g019-residuals)).
  Denials are counted in `root_barrier_counters` only: they are not exec
  verdict events.
- **Container start.** The barrier must not judge the runtime's own root
  setup (`pivot_root`, its mounts, masked and read-only paths), which runs
  in the container cgroup. That holds when the host publishes the route
  after that setup: for example from Inspektor Gadget's container hook
  (`containercollection.WithContainerFanotifyEbpf`), which fires when `runc
  create` has written its pid file, while the container init waits to exec
  the workload. Measured with runc 1.4.3 and containerd 2.3.7: the last root
  or mount call of the init came about 1.2 ms before that hook. A host that
  publishes earlier, from an OCI `createRuntime` or `createContainer` hook
  (they run before `pivot_root`), would see the container setup denied and
  every Strict container fail to start.
- **Runtime exec helpers (limit).** runc 1.2 and later start the `runc exec`
  helper (`kubectl exec`, `crictl exec`) inside the container cgroup with
  `CLONE_INTO_CGROUP`, before it joins the container's namespaces. In a
  Strict cgroup the barrier then denies its `setns` into the mount namespace
  and the exec fails, when the exec policy allows the helper's own exec in
  that cgroup. When the exec policy denies the helper's exec (a default
  deny), runc retries without `CLONE_INTO_CGROUP`, joins the namespaces
  outside the cgroup, and the session that it starts in the cgroup is
  covered. Measured with runc 1.4.3 and the barrier header covering one
  cgroup.
- **Not a replacement for the workload seccomp contract.** The barrier
  covers only tasks of a Strict binding in its exact cgroup: never an Audit
  binding, nor a task outside that cgroup. A host that requires the workload
  seccomp contract keeps it.

### Future work (not implemented)

1. **Startup self-test:** load, probe execs, check hook firing and ordering,
   then enable.
   - Pro: broad coverage.
   - Cons: proves only the exercised paths (races, binfmt_misc, ptrace and rare
     paths stay unproven); needs a test cgroup on production nodes; adds startup
     latency; a false pass is a silent bypass; a test binding would hold one
     of the node's two route slots.
2. **Audit-first, promoted to Strict after a clean period.**
   - Pro: no outage risk; reuses the fail-closed witness thresholds.
   - Cons: missed hooks look clean; the clean period is arbitrary; no protection
     meanwhile; promotion needs an operator.
3. **Targeted BTF matching** of the functions and types the object depends on,
   instead of the whole-vmlinux hash.
   - Pro: survives unrelated backports.
   - Cons: types do not prove semantics or call order; the dependency set must
     be complete and maintained; a gap is a silent bypass.
4. **Kernel-family suite runs** (kubescape/inspektor-gadget#27): run the
   product-load suite per kernel family.
   - Pro: proves verdicts on the kernels that ran.
   - Cons: needs a pipeline that tracks vendor updates.

## Fail-closed accounting, capacity, adoption and publication

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
  `AT_EXECVE_CHECK` (6.14 and later) runs no `bprm_check` and is never evaluated (user
  decision D4, a documented residual: the flag only asks whether the file
  could be executed, nothing runs; `execveat(AT_EXECVE_CHECK)` returns what
  the kernel says, 0 for an executable file even when a Strict policy
  denies it, with no event and no counter; the real exec of the same file
  is evaluated and denied as usual: EPERM and one decision event. A kernel
  without the flag (`linux_binprm` has no `is_check`) rejects it with
  `EINVAL`. Live:
  `TestSharedNodeExecveCheckAttached`); a
  binfmt_misc `F` (fix-binary) interpreter, opened at registration and
  possibly outside the container's mount namespace, is evaluated like any
  file, and a path that does not resolve for the policy denies under Strict.
  Every pass is evaluated with its own target facts: path, filesystem
  class, stdin and image origin are collected per pass
  (`full/shared_pass_facts.h`; image origin `full/shared_image_classify.h`), so "allowed script, denied interpreter" is
  expressible. Which predicates the product admits is listed in
  [Product predicate admission](#product-predicate-admission-g020).

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
  3 streams, at least 10,000 paced births per kernel and class, at
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
    the test kernels at 1-3 ms reap latency), so it is advisory and test only
    (lead decision (b)): the product object requires the synchronous return
    (`#error` + NEG `pkg-without-sync-return`, and product admission refuses
    an image without `opaque_real_work_sync`), and non-sync bursts are
    measured, never zero-gated (the burst gate counts every refusal). Sizing rule (option B):
    `W ≥ 1 + 2 · (concurrent births + λ · D)`, with `λ` the binding's
    birth rate and `D` the reap-latency tail (`λ · D`: births whose credits
    are still in the reaper).
  - At or below capacity: 0 refusals for 1,000 back-to-back births (witness
    `fail_closed=0`, evaluated == births, no reaper `Faulted`), Strict and
    Audit, on the test kernels. With the synchronous return at 3, 6 and 7
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

    | Settle program | on | off |
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
    (`run-g19dec2.sh` `ONLY=fs6x20`: `burst-nosync-s6` ×20 on the test kernels,
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
    capsule exists without its terminal, and the final reading is taken before
    detach. In D1, `tp_btf/sys_exit` can be skipped by the tracing recursion
    guard, so a death retire is an expected recovery path when `sys_exit` was
    skipped (the health poller exports `SysExitRecursionMisses` from
    `ProgramStats.RecursionMisses`). It is not sticky: the retire released the
    pin (a failed release is a sticky release fault) and the exec's admission
    was evaluated.
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
    identity (non-pinned) re-claim requires it, so a RETIRING record's holder
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
    loads under the verifier budget.
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
  - cell 11 is **ENTRY**: an exec or a fork on an OWNED route by a task
    that has no TASK at all, such as a runtime exec entry (`kubectl exec`)
    or a migration into the cgroup. It is reported apart, like the WORK
    retry subset, and is never added to Total: such a task is refused by
    design (Strict denies, Audit leaves it unevaluated), which is not an
    enforcement fault of a managed task (SUB-10297). A failed open while a
    TASK exists stays class 8 (open-parent, exec) or class 1 (source
    refusal, fork) and counts in Total.
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
release. It is a manual VM test: CI has no BPF LSM runners.

## Attach capacity and readiness

The capacity is the per-trampoline link limit: **38 links per hook** on
x86_64 (`BPF_MAX_TRAMP_LINKS`; the limit hit is `E2BIG` from the link count,
not the trampoline image size), measured with no-op fillers on LSM,
fentry/fexit and mixed trampolines,
shared by fentry, fexit, fmod_ret and LSM programs on the same trampoline (an
LSM hook `X` uses the trampoline of `bpf_lsm_X`). The 38 is shared with every
other BPF consumer on the node (a stock VM already had one `file_open`
link).

* **K/R policy.** Each enforcement family may use at most `K` links per hook
  and must leave `R` free for third parties. `R` defaults to **8**
  (`nativeattach.DefaultReservePerHook`; `operators.NativeAttachReserveKey`
  overrides it), so at most 30 per hook are usable by enforcement families
  together. `K` is the family's own need per hook, derived from its packaged
  attach set, and must be **at most 8** (`nativeattach.MaxFamilyLinksPerHook`).
  The exec candidate needs at most **3** on any hook: bprm_execve 3, and 1
  each on task_free, task_alloc, security_bprm_creds_for_exec and
  bprm_check_security. The shared candidate's D1 objects also take one link
  on each of the seven root barrier hooks (path_chroot, sb_pivotroot,
  userns_create, capable, sb_mount, move_mount, sb_umount; see
  [Root barrier](#root-barrier)), so `K` is 1 there. The link limit of those
  trampolines was not measured; it is the same
  `BPF_MAX_TRAMP_LINKS`, shared with every other BPF LSM user of the hook
  (for example another security agent on `capable` or `sb_mount`).
* **Packaged attach set.** The candidate's ELF has 13 programs on
  bprm_check_security; 11 are tail-call targets and must never be attached.
  `bpf/opaque_real_owner_child_candidate.programs.yaml` is the gadget.yaml
  `programs:` block that marks every trampoline program outside the steady
  state `attach_to: gadget_program_disabled` (tail-call targets, the two
  bootstrap programs, two diagnostics). The eBPF operator skips those programs
  and leaves them out of `K`. `TestCandidateAttachSetDeclaration` and
  `TestCandidateAttachSetObjects` (with `IG_ENFORCE_EXEC_CANDIDATE_OBJECTS`)
  derive the attach set from that block plus the object and pin it.
  The shared-node qualification path (Phase A, `shared_host.go`) pinned the
  steady state at **16 links** (before D1; the D1 attach set is 13
  trampoline links and 5 probe links, `sharedCandidateAttachSet` and
  `sharedCandidateProbeSet`): 8 trampoline links
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
  needs kernel ≥ 5.14; stock Rocky 4.18 is not supported by it.
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
* **The shared node retries outside the lifecycle lock, a bounded number of
  times.** The in-Start retry above runs inside the gadget's Start, so under
  an instance manager it holds the manager's lifecycle lock across every
  wait. The shared node therefore never retries there: `WithNodeEnforcer`
  sets `operators.NativeAttachRetryKey` to `false`, and admission refuses any
  other value. A capacity refusal fails that `StartGadget` at once (rolled
  back, nothing attached). `StartNode` then joins the host's teardown (the
  `stop` from `Run`), and only after that waits and calls `Run` again with a
  fresh `NodeEnforcer`. So the lock is free during every wait: a stop,
  replace or start on the same manager (for example the stop that frees the
  trampoline links) runs at once, and two attempts never coexist. Each retry
  repeats the full start (image load, collection load and verification),
  bounded by the retry budget. The retry (`sharedNodeAttachRetry`) allows at most 8 attempts, 500 ms doubling to a
  5 s cap, and no wait that would end past 30 s from the first attempt;
  `StartNode` refuses an unbounded retry before running anything. Canceling
  the `StartNode` context ends a wait at once. A failed teardown ends the
  retry, with no further attempt; `AttachState` then receives the refusal
  that the returned error wraps. While `StartNode` retries,
  `SharedNodeConfig.AttachState` (if set) receives every
  `*nativeattach.ErrAttachCapacity` (the host shows the node NotReady with
  it) and then nil once started; `Ready` itself is only reachable after
  `StartNode` returns. When the retry runs out or is canceled during a wait,
  nothing stays attached and `StartNode` returns `ErrSharedNodeNotReady`
  wrapping the last refusal; it never falls open. A cancel during a later
  attempt's `Run` returns that attempt's context error without the earlier
  refusal (still nothing attached). **Host contract:** `Run` may be called
  again for the same gadget ID after its `stop` returned nil. The host must
  not run two `StartNode` calls for the same gadget ID concurrently: `stop`
  targets the gadget ID, so a refused attempt's `stop` could tear down the
  other caller's live gadget. `stop` should be a no-op when its own
  `StartGadget` failed.
* **Link-based programs only.** Rollback closes bpf links only. A native
  family is therefore refused, before anything is attached and without
  retry, if an enabled program would attach without a bpf link or with side
  effects rollback cannot undo (kprobes/uprobes, tracepoints, perf events,
  socket filters, TC, sockmap programs, iterators). Admitted are LSM and
  fentry/fexit/tp_btf links, syscall commands and admitted recovery TEST_RUN
  programs, which covers the exec candidate family.
* **Readiness component.** In the native path each receipt's `Check` also
  verifies, by link ID, that the link still exists and references the same
  program. A missing or replaced link returns `*nativeattach.ErrNotReady`
  naming the target; a stale Ready is never reported. This is a component
  check of the product node's `Ready` (a failed receipt fails it with
  `ErrSharedNodeNotReady`); a qualification node's `Ready` stays unavailable.

## Accepted residuals: root anchor and mounts

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
containers without `CAP_SYS_ADMIN`. The [root barrier](#root-barrier) now
denies such a mount to a task of a Strict binding in its exact cgroup. It
does not cover Audit bindings, so this residual stays for them, and it does
not replace the workload seccomp contract.

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
| Degraded (`ErrSharedFailClosedDegraded`) | any fail-closed refusal (Strict), unevaluated child (Audit), ADMISSION fault or root barrier fault within 60 s (threshold 0); clears after a quiet window | `Ready`, `Inspect` (binding `Fault`), qualified operator readiness |
| NotReady (`ErrSharedFailClosedNotReady`) | Total, ADMISSION or root barrier rate above 0.1% over 5 min (over the node's age while it is younger) | as Degraded |
| Unknown (wraps NotReady) | unreadable witness, a counter moving backwards, or counts `FailClosedProductRate` refuses (ENTRY + ADMISSION + Total above the attempts); sticky until node teardown. A poller with no sample for 3 intervals is Unknown while stalled | as Degraded, and the `StopNode` result |

ENTRY [11] and ADMISSION [12] are outside Total; the denominator of Total is
the attempts minus ENTRY minus ADMISSION, and every rate is per attempt.
ENTRY never degrades. The root barrier class (`FailClosedRootBarrier`,
`root_barrier_faults`, both cells) is outside Total too and degrades by its
own rate per attempt; a barrier fault is judged on a root or mount operation,
not on an attempt, so with no attempt in the window each fault counts as a
whole attempt. A gated product object must carry the barrier's fault counter,
or startup is refused. A window's attempts start one sample before its base
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
failure; only a sticky Unknown is. A qualification node's
`NodeEnforcer.Ready` still returns `ErrSharedNativeUnavailable`.

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
