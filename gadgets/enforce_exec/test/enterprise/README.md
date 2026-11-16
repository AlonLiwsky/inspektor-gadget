# A0 metadata-only copy-route discovery fixture

**Test-only and default disabled. Four isolated candidates remain NOT_READY;
any new native execution needs a fresh, separate execution review.**

Two candidates have each been tried once on the authenticated Rocky GA target:
the original and the single-captured-depth revision. Both runs rejected
`copy_exit` during loading for unbounded map-value pointer arithmetic, before any
attachment or synthetic helper execution. Both were **NOT_READY**, not platform
gaps or evidence of enforcement.

A pointer-return switch and a per-slot field-copy switch were also assessed
offline; ordinary Clang19 output still merged their offsets, so neither was
selected for another native run. The frame-map revision was tried once: collection
load and typed `start` attachment succeeded, then typed `copy_enter` attachment
failed with EBUSY before helper launch. This remains **NOT_READY**.

The mixed-hook candidate was tried once on 2026-10-31 at 19:23:17 UTC, using
published revision `073ac0d8` (the explicit BPF-helper-header include fixed the
older libbpf userspace regression; complete guest preflight then passed). All six
maps and five programs loaded, and typed `start` attached. Canonical
`copy_enter` failed opening its PMU event with EINVAL, before config publication
or helper launch; later hooks were not attempted. Sticky attachment uncertainty
kept the process in quarantine until whole-VM deletion. Exact owned VM, firewall,
temporary key and tag absence were confirmed; no run resources remain.

Exact-vendor source/config research identifies the shared trace-kprobe notrace
guard as the strongest explanation, **not a captured live-branch proof**.
PMU and tracefs both reach that guard; changing transport alone is not a remedy.
Do not repeat the unchanged attempt or disable protections. This is one failed
hookpoint candidate, not a platform gap or full-enforcement result. No owned
copy observations, pairing/loss proof or A0 completion were obtained.

Target: authenticated Rocky 8.10 GA `4.18.0-553.el8_10.x86_64`, not a production
patch recommendation. See `.omx/plans/ig15-enterprise-copy-completion-gatea.md`.
The exact reference ELF SHA256 is
`742ecbff5b4cc8b13f7d3ca064a641af11cf67aaec3dcf1d3e4a6d9675c60d53`.

## Scope and hard bounds

- Four registered owned synthetic TGIDs maximum; this first harness uses **one**
  single-threaded owned child and one gated exec, not a concurrency proof.
- At most sixteen total attempts (stricter than sixteen simultaneously pending),
  eight nested copies, 4096 records, 64 possible CPUs and a thirty-second native
  deadline. Global counters flag overflow; overflow cannot claim completeness.
- **Zero payload bytes.** No argv, source-buffer or destination-buffer contents.
  Typed bprm scalar fields and a bounded sixteen-address kernel stack are metadata.
- No LSM programs, result changes, denial, roles, production readiness, pins or
  changes to security settings. No fallback to guessed kprobe offsets/clone ABI.

`copy_metadata.bpf.c` is a mixed typed/kprobe hypothesis, not kernel-admission
proof. The loader validates the actual reference and running BTF signatures for
`security_bprm_creds_for_exec`, `_copy_from_user`, `security_bprm_check` and
`free_bprm`, plus the scalar `linux_binprm` fields it reads. All bprm dereferences
use the **live typed callback argument**. Saved task/bprm addresses are opaque
identity comparisons only, never dereferenced later.

Pending metadata begins only after a successful credentials boundary. Explicit
attempt/call IDs, physical task-address comparisons, nesting and typed lifecycle
records bound the experiment. `_copy_from_user` entry records opaque To and
scalar N plus a bounded stack. Return reads only the ax Remaining scalar;
its To/N values are retained **ENTRY SNAPSHOTS**, not fresh return arguments.
A full/truncated stack, lost pair, identity mismatch, read fault or overflow
invalidates structural completeness. A registered PID alone is not production
identity or direct-caller provenance.

**Every copy record retains UNKNOWN_DIRECT_ORIGIN.** The stack is diagnostic,
not an authentication mechanism: same-task membership and an ancestor match are
insufficient. Structural success never clears that flag or declares A0 PASS.
All-path copy coverage, direct return-frame attribution and mapping lifetime are
experiment outputs requiring independent interpretation, not assumptions hidden
in prerequisites. Metadata cannot prove destination-byte readability for A1.

## Canonical mixed attachment and uncertainty

Attachment order is explicit: typed `start`, canonical entry kprobe
`copy_enter`, canonical return kretprobe `copy_exit`, typed `check`, typed
`finish`. Both copy hooks request exactly `_copy_from_user`, offset zero and
`ExactSymbol=true` through the already-pinned fork. No fixture-level retry,
symbol alias, offset search or post-failure mechanism fallback is performed.
The dependency can use its same-symbol PMU-to-tracefs transport fallback.

The return hook requests fixed `RetprobeMaxActive=128`; it is never auto-grown.
Return instances and perf/tracefs handles add kernel resources beyond the six
maps. A 16 MiB memlock setting is a prerequisite, not measured total-memory
proof. Foreign calls can consume return instances before owned-task filtering.
On this vendor kernel, readable zero in `kprobe_profile` is not proof of zero
return-instance misses; ambiguous/unavailable diagnostics cannot upgrade it.
No such counter is used as a losslessness certificate.

C static assertions bind the actual included amd64 UAPI registers
rdi/rsi/rdx/rax to offsets 112/104/96/80 and 64-bit fields in a 168-byte
`pt_regs`. Before native setup, authenticated target BTF must independently
match vendor di/si/dx/ax at those offsets/types, and the reference must be
little-endian amd64 ELF64. Real included tracing macros are tested with distinct
64-bit registers and poisoned return argument registers. This is normal
function ABI, not syscall-wrapper ABI. No argument-buffer contents are read.

The 256-byte record layout is unchanged. Entry Unknown bits are
`2|32|64` (UNKNOWN_DIRECT_ORIGIN, LIFO candidate, unknown return-instance loss);
return additionally requires `128` (entry snapshots). Fault bits stay additive.
The Go validator and actual-C regression check these representations together.
Machine-checked reports permanently carry `return_arguments=entry_snapshot`,
`pairing=LIFO_candidate`, `return_instance_loss=UNKNOWN` and
`completeness=NOT_READY`, even for balanced records. Internal call IDs and
matching snapshots are not proof of actual entry/return invocation identity.

## Fixed frame storage

The captured authenticated owner slot is checked once as a 32-bit value below
four and reused unchanged for pending-state and frame selection. Entry depth
must be 0–7; exit depth must be 1–8 before subtraction. The checked key is
`slot * 8 + index` (0–31), with conversion only after full-width validation.
Each `frames` ARRAY value holds one 24-byte frame; field accesses use fixed
offsets 0, 8 and 16. A missing lookup faults before changing call IDs, frame
contents or depth. All three fields are written before publishing pushed depth.

This replaces the eight-frame array inside each `pending` value: pending values
shrink from 224 to 32 bytes. Total frame payload remains 32 × 24 = 768 bytes,
but a sixth map adds a collection-owned FD and kernel allocation/accounting
overhead. The existing collection load/close and uncertain-detach retention
own this extra map too. The mixed-attachment revision preserves that ownership,
but extends sticky attachment uncertainty as described below.

Actual-C userspace regression covers all 32 keys and interleaved owners,
including real production ownership lookup and capture, invalid slots/depths,
zero-initialized frames, and failed lookups without mutation. This is **not**
live four-owner proof: the native harness still uses one child and slot zero.
The opt-in offline map-layout test parses the compiled object without loading
it and checks six maps, frames/pending sizes, and exactly two Kprobe plus three
Tracing programs.

## Ownership and cleanup

The native OS thread is locked while establishing and using the PID namespace
anchor. It requires a genuine procfs root (the authenticated vendor's
`PROC_ROOT_INO=1`), then resolves `thread-self/ns` with openat2 `RESOLVE_BENEATH |
RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS`. A real pinned procfs namespace symlink
supplies the expected inode through empty-path readlink; the opened namespace
FD must be real nsfs, have PID namespace type and match that inode. Active and
children namespace anchors must match. Unsupported/ambiguous operations refuse.
No `/proc/1` equality or `NS_GET_PARENT` error is treated as initial-namespace
proof; **nested namespaces are not silently treated as host namespaces**.

The pinned namespace FD stays alive through teardown. Its dev/ino and deadline
are frozen before registration. The authenticated vendor tracing dispatcher
registers `bpf_get_ns_current_pid_tgid` (`kernel/trace/bpf_trace.c:1027-1028`);
its implementation (`kernel/bpf/helpers.c:571-611`) requires the current task's
active namespace to match before returning namespace-local IDs. The producer
uses those local IDs **before ownership lookup**, never userspace-local IDs
against `bpf_get_current_pid_tgid`'s host IDs. Raw host IDs are separate diagnostic
metadata. The helper's initial getpid/getppid pipe handshake also must match the
owned process handle and parent before registration.

The initial helper is launched with an explicitly empty environment, preventing
inherited `LD_PRELOAD`/`LD_AUDIT` injection before the gate.

The helper blocks on inherited parent FD3 before exec, then reports arrival over
FD4 and blocks again. Its process handle stays owned and unreaped through
observation; only that child can be killed. Parent death closes the gate. No
process-tree searches, global kill, arbitrary workloads or descendant management.

The record array is fixed-size, not a ring: producers stop before synchronous
bounded map reads. There is no asynchronous event-reader goroutine to join. Pipe
reads have a deadline. A native invocation must use `go test -timeout=0`; the harness rejects any
`testing.T.Deadline` before namespace or kernel setup. Compile-only retains its
normal test timeout because it creates no native resources. A process-kill
`timeout` wrapper is **not** a replacement for whole-VM supervision.

All five attachments must finish before config publication/freeze, helper
creation/handshake, owned registration or gate release. Every returned handle
is retained immediately, including a handle returned alongside an error.

**Any attachment error or nil-link anomaly is sticky uncertainty**, because
the dependency can hide failed rollback closes. Cleanup still attempts every
available returned handle exactly once in reverse order, including when
attachment uncertainty is already set. Successful closes do not clear that
uncertainty. Every close error is retained; later nil Close results are not
stop evidence. Collection, namespace anchor and all available handle references
remain held in fail-stop quarantine, before any helper launch on attach failure.
Unreturned library-internal handles cannot honestly be claimed retained or
accounted for; whole-VM retirement is mandatory for this case.

Normal cleanup positively detaches every producer **before** unregistering or
reaping the child. Only then are maps/descriptors released. Failure to delete an
inactive ownership entry still reports an error, but cannot expose a reused PID
to stopped producers. The first detach error is permanently sticky: a later `Close` returning nil
cannot clear it, since the approved FD wrapper disowns the descriptor before
the close syscall and may subsequently return nil without a syscall. Link
references are retained on any uncertainty; no in-process recovery proof exists.
If attachment or detach is uncertain, cleanup does **not** unregister,
reap, release resources or return: it emits UNCERTAIN and retains strong references
in a timed fail-stop loop. The child may be killed at deadline, but remains
unreaped. Injected pure tests exercise this ordering without running the loop.

This exceptional quarantine has **unbounded process lifetime**, distinct from
the thirty-second recording bound. A separately reviewed external **whole-VM
supervisor** capable of destroying the owned VM is mandatory before any native
run; Go test timeout or a failed assertion is not a safe substitute for that
recovery contract. The attestation environment string does not establish that
such a supervisor exists or grant execution authority. The context bounds normal userspace
work and the BPF config bounds callback recording; **a stuck kernel syscall is
not proven interruptible by Go context cancellation**. Isolated execution must
retain external supervision/recovery for that case.

## Local checks

Ordinary tests skip all opt-in entrypoints before any compiler/subprocess/BPF
operation. Existing approved root dependencies only; no module changes.

```
go test ./gadgets/enforce_exec/test/enterprise
go test -race -count=3 ./gadgets/enforce_exec/test/enterprise
go vet ./gadgets/enforce_exec/test/enterprise
```

Compile-only (no load, attachment or synthetic helper execution):

```
IG_ENTERPRISE_A0_REPORT_ONLY_TEST=1 \
IG_ENTERPRISE_A0_REFERENCE_ELF=/absolute/authenticated/vmlinux.elf \
IG_ENTERPRISE_A0_CLANG=/absolute/trusted/clang \
go test -v -run '^TestA0CompileOnly$' ./gadgets/enforce_exec/test/enterprise
```

The opt-in pure C regression compiles the actual production ownership/frame
lookup, callback bodies and type declarations with deterministic userspace stubs, then runs them with
undefined-behavior/bounds sanitizers. It covers every slot and depths 0 through 9, 2^32 and
UINT64_MAX, eight-frame LIFO, task mismatch, stack/copy faults, and permanent unknown
origin. It also exercises actual register adapters and poisoned return arguments.
Pure attachment tests inject errors at all five positions, nil-link anomalies
and close-error combinations, proving one reverse close pass and no resource
release on uncertainty; a source-order check guards activation ordering.
This does not execute BPF, kernel helpers, or `exec_target`. Ordinary
tests still skip compiler/subprocess operations unless explicitly opted in.

```
IG_ENTERPRISE_A0_REPORT_ONLY_TEST=1 \
IG_ENTERPRISE_A0_CLANG=/absolute/trusted/clang \
go test -v -run '^TestA0CopyDepthCRegression$' ./gadgets/enforce_exec/test/enterprise
```

The current compile profile uses Clang19, x86-64 Linux system/libbpf headers,
`-target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Werror`, and a C11 synthetic helper
with `-O2 -Wall -Wextra -Werror`. Target BTF checks are performed offline before
compilation. Temporary object/helper hashes are printed; compiler success says
nothing about verifier acceptance. No helper binary is executed by compile-only.

## Native gate — not an instruction to run now

`TestA0KernelReportOnly` additionally refuses to proceed without the explicit
`IG_ENTERPRISE_A0_EXECUTION_REVIEW=approved-owned-isolated-metadata-only`
attestation, `IG_ENTERPRISE_A0_BOOT_ELF_SHA256` matching the authenticated ELF,
matching exact runtime release and byte-for-byte matching BTF. The string is an
operator attestation, **not cryptographic proof that a review occurred**. Obtain
and archive the actual independent review and isolated execution authority first.
The fixture neither weakens policy nor automatically provisions a machine.

Kernel addresses in `OWNER_ONLY_METADATA` logs are private diagnostic material;
keep runtime output owner-restricted, never public CI or OTel events. Outputs
separate `METADATA_COLLECTED`, kernel-probe observation and `NOT_READY`
completeness. Exit zero, a passing Go test or successful compilation does not
qualify A0, enforcement, Ready, G011 or G020. No full argv/predicate/lifecycle
qualification is claimed.

## Remaining experimental questions

- Actual load/attachment eligibility and callback access on the exact target.
- Compiled direct-call attribution from stack metadata, without ancestor guessing.
- Missing-call/all-path coverage and external supervision of stuck kernel calls.
- Concurrency, error-path and cleanup-fault live controls (this harness is one
  owned happy-path discovery run only).
- All A1–A4 payload/reconstruction work and full enforcement integration.
