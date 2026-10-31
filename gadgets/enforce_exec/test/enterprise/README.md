# A0 metadata-only copy-route discovery fixture

**Test-only and default disabled. The revised candidate is locally validated
only; another native execution needs a fresh, separate execution review.**

The first candidate was tried once on the authenticated Rocky GA target. Loading
`copy_exit` was rejected for unbounded map-value pointer arithmetic, before any
attachment or synthetic helper execution. That run was **NOT_READY**, not a
platform gap or evidence of enforcement. The revision captures the full-width
map depth once, validates that same scalar before subtraction/indexing, and
retains the eight-frame LIFO and fault behavior. No masks, narrowing, or wrapped
indices accept invalid depths. Local regression and compilation do **not** prove
that the revised program loads or attaches; it has not been rerun natively.

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

`copy_metadata.bpf.c` is a fentry/fexit hypothesis, not verifier/attachability
proof. The loader validates the actual reference and running BTF signatures for
`security_bprm_creds_for_exec`, `_copy_from_user`, `security_bprm_check` and
`free_bprm`, plus the scalar `linux_binprm` fields it reads. All bprm dereferences
use the **live typed callback argument**. Saved task/bprm addresses are opaque
identity comparisons only, never dereferenced later.

Pending metadata begins only after a successful credentials boundary. Explicit
attempt/call IDs, physical task-address comparisons, nesting and typed lifecycle
records bound the experiment. `_copy_from_user` entry and return collect pointer,
length and remaining-count metadata; entry also collects a bounded kernel stack.
A full/truncated stack, lost pair, identity mismatch, read fault or overflow
invalidates structural completeness. A registered PID alone is not production
identity or direct-caller provenance.

**Every copy record retains UNKNOWN_DIRECT_ORIGIN.** The stack is diagnostic,
not an authentication mechanism: same-task membership and an ancestor match are
insufficient. Structural success never clears that flag or declares A0 PASS.
All-path copy coverage, direct return-frame attribution and mapping lifetime are
experiment outputs requiring independent interpretation, not assumptions hidden
in prerequisites. Metadata cannot prove destination-byte readability for A1.

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

Normal cleanup positively detaches every producer **before** unregistering or
reaping the child. Only then are maps/descriptors released. Failure to delete an
inactive ownership entry still reports an error, but cannot expose a reused PID
to stopped producers. The first detach error is permanently sticky: a later `Close` returning nil
cannot clear it, since the approved FD wrapper disowns the descriptor before
the close syscall and may subsequently return nil without a syscall. Link
references are retained on any uncertainty; no in-process recovery proof exists.
If any detach is uncertain, cleanup does **not** unregister,
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

The opt-in pure C regression compiles the actual production callback bodies and
type declarations with deterministic userspace stubs, then runs them with
undefined-behavior/bounds sanitizers. It covers depths 0, 1, 7, 8, 9, 2^32 and
UINT64_MAX, eight-frame LIFO, task mismatch, copy faults, and permanent unknown
origin. This does not execute BPF, kernel helpers, or `exec_target`. Ordinary
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
