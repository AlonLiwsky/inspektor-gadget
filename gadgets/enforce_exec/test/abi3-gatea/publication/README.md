# ABI3 real-content publication primitive — isolated Gate A fixture

**Test-only MAX8 revision, unexecuted on a kernel.** The prior two-UID revision
has separately frozen exact-kernel evidence; that evidence does not cover this
revision. Compilation/static checks are not verifier
acceptance or runtime evidence. Run only on a newly created disposable amd64 VM
and retain logs/identities for **both exact admitted BTFs**. This directory does
not change the production owner, evaluator, manifest, or consumer pins.

## What this fixture implements

This is a bounded publication protocol with actual policy-like data, not bank
identifier tags:

- Two permanent `ARRAY` values hold two UID/epoch/actor-role/argument/deny rules
  and eight distinct sealed UID/epoch publication targets, plus a complete
  audit/strict class. The six additional targets are real reserved/read-back
  catalogue identities, not extra evaluated history rows. Only the authenticated BPF loader writes
  these UAPI-readonly values while the inactive bank is `LOADING`.
- A preallocated 32-entry UID `HASH` is never deleted. Aborted reservations
  retain epoch zero and consume capacity; accepted epochs are immutable.
- Three real native threads register their own physical task addresses and
  nonwrapping cookies in a preallocated `HASH`. Each has two role-history banks.
  The threads remain alive until all protocol tests finish; this fixture does
  **not** implement task deletion/reuse or replace the separate lifetime proof.
- Writer ownership excludes SEAL and abort. `SEALING` excludes new writers for
  the entire stamped-content validation; completed sealing forbids more writes.
- Staging, validation, loaders, evaluations and semantic control queries acquire
  the shared authority-reader count before reading authority and release it
  after final use. No task lock nests inside the dispatch lock. Raw userspace
  state reads are locked diagnostics, not authorization decisions.
- Snapshot/staging/certification checks current task inventory and a mutation
  serial. Actual admissions invalidate the serial before reading authority.
- ARM only commits from authenticated successful `cgroup_kn_lock_live` fexit,
  while the kernel holds `cgroup_mutex`. The administrative thread retains its
  exact `O_PATH` control-file pin and physical-task binding. A negative-PID write
  must fail with `EINVAL`; only the matching COMMITTED receipt proves success.
- ARM prelooks up stable catalogue/program values, then checks **all** inputs,
  epochs, candidate stamps, zero reader/writer counts and the receipt under the
  shared lock. Its irreversible block stores eight accepted epochs and the
  descriptor with no branch/helper/exit between two explicit NOTYPE labels.
  `check-bytecode.py` inspects the actual compiled block and rejects injected
  helper/branch/exit and missing-eighth-store negative controls. It requires
  eight distinct prelooked-up pointer spills and the eight sealed epoch loads,
  then exactly nine descriptor/receipt/metric stores (compiler-shape check,
  not semantic verifier proof). Unlock remains outside that block.
- Evaluation reads the latched program, actual per-thread role history and
  accepted catalogue epochs, checks their coherence, and evaluates the two
  role/argument predicates. An audit class never adds denial. Strict class
  denies a matching deny rule, relevant unknown or incoherent state; all
  incoherence also increments a mandatory-zero proof counter.

## Deterministic runtime assertions (pending execution)

The native runner uses mutex/condition-variable handshakes, not sleeping to
infer a race:

1. Wrong nonce, duplicate enrollment, UAPI program overwrite and syscall-only
   ARM are rejected. A missing second catalogue pointer must refuse ARM without
   accepting the first UID or publishing a descriptor. Missing and existing-but-
   mismatched eighth targets must leave all eight epochs zero and preserve the
   entire active descriptor, receipt, serial and accepted counter. Successful
   publication reads back all eight exact epochs with the COMMITTED descriptor.
2. A worker holds a real loader token across calls while the administrator
   attempts SEAL and abort; both refuse. A malformed stamp cannot seal, and a
   sealed bank cannot be rewritten.
3. A worker acquires an old-generation read before inactive loading starts.
   Its explicit ownership count must remain held after the complete write and
   SEAL. Only then does the administrator permit its matching-rule evaluation
   and exact-once release; the result must retain the old audit classification.
   A separate evaluation stress loop runs concurrently, but its scheduler timing
   is not the proof of overlap. No evaluation may report mixed content.
4. A required UNKNOWN candidate row prevents strict certification. A fresh copy
   of the unchanged, known **active** facts may repair that uncommitted candidate;
   this is not permission to turn committed UNKNOWN history into known history.
5. Two actual threads hold overlapping admission tokens after certification.
   Their shared count must be two and ARM must refuse. After both release,
   duplicate release is rejected and ARM must still refuse the stale serial.
   A complete fresh snapshot/restaging/certification is required.
6. Lost-ACK simulation deliberately does not inspect the commit receipt after
   the control write. A counted query then reconciles the committed descriptor;
   abort must not roll it back or change same-UID epochs.
7. Unaccepted abort reservations exhaust the fixed UID capacity without granting
   authority or replacing the last-good strict policy. Same-UID reload remains
   possible at capacity. A natural-quiescence strict-to-audit publication changes
   the actual evaluation result.

## Explicit limits — not full Gate A completion

This fixture proves only the chosen **two-rule/eight-catalogue-target/three-retained-task**
publication slice once its real tests pass. It does not demonstrate the complete
256-rule evaluator, eight-role history integration, 65,536-entry catalogue, production
memory bound, arbitrary task inventory/lineage/root qualification, role
transitions, the full required-known dependency closure, attachment-prefix
qualification, ingress/fork cancellation, or nested scratch ownership. Those
remain separate mandatory gates. Two fixed bank names alone do not establish
all production resource accounting; map freelists/possible-CPU overhead still
matter. Fixed maps in this fixture are never replaced during the run.

The two-command held-read/write tokens intentionally expose deterministic
ownership intervals for testing. They are not a production crash-recovery API.
A dead test process discards all its unpinned maps/links. No claim is made that a
production owner may abandon readers or reconstruct unknown history.

## Concrete fixture payload accounting

The Clang 21.1.8 emitted BTF records (also guarded by C static assertions) are:
`pc_config=24`, `pc_command=120`, `scope=312`, `pc_program=208`,
`pc_catalogue=16`, `task=208`, `pc_history=80`, `pc_role=32`,
`pc_rule=32`, `pc_epoch=16` bytes. The task includes two 80-byte history banks;
program includes two 32-byte rules and eight 16-byte epoch targets.

| Map | Kind | Entries | Key bytes | Value bytes | Capacity × value |
| --- | --- | ---: | ---: | ---: | ---: |
| config | ARRAY | 1 | 4 | 24 | 24 |
| commands | preallocated HASH | 3 | 4 | 120 | 360 |
| state | ARRAY | 1 | 4 | 312 | 312 |
| programs | ARRAY | 2 | 4 | 208 | 416 |
| catalogue | preallocated HASH | 32 | 8 | 16 | 512 |
| tasks | preallocated HASH | 3 | 8 | 208 | 624 |

Six maps, 42 total entry slots, **2,248 bytes of value payload**; explicitly
stored HASH key payload adds 292 bytes, for **2,540 logical key/value bytes**.
ARRAY indices are implicit, not physically stored key records. These are NOT
allocated bytes, memlock, slab usage or RSS. Map objects, buckets, aligned hash
elements/headers, allocation rounding, lock metadata, possible-CPU-sized
freelists and per-CPU scratch/auxiliary storage, plus programs/JIT/BTF and
userspace verifier buffers are excluded. Hash overhead depends on the exact
kernel and possible CPU count even though these are not per-CPU-value maps.
No numerical full-resource ceiling is inferred from this tiny fixture. Full
65,536-entry catalogue / task inventory / 256-rule resource accounting remains
a separate preintegration gate. No map is resized/replaced in this fixture.

## Build and run

Dependencies: clang with BPF target, a C compiler, pthreads, libbpf headers,
bpftool, llvm-objdump, readelf and Python 3. Record the actual compiler version;
local Clang 19 compilation is not a substitute for the supported Clang 21.1.8
build and exact-kernel verification.

```sh
./build.sh /tmp/publication-build
python3 ./check-abi.py /trusted/exact-vmlinux.btf --self-test
# Only inside a reviewed disposable VM, never the development host:
sudo IG_ABI3_GATE_A_DISPOSABLE=1 ./run-disposable.sh \
  /tmp/publication-build /durable/new-publication-evidence
```

Both the native runner and wrapper require explicit disposable-host consent
before opening control files or loading BPF. The unprivileged
`runner --self-test-consent` checks root/nonroot and missing/malformed consent
cases without opening control files or loading BPF. The wrapper checks exact BTF
membership, actual hook prototype and commit
bytecode before creating its unique cgroup. It logs to regular files, times out
the runner, kills/removes only its own cgroup, and verifies recorded program IDs
are absent. Neither this cleanup mechanism nor runtime assertions have yet been
executed for this publication fixture. Preserve source/object/runner hashes,
verifier logs, runtime results and cleanup receipts; do not relabel compile-only
checks as successful kernel evidence.

### First actual load: staging bounds remediation

The first original-kernel Clang 21.1.8 load failed in `stage_task`: the
address-taken map lookup key was reloaded with an unconstrained u32 range before
indexing task history. This is a fixture bounds-proof failure, not a successful
publication proof or evidence that the architecture itself is impossible.
The callback now explicitly rejects the reloaded bank above one before acquiring
reader ownership, then materializes the checked history pointer before helper
calls. It never masks an invalid bank into a valid one. The bytecode checker
requires that exact checked-register pointer derivation before the first lock,
and rejects a weakened bound; this compiler-shape check is not a verifier.
The runner also checks malformed-bank rejection leaves ownership, receipt and
active authority unchanged. Both exact kernels still require a fresh load and
all runtime assertions; no success is claimed from compilation.

The bounds-remediated original-kernel retry accepted `pc_command` (2,844
processed instructions), but rejected `pc_arm` metadata before instruction
verification: duplicate BTF line offset 171. The archived Clang 21 ELF already
contains duplicate raw `.BTF.ext` byte offsets 1368 at line records 96/97; this
is not introduced by load relocation. Each commit marker now emits one harmless
self-move of an initialized operand (`new_accepted` at begin, `s` at end), giving
the inline assembly and following C distinct instruction locations. BTF types,
CO-RE relocations and source line evidence remain present. The checker rejects
non-increasing raw BTF line offsets; it rejects the actual prior ELF and accepts
the rebuilt ELF. This metadata remediation still needs actual kernel acceptance
and does not establish ARM runtime correctness.

### MAX8 extension — build-only proof boundary

The pre-edit two-UID object was rejected by the tightened authority-store
regression before implementation. The revised emitted commit has eight real
epoch stores with no helper, branch, loop or exit between its markers; the
checker also deletes the eighth emitted store as a negative control. Full raw
BTF.ext monotonic line checks and earlier guard/helper/branch negatives remain.
Missing/invalid eighth-target runtime assertions are implemented but not yet
executed. Fresh verifier/load/attach/runtime/cleanup evidence on both admitted
kernels is mandatory; the frozen previous run3 artifacts are not modified or
relabelled as MAX8 proof. Historical failures above remain failure evidence.

### Fresh ARM receipt regression

Every acknowledged ARM probe now requires its own exact counter increment:
`arm_refused = before + 1` for refusal, or `arms = before + 1` for success,
with the opposite counter unchanged and overflow rejected. A stale EAGAIN
from an earlier probe cannot satisfy the missing/invalid eighth-target oracle.
Refusal also preserves reader/writer/registration counts and candidate/receipt
state; all-eight epoch readbacks remain mandatory. Deliberately lost ACK still
skips receipt inspection and is reconciled by the subsequent committed query.
`runner --self-test-arm-receipt` is pure host logic (no control files or BPF
operations): it rejects skipped-hook/stale, duplicate-count and wrapped receipts
and accepts exact fresh ones. Its stale-EAGAIN test failed before the fix.
