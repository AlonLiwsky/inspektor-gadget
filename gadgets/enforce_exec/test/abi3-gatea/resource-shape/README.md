# Maximum-shape resource feasibility fixture — incomplete, build-only

Test-only sibling of the Gate A fixtures. This is **not** the evaluator, a
production ABI, a task-lifetime proof, verifier evidence, or G018 closure.
No BPF loading, map creation, attach, cgroup changes, or cloud activity is
performed by `build.sh` or its offline checker. Synthetic keys, when later
exercised, establish storage shape only and cannot stand in for task identity.

## Evidence boundary

The proposed twelve core maps have 39,637,624 bytes of value payload plus
573,440 bytes of HASH keys. The proposed P=64 allocation-formula result of
43,707,304 bytes is neither a physical ceiling nor a whole-owner budget.
`support-profile.json` lists the additional owner support resources and unresolved
lifecycle/accounting decisions; no whole-profile total is currently asserted.
Both admitted kernel configs have CONFIG_NR_CPUS=64, but runtime accounting must
read actual **possible** CPUs, never online CPUs. The support image-origin map
keeps the existing NO_PREALLOC model; arbitrary reload is NOT justified by
pretending it is a single permanent index. Frozen replacement and deferred
retirement lifetimes still need a bounded architecture decision and proof.

Native and BPF sizes must agree via actual object BTF, not merely a handwritten
size table. The offline libbpf checker opens the ELF and checks type, key/value
sizes, max entries and flags of every core map. This is not live mapinfo.
A later separately authorized exact-kernel run must compare actual mapinfo and
record all map IDs before/after cycles, full-capacity NOEXIST/refusal/owned delete,
16 retained rows including UNKNOWN with accepted epochs, 17th-row refusal,
high observation offsets, all 16,384 chunk stamps (including last-index/stamp
negative cases preserving active content), and enlarged-record MAX8 commit.

## Isolated build pattern

Use the existing pinned Clang 21.1.8 build image with `--network none`, source
mounted read-only, no capabilities/BPF mounts, and a fresh writable output dir.
The build emits compiler identity, exact BTF, disassembly, native-vs-BTF/map
report, and source/build SHA-256 manifests. Build success alone authorizes no
kernel run. Map allocator rounding, possible-CPU overhead, native buffers,
BTF/JIT/link/trampoline/FD/pin costs and deferred retirement remain explicit gaps.

## Implemented versus unproved

`shape.h` follows the architect's proposed semantic records and includes the
existing evaluator/matcher definitions, giving actual facts=9216,
scratch=2616, argument=4097, observation=15936. TaskBank.version is the proposed
bank-level version, **not proof that every per-UID roleVersion obligation is
satisfied**; adding independent per-UID versions changes the layout/budget.
No semantic requirement is waived by these size checks.

The offline checker executes shared append/copy helpers for all 16 retained
rows, UNKNOWN with accepted epoch retained, and unchanged 17th refusal. The
bytecode checker examines actual emitted MAX8 stores and rejects injected
branches/helpers; it also validates raw BTF.ext line offsets. An initial
empty-label build had duplicate offsets and was rejected; nonempty self-move
labels (the existing publication-fixture pattern) fix the source, not metadata.

The **compiled, never executed here** runner contains future assertions for
full HASH capacities, duplicate NOEXIST, owned task deletion/reinsertion, high
observation offsets, all 16,384 program chunk stamps, bad final stamp/index,
unchanged active first/last chunks, MAX8 publication and fixed IDs over two
cycles, and wrapper-owned exact-ID absence after process termination. The catalogue is never
deleted. The native command harness is single-threaded: concurrent command mutation,
reader/writer races and exact-once lifetime ownership are not proved.
Helper/key/row operations remain synthetic: zero templates, program
bank loading and candidate setup are test controls, not an authenticated loader
or a certified ARM state machine. This syscall TEST_RUN program is not
attached to any workload and makes no cgroup-mutex/permission/endpoint claim.
Its verifier compatibility, loop bounds and return semantics are **unproved**
until the exact-kernel run succeeds. The wrapper requires exact admitted BTF,
x86_64, CONFIG_NR_CPUS=64, explicit disposable consent and a new evidence dir.
The build never invokes that wrapper or runner.

Bounds visible in source: 16-row append/copy; 8 pointer lookups and prechecks
before MAX8 commit; exactly 8 epoch plus 6 scope stores in its branch/helper-free
emitted region; one `bpf_loop` call capped at 16,384 for a stamp scan (one map
lookup per callback); command input index is rejected at 16,384. MAX8 is primitive
shape only: full production reader/writer exclusion and complete fallible
prevalidation still belong to the separately reviewed publication protocol.

Additional discovered support maps: `full/filesystem.h` unconditionally adds
`fs_inode_origins` INODE_STORAGE (NO_PREALLOC, value8, lifetime credit limit65536)
and `fs_diagnostics` ARRAY1/value16. Their local-storage overhead and native
tracker allocations are not zero and are not included in the twelve-map core.
Independent manifest/layout review is pending; no full-budget approval is claimed.


## v2 bounded failure/cleanup repair

The v1 frozen source remains retained; v1 was rejected for missing timeout and
failure-path cleanup evidence. v2 sets C stdout/stderr unbuffered before loading
and emits each exact `PROGRAM_ID`/`MAP_ID` immediately after its FD is identified,
followed by `OWNERSHIP_COMPLETE 12 1` before any operation. Load failure or death
before the complete marker leaves **partial-load/unrecorded IDs UNPROVEN**, even
if all recorded IDs subsequently disappear; this can never become a pass.

`supervise.py` owns the runner process group, enforces 180 seconds plus TERM/5s/
KILL/5s bounds, and unconditionally performs read-only exact-ID joins after
success, assertion failure, timeout or signal. The shared proven program cleanup
utility is reused unchanged; maps have a separate 10-second total join. Each
query itself has the remaining deadline as subprocess timeout. No map/program
is deleted, globally enumerated or adopted. Cleanup failure fails an otherwise
successful run; failed runner status (including timeout124) is retained separately
and as the final status, never replaced by successful cleanup. Complete ownership
records and both joins are required for success. Power loss, SIGKILL of the
supervisor or an unkillable process cannot be certified by this mechanism.

The map classifier accepts only C-locale bpftool status255, empty stdout and exact
`Error: get map by id (ID): No such file or directory\n`. This contract was
validated against the pinned build image's bpftool7.7.0/libbpf1.7 by strace ENOENT
syscall injection: the BPF syscall was **replaced**, not executed. Durable
`provenance/pinned-map-enoent.*` retains status/stdout/stderr/strace. Permission,
wrong-ID, wrong-stream/status, missing executable or arbitrary query errors are
not absence. Ten puremock regressions exercise failure, timeout/KILL, flushed
IDs, partial ownership and cleanup errors without running BPF or the real runner.

Whole-profile accounting still has no total: admin TASK_STORAGE key size is4,
and implicit ELF data maps (.bss/.rodata etc), notably GADGET_TRACER pointer
globals, require inspection of the exact owner compilation profile. Passing this
repair does not approve production layout/per-UID-version semantics or any budget.


## v3 program-type correction after actual run6 rejection

Resource-v2 on the original exact kernel was rejected at processed0 instructions:
`socket filter progs cannot use bpf_spin_lock yet` (EINVAL). This remains a real
failed attempt; partial-load ID absence remained UNPROVEN and the other run6
cases were NOTRUN. No subsequent static check reclassifies that attempt.

The pinned kernel source `kernel/bpf/verifier.c:20952–20957` explicitly rejects
SOCKET_FILTER programs referencing spinlocked map values. At22955–22960 it
requires SYSCALL programs to be sleepable. The already-proved publication
fixture uses `SEC("syscall")` and empty `bpf_test_run_opts`, reading signed command
results through `(int)retval`. v3 follows exactly that program-type/command-run
model: libbpf must infer SYSCALL plus BPF_F_SLEEPABLE from the ELF; no flags/type
are forced by the runner and no spinlock/security check is removed. Packet data
and repeat fields from the socket-filter API are removed from its TEST_RUN call.

A shared open-only contract now requires exactly one program, name `shape`,
section `syscall`, type SYSCALL and zero explicit flags at object-open time. Both the checker and
runner use it, with the runner rejecting mismatches **before LOAD_BEGIN/load**.
The checker tests negative in-memory SOCKET_FILTER and unexpected explicit flags;
the frozen actual v2 ELF is also rejected open-only. These checks establish
classification, not verifier acceptance. All prior map/layout/MAX8/supervision
checks remain. A fresh independently reviewed exact-kernel run is still required.


Open-only nuance confirmed against upstream libbpf v1.7.0 `src/libbpf.c`:
`section_defs` maps syscall to SYSCALL/SEC_SLEEPABLE (retained source line9880),
while `libbpf_prepare_prog_load` applies BPF_F_SLEEPABLE to load opts at7725–7726.
Consequently `bpf_program__flags()` is zero immediately after object open; the
first v3 offline assertion incorrectly expected the eventual load flag and
failed before any load. It was corrected to the actual phase contract, not
weakened to permit sockets or arbitrary flags. The runner neither rewrites type
nor suppresses required sleepability. Pinned libbpf and the previous publication
runtime establish the loading model, but v3 itself still needs verifier proof.
Source: https://raw.githubusercontent.com/libbpf/libbpf/v1.7.0/src/libbpf.c

## v4 FD-access versus map-object metadata correction

Run7 original/resource-v3 verified/loaded (1195 instructions), then aborted134
at the initial map-flags equality assertion. Its twelve owned map IDs and one
program ID joined absent (cleanup0); that remains a failed runtime attempt,
not a pass. Other resource matrix cells were NOTRUN.

Pinned Linux6b4b543fa18757297ac756a6fe6e64f506b7844a `kernel/bpf/syscall.c`
separates these properties: `bpf_map_flags_retain_permanent` removes **only**
BPF_F_RDONLY/BPF_F_WRONLY when setting object map_flags (424–442), while
`bpf_get_file_flag` selects O_RDONLY/O_WRONLY/O_RDWR (1216–1225), which map_create
passes to the new FD (1675–1693). GET_INFO returns the persistent map flags
(5484). Therefore equality with all ELF-declared flags was the wrong assertion.
The exact retrieved file is Git-blob verified against the pinned commit.

v4 keeps every ELF map flag unchanged. The live assertion compares precisely
the persistent flags and separately uses fcntl(F_GETFL)/O_ACCMODE to verify the
actual owned FD access mode. All actual/declared flags, expected persistent
flags and FD modes are printed unbuffered before validation, alongside the
unchanged type/key/value/capacity/ID assertions. Host regressions reject wrong
FD permissions, missing/added persistent flags, retained FD-only flags, failed
fcntl and invalid simultaneous read/write-only declarations.

A future runtime negative host write probes the readonly inventory FD at its
out-of-range key4096. Pinned map_update_elem checks write permission and returns
EPERM before key/bounds processing (1883–1885). Thus even if the FD were wrongly
writable, the invalid ARRAY index cannot modify any entry or committed state.
Both libbpf's result and errno must be EPERM. Config/command separately retain
RDONLY_PROG in object metadata, require host O_RDWR FDs, and perform same-value
host writes/readbacks before exercises; RDONLY_PROG is not host-FD readonly.
This is not new dynamic verifier proof of program-side forbidden writes.

No load, runtime permission probe or cloud operation was performed for this
repair. Existing type guard, mapcount/capacity/preallocation, size/BTF/MAX8,
ID-cycle and bounded unconditional cleanup checks remain. Both exact kernels
still need independently reviewed fresh evidence. Source:
https://raw.githubusercontent.com/torvalds/linux/6b4b543fa18757297ac756a6fe6e64f506b7844a/kernel/bpf/syscall.c
