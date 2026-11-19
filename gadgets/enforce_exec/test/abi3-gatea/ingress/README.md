# Exact-target ingress permission / ARM probe

**Separate, test-only primitive prototype.** The six initial Gate A files in the
parent directory are unchanged. This is not production ingress enforcement and
is not completion of G018 or the ScopeSession architecture.

## First slice

The first slice implements three kernel programs (five tracing programs are added
by the owned-ingress expansion below):

1. An authenticated syscall command resolves retained `O_PATH` FDs in the
   single-threaded administrative task. It checks cgroup2 superblock magic,
   `cgroup.procs` kernfs node name, distinct target/control objects and the
   `O_PATH` flag. The node identity comes from `inode->i_private`, not inode
   number, path equality or mount read-only flags. The harness retains every FD
   until after all links detach. RCU protects fd-table lookup. Configuration,
   including the admin TID and random nonce, is frozen before commands execute;
   pinning records the exact administrative task pointer and cannot overwrite it.
2. Non-sleepable `inode_permission` preserves a prior denial and observes only
   exact target-node `MAY_WRITE` permission requests on cgroup2. Audit returns its
   incoming result; strict denies with `EPERM`, regardless of caller identity.
   An inspection fault is counted; audit never blocks for that fault, and a
   recorded inspection fault prevents strict ARM. Runtime inspection faults and
   their complete strict fail-closed handling remain an integration obligation;
   this first probe requires zero faults throughout its successful cases.
3. `fexit/cgroup_kn_lock_live` commits a pending class only on a successful live
   return for the exact administrative control node, exact admin task/TID,
   frozen nonce and matching attempt. The control root is a different object,
   **not** a caller exemption on the protected target. A negative-PID write must
   fail and produce the matching new kernel receipt; error alone cannot prove ARM.
   No helper executes while the dispatch spinlock is held.

The native runner requires real positive and negative controls:

- Outside `clone3(CLONE_INTO_CGROUP)` succeeds **before hooks**, with child
  `/proc/self/cgroup` confirming actual placement. An unrelated permission denial
  cannot substitute for this baseline.
- Wrong nonce and a `/dev/null` O_PATH FD cannot authenticate the target; the
  established target cannot be replaced.
- Audit permits the outside clone and records the exact target permission check.
- Wrong nonce cannot stage strict. A negative write through the wrong control
  inode cannot ARM; the exact control inode produces the authenticated receipt.
- Strict denies target clone before child success. Ordinary outside forks and
  unrelated target clones still succeed. Even the administrative caller cannot
  open the protected `cgroup.procs` for writing.
- A child enters a private mount namespace **and a new cgroup namespace**, mounts
  a read-only cgroup2 filesystem, opens its target directory O_PATH and repeats
  strict denial and audit success. `statx(STATX_MNT_ID)` on the original and new
  target FDs must report distinct mount IDs; both mount and cgroup namespace
  `(st_dev, st_ino)` identities must change. `fstatvfs` on the actual clone target
  FD must report read-only and `fstatfs` must report cgroup2 magic. The permission
  observation must freshly match the same exact pinned kernfs node in the clone
  creator, with the expected audit/denial counter increment. Superblock pointers
  are diagnostic only: neither equality nor inequality is required.
  Namespace creation/mount failures fail the test; they are not skips.
- Switching back to audit through the control receipt restores successful target
  clone. Final state requires no inspection faults or pending ARM.

## Deliberately pending

The local expansion implements target-aware successful `cgroup_can_fork` tokens,
post-fork/cancel completion accounting, serial invalidation and conservative
unknown-prefix handling. These isolated owned-token and completion assertions passed on both exact
admitted kernels in run2. They do not prove stalled-operation race safety or
completion of G018.
Actual stalled audit-era forks racing promotion, full candidate receipts/history
certification, attachment-prefix qualification and in-scope ordinary-fork tests
remain required. Compact last-fact fields are not a retained production ledger.

The prior nonzero LSM-return branch is present but this first slice does not
inject an independent earlier LSM denial. There is no claim of migration veto,
revocation of already-open descriptors, descendant coverage, hostile-admin
resistance, general multithreaded FD authentication or error-path fail-closed
qualification. No public/private dependency pins or production profiles use it.

## Build and run

Build unprivileged with Clang BPF support, libbpf headers, pkg-config and a C
compiler, Python 3 and llvm-objdump:

```sh
gadgets/enforce_exec/test/abi3-gatea/ingress/build.sh /tmp/gatea-ingress-build
```

After independent review, execute only on an owned disposable root host with
one of the two exact BTF identities in `fullruntime/KERNEL-MATRIX.md`:

```sh
IG_ABI3_GATE_A_DISPOSABLE=1 \
  gadgets/enforce_exec/test/abi3-gatea/ingress/run-disposable.sh \
  /tmp/gatea-ingress-build /var/tmp/gatea-ingress-NEW
```

The wrapper creates one exact cgroup root plus two children and places only its
runner in that root. It logs directly to a regular file, so inherited stdout
cannot stall cleanup. A 180-second timeout bounds the runner; the EXIT trap kills
only that owned tree, removes its three cgroups, and verifies every recorded BPF
program ID is absent. Nothing is pinned. Preserve identity, verifier, runtime and
cleanup logs. This does not replace the cloud resource ledger/cleanup receipts.

## Current archived evidence

All six current isolated Gate A cases passed actual verifier/load/attach/runtime assertions and owned-program/cgroup cleanup on both exact admitted kernels. Durable evidence: `/home/mbertschy/ig15-gatea-proof-20261028-run2-215027Z/{README.md,matrix-results.json,FINAL-SHA256SUMS}` and `proof/final-all-proof/proof/`. Initial and ingress use `cleanup-v2`; publication uses `lineinfo-v4`. Each matrix entry reports wrapper status 0 and all owned program IDs absent. Proof applies to the archived source/build snapshots, not arbitrary later working-tree bytes. Exact live BTFs are original `12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b` and Kubernetes-capable `759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51`. Archived builds used actual pinned Ubuntu Clang 21.1.8. `cleanup-receipt.json` and exact API-404 logs confirm deletion of the newly owned droplet/key/tag by 22:29:39Z. Earlier failed attempts remain failed; later retries do not reclassify them.

G018 remains incomplete and production integration remains blocked pending real stalled audit-era ingress/ARM overlap, initial attachment-prefix qualification, real nested scratch ownership, narrow audit-fault/nonwrap regressions, maximum-eight publication proof and concrete resource ceilings. Full real-history semantic qualification remains required before production approval. These bounded primitive results do not certify full ScopeSession, owner, lineage, policy or consumer integration.

### Historical verifier and runtime attempts

The following records describe evidence available at each earlier attempt;
pending/no-success statements below are superseded only for the archived cases
above, not for current working-tree changes or remaining obligations.

 the first original-kernel probe established the real
outside clone-into positive baseline before hooks, then failed verifier loading
at the prior-result return in `inode_permission`. Its unbounded int return reached
R0 as an unsigned 32-bit value, outside the required `[-4095, 0]` interval.
The hook now returns a signed 64-bit bounded value: zero stays zero, every valid
prior errno is preserved exactly, and invalid nonzero inputs remain denial
(`EPERM`), never allow. `return_test.c`, run by the build, checks all 4095 valid
denials plus zero and invalid boundary values. A reverted unbounded-return
negative control fails that test. The emitted BPF explicitly sign-extends the
input and applies signed bounds. At that stage, a fresh verifier retry remained necessary; no successful
ingress attachment or permission/promotion proof was available.

A second verifier attempt exposed Clang 21.1.8 lowering the pure C lower-bound
check on a `w` register while returning a separately sign-extended `r` register.
The verifier correctly could not transfer that lower bound. The BPF helper now
uses five explicit instructions keeping extension, signed bounds and selected
result on one 64-bit register; the native C equivalent remains exhaustively
tested. The build inspects the emitted LSM bytecode and rejects the old lowering.
Actual guest Clang 21.1.8 compilation confirms the new sequence on R7; this is
compiler evidence, **not** verifier acceptance. The runner also now exercises the
actual BPF helper through an authenticated syscall command for every valid errno
and invalid boundary samples after load, before target authentication. That
runtime regression was then pending; both archived run2 cases passed it.

The next probe loaded all three programs and passed actual-BPF errno tests and
pin authentication, then failed its first audit clone assertion. Exact kernel
BTF exposed a fixture ABI bug: the hook had omitted the leading
`const struct mnt_idmap *idmap` argument. It read the write mask as the prior LSM
result and could deny before reaching any target counters. The signature now
matches the actual `bpf_lsm_inode_permission(idmap, inode, mask)` prototype, with
BPF's prior result in the fourth context slot. The wrapper verifies that exact
prototype against running BTF before creating cgroups/loading BPF. The build
checks emitted context offsets 8/16/24; `check-abi.py --self-test BTF` also rejects
missing/swapped-idmap negative controls on the supplied exact BTF.

Every assertion now prints reachability counters (hook calls, prior returns,
zero inputs, cgroup magic matches, write requests and node matches), plus the
last observed magic/superblock/node/mask/TID. Clone attempts explicitly print
their result and successful placement. The exact-target audit assertion is
unchanged. The corrected ABI then required independent review and a fresh
kernel run; zero target hits from the mis-specified hook do not establish that
the permission primitive is unreachable.

## Approved mount-identity criterion correction

The corrected-ABI original-kernel run proved outside audit success with a target
hit, authenticated strict ARM, strict clone denial, administrative no-exemption
denial, unrelated clone/ordinary fork success and read-only new-namespace clone
denial. It failed the subsequent **test assumption** requiring a different
superblock. The pinned source shares kernfs superblocks by `(root, ns_tag)`;
cgroup2 uses its fixed default root, leaves `ns_tag` zero and sets `fc->global`.
A cgroup namespace changes the returned root dentry, not that superblock key.
See [kernfs sharing](https://github.com/torvalds/linux/blob/6b4b543fa18757297ac756a6fe6e64f506b7844a/fs/kernfs/mount.c#L336-L342)
and [cgroup mount setup](https://github.com/torvalds/linux/blob/6b4b543fa18757297ac756a6fe6e64f506b7844a/kernel/cgroup/cgroup.c#L2262-L2301).

After explicit architect and independent critic approval, the runner now requires
the distinct mount-ID and namespace identities, actual-FD read-only/cgroup2
checks, fresh exact-node match and unchanged strict/audit outcomes described
above. This corrects an impossible mount-setup premise; it does not relax the
BPF matcher, authentication, pin lifetime or no-exemption behavior. It makes no
cross-superblock proof claim.

Run the new identity-check regression without privileges or BPF loading:

```sh
/tmp/gatea-ingress-build/runner --self-test-identities
```

It covers a valid evidence tuple, missing original/new mount IDs, unchanged mount
ID, unchanged mount/cgroup namespaces, writable flags and non-cgroup2 magic. An
actual local O_PATH FD queried twice with statx must also be rejected as the same
mount. These local checks pass; the corrected privileged mount test was pending at that stage and subsequently
passed in both archived run2 cases. Source/runtime evidence from the earlier failed assertion is retained,
not relabelled as a fully passing ingress run.

## Owned-ingress expansion — bounded two-kernel runtime evidence

Five new tracing programs observe successful target `CLONE_INTO_CGROUP` admission,
post-fork and cancellation entry/exit. The preallocated 64-entry HASH owns a
nonwrapping cookie, creator physical identity, frozen scope nonce and target node.
Registration increments a dispatch-protected count and serial while the real
`cgroup_mutex` is still held. Failed insertion records sticky uncertainty; an
existing same-address row is quarantined rather than credited to the new birth.
Completion validates and claims ownership once, publishes a compact fact or
unknown result, then releases its own count. An unowned completion cannot refund
another birth. Stage/ARM refuse uncertain or nonquiescent state, and ARM rejects
any serial change since staging before publishing the class. These isolated primitive semantics have verifier/runtime evidence on both exact
kernels, not a stalled-operation concurrency proof.

The runner now requires success-token reclamation, strict/unrelated non-admission,
an actual intervening audit clone invalidating a staged strict receipt, natural
quiescence followed by fresh ARM, and an actual unobserved admission (registration
link detached) causing prefix uncertainty without a false decrement. These assertions passed in both archived run2 ingress cases. Neither synthetic counters nor elapsed sleeps substitute for overlap.

A cancellation test uses a pipe-stalled direct child of the exact administrative
task, still in the owned control cgroup. Authentication acquires a task reference
and records its physical identity plus a fresh random test nonce. Only that
one-shot creator's real successful target admission can call `bpf_send_signal(9)`.
The test requires helper success, that worker's SIGKILL status, a genuine cancel
completion, exactly one reclaimed token, zero uncertainty, and explicit task
reference release. No generic PID trigger or host-task signal is permitted.
This authenticated injection passed on both exact kernels: helper success,
direct-child SIGKILL status, genuine cancel completion and exact token reclamation
were recorded. It does not prove stalled-fork/ARM overlap.

## New bounded overlap fixture — build only, not kernel validated

The current working tree adds one authenticated, single-use rendezvous using a
held direct-child task reference and fresh nonce, distinct frozen allowed CPU
identities and exact target/admin/control-node identity. It never fabricates an
inflight count. Successful target `cgroup_can_fork` fexit, while cgroup_mutex is
held, waits for the real control-thread `cgroup_kn_lock_live` fentry. Its release
witness requires that no ARM exit occurred first. Real post/cancel fexit waits
for actual ARM exit before publishing facts and releasing the owned token. ARM
must observe exactly one real ingress token and refuse BUSY plus STALE; its
serial, receipt, CPU, child/cookie and ordering witnesses are asserted and logged.
An already-recorded ARM exit between kernel unlock and completion fexit is valid.

Each BPF wait is bounded by both 65,536 iterations and a 10ms monotonic deadline,
checked every iteration. No spinlock is held across a wait or helper. Exhaustion
records explicit failure, resumes normal audit/owned completion and fails the
runner; it is never evidence of quiescence. No automatic retry or bound increase
is permitted. A stale receipt must still refuse after completion, while fresh
staging may commit. Existing signal cancellation remains a disjoint mode. The
same new read-only mount also exercises an unrelated target successfully.

Local Clang 21.1.8 compilation and existing emitted-bytecode/BTF/errno checks are
build evidence only. The new hook/callback, bounded timing, distinct-CPU witnesses
and overlap assertions require independent review, actual verifier/load/attach
and isolated runtime proof on both exact kernels. Ordinary fork from inside the
strict target, overflow/fault regressions and full production history remain
unproved. Earlier Clang 19.1.7 local builds and failed attempts are historical;
archived run2 used actual pinned Ubuntu Clang 21.1.8 and passed its narrower cases.
