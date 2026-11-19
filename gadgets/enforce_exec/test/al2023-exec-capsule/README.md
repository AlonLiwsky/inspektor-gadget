# AL2023 source-only exec capsule fixture (default off, test only)

Exact-kernel proof for `../../full/shared_exec_capsule.h`. No product image,
Makefile or Ready path selects it.

The capsule freezes an exec's **original** class at its first selected policy
admission and keeps that class for the rest of the same physical exec. It
replaces the unsafe current-route fallback documented by
`fullruntime/opaque_source_mode_headerless_migration_test.go`.

## Design

**Storage.** There are two preallocated ARRAY maps, sized to the guest
`pid_max`:

* `capsules`, indexed by the initial-namespace TGID.
* `markers`, indexed by the initial-namespace thread ID.

The indexes are lookup keys only.

* **Identity.** An admission identifies its exec by the exact `task_struct`
  pointer plus the `linux_binprm` pointer. The LSM hook cannot know the
  exec's sequence.
* **Freshness.** Task and bprm addresses can be reused. Protection against
  that comes from every covered begin unconditionally retiring the previous
  capsule.
* **Binding.** The nonwrapping sequence ties the retire and the route pin to
  one exec.

Insertion cannot fail. An out-of-range index is an invariant fault. The arrays
are sized to `pid_max` at load, so raising `kernel.pid_max` later turns
high-PID execs into invariant faults. A product loader must size to
`PID_MAX_LIMIT` or refuse a larger `pid_max`.

**Hooks.** A product loader MUST attach them in this order and detach in the
exact reverse. The order is part of the coverage proof and is a hard
invariant:

1. **Terminal**, `fexit/bprm_execve`. Only the exact task+bprm owner retires
   the capsule. A same-TGID losing waiter, a wrong bprm or a duplicate
   terminal is FOREIGN and changes nothing. Retiring releases the
   original-route pin under that route's lock.
2. **Entry marker**, `fentry/bprm_execve`. It is attached after the terminal,
   so every marked call is guaranteed a terminal.
3. **Begin**, `fentry/security_bprm_creds_for_exec`.
   * This runs under `signal->cred_guard_mutex`. Per the exact vendor
     `fs/exec.c` (independently audited), that mutex is released only in
     three places:
     * by `setup_new_exec()`;
     * by `begin_new_exec()`'s `out_unlock`;
     * by `free_bprm()`, after `bprm_execve()` returns.

     The first two both run after `commit_creds()`, so after `de_thread()`
     has left a single thread. Any capsule still present for the TGID
     therefore belongs to a finished exec. It is retired, and its pin
     released, before the new exec opens. This happens even when this begin
     then faults.
   * A call with no marker (late attach) is never opened.
4. **Admission**, `lsm/bprm_check_security`. In this fixture it only observes
   and returns the prior result.
   * **First selected admission:** freezes the class and takes the
     original-route source pin under the route lock.
   * **Later admissions** (interpreter iterations, possibly after a cgroup
     move): claim the **original** route through the protected owner. The
     current cgroup is never consulted.
   * **Mismatch:** faults with the frozen class.
   * **Uncovered exec** (late attach): freezes without a pin.
   * **Unselected first admission:** freezes nothing.

**Coverage caveat.** The per-CPU fentry/fexit recursion guard can skip a
program, but only under involuntary preemption, for example `preempt=full` on
a `PREEMPT_DYNAMIC` kernel. AL2023 defaults to `(none)`. A skipped terminal
leaves a finished exec's capsule and pin in place until the TGID's next begin
or admission. Every begin retires a stale capsule, covered or not. A class
can therefore leak only if three things all happen:
* that terminal is skipped;
* the same thread's next begin is also skipped;
* the new bprm reuses the old address.

The runner accepts only the `(none)` and `(voluntary)` preemption modes,
refuses unknown modes, and requires zero recursion misses.

**Pin failures.**
* If the pin cannot be acquired, the intent is dropped (`PIN_FAILED`), and
  every later admission of that exec faults with the frozen class, even
  without migration.
* If a pin cannot be released (an invariant breach), the route keeps its pin
  and is latched `unresolved_sources`, so publication stays refused. The owner
  is abandoned, which keeps the TGID usable.
  * The latch is permanent by design and has no clear API.
  * Recovery is operator-driven: unload the collection, which destroys the
    route ARRAY, and reload it. That runs a fresh qualification.
  * It must never be cleared in place.

**Capsule-internal faults** never become a deny for every exec on the node. These are an
out-of-range TGID, a capsule stuck in RETIRING, a failed retire or a corrupt frozen class,
none of which the kernel premises allow. `se_cap_degrade` resolves them through the
*current* route selection and grants no claim:
* an unselected exec stays unselected;
* an Audit exec gets an Audit fault (nonblocking);
* only a selected Strict exec is denied.

Loaders size the arrays to `PID_MAX_LIMIT` (2^22 on 64-bit), so a TGID cannot be out of
range.

**Uncovered execs.** An exec already in flight at attach can see a
shebang-iteration fault even without migration. This is a transient
availability cost at gadget start.

**Locks.** The capsule lock guards the capsule. The embedded owner is guarded
only by the original route lock. The code never nests the two.

## Build and run

```sh
D="$HOME/.local/state/sandbox-policy-recovery/g005a-exec-capsule-20261109"
P=gadgets/enforce_exec/test/al2023-exec-capsule
for v in 6.12 6.18; do
  VMLINUX_DIR="$HOME/.local/state/sandbox-policy-recovery/g020-phase-live-20261109/$v" \
    OUTPUT="$D/capsule-$v.bpf.o" "$P/build.sh"
done
gcc -static -pthread -O2 -Wall -Wextra -Werror "$P/helper/waiter.c" -o "$D/waiter"
CGO_ENABLED=0 GOWORK=off go build -o "$D/exec-capsule-runner" "./$P/runner"
"$D/exec-capsule-runner" -object "$D/capsule-6.12.bpf.o"   # inspect only
# On an isolated exact AL2023 guest, as root:
./exec-capsule-runner -object capsule-6.12.bpf.o -waiter ./waiter -run-isolated
```

Live mode first checks the exact kernel release and BTF SHA256, and that BPF
LSM is active. It then runs these scenarios:

* **Late attach.** An exec is blocked before load and attach, then released.
  * Expected: an uncovered unpinned freeze of the original class, then a stale
    retire on the next covered exec.
* **Audit↔Strict migration.** The interpreter's exec-open is held with
  fanotify `FAN_OPEN_EXEC_PERM` while the process is moved to the other
  cgroup.
  * Expected: the interpreter admission sees the original class; the next
    fresh exec uses the new route.
* **The same migration inside a new PID namespace.**
* **Nonleader exec with a same-TGID losing waiter.**
  * Expected: the loser is killed by `de_thread()` and its terminal is
    FOREIGN; after `exchange_tids()` the winner holds the leader PID.
* **ENOEXEC failure.**
* **`AT_EXECVE_CHECK`.**
  * On 6.18: begin plus a check-only terminal, with no admission and no
    success.
  * On 6.12: EINVAL, rejected inside `alloc_bprm` before any bprm or hook.

Every scenario requires balanced routes (no early claims, pins or unresolved
sources), zero faults, FREE capsules for the test TGIDs, and exact deltas for
the counters named in that scenario's `exactly()` map in `runner/main.go`. At the end, the run scans the whole `markers` array
for leftovers and checks recursion misses on every program.

The late-attach live scenario has only one admission after attach. Its
"later uncovered admission faults with the original class" behaviour is
proved only by the host contract.

The runner execs the helper's `exec` mode before any exec that will block in
fanotify. Go starts children with vfork, and blocking inside that exec would
deadlock the Go runtime.

## Not proved here

This fixture does not prove any of the following:

* Real policy evaluation, verdicts or deny behavior.
* TASK/WORK integration or success history.
* The capsule wired into the verdict candidate. The same-bprm compile guard
  remains.
* Route publication races beyond the pin barrier.
* Resource acceptance of about 436 MiB + 64 MiB at `pid_max` = 4194304.
* Product Ready. `NodeEnforcer.Ready` stays unavailable.
