// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import "fmt"

// Credit-at-exit witness opaque_real_exit_credit
// (ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE in
// bpf/opaque_real_owner_child_candidate.bpf.c), indexed by
// REAL_OWNER_EXIT_*. A charged task is settled in tp_btf/sched_process_exit
// and its exact identity is carried to task_free by a tombstone in
// se_exit_tombstones, keyed by the task address. An earlier lifetime's
// tombstone at that address is told apart by its task start_time and, since
// start_time alone can repeat across lifetimes, by the published directory
// value:
//   - Inserted: tombstone inserts at exit. Refused inserts take the slow
//     path (task_free settles the task as before, FallbackFree), never
//     early: Overflow (map full), AccountOverflow (the binding's share of
//     the map full: one workload's zombies overflow only its own binding),
//     Busy (-EBUSY bucket) and Blocked (an earlier lifetime's tombstone the
//     reaper still owns);
//   - Stale: a tombstone of an earlier lifetime at the address (start_time
//     or directory mismatch), found at exit or free and finished as its own
//     free would have. It proves an earlier fault (failed delete, missed
//     task_free);
//   - Settled, DirPending: inserted exits whose withdrawal completed, or was
//     refused (the death lease stays held until task_free resumes it);
//   - Unsettled: se_of_record_death CONTENDED at exit (this task never
//     owned the charge: benign); UnsettledFault: LIMIT, CORRUPT or STALE;
//     both leave the task to the task_free fallback;
//   - DirResumed, DirFaulted: task_free resumes of DirPending; a faulted
//     resume leaves the withdrawal and the tombstone to the reaper
//     (ReaperRetired); RetireLost: reaper visits that lost the retirement
//     CAS to another visit (benign);
//   - FallbackFree: task_free settled a task with no exit settlement;
//   - Freed: tombstones consumed by task_free (TASK FREED wakeups);
//   - TombFault: a tombstone delete or lookup failed;
//   - LeaseFault: a free could not rebuild a DirPending exit's lease
//     exactly or release it: the lease stays held, so the reaper never
//     retires that tombstone or withdraws the key, and the slot stays
//     charged (fail-closed, counted);
//   - HeldStuck: DEAD charges a reaper visit still found with their death
//     lease held, and no tombstone of theirs accounting for it (DIR_PENDING
//     or FREE_PENDING), one second after it first found them so. The visit
//     stays PENDING (the slot charged, fail-closed); the count makes a lost
//     lease holder visible instead of an endless "not yet";
//   - HighCrossed: inserts that raised Live to the high-water mark
//     (ExitCreditHighWaterPercent of the map), once per upward crossing;
//   - Live and HighWater are gauges: tombstones held now, and the most held
//     (a lower bound under more than 16 racing inserts).
//
// A zombie holds no TASK credit: the TASK quota bounds live tasks, the
// tombstones bound exited-but-unfreed ones, node-wide (32 x TASKS) and per
// binding (an equal share each, opaque_real_exit_accounts).
const (
	ExitCreditInserted = iota
	ExitCreditLive
	ExitCreditHighWater
	ExitCreditOverflow
	ExitCreditStale
	ExitCreditSettled
	ExitCreditDirPending
	ExitCreditDirResumed
	ExitCreditDirFaulted
	ExitCreditFallbackFree
	ExitCreditFreed
	ExitCreditReaperRetired
	ExitCreditUnsettled
	ExitCreditTombFault
	ExitCreditUnsettledFault
	ExitCreditBusy
	ExitCreditBlocked
	ExitCreditAccountOverflow
	ExitCreditRetireLost
	ExitCreditLeaseFault
	ExitCreditHeldStuck
	ExitCreditHighCrossed
	ExitCreditCounters
)

var exitCreditNames = [ExitCreditCounters]string{
	"inserted", "live", "high-water", "overflow", "stale", "settled",
	"dir-pending", "dir-resumed", "dir-faulted", "fallback-free", "freed",
	"reaper-retired", "unsettled", "tomb-fault", "unsettled-fault", "busy",
	"blocked", "account-overflow", "retire-lost", "lease-fault",
	"held-stuck", "high-crossed",
}

// ExitCreditHighWaterPercent is the tombstone high-water threshold: a window
// in which Live crossed this share of the map (HighCrossed), the HighWater
// gauge rose to it, or whose Live gauge is at it now, is Degraded, before
// any insert overflows. A peak of an earlier window does not degrade later
// ones; a repeat peak of a later window does, even below the lifetime
// HighWater. BPF pins the same mark (REAL_OWNER_EXIT_HIGH_MARK).
const ExitCreditHighWaterPercent = 75

// ExitCreditHealth is the node-health reading of one witness window.
type ExitCreditHealth uint8

const (
	// ExitCreditUnknown: the witness could not be read, the tombstone
	// capacity is unknown or a counter moved backwards. Never clean: the
	// node is NotReady for credit at exit.
	ExitCreditUnknown ExitCreditHealth = iota
	ExitCreditHealthy
	ExitCreditDegraded
)

func (h ExitCreditHealth) String() string {
	switch h {
	case ExitCreditHealthy:
		return "healthy"
	case ExitCreditDegraded:
		return "degraded"
	}
	return "unknown"
}

// ExitCreditVerdict is the credit-at-exit report for one window.
type ExitCreditVerdict struct {
	// Delta is the per-counter delta; for the Live and HighWater gauges it
	// is the value after the window.
	Delta [ExitCreditCounters]uint64
	// LiveBefore is the Live gauge before the window.
	LiveBefore uint64
	// Capacity is se_exit_tombstones' max_entries.
	Capacity uint64
	// SlowPath counts the exits whose credit waited for task_free: refused
	// inserts (Overflow, AccountOverflow, Busy, Blocked), refused exit
	// withdrawals (DirPending) and exits that settled nothing (Unsettled,
	// UnsettledFault).
	SlowPath uint64
	// Faults counts faulted free-time resumes, tombstone and lease faults,
	// stuck held leases (HeldStuck), faulted exit settlements
	// (UnsettledFault) and stale tombstones (each one the trace of an
	// earlier fault).
	Faults uint64
	// HighWater is true when Live crossed ExitCreditHighWaterPercent of
	// Capacity within the window (HighCrossed), the HighWater gauge rose to
	// it, or Live is at it after the window.
	HighWater bool
	// Degraded is true on any slow path other than the benign Unsettled
	// (CONTENDED), any fault, or HighWater: the credit of those tasks
	// returned no earlier than before credit at exit, or the node is close
	// to it (user decision: overflow is counted and reported Degraded, never
	// refused).
	Degraded bool
}

func (v ExitCreditVerdict) String() string {
	out := ""
	for i, name := range exitCreditNames {
		out += fmt.Sprintf("%s=%d ", name, v.Delta[i])
	}
	return out + fmt.Sprintf("capacity=%d slow=%d faults=%d high=%v degraded=%v", v.Capacity, v.SlowPath, v.Faults, v.HighWater, v.Degraded)
}

// ExitCredit maps two witness snapshots and the tombstone capacity to a
// verdict. A monotonic counter that moved backwards (reset or reload) or an
// unknown capacity is an error: the verdict is unknown, never clean.
func ExitCredit(before, after [ExitCreditCounters]uint64, capacity uint64) (ExitCreditVerdict, error) {
	v := ExitCreditVerdict{LiveBefore: before[ExitCreditLive], Capacity: capacity}
	if capacity == 0 {
		return v, fmt.Errorf("exit credit: unknown tombstone capacity")
	}
	for i := range after {
		if i == ExitCreditLive || i == ExitCreditHighWater {
			v.Delta[i] = after[i]
			continue
		}
		if after[i] < before[i] {
			return v, fmt.Errorf("exit credit %s counter moved backwards (%d -> %d)", exitCreditNames[i], before[i], after[i])
		}
		v.Delta[i] = after[i] - before[i]
	}
	if after[ExitCreditHighWater] < before[ExitCreditHighWater] {
		return v, fmt.Errorf("exit credit high-water moved backwards (%d -> %d)", before[ExitCreditHighWater], after[ExitCreditHighWater])
	}
	d := v.Delta
	refused := d[ExitCreditOverflow] + d[ExitCreditAccountOverflow] + d[ExitCreditBusy] + d[ExitCreditBlocked]
	v.SlowPath = refused + d[ExitCreditDirPending] + d[ExitCreditUnsettled] + d[ExitCreditUnsettledFault]
	v.Faults = d[ExitCreditDirFaulted] + d[ExitCreditTombFault] + d[ExitCreditLeaseFault] + d[ExitCreditHeldStuck] + d[ExitCreditUnsettledFault] + d[ExitCreditStale]
	high := func(n uint64) bool { return n*100 >= capacity*ExitCreditHighWaterPercent }
	v.HighWater = d[ExitCreditHighCrossed] > 0 ||
		(after[ExitCreditHighWater] > before[ExitCreditHighWater] && high(after[ExitCreditHighWater])) ||
		high(after[ExitCreditLive])
	v.Degraded = v.SlowPath-d[ExitCreditUnsettled]+v.Faults > 0 || v.HighWater
	return v, nil
}

// ExitCreditCheck is the complete node-health verdict of one window: the
// witness read error (readErr, for either snapshot), the two snapshots and
// the tombstone capacity. An unreadable witness, an unknown capacity or a
// counter that moved backwards is ExitCreditUnknown with the error.
func ExitCreditCheck(before, after [ExitCreditCounters]uint64, readErr error, capacity uint64) (ExitCreditVerdict, ExitCreditHealth, error) {
	if readErr != nil {
		return ExitCreditVerdict{Capacity: capacity}, ExitCreditUnknown, fmt.Errorf("exit credit witness unreadable: %w", readErr)
	}
	v, err := ExitCredit(before, after, capacity)
	switch {
	case err != nil:
		return v, ExitCreditUnknown, err
	case v.Degraded:
		return v, ExitCreditDegraded, nil
	}
	return v, ExitCreditHealthy, nil
}

// Quiescent checks the relations of a window in which every task that
// exited was also freed and reaped: every inserted tombstone was settled,
// pending or unsettled; every settled or pending one was freed; every
// pending one was resumed or faulted; every faulted one was retired by the
// reaper; no tombstone of the window is left; and no tombstone or lease
// fault, and no stuck held lease, was counted. Tombstones already held
// when the window opened (LiveBefore: exits before it whose free falls in
// it) may be consumed inside it, so the free-side counts may exceed the
// window's own by at most LiveBefore, and Live may not exceed LiveBefore.
// With LiveBefore == 0 every relation is exact.
func (v ExitCreditVerdict) Quiescent() error {
	d := v.Delta
	carry := v.LiveBefore
	settled := d[ExitCreditSettled] + d[ExitCreditDirPending]
	within := func(got, want uint64) bool { return got >= want && got-want <= carry }
	switch {
	case d[ExitCreditInserted] != settled+d[ExitCreditUnsettled]+d[ExitCreditUnsettledFault]:
		return fmt.Errorf("exit credit: %d inserted, want %d settled + %d dir-pending + %d unsettled + %d unsettled-fault",
			d[ExitCreditInserted], d[ExitCreditSettled], d[ExitCreditDirPending], d[ExitCreditUnsettled], d[ExitCreditUnsettledFault])
	case !within(d[ExitCreditFreed], settled):
		return fmt.Errorf("exit credit: %d freed, want %d settled + %d dir-pending (+ at most %d held before)",
			d[ExitCreditFreed], d[ExitCreditSettled], d[ExitCreditDirPending], carry)
	case !within(d[ExitCreditDirResumed]+d[ExitCreditDirFaulted], d[ExitCreditDirPending]):
		return fmt.Errorf("exit credit: %d dir-pending, want %d resumed + %d faulted (+ at most %d held before)",
			d[ExitCreditDirPending], d[ExitCreditDirResumed], d[ExitCreditDirFaulted], carry)
	case !within(d[ExitCreditReaperRetired], d[ExitCreditDirFaulted]):
		return fmt.Errorf("exit credit: %d tombstones retired by the reaper, want %d faulted resumes (+ at most %d held before)",
			d[ExitCreditReaperRetired], d[ExitCreditDirFaulted], carry)
	case d[ExitCreditLive] > carry || (carry == 0 && d[ExitCreditLive] != 0):
		return fmt.Errorf("exit credit: %d tombstones live, want at most the %d held before", d[ExitCreditLive], carry)
	case d[ExitCreditTombFault] != 0:
		return fmt.Errorf("exit credit: %d tombstone faults", d[ExitCreditTombFault])
	case d[ExitCreditLeaseFault] != 0:
		return fmt.Errorf("exit credit: %d exit leases left held (slots stay charged)", d[ExitCreditLeaseFault])
	case d[ExitCreditHeldStuck] != 0:
		return fmt.Errorf("exit credit: %d death leases found held with no accounted holder (slots stay charged)", d[ExitCreditHeldStuck])
	}
	return nil
}

// DeadSettlements is the number of DEAD TASK settlements of the window:
// at exit (settled or pending) or by the task_free fallback. Each one is
// exactly one DEAD TASK credit the reaper returns.
func (v ExitCreditVerdict) DeadSettlements() uint64 {
	return v.Delta[ExitCreditSettled] + v.Delta[ExitCreditDirPending] + v.Delta[ExitCreditFallbackFree]
}
