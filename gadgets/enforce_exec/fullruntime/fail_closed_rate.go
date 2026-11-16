// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"math"
	"time"
)

// FailClosedRateClasses mirrors the opaque_real_fail_closed_rates witness
// (ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE in
// bpf/opaque_real_owner_child_candidate.bpf.c), indexed by class: TASK
// quota LIMIT, source refusal, missing target, evaluation WORK refusal,
// deferred storage quarantine, other constructor failure, and (G019 M0)
// first-exec qualification fault, pending-receipt quarantine, birth target
// parent open failure, and the interpreter continuation refusals (GAP).
//
// The G019 M0 classes cover the outcomes G025 excluded:
//   - qualification: an owned exec refused because real_owner_birth_qualify
//     faulted at bprm_check (first-exec qualification is now built with the
//     verdict candidate, not only under the successful-birth diagnostic);
//     the same fault at task_alloc was and stays a source refusal;
//   - pending: an owned exec refused while a prior terminal receipt is
//     pending (real_owner_reader_begin_core result & 8), quarantined by
//     real_owner_reader_quarantine_pending;
//   - open-parent: real_owner_child_open_parent failed in
//     real_owner_child_finish;
//   - gap [9]: interpreter continuation refusals only (G019 gap 4, H1;
//     real_owner_continue_refuse, reason in opaque_real_interp_stats).
//     Migration relabel (gap 5) is a binding status, never counted. The
//     G019 gaps 1-3 refusals are not counted here: they land in
//     CONSTRUCT [5], QUALIFY [6] and OPEN_PARENT [8].
//
// Remaining exclusions of an object without the product publisher
// (FailClosedRateLegacyCounters cells): an exec of a task that has no TASK
// (born before the binding, or a birth already counted as refused or
// unconstructed) fails real_owner_child_open_parent in the exec reader and
// is not counted again, and a pending-receipt quarantine on the fork path is
// part of the source refusal class. A zero rate is therefore evidence for
// managed, TASK-carrying births and execs only.
//
// A product-publisher object (FailClosedRateCounters cells) closes the first
// exclusion: that exec is FailClosedRateEntry, and an exec or fork admission
// fault is FailClosedRateAdmission, both counted against an attempt and
// reported outside Total. Its remaining exclusions are the fork path's
// pending-receipt quarantine (a source refusal, as above) and another LSM's
// earlier deny, which is not ours to count.
const FailClosedRateClasses = 10

// Indices of the G019 M0 classes in a FailClosedRateVerdict.
const (
	FailClosedRateQualify    = 6
	FailClosedRatePending    = 7
	FailClosedRateOpenParent = 8
	FailClosedRateGap        = 9
)

// FailClosedRateCounters is the witness map size of a product-publisher
// object: the classes, then FailClosedRateWorkRetry, the WORK start
// retry-bound exhaustions (SE_PROFILE_WORK_RETRIES), then (G019 M4, U2)
// FailClosedRateEntry, then (G019 chain16) FailClosedRateAdmission. Objects
// built without the product publisher have neither (FailClosedRateLegacyCounters).
//
// WorkRetry is a subset already counted as a source or evaluation refusal
// (or a refused terminal fallback). ENTRY counts an exec on an OWNED route
// by a task with no TASK at all (no se_opaque_keys entry: a runtime exec
// entry or a migration in); a failed open with a TASK present stays
// FailClosedRateOpenParent. ADMISSION counts every exec admission fault of
// the exec reader (a STRICT, AUDIT or INVARIANT route-claim fault: a
// latched/adopting/reserved route, a degraded exec-capsule admission, a
// frozen-class mismatch); Strict and invariant faults deny, Audit faults
// allow, and neither is silent any more. Each ADMISSION is also an exec
// attempt, or, for a fork's admission fault (the task_alloc source's claim,
// or the constructor target's re-admission), the birth attempt the source
// counted: one class per attempt. ENTRY and ADMISSION are reported apart and never added to a
// verdict's Total; ADMISSION degrades the node by its own rate.
const (
	FailClosedRateWorkRetry      = FailClosedRateClasses
	FailClosedRateEntry          = FailClosedRateClasses + 1
	FailClosedRateAdmission      = FailClosedRateClasses + 2
	FailClosedRateLegacyCounters = FailClosedRateClasses + 1
	FailClosedRateCounters       = FailClosedRateClasses + 3
)

// FailClosedRateAttempts is the opaque_real_attempts witness of a
// product-publisher object: every OWNED birth claim [0] and every exec
// admission [1] (OWNED, or an ADMISSION fault). Their sum is the
// denominator of Total, ENTRY and ADMISSION.
const FailClosedRateAttempts = 2

// FailClosedRateCells validates a fail-closed rate witness map size: 13
// with the product publisher (ENTRY and ADMISSION present), 11 without.
func FailClosedRateCells(maxEntries uint32) (int, error) {
	switch maxEntries {
	case FailClosedRateCounters, FailClosedRateLegacyCounters:
		return int(maxEntries), nil
	}
	return 0, fmt.Errorf("fail-closed rate witness has %d cells, want %d or %d", maxEntries, FailClosedRateCounters, FailClosedRateLegacyCounters)
}

var failClosedRateClassNames = [FailClosedRateClasses]string{
	"quota-limit", "source-refusal", "missing-target",
	"eval-work-refusal", "storage-refusal", "construct-failure",
	"qualify-fault", "pending-quarantine", "open-parent-failure", "gap-refusal",
}

// Runtime reporting rule (G025, user-approved), applied at runtime by the
// live node's witness poller (sharedLiveFailClosed, NodeEnforcer
// FailClosedHealth) over two sliding windows:
//   - Degraded when the FailClosedRateDegradedWindow verdict at
//     FailClosedRateDegradedThreshold is Degraded, i.e. on any fail-closed
//     refusal (Strict) or unevaluated child (Audit) within 60 s;
//   - NotReady when the FailClosedRateNotReadyWindow verdict at
//     FailClosedRateNotReadyThreshold is Degraded, i.e. a rate above 0.1%
//     over 5 min;
//   - unknown, never zero, when the witness is missing or unreadable or
//     FailClosedRate returns an error; unknown is NotReady-equivalent.
const (
	FailClosedRateDegradedWindow    = time.Minute
	FailClosedRateDegradedThreshold = 0.0
	FailClosedRateNotReadyWindow    = 5 * time.Minute
	FailClosedRateNotReadyThreshold = 0.001
)

// ConcurrentBirthCapacity is the burst capacity of one binding (G019 burst
// gate, user decision "gate at capacity"): the number of concurrent births a
// per-binding WORK quota W admits with no fail-closed refusal. syncReturn is
// whether the object returns WORK credit synchronously at settle
// (ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE, option C; its
// witness map opaque_real_work_sync is the signal).
//
// An in-flight child holds at most two WORK charges at once (its birth WORK
// and its exec evaluation WORK) and the binding's managed parent retains
// one, so the static bound is (W-1)/2: 3 at 64/8, 7 at 128/16, 15 at 128/32
// (the product profile: 8 zero-gated burst streams need W >= 17 and W is a
// power of two) and 256/32.
//
//   - With the synchronous return a WORK credit is held only from its charge
//     until the settling program returns: the birth WORK within the fork,
//     the evaluation WORK from the exec check to the exec terminal, never
//     waiting for the userspace reaper. The capacity is the static bound
//     (W-1)/2 (user decision: the conservative bound is gated). A child
//     then holds at most one WORK at a time, so the measured bound per
//     forking parent thread is about W - retained - 1; it is recorded as
//     information only, never gated.
//
//   - Without it (ADVISORY, TEST ONLY: G019 lead decision (b); the product
//     object requires the synchronous return, by #error in the source and
//     by product admission, and nothing in the product path may use this
//     branch) the WORK credits of an exited child come back
//     asynchronously through the product reaper and nothing throttles forks
//     meanwhile. Non-sync bursts are measured (every refusal counted in its
//     class), never zero-gated: chain15 fs6x20 refused at (W-3)/2 in 4 of
//     160 runs on both kernels under 1-3 ms reap latency. Measured back to back (G019 chain6/chain7, 128/16) refusals
//     came from reaper stalls; the capacity reserves one late child,
//     (W-3)/2: 2 at 64/8, 6 at 128/16, 14 at 256/32 (0 for W < 5). It is a
//     measured claim, not a guarantee: reaper scheduling latency has no
//     hard bound. Sizing rule (option B) for such objects:
//
//     W >= 1 + 2*(concurrent births + λ*D)
//
// with λ the binding's birth rate and D the reap-latency tail of the
// qualified kernels. Births beyond the capacity are never admitted silently:
// each refused evaluation WORK (or birth) fails closed (Strict refusal,
// Audit unevaluated child), is counted in its opaque_real_fail_closed_rates
// class, and degrades the node under the runtime reporting rule below. A
// synchronous return that stopped early (opaque_real_work_sync pending,
// fault or stuck) is Degraded too: that WORK waits for the reaper.
func ConcurrentBirthCapacity(workQuota uint32, syncReturn bool) uint32 {
	if syncReturn {
		if workQuota < 1 {
			return 0
		}
		return (workQuota - 1) / 2
	}
	if workQuota < 3 {
		return 0
	}
	return (workQuota - 3) / 2
}

// FailClosedRateVerdict is the degraded verdict for one sampling window.
type FailClosedRateVerdict struct {
	// Failures is the per-class counter delta over the window.
	Failures [FailClosedRateClasses]uint64
	// Total is the sum of Failures.
	Total uint64
	// Rate is Total per managed attempt (0 when attempts is 0).
	Rate float64
	// Degraded is true when Total is nonzero and Rate exceeds the
	// threshold (a threshold of 0 degrades on any failure).
	Degraded bool
	// Entry and EntryRate are the ENTRY delta and its rate per attempt
	// (FailClosedProductRate only). Entry is never part of Total and never
	// sets Degraded.
	Entry     uint64
	EntryRate float64
	// Admission and AdmissionRate are the ADMISSION delta and its rate per
	// attempt (FailClosedProductRate only). Admission is never part of
	// Total; an AdmissionRate above the threshold sets Degraded.
	Admission     uint64
	AdmissionRate float64
}

// FailClosedRate maps two snapshots of the fail-closed rate witness to a
// degraded verdict. attempts is the number of managed births and execs in
// the window, as counted by the caller. A counter that moved backwards
// (reset or reload), or more failures than attempts, is an error (the
// verdict is unknown), never a zero rate.
//
// This is a pure function. The live node applies the runtime reporting rule
// above through FailClosedProductRate (sharedLiveFailClosed); a missing or
// unreadable witness is never a zero rate.
func FailClosedRate(before, after [FailClosedRateClasses]uint64, attempts uint64, threshold float64) (FailClosedRateVerdict, error) {
	var v FailClosedRateVerdict
	if math.IsNaN(threshold) || threshold < 0 || threshold > 1 {
		return v, fmt.Errorf("fail-closed rate threshold %v outside [0, 1]", threshold)
	}
	for i := range after {
		if after[i] < before[i] {
			return v, fmt.Errorf("fail-closed %s counter moved backwards (%d -> %d)",
				failClosedRateClassNames[i], before[i], after[i])
		}
		v.Failures[i] = after[i] - before[i]
		if v.Total+v.Failures[i] < v.Total {
			return v, fmt.Errorf("fail-closed rate total overflows")
		}
		v.Total += v.Failures[i]
	}
	// Every counted failure refuses one counted attempt; more failures
	// than attempts means the two counts disagree.
	if v.Total > attempts {
		return v, fmt.Errorf("fail-closed total %d exceeds %d attempts", v.Total, attempts)
	}
	if attempts > 0 {
		v.Rate = float64(v.Total) / float64(attempts)
	}
	v.Degraded = v.Total > 0 && v.Rate > threshold
	return v, nil
}

// FailClosedProductRate is FailClosedRate over two snapshots of a
// product-publisher object's witnesses: the 13-cell rate witness and the
// opaque_real_attempts births/execs. attempts is births + execs, the shared
// denominator of Total, ENTRY and ADMISSION. Every counted failure is
// exactly one attempt (an ADMISSION fault never also counts another class),
// so Total + Entry + Admission > attempts (or any counter moving backwards)
// is an error: the verdict is unknown, never zero. Degraded: Total above
// the threshold, or ADMISSION above it.
func FailClosedProductRate(before, after [FailClosedRateCounters]uint64, attemptsBefore, attemptsAfter [FailClosedRateAttempts]uint64, threshold float64) (FailClosedRateVerdict, error) {
	var attempts uint64
	for i := range attemptsAfter {
		if attemptsAfter[i] < attemptsBefore[i] {
			return FailClosedRateVerdict{}, fmt.Errorf("fail-closed attempts[%d] moved backwards (%d -> %d)", i, attemptsBefore[i], attemptsAfter[i])
		}
		d := attemptsAfter[i] - attemptsBefore[i]
		if attempts+d < attempts {
			return FailClosedRateVerdict{}, fmt.Errorf("fail-closed attempts overflow")
		}
		attempts += d
	}
	if after[FailClosedRateEntry] < before[FailClosedRateEntry] {
		return FailClosedRateVerdict{}, fmt.Errorf("fail-closed entry counter moved backwards (%d -> %d)", before[FailClosedRateEntry], after[FailClosedRateEntry])
	}
	entry := after[FailClosedRateEntry] - before[FailClosedRateEntry]
	if after[FailClosedRateAdmission] < before[FailClosedRateAdmission] {
		return FailClosedRateVerdict{}, fmt.Errorf("fail-closed admission counter moved backwards (%d -> %d)", before[FailClosedRateAdmission], after[FailClosedRateAdmission])
	}
	admission := after[FailClosedRateAdmission] - before[FailClosedRateAdmission]
	if entry > attempts || admission > attempts-entry {
		return FailClosedRateVerdict{}, fmt.Errorf("fail-closed entry %d + admission %d exceed %d attempts", entry, admission, attempts)
	}
	var b, a [FailClosedRateClasses]uint64
	copy(b[:], before[:])
	copy(a[:], after[:])
	v, err := FailClosedRate(b, a, attempts-entry-admission, threshold)
	if err != nil {
		return FailClosedRateVerdict{}, err
	}
	// FailClosedRate checked Total <= attempts - entry - admission; rates
	// are per attempt, ENTRY and ADMISSION included.
	v.Entry, v.Admission = entry, admission
	if attempts > 0 {
		v.Rate = float64(v.Total) / float64(attempts)
		v.EntryRate = float64(entry) / float64(attempts)
		v.AdmissionRate = float64(admission) / float64(attempts)
	}
	v.Degraded = (v.Total > 0 && v.Rate > threshold) || (admission > 0 && v.AdmissionRate > threshold)
	return v, nil
}
