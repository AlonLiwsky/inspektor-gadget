// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"
)

// Product command result codes (G019 M4 design section 13.6). Every
// authenticated product command returns one of these.
const (
	sharedProductOK         = 0
	sharedProductRetry      = 1 // retryable / not found (adopt_task: tid vanished)
	sharedProductRefused    = 2 // refused; terminal for this adoption
	sharedProductLatched    = 3 // route latched (reserved, unresolved sources)
	sharedProductReused     = 4 // cgroup of a withdrawn route
	sharedProductAuthFailed = 5 // authentication refused; no state change
	// sharedProductRecycleUnclean (recycle only): the route is FREE but its
	// cleanup could not run. Fail-closed: the slot stays occupied and the
	// recycle is retried; the slot is never reused on this code.
	sharedProductRecycleUnclean = 6
	// sharedProductUnarmed (route_publish, adopt_verify): the image's
	// configuration is not installed, so its hooks are not armed; nothing
	// changed. A terminal control fault, never retried (G019 chain14).
	sharedProductUnarmed = 7
)

// sharedProductStuckAfter is how long a quarantined Strict slot may wait for
// its cgroup to empty before the node reports AdoptionStuck (user decision).
const sharedProductStuckAfter = 30 * time.Second

// Adoption refusal reasons (design sections 13.6, 13.9). Each is a counted,
// reported fail-closed container start refusal.
const (
	AdoptionRefusedIdentity    = "AdoptionIdentity"     // pass 1: tgid/leader/mntns/cgroup/quota
	AdoptionRefusedTask        = "AdoptionTaskRefused"  // adopt_task refused a present task
	AdoptionThreadExited       = "AdoptionThreadExited" // finish: iterated != adopted or exiting
	AdoptionCloneRefused       = "AdoptionCloneRefused" // finish: a fork/clone was refused while adopting
	AdoptionRefusedFinish      = "AdoptionFinishRefused"
	AdoptionRefusedAuth        = "AdoptionAuthentication"
	AdoptionRefusedDeadline    = "AdoptionDeadline"
	AdoptionRefusedQuarantined = "AdoptionQuarantineIncomplete"
)

// AdoptionStuck is the Degraded report of a quarantined Strict slot whose
// cgroup has not emptied sharedProductStuckAfter after the refusal (counted
// once per slot).
const AdoptionStuck = "AdoptionStuck"

// PublishUnconfirmed is the Degraded report of a first publication whose
// outcome could not be confirmed (review M2): the slot is latched, its route
// never withdrawn or reused before node teardown.
const PublishUnconfirmed = "PublishUnconfirmed"

// MigratedAfterRelease is the Degraded report of a refused Strict adoption
// whose cgroup held tasks again right after its route was withdrawn: a task
// migrated in between the empty poll and the withdrawal, and the WITHDRAWN
// route (UNSELECTED) now allows it unevaluated. The residual cannot be
// closed from userspace (a withdrawal cannot be undone); it is reported,
// sticky until node teardown, and counted.
const MigratedAfterRelease = "MigratedAfterRelease"

// ErrSharedAdoptionRefused is the typed refusal of a first publication whose
// root-task adoption did not complete. Every refusal is counted and
// reported (Degraded).
//
// Strict (Audit false): the container start MUST fail (fail-closed).
// Audit (Audit true): the route is withdrawn and the binding is unbound,
// but the start MUST NOT fail: Audit never blocks a workload (design 6).
// The NRI caller decides with errors.As and Audit.
type ErrSharedAdoptionRefused struct {
	Reason string
	Slot   uint32
	Cgroup uint64
	Audit  bool
	Err    error
}

func (e *ErrSharedAdoptionRefused) Error() string {
	class := "Strict"
	if e.Audit {
		class = "Audit"
	}
	return fmt.Sprintf("%s adoption refused (%s) on slot %d cgroup %d: %v", class, e.Reason, e.Slot, e.Cgroup, e.Err)
}

func (e *ErrSharedAdoptionRefused) Unwrap() error { return e.Err }

// sharedFinishDetail is what finish reports besides its code: the per-slot
// counts that distinguish the refusal reasons.
type sharedFinishDetail struct {
	Iterated, Adopted, AdoptingFaults uint64
	Exiting                           bool
	// Bad counts the iterated tasks finish refused (exiting, not adopted,
	// or another TASK); ExitingCount those of them already exiting.
	Bad, ExitingCount uint64
}

// sharedProductCommander issues the typed product commands on the node's
// admin thread. Its implementation owns the BPF request layouts (M4 B2-B5);
// the publisher below only sequences them.
type sharedProductCommander interface {
	publishFirst(ctx context.Context, slot uint32, cgroup uint64, policy SharedBindingPolicy, init SharedInitIdentity) (uint32, error)
	revise(ctx context.Context, slot uint32, cgroup uint64, policy SharedBindingPolicy) (uint32, error)
	// verify runs pass 1; on a refusal, threadExited reports that the only
	// mismatches were tasks already exiting (state.exiting == state.bad).
	verify(ctx context.Context, slot uint32, cgroup uint64, init SharedInitIdentity) (code uint32, threadExited bool, err error)
	adoptTask(ctx context.Context, slot uint32, cgroup uint64, tid uint32, init SharedInitIdentity) (uint32, error)
	finish(ctx context.Context, slot uint32, cgroup uint64) (uint32, sharedFinishDetail, error)
	// quarantine marks every adopted entry of the slot in one BPF run
	// (design 13.6) and reports the counts; Complete is false when at least
	// one entry could not be marked.
	quarantine(ctx context.Context, slot uint32, cgroup uint64) (sharedQuarantineResult, error)
	withdraw(ctx context.Context, slot uint32, cgroup uint64) (uint32, error)
	recycle(ctx context.Context, slot uint32) (uint32, error)
	route(slot uint32) (SharedRouteState, error)
	// adopting reads the kernel route anchor's adopting marker and class.
	adopting(slot uint32) (adopting bool, class uint32, err error)
}

// SharedAdoptionStatus is the reported (Degraded) state of one slot's
// adoption failure, from the refusal until the slot is recycled.
type SharedAdoptionStatus struct {
	Reason      string
	Slot        uint32
	Cgroup      uint64
	InitTGID    uint32
	Audit       bool
	Stuck       bool // AdoptionStuck: cgroup not empty sharedProductStuckAfter after the refusal
	Quarantined bool
	// Failed: the quarantine stayed incomplete (AdoptionQuarantineIncomplete).
	// The route then stays latched until node teardown; it is never
	// withdrawn or recycled.
	Failed bool
	// Marked, Missed and Gone are the last quarantine run's counts: entries
	// marked, entries found but not marked (incomplete), and entries whose
	// TASK was already gone (nothing left to mark; not incomplete).
	Marked, Missed, Gone uint32
}

// sharedQuarantineResult is one quarantine run's outcome. Complete is false
// only when an entry was found but could not be marked (Missed); a TASK that
// is gone (Gone) has nothing left to mark (lead decision I-3).
type sharedQuarantineResult struct {
	Complete                  bool
	Quarantined, Missed, Gone uint32
}

// sharedQuarantineAttempts bounds the quarantine retries of one failed
// adoption: an entry missed three times is reported, not retried forever.
const sharedQuarantineAttempts = 3

// productRoutePublisher implements SharedRoutePublisher over the product
// commands, including root-task adoption on a first publication (design
// section 4.0): publish(first, adopting) -> verify -> adopt_task per tid,
// leader first -> finish; any failure quarantines every adopted entry and
// fails the start. Strict then keeps the route latched until the cgroup is
// empty (polled; AdoptionStuck after 30 s), Audit withdraws at once.
type productRoutePublisher struct {
	cmd sharedProductCommander
	// threads lists the init-namespace tids of the slot's cgroup
	// (cgroup.threads); errCgroupGone when the cgroup no longer exists.
	threads func(slot uint32) ([]uint32, error)
	// now and sleep are clock seams for the stuck-slot poll.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error

	mu     sync.Mutex
	status map[uint32]*SharedAdoptionStatus
	// migrated are the MigratedAfterRelease reports, kept (Degraded) until
	// node teardown: the slot itself is recycled and may be reused.
	migrated []SharedAdoptionStatus
	// onReleased (setOnReleased) is called after the poller recycled a
	// refused adoption's slot, before its report is cleared.
	onReleased func(slot uint32, cgroup uint64)
	// counts are the per-node refusal counters, by reason (plus
	// AdoptionStuck), never reset.
	counts  map[string]uint64
	pollers sync.WaitGroup
	cancel  context.CancelFunc
	pollCtx context.Context
}

// errCgroupGone: the slot's cgroup no longer exists (it is therefore empty).
var errCgroupGone = errors.New("cgroup gone")

func newProductRoutePublisher(cmd sharedProductCommander, threads func(uint32) ([]uint32, error)) *productRoutePublisher {
	ctx, cancel := context.WithCancel(context.Background())
	return &productRoutePublisher{
		cmd: cmd, threads: threads, now: time.Now,
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		status: map[uint32]*SharedAdoptionStatus{}, counts: map[string]uint64{}, pollCtx: ctx, cancel: cancel,
	}
}

func (p *productRoutePublisher) Publish(ctx context.Context, slot uint32, cgroup uint64, policy SharedBindingPolicy, first bool, init SharedInitIdentity) (SharedRouteState, error) {
	if !first {
		code, err := p.cmd.revise(ctx, slot, cgroup, policy)
		if err == nil && code == sharedProductRefused {
			// G019 limit (review L-6, pkgB m1fix): a revision keeps the
			// binding's policy UID, execution class and root role, and its
			// staged object must match the request. Terminal, never retried.
			// A class change (gap 6, accepted) is named explicitly: the
			// kernel route's frozen class differs from the request's.
			if route, rerr := p.cmd.route(slot); rerr == nil && (route.Class == sharedClassAudit || route.Class == sharedClassStrict) && route.Class != policy.Class {
				return SharedRouteState{}, fmt.Errorf("revise: refused: %w", sharedClassChangeError(slot, route.Class, policy.Class))
			}
			return SharedRouteState{}, fmt.Errorf("revise: refused: the revision changes the policy UID, class, root role or root epoch, or its staged object does not match: %w", ErrSharedNativeUnavailable)
		}
		if err := sharedProductCodeError("revise", code, err); err != nil {
			return SharedRouteState{}, err
		}
		return p.cmd.route(slot)
	}
	if init.TGID == 0 || init.StartTicks == 0 || init.MountNS == 0 {
		return SharedRouteState{}, &ErrSharedAdoptionRefused{Reason: AdoptionRefusedIdentity, Slot: slot, Cgroup: cgroup, Err: fmt.Errorf("incomplete init identity %+v", init)}
	}
	code, err := p.cmd.publishFirst(ctx, slot, cgroup, policy, init)
	if errors.Is(err, errSharedPublishUnknown) {
		p.mu.Lock()
		p.status[slot] = &SharedAdoptionStatus{Reason: PublishUnconfirmed, Slot: slot, Cgroup: cgroup, InitTGID: init.TGID, Audit: policy.Class == 1, Failed: true}
		p.counts[PublishUnconfirmed]++
		p.mu.Unlock()
		return SharedRouteState{}, fmt.Errorf("publish: slot %d latched until node teardown: %w", slot, err)
	}
	if err == nil && code == sharedProductRefused {
		// The kernel compares the policy UID, init_role, mode and root epoch
		// (0 in a shared object) with the staged object; Go always sends
		// the compiled values, so a refusal means a forged or stale
		// request, not an adoption failure.
		return SharedRouteState{}, fmt.Errorf("publish: refused (policy UID, init role, mode or epoch differs from the staged object: forged or stale request): %w", ErrSharedNativeUnavailable)
	}
	if err := sharedProductCodeError("publish", code, err); err != nil {
		return SharedRouteState{}, err
	}
	// From here the route is ACTIVE with adopting set: every outcome other
	// than a completed finish quarantines and fails the start.
	reason, cause := p.adopt(ctx, slot, cgroup, policy, init)
	if reason == "" {
		return p.cmd.route(slot)
	}
	return SharedRouteState{}, p.fail(slot, cgroup, policy, init, reason, cause)
}

// adopt runs passes 1-3; "" means adopted.
func (p *productRoutePublisher) adopt(ctx context.Context, slot uint32, cgroup uint64, policy SharedBindingPolicy, init SharedInitIdentity) (string, error) {
	code, exited, err := p.cmd.verify(ctx, slot, cgroup, init)
	if err == nil && code == sharedProductRefused && exited {
		return AdoptionThreadExited, fmt.Errorf("pass 1 found only exiting tasks of the init")
	}
	if reason, cause := sharedAdoptionStep(code, err, AdoptionRefusedIdentity); reason != "" {
		return reason, cause
	}
	tids, err := p.threads(slot)
	if err != nil {
		return AdoptionRefusedIdentity, err
	}
	for _, tid := range sharedLeaderFirst(tids, init.TGID) {
		if err := ctx.Err(); err != nil {
			return AdoptionRefusedDeadline, err
		}
		if tid == 0 {
			return AdoptionRefusedIdentity, fmt.Errorf("tid 0")
		}
		code, err := p.cmd.adoptTask(ctx, slot, cgroup, tid, init)
		if code == sharedProductRetry && err == nil {
			continue // vanished: finish's count rule decides
		}
		if reason, cause := sharedAdoptionStep(code, err, AdoptionRefusedTask); reason != "" {
			return reason, cause
		}
	}
	if err := ctx.Err(); err != nil {
		return AdoptionRefusedDeadline, err
	}
	code, detail, err := p.cmd.finish(ctx, slot, cgroup)
	if err == nil && code == sharedProductRefused {
		switch {
		case detail.AdoptingFaults > 0:
			return AdoptionCloneRefused, fmt.Errorf("%d fork/exec attempts refused while adopting", detail.AdoptingFaults)
		// A thread that exited mid-adoption: every refused task is an
		// exiting one, and something exited (an exiting task, or an adopted
		// task no longer iterated). A task that appeared unadopted, or any
		// other mismatch, is a generic finish refusal (review M1). Known
		// limitation: Iterated < Adopted also matches an adopted task that
		// migrated out of the cgroup; it is reported as ThreadExited. Still a
		// refusal (fail-closed), only the reason may be imprecise.
		case detail.Bad == detail.ExitingCount && (detail.ExitingCount > 0 || detail.Iterated < detail.Adopted):
			return AdoptionThreadExited, fmt.Errorf("finish counted %d tasks, adopted %d (%d exiting)", detail.Iterated, detail.Adopted, detail.ExitingCount)
		}
	}
	return sharedAdoptionStep(code, err, AdoptionRefusedFinish)
}

// sharedAdoptionStep maps a command result to a refusal reason ("" = ok).
func sharedAdoptionStep(code uint32, err error, refused string) (string, error) {
	switch {
	case err != nil:
		return refused, err
	case code == sharedProductOK:
		return "", nil
	case code == sharedProductAuthFailed:
		return AdoptionRefusedAuth, fmt.Errorf("product command authentication refused")
	case code == sharedProductUnarmed:
		return refused, fmt.Errorf("hooks not armed (image configuration not installed): %w", ErrSharedNativeUnavailable)
	}
	return refused, fmt.Errorf("product command returned %d", code)
}

// fail quarantines every adopted entry, records the reported status and
// arranges the route's release: Audit withdraws now, Strict stays latched
// until the cgroup is empty. A quarantine still incomplete after
// sharedQuarantineAttempts marks the slot failed: its route then stays
// latched until node teardown (never withdrawn or recycled, in either mode,
// so the missed entries cannot outlive their route) and the node reports
// Degraded with the counts.
func (p *productRoutePublisher) fail(slot uint32, cgroup uint64, policy SharedBindingPolicy, init SharedInitIdentity, reason string, cause error) error {
	// Never under the caller's (possibly expired) context: an accepted
	// adoption failure must always quarantine.
	ctx := context.WithoutCancel(p.pollCtx)
	var last sharedQuarantineResult
	for range sharedQuarantineAttempts {
		result, err := p.cmd.quarantine(ctx, slot, cgroup)
		if err != nil {
			cause = errors.Join(cause, fmt.Errorf("quarantine: %w", err))
			continue
		}
		last = result
		if result.Complete {
			break
		}
	}
	audit := policy.Class == 1
	st := &SharedAdoptionStatus{
		Reason: reason, Slot: slot, Cgroup: cgroup, InitTGID: init.TGID, Audit: audit,
		Quarantined: last.Complete, Marked: last.Quarantined, Missed: last.Missed, Gone: last.Gone,
	}
	if !last.Complete {
		st.Reason, st.Failed = AdoptionRefusedQuarantined, true
		cause = errors.Join(cause, fmt.Errorf("quarantine incomplete after %d attempts (%s): marked %d, missed %d, gone %d",
			sharedQuarantineAttempts, reason, last.Quarantined, last.Missed, last.Gone))
	}
	p.mu.Lock()
	p.status[slot] = st
	p.counts[reason]++
	if st.Failed {
		p.counts[AdoptionRefusedQuarantined]++
	}
	p.mu.Unlock()
	if !st.Failed {
		p.pollers.Add(1)
		go func() {
			defer p.pollers.Done()
			// Strict: latched (every claim faults) until the cgroup is
			// empty; a WITHDRAWN route would allow (UNSELECTED), so a
			// teardown that ends the poll first never withdraws it.
			if audit || p.pollEmpty(slot) {
				p.release(ctx, slot, cgroup)
			}
		}()
	}
	return &ErrSharedAdoptionRefused{Reason: st.Reason, Slot: slot, Cgroup: cgroup, Audit: audit, Err: cause}
}

// pollEmpty waits, keeping a quarantined Strict route latched, until the
// slot's cgroup is empty, reporting AdoptionStuck after
// sharedProductStuckAfter (the report clears with the release).
func (p *productRoutePublisher) pollEmpty(slot uint32) bool {
	start := p.now()
	for {
		tids, err := p.threads(slot)
		if errors.Is(err, errCgroupGone) || (err == nil && len(tids) == 0) {
			return true
		}
		if p.now().Sub(start) >= sharedProductStuckAfter {
			p.mu.Lock()
			if st := p.status[slot]; st != nil && !st.Stuck {
				st.Stuck = true
				p.counts[AdoptionStuck]++
			}
			p.mu.Unlock()
		}
		if p.sleep(p.pollCtx, time.Second) != nil {
			return false // node teardown: the collection is destroyed latched
		}
	}
}

// release withdraws the slot's route (retrying transient claims), then
// recycles it once its TASK account drained (recycle CONTENDED retries).
// The slot stays reported until the recycle succeeds; a latched or failed
// step leaves it reported until node teardown destroys the collection.
func (p *productRoutePublisher) release(ctx context.Context, slot uint32, cgroup uint64) {
	p.mu.Lock()
	owned := p.status[slot] // the report this poller releases
	p.mu.Unlock()
	migrated := false // one MigratedAfterRelease report per release
	for k, step := range []func() (uint32, error){
		func() (uint32, error) { return p.cmd.withdraw(ctx, slot, cgroup) },
		func() (uint32, error) { return p.cmd.recycle(ctx, slot) },
	} {
		if k == 1 {
			var live bool
			if migrated, live = p.watchMigratedAfterRelease(slot, owned); !live {
				return // node teardown: the collection is destroyed latched
			}
		}
		for {
			if k == 1 && !migrated {
				// The check before every recycle attempt.
				migrated = p.checkMigratedAfterRelease(slot, owned)
			}
			code, err := step()
			// Retry while contended; recycle UNCLEAN (6) keeps the slot
			// occupied and retries too, it is never reused on 6.
			if err != nil || (code != sharedProductOK && code != sharedProductRetry && code != sharedProductRecycleUnclean) {
				return
			}
			if code == sharedProductOK {
				break
			}
			if p.sleep(p.pollCtx, time.Second) != nil {
				return
			}
		}
	}
	// The node first marks the account released (so a Remove racing this
	// never attempts a withdrawal of the recycled route), then the report
	// is cleared. Only this poller's own report is cleared: once the slot
	// is freed a new binding may already have a report of its own.
	p.mu.Lock()
	released := p.onReleased
	p.mu.Unlock()
	if released != nil {
		released(slot, cgroup)
	}
	p.mu.Lock()
	if p.status[slot] == owned {
		delete(p.status, slot)
	}
	p.mu.Unlock()
}

// sharedMigratedRereads reads of a withdrawn Strict slot's cgroup, spread
// evenly over sharedMigratedWindow, follow the withdrawal (G020 carryover:
// one read missed a task that migrated in a moment after it).
const (
	sharedMigratedRereads = 3
	sharedMigratedWindow  = 250 * time.Millisecond
)

// watchMigratedAfterRelease re-reads a withdrawn Strict slot's cgroup
// sharedMigratedRereads times over sharedMigratedWindow (at 0, 125 and
// 250 ms), stopping at the first report (reported). live is false only on
// node teardown.
func (p *productRoutePublisher) watchMigratedAfterRelease(slot uint32, owned *SharedAdoptionStatus) (reported, live bool) {
	for i := range sharedMigratedRereads {
		if i > 0 && p.sleep(p.pollCtx, sharedMigratedWindow/(sharedMigratedRereads-1)) != nil {
			return false, false
		}
		if p.checkMigratedAfterRelease(slot, owned) {
			return true, true
		}
	}
	return false, true
}

// checkMigratedAfterRelease re-reads a withdrawn Strict slot's cgroup once:
// the empty poll and the withdrawal are not atomic, so a task can migrate in
// between and then run under the WITHDRAWN (allowing) route. A non-empty or
// unreadable (not gone) cgroup is reported MigratedAfterRelease (sticky;
// the caller reports a release at most once) and true is returned.
func (p *productRoutePublisher) checkMigratedAfterRelease(slot uint32, owned *SharedAdoptionStatus) bool {
	if owned == nil || owned.Audit {
		return false // Audit withdraws at once by design: its tasks are allowed anyway
	}
	tids, err := p.threads(slot)
	if errors.Is(err, errCgroupGone) || (err == nil && len(tids) == 0) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := *owned
	st.Reason, st.Stuck = MigratedAfterRelease, false
	p.migrated = append(p.migrated, st)
	p.counts[MigratedAfterRelease]++
	return true
}

// setOnReleased installs the node's callback for a slot whose refused
// adoption (on cgroup) the poller withdrew and recycled.
func (p *productRoutePublisher) setOnReleased(fn func(slot uint32, cgroup uint64)) {
	p.mu.Lock()
	p.onReleased = fn
	p.mu.Unlock()
}

// adoptionStatus reports the slot's adoption failure, if any.
func (p *productRoutePublisher) adoptionStatus(slot uint32) (SharedAdoptionStatus, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.status[slot]
	if st == nil {
		return SharedAdoptionStatus{}, false
	}
	return *st, true
}

// Withdraw is the binding's own withdrawal (Remove). It never withdraws a
// slot whose adoption failed: only that slot's poller releases it (Strict
// once the cgroup is empty, Audit at once, never when the quarantine was
// incomplete), because a WITHDRAWN route is UNSELECTED, which allows every
// remaining task. Such a slot reports ErrSharedNativeUnavailable (withdraw
// pending). As a second guard it refuses whenever the kernel anchor still
// holds a Strict route with adopting set.
//
// No race with the poller: status is set by fail() inside Publish and
// removed only by the poller after its recycle, and the binding serializes
// its Publish and Withdraw (account lock), so a slot without status here has
// no poller.
func (p *productRoutePublisher) Withdraw(ctx context.Context, slot uint32, cgroup uint64) error {
	p.mu.Lock()
	st := p.status[slot]
	p.mu.Unlock()
	if st != nil && st.Cgroup == cgroup { // a report of this cgroup's refused adoption
		return fmt.Errorf("withdraw slot %d: adoption refused (%s), released only by its poller: %w", slot, st.Reason, ErrSharedNativeUnavailable)
	}
	adopting, class, err := p.cmd.adopting(slot)
	if err != nil {
		return fmt.Errorf("withdraw slot %d: route unreadable: %w: %w", slot, err, ErrSharedNativeUnavailable)
	}
	if adopting && class == 2 {
		return fmt.Errorf("withdraw slot %d: Strict route still adopting: %w", slot, ErrSharedNativeUnavailable)
	}
	code, err := p.cmd.withdraw(ctx, slot, cgroup)
	return sharedProductCodeError("withdraw", code, err)
}

// errSharedRecycleContended: a withdrawn route's recycle is refused while
// TASK credits of that route are still held; retry later.
var errSharedRecycleContended = errors.New("route recycle contended")

// Recycle frees a withdrawn slot once its TASK account drained (G4). It is
// refused for a slot whose adoption failed: that slot's poller recycles it.
func (p *productRoutePublisher) Recycle(ctx context.Context, slot uint32, cgroup uint64) error {
	p.mu.Lock()
	st := p.status[slot]
	p.mu.Unlock()
	if st != nil && st.Cgroup == cgroup {
		return fmt.Errorf("recycle slot %d: adoption refused (%s), released only by its poller: %w", slot, st.Reason, ErrSharedNativeUnavailable)
	}
	code, err := p.cmd.recycle(ctx, slot)
	if err == nil && (code == sharedProductRetry || code == sharedProductRecycleUnclean) {
		return errSharedRecycleContended // keep the slot occupied, retry
	}
	return sharedProductCodeError("recycle", code, err)
}

// adoptionReport returns every reported slot (MigratedAfterRelease reports
// included) and the per-node counters.
func (p *productRoutePublisher) adoptionReport() ([]SharedAdoptionStatus, map[string]uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	slots := make([]SharedAdoptionStatus, 0, len(p.status)+len(p.migrated))
	for _, st := range p.status {
		slots = append(slots, *st)
	}
	slots = append(slots, p.migrated...)
	slices.SortFunc(slots, func(a, b SharedAdoptionStatus) int { return cmp.Compare(a.Slot, b.Slot) })
	return slots, maps.Clone(p.counts)
}

func (p *productRoutePublisher) Route(slot uint32) (SharedRouteState, error) {
	return p.cmd.route(slot)
}

// Close stops the stuck-slot pollers. Latched slots are destroyed with the
// collection.
func (p *productRoutePublisher) Close() error {
	p.cancel()
	p.pollers.Wait()
	return nil
}

// sharedLeaderFirst orders tids with the init leader first, without
// duplicates.
func sharedLeaderFirst(tids []uint32, leader uint32) []uint32 {
	out := make([]uint32, 0, len(tids))
	seen := map[uint32]bool{}
	for _, tid := range tids {
		if tid == leader && !seen[tid] {
			out = append(out, tid)
			seen[tid] = true
		}
	}
	for _, tid := range tids {
		if !seen[tid] {
			out = append(out, tid)
			seen[tid] = true
		}
	}
	return out
}

// sharedProductCodeError maps a non-adoption command result.
func sharedProductCodeError(op string, code uint32, err error) error {
	switch {
	case err != nil:
		return fmt.Errorf("%s: %w", op, err)
	case code == sharedProductOK:
		return nil
	case code == sharedProductRetry:
		return fmt.Errorf("%s: %w", op, ErrSharedRetryableRefusal)
	case code == sharedProductLatched:
		return fmt.Errorf("%s: route latched: %w", op, ErrSharedNativeUnavailable)
	case code == sharedProductReused:
		return fmt.Errorf("%s: %w", op, ErrSharedBindingWithdrawn)
	case code == sharedProductAuthFailed:
		return fmt.Errorf("%s: product command authentication refused", op)
	case code == sharedProductUncertain:
		return fmt.Errorf("%s: %w (reconciled by INSPECT)", op, errSharedImageUncertain)
	case code == sharedProductImage:
		return fmt.Errorf("%s: the image handle is not a sealed set of the binding: %w: %w", op, ErrSharedImageIndexUnavailable, ErrSharedRetryableRefusal)
	case code == sharedProductUnarmed:
		// Reachable only on a test-gate twin: on a product object an
		// unarmed image already fails authentication (code 5), which
		// requires se_profile_matches (review L2).
		return fmt.Errorf("%s: hooks not armed (image configuration not installed): %w", op, ErrSharedNativeUnavailable)
	}
	return fmt.Errorf("%s: product command returned %d", op, code)
}
