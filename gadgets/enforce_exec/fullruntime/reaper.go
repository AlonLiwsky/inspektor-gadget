// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// G019 M1 event-driven product reaper for the exec verdict candidate
// (bpf/opaque_real_owner_child_candidate.bpf.c, built with
// ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE).
//
// BPF emits a compact (cookie, slot, kind) wakeup into the ringbuf
// opaque_real_reap_events when one exact charge becomes terminal: TASK DEAD
// (lsm/task_free, or tp_btf/sched_process_exit with
// ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE), WORK DONE, WORK ABORTED
// and TASK ABORTED. TASK FREED (credit at exit only) is a witness that a task
// settled at exit reached task_free; it is counted (ReaperStats.Freed) and
// never visited. A wakeup is a
// hint, never authority. The reaper re-reads the exact phase and cookie,
// and the reap command (the syscall program opaque_real_reap, run with
// BPF_PROG_TEST_RUN) refuses anything not yet terminal; a refusal means
// "not yet", never an error. A lost wakeup (ringbuf full, counted in
// opaque_real_reap_event_drops) only delays the reap to the fallback sweep,
// a bounded scan of every charge slot, every ReaperConfig.Sweep (50 ms).
//
// A reap fault (a fault code, or progress beyond reapMaxSteps) is confined
// to its exact charge: that (kind, slot, cookie) is quarantined, never
// visited again until the slot carries another cookie, counted
// (ReaperStats.Faulted) and reported Degraded. Its credit stays charged, so
// the slot is lost fail-closed while every other charge is still reaped.
// Only infrastructure errors stop the reaper: a closed or failing ringbuf,
// a charge or meta map read failure, a failed reap command run, a malformed
// or unknown wakeup, and a hook error.

// ReapKind selects the reap command: one exact step of a WORK or TASK charge.
type ReapKind uint32

const (
	ReapWork ReapKind = 1
	ReapTask ReapKind = 2
)

func (k ReapKind) String() string {
	switch k {
	case ReapWork:
		return "WORK"
	case ReapTask:
		return "TASK"
	}
	return fmt.Sprintf("kind(%d)", uint32(k))
}

// Wakeup kinds emitted by BPF (REAL_OWNER_REAP_*).
const (
	ReapEventTaskDead    = 1
	ReapEventWorkDone    = 2
	ReapEventWorkAborted = 3
	ReapEventTaskAborted = 4
	ReapEventTaskFreed   = 5
)

// Terminal phases (se_owk_meta.phase and se_ol_meta.phase). A WORK is also
// resumable in the reap sequence's own intermediate phases: CLEANING,
// REFUND_PENDING, and META_FREE while its charge and meta still carry the
// cookie (between the meta wipe and the account return). A visit that
// stopped there (a reaper restart, an interrupted synchronous return, a
// stage that answered "not yet") continues from that exact state; each
// stage re-checks it.
const (
	ReapWorkPhaseMetaFree      = 0 // SE_OWK_META_FREE
	ReapWorkPhaseDone          = 4 // SE_OWK_DONE
	ReapWorkPhaseAborted       = 5 // SE_OWK_ABORTED
	ReapWorkPhaseCleaning      = 6 // SE_OWK_CLEANING
	ReapWorkPhaseRefundPending = 7 // SE_OWK_REFUND_PENDING
	ReapTaskPhaseDead          = 2 // SE_OL_DEAD
	ReapTaskPhaseAborted       = 6 // SE_OL_ABORTED
)

// Reap command codes. WORK: se_owk_reap_step; TASK: se_or_task_visit.
const (
	reapWorkProgress = 0 // SE_OWK_PROGRESS
	reapWorkReturned = 1 // SE_OWK_RETURNED
	// The charge no longer carries the cookie (STALE), or it was already
	// returned: nothing of it is left for this cookie.
	reapWorkStale           = 3 // SE_OWK_STALE
	reapWorkAlreadyReturned = 4 // SE_OWK_ALREADY_RETURNED
	reapWorkFault           = 5 // SE_OWK_CORRUPT and above, except:
	// reapWorkClaimHeld: another visitor (the synchronous WORK return,
	// ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE) holds the WORK's
	// visit claim; nothing was touched. That visitor finishes the WORK, or
	// emits a fresh WORK_DONE wakeup when it stops early.
	reapWorkClaimHeld = 6 // SE_OWK_CLAIM_HELD
	reapTaskProgress  = 1 // SE_OR_PROGRESS
	reapTaskReturned  = 2 // SE_OR_RETURNED
	reapTaskFault     = 4 // SE_OR_FAULT and above
	reapMaxSteps      = 32
	// An event-driven reap refused as "not yet" is retried every
	// reapRetryEvery, at most reapRetryLimit times, then left to the sweep.
	reapRetryEvery = time.Millisecond
	reapRetryLimit = 64
)

// ReaperDefaultSweep is the fallback sweep period (user decision, G019).
const ReaperDefaultSweep = 50 * time.Millisecond

// ReapLatencyBuckets are the upper bounds of the reap latency histogram
// (event read -> credit returned); the last bucket is unbounded.
var ReapLatencyBuckets = [...]time.Duration{
	50 * time.Microsecond, 100 * time.Microsecond, 250 * time.Microsecond,
	500 * time.Microsecond, time.Millisecond, 2 * time.Millisecond,
	5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond,
	50 * time.Millisecond, 100 * time.Millisecond,
}

// ReapRecord describes one credit returned by the reaper.
type ReapRecord struct {
	Kind   ReapKind
	Slot   uint32
	Cookie uint64
	// Phase is the terminal phase seen when the reap started.
	Phase uint32
	// Event is true when a ringbuf wakeup led to this reap, false when the
	// fallback sweep found it. Latency is event read -> credit returned
	// (zero for a sweep reap).
	Event   bool
	Latency time.Duration
}

// ReaperHooks lets a caller exclude charges and observe reaps. All hooks run
// on the reaper goroutine; an error stops the reaper with that error.
type ReaperHooks struct {
	// Skip excludes a terminal charge from reaping (for example a retained
	// WORK that a caller still owns).
	Skip func(kind ReapKind, slot uint32, cookie uint64) bool
	// Start runs once when the reap of one exact terminal charge begins.
	Start func(kind ReapKind, slot uint32, cookie uint64, phase uint32) error
	// Returned runs after the reap returned the credit.
	Returned func(ReapRecord)
	// Fault runs when one exact charge is quarantined after a reap fault.
	Fault func(ReapFault)
	// BeforeVisit runs before each event batch and each sweep, before any
	// credit is returned.
	BeforeVisit func() error
}

// ReapFault describes one quarantined charge: its last reap code, and
// whether the fault was progress beyond reapMaxSteps steps of one visit.
type ReapFault struct {
	Kind     ReapKind
	Slot     uint32
	Cookie   uint64
	Code     uint32
	Progress bool
}

func (f ReapFault) String() string {
	what := "fault"
	if f.Progress {
		what = "unbounded progress"
	}
	return fmt.Sprintf("%s slot %d cookie %d: %s (reap code %d)", f.Kind, f.Slot, f.Cookie, what, f.Code)
}

// ReaperConfig configures a Reaper. Zero values select the defaults.
type ReaperConfig struct {
	// Sweep is the fallback sweep period (default ReaperDefaultSweep).
	Sweep time.Duration
	Hooks ReaperHooks
}

// ReaperStats is a snapshot of the reaper counters.
type ReaperStats struct {
	// Events read from the ringbuf, and Drops the BPF witness of wakeups
	// lost to a full ringbuf.
	Events, Drops uint64
	// Sweeps completed, and the credits they returned (each one a missed or
	// early wakeup).
	Sweeps, SweepReaps uint64
	// EventReaps is the credits returned from a wakeup, Retries the refused
	// ("not yet") event visits retried, and Expired the event visits left
	// to the sweep after reapRetryLimit retries.
	EventReaps, Retries, Expired uint64
	// ClaimHeld is the WORK visits that found the visit claim held by the
	// synchronous return, and Settled the WORK visits answered STALE or
	// ALREADY_RETURNED. Both end the visit for that cookie: no retry.
	ClaimHeld, Settled uint64
	// Freed is the TASK FREED witnesses read (credit at exit): counted,
	// never reaped.
	Freed uint64
	// Tasks and Works returned in total.
	Tasks, Works uint64
	// Faulted counts the charges quarantined after a reap fault, and
	// Quarantined the ones still quarantined (their slot still carries the
	// faulted cookie). Any fault makes the reaper Degraded.
	Faulted     uint64
	Quarantined int
	// Latency histogram over ReapLatencyBuckets (+1 unbounded) and the
	// largest event-driven latency.
	Latency    [len(ReapLatencyBuckets) + 1]uint64
	MaxLatency time.Duration
}

// Degraded reports whether any charge faulted since the reaper started: its
// credit stayed charged (fail-closed), so the node lost that slot.
func (s ReaperStats) Degraded() bool {
	return s.Faulted > 0
}

// String renders the counters and the latency histogram.
func (s ReaperStats) String() string {
	out := fmt.Sprintf("events=%d drops=%d sweeps=%d event-reaps=%d sweep-reaps=%d retries=%d expired=%d tasks=%d works=%d freed=%d faulted=%d quarantined=%d claim-held=%d settled=%d max=%s hist=[",
		s.Events, s.Drops, s.Sweeps, s.EventReaps, s.SweepReaps, s.Retries, s.Expired, s.Tasks, s.Works, s.Freed, s.Faulted, s.Quarantined, s.ClaimHeld, s.Settled, s.MaxLatency)
	for i, n := range s.Latency {
		if i > 0 {
			out += " "
		}
		if i < len(ReapLatencyBuckets) {
			out += fmt.Sprintf("<=%s:%d", ReapLatencyBuckets[i], n)
		} else {
			out += fmt.Sprintf(">%s:%d", ReapLatencyBuckets[len(ReapLatencyBuckets)-1], n)
		}
	}
	return out + "]"
}

type reapEvent struct {
	cookie     uint64
	slot, kind uint32
}

// reaperBackend is the kernel surface of the reaper.
type reaperBackend interface {
	// readEvent blocks until a wakeup, the deadline (os.ErrDeadlineExceeded)
	// or close (os.ErrClosed).
	readEvent(deadline time.Time) (reapEvent, error)
	reap(kind ReapKind, slot uint32, cookie uint64) (uint32, error)
	// charge returns the exact charge cookie, meta phase and meta cookie.
	charge(kind ReapKind, slot uint32) (cookie uint64, phase uint32, metaCookie uint64, err error)
	slots(kind ReapKind) uint32
	drops() (uint64, error)
	close() error
}

// Reaper is the per-node product reaper. One Reaper consumes one ringbuf.
type Reaper struct {
	backend reaperBackend
	sweep   time.Duration
	hooks   ReaperHooks
	// owner is the reap command's program ID (owned: set by NewReaper),
	// registered in runningReapers while the reaper runs.
	owner ebpf.ProgramID
	owned bool

	mu    sync.Mutex
	stats ReaperStats

	// Reaper goroutine state.
	started map[reapKey]reapStart
	retry   map[reapKey]reapRetry
	// quarantine holds the faulted cookie of each quarantined charge slot;
	// faults is its copy for Faults, under mu.
	quarantine map[reapKey]uint64
	faults     map[reapKey]ReapFault
	done       chan struct{}
	err        error
}

type reapKey struct {
	kind ReapKind
	slot uint32
}

type reapStart struct {
	cookie uint64
	phase  uint32
}

type reapRetry struct {
	cookie uint64
	// event is when the wakeup was read; at is the next retry.
	event, at time.Time
	tries     int
}

// NewReaper builds a reaper over the reap-event collection: the ringbuf
// opaque_real_reap_events, the drop witness opaque_real_reap_event_drops,
// the syscall program opaque_real_reap and the four charge/meta maps.
//
// Exactly one Reaper may run per collection: BPF relies on it. The
// directory delete stage (se_ow_delete_withdrawn_zero) deletes the key and
// then records DELETED in a non-return group; a second visit of the same
// charge inside that window finds the key gone while the metadata still
// says WITHDRAWN_ZERO (a reap fault), and a key a successor re-created at
// that address in the window could be deleted. Every other step is safe
// under concurrent visits (each re-checks the exact cookie and phase under
// the charge's own claims, and a FREE_PENDING tombstone is retired only by
// the visit that wins its FREE_PENDING -> RETIRING CAS), but the delete
// stage is not, so single-flight is a requirement, not a deployment hint.
// With ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE, BPF itself also
// visits WORK charges (the synchronous WORK return at settle); every WORK
// step, the reaper's and BPF's, then runs under a per-WORK visit claim, and
// a reaper step that finds it held is answered reapWorkClaimHeld. TASK
// steps keep the single-reaper rule.
// It is enforced per process: NewReaper refuses while, and Start refuses
// unless, no other Reaper of this process is running over the same reap
// command (by its kernel program ID), with ErrReaperActive. A reaper in
// another process over a pinned collection is not detected; a BPF-side
// single-owner token for the reap command is future work.
func NewReaper(c *ebpf.Collection, config ReaperConfig) (*Reaper, error) {
	if c == nil {
		return nil, errors.New("reaper: nil collection")
	}
	b := &collectionReaper{program: c.Programs["opaque_real_reap"]}
	maps := map[string]**ebpf.Map{
		"opaque_real_reap_events":      &b.events,
		"opaque_real_reap_event_drops": &b.dropMap,
		"se_opaque_charges":            &b.taskCharges,
		"se_opaque_meta":               &b.taskMeta,
		"se_opaque_work_charges":       &b.workCharges,
		"se_opaque_work_meta":          &b.workMeta,
	}
	for name, field := range maps {
		if *field = c.Maps[name]; *field == nil {
			return nil, fmt.Errorf("reaper: object has no map %s (build with ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE)", name)
		}
	}
	if b.program == nil {
		return nil, errors.New("reaper: object has no program opaque_real_reap (build with ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE)")
	}
	info, err := b.program.Info()
	if err != nil {
		return nil, fmt.Errorf("reaper: opaque_real_reap info: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return nil, errors.New("reaper: opaque_real_reap has no program ID: single-reaper ownership cannot be enforced")
	}
	if reaperRunning(id) {
		return nil, fmt.Errorf("%w (opaque_real_reap program %d)", ErrReaperActive, id)
	}
	reader, err := ringbuf.NewReader(b.events)
	if err != nil {
		return nil, fmt.Errorf("reaper: ringbuf reader: %w", err)
	}
	b.reader = reader
	r := newReaper(b, config)
	r.owner, r.owned = id, true
	return r, nil
}

// ErrReaperActive reports that another Reaper of this process is running over the same
// reap command. At most one may run per collection (see NewReaper).
var ErrReaperActive = errors.New("reaper: another reaper is running for this collection")

// runningReapers holds the reap command program IDs of the running Reapers
// of this process.
var runningReapers = struct {
	sync.Mutex
	ids map[ebpf.ProgramID]bool
}{ids: map[ebpf.ProgramID]bool{}}

func reaperRunning(id ebpf.ProgramID) bool {
	runningReapers.Lock()
	defer runningReapers.Unlock()
	return runningReapers.ids[id]
}

// claim registers r as the running Reaper of its reap command.
func (r *Reaper) claim() error {
	if !r.owned {
		return nil
	}
	runningReapers.Lock()
	defer runningReapers.Unlock()
	if runningReapers.ids[r.owner] {
		return fmt.Errorf("%w (opaque_real_reap program %d)", ErrReaperActive, r.owner)
	}
	runningReapers.ids[r.owner] = true
	return nil
}

func (r *Reaper) unclaim() {
	if !r.owned {
		return
	}
	runningReapers.Lock()
	delete(runningReapers.ids, r.owner)
	runningReapers.Unlock()
}

func newReaper(b reaperBackend, config ReaperConfig) *Reaper {
	if config.Sweep <= 0 {
		config.Sweep = ReaperDefaultSweep
	}
	return &Reaper{
		backend:    b,
		sweep:      config.Sweep,
		hooks:      config.Hooks,
		started:    map[reapKey]reapStart{},
		retry:      map[reapKey]reapRetry{},
		quarantine: map[reapKey]uint64{},
		faults:     map[reapKey]ReapFault{},
	}
}

// Start runs the reaper goroutine until ctx is done or an infrastructure
// error stops it (a reap fault only quarantines its charge). Call Wait for
// its error. Start may be called once. It refuses with ErrReaperActive (and
// closes this reaper's ringbuf reader) while another Reaper of this process
// runs over the same reap command; the claim is released when the reaper
// goroutine ends, before Wait returns.
func (r *Reaper) Start(ctx context.Context) error {
	if r.done != nil {
		return errors.New("reaper: already started")
	}
	if err := r.claim(); err != nil {
		_ = r.backend.close()
		return err
	}
	r.done = make(chan struct{})
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
		}
		_ = r.backend.close()
	}()
	go func() {
		defer close(r.done)
		defer close(stop)
		defer r.unclaim()
		r.err = r.run(ctx)
	}()
	return nil
}

// Wait blocks until the reaper goroutine stopped and returns its error
// (nil after a context cancel).
func (r *Reaper) Wait() error {
	if r.done == nil {
		return errors.New("reaper: not started")
	}
	<-r.done
	return r.err
}

// Stats returns a snapshot of the counters, with Drops read from BPF.
func (r *Reaper) Stats() (ReaperStats, error) {
	drops, err := r.backend.drops()
	r.mu.Lock()
	s := r.stats
	r.mu.Unlock()
	s.Drops = drops
	return s, err
}

// Faults returns the charges quarantined now, in no particular order.
func (r *Reaper) Faults() []ReapFault {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ReapFault, 0, len(r.faults))
	for _, f := range r.faults {
		out = append(out, f)
	}
	return out
}

func (r *Reaper) run(ctx context.Context) error {
	nextSweep := time.Now()
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := time.Now()
		if !now.Before(nextSweep) {
			if err := r.sweepOnce(); err != nil {
				return err
			}
			nextSweep = time.Now().Add(r.sweep)
			continue
		}
		deadline := nextSweep
		for _, p := range r.retry {
			if p.at.Before(deadline) {
				deadline = p.at
			}
		}
		event, err := r.backend.readEvent(deadline)
		switch {
		case err == nil:
			r.count(func(s *ReaperStats) { s.Events++ })
			if err := r.beforeVisit(); err != nil {
				return err
			}
			if err := r.onEvent(event, time.Now()); err != nil {
				return err
			}
		case errors.Is(err, os.ErrDeadlineExceeded):
		case errors.Is(err, os.ErrClosed) || errors.Is(err, ringbuf.ErrClosed):
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("reaper: ringbuf closed: %w", err)
		default:
			return fmt.Errorf("reaper: ringbuf read: %w", err)
		}
		if err := r.retryDue(time.Now()); err != nil {
			return err
		}
	}
}

func (r *Reaper) beforeVisit() error {
	if r.hooks.BeforeVisit == nil {
		return nil
	}
	return r.hooks.BeforeVisit()
}

func (r *Reaper) count(f func(*ReaperStats)) {
	r.mu.Lock()
	f(&r.stats)
	r.mu.Unlock()
}

func (r *Reaper) onEvent(event reapEvent, at time.Time) error {
	var kind ReapKind
	switch event.kind {
	case ReapEventTaskDead, ReapEventTaskAborted:
		kind = ReapTask
	case ReapEventWorkDone, ReapEventWorkAborted:
		kind = ReapWork
	case ReapEventTaskFreed:
		// Witness only: the credit already returned from TASK DEAD.
		r.count(func(s *ReaperStats) { s.Freed++ })
		return nil
	default:
		return fmt.Errorf("reaper: unknown event kind %d (slot %d cookie %d)", event.kind, event.slot, event.cookie)
	}
	if event.slot >= r.backend.slots(kind) || event.cookie == 0 {
		return fmt.Errorf("reaper: malformed %s event slot %d cookie %d", kind, event.slot, event.cookie)
	}
	key := reapKey{kind, event.slot}
	returned, err := r.visit(key, event.cookie, true, at)
	if err != nil || returned || r.quarantined(key, event.cookie) {
		return err
	}
	// Not yet (the source callback still holds the charge): retry shortly.
	r.retry[key] = reapRetry{cookie: event.cookie, event: at, at: time.Now().Add(reapRetryEvery), tries: 1}
	return nil
}

func (r *Reaper) retryDue(now time.Time) error {
	visited := false
	for key, p := range r.retry {
		if now.Before(p.at) {
			continue
		}
		if !visited {
			visited = true
			if err := r.beforeVisit(); err != nil {
				return err
			}
		}
		r.count(func(s *ReaperStats) { s.Retries++ })
		returned, err := r.visit(key, p.cookie, true, p.event)
		if err != nil {
			return err
		}
		if _, pending := r.retry[key]; returned || !pending {
			continue
		}
		switch {
		case p.tries >= reapRetryLimit:
			delete(r.retry, key)
			r.count(func(s *ReaperStats) { s.Expired++ })
		default:
			p.at, p.tries = now.Add(reapRetryEvery), p.tries+1
			r.retry[key] = p
		}
	}
	return nil
}

// sweepOnce visits every WORK slot, then every TASK slot, once.
func (r *Reaper) sweepOnce() error {
	if err := r.beforeVisit(); err != nil {
		return err
	}
	for _, kind := range []ReapKind{ReapWork, ReapTask} {
		for slot := uint32(0); slot < r.backend.slots(kind); slot++ {
			cookie, _, _, err := r.backend.charge(kind, slot)
			if err != nil {
				return fmt.Errorf("reaper: %s charge %d: %w", kind, slot, err)
			}
			key := reapKey{kind, slot}
			if faulted, ok := r.quarantine[key]; ok && faulted != cookie {
				r.release(key)
			}
			if cookie == 0 || r.quarantined(key, cookie) {
				continue
			}
			if _, err := r.visit(reapKey{kind, slot}, cookie, false, time.Time{}); err != nil {
				return err
			}
		}
	}
	r.count(func(s *ReaperStats) { s.Sweeps++ })
	return nil
}

// visit runs the exact reap of one charge if it is terminal under the exact
// cookie. It reports whether this cookie's visit is finished: the credit was
// returned here (counted, Returned hook), or the WORK was settled elsewhere
// (STALE, ALREADY_RETURNED or the visit claim held: counted Settled or
// ClaimHeld, no Returned hook; the synchronous WORK return accounts for the
// WORKs it returns in its own witness). "Not yet" and a quarantined charge
// are false with no error.
func (r *Reaper) visit(key reapKey, cookie uint64, event bool, at time.Time) (bool, error) {
	if r.quarantined(key, cookie) {
		delete(r.retry, key)
		return false, nil
	}
	start, ok := r.started[key]
	if !ok || start.cookie != cookie {
		charge, phase, metaCookie, err := r.backend.charge(key.kind, key.slot)
		if err != nil {
			return false, fmt.Errorf("reaper: %s charge %d: %w", key.kind, key.slot, err)
		}
		if charge != cookie || metaCookie != cookie || !reapTerminal(key.kind, phase) {
			if charge != cookie {
				// Already returned (or reused): nothing left for this wakeup.
				delete(r.retry, key)
			}
			return false, nil
		}
		if r.hooks.Skip != nil && r.hooks.Skip(key.kind, key.slot, cookie) {
			delete(r.retry, key)
			return false, nil
		}
		if r.hooks.Start != nil {
			if err := r.hooks.Start(key.kind, key.slot, cookie, phase); err != nil {
				return false, err
			}
		}
		start = reapStart{cookie: cookie, phase: phase}
		r.started[key] = start
	}
	for step := 0; ; step++ {
		code, err := r.backend.reap(key.kind, key.slot, cookie)
		if err != nil {
			return false, fmt.Errorf("reaper: %s slot %d cookie %d: %w", key.kind, key.slot, cookie, err)
		}
		returned, progress, fault := reapOutcome(key.kind, code)
		if returned {
			r.returned(key, start, event, at)
			return true, nil
		}
		// Final for this cookie: no retry, no restart of the sequence.
		if key.kind == ReapWork && reapWorkFinal(code) {
			delete(r.started, key)
			delete(r.retry, key)
			r.count(func(s *ReaperStats) {
				if code == reapWorkClaimHeld {
					s.ClaimHeld++
				} else {
					s.Settled++
				}
			})
			return true, nil
		}
		if progress && step < reapMaxSteps {
			continue
		}
		if progress || fault {
			r.fault(ReapFault{Kind: key.kind, Slot: key.slot, Cookie: cookie, Code: code, Progress: progress})
		}
		return false, nil
	}
}

func (r *Reaper) quarantined(key reapKey, cookie uint64) bool {
	faulted, ok := r.quarantine[key]
	return ok && faulted == cookie
}

// fault quarantines one exact charge: no further visit until its slot
// carries another cookie. The credit stays charged (fail-closed).
func (r *Reaper) fault(f ReapFault) {
	key := reapKey{f.Kind, f.Slot}
	delete(r.started, key)
	delete(r.retry, key)
	r.quarantine[key] = f.Cookie
	r.count(func(s *ReaperStats) {
		s.Faulted++
		s.Quarantined = len(r.quarantine)
		r.faults[key] = f
	})
	if r.hooks.Fault != nil {
		r.hooks.Fault(f)
	}
}

// release ends a quarantine once the slot no longer carries the faulted
// cookie (the charge was returned by other means, or the slot is reused).
func (r *Reaper) release(key reapKey) {
	delete(r.quarantine, key)
	r.count(func(s *ReaperStats) {
		s.Quarantined = len(r.quarantine)
		delete(r.faults, key)
	})
}

func (r *Reaper) returned(key reapKey, start reapStart, event bool, at time.Time) {
	delete(r.started, key)
	delete(r.retry, key)
	record := ReapRecord{Kind: key.kind, Slot: key.slot, Cookie: start.cookie, Phase: start.phase, Event: event}
	if event {
		record.Latency = time.Since(at)
	}
	r.count(func(s *ReaperStats) {
		if key.kind == ReapTask {
			s.Tasks++
		} else {
			s.Works++
		}
		if !event {
			s.SweepReaps++
			return
		}
		s.EventReaps++
		s.MaxLatency = max(s.MaxLatency, record.Latency)
		i := 0
		for i < len(ReapLatencyBuckets) && record.Latency > ReapLatencyBuckets[i] {
			i++
		}
		s.Latency[i]++
	})
	if r.hooks.Returned != nil {
		r.hooks.Returned(record)
	}
}

func reapTerminal(kind ReapKind, phase uint32) bool {
	if kind == ReapWork {
		// META_FREE qualifies only while the charge and meta still carry
		// the visited cookie, which visit checks before this.
		return phase == ReapWorkPhaseDone || phase == ReapWorkPhaseAborted ||
			phase == ReapWorkPhaseCleaning || phase == ReapWorkPhaseRefundPending ||
			phase == ReapWorkPhaseMetaFree
	}
	return phase == ReapTaskPhaseDead || phase == ReapTaskPhaseAborted
}

// reapWorkFinal reports a WORK reap code that ends the visit of that cookie
// without a fault: STALE, ALREADY_RETURNED, or the visit claim held.
func reapWorkFinal(code uint32) bool {
	return code == reapWorkStale || code == reapWorkAlreadyReturned || code == reapWorkClaimHeld
}

// reapOutcome classifies a reap command code. Neither returned, progress
// nor fault means "not yet": WORK PENDING (WORK codes 3, 4 and 6 are final,
// see reapWorkFinal, and visit handles them first), TASK EMPTY/PENDING.
func reapOutcome(kind ReapKind, code uint32) (returned, progress, fault bool) {
	if kind == ReapWork {
		return code == reapWorkReturned, code == reapWorkProgress, code >= reapWorkFault && code != reapWorkClaimHeld
	}
	return code == reapTaskReturned, code == reapTaskProgress, code >= reapTaskFault
}

// collectionReaper is the kernel backend over one loaded collection.
type collectionReaper struct {
	reader                *ringbuf.Reader
	program               *ebpf.Program
	events, dropMap       *ebpf.Map
	taskCharges, taskMeta *ebpf.Map
	workCharges, workMeta *ebpf.Map
	record                ringbuf.Record
}

func (b *collectionReaper) readEvent(deadline time.Time) (reapEvent, error) {
	b.reader.SetDeadline(deadline)
	if err := b.reader.ReadInto(&b.record); err != nil {
		return reapEvent{}, err
	}
	raw := b.record.RawSample
	if len(raw) < 16 {
		return reapEvent{}, fmt.Errorf("short reap event (%d bytes)", len(raw))
	}
	return reapEvent{
		cookie: binary.LittleEndian.Uint64(raw[0:8]),
		slot:   binary.LittleEndian.Uint32(raw[8:12]),
		kind:   binary.LittleEndian.Uint32(raw[12:16]),
	}, nil
}

func (b *collectionReaper) reap(kind ReapKind, slot uint32, cookie uint64) (uint32, error) {
	command := make([]byte, 16)
	binary.LittleEndian.PutUint64(command[0:8], cookie)
	binary.LittleEndian.PutUint32(command[8:12], slot)
	binary.LittleEndian.PutUint32(command[12:16], uint32(kind))
	return b.program.Run(&ebpf.RunOptions{Context: command})
}

func (b *collectionReaper) charge(kind ReapKind, slot uint32) (uint64, uint32, uint64, error) {
	charges, meta, cookieAt := b.workCharges, b.workMeta, 8
	if kind == ReapTask {
		// se_ol_meta: lock, phase, locator, cookie.
		charges, meta, cookieAt = b.taskCharges, b.taskMeta, 16
	}
	raw, err := charges.LookupBytes(slot)
	if err != nil || len(raw) < 8 {
		return 0, 0, 0, fmt.Errorf("charge: %w (%d bytes)", err, len(raw))
	}
	cookie := binary.LittleEndian.Uint64(raw[:8])
	if cookie == 0 {
		return 0, 0, 0, nil
	}
	m, err := meta.LookupBytes(slot)
	if err != nil || len(m) < cookieAt+8 {
		return 0, 0, 0, fmt.Errorf("meta: %w (%d bytes)", err, len(m))
	}
	return cookie, binary.LittleEndian.Uint32(m[4:8]), binary.LittleEndian.Uint64(m[cookieAt : cookieAt+8]), nil
}

func (b *collectionReaper) slots(kind ReapKind) uint32 {
	if kind == ReapTask {
		return b.taskCharges.MaxEntries()
	}
	return b.workCharges.MaxEntries()
}

func (b *collectionReaper) drops() (uint64, error) {
	var n uint64
	err := b.dropMap.Lookup(uint32(0), &n)
	return n, err
}

func (b *collectionReaper) close() error {
	return b.reader.Close()
}
