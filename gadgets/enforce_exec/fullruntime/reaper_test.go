// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

type fakeReapCharge struct {
	cookie, metaCookie uint64
	phase              uint32
	// pending is how many reap calls still answer "not yet".
	pending int
	// code overrides the reap result when nonzero.
	code uint32
}

type fakeReapBackend struct {
	mu      sync.Mutex
	events  chan reapEvent
	closed  chan struct{}
	once    sync.Once
	charges map[reapKey]*fakeReapCharge
	reaps   map[reapKey]int
	dropped uint64
	// chargeErr and reapErr fail every charge read / reap command.
	chargeErr, reapErr error
}

func (f *fakeReapBackend) setErr(field *error, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	*field = err
}

func newFakeReapBackend() *fakeReapBackend {
	return &fakeReapBackend{
		events:  make(chan reapEvent, 64),
		closed:  make(chan struct{}),
		charges: map[reapKey]*fakeReapCharge{},
		reaps:   map[reapKey]int{},
	}
}

func (f *fakeReapBackend) set(kind ReapKind, slot uint32, c fakeReapCharge) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.charges[reapKey{kind, slot}] = &c
}

func (f *fakeReapBackend) reapCalls(kind ReapKind, slot uint32) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reaps[reapKey{kind, slot}]
}

func (f *fakeReapBackend) readEvent(deadline time.Time) (reapEvent, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-f.closed:
		return reapEvent{}, os.ErrClosed
	case e := <-f.events:
		return e, nil
	case <-timer.C:
		return reapEvent{}, os.ErrDeadlineExceeded
	}
}

func (f *fakeReapBackend) reap(kind ReapKind, slot uint32, cookie uint64) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reapErr != nil {
		return 0, f.reapErr
	}
	key := reapKey{kind, slot}
	f.reaps[key]++
	c := f.charges[key]
	notYet, returned := uint32(2), uint32(reapWorkReturned) // WORK PENDING, RETURNED
	if kind == ReapTask {
		notYet, returned = 3, reapTaskReturned // TASK PENDING, RETURNED
	}
	switch {
	case c == nil || c.cookie != cookie || !reapTerminal(kind, c.phase):
		return notYet, nil
	case c.code != 0:
		return c.code, nil
	case c.pending > 0:
		c.pending--
		return notYet, nil
	}
	delete(f.charges, key)
	return returned, nil
}

func (f *fakeReapBackend) charge(kind ReapKind, slot uint32) (uint64, uint32, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.chargeErr != nil {
		return 0, 0, 0, f.chargeErr
	}
	c := f.charges[reapKey{kind, slot}]
	if c == nil {
		return 0, 0, 0, nil
	}
	return c.cookie, c.phase, c.metaCookie, nil
}

func (f *fakeReapBackend) slots(ReapKind) uint32 { return 8 }

func (f *fakeReapBackend) drops() (uint64, error) { return f.dropped, nil }

func (f *fakeReapBackend) close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

type reapRecorder struct {
	mu      sync.Mutex
	records []ReapRecord
	starts  int
}

func (r *reapRecorder) hooks(skip func(ReapKind, uint32, uint64) bool) ReaperHooks {
	return ReaperHooks{
		Skip: skip,
		Start: func(ReapKind, uint32, uint64, uint32) error {
			r.mu.Lock()
			r.starts++
			r.mu.Unlock()
			return nil
		},
		Returned: func(rec ReapRecord) {
			r.mu.Lock()
			r.records = append(r.records, rec)
			r.mu.Unlock()
		},
	}
}

func (r *reapRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}

func waitReaper(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestReaperEventDrivenReap(t *testing.T) {
	f := newFakeReapBackend()
	rec := &reapRecorder{}
	// A long sweep so only wakeups (and their retries) can reap.
	r := newReaper(f, ReaperConfig{Sweep: time.Hour, Hooks: rec.hooks(nil)})
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// The first sweep runs at start; wait for it before any charge exists.
	waitReaper(t, "first sweep", func() bool { s, _ := r.Stats(); return s.Sweeps == 1 })
	f.set(ReapWork, 1, fakeReapCharge{cookie: 11, metaCookie: 11, phase: ReapWorkPhaseDone})
	f.set(ReapTask, 2, fakeReapCharge{cookie: 22, metaCookie: 22, phase: ReapTaskPhaseDead, pending: 3})
	f.set(ReapWork, 3, fakeReapCharge{cookie: 33, metaCookie: 33, phase: ReapWorkPhaseAborted})
	f.set(ReapTask, 4, fakeReapCharge{cookie: 44, metaCookie: 44, phase: ReapTaskPhaseAborted})
	f.events <- reapEvent{cookie: 11, slot: 1, kind: ReapEventWorkDone}
	f.events <- reapEvent{cookie: 22, slot: 2, kind: ReapEventTaskDead}
	f.events <- reapEvent{cookie: 33, slot: 3, kind: ReapEventWorkAborted}
	f.events <- reapEvent{cookie: 44, slot: 4, kind: ReapEventTaskAborted}
	waitReaper(t, "four reaps", func() bool { return rec.count() == 4 })
	cancel()
	if err := r.Wait(); err != nil {
		t.Fatal(err)
	}
	s, err := r.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.Events != 4 || s.EventReaps != 4 || s.SweepReaps != 0 || s.Tasks != 2 || s.Works != 2 || s.Retries != 3 || s.Expired != 0 {
		t.Fatalf("stats %s", s)
	}
	var hist uint64
	for _, n := range s.Latency {
		hist += n
	}
	if hist != 4 || rec.starts != 4 {
		t.Fatalf("histogram %d samples, %d starts, want 4/4", hist, rec.starts)
	}
	for _, record := range rec.records {
		if !record.Event || record.Latency <= 0 {
			t.Fatalf("record %+v: want an event reap with latency", record)
		}
	}
	if !strings.Contains(s.String(), "event-reaps=4") {
		t.Fatalf("stats string %q", s.String())
	}
}

func TestReaperSweepCoversLostWakeups(t *testing.T) {
	f := newFakeReapBackend()
	f.dropped = 2
	rec := &reapRecorder{}
	// Charge 5 stands for a caller-retained WORK: terminal, but skipped.
	skip := func(kind ReapKind, slot uint32, cookie uint64) bool { return kind == ReapWork && slot == 5 }
	f.set(ReapWork, 0, fakeReapCharge{cookie: 1, metaCookie: 1, phase: ReapWorkPhaseDone})
	f.set(ReapTask, 0, fakeReapCharge{cookie: 2, metaCookie: 2, phase: ReapTaskPhaseDead})
	f.set(ReapWork, 5, fakeReapCharge{cookie: 5, metaCookie: 5, phase: ReapWorkPhaseDone})
	// Not terminal, or a stale metadata cookie: never reaped.
	f.set(ReapWork, 6, fakeReapCharge{cookie: 6, metaCookie: 6, phase: 2})
	f.set(ReapTask, 6, fakeReapCharge{cookie: 7, metaCookie: 7, phase: 1})
	f.set(ReapTask, 7, fakeReapCharge{cookie: 8, metaCookie: 9, phase: ReapTaskPhaseDead})
	r := newReaper(f, ReaperConfig{Sweep: 5 * time.Millisecond, Hooks: rec.hooks(skip)})
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitReaper(t, "two sweep reaps and a later sweep", func() bool { s, _ := r.Stats(); return rec.count() == 2 && s.Sweeps >= 3 })
	cancel()
	if err := r.Wait(); err != nil {
		t.Fatal(err)
	}
	s, _ := r.Stats()
	if s.SweepReaps != 2 || s.EventReaps != 0 || s.Drops != 2 {
		t.Fatalf("stats %s", s)
	}
	for _, slot := range []uint32{5, 6} {
		if n := f.reapCalls(ReapWork, slot); n != 0 {
			t.Fatalf("WORK slot %d reaped %d times, want never", slot, n)
		}
	}
	for _, slot := range []uint32{6, 7} {
		if n := f.reapCalls(ReapTask, slot); n != 0 {
			t.Fatalf("TASK slot %d reaped %d times, want never", slot, n)
		}
	}
}

func TestReaperExpiresRetriesToSweep(t *testing.T) {
	f := newFakeReapBackend()
	r := newReaper(f, ReaperConfig{Sweep: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitReaper(t, "first sweep", func() bool { s, _ := r.Stats(); return s.Sweeps == 1 })
	f.set(ReapTask, 3, fakeReapCharge{cookie: 9, metaCookie: 9, phase: ReapTaskPhaseDead, pending: 1 << 20})
	f.events <- reapEvent{cookie: 9, slot: 3, kind: ReapEventTaskDead}
	waitReaper(t, "expiry", func() bool { s, _ := r.Stats(); return s.Expired == 1 })
	cancel()
	if err := r.Wait(); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.Stats(); s.Retries != reapRetryLimit || s.Tasks != 0 {
		t.Fatalf("stats %s, want %d retries and no reap", s, reapRetryLimit)
	}
}

// TestReaperResumesIntermediateWorkPhases (G019 option C, review C1): a
// WORK left in the reap sequence's own intermediate phases (a reaper
// restart, an interrupted synchronous return) is resumed by the sweep from
// that exact state: CLEANING, REFUND_PENDING, and META_FREE while the
// charge and meta still carry the cookie. A META_FREE slot whose meta no
// longer carries the charge's cookie, or a live phase, is never visited.
func TestReaperResumesIntermediateWorkPhases(t *testing.T) {
	f := newFakeReapBackend()
	f.set(ReapWork, 1, fakeReapCharge{cookie: 11, metaCookie: 11, phase: ReapWorkPhaseCleaning})
	f.set(ReapWork, 2, fakeReapCharge{cookie: 12, metaCookie: 12, phase: ReapWorkPhaseRefundPending})
	f.set(ReapWork, 3, fakeReapCharge{cookie: 13, metaCookie: 13, phase: ReapWorkPhaseMetaFree})
	f.set(ReapWork, 4, fakeReapCharge{cookie: 14, metaCookie: 99, phase: ReapWorkPhaseMetaFree})
	f.set(ReapWork, 5, fakeReapCharge{cookie: 15, metaCookie: 15, phase: 3}) // SE_OWK_ACTIVE
	r := newReaper(f, ReaperConfig{Sweep: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitReaper(t, "first sweep", func() bool { s, _ := r.Stats(); return s.Sweeps == 1 })
	cancel()
	if err := r.Wait(); err != nil {
		t.Fatal(err)
	}
	s, _ := r.Stats()
	if s.SweepReaps != 3 || s.Works != 3 || s.Faulted != 0 {
		t.Fatalf("stats %s, want the 3 intermediate WORKs resumed", s)
	}
	for _, slot := range []uint32{4, 5} {
		if n := f.reapCalls(ReapWork, slot); n != 0 {
			t.Fatalf("WORK slot %d visited %d times, want never", slot, n)
		}
	}
}

// TestReaperWorkFinalCodes (review M3): a WORK reap answered with the visit
// claim held (the synchronous return owns the WORK), STALE or
// ALREADY_RETURNED ends that cookie's visit: no fault, no retry, counted
// ClaimHeld or Settled. A later wakeup (the synchronous return's recovery
// WORK_DONE after it stopped early) visits it again and returns it.
func TestReaperWorkFinalCodes(t *testing.T) {
	f := newFakeReapBackend()
	r := newReaper(f, ReaperConfig{Sweep: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitReaper(t, "first sweep", func() bool { s, _ := r.Stats(); return s.Sweeps == 1 })
	f.set(ReapWork, 1, fakeReapCharge{cookie: 21, metaCookie: 21, phase: ReapWorkPhaseDone, code: reapWorkClaimHeld})
	f.set(ReapWork, 2, fakeReapCharge{cookie: 22, metaCookie: 22, phase: ReapWorkPhaseCleaning, code: reapWorkStale})
	f.set(ReapWork, 3, fakeReapCharge{cookie: 23, metaCookie: 23, phase: ReapWorkPhaseDone, code: reapWorkAlreadyReturned})
	f.events <- reapEvent{cookie: 21, slot: 1, kind: ReapEventWorkDone}
	f.events <- reapEvent{cookie: 22, slot: 2, kind: ReapEventWorkDone}
	f.events <- reapEvent{cookie: 23, slot: 3, kind: ReapEventWorkDone}
	waitReaper(t, "three final visits", func() bool { s, _ := r.Stats(); return s.ClaimHeld == 1 && s.Settled == 2 })
	// The synchronous return stopped early and emitted a recovery wakeup.
	f.mu.Lock()
	f.charges[reapKey{ReapWork, 1}].code = 0
	f.mu.Unlock()
	f.events <- reapEvent{cookie: 21, slot: 1, kind: ReapEventWorkDone}
	waitReaper(t, "recovery reap", func() bool { s, _ := r.Stats(); return s.Works == 1 })
	cancel()
	if err := r.Wait(); err != nil {
		t.Fatal(err)
	}
	s, _ := r.Stats()
	if s.Retries != 0 || s.Expired != 0 || s.Faulted != 0 || s.EventReaps != 1 {
		t.Fatalf("stats %s, want no retry, no fault, one event reap", s)
	}
	if n := f.reapCalls(ReapWork, 1); n != 2 {
		t.Fatalf("WORK slot 1 reaped %d times, want 2 (held, then recovered)", n)
	}
	if !strings.Contains(s.String(), "claim-held=1 settled=2") {
		t.Fatalf("stats string %q", s.String())
	}
}

// TestReaperQuarantinesFault: a reap fault (a fault code, or progress
// beyond reapMaxSteps) quarantines that exact charge only. The reaper keeps
// running and keeps reaping every other charge; the faulted one is never
// visited again (by its wakeup's retries, later wakeups or sweeps) while
// its slot carries that cookie, is counted Faulted and makes the reaper
// Degraded. Once the slot carries another cookie the quarantine ends and
// the new charge is reaped normally.
func TestReaperQuarantinesFault(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kind     ReapKind
		phase    uint32
		event    uint32
		code     uint32
		progress bool
	}{
		{"work fault code", ReapWork, ReapWorkPhaseDone, ReapEventWorkDone, reapWorkFault, false},
		{"work fault code above corrupt", ReapWork, ReapWorkPhaseDone, ReapEventWorkDone, reapWorkFault + 2, false},
		{"task fault code", ReapTask, ReapTaskPhaseDead, ReapEventTaskDead, reapTaskFault, false},
		{"task progress forever", ReapTask, ReapTaskPhaseDead, ReapEventTaskDead, reapTaskProgress, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeReapBackend()
			rec := &reapRecorder{}
			var faults []ReapFault
			hooks := rec.hooks(nil)
			hooks.Fault = func(fault ReapFault) { faults = append(faults, fault) }
			r := newReaper(f, ReaperConfig{Sweep: 5 * time.Millisecond, Hooks: hooks})
			ctx, cancel := context.WithCancel(context.Background())
			if err := r.Start(ctx); err != nil {
				t.Fatal(err)
			}
			waitReaper(t, "first sweep", func() bool { s, _ := r.Stats(); return s.Sweeps >= 1 })
			f.set(tc.kind, 1, fakeReapCharge{cookie: 4, metaCookie: 4, phase: tc.phase, code: tc.code})
			f.set(ReapTask, 2, fakeReapCharge{cookie: 5, metaCookie: 5, phase: ReapTaskPhaseDead})
			f.events <- reapEvent{cookie: 4, slot: 1, kind: tc.event}
			f.events <- reapEvent{cookie: 4, slot: 1, kind: tc.event}
			waitReaper(t, "the fault and the healthy reap", func() bool {
				s, _ := r.Stats()
				return s.Faulted == 1 && rec.count() == 1
			})
			calls := f.reapCalls(tc.kind, 1)
			want := 1
			if tc.progress {
				want = reapMaxSteps + 1
			}
			if calls != want {
				t.Fatalf("%d reap calls of the faulted charge, want %d", calls, want)
			}
			// Several sweeps later: still never visited again.
			waitReaper(t, "three more sweeps", func() bool { s, _ := r.Stats(); return s.Sweeps >= 5 })
			s, _ := r.Stats()
			if got := f.reapCalls(tc.kind, 1); got != calls || s.Faulted != 1 || s.Quarantined != 1 || !s.Degraded() || s.Retries != 0 {
				t.Fatalf("quarantined charge: %d reap calls (want %d), stats %s", got, calls, s)
			}
			if q := r.Faults(); len(q) != 1 || q[0] != (ReapFault{Kind: tc.kind, Slot: 1, Cookie: 4, Code: tc.code, Progress: tc.progress}) ||
				len(faults) != 1 || faults[0] != q[0] || !strings.Contains(q[0].String(), fmt.Sprintf("reap code %d", tc.code)) {
				t.Fatalf("faults %v, hook %v", q, faults)
			}
			// The slot reused by another charge: quarantine released, the
			// new charge reaped; Faulted stays (the node stays Degraded).
			f.set(tc.kind, 1, fakeReapCharge{cookie: 6, metaCookie: 6, phase: tc.phase})
			waitReaper(t, "the new charge reaped", func() bool { return rec.count() == 2 })
			cancel()
			if err := r.Wait(); err != nil {
				t.Fatalf("reaper stopped: %v", err)
			}
			s, _ = r.Stats()
			if s.Faulted != 1 || s.Quarantined != 0 || !s.Degraded() || len(r.Faults()) != 0 || !strings.Contains(s.String(), "faulted=1 quarantined=0") {
				t.Fatalf("after reuse: stats %s, faults %v", s, r.Faults())
			}
		})
	}
}

// TestReaperStopsOnInfrastructureError: errors outside one charge's reap
// still stop the reaper: malformed or unknown wakeups, a failing charge
// read, a failing reap command and a closed ringbuf.
func TestReaperStopsOnInfrastructureError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event *reapEvent
		set   func(*fakeReapBackend)
		want  string
	}{
		{"unknown kind", &reapEvent{cookie: 4, slot: 1, kind: 9}, func(*fakeReapBackend) {}, "unknown event kind"},
		{"slot out of range", &reapEvent{cookie: 4, slot: 8, kind: ReapEventTaskDead}, func(*fakeReapBackend) {}, "malformed"},
		{"zero cookie", &reapEvent{cookie: 0, slot: 1, kind: ReapEventWorkDone}, func(*fakeReapBackend) {}, "malformed"},
		{"charge read failure", nil, func(f *fakeReapBackend) { f.setErr(&f.chargeErr, errors.New("map gone")) }, "map gone"},
		{"reap command failure", &reapEvent{cookie: 4, slot: 1, kind: ReapEventTaskDead}, func(f *fakeReapBackend) {
			f.set(ReapTask, 1, fakeReapCharge{cookie: 4, metaCookie: 4, phase: ReapTaskPhaseDead})
			f.setErr(&f.reapErr, errors.New("prog run failed"))
		}, "prog run failed"},
		{"ringbuf closed", nil, func(f *fakeReapBackend) { _ = f.close() }, "ringbuf closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeReapBackend()
			// Short sweeps: a charge read failure surfaces at the next one.
			r := newReaper(f, ReaperConfig{Sweep: 5 * time.Millisecond})
			if err := r.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitReaper(t, "first sweep", func() bool { s, _ := r.Stats(); return s.Sweeps >= 1 })
			tc.set(f)
			if tc.event != nil {
				f.events <- *tc.event
			}
			err := r.Wait()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
			if s, _ := r.Stats(); s.Faulted != 0 {
				t.Fatalf("infrastructure error counted as a charge fault: %s", s)
			}
		})
	}
}

func TestReaperStartTwice(t *testing.T) {
	r := newReaper(newFakeReapBackend(), ReaperConfig{})
	if r.sweep != ReaperDefaultSweep {
		t.Fatalf("default sweep %s", r.sweep)
	}
	if err := r.Wait(); err == nil {
		t.Fatal("Wait before Start succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx); err == nil {
		t.Fatal("second Start succeeded")
	}
	cancel()
	if err := r.Wait(); err != nil {
		t.Fatal(err)
	}
}

// bpfEnum returns the values of the C enum named name in header (implicit
// values count up from the previous one).
func bpfEnum(t *testing.T, header, name string) map[string]int {
	t.Helper()
	raw, err := os.ReadFile(header)
	if err != nil {
		t.Fatal(err)
	}
	body := regexp.MustCompile(`enum\s+` + name + `\s*\{([^}]*)\}`).FindSubmatch(raw)
	if body == nil {
		t.Fatalf("%s: no enum %s", header, name)
	}
	values, next := map[string]int{}, 0
	for _, item := range strings.Split(string(body[1]), ",") {
		key, value, explicit := strings.Cut(strings.TrimSpace(item), "=")
		if key = strings.TrimSpace(key); key == "" {
			continue
		}
		if explicit {
			if next, err = strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(value), "U")); err != nil {
				t.Fatalf("%s: %s = %q", header, key, value)
			}
		}
		values[key] = next
		next++
	}
	return values
}

// TestReaperBPFConstants pins the Go phases and reap codes to the BPF enums:
// a wrong terminal phase leaves every such charge to nobody (G019 M1 VM:
// ReapTaskPhaseDead was SE_OL_CLEANING, so no DEAD TASK was ever reaped).
func TestReaperBPFConstants(t *testing.T) {
	task := bpfEnum(t, "../full/shared_pool_opaque_lookup_candidate.h", "se_ol_phase")
	work := bpfEnum(t, "../full/shared_pool_opaque_work_candidate.h", "se_owk_phase")
	workReap := bpfEnum(t, "../full/shared_pool_opaque_work_reap_candidate.h", "se_owk_reap_result")
	taskReap := bpfEnum(t, "../full/shared_pool_opaque_reaper_visit_candidate.h", "se_or_visit_result")
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"ReapTaskPhaseDead", ReapTaskPhaseDead, task["SE_OL_DEAD"]},
		{"ReapTaskPhaseAborted", ReapTaskPhaseAborted, task["SE_OL_ABORTED"]},
		{"ReapWorkPhaseDone", ReapWorkPhaseDone, work["SE_OWK_DONE"]},
		{"ReapWorkPhaseAborted", ReapWorkPhaseAborted, work["SE_OWK_ABORTED"]},
		{"ReapWorkPhaseCleaning", ReapWorkPhaseCleaning, work["SE_OWK_CLEANING"]},
		{"ReapWorkPhaseRefundPending", ReapWorkPhaseRefundPending, work["SE_OWK_REFUND_PENDING"]},
		{"ReapWorkPhaseMetaFree", ReapWorkPhaseMetaFree, work["SE_OWK_META_FREE"]},
		{"reapWorkStale", reapWorkStale, workReap["SE_OWK_STALE"]},
		{"reapWorkAlreadyReturned", reapWorkAlreadyReturned, workReap["SE_OWK_ALREADY_RETURNED"]},
		{"reapWorkProgress", reapWorkProgress, workReap["SE_OWK_PROGRESS"]},
		{"reapWorkReturned", reapWorkReturned, workReap["SE_OWK_RETURNED"]},
		{"reapWorkFault", reapWorkFault, workReap["SE_OWK_CORRUPT"]},
		{"reapTaskProgress", reapTaskProgress, taskReap["SE_OR_PROGRESS"]},
		{"reapTaskReturned", reapTaskReturned, taskReap["SE_OR_RETURNED"]},
		{"reapTaskFault", reapTaskFault, taskReap["SE_OR_FAULT"]},
	} {
		// Zero is a valid value only for the enumerators that are 0 in BPF;
		// bpfEnum also yields 0 for a missing name.
		if c.got != c.want || c.want == 0 && !strings.Contains(c.name, "Progress") && c.name != "ReapWorkPhaseMetaFree" {
			t.Errorf("%s = %d, BPF %d", c.name, c.got, c.want)
		}
	}
	// Wakeup kinds (REAL_OWNER_REAP_*); TASK_FREED exists only with
	// ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE.
	raw, err := os.ReadFile("bpf/opaque_real_owner_child_candidate.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := work["SE_OWK_META_FREE"]; !ok {
		t.Error("se_owk_phase lacks SE_OWK_META_FREE")
	}
	// The visit-claim code of the synchronous WORK return.
	if define := fmt.Sprintf("#define SE_OWK_CLAIM_HELD %d\n", reapWorkClaimHeld); !strings.Contains(string(raw), define) {
		t.Errorf("candidate source lacks %q", strings.TrimSpace(define))
	}
	for name, kind := range map[string]int{
		"TASK_DEAD": ReapEventTaskDead, "WORK_DONE": ReapEventWorkDone,
		"WORK_ABORTED": ReapEventWorkAborted, "TASK_ABORTED": ReapEventTaskAborted,
		"TASK_FREED": ReapEventTaskFreed,
	} {
		if define := fmt.Sprintf("#define REAL_OWNER_REAP_%s %d\n", name, kind); !strings.Contains(string(raw), define) {
			t.Errorf("candidate source lacks %q", strings.TrimSpace(define))
		}
	}
}

// TestReaperCountsTaskFreed: a TASK FREED wakeup (credit at exit) is a
// witness only. It is counted and never visited, and it does not stop the
// reaper; a DEAD wakeup of the same slot is still reaped.
func TestReaperCountsTaskFreed(t *testing.T) {
	f := newFakeReapBackend()
	rec := &reapRecorder{}
	r := newReaper(f, ReaperConfig{Sweep: time.Hour, Hooks: rec.hooks(nil)})
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitReaper(t, "first sweep", func() bool { s, _ := r.Stats(); return s.Sweeps == 1 })
	f.set(ReapTask, 2, fakeReapCharge{cookie: 22, metaCookie: 22, phase: ReapTaskPhaseDead})
	f.events <- reapEvent{cookie: 22, slot: 2, kind: ReapEventTaskDead}
	f.events <- reapEvent{cookie: 22, slot: 2, kind: ReapEventTaskFreed}
	// A FREED wakeup of a slot already reused by another charge.
	f.events <- reapEvent{cookie: 7, slot: 2, kind: ReapEventTaskFreed}
	waitReaper(t, "one reap and two freed", func() bool { s, _ := r.Stats(); return rec.count() == 1 && s.Freed == 2 })
	cancel()
	if err := r.Wait(); err != nil {
		t.Fatal(err)
	}
	s, _ := r.Stats()
	if s.Events != 3 || s.Freed != 2 || s.Tasks != 1 || s.EventReaps != 1 || s.Retries != 0 || f.reapCalls(ReapTask, 2) != 1 {
		t.Fatalf("stats %s, %d reap calls", s, f.reapCalls(ReapTask, 2))
	}
	if !strings.Contains(s.String(), "freed=2") {
		t.Fatalf("stats string %q", s.String())
	}
}

// TestReaperVisitSnapshotPins pins the two exactness rules of the TASK visit
// (full/shared_pool_opaque_reaper_visit_candidate.h) in every build that
// includes it: a DEAD charge whose death lease is held, read in the same
// lock section as the stage snapshot, is PENDING before any directory stage
// (the holder runs its own stages), and a CORRUPT stage is a fault only
// when directory_state still equals the snapshot that selected the stage
// (a concurrent visit that completed it first is PENDING). The product
// reap command answers a cookie its charge no longer carries with PENDING.
func TestReaperVisitSnapshotPins(t *testing.T) {
	raw, err := os.ReadFile("../full/shared_pool_opaque_reaper_visit_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	visit := squashSpace(string(raw))
	for _, pin := range []string{
		"__u32 done = meta->cleanup_done;\n\t__u32 leases = meta->active_leases;\n\tint same = meta->cookie == cookie",
		"if (phase == SE_OL_DEAD && leases) {\n#ifdef SE_OR_TASK_HELD\n\t\tSE_OR_TASK_HELD(slot, cookie, locator, leases);\n#endif\n\t\treturn SE_OR_PENDING;\n\t}\n#ifdef SE_OR_TASK_PRE_VISIT",
		"if (result == SE_OL_CONTENDED || result == SE_OL_STALE)\n\t\treturn SE_OR_PENDING;\n\tbpf_spin_lock(&meta->lock);\n" +
			"\tint moved = meta->directory_state != directory;\n\tbpf_spin_unlock(&meta->lock);\n\treturn moved ? SE_OR_PENDING : SE_OR_FAULT;",
	} {
		if !strings.Contains(visit, squashSpace(pin)) {
			t.Errorf("visit header lacks %q", pin)
		}
	}
	// The held check precedes every stage: no directory or archive stage,
	// refund or pre-step appears before it in se_or_task_visit.
	body := visit[strings.Index(visit, "static__attribute__((noinline))intse_or_task_visit(__u32slot)"):]
	held := strings.Index(body, "if(phase==SE_OL_DEAD&&leases){")
	for _, stage := range []string{"SE_OR_TASK_PRE_VISIT(slot,", "se_or_task_terminal_guard(slot,", "se_oc_refund_step(", "se_op_zero_payload(", "se_or_task_directory_step(meta,"} {
		if at := strings.Index(body, stage); held < 0 || at < 0 || at < held {
			t.Errorf("se_or_task_visit: %q at %d, before the held-lease check at %d", stage, at, held)
		}
	}
	raw, err = os.ReadFile("bpf/opaque_real_owner_child_candidate.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	if pin := "if (charge->cookie != cookie)\n\t\treturn SE_OR_PENDING;\n\treturn se_or_task_visit(slot);"; !strings.Contains(squashSpace(string(raw)), squashSpace(pin)) {
		t.Errorf("product reap command lacks %q", pin)
	}
}

// TestReaperSingleOwner: exactly one Reaper may run per reap command (BPF's
// directory delete stage is not safe under two concurrent visits). A second
// Reaper over the same command is refused at Start with ErrReaperActive and
// its backend closed; one over another command runs; once the first one
// stopped (Wait returned), the command can be reaped again.
func TestReaperSingleOwner(t *testing.T) {
	owned := func(id ebpf.ProgramID) (*Reaper, *fakeReapBackend) {
		f := newFakeReapBackend()
		r := newReaper(f, ReaperConfig{Sweep: time.Hour})
		r.owner, r.owned = id, true
		return r, f
	}
	first, _ := owned(7001)
	ctx, cancel := context.WithCancel(context.Background())
	if err := first.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !reaperRunning(7001) {
		t.Fatal("running reaper not registered")
	}
	second, f2 := owned(7001)
	if err := second.Start(context.Background()); !errors.Is(err, ErrReaperActive) {
		t.Fatalf("second reaper over the same command: %v, want ErrReaperActive", err)
	}
	select {
	case <-f2.closed:
	default:
		t.Fatal("refused reaper's backend left open")
	}
	if err := second.Wait(); err == nil {
		t.Fatal("refused reaper reports started")
	}
	other, _ := owned(7002)
	otherCtx, otherCancel := context.WithCancel(context.Background())
	if err := other.Start(otherCtx); err != nil {
		t.Fatalf("reaper over another command: %v", err)
	}
	cancel()
	if err := first.Wait(); err != nil {
		t.Fatal(err)
	}
	if reaperRunning(7001) {
		t.Fatal("stopped reaper still registered after Wait")
	}
	third, _ := owned(7001)
	thirdCtx, thirdCancel := context.WithCancel(context.Background())
	if err := third.Start(thirdCtx); err != nil {
		t.Fatalf("reaper after the first stopped: %v", err)
	}
	thirdCancel()
	otherCancel()
	if err := third.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := other.Wait(); err != nil {
		t.Fatal(err)
	}
	// A reaper stopped by an infrastructure error releases its claim too.
	failing, f := owned(7003)
	if err := failing.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = f.close()
	if err := failing.Wait(); err == nil {
		t.Fatal("closed ringbuf did not stop the reaper")
	}
	if reaperRunning(7003) {
		t.Fatal("failed reaper still registered")
	}
}
