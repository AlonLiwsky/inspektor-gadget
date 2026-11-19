// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedFailClosedFake is a fake witness with a fake clock.
type sharedFailClosedFake struct {
	mu       sync.Mutex
	rates    [FailClosedRateCounters]uint64
	attempts [FailClosedRateAttempts]uint64
	err      error
	at       time.Time
}

func (w *sharedFailClosedFake) read() ([FailClosedRateCounters]uint64, [FailClosedRateAttempts]uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rates, w.attempts, w.err
}

func (w *sharedFailClosedFake) clock() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.at
}

// tick advances the clock one interval, applies change and samples.
func (w *sharedFailClosedFake) tick(f *sharedLiveFailClosed, change func(w *sharedFailClosedFake)) {
	w.mu.Lock()
	w.at = w.at.Add(f.interval)
	if change != nil {
		change(w)
	}
	w.mu.Unlock()
	f.sample()
}

// quiet is managed traffic with no refusal: n births and n execs.
func sharedFailClosedQuiet(n uint64) func(*sharedFailClosedFake) {
	return func(w *sharedFailClosedFake) { w.attempts[0] += n; w.attempts[1] += n }
}

func newSharedFailClosedTest(t *testing.T, product, gated bool) (*sharedLiveFailClosed, *sharedFailClosedFake) {
	t.Helper()
	w := &sharedFailClosedFake{at: time.Unix(1_000_000, 0)}
	f, err := newSharedLiveFailClosed(w.read, product, gated, SharedFailClosedPollInterval, w.clock)
	if err != nil {
		t.Fatal(err)
	}
	return f, w
}

func requireFailClosedState(t *testing.T, f *sharedLiveFailClosed, want SharedFailClosedState, step string) SharedFailClosedHealth {
	t.Helper()
	h, err := f.report()
	var sentinel error
	switch want {
	case SharedFailClosedDegraded:
		sentinel = ErrSharedFailClosedDegraded
	case SharedFailClosedNotReady:
		sentinel = ErrSharedFailClosedNotReady
	case SharedFailClosedUnknown:
		sentinel = ErrSharedFailClosedUnknown
	}
	if h.State != want || (sentinel == nil) != (err == nil) || (sentinel != nil && !errors.Is(err, sentinel)) {
		t.Fatalf("%s: state %s err %v (%+v), want %s", step, h.State, err, h, want)
	}
	if f.gated && !errors.Is(f.check(), sentinel) {
		t.Fatalf("%s: gated check %v, want %v", step, f.check(), sentinel)
	}
	return h
}

// TestSharedFailClosedDegradedWindow: one refusal is Degraded within the
// 60 s window (not NotReady at a low rate) and clears after a quiet window.
func TestSharedFailClosedDegradedWindow(t *testing.T) {
	f, w := newSharedFailClosedTest(t, true, true)
	requireFailClosedState(t, f, SharedFailClosedHealthy, "baseline")
	w.tick(f, sharedFailClosedQuiet(500))
	requireFailClosedState(t, f, SharedFailClosedHealthy, "quiet")
	// One source refusal: its birth attempt and the refusal.
	w.tick(f, func(w *sharedFailClosedFake) { sharedFailClosedQuiet(500)(w); w.attempts[0]++; w.rates[1]++ })
	refused := w.clock()
	h := requireFailClosedState(t, f, SharedFailClosedDegraded, "refusal")
	if h.Recent.Total != 1 || h.Recent.Failures[1] != 1 || h.Sustained.Degraded || h.Counters[1] != 1 {
		t.Fatalf("refusal verdicts: %+v", h)
	}
	for w.clock().Before(refused.Add(FailClosedRateDegradedWindow - f.interval)) {
		w.tick(f, sharedFailClosedQuiet(500))
		requireFailClosedState(t, f, SharedFailClosedDegraded, "within the window")
	}
	w.tick(f, sharedFailClosedQuiet(500))
	if h := requireFailClosedState(t, f, SharedFailClosedHealthy, "after a quiet window"); h.Recent.Total != 0 || h.Sustained.Total != 1 || h.RecentSpan < FailClosedRateDegradedWindow {
		t.Fatalf("after a quiet window: %+v", h)
	}
}

// TestSharedFailClosedNotReadyRate: a rate above 0.1% over the 5 min window
// is NotReady (after the Degraded window cleared), at or below it is not.
func TestSharedFailClosedNotReadyRate(t *testing.T) {
	f, w := newSharedFailClosedTest(t, true, true)
	w.tick(f, sharedFailClosedQuiet(50))
	// Two evaluation WORK refusals (exec attempts).
	w.tick(f, func(w *sharedFailClosedFake) { sharedFailClosedQuiet(50)(w); w.attempts[1] += 2; w.rates[3] += 2 })
	refused := w.clock()
	requireFailClosedState(t, f, SharedFailClosedNotReady, "2 of ~200 attempts") // also within 60 s: NotReady wins
	for w.clock().Before(refused.Add(FailClosedRateDegradedWindow)) {
		w.tick(f, sharedFailClosedQuiet(50))
	}
	h := requireFailClosedState(t, f, SharedFailClosedNotReady, "2 of ~1400 attempts, 60 s quiet")
	if h.Recent.Degraded || h.Sustained.Total != 2 || h.Sustained.Rate <= FailClosedRateNotReadyThreshold {
		t.Fatalf("sustained verdicts: %+v", h)
	}
	// The denominator grows: 2 of > 2000 attempts is at most 0.1%.
	for h.Sustained.Rate > FailClosedRateNotReadyThreshold {
		w.tick(f, sharedFailClosedQuiet(50))
		h, _ = f.report()
	}
	requireFailClosedState(t, f, SharedFailClosedHealthy, "rate at most 0.1%")
	for w.clock().Before(refused.Add(FailClosedRateNotReadyWindow)) {
		w.tick(f, sharedFailClosedQuiet(50))
	}
	if h := requireFailClosedState(t, f, SharedFailClosedHealthy, "after 5 min"); h.Sustained.Total != 0 || h.SustainedSpan < FailClosedRateNotReadyWindow {
		t.Fatalf("after 5 min: %+v", h)
	}
	// A rate above the threshold within the window again.
	w.tick(f, func(w *sharedFailClosedFake) { w.attempts[0] += 10; w.rates[0] += 10 })
	requireFailClosedState(t, f, SharedFailClosedNotReady, "10 quota refusals")
}

// TestSharedFailClosedEntryAdmission: ENTRY is reported apart and never
// degrades; ADMISSION is outside Total but degrades by its own rate.
func TestSharedFailClosedEntryAdmission(t *testing.T) {
	f, w := newSharedFailClosedTest(t, true, true)
	w.tick(f, func(w *sharedFailClosedFake) {
		sharedFailClosedQuiet(5000)(w)
		w.attempts[1]++
		w.rates[FailClosedRateEntry]++
	})
	h := requireFailClosedState(t, f, SharedFailClosedHealthy, "ENTRY")
	if h.Recent.Entry != 1 || h.Recent.Total != 0 || h.Counters[FailClosedRateEntry] != 1 {
		t.Fatalf("ENTRY: %+v", h)
	}
	w.tick(f, func(w *sharedFailClosedFake) {
		sharedFailClosedQuiet(5000)(w)
		w.attempts[1]++
		w.rates[FailClosedRateAdmission]++
	})
	h = requireFailClosedState(t, f, SharedFailClosedDegraded, "ADMISSION")
	if h.Recent.Admission != 1 || h.Recent.Total != 0 || h.Recent.Entry != 1 {
		t.Fatalf("ADMISSION: %+v", h)
	}
	// WorkRetry is a subset, never a class: it does not degrade on its own.
	g, v := newSharedFailClosedTest(t, true, true)
	v.tick(g, func(w *sharedFailClosedFake) { w.attempts[0]++; w.rates[FailClosedRateWorkRetry]++ })
	requireFailClosedState(t, g, SharedFailClosedHealthy, "WorkRetry only")
}

// TestSharedFailClosedInFlightAttempt: an attempt counted in one sample and
// its failure in the next (with no new attempt) is a refusal, not an
// inconsistent witness: the window's attempts start one sample earlier.
func TestSharedFailClosedInFlightAttempt(t *testing.T) {
	f, w := newSharedFailClosedTest(t, true, true)
	w.tick(f, sharedFailClosedQuiet(5000))
	// A fork's birth attempt (source) is read; its target's ADMISSION
	// fault lands after the read. Then nothing else happens: each window's
	// base passes the sample that saw the attempt but not the failure.
	w.tick(f, func(w *sharedFailClosedFake) { w.attempts[0]++ })
	w.tick(f, func(w *sharedFailClosedFake) { w.rates[FailClosedRateAdmission]++ })
	requireFailClosedState(t, f, SharedFailClosedDegraded, "in-flight ADMISSION")
	end := w.clock().Add(FailClosedRateNotReadyWindow + time.Minute)
	for w.clock().Before(end) {
		w.tick(f, nil)
		// The 5 min window may hold just that attempt and its failure
		// (NotReady); never Unknown.
		if h, err := f.report(); h.State == SharedFailClosedUnknown {
			t.Fatalf("in-flight attempt at %s: %s %v", h.LastSample, h.State, err)
		}
	}
	requireFailClosedState(t, f, SharedFailClosedHealthy, "after both windows")
}

// TestSharedFailClosedUnknown: an unreadable witness, a counter moving
// backwards and counts exceeding the attempts are Unknown (NotReady
// equivalent), sticky until teardown; a stalled poller is Unknown while
// stalled.
func TestSharedFailClosedUnknown(t *testing.T) {
	for name, change := range map[string]func(*sharedFailClosedFake){
		"unreadable":         func(w *sharedFailClosedFake) { w.err = syscall.EIO },
		"rates backwards":    func(w *sharedFailClosedFake) { w.rates[2]-- },
		"entry backwards":    func(w *sharedFailClosedFake) { w.rates[FailClosedRateEntry]-- },
		"attempts backwards": func(w *sharedFailClosedFake) { w.attempts[1]-- },
		"total > attempts":   func(w *sharedFailClosedFake) { w.attempts[0] += 2; w.rates[1] += 1000 },
		"entry > attempts":   func(w *sharedFailClosedFake) { w.attempts[1]++; w.rates[FailClosedRateEntry] += 1000 },
	} {
		t.Run(name, func(t *testing.T) {
			f, w := newSharedFailClosedTest(t, true, true)
			w.tick(f, func(w *sharedFailClosedFake) {
				sharedFailClosedQuiet(100)(w)
				w.rates[2]++
				w.attempts[0]++
				w.rates[FailClosedRateEntry]++
				w.attempts[1]++
			})
			w.tick(f, change)
			requireFailClosedState(t, f, SharedFailClosedUnknown, name)
			if _, err := f.report(); !errors.Is(err, ErrSharedFailClosedNotReady) {
				t.Fatalf("Unknown is not NotReady-equivalent: %v", err)
			}
			// Sticky: a healthy witness later does not clear it.
			w.tick(f, func(w *sharedFailClosedFake) {
				w.err, w.rates, w.attempts = nil, [FailClosedRateCounters]uint64{}, [FailClosedRateAttempts]uint64{1 << 20, 1 << 20}
			})
			requireFailClosedState(t, f, SharedFailClosedUnknown, name+", later")
			if err := f.stickyFault(); !errors.Is(err, ErrSharedFailClosedUnknown) {
				t.Fatalf("sticky fault %v", err)
			}
		})
	}
	t.Run("stalled", func(t *testing.T) {
		f, w := newSharedFailClosedTest(t, true, true)
		w.mu.Lock()
		w.at = w.at.Add(sharedFailClosedStaleIntervals*f.interval + time.Second)
		w.mu.Unlock()
		requireFailClosedState(t, f, SharedFailClosedUnknown, "stalled")
		if f.stickyFault() != nil {
			t.Fatal("a stalled poller is not a sticky fault")
		}
		w.tick(f, nil)
		requireFailClosedState(t, f, SharedFailClosedHealthy, "sampled again")
	})
	t.Run("unreadable at start", func(t *testing.T) {
		w := &sharedFailClosedFake{err: syscall.EPERM}
		if _, err := newSharedLiveFailClosed(w.read, true, true, SharedFailClosedPollInterval, w.clock); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("unreadable baseline: %v", err)
		}
	})
}

// TestSharedFailClosedLegacy: an 11-cell witness has no attempts
// denominator: its failures are reported, its state is Unknown, and it is
// never a node health input.
func TestSharedFailClosedLegacy(t *testing.T) {
	f, w := newSharedFailClosedTest(t, false, false)
	w.tick(f, func(w *sharedFailClosedFake) { w.rates[1] += 3 })
	h, err := f.report()
	if h.State != SharedFailClosedUnknown || !errors.Is(err, ErrSharedFailClosedUnknown) || h.Recent.Total != 3 || h.Product || h.Gated || f.check() != nil || f.stickyFault() != nil {
		t.Fatalf("legacy: %+v %v check %v", h, err, f.check())
	}
}

// TestSharedFailClosedRingBounded: the ring keeps the 5 min window plus one
// sample before it, and never grows past its bound.
func TestSharedFailClosedRingBounded(t *testing.T) {
	f, w := newSharedFailClosedTest(t, true, true)
	capacity := cap(f.samples)
	window := int(FailClosedRateNotReadyWindow / f.interval)
	for range 10 * window {
		w.tick(f, sharedFailClosedQuiet(10))
	}
	h := requireFailClosedState(t, f, SharedFailClosedHealthy, "long run")
	if h.Samples != window+2 || cap(f.samples) != capacity || h.SustainedSpan != FailClosedRateNotReadyWindow {
		t.Fatalf("ring: %d samples (want %d), cap %d -> %d, span %s", h.Samples, window+2, capacity, cap(f.samples), h.SustainedSpan)
	}
	// A burst of early ticks (no clock advance) stays bounded.
	for range 10 * window {
		f.sample()
	}
	if len(f.samples) > f.limit || cap(f.samples) != capacity {
		t.Fatalf("burst: %d samples, limit %d, cap %d -> %d", len(f.samples), f.limit, capacity, cap(f.samples))
	}
}

// TestSharedFailClosedPollerStops: the poller samples on its own and close
// joins it (no goroutine left), takes a final reading and never reads again.
func TestSharedFailClosedPollerStops(t *testing.T) {
	w := &sharedFailClosedFake{}
	var reads int
	var mu sync.Mutex
	read := func() ([FailClosedRateCounters]uint64, [FailClosedRateAttempts]uint64, error) {
		mu.Lock()
		reads++
		mu.Unlock()
		return w.read()
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return reads }
	f, err := newSharedLiveFailClosed(read, true, true, SharedFailClosedPollMin, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.start()
	for deadline := time.Now().Add(10 * time.Second); count() < 3; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("poller took %d reads in 10 s", count())
		}
	}
	f.close()
	select {
	case <-f.done:
	default:
		t.Fatal("close returned before the poller exited")
	}
	final := count()
	f.close() // idempotent
	time.Sleep(5 * SharedFailClosedPollMin)
	if count() != final {
		t.Fatalf("witness read after close: %d -> %d", final, count())
	}
	if h, err := f.report(); err != nil || h.State != SharedFailClosedHealthy {
		t.Fatalf("closed: %+v %v", h, err)
	}
}

func sharedStartProductFakeNode(t *testing.T, host *sharedFakeNativeHost, interval time.Duration) (*NodeEnforcer, error) {
	t.Helper()
	sharedEnableQualification(t)
	q := host.qualification(nil)
	q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
		return newSharedFakePublisher(), nil
	}
	config := sharedQualifiedConfig()
	config.FailClosedPollInterval = interval
	return StartNode(WithSharedNodeQualification(t.Context(), q), config)
}

func waitSharedFailClosed(t *testing.T, n *NodeEnforcer, want SharedFailClosedState) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if h, _ := n.FailClosedHealth(); h.State == want {
			return
		}
		if time.Now().After(deadline) {
			h, err := n.FailClosedHealth()
			t.Fatalf("fail-closed state %s (%v), want %s", h.State, err, want)
		}
	}
}

// TestSharedNodeFailClosedLive: a product node polls its witness; the
// Degraded state reaches Ready and Inspect (checkLiveReceipts) but not the
// teardown result; StopNode joins the poller. An Unknown witness is a
// sticky fault that StopNode reports.
func TestSharedNodeFailClosedLive(t *testing.T) {
	host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
	n, err := sharedStartProductFakeNode(t, host, SharedFailClosedPollMin)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := n.FailClosedHealth(); err != nil || !h.Gated || !h.Product || h.State != SharedFailClosedHealthy || host.failClosedCells != FailClosedRateCounters {
		t.Fatalf("started: %+v %v cells %d", h, err, host.failClosedCells)
	}
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || errors.Is(err, ErrSharedFailClosedDegraded) {
		t.Fatalf("Ready: %v", err)
	}
	host.setFailClosed(func(r *[FailClosedRateCounters]uint64, a *[FailClosedRateAttempts]uint64, _ *error) {
		a[0] += 1 << 20
		r[0]++
	})
	waitSharedFailClosed(t, n, SharedFailClosedDegraded)
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || !errors.Is(err, ErrSharedFailClosedDegraded) {
		t.Fatalf("Ready while Degraded: %v", err)
	}
	if err := n.checkLiveReceipts(); !errors.Is(err, ErrSharedFailClosedDegraded) {
		t.Fatalf("Inspect health while Degraded: %v", err)
	}
	f := n.host.live.failClosed
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatalf("StopNode: %v (a refusal rate is not a teardown failure)", err)
	}
	select {
	case <-f.done:
	default:
		t.Fatal("StopNode left the poller running")
	}

	host = &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
	if n, err = sharedStartProductFakeNode(t, host, SharedFailClosedPollMin); err != nil {
		t.Fatal(err)
	}
	host.setFailClosed(func(_ *[FailClosedRateCounters]uint64, _ *[FailClosedRateAttempts]uint64, err *error) {
		*err = syscall.EIO
	})
	waitSharedFailClosed(t, n, SharedFailClosedUnknown)
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedFailClosedUnknown) {
		t.Fatalf("Ready while Unknown: %v", err)
	}
	if err := n.StopNode(t.Context()); !errors.Is(err, ErrSharedFailClosedUnknown) || !errors.Is(err, syscall.EIO) {
		t.Fatalf("StopNode with an Unknown witness: %v", err)
	}
}

// TestSharedNodeFailClosedSelection: a product object on its product
// publisher is gated and must carry the 13-cell witness; an object without
// a witness runs no poller; a publisher override is reported only; the poll
// interval is bounded.
func TestSharedNodeFailClosedSelection(t *testing.T) {
	for name, drop := range map[string]string{"no rates": sharedFailClosedRatesMap, "no attempts": sharedFailClosedAttemptsMap} {
		host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
		delete(host.manifest.Maps, drop)
		if _, err := sharedStartProductFakeNode(t, host, 0); err == nil || !strings.Contains(err.Error(), "fail-closed") {
			t.Fatalf("%s: product node started: %v", name, err)
		}
	}
	legacy := sharedProductFakeManifest()
	m := legacy.Maps[sharedFailClosedRatesMap]
	m.MaxEntries = FailClosedRateLegacyCounters
	legacy.Maps[sharedFailClosedRatesMap] = m
	if _, err := sharedStartProductFakeNode(t, &sharedFakeNativeHost{manifest: legacy}, 0); err == nil {
		t.Fatal("product node started with a legacy witness")
	}

	n, _, _, _ := sharedStartPublishingNode(t, newSharedFakePublisher())
	if _, err := n.FailClosedHealth(); !errors.Is(err, ErrSharedNativeUnavailable) || n.host.live.failClosed != nil {
		t.Fatalf("object without a witness: %v", err)
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}

	host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
	sharedEnableQualification(t)
	override, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(func(operators.GadgetContext) (SharedRoutePublisher, error) {
		return newSharedFakePublisher(), nil
	})), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	if h, err := override.FailClosedHealth(); err != nil || h.Gated || !h.Product {
		t.Fatalf("publisher override: %+v %v", h, err)
	}
	if err := override.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}

	for _, d := range []time.Duration{-time.Second, SharedFailClosedPollMin - 1, SharedFailClosedPollMax + 1} {
		config := sharedQualifiedConfig()
		config.FailClosedPollInterval = d
		if _, err := NewNodeEnforcer(config); err == nil || !strings.Contains(err.Error(), "poll interval") {
			t.Fatalf("interval %s: %v", d, err)
		}
	}
}

// TestSharedMigrationOutUnenforcedStatus (G019 gap 5, accepted residual):
// every published Strict binding is labelled, an Audit one is not, and the
// label is never a Fault.
func TestSharedMigrationOutUnenforcedStatus(t *testing.T) {
	n, _, a, b := sharedStartPublishingNode(t, newSharedFakePublisher())
	defer func() { _ = n.StopNode(t.Context()) }()
	if st := a.Inspect(); !st.MigrationOutUnenforced || st.Fault != nil {
		t.Fatalf("Strict binding: %+v", st)
	}
	if st := b.Inspect(); st.MigrationOutUnenforced || st.Fault != nil {
		t.Fatalf("Audit binding: %+v", st)
	}
}

// TestSharedClassChangeRefused (G019 gap 6, accepted): a class-changing
// revision is refused before any command, explicitly (ErrSharedClassChange)
// and terminally, and the binding keeps its last-good route.
func TestSharedClassChangeRefused(t *testing.T) {
	pub := newSharedFakePublisher()
	n, _, a, b := sharedStartPublishingNode(t, pub)
	defer func() { _ = n.StopNode(t.Context()) }()
	for s, to := range map[*BindingSession]SharedBindingPolicy{a: {Class: 1, Fallback: 2, Rules: 1}, b: {Class: 2, Fallback: 2, Rules: 1}} {
		before := s.Inspect()
		publishes := pub.publishes[before.RouteSlot]
		state, err := s.Publish(t.Context(), to)
		if !errors.Is(err, ErrSharedClassChange) || !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "new container") {
			t.Fatalf("class change: %v", err)
		}
		if after := s.Inspect(); state.Generation != before.Generation || after.Generation != before.Generation || after.Fault != nil || pub.publishes[before.RouteSlot] != publishes {
			t.Fatalf("class change not last-good: %+v -> %+v, %d publishes", before, after, pub.publishes[before.RouteSlot]-publishes)
		}
	}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 1, Rules: 1}); err != nil {
		t.Fatalf("same-class revision after the refusal: %v", err)
	}
}

// TestProductPublisherClassChangeRefusal: a kernel-refused revision whose
// route holds another class is reported as ErrSharedClassChange; any other
// refused revision keeps the generic terminal refusal.
func TestProductPublisherClassChangeRefusal(t *testing.T) {
	cmd := &sharedFakeCommander{reviseCode: sharedProductRefused, routeState: SharedRouteState{Cgroup: 11, Generation: 1, Class: 2}}
	p, _ := newTestProductPublisher(cmd, &sharedFakeThreads{})
	defer p.Close()
	_, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}, false, SharedInitIdentity{})
	if !errors.Is(err, ErrSharedClassChange) || !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "Strict -> Audit") {
		t.Fatalf("class-changing revision: %v", err)
	}
	_, err = p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, false, SharedInitIdentity{})
	if errors.Is(err, ErrSharedClassChange) || !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "policy UID") {
		t.Fatalf("same-class refused revision: %v", err)
	}
}
