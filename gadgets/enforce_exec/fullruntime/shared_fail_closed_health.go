// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// The fail-closed rate witness of the live candidate (G019/G025 runtime
// reporting rule, fail_closed_rate.go).
const (
	sharedFailClosedRatesMap    = "opaque_real_fail_closed_rates"
	sharedFailClosedAttemptsMap = "opaque_real_attempts"

	// SharedFailClosedPollInterval is the default witness poll interval
	// (SharedNodeConfig.FailClosedPollInterval).
	SharedFailClosedPollInterval = 5 * time.Second
	// SharedFailClosedPollMin and SharedFailClosedPollMax bound a configured
	// interval: at most half the Degraded window, so a refusal is seen
	// within it.
	SharedFailClosedPollMin = 100 * time.Millisecond
	SharedFailClosedPollMax = FailClosedRateDegradedWindow / 2

	// sharedFailClosedStaleIntervals: a gated witness with no sample for
	// this many intervals (a stalled poller) is Unknown.
	sharedFailClosedStaleIntervals = 3
)

// SharedFailClosedState is the node health the fail-closed rate witness
// reports. The zero value is Unknown: an unread witness is never healthy.
type SharedFailClosedState uint8

const (
	// SharedFailClosedUnknown: the witness is unreadable, a counter moved
	// backwards, the counts are inconsistent (FailClosedProductRate error),
	// the poller stalled, or (a legacy witness) there is no attempts
	// denominator. NotReady-equivalent.
	SharedFailClosedUnknown SharedFailClosedState = iota
	SharedFailClosedHealthy
	// SharedFailClosedDegraded: a fail-closed refusal (Strict) or an
	// unevaluated child (Audit), or an ADMISSION fault, within the last
	// FailClosedRateDegradedWindow.
	SharedFailClosedDegraded
	// SharedFailClosedNotReady: the rate exceeds
	// FailClosedRateNotReadyThreshold over FailClosedRateNotReadyWindow.
	SharedFailClosedNotReady
)

func (s SharedFailClosedState) String() string {
	switch s {
	case SharedFailClosedHealthy:
		return "healthy"
	case SharedFailClosedDegraded:
		return "degraded"
	case SharedFailClosedNotReady:
		return "not-ready"
	}
	return "unknown"
}

// Node health errors of the fail-closed rate witness (errors.Is). Unknown
// wraps NotReady: an unknown witness is never better than NotReady.
var (
	ErrSharedFailClosedDegraded = errors.New("fail-closed rate Degraded")
	ErrSharedFailClosedNotReady = errors.New("fail-closed rate NotReady")
	ErrSharedFailClosedUnknown  = fmt.Errorf("fail-closed rate witness unknown: %w", ErrSharedFailClosedNotReady)
)

// SharedFailClosedHealth is the fail-closed rate witness of the live node.
type SharedFailClosedHealth struct {
	State SharedFailClosedState
	// Product: the 13-cell witness with opaque_real_attempts (a product
	// publisher object). A legacy 11-cell witness has no denominator: its
	// counts are reported and its State is Unknown.
	Product bool
	// Gated: State is a node health input (Ready, Inspect, the qualified
	// operator readiness): a product object served by its own product
	// publisher. A qualification publisher override (the bootstrap
	// publisher, whose untracked tasks are refused by design) or a legacy
	// object is reported only.
	Gated    bool
	Interval time.Duration
	// Samples is the number of retained samples (bounded: the
	// FailClosedRateNotReadyWindow plus one sample before it), LastSample the
	// time of the latest.
	Samples    int
	LastSample time.Time
	// Recent is the FailClosedRateDegradedWindow verdict at
	// FailClosedRateDegradedThreshold, Sustained the
	// FailClosedRateNotReadyWindow verdict at FailClosedRateNotReadyThreshold;
	// each span is the window actually measured (shorter while the node is
	// younger than the window, at most one interval longer otherwise).
	Recent, Sustained         FailClosedRateVerdict
	RecentSpan, SustainedSpan time.Duration
	// Counters and Attempts are the witness deltas since node start.
	Counters [FailClosedRateCounters]uint64
	Attempts [FailClosedRateAttempts]uint64
}

// sharedFailClosedRead reads the witness: the rate cells (the first 11 of a
// legacy object), then the attempts (zero for a legacy object). Rates are
// read before attempts: BPF counts an attempt before its failure, so every
// failure a sample sees has its attempt in the same sample.
type sharedFailClosedRead func() ([FailClosedRateCounters]uint64, [FailClosedRateAttempts]uint64, error)

// sharedFailClosedShape returns the admitted witness size: 0 when the object
// has no witness, FailClosedRateCounters (with the attempts witness) or
// FailClosedRateLegacyCounters; anything else is malformed.
func sharedFailClosedShape(resources *operators.NativeResources) (int, error) {
	m, ok := resources.Maps[sharedFailClosedRatesMap]
	if !ok {
		return 0, nil
	}
	cells, err := FailClosedRateCells(m.MaxEntries)
	if err != nil || m.Type != uint32(ebpf.Array) || m.KeySize != 4 || m.ValueSize != 8 {
		return 0, errors.Join(err, fmt.Errorf("shared candidate fail-closed witness %s malformed: %+v", sharedFailClosedRatesMap, m))
	}
	if cells == FailClosedRateCounters {
		a, ok := resources.Maps[sharedFailClosedAttemptsMap]
		if !ok || a.Type != uint32(ebpf.Array) || a.KeySize != 4 || a.ValueSize != 8 || a.MaxEntries != FailClosedRateAttempts {
			return 0, fmt.Errorf("shared candidate fail-closed attempts witness %s missing or malformed: %+v", sharedFailClosedAttemptsMap, a)
		}
	}
	return cells, nil
}

// borrowSharedFailClosed reads the witness through the map handles the eBPF
// operator published (operators.MapPrefix); the operator owns them.
func borrowSharedFailClosed(gc operators.GadgetContext, cells int) (sharedFailClosedRead, error) {
	mapOf := func(name string, entries int) (*ebpf.Map, error) {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, _ := value.(*ebpf.Map)
		if m == nil {
			return nil, fmt.Errorf("shared candidate map %s was not published", name)
		}
		if m.MaxEntries() != uint32(entries) {
			return nil, fmt.Errorf("shared candidate map %s has %d entries, admitted %d", name, m.MaxEntries(), entries)
		}
		return m, nil
	}
	rates, err := mapOf(sharedFailClosedRatesMap, cells)
	if err != nil {
		return nil, err
	}
	var attempts *ebpf.Map
	if cells == FailClosedRateCounters {
		if attempts, err = mapOf(sharedFailClosedAttemptsMap, FailClosedRateAttempts); err != nil {
			return nil, err
		}
	}
	return func() (r [FailClosedRateCounters]uint64, a [FailClosedRateAttempts]uint64, err error) {
		for i := range cells {
			if err := rates.Lookup(uint32(i), &r[i]); err != nil {
				return r, a, fmt.Errorf("%s[%d]: %w", sharedFailClosedRatesMap, i, err)
			}
		}
		if attempts != nil {
			for i := range a {
				if err := attempts.Lookup(uint32(i), &a[i]); err != nil {
					return r, a, fmt.Errorf("%s[%d]: %w", sharedFailClosedAttemptsMap, i, err)
				}
			}
		}
		return r, a, nil
	}, nil
}

type sharedFailClosedSample struct {
	at       time.Time
	rates    [FailClosedRateCounters]uint64
	attempts [FailClosedRateAttempts]uint64
}

// sharedLiveFailClosed polls the fail-closed rate witness and applies the
// runtime reporting rule (fail_closed_rate.go) over a bounded ring of
// samples:
//   - Degraded: the FailClosedRateDegradedWindow verdict (threshold 0) is
//     Degraded, i.e. a refusal, an unevaluated child or an ADMISSION fault
//     within 60 s (ENTRY never degrades). It clears after a quiet window;
//   - NotReady: the FailClosedRateNotReadyWindow verdict (0.1%) is Degraded;
//   - Unknown, sticky until node teardown like sharedLiveCapsule's: an
//     unreadable witness, a counter that moved backwards, or counts that
//     FailClosedProductRate refuses (ENTRY + ADMISSION + Total above the
//     attempts). A stalled poller is Unknown while it stays stalled.
//
// A window's failures are those between its base sample and the latest; its
// attempts start one sample earlier. BPF counts an attempt before its
// failure, and a fork's ADMISSION can be counted by the target after the
// source counted the attempt, so an attempt in flight while the base sample
// was read has its failure after the base: the extra interval of attempts
// keeps the invariant exact for such a failure, at the cost of a rate
// diluted by at most one interval in a window (1/60 at the defaults). The
// node-start baseline has no earlier sample; no route is published then, so
// no owned attempt is in flight.
type sharedLiveFailClosed struct {
	read     sharedFailClosedRead
	product  bool
	gated    bool
	interval time.Duration
	clock    func() time.Time // nil: time.Now
	limit    int              // ring bound

	mu       sync.Mutex
	baseline sharedFailClosedSample
	samples  []sharedFailClosedSample // oldest first, never empty
	last     SharedFailClosedHealth
	fault    error // sticky Unknown
	closed   bool  // the collection is closing: never read again

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{} // nil until start
}

// newSharedLiveFailClosed takes the node-start baseline: the window opens
// here.
func newSharedLiveFailClosed(read sharedFailClosedRead, product, gated bool, interval time.Duration, clock func() time.Time) (*sharedLiveFailClosed, error) {
	if interval < SharedFailClosedPollMin || interval > SharedFailClosedPollMax {
		return nil, fmt.Errorf("fail-closed poll interval %s outside [%s, %s]", interval, SharedFailClosedPollMin, SharedFailClosedPollMax)
	}
	f := &sharedLiveFailClosed{read: read, product: product, gated: gated, interval: interval, clock: clock, stop: make(chan struct{})}
	// The NotReady window, one sample before it and the latest; twice that
	// tolerates irregular ticks. Allocated once: the ring never grows.
	f.limit = 2*int(FailClosedRateNotReadyWindow/interval) + 4
	rates, attempts, err := read()
	if err != nil {
		return nil, fmt.Errorf("shared candidate fail-closed witness unreadable: %w", err)
	}
	f.baseline = sharedFailClosedSample{at: f.now(), rates: rates, attempts: attempts}
	f.samples = append(make([]sharedFailClosedSample, 0, f.limit+1), f.baseline)
	f.evaluate()
	return f, nil
}

func (f *sharedLiveFailClosed) now() time.Time {
	if f.clock != nil {
		return f.clock()
	}
	return time.Now()
}

// start runs the poller until close.
func (f *sharedLiveFailClosed) start() {
	f.done = make(chan struct{})
	go func() {
		defer close(f.done)
		t := time.NewTicker(f.interval)
		defer t.Stop()
		for {
			select {
			case <-f.stop:
				return
			case <-t.C:
				f.sample()
			}
		}
	}()
}

// close stops and joins the poller, then takes the final reading before the
// collection closes. Idempotent.
func (f *sharedLiveFailClosed) close() {
	f.stopOnce.Do(func() {
		close(f.stop)
		if f.done != nil {
			<-f.done
		}
		f.sample() // sticky in f.fault, reported by liveHealthFault
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
	})
}

func (f *sharedLiveFailClosed) unknown(err error) {
	f.fault = fmt.Errorf("shared candidate fail-closed witness unknown, node NotReady: %w: %w", err, ErrSharedFailClosedUnknown)
	f.last.State = SharedFailClosedUnknown
}

// sample reads the witness once and re-evaluates both windows.
func (f *sharedLiveFailClosed) sample() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.fault != nil {
		return
	}
	rates, attempts, err := f.read()
	if err != nil {
		f.unknown(err)
		return
	}
	prev := f.samples[len(f.samples)-1]
	s := sharedFailClosedSample{at: f.now(), rates: rates, attempts: attempts}
	if s.at.Before(prev.at) {
		s.at = prev.at
	}
	for i := range s.rates {
		if s.rates[i] < prev.rates[i] {
			f.unknown(fmt.Errorf("%s[%d] moved backwards (%d -> %d)", sharedFailClosedRatesMap, i, prev.rates[i], s.rates[i]))
			return
		}
	}
	for i := range s.attempts {
		if s.attempts[i] < prev.attempts[i] {
			f.unknown(fmt.Errorf("%s[%d] moved backwards (%d -> %d)", sharedFailClosedAttemptsMap, i, prev.attempts[i], s.attempts[i]))
			return
		}
	}
	f.samples = append(f.samples, s)
	// Drop what no window needs: the oldest sample, while the third one is
	// already older than the NotReady window (its predecessor then serves
	// as the attempts base); and anything beyond the bound.
	drop := 0
	for len(f.samples)-drop > 2 && !f.samples[drop+2].at.After(s.at.Add(-FailClosedRateNotReadyWindow)) {
		drop++
	}
	drop = max(drop, len(f.samples)-f.limit)
	f.samples = slices.Delete(f.samples, 0, drop)
	f.evaluate()
}

// window is the verdict of the window ending at the latest sample: base is
// the newest sample at least w old (the oldest while none is), attempts one
// sample earlier.
func (f *sharedLiveFailClosed) window(w time.Duration, threshold float64) (FailClosedRateVerdict, time.Duration, error) {
	latest := f.samples[len(f.samples)-1]
	base := 0
	for i, s := range f.samples {
		if !s.at.After(latest.at.Add(-w)) {
			base = i
		}
	}
	span := latest.at.Sub(f.samples[base].at)
	if !f.product {
		// Legacy: no denominator. The failures only (classes, no rate).
		var v FailClosedRateVerdict
		for i := range v.Failures {
			v.Failures[i] = latest.rates[i] - f.samples[base].rates[i]
			v.Total += v.Failures[i]
		}
		return v, span, nil
	}
	before := f.samples[max(base-1, 0)].attempts
	v, err := FailClosedProductRate(f.samples[base].rates, latest.rates, before, latest.attempts, threshold)
	if err != nil {
		return v, span, fmt.Errorf("%s window: %w", w, err)
	}
	return v, span, nil
}

// evaluate applies the runtime reporting rule to the samples (under f.mu).
func (f *sharedLiveFailClosed) evaluate() {
	latest := f.samples[len(f.samples)-1]
	h := SharedFailClosedHealth{Product: f.product, Gated: f.gated, Interval: f.interval, Samples: len(f.samples), LastSample: latest.at}
	for i := range h.Counters {
		h.Counters[i] = latest.rates[i] - f.baseline.rates[i]
	}
	for i := range h.Attempts {
		h.Attempts[i] = latest.attempts[i] - f.baseline.attempts[i]
	}
	var errRecent, errSustained error
	h.Recent, h.RecentSpan, errRecent = f.window(FailClosedRateDegradedWindow, FailClosedRateDegradedThreshold)
	h.Sustained, h.SustainedSpan, errSustained = f.window(FailClosedRateNotReadyWindow, FailClosedRateNotReadyThreshold)
	f.last = h
	switch {
	case errRecent != nil || errSustained != nil:
		f.unknown(errors.Join(errRecent, errSustained))
	case !f.product:
		f.last.State = SharedFailClosedUnknown
	case h.Sustained.Degraded:
		f.last.State = SharedFailClosedNotReady
	case h.Recent.Degraded:
		f.last.State = SharedFailClosedDegraded
	default:
		f.last.State = SharedFailClosedHealthy
	}
}

// report returns the latest evaluation and its health error (nil only when
// Healthy).
func (f *sharedLiveFailClosed) report() (SharedFailClosedHealth, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := f.last
	if f.fault != nil {
		return h, f.fault
	}
	if !f.closed {
		if stalled := f.now().Sub(h.LastSample); stalled > sharedFailClosedStaleIntervals*f.interval {
			h.State = SharedFailClosedUnknown
			return h, fmt.Errorf("shared candidate fail-closed witness not sampled for %s (poll interval %s), node NotReady: %w", stalled, f.interval, ErrSharedFailClosedUnknown)
		}
	}
	switch h.State {
	case SharedFailClosedHealthy:
		return h, nil
	case SharedFailClosedNotReady:
		v := h.Sustained
		return h, fmt.Errorf("shared candidate fail-closed rate %.4f%% (total=%d admission=%d, %v) over %s exceeds %.1f%%, node NotReady: %w",
			100*max(v.Rate, v.AdmissionRate), v.Total, v.Admission, v.Failures, h.SustainedSpan.Round(time.Millisecond), 100*FailClosedRateNotReadyThreshold, ErrSharedFailClosedNotReady)
	case SharedFailClosedDegraded:
		v := h.Recent
		return h, fmt.Errorf("shared candidate fail-closed refusals within %s (total=%d admission=%d, %v), node degraded: %w",
			h.RecentSpan.Round(time.Millisecond), v.Total, v.Admission, v.Failures, ErrSharedFailClosedDegraded)
	}
	return h, fmt.Errorf("shared candidate legacy fail-closed witness has no attempts denominator (failures within %s: %d): %w",
		h.RecentSpan.Round(time.Millisecond), h.Recent.Total, ErrSharedFailClosedUnknown)
}

// check is the live node health input: the report's error when gated.
func (f *sharedLiveFailClosed) check() error {
	if !f.gated {
		return nil
	}
	_, err := f.report()
	return err
}

// stickyFault is the sticky Unknown of a gated witness (liveHealthFault, the
// teardown result). The rate states are live only: a refusal rate is not a
// teardown failure.
func (f *sharedLiveFailClosed) stickyFault() error {
	if !f.gated {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fault
}

// newLiveFailClosed builds the node's fail-closed witness poller (not yet
// started): gated for a product object on its own product publisher, which
// must carry the 13-cell witness; reported only for any other object that
// carries a witness; nil without one.
func (n *NodeEnforcer) newLiveFailClosed(gc operators.GadgetContext, admitted *operators.NativeResources) (*sharedLiveFailClosed, error) {
	cells, err := sharedFailClosedShape(admitted)
	if err != nil {
		return nil, err
	}
	gated := sharedHasProductCommands(admitted) && n.host.newPublisher == nil
	switch {
	case gated && cells != FailClosedRateCounters:
		return nil, fmt.Errorf("shared candidate product object has %d fail-closed witness cells, want %d with %s", cells, FailClosedRateCounters, sharedFailClosedAttemptsMap)
	case cells == 0:
		return nil, nil
	}
	borrow := n.host.failClosed
	if borrow == nil {
		borrow = borrowSharedFailClosed
	}
	read, err := borrow(gc, cells)
	if err != nil || read == nil {
		return nil, errors.Join(err, fmt.Errorf("shared candidate fail-closed witness unavailable"))
	}
	return newSharedLiveFailClosed(read, cells == FailClosedRateCounters, gated, n.config.failClosedPollInterval(), n.host.failClosedClock)
}

// FailClosedHealth reports the fail-closed rate witness of the live node
// since its start, with its health error: Degraded and NotReady while their
// windows hold them, Unknown (sticky, wrapping ErrSharedFailClosedUnknown)
// for an unreadable, backwards or inconsistent witness. When Gated, the same
// error is carried by Ready and Inspect. ErrSharedNativeUnavailable without
// a live node or without a witness.
func (n *NodeEnforcer) FailClosedHealth() (SharedFailClosedHealth, error) {
	n.mu.Lock()
	var f *sharedLiveFailClosed
	if n.host != nil && n.host.live != nil {
		f = n.host.live.failClosed
	}
	n.mu.Unlock()
	if f == nil {
		return SharedFailClosedHealth{}, ErrSharedNativeUnavailable
	}
	return f.report()
}
