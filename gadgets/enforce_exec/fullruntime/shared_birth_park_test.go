// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// TestSharedLiveBirthParkHealth (G019 gaps 1 and 2): the birth-park witness
// over the window since node start. Parked, taken, abandoned and
// cross-generation counts are reported only; a stale park or a failed take
// is Degraded for FailClosedRateDegradedWindow after it was observed (each
// new one restarts it); a latched park and an unreadable or backwards
// witness are sticky.
func TestSharedLiveBirthParkHealth(t *testing.T) {
	var clock sharedTestClock
	var counters [BirthParkStats]uint64
	var readErr error
	counters[BirthParkParked] = 9 // before the window
	b := &sharedLiveBirthPark{read: func() ([BirthParkStats]uint64, error) { return counters, readErr }, clock: clock.now}
	b.baseline = counters
	counters[BirthParkParked] += 5
	counters[BirthParkTaken] += 3
	counters[BirthParkAbandoned] += 1
	counters[BirthParkPutFailed] += 1
	counters[BirthParkCrossGeneration] += 2
	got, err := b.report()
	if err != nil || got != (SharedBirthParkHealth{Parked: 5, Taken: 3, Abandoned: 1, PutFailed: 1, CrossGeneration: 2}) {
		t.Fatalf("healthy window %+v, %v", got, err)
	}
	for _, cell := range []int{BirthParkStale, BirthParkTakeFailed} {
		counters[cell]++
		if err := b.check(); err == nil || !strings.Contains(err.Error(), "birth-park stale=") {
			t.Fatalf("cell %d growth: %v, want Degraded", cell, err)
		}
		clock.advance(FailClosedRateDegradedWindow - time.Second)
		if err := b.check(); err == nil {
			t.Fatalf("cell %d: cleared inside the window", cell)
		}
		clock.advance(time.Second)
		if err := b.check(); err != nil {
			t.Fatalf("cell %d: quiet window: %v", cell, err)
		}
	}
	counters[BirthParkLatched]++
	if err := b.check(); err == nil || !strings.Contains(err.Error(), "latched=1") {
		t.Fatalf("latched: %v", err)
	}
	clock.advance(10 * FailClosedRateDegradedWindow)
	if err := b.check(); err == nil || !strings.Contains(err.Error(), "latched=1") {
		t.Fatalf("latched not sticky: %v", err)
	}

	for name, set := range map[string]func(){
		"unreadable": func() { readErr = errors.New("map gone") },
		"backwards":  func() { counters[BirthParkParked] = 0 },
	} {
		counters, readErr = [BirthParkStats]uint64{}, nil
		b := &sharedLiveBirthPark{read: func() ([BirthParkStats]uint64, error) { return counters, readErr }, clock: clock.now}
		b.baseline[BirthParkParked] = 1
		counters[BirthParkParked] = 1
		if err := b.check(); err != nil {
			t.Fatalf("%s: healthy: %v", name, err)
		}
		set()
		if err := b.check(); err == nil || !strings.Contains(err.Error(), "witness unknown") {
			t.Fatalf("%s: %v, want Unknown", name, err)
		}
		counters, readErr = [BirthParkStats]uint64{BirthParkParked: 1}, nil
		if err := b.check(); err == nil {
			t.Fatalf("%s: not sticky", name)
		}
	}
}

// TestSharedBirthParkNodeHealth: a product object's birth-park witness is
// part of node health (Ready, Inspect, BirthParkHealth), a malformed witness
// refuses startup, and an object without it (not a product object) has
// none.
func TestSharedBirthParkNodeHealth(t *testing.T) {
	sharedEnableQualification(t)
	start := func(t *testing.T, manifest *operators.NativeResources) (*NodeEnforcer, *sharedFakeNativeHost, error) {
		host := &sharedFakeNativeHost{manifest: manifest}
		q := host.qualification(nil)
		q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			return newSharedFakePublisher(), nil
		}
		n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig())
		return n, host, err
	}

	t.Run("product object", func(t *testing.T) {
		n, host, err := start(t, sharedProductFakeManifest())
		if err != nil {
			t.Fatal(err)
		}
		host.setBirthPark(func(c *[BirthParkStats]uint64, _ *error) {
			c[BirthParkParked], c[BirthParkTaken] = 4, 4
		})
		if got, err := n.BirthParkHealth(); err != nil || got.Parked != 4 || got.Taken != 4 {
			t.Fatalf("healthy BirthParkHealth %+v, %v", got, err)
		}
		if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(err.Error(), "birth-park") {
			t.Fatalf("healthy Ready: %v", err)
		}
		host.setBirthPark(func(c *[BirthParkStats]uint64, _ *error) { c[BirthParkLatched] = 1 })
		if err := n.Ready(host.gc); err == nil || !strings.Contains(err.Error(), "birth-park latched=1") {
			t.Fatalf("latched Ready: %v", err)
		}
		if err := n.StopNode(t.Context()); err == nil || !strings.Contains(err.Error(), "birth-park latched=1") {
			t.Fatalf("StopNode: %v, want the latched park", err)
		}
		if host.stops != 1 || !n.host.released {
			t.Fatalf("teardown blocked: stops=%d released=%v", host.stops, n.host.released)
		}
	})

	t.Run("malformed witness refuses startup", func(t *testing.T) {
		m := sharedProductFakeManifest()
		w := m.Maps[BirthParkStatsMap]
		w.MaxEntries = 4
		m.Maps[BirthParkStatsMap] = w
		n, _, err := start(t, m)
		if n != nil || err == nil || !strings.Contains(err.Error(), BirthParkStatsMap) {
			t.Fatalf("malformed birth-park witness: node=%v err=%v", n, err)
		}
	})

	t.Run("not a product object", func(t *testing.T) {
		n, _, err := start(t, sharedCandidateFakeManifest())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = n.StopNode(t.Context()) }()
		if _, err := n.BirthParkHealth(); !errors.Is(err, ErrSharedNativeUnavailable) {
			t.Fatalf("BirthParkHealth without the birth park: %v", err)
		}
	})
}
