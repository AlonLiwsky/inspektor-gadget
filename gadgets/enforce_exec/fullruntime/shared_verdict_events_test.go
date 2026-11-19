// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// TestSharedVerdictCountersShape: the counters map has the owner's verdict
// counters shape, pinned when present and required only once the emitter
// landed (the single switch).
func TestSharedVerdictCountersShape(t *testing.T) {
	s := sharedVerdictCountersShape
	if err := validateCounterMap(&ebpf.MapInfo{Type: ebpf.MapType(s.Type), KeySize: s.KeySize, ValueSize: s.ValueSize, MaxEntries: s.MaxEntries}); err != nil {
		t.Fatalf("admitted shape is not the owner's counters shape: %v", err)
	}
	with := func(m *operators.NativeMapResource) *operators.NativeResources {
		r := sharedProductFakeManifest()
		delete(r.Maps, SharedVerdictCountersMap)
		if m != nil {
			r.Maps[SharedVerdictCountersMap] = *m
		}
		return r
	}
	malformed := s
	malformed.MaxEntries = 4
	array := s
	array.Type = uint32(ebpf.Array)
	for _, landed := range []bool{false, true} {
		validateSharedVerdictCounters := func(r *operators.NativeResources) error { return validateSharedVerdictCountersLanded(r, landed) }
		if err := validateSharedVerdictCounters(with(&s)); err != nil {
			t.Fatalf("landed=%v exact shape: %v", landed, err)
		}
		if err := validateSharedVerdictCounters(with(nil)); (err == nil) == landed {
			t.Fatalf("landed=%v absent map: %v", landed, err)
		}
		for _, m := range []operators.NativeMapResource{malformed, array} {
			if err := validateSharedVerdictCounters(with(&m)); err == nil || !strings.Contains(err.Error(), "malformed") {
				t.Fatalf("landed=%v malformed %+v: %v", landed, m, err)
			}
		}
	}
}

// TestSharedEventABIAnnotation: a mismatching event ABI is refused; an
// absent one only once the emitter landed.
func TestSharedEventABIAnnotation(t *testing.T) {
	meta := func(value *string) *viper.Viper {
		v := viper.New()
		v.Set("annotations.enforce-exec-shared-profile", "1")
		if value != nil {
			v.Set("annotations."+SharedEventABIAnnotation, *value)
		}
		return v
	}
	one, two, empty := "1", "2", ""
	for _, landed := range []bool{false, true} {
		admitSharedEventABI := func(v *viper.Viper) error { return admitSharedEventABILanded(v, landed) }
		if err := admitSharedEventABI(meta(&one)); err != nil {
			t.Fatalf("landed=%v version 1: %v", landed, err)
		}
		for _, v := range []*string{&two, &empty} {
			if err := admitSharedEventABI(meta(v)); err == nil {
				t.Fatalf("landed=%v admitted event ABI %q", landed, *v)
			}
		}
		if err := admitSharedEventABI(meta(nil)); (err == nil) == landed {
			t.Fatalf("landed=%v absent annotation: %v", landed, err)
		}
	}
	if SharedNodeAPIVersion != 1 || SharedEventABIVersion != "1" || SharedEventABIAnnotation != "enforce-exec-shared-event-abi" {
		t.Fatal("version contract changed")
	}
}

// sharedFakeVerdict is a fake verdict counters map with its own clock.
type sharedFakeVerdict struct {
	mu       sync.Mutex
	counters KernelEventCounters
	err      error
	releases int
	now      time.Time
}

func (f *sharedFakeVerdict) borrow(operators.GadgetContext) (sharedVerdictCountersRead, func() error, error) {
	read := func() (KernelEventCounters, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.counters, f.err
	}
	release := func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.releases++
		return nil
	}
	return read, release, nil
}

func (f *sharedFakeVerdict) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *sharedFakeVerdict) set(update func(*sharedFakeVerdict)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	update(f)
}

// TestSharedVerdictNodeHealth (D2): KernelEventCounters reports the
// counters, Final after StopNode's detach; Lost growth labels Ready Degraded
// (never NotReady) for FailClosedRateDegradedWindow; unreadable counters are
// Degraded too, never a teardown fault; an object without the map has none.
func TestSharedVerdictNodeHealth(t *testing.T) {
	sharedEnableQualification(t)
	start := func(t *testing.T, manifest *operators.NativeResources, fake *sharedFakeVerdict) (*NodeEnforcer, *sharedFakeNativeHost, error) {
		host := &sharedFakeNativeHost{manifest: manifest}
		q := host.qualification(nil)
		q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			return newSharedFakePublisher(), nil
		}
		q.verdictCounters, q.verdictClock = fake.borrow, fake.clock
		n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig())
		return n, host, err
	}
	withCounters := func() *operators.NativeResources {
		m := sharedProductFakeManifest()
		m.Maps[SharedVerdictCountersMap] = sharedVerdictCountersShape
		return m
	}
	lossLabel := func(t *testing.T, n *NodeEnforcer, host *sharedFakeNativeHost) bool {
		t.Helper()
		err := n.Ready(host.gc)
		if !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(err.Error(), "NotReady") || errors.Is(err, ErrSharedFailClosedNotReady) {
			t.Fatalf("Ready: %v", err)
		}
		return errors.Is(err, ErrSharedVerdictEventLoss)
	}

	t.Run("loss is Degraded only", func(t *testing.T) {
		fake := &sharedFakeVerdict{now: time.Unix(1000, 0), counters: KernelEventCounters{Submitted: 5}}
		n, host, err := start(t, withCounters(), fake)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := n.KernelEventCounters(); err != nil || got != (KernelEventCounters{Submitted: 5}) {
			t.Fatalf("KernelEventCounters %+v %v", got, err)
		}
		if lossLabel(t, n, host) {
			t.Fatal("Degraded without a loss")
		}
		fake.set(func(f *sharedFakeVerdict) {
			f.counters = KernelEventCounters{Submitted: 9, Lost: 2, ObservationErrors: 1}
		})
		if !lossLabel(t, n, host) {
			t.Fatal("lost events not labelled Degraded")
		}
		// No further loss: Degraded until the window passes.
		fake.set(func(f *sharedFakeVerdict) { f.now = f.now.Add(FailClosedRateDegradedWindow - time.Second) })
		if !lossLabel(t, n, host) {
			t.Fatal("loss label dropped inside the window")
		}
		fake.set(func(f *sharedFakeVerdict) { f.now = f.now.Add(2 * time.Second) })
		if lossLabel(t, n, host) {
			t.Fatal("loss label kept after the window")
		}
		// Unreadable: Degraded, the last sample kept, never a teardown fault.
		fake.set(func(f *sharedFakeVerdict) { f.err = errors.New("lookup failed") })
		if !lossLabel(t, n, host) {
			t.Fatal("unreadable counters not labelled Degraded")
		}
		if got, err := n.KernelEventCounters(); err == nil || got.Lost != 2 || got.Final {
			t.Fatalf("unreadable KernelEventCounters %+v %v", got, err)
		}
		fake.set(func(f *sharedFakeVerdict) {
			f.err = nil
			f.counters = KernelEventCounters{Submitted: 20, Lost: 3, ObservationErrors: 1}
		})
		if err := n.StopNode(t.Context()); err != nil {
			t.Fatalf("StopNode: %v", err)
		}
		final := KernelEventCounters{Submitted: 20, Lost: 3, ObservationErrors: 1, Final: true}
		if got, err := n.KernelEventCounters(); err != nil || got != final || fake.releases != 1 {
			t.Fatalf("final %+v %v releases %d", got, err, fake.releases)
		}
		fake.set(func(f *sharedFakeVerdict) { f.counters.Submitted = 99 })
		if got, _ := n.KernelEventCounters(); got != final {
			t.Fatalf("Final snapshot changed: %+v", got)
		}
	})

	t.Run("malformed map refuses startup", func(t *testing.T) {
		m := withCounters()
		w := m.Maps[SharedVerdictCountersMap]
		w.ValueSize = 16
		m.Maps[SharedVerdictCountersMap] = w
		fake := &sharedFakeVerdict{}
		n, _, err := start(t, m, fake)
		if n != nil || err == nil || !strings.Contains(err.Error(), SharedVerdictCountersMap) {
			t.Fatalf("malformed verdict counters: node=%v err=%v", n, err)
		}
	})

	t.Run("refused startup releases the clone", func(t *testing.T) {
		fake := &sharedFakeVerdict{}
		host := &sharedFakeNativeHost{manifest: withCounters()}
		q := host.qualification(nil)
		q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			return nil, errors.New("no publisher")
		}
		q.verdictCounters = fake.borrow
		if _, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig()); err == nil {
			t.Fatal("started without a publisher")
		}
		if fake.releases != 1 {
			t.Fatalf("clone released %d times", fake.releases)
		}
	})

	t.Run("product object without the emitter refused", func(t *testing.T) {
		m := sharedProductFakeManifest()
		delete(m.Maps, SharedVerdictCountersMap)
		n, _, err := start(t, m, &sharedFakeVerdict{})
		if n != nil || err == nil || !strings.Contains(err.Error(), "lacks the verdict counters map") {
			t.Fatalf("product object without the emitter: node=%v err=%v", n, err)
		}
	})

	// The pre-landing start path (an object without the counters map
	// admitted) is unreachable: sharedVerdictEmitterLanded is a constant and
	// the subtest above refuses that object. The pre-landing admission rules
	// are TestSharedVerdictCountersShape's landed=false cases.

	t.Run("no live node", func(t *testing.T) {
		n, err := NewNodeEnforcer(sharedQualifiedConfig())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.KernelEventCounters(); !errors.Is(err, ErrSharedNativeUnavailable) {
			t.Fatalf("KernelEventCounters without a live node: %v", err)
		}
	})
}

// TestSharedVerdictRingGeometry (G020): the verdict ring defaults to
// max(1 MiB, Bindings x 256 KiB) rounded up to a power of two (the BPF
// SE_VERDICT_RING_FOR), an explicit size must be a power of two from 4 KiB
// to 256 MiB, the image carries it as enforce-exec-shared-verdict-ring, and
// the product admission pins the loaded ring to it.
func TestSharedVerdictRingGeometry(t *testing.T) {
	for bindings, want := range map[uint64]uint64{1: 1 << 20, 2: 1 << 20, 4: 1 << 20, 5: 2 << 20, 8: 2 << 20, 9: 4 << 20, 1024: 1 << 28, 1025: 0} {
		p := SharedProfile{Bindings: bindings}
		if got := p.verdictRing(); got != want {
			t.Fatalf("%d bindings: default ring %d, want %d", bindings, got, want)
		}
	}
	base := sharedCandidateQualificationProfile()
	if _, err := base.Validate(); err != nil || base.verdictRing() != 1<<20 {
		t.Fatalf("qualification profile ring %d: %v", base.verdictRing(), err)
	}
	if got := sharedGeometryAnnotations(base)["annotations.enforce-exec-shared-verdict-ring"]; got != "1048576" {
		t.Fatalf("verdict-ring annotation %q", got)
	}
	for _, ring := range []uint64{4096, 1 << 20, 1 << 28} {
		p := base
		p.VerdictRing = ring
		if _, err := p.Validate(); err != nil {
			t.Fatalf("ring %d refused: %v", ring, err)
		}
	}
	for _, ring := range []uint64{2048, 3072, 1<<20 + 4096, 1 << 29} {
		p := base
		p.VerdictRing = ring
		if _, err := p.Validate(); err == nil || !strings.Contains(err.Error(), "verdict ring") {
			t.Fatalf("ring %d admitted: %v", ring, err)
		}
	}
	p := base
	p.VerdictRing = 4096
	r := sharedProductManifest(p)
	if err := validateSharedProductControl(p, r); err != nil {
		t.Fatalf("4 KiB ring object: %v", err)
	}
	if err := validateSharedProductControl(base, r); err == nil || !strings.Contains(err.Error(), SharedVerdictRingMap) {
		t.Fatalf("ring/profile mismatch admitted: %v", err)
	}
	delete(r.Maps, SharedVerdictRingMap)
	if err := validateSharedProductControl(p, r); err == nil || !strings.Contains(err.Error(), SharedVerdictRingMap) {
		t.Fatalf("object without the ring admitted: %v", err)
	}
}
