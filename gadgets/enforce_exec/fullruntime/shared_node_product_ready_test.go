// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

// sharedReportingPublisher is the fake publisher with the adoption,
// revision and image-ledger reports a product publisher exposes.
type sharedReportingPublisher struct {
	*sharedFakePublisher
	adoption []SharedAdoptionStatus
	revision []SharedRevisionStatus
	image    error
}

func (p *sharedReportingPublisher) adoptionStatus(slot uint32) (SharedAdoptionStatus, bool) {
	for _, st := range p.adoption {
		if st.Slot == slot {
			return st, true
		}
	}
	return SharedAdoptionStatus{}, false
}

func (p *sharedReportingPublisher) adoptionReport() ([]SharedAdoptionStatus, map[string]uint64) {
	return p.adoption, map[string]uint64{}
}

func (p *sharedReportingPublisher) revisionReport(slot uint32) (SharedRevisionStatus, bool) {
	for _, st := range p.revision {
		if st.Slot == slot {
			return st, true
		}
	}
	return SharedRevisionStatus{}, false
}

func (p *sharedReportingPublisher) revisionReports() []SharedRevisionStatus { return p.revision }

func (p *sharedReportingPublisher) imageHealth() error { return p.image }

// startSharedProductTestNode starts a live product node (product flag, no
// qualification build) over the fake native host, with the reporting
// publisher; the kernel probe is a healthy fake of the first pin.
func startSharedProductTestNode(t *testing.T) (*NodeEnforcer, *sharedFakeNativeHost, *sharedReportingPublisher, *fakeProductKernel) {
	t.Helper()
	sharedProductBuild(t)
	oldNS := sharedNamespaceCheck
	sharedNamespaceCheck = func() error { return nil }
	t.Cleanup(func() { sharedNamespaceCheck = oldNS })
	k := arbitraryProductKernel()
	useProductKernel(t, k)
	host := &sharedFakeNativeHost{manifest: sharedProductExactManifest()}
	pub := &sharedReportingPublisher{sharedFakePublisher: newSharedFakePublisher()}
	seams := host.qualification(func(operators.GadgetContext) (SharedRoutePublisher, error) { return pub, nil })
	n, err := startLiveSharedNode(t.Context(), sharedQualifiedConfig(), host.run, seams, true)
	if err != nil {
		t.Fatalf("product node: %v", err)
	}
	t.Cleanup(func() { _ = n.StopNode(context.WithoutCancel(t.Context())) })
	if !n.host.product || n.host.qualified || !n.host.liveHost() {
		t.Fatalf("product=%v qualified=%v live=%v", n.host.product, n.host.qualified, n.host.liveHost())
	}
	return n, host, pub, k
}

// requireProductReady requires Ready nil and Degraded to match degraded
// (empty: nil).
func requireProductReady(t *testing.T, n *NodeEnforcer, gc operators.GadgetContext, degraded string) {
	t.Helper()
	if err := n.Ready(gc); err != nil {
		t.Fatalf("Ready: %v, want nil", err)
	}
	err := n.Degraded(gc)
	if degraded == "" && err != nil || degraded != "" && (err == nil || !strings.Contains(err.Error(), degraded)) {
		t.Fatalf("Degraded: %v, want %q", err, degraded)
	}
}

// requireProductNotReady requires a typed Ready failure naming reason.
func requireProductNotReady(t *testing.T, n *NodeEnforcer, gc operators.GadgetContext, reason string) error {
	t.Helper()
	err := n.Ready(gc)
	if !errors.Is(err, ErrSharedNodeNotReady) || errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), reason) {
		t.Fatalf("Ready: %v, want ErrSharedNodeNotReady with %q", err, reason)
	}
	return err
}

// TestSharedProductReadySplit (plan 3.5): a healthy product node is Ready
// with zero bindings; each NotReady input fails Ready with
// ErrSharedNodeNotReady; each Degraded input leaves Ready nil and shows in
// Degraded.
func TestSharedProductReadySplit(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		n, host, _, _ := startSharedProductTestNode(t)
		if len(n.bindings) != 0 {
			t.Fatalf("bindings %d", len(n.bindings))
		}
		requireProductReady(t, n, host.gc, "")
		if err := (sharedQualifiedOperator{n}).Ready(host.gc); err != nil {
			t.Fatalf("startup readiness: %v", err)
		}
	})
	t.Run("receipt", func(t *testing.T) {
		n, host, _, _ := startSharedProductTestNode(t)
		host.removedLinkID = n.host.live.receipts["opaque_real_owner_reader_begin_probe"].LinkID
		err := requireProductNotReady(t, n, host.gc, "bpf_lsm_bprm_check_security")
		var notReady *nativeattach.ErrNotReady
		if !errors.As(err, &notReady) {
			t.Fatalf("receipt Ready: %v, want nativeattach.ErrNotReady", err)
		}
	})
	t.Run("reaper", func(t *testing.T) {
		n, host, _, _ := startSharedProductTestNode(t)
		waitReaper(t, "first sweep", func() bool { s, _ := host.reaper.Stats(); return s.Sweeps >= 1 })
		host.reapBackend.events <- reapEvent{cookie: 4, slot: 8, kind: ReapEventTaskDead} // malformed: faults
		<-n.host.live.reaper.waited
		requireProductNotReady(t, n, host.gc, "reaper")
	})
	witnesses := map[string]func(*sharedFakeNativeHost){
		"credit at exit": func(h *sharedFakeNativeHost) {
			h.setExit(func(_ *[ExitCreditCounters]uint64, err *error) { *err = errors.New("exit witness read failed") })
		},
		"exec-capsule": func(h *sharedFakeNativeHost) {
			h.setCapsule(func(_ *[SharedCapsuleCounters]uint64, err *error) { *err = errors.New("capsule witness read failed") })
		},
		"birth-park": func(h *sharedFakeNativeHost) {
			h.setBirthPark(func(_ *[BirthParkStats]uint64, err *error) { *err = errors.New("birth-park witness read failed") })
		},
		"fact witness": func(h *sharedFakeNativeHost) {
			h.setFacts(func(_ *[FactStats]uint64, err *error) { *err = errors.New("fact witness read failed") })
		},
	}
	for name, fail := range witnesses {
		t.Run(name, func(t *testing.T) {
			n, host, _, _ := startSharedProductTestNode(t)
			fail(host)
			requireProductNotReady(t, n, host.gc, "read failed")
		})
	}
	t.Run("strict refused", func(t *testing.T) {
		n, host, _, _ := startSharedProductTestNode(t)
		n.mu.Lock()
		n.host.strictRefused = errors.New("agent pid namespace is not the initial one")
		n.mu.Unlock()
		requireProductNotReady(t, n, host.gc, "strict publication refused")
	})
	t.Run("ftrace flipped after start", func(t *testing.T) {
		n, host, _, k := startSharedProductTestNode(t)
		k.ftrace = "0"
		requireProductNotReady(t, n, host.gc, "ftrace is not enabled")
		k.ftrace = "1"
		requireProductReady(t, n, host.gc, "")
	})
	t.Run("livepatch after start", func(t *testing.T) {
		n, host, _, k := startSharedProductTestNode(t)
		k.tainted = "32768"
		requireProductNotReady(t, n, host.gc, "livepatched")
	})
	t.Run("stopped", func(t *testing.T) {
		n, host, _, _ := startSharedProductTestNode(t)
		if err := n.StopNode(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := n.Ready(host.gc); err == nil {
			t.Fatal("Ready after StopNode")
		}
		if err := n.Degraded(host.gc); err == nil {
			t.Fatal("Degraded after StopNode")
		}
	})
	t.Run("image ledger", func(t *testing.T) {
		n, host, pub, _ := startSharedProductTestNode(t)
		pub.image = errors.New("image ledger count mismatch")
		requireProductReady(t, n, host.gc, "image ledger count mismatch")
	})
	t.Run("adoption", func(t *testing.T) {
		n, host, pub, _ := startSharedProductTestNode(t)
		pub.adoption = []SharedAdoptionStatus{{Slot: 0, Cgroup: 11, Reason: "init gone"}}
		requireProductReady(t, n, host.gc, "adoption refused (init gone")
	})
	t.Run("revision", func(t *testing.T) {
		n, host, pub, _ := startSharedProductTestNode(t)
		pub.revision = []SharedRevisionStatus{{Slot: 1, Reason: RevisionDrainTimeout, Generation: 3}}
		requireProductReady(t, n, host.gc, "revision "+RevisionDrainTimeout)
	})
	t.Run("overlay", func(t *testing.T) {
		n, host, _, _ := startSharedProductTestNode(t)
		reason := fmt.Errorf("overlay module BTF unavailable")
		n.host.overlayFailure.Store(&reason)
		requireProductReady(t, n, host.gc, "FromImage policies refused")
	})
}

// TestSharedProductHealthRouting: the fail-closed witness routes by state
// (Degraded to Degraded, NotReady and Unknown to NotReady), and the
// qualified join keeps every input.
func TestSharedProductHealthRouting(t *testing.T) {
	witness := func(state SharedFailClosedState, fault error) *sharedLiveFailClosed {
		return &sharedLiveFailClosed{gated: true, closed: true, last: SharedFailClosedHealth{State: state}, fault: fault}
	}
	for name, tc := range map[string]struct {
		w                 *sharedLiveFailClosed
		notReady, degrade bool
	}{
		"healthy":  {witness(SharedFailClosedHealthy, nil), false, false},
		"degraded": {witness(SharedFailClosedDegraded, nil), false, true},
		"notready": {witness(SharedFailClosedNotReady, nil), true, false},
		"unknown":  {witness(SharedFailClosedHealthy, fmt.Errorf("read failed: %w", ErrSharedFailClosedUnknown)), true, false},
		"ungated":  {&sharedLiveFailClosed{gated: false, last: SharedFailClosedHealth{State: SharedFailClosedNotReady}}, false, false},
	} {
		h := sharedLiveHealth{failClosed: tc.w}
		notReady, degraded := h.checks()
		if (len(notReady) != 0) != tc.notReady || (len(degraded) != 0) != tc.degrade {
			t.Errorf("%s: notReady %v degraded %v", name, notReady, degraded)
		}
		if err := sharedProductReady(h, nil); (err != nil) != tc.notReady || err != nil && !errors.Is(err, ErrSharedNodeNotReady) {
			t.Errorf("%s: product Ready %v", name, err)
		}
		if err := h.check(); (err != nil) != (tc.notReady || tc.degrade) {
			t.Errorf("%s: qualified check %v", name, err)
		}
	}
	if notReady, _ := (sharedLiveHealth{unavailable: true}).checks(); len(notReady) != 1 || !errors.Is(notReady[0], ErrSharedNativeUnavailable) {
		t.Fatalf("unavailable: %v", notReady)
	}
	if err := (sharedLiveHealth{unavailable: true}).check(); err != ErrSharedNativeUnavailable { //nolint:errorlint // Assert the qualification check still returns the exact sentinel (unchanged behaviour).
		t.Fatalf("unavailable check: %v", err)
	}
}

// TestSharedBindingProtected: the per-binding contract (plan Q6/F4).
func TestSharedBindingProtected(t *testing.T) {
	good := SharedBindingStatus{Attached: true, RouteReserved: true, RoutePublished: true, Generation: 3}
	if err := good.Protected(3); err != nil {
		t.Fatalf("protected binding: %v", err)
	}
	for name, mutate := range map[string]func(*SharedBindingStatus){
		"fault":               func(s *SharedBindingStatus) { s.Fault = errors.New("receipt gone") },
		"not attached":        func(s *SharedBindingStatus) { s.Attached = false },
		"unpublished":         func(s *SharedBindingStatus) { s.RoutePublished = false },
		"withdraw pending":    func(s *SharedBindingStatus) { s.WithdrawPending = true },
		"generation mismatch": func(s *SharedBindingStatus) { s.Generation = 2 },
		"adoption refused":    func(s *SharedBindingStatus) { s.Adoption = &SharedAdoptionStatus{Reason: "init gone"} },
		"removed":             func(s *SharedBindingStatus) { s.Removed = true },
	} {
		s := good
		mutate(&s)
		if err := s.Protected(3); err == nil {
			t.Errorf("%s: protected", name)
		}
	}
	if err := (SharedBindingStatus{Attached: true, RoutePublished: true}).Protected(0); err == nil {
		t.Fatal("generation 0 protected")
	}
}

// TestSharedProductStartupGate (review L2): product startup readiness
// fails only on NotReady inputs, the Strict namespace and the kernel
// controls; a Degraded input (here the image ledger) never fails product
// startup, while the qualification startup still joins it.
func TestSharedProductStartupGate(t *testing.T) {
	start := func(t *testing.T, image error, namespace error, product bool) (*NodeEnforcer, *sharedFakeNativeHost, error) {
		t.Helper()
		if product {
			sharedProductBuild(t)
		} else {
			sharedEnableQualification(t)
		}
		oldNS := sharedNamespaceCheck
		sharedNamespaceCheck = func() error { return namespace }
		t.Cleanup(func() { sharedNamespaceCheck = oldNS })
		useProductKernel(t, arbitraryProductKernel())
		manifest := sharedProductExactManifest()
		if !product {
			manifest = sharedProductFakeManifest()
		}
		host := &sharedFakeNativeHost{manifest: manifest}
		pub := &sharedReportingPublisher{sharedFakePublisher: newSharedFakePublisher(), image: image}
		seams := host.qualification(func(operators.GadgetContext) (SharedRoutePublisher, error) { return pub, nil })
		n, err := startLiveSharedNode(t.Context(), sharedQualifiedConfig(), host.run, seams, product)
		if n != nil {
			t.Cleanup(func() { _ = n.StopNode(context.WithoutCancel(t.Context())) })
		}
		return n, host, err
	}
	ledger := errors.New("image ledger count mismatch")
	t.Run("product, Degraded at startup", func(t *testing.T) {
		n, host, err := start(t, ledger, nil, true)
		if err != nil {
			t.Fatalf("product startup failed on a Degraded input: %v", err)
		}
		requireProductReady(t, n, host.gc, "image ledger count mismatch")
	})
	t.Run("product, Strict namespace refused", func(t *testing.T) {
		_, host, err := start(t, nil, errors.New("agent pid namespace is not the initial one"), true)
		if !errors.Is(err, ErrSharedNodeNotReady) || !strings.Contains(err.Error(), "strict publication refused") || host.stops != 1 {
			t.Fatalf("product startup: %v stops %d, want a typed refusal and teardown", err, host.stops)
		}
	})
	t.Run("qualification, Degraded at startup", func(t *testing.T) {
		_, _, err := start(t, ledger, nil, false)
		if err == nil || !strings.Contains(err.Error(), "image ledger count mismatch") {
			t.Fatalf("qualification startup: %v, want the joined Degraded input", err)
		}
	})
}
