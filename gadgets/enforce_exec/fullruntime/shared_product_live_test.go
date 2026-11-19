// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedProductFakeManifest is a non-recovery product-publisher object of
// the qualification profile (its exact product geometry and commands).
func sharedProductFakeManifest() *operators.NativeResources {
	return sharedProductManifest(sharedCandidateQualificationProfile())
}

// TestSharedLiveProductSelection (G1): only an object carrying all 8 product
// commands selects the product publisher.
func TestSharedLiveProductSelection(t *testing.T) {
	if sharedHasProductCommands(sharedCandidateFakeManifest()) || sharedHasProductCommands(nil) {
		t.Fatal("object without the publisher selected the product publisher")
	}
	r := sharedProductFakeManifest()
	if !sharedHasProductCommands(r) {
		t.Fatal("object with the publisher not selected")
	}
	delete(r.Programs, "opaque_real_adopt_quarantine")
	if sharedHasProductCommands(r) {
		t.Fatal("7 of 8 commands selected the product publisher")
	}
}

// TestSharedSlotThreads (G1): a slot's tids come from its owning account's
// retained cgroup pin; an unbound slot, or an agent outside the initial pid
// namespace, is an error, never empty.
func TestSharedSlotThreads(t *testing.T) {
	n, _, a, _ := sharedStartPublishingNode(t, newSharedFakePublisher())
	defer func() { _ = n.StopNode(t.Context()) }()
	slot := a.Inspect().RouteSlot
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.threads"), []byte("1\n42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	a.account.mu.Lock()
	old := a.account.pins.cgroup
	a.account.pins.cgroup = pin
	a.account.mu.Unlock()
	defer func() { a.account.mu.Lock(); a.account.pins.cgroup = old; a.account.mu.Unlock() }()
	if tids, err := n.slotThreads(slot); err != nil || !reflect.DeepEqual(tids, []uint32{1, 42}) {
		t.Fatalf("slot %d tids %v %v", slot, tids, err)
	}
	n.mu.Lock()
	n.host.strictRefused = errors.New("agent pid namespace is not the initial one")
	n.mu.Unlock()
	if _, err := n.slotThreads(slot); err == nil || !strings.Contains(err.Error(), "init-namespace") {
		t.Fatalf("outside the initial pid namespace: %v", err)
	}
	n.mu.Lock()
	n.host.strictRefused = nil
	n.mu.Unlock()
	if err := os.Remove(filepath.Join(dir, "cgroup.threads")); err != nil {
		t.Fatal(err)
	}
	if _, err := n.slotThreads(slot); !errors.Is(err, errCgroupGone) {
		t.Fatalf("removed cgroup: %v", err)
	}
	if _, err := n.slotThreads(uint32(len(n.host.scopeSlots))); err == nil {
		t.Fatal("unbound slot listed")
	}
}

// TestSharedBorrowProductPublisherMissingHandles: a gadget context without
// the published commands or maps builds no publisher.
func TestSharedBorrowProductPublisherMissingHandles(t *testing.T) {
	n, host, _, _ := sharedStartPublishingNode(t, newSharedFakePublisher())
	defer func() { _ = n.StopNode(t.Context()) }()
	if p, err := n.borrowSharedProductPublisher(host.gc, sharedProductFakeManifest()); p != nil || err == nil || !strings.Contains(err.Error(), "was not published") {
		t.Fatalf("missing handles: %v %v", p, err)
	}
}

// TestSharedBuildProductPublisher: the builder installs the admin thread and
// returns a working publisher; a control that fails after its thread
// started is closed.
func TestSharedBuildProductPublisher(t *testing.T) {
	p := sharedCandidateQualificationProfile()
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: p, ABI3Development: true, Image: "local/shared-candidate:abi3-development"})
	if err != nil {
		t.Fatal(err)
	}
	maps := func() (sharedBytesMap, sharedBytesMap, sharedBytesMap) {
		return &sharedFakeBytesMap{size: sharedProductRouteAnchorBytes}, &sharedFakeBytesMap{size: sharedProductObjectBytes}, &sharedFakeBytesMap{size: sharedProductAdoptStateBytes}
	}
	programs, _ := sharedProductPrograms()
	routes, objects, state := maps()
	pub, err := n.buildSharedProductPublisher(t.Context(), sharedProductManifest(p), programs, &sharedFakeAdminMap{}, &sharedFakeAdminMap{}, routes, objects, state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pub.Route(0); !errors.Is(err, ErrSharedRouteFree) {
		t.Fatalf("route of a fresh slot: %v", err)
	}
	if err := pub.Close(); err != nil {
		t.Fatal(err)
	}
	var captured *sharedProductControl
	old := sharedNewProductControl
	sharedNewProductControl = func(ctx context.Context, p SharedProfile, m *operators.NativeResources, admin sharedAdminMap, c sharedProductConfigMap, progs map[string]sharedCommandProgram) (*sharedProductControl, error) {
		control, err := old(ctx, p, m, admin, c, progs)
		captured = control
		return control, err
	}
	defer func() { sharedNewProductControl = old }()
	routes, objects, state = maps()
	if pub, err := n.buildSharedProductPublisher(t.Context(), sharedProductManifest(p), programs, &sharedFakeAdminMap{putErr: errors.New("EPERM")}, &sharedFakeAdminMap{}, routes, objects, state); pub != nil || err == nil {
		t.Fatalf("admin install failure: %v %v", pub, err)
	}
	// A context canceled after a successful install (inside the last
	// install step): the control's admin thread is running and the builder
	// must close it.
	captured = nil
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	routes, objects, state = maps()
	configuration := &sharedCancelOnFreeze{sharedFakeAdminMap: &sharedFakeAdminMap{}, cancel: cancel}
	if pub, err := n.buildSharedProductPublisher(ctx, sharedProductManifest(p), programs, &sharedFakeAdminMap{}, configuration, routes, objects, state); pub != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled after install: %v %v", pub, err)
	}
	if captured == nil || !configuration.frozen {
		t.Fatal("control not installed")
	}
	if _, err := captured.run(t.Context(), "opaque_real_route_publish", nil); !errors.Is(err, ErrControlClosed) {
		t.Fatalf("the abandoned control's admin thread: %v, want ErrControlClosed", err)
	}
}

// TestSharedLiveProductPublisherCloseOrder: Close joins every poller before
// it ends the admin thread.
func TestSharedLiveProductPublisherCloseOrder(t *testing.T) {
	var mu sync.Mutex
	var log []string
	note := func(s string) { mu.Lock(); log = append(log, s); mu.Unlock() }
	cmd := &sharedFakeCommander{verifyCode: sharedProductRefused}
	threads := &sharedFakeThreads{tids: []uint32{7}}
	inner, _ := newTestProductPublisher(cmd, threads)
	list := inner.threads
	inner.threads = func(slot uint32) ([]uint32, error) { note("poll"); return list(slot) }
	p := &sharedLiveProductPublisher{productRoutePublisher: inner, closeControl: func() error { note("control"); return nil }}
	if _, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, true, sharedTestInit); err == nil {
		t.Fatal("refused adoption published")
	}
	waitFor(t, "poller", func() bool { mu.Lock(); defer mu.Unlock(); return len(log) >= 2 })
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if log[len(log)-1] != "control" || strings.Count(strings.Join(log, ","), "control") != 1 {
		t.Fatalf("close order %v: the admin thread must end after every poller", log)
	}
}

// sharedClosingPublisher counts Close calls and can fail them.
type sharedClosingPublisher struct {
	*sharedFakePublisher
	mu       sync.Mutex
	closes   int
	closeErr error
}

func (p *sharedClosingPublisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes++
	return p.closeErr
}

func (p *sharedClosingPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closes
}

// TestSharedNodeProductPublisherLifecycle (G1 branch): a product object
// selects the product publisher, built before the reaper; a refused
// publisher starts no reaper, a refused reaper closes the publisher, a node
// that is stopping or already live closes the new publisher, Stop(gc)
// closes it, and a publisher Close failure never blocks teardown.
func TestSharedNodeProductPublisherLifecycle(t *testing.T) {
	start := func(t *testing.T, host *sharedFakeNativeHost, factory func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error)) (*NodeEnforcer, error) {
		t.Helper()
		sharedEnableQualification(t)
		q := host.qualification(nil)
		q.newProductPublisher = factory
		return StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig())
	}
	t.Run("selected and closed once", func(t *testing.T) {
		pub := &sharedClosingPublisher{sharedFakePublisher: newSharedFakePublisher()}
		host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
		n, err := start(t, host, func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			return pub, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := n.livePublisher(false); got != pub {
			t.Fatalf("live publisher %T, want the product publisher", got)
		}
		// Already live, then stopping: the extra publisher is closed.
		extra := &sharedClosingPublisher{sharedFakePublisher: newSharedFakePublisher()}
		n.host.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			return extra, nil
		}
		if err := n.startLiveCandidate(host.gc, host.manifest); err == nil || !strings.Contains(err.Error(), "already live") || extra.count() != 1 {
			t.Fatalf("already live: %v closes %d", err, extra.count())
		}
		n.mu.Lock()
		n.closing = true
		n.mu.Unlock()
		if err := n.startLiveCandidate(host.gc, host.manifest); err == nil || !strings.Contains(err.Error(), "node stopping") || extra.count() != 2 {
			t.Fatalf("stopping: %v closes %d", err, extra.count())
		}
		n.mu.Lock()
		n.closing = false
		n.mu.Unlock()
		if err := n.Stop(host.gc); err != nil && !errors.Is(err, ErrSharedNativeUnavailable) {
			t.Logf("Stop: %v", err)
		}
		if pub.count() != 1 {
			t.Fatalf("Stop(gc) closed the publisher %d times", pub.count())
		}
		if err := n.StopNode(t.Context()); err != nil {
			t.Fatal(err)
		}
		if pub.count() != 1 {
			t.Fatalf("publisher closed %d times", pub.count())
		}
	})
	t.Run("refused publisher starts no reaper", func(t *testing.T) {
		host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
		_, err := start(t, host, func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			return nil, errors.New("admin install refused")
		})
		if err == nil || !strings.Contains(err.Error(), "admin install refused") || host.reaper != nil {
			t.Fatalf("refused publisher: %v reaper %v", err, host.reaper)
		}
	})
	t.Run("refused reaper closes the publisher", func(t *testing.T) {
		pub := &sharedClosingPublisher{sharedFakePublisher: newSharedFakePublisher()}
		host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest(), reaperErr: errors.New("no reaper")}
		if _, err := start(t, host, func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			return pub, nil
		}); err == nil || pub.count() != 1 {
			t.Fatalf("refused reaper: %v closes %d", err, pub.count())
		}
	})
	t.Run("publisher close failure never blocks teardown", func(t *testing.T) {
		pub := &sharedClosingPublisher{sharedFakePublisher: newSharedFakePublisher(), closeErr: errors.New("admin thread failed")}
		host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
		n, err := start(t, host, func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			return pub, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.StopNode(t.Context()); err == nil || !strings.Contains(err.Error(), "admin thread failed") {
			t.Fatalf("StopNode: %v", err)
		}
		n.mu.Lock()
		stopped, released, scopes := n.host.gadgetStopped, n.host.released, len(n.scopes)
		n.mu.Unlock()
		if !stopped || !released || scopes != 0 || host.stops != 1 || pub.count() != 1 {
			t.Fatalf("teardown blocked: stopped %v released %v scopes %d stops %d closes %d", stopped, released, scopes, host.stops, pub.count())
		}
	})
}

// sharedCancelOnFreeze cancels a context when the configuration map is
// frozen: the last step of a successful admin install.
type sharedCancelOnFreeze struct {
	*sharedFakeAdminMap
	cancel context.CancelFunc
}

func (m *sharedCancelOnFreeze) Freeze() error {
	err := m.sharedFakeAdminMap.Freeze()
	m.cancel()
	return err
}

// TestSharedStopWithdrawsBeforeClosingPublisher: an operator-driven
// teardown (Stop(gc)) removes the sessions, withdrawing their routes while
// the publisher is alive, and only then closes the publisher.
func TestSharedStopWithdrawsBeforeClosingPublisher(t *testing.T) {
	inner := newSharedFakePublisher()
	pub := &sharedOrderedPublisher{sharedFakePublisher: inner}
	n, host, a, b := sharedStartPublishingNode(t, inner)
	n.mu.Lock()
	n.host.live.publisher = pub
	n.mu.Unlock()
	slotA, slotB := a.Inspect().RouteSlot, b.Inspect().RouteSlot
	if err := n.Stop(host.gc); err != nil && !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Logf("Stop: %v", err)
	}
	if !pub.closed || !pub.withdrawnAtClose[slotA] || !pub.withdrawnAtClose[slotB] {
		t.Fatalf("Stop(gc): closed %v, withdrawn at close %v: routes must be withdrawn before the publisher closes", pub.closed, pub.withdrawnAtClose)
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// sharedOrderedPublisher records which routes were withdrawn when it closed.
type sharedOrderedPublisher struct {
	*sharedFakePublisher
	closed           bool
	withdrawnAtClose map[uint32]bool
}

func (p *sharedOrderedPublisher) Close() error {
	p.closed = true
	p.withdrawnAtClose = maps.Clone(p.withdrawn)
	return nil
}

// TestSharedNodePublisherSelectionPaths (chain12 regression): a qualified
// node with a Publisher override and a product object uses the override and
// never builds the product publisher; a non-product object builds none; a
// product factory failing with a typed nil fails startup without a panic;
// a recovery object is refused by name.
func TestSharedNodePublisherSelectionPaths(t *testing.T) {
	start := func(t *testing.T, manifest *operators.NativeResources, override func(operators.GadgetContext) (SharedRoutePublisher, error), product func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error)) (*NodeEnforcer, *sharedFakeNativeHost, error) {
		t.Helper()
		sharedEnableQualification(t)
		host := &sharedFakeNativeHost{manifest: manifest}
		q := host.qualification(override)
		q.newProductPublisher = product
		n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig())
		return n, host, err
	}
	productCalls := 0
	product := func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
		productCalls++
		return &sharedClosingPublisher{sharedFakePublisher: newSharedFakePublisher()}, nil
	}
	t.Run("override wins on a product object", func(t *testing.T) {
		override := newSharedFakePublisher()
		n, _, err := start(t, sharedProductFakeManifest(), func(operators.GadgetContext) (SharedRoutePublisher, error) { return override, nil }, product)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := n.livePublisher(false); got != override || productCalls != 0 {
			t.Fatalf("publisher %T, product factory calls %d", got, productCalls)
		}
		if err := n.StopNode(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("non-product object builds no publisher", func(t *testing.T) {
		n, _, err := start(t, sharedCandidateFakeManifest(), nil, product)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.livePublisher(false); !errors.Is(err, ErrSharedNativeUnavailable) || productCalls != 0 {
			t.Fatalf("publisher %v, product factory calls %d", err, productCalls)
		}
		if err := n.StopNode(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("typed nil from a failing factory", func(t *testing.T) {
		_, host, err := start(t, sharedProductFakeManifest(), nil, func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			var typed *sharedLiveProductPublisher
			return typed, errors.New("admission refused")
		})
		if err == nil || !strings.Contains(err.Error(), "admission refused") || host.stops != 1 {
			t.Fatalf("typed-nil startup: %v stops %d", err, host.stops)
		}
	})
	t.Run("nil-safe Close", func(t *testing.T) {
		var typed *sharedLiveProductPublisher
		if err := typed.Close(); err != nil {
			t.Fatal(err)
		}
		if err := (&sharedLiveProductPublisher{}).Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("recovery object refused", func(t *testing.T) {
		n, host, _, _ := sharedStartPublishingNode(t, newSharedFakePublisher())
		defer func() { _ = n.StopNode(t.Context()) }()
		recovery := sharedProductFakeManifest()
		recovery.Maps["se_rm_control"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: 1}
		// Refused before any handle is borrowed.
		if p, err := n.borrowSharedProductPublisher(host.gc, recovery); p != nil || err == nil || !strings.Contains(err.Error(), "recovery object") {
			t.Fatalf("recovery object: %v %v", p, err)
		}
	})
}

// TestSharedRefusedAdoptionsFreeSlots: the slot of a refused adoption is
// freed once its poller withdrew and recycled it: two refused containers on
// a 2-binding node, then a third container binds and publishes.
func TestSharedRefusedAdoptionsFreeSlots(t *testing.T) {
	cmd := &sharedFakeCommander{verifyCode: sharedProductRefused, routeState: SharedRouteState{Scope: 5, Generation: 1, Serial: 1, Incarnation: 1, Class: 2, Phase: 2}, routeAdopting: true}
	threads := &sharedFakeThreads{gone: true} // the refused containers' cgroups are gone: released at once
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
	q := host.qualification(nil)
	q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
		p, _ := newTestProductPublisher(cmd, threads)
		return &sharedLiveProductPublisher{productRoutePublisher: p, closeControl: func() error { return nil }}, nil
	}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	lease := func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }
	var refused []*BindingSession
	for i, cgroup := range []uint64{31, 32} {
		cmd.mu.Lock()
		cmd.routeState.Cgroup = cgroup
		cmd.mu.Unlock()
		s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: cgroup, InitHostPID: 1, Acquire: lease})
		if err != nil {
			t.Fatalf("container %d bind: %v", i, err)
		}
		var adoption *ErrSharedAdoptionRefused
		if _, err := s.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}); !errors.As(err, &adoption) {
			t.Fatalf("container %d publish: %v", i, err)
		}
		refused = append(refused, s)
	}
	// Container 0 is removed before its poller releases or after: either
	// way its slot is freed and its account retired.
	if err := refused[0].Remove(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	for _, s := range refused {
		waitFor(t, "released", func() bool { s.account.mu.Lock(); defer s.account.mu.Unlock(); return s.account.released })
	}
	if err := refused[1].Remove(t.Context(), 1); err != nil {
		t.Fatalf("Remove after the release: %v", err)
	}
	for _, s := range refused {
		waitFor(t, "retired", func() bool { s.account.mu.Lock(); defer s.account.mu.Unlock(); return s.account.retired })
	}
	cmd.mu.Lock()
	cmd.verifyCode, cmd.routeAdopting, cmd.routeState.Cgroup = sharedProductOK, false, 33
	cmd.mu.Unlock()
	threads.set([]uint32{1}, false) // the third container's init (pinned TGID 1)
	c, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 33, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatalf("third container: %v", err)
	}
	if _, err := c.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}); err != nil {
		t.Fatalf("third container publish: %v", err)
	}
	for _, s := range refused {
		if r, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: s.cgroup, InitHostPID: 1, Acquire: lease}); r != nil || !errors.Is(err, ErrSharedBindingWithdrawn) {
			t.Fatalf("rebind of refused cgroup %d: %v", s.cgroup, err)
		}
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestSharedBorrowNeverReturnsTypedNil pins the borrow's error return (the
// chain12 panic: a typed nil *sharedLiveProductPublisher in the interface)
// and the startup check that discards a typed nil returned without an error.
func TestSharedBorrowNeverReturnsTypedNil(t *testing.T) {
	raw, err := os.ReadFile("shared_product_live.go")
	if err != nil {
		t.Fatal(err)
	}
	pin := "p, err := n.buildSharedProductPublisher("
	ret := "if err != nil {\n\t\treturn nil, err // never a typed nil in the interface\n\t}\n\tif err := n.withImageIndex(p, maps[sharedImageBindingsMap]); err != nil {\n\t\treturn nil, errors.Join(err, p.Close())\n\t}\n\treturn p.withBindings(maps[\"se_bindings\"]), nil"
	if strings.Count(squashSpace(string(raw)), squashSpace(pin)) != 1 || strings.Count(squashSpace(string(raw)), squashSpace(ret)) != 1 {
		t.Fatal("borrowSharedProductPublisher must return an untyped nil on error")
	}
	var typed *sharedLiveProductPublisher
	if !sharedNilPublisher(typed) || !sharedNilPublisher(nil) || sharedNilPublisher(newSharedFakePublisher()) {
		t.Fatal("sharedNilPublisher misclassifies")
	}
	_, host, err := func() (*NodeEnforcer, *sharedFakeNativeHost, error) {
		sharedEnableQualification(t)
		host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
		q := host.qualification(nil)
		q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			return typed, nil // a typed nil WITHOUT an error
		}
		n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig())
		return n, host, err
	}()
	if err == nil || !strings.Contains(err.Error(), "route publisher unavailable") || host.stops != 1 {
		t.Fatalf("typed nil without an error: %v", err)
	}
}

// TestSharedAdmittedManifestKeepsTailCalls (review H1): the node's admitted
// copy keeps the tail-call slots, so the product control built from it at
// startup passes its own validation; and a product object without them is
// refused at pre-load admission.
func TestSharedAdmittedManifestKeepsTailCalls(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
	q := host.qualification(nil)
	q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
		return newSharedFakePublisher(), nil
	}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.StopNode(t.Context()) }()
	n.mu.Lock()
	admitted := n.host.admitted
	n.mu.Unlock()
	if !reflect.DeepEqual(admitted.TailCalls, sharedProductTailCalls) {
		t.Fatalf("admitted tail calls %+v", admitted.TailCalls)
	}
	programs, _ := sharedProductPrograms()
	pub, err := n.buildSharedProductPublisher(t.Context(), admitted, programs, &sharedFakeAdminMap{}, &sharedFakeAdminMap{},
		&sharedFakeBytesMap{size: sharedProductRouteAnchorBytes}, &sharedFakeBytesMap{size: sharedProductObjectBytes}, &sharedFakeBytesMap{size: sharedProductAdoptStateBytes})
	if err != nil {
		t.Fatalf("product control over the admitted manifest: %v", err)
	}
	if err := pub.Close(); err != nil {
		t.Fatal(err)
	}

	missing := sharedProductFakeManifest()
	missing.TailCalls = nil
	host2 := &sharedFakeNativeHost{manifest: missing}
	q2 := host2.qualification(nil)
	q2.newProductPublisher = q.newProductPublisher
	if n2, err := StartNode(WithSharedNodeQualification(t.Context(), q2), sharedQualifiedConfig()); err == nil || !strings.Contains(err.Error(), "not installed") {
		if n2 != nil {
			_ = n2.StopNode(t.Context())
		}
		t.Fatalf("product object without tail calls admitted: %v", err)
	}
}

// TestSharedProductCapsuleStoreAdmission (G019 chain16): a product object
// whose exec-capsule store is not per-task storage (the build's one-entry
// array) is refused at pre-load admission; it would degrade every exec.
func TestSharedProductCapsuleStoreAdmission(t *testing.T) {
	sharedEnableQualification(t)
	small := sharedProductFakeManifest()
	small.Maps["se_exec_capsules"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 104, MaxEntries: 1}
	host := &sharedFakeNativeHost{manifest: small}
	q := host.qualification(nil)
	q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
		return newSharedFakePublisher(), nil
	}
	if n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig()); err == nil || !strings.Contains(err.Error(), "se_exec_capsules") {
		if n != nil {
			_ = n.StopNode(t.Context())
		}
		t.Fatalf("product object with a one-entry capsule store admitted: %v", err)
	}
}

// TestSharedProductWorkSyncAdmission (G019 lead decision (b)): a product
// object without the synchronous WORK return witness (opaque_real_work_sync)
// is refused at pre-load admission; its burst capacity would rest on the
// test-only non-sync branch of ConcurrentBirthCapacity.
func TestSharedProductWorkSyncAdmission(t *testing.T) {
	sharedEnableQualification(t)
	nosync := sharedProductFakeManifest()
	delete(nosync.Maps, WorkSyncWitnessMap)
	host := &sharedFakeNativeHost{manifest: nosync}
	q := host.qualification(nil)
	q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
		return newSharedFakePublisher(), nil
	}
	if n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig()); err == nil || !strings.Contains(err.Error(), WorkSyncWitnessMap) {
		if n != nil {
			_ = n.StopNode(t.Context())
		}
		t.Fatalf("product object without the synchronous WORK return admitted: %v", err)
	}
	if host.runs != 1 || len(host.attached) != 0 {
		t.Fatalf("refused product object attached: runs=%d attached=%d", host.runs, len(host.attached))
	}
}

// TestSharedProductTestGateAdmission (review L3): a product-publisher object
// carrying the userspace-writable test gate (opaque_real_owner_child_gate) is
// refused at pre-load admission, before anything is loaded or attached and
// before the product control is built.
func TestSharedProductTestGateAdmission(t *testing.T) {
	sharedEnableQualification(t)
	gated := sharedProductFakeManifest()
	gated.Maps[sharedProductTestGateMaps[0]] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 4, MaxEntries: 1}
	host := &sharedFakeNativeHost{manifest: gated}
	q := host.qualification(nil)
	built := false
	q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
		built = true
		return newSharedFakePublisher(), nil
	}
	if n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig()); err == nil || !strings.Contains(err.Error(), "test gate "+sharedProductTestGateMaps[0]) {
		if n != nil {
			_ = n.StopNode(t.Context())
		}
		t.Fatalf("product object with the test gate admitted: %v", err)
	}
	if host.runs != 1 || len(host.attached) != 0 || built {
		t.Fatalf("refused product object attached or built: runs=%d attached=%d built=%v", host.runs, len(host.attached), built)
	}
}
