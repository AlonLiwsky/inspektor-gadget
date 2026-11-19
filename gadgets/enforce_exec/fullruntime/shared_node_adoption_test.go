// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedStartProductNode starts a fake-host node whose publisher is a
// productRoutePublisher over cmd, with one binding on cgroup 21.
func sharedStartProductNode(t *testing.T, cmd *sharedFakeCommander, threads *sharedFakeThreads) (*NodeEnforcer, *sharedFakeNativeHost, *BindingSession, *productRoutePublisher) {
	t.Helper()
	sharedEnableQualification(t)
	p, _ := newTestProductPublisher(cmd, threads)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(
		func(operators.GadgetContext) (SharedRoutePublisher, error) { return p, nil })), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	lease := func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatal(err)
	}
	return n, host, a, p
}

// TestSharedRemoveNeverWithdrawsFailedAdoption (review I-1): after a refused
// Strict adoption the kernel route is ACTIVE with adopting set (latched).
// Remove must not withdraw it (WITHDRAWN is UNSELECTED: allow); it reports
// withdraw pending, and only the poller releases the slot once the cgroup
// is empty. The adoption is reported through Inspect, Ready and the
// counters until then.
func TestSharedRemoveNeverWithdrawsFailedAdoption(t *testing.T) {
	cmd := &sharedFakeCommander{
		finishCode: sharedProductRefused, finishDetail: sharedFinishDetail{Iterated: 1, Adopted: 2},
		routeState: SharedRouteState{Cgroup: 21, Scope: 5, Generation: 1, Serial: 1, Incarnation: 1, Class: 2, Phase: 2}, routeAdopting: true,
	}
	threads := &sharedFakeThreads{tids: []uint32{1, 9}}
	n, host, a, p := sharedStartProductNode(t, cmd, threads)
	_, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1})
	var refused *ErrSharedAdoptionRefused
	if !errors.As(err, &refused) || refused.Reason != AdoptionThreadExited || refused.Audit {
		t.Fatalf("publish: %v", err)
	}
	st := a.Inspect()
	if !st.RoutePublished || st.Fault == nil || st.Adoption == nil || st.Adoption.Reason != AdoptionThreadExited || st.Adoption.InitTGID != 1 {
		t.Fatalf("A after a refused adoption: %+v adoption %+v", st, st.Adoption)
	}
	if err := n.Ready(host.gc); err == nil || !strings.Contains(err.Error(), "adoption refused (AdoptionThreadExited") {
		t.Fatalf("Ready does not report the refused adoption: %v", err)
	}
	if _, counts, err := n.AdoptionReport(); err != nil || counts[AdoptionThreadExited] != 1 {
		t.Fatalf("counters %v %v", counts, err)
	}
	if err := a.Remove(t.Context(), 1); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if st := a.Inspect(); !st.Removed || !st.WithdrawPending {
		t.Fatalf("A after Remove: %+v", st)
	}
	if strings.Contains(strings.Join(cmd.log(), ","), "withdraw") {
		t.Fatalf("Remove withdrew a latched Strict route: %v", cmd.log())
	}
	// The poller alone releases it once the cgroup is empty.
	threads.set(nil, true)
	waitFor(t, "poller release", func() bool { _, r := p.adoptionStatus(0); return !r })
	if log := strings.Join(cmd.log(), ","); !strings.HasSuffix(log, "withdraw,recycle") || strings.Count(log, "withdraw") != 1 {
		t.Fatalf("release %s", log)
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestProductPublisherWithdrawGuards: Withdraw refuses a reported slot and a
// kernel anchor still Strict and adopting (pending, never a withdraw).
func TestProductPublisherWithdrawGuards(t *testing.T) {
	cmd := &sharedFakeCommander{routeState: SharedRouteState{Class: 2}, routeAdopting: true}
	p, _ := newTestProductPublisher(cmd, &sharedFakeThreads{})
	defer p.Close()
	if err := p.Withdraw(t.Context(), 0, 11); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("adopting Strict withdraw: %v", err)
	}
	cmd.routeState.Class = 1
	if err := p.Withdraw(t.Context(), 0, 11); err != nil {
		t.Fatalf("adopting Audit withdraw: %v", err)
	}
	p.status[3] = &SharedAdoptionStatus{Reason: AdoptionRefusedIdentity, Cgroup: 11}
	if err := p.Withdraw(t.Context(), 3, 11); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("reported slot withdraw: %v", err)
	}
	if err := p.Recycle(t.Context(), 3, 11); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("reported slot recycle: %v", err)
	}
	if n := strings.Count(strings.Join(cmd.log(), ","), "withdraw"); n != 1 {
		t.Fatalf("%d withdraws, want only the Audit one", n)
	}
	// A report is its cgroup's only: another cgroup on the slot (after the
	// slot was freed and reused) is not blocked by it.
	if err := p.Withdraw(t.Context(), 3, 12); err != nil {
		t.Fatalf("another cgroup's withdraw blocked by a stale report: %v", err)
	}
	if err := p.Recycle(t.Context(), 3, 12); err != nil {
		t.Fatalf("another cgroup's recycle blocked by a stale report: %v", err)
	}
}

// sharedFakeRecycler adds G4 recycling to the fake publisher: Recycle pops
// scripted results (contended first), then succeeds.
type sharedFakeRecycler struct {
	*sharedFakePublisher
	mu       sync.Mutex
	results  []error
	recycled map[uint32]int
}

func (p *sharedFakeRecycler) Recycle(_ context.Context, slot uint32, _ uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recycled[slot]++
	if len(p.results) == 0 {
		return nil
	}
	err := p.results[0]
	p.results = p.results[1:]
	return err
}

// TestSharedRemoveRecyclesSlot (review I-4): a normal Remove withdraws, then
// recycles in the background (retrying while contended) and frees the slot
// for a new binding; the withdrawn cgroup stays terminal.
func TestSharedRemoveRecyclesSlot(t *testing.T) {
	pub := &sharedFakeRecycler{sharedFakePublisher: newSharedFakePublisher(), results: []error{errSharedRecycleContended, errSharedRecycleContended}, recycled: map[uint32]int{}}
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(
		func(operators.GadgetContext) (SharedRoutePublisher, error) { return pub, nil })), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	lease := func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}); err != nil {
		t.Fatal(err)
	}
	slot := a.Inspect().RouteSlot
	if err := a.Remove(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "slot freed", func() bool {
		n.mu.Lock()
		defer n.mu.Unlock()
		return n.host.scopeSlots[slot] == nil
	})
	pub.mu.Lock()
	recycles := pub.recycled[slot]
	pub.mu.Unlock()
	if recycles != 3 || !pub.withdrawn[slot] {
		t.Fatalf("recycles %d (want 2 contended + 1), withdrawn %v", recycles, pub.withdrawn[slot])
	}
	if s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 1, Acquire: lease}); s != nil || !errors.Is(err, ErrSharedBindingWithdrawn) {
		t.Fatalf("rebind of the withdrawn cgroup: %v %v", s, err)
	}
	b, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 22, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Inspect().RouteSlot; got != slot {
		// Bind reserves the lowest free slot: the recycled one.
		t.Fatalf("new binding on slot %d, want the recycled %d", got, slot)
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := n.liveHealthFault(); err != nil {
		t.Fatalf("recycle fault: %v", err)
	}
}

// TestSharedRecycleRefusalKeepsSlot: a recycle refused for any other reason
// keeps the slot reserved (never reused) and is a sticky node fault.
func TestSharedRecycleRefusalKeepsSlot(t *testing.T) {
	pub := &sharedFakeRecycler{sharedFakePublisher: newSharedFakePublisher(), results: []error{errors.New("route latched")}, recycled: map[uint32]int{}}
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(
		func(operators.GadgetContext) (SharedRoutePublisher, error) { return pub, nil })), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}); err != nil {
		t.Fatal(err)
	}
	slot := a.Inspect().RouteSlot
	if err := a.Remove(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "recycle fault", func() bool { return n.liveHealthFault() != nil })
	n.mu.Lock()
	kept := n.host.scopeSlots[slot] == a.account
	n.mu.Unlock()
	if !kept {
		t.Fatal("refused recycle released the slot")
	}
	if err := n.StopNode(t.Context()); err == nil || !strings.Contains(err.Error(), "route latched") {
		t.Fatalf("StopNode does not report the recycle fault: %v", err)
	}
}

// TestSharedStrictRefusedOutsideInitNamespaces (review M-2, design 13.8).
func TestSharedStrictRefusedOutsideInitNamespaces(t *testing.T) {
	pub := newSharedFakePublisher()
	sharedEnableQualification(t)
	sharedNamespaceCheck = func() error { return errors.New("agent pid namespace 4026532001 is not the initial one") }
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(
		func(operators.GadgetContext) (SharedRoutePublisher, error) { return pub, nil })), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("Strict outside the initial namespaces: %v", err)
	}
	if len(pub.publishes) != 0 {
		t.Fatal("a refused Strict publication reached the publisher")
	}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSharedInitNamespacesOnHost(t *testing.T) {
	err := checkSharedInitNamespaces()
	t.Logf("agent namespaces: %v", err)
	if err != nil && !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("unexpected error form: %v", err)
	}
}

// TestSharedRecycleRefusedAfterStop: once the recycle loops are being
// joined (stopRecycles), a later withdrawal starts no recycle (no
// WaitGroup Add during the Wait) and its slot stays reserved until the
// collection is destroyed.
func TestSharedRecycleRefusedAfterStop(t *testing.T) {
	pub := &sharedFakeRecycler{sharedFakePublisher: newSharedFakePublisher(), recycled: map[uint32]int{}}
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(
		func(operators.GadgetContext) (SharedRoutePublisher, error) { return pub, nil })), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}); err != nil {
		t.Fatal(err)
	}
	slot := a.Inspect().RouteSlot
	n.stopRecycles(n.host.live)
	if err := a.Remove(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if !pub.withdrawn[slot] {
		t.Fatal("route not withdrawn")
	}
	time.Sleep(50 * time.Millisecond)
	pub.mu.Lock()
	recycles := pub.recycled[slot]
	pub.mu.Unlock()
	n.mu.Lock()
	kept := n.host.scopeSlots[slot] == a.account
	n.mu.Unlock()
	if recycles != 0 || !kept {
		t.Fatalf("after stopRecycles: %d recycles, slot kept %v", recycles, kept)
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestSharedRecycledAccountsRetire: a withdrawn account whose slot was
// recycled releases its pins and binding capacity (a retired tombstone), so
// a node keeps binding new cgroups across many container lifetimes; the
// withdrawn cgroups stay terminal.
func TestSharedRecycledAccountsRetire(t *testing.T) {
	pub := &sharedFakeRecycler{sharedFakePublisher: newSharedFakePublisher(), recycled: map[uint32]int{}}
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(
		func(operators.GadgetContext) (SharedRoutePublisher, error) { return pub, nil })), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	lease := func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }
	var retired []*sharedPhysicalScope
	for cycle := range 3 * int(n.config.Profile.Bindings) {
		cgroup := uint64(100 + cycle)
		s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: cgroup, InitHostPID: 1, Acquire: lease})
		if err != nil {
			t.Fatalf("cycle %d bind: %v", cycle, err)
		}
		if _, err := s.Publish(t.Context(), SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}); err != nil {
			t.Fatalf("cycle %d publish: %v", cycle, err)
		}
		if err := s.Remove(t.Context(), 1); err != nil {
			t.Fatalf("cycle %d remove: %v", cycle, err)
		}
		waitFor(t, "retired", func() bool { s.account.mu.Lock(); defer s.account.mu.Unlock(); return s.account.retired })
		retired = append(retired, s.account)
	}
	for _, a := range retired {
		a.mu.Lock()
		pins, reserved := a.pins, a.native.reserved
		a.mu.Unlock()
		if pins != nil || reserved {
			t.Fatalf("retired account of cgroup %d keeps pins %v or slot %v", a.cgroup, pins != nil, reserved)
		}
		if s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: a.cgroup, InitHostPID: 1, Acquire: lease}); s != nil || !errors.Is(err, ErrSharedBindingWithdrawn) {
			t.Fatalf("rebind of retired cgroup %d: %v %v", a.cgroup, s, err)
		}
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(n.scopes) != 0 || uint64(len(n.withdrawnCgroups)) != 3*n.config.Profile.Bindings {
		t.Fatalf("after teardown: scopes %d, withdrawn record %d", len(n.scopes), len(n.withdrawnCgroups))
	}
}

// TestSharedWithdrawnRefusedBeforeAcquire (review HIGH 2): a withdrawn
// cgroup is refused as terminal before any lease is acquired, so the
// answer is ErrSharedBindingWithdrawn even when its init is gone (Acquire
// would fail).
func TestSharedWithdrawnRefusedBeforeAcquire(t *testing.T) {
	pub := &sharedFakeRecycler{sharedFakePublisher: newSharedFakePublisher(), recycled: map[uint32]int{}}
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(
		func(operators.GadgetContext) (SharedRoutePublisher, error) { return pub, nil })), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}); err != nil {
		t.Fatal(err)
	}
	if err := a.Remove(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	acquired := false
	gone := func(context.Context) (BindingLease, error) {
		acquired = true
		return nil, errors.New("open /proc/4242: no such file or directory")
	}
	// Before and after the recycle retires the account.
	for _, when := range []string{"withdrawn", "retired"} {
		if when == "retired" {
			waitFor(t, "retired", func() bool { a.account.mu.Lock(); defer a.account.mu.Unlock(); return a.account.retired })
		}
		if s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 4242, Acquire: gone}); s != nil || !errors.Is(err, ErrSharedBindingWithdrawn) || acquired {
			t.Fatalf("%s: rebind %v %v (lease acquired %v)", when, s, err, acquired)
		}
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestSharedRefusedAdoptionTerminalImmediately (re-review LOW 3): a refused
// adoption makes its cgroup terminal at once: while its Strict route is
// still latched (the cgroup not empty), a rebind is refused with
// ErrSharedBindingWithdrawn and the session cannot publish again.
func TestSharedRefusedAdoptionTerminalImmediately(t *testing.T) {
	cmd := &sharedFakeCommander{verifyCode: sharedProductRefused, routeState: SharedRouteState{Cgroup: 41, Scope: 5, Generation: 1, Serial: 1, Incarnation: 1, Class: 2, Phase: 2}, routeAdopting: true}
	threads := &sharedFakeThreads{tids: []uint32{1}} // not empty: latched
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
	s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 41, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatal(err)
	}
	var adoption *ErrSharedAdoptionRefused
	if _, err := s.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}); !errors.As(err, &adoption) {
		t.Fatalf("publish: %v", err)
	}
	if _, err := s.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}); !errors.Is(err, ErrSharedBindingWithdrawn) {
		t.Fatalf("re-publish of a refused session: %v", err)
	}
	if err := s.Remove(t.Context(), 1); err != nil || !s.Inspect().WithdrawPending {
		t.Fatalf("Remove while latched: %v %+v", err, s.Inspect())
	}
	if r, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 41, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) {
		t.Fatal("lease acquired for a terminal cgroup")
		return nil, nil
	}}); r != nil || !errors.Is(err, ErrSharedBindingWithdrawn) {
		t.Fatalf("rebind during the latch: %v %v", r, err)
	}
	if strings.Contains(strings.Join(cmd.log(), ","), "withdraw") {
		t.Fatal("the latched Strict route was withdrawn")
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestSharedGadgetEndsBeforeStopNode (chain13): the host gadget ends on its
// own (its context canceled) while a refused adoption's session is still
// bound; its Stop(gc) removes the sessions anyway (never under the canceled
// context) and closes the publisher, and the later StopNode succeeds. A
// Remove after the publisher closed is recorded pending (fail-closed).
func TestSharedGadgetEndsBeforeStopNode(t *testing.T) {
	cmd := &sharedFakeCommander{verifyCode: sharedProductRefused, routeState: SharedRouteState{Cgroup: 51, Scope: 5, Generation: 1, Serial: 1, Incarnation: 1, Class: 2, Phase: 2}, routeAdopting: true}
	threads := &sharedFakeThreads{tids: []uint32{1}} // latched
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedProductFakeManifest()}
	q := host.qualification(nil)
	q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
		p, _ := newTestProductPublisher(cmd, threads)
		return &sharedLiveProductPublisher{productRoutePublisher: p, closeControl: func() error { return nil }}, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	n, err := StartNode(WithSharedNodeQualification(ctx, q), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	lease := func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }
	s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 51, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatal(err)
	}
	var adoption *ErrSharedAdoptionRefused
	if _, err := s.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}); !errors.As(err, &adoption) {
		t.Fatalf("publish: %v", err)
	}
	cancel() // the gadget's context ends first
	if err := n.Stop(host.gc); err != nil {
		t.Fatalf("Stop(gc) after the gadget context ended: %v", err)
	}
	if !s.Inspect().Removed {
		t.Fatal("Stop(gc) under a canceled gadget context left the session bound")
	}
	if err := n.StopNode(context.WithoutCancel(t.Context())); err != nil {
		t.Fatalf("StopNode after the gadget ended: %v", err)
	}
	if strings.Contains(strings.Join(cmd.log(), ","), "withdraw") {
		t.Fatal("the latched Strict route was withdrawn")
	}

	// A Remove that reaches a closed publisher records the withdrawal
	// pending instead of failing.
	n2, _, a, _ := sharedStartPublishingNode(t, newSharedFakePublisher())
	if err := n2.closeLivePublisher(); err != nil {
		t.Fatal(err)
	}
	if err := a.Remove(t.Context(), 1); err != nil || !a.Inspect().WithdrawPending || !a.Inspect().Removed {
		t.Fatalf("Remove after the publisher closed: %v %+v", err, a.Inspect())
	}
	if got := n2.TeardownPendingWithdrawals(); got != 1 {
		t.Fatalf("teardown-pending withdrawals %d, want 1", got)
	}
	if err := n2.StopNode(t.Context()); err != nil {
		t.Fatalf("StopNode: %v", err)
	}
}
