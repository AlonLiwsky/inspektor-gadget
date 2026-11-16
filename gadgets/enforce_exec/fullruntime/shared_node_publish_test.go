// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedFakePublisher is a per-slot kernel route table: each Publish touches
// only its own slot and is all-or-nothing, like the BPF commit pair.
type sharedFakePublisher struct {
	routes     map[uint32]SharedRouteState
	fault      map[uint32]error
	withdrawn  map[uint32]bool
	noWithdraw bool
	publishes  map[uint32]int
	closes     int
	nextScope  uint64
	// commitThenFail commits the slot's publication, then reports failure.
	commitThenFail map[uint32]bool
	// inits records the init identity of each slot's last publication.
	inits map[uint32]SharedInitIdentity
}

func newSharedFakePublisher() *sharedFakePublisher {
	return &sharedFakePublisher{routes: map[uint32]SharedRouteState{}, fault: map[uint32]error{}, withdrawn: map[uint32]bool{}, publishes: map[uint32]int{}, nextScope: 10}
}

func (p *sharedFakePublisher) Publish(_ context.Context, slot uint32, cgroup uint64, policy SharedBindingPolicy, first bool, init SharedInitIdentity) (SharedRouteState, error) {
	p.publishes[slot]++
	if p.inits != nil {
		p.inits[slot] = init
	}
	if err := p.fault[slot]; err != nil {
		return SharedRouteState{}, err
	}
	r, ok := p.routes[slot]
	if first == ok {
		return SharedRouteState{}, errors.New("fake: first/revision mismatch")
	}
	if first {
		r = SharedRouteState{Cgroup: cgroup, Scope: p.nextScope, Incarnation: 1, Phase: 2}
		p.nextScope++
	}
	r.Generation++
	r.Serial++
	r.Record = uint32(r.Serial-1) & 1
	r.Class = policy.Class
	p.routes[slot] = r
	if p.commitThenFail[slot] {
		return SharedRouteState{}, errors.New("fake: committed, then the reply was lost")
	}
	return r, nil
}

func (p *sharedFakePublisher) Withdraw(_ context.Context, slot uint32, _ uint64) error {
	if p.noWithdraw {
		return ErrSharedNativeUnavailable
	}
	p.withdrawn[slot] = true
	delete(p.routes, slot)
	return nil
}

func (p *sharedFakePublisher) Route(slot uint32) (SharedRouteState, error) {
	r, ok := p.routes[slot]
	if !ok {
		return SharedRouteState{}, fmt.Errorf("fake: %w", ErrSharedRouteFree)
	}
	return r, nil
}

func (p *sharedFakePublisher) Close() error { p.closes++; return nil }

func sharedStartPublishingNode(t *testing.T, pub *sharedFakePublisher) (*NodeEnforcer, *sharedFakeNativeHost, *BindingSession, *BindingSession) {
	t.Helper()
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	ctx := WithSharedNodeQualification(t.Context(), host.qualification(
		func(operators.GadgetContext) (SharedRoutePublisher, error) { return pub, nil }))
	n, err := StartNode(ctx, sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	lease := func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatal(err)
	}
	b, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 22, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatal(err)
	}
	strict := SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}
	audit := SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}
	if _, err := a.Publish(t.Context(), strict); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Publish(t.Context(), audit); err != nil {
		t.Fatal(err)
	}
	return n, host, a, b
}

func sharedRequirePublished(t *testing.T, s *BindingSession, generation uint64) SharedBindingStatus {
	t.Helper()
	st := s.Inspect()
	if st.Fault != nil || !st.Attached || !st.RoutePublished || st.Generation != generation || st.Ready || st.Removed {
		t.Fatalf("binding %d: %+v, want published generation %d", s.cgroup, st, generation)
	}
	return st
}

func TestSharedPublishUnavailableWithoutPublisher(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("publish without publisher: %v", err)
	}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 3, Rules: 1}); err == nil {
		t.Fatal("invalid class accepted")
	}
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("Ready: %v", err)
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestSharedPublishIndependentRevision(t *testing.T) {
	pub := newSharedFakePublisher()
	n, host, a, b := sharedStartPublishingNode(t, pub)
	sa, sb := sharedRequirePublished(t, a, 1), sharedRequirePublished(t, b, 1)
	if sa.RouteSlot == sb.RouteSlot {
		t.Fatal("bindings share a route slot")
	}
	bRoute := pub.routes[sb.RouteSlot]
	for i := uint64(2); i <= 4; i++ {
		state, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: uint32(i % 3), Rules: 17})
		if err != nil || state.Generation != i {
			t.Fatalf("republish A: %+v %v", state, err)
		}
		sharedRequirePublished(t, a, i)
		sharedRequirePublished(t, b, 1)
		if pub.routes[sb.RouteSlot] != bRoute || pub.publishes[sb.RouteSlot] != 1 {
			t.Fatalf("A's revision touched B: %+v publishes=%d", pub.routes[sb.RouteSlot], pub.publishes[sb.RouteSlot])
		}
	}
	// A class change is a new route (gap 6), refused with A on last-good.
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("class change: %v", err)
	}
	sharedRequirePublished(t, a, 4)
	// Kernel divergence from last-good is a fault of that binding only.
	drift := pub.routes[sb.RouteSlot]
	drift.Generation++
	pub.routes[sb.RouteSlot] = drift
	if st := b.Inspect(); st.Fault == nil || st.Attached != true {
		t.Fatalf("drifted route not reported: %+v", st)
	}
	sharedRequirePublished(t, a, 4)
	pub.routes[sb.RouteSlot] = bRoute
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("Ready: %v", err)
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
	if pub.closes != 1 || host.stops != 1 || len(n.scopes) != 0 {
		t.Fatalf("cleanup: closes=%d stops=%d scopes=%d", pub.closes, host.stops, len(n.scopes))
	}
	if _, err := b.Publish(t.Context(), SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}); err == nil {
		t.Fatal("publish after stop")
	}
}

func TestSharedPublishIndependentRemoval(t *testing.T) {
	for _, noWithdraw := range []bool{false, true} {
		pub := newSharedFakePublisher()
		pub.noWithdraw = noWithdraw
		n, _, a, b := sharedStartPublishingNode(t, pub)
		if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 1, Rules: 1}); err != nil {
			t.Fatal(err)
		}
		sb := sharedRequirePublished(t, b, 1)
		bRoute := pub.routes[sb.RouteSlot]
		if err := a.Remove(t.Context(), 1); err == nil {
			t.Fatal("stale generation removed A")
		}
		if err := a.Remove(t.Context(), 2); err != nil {
			t.Fatalf("remove A: %v", err)
		}
		st := a.Inspect()
		slotA := st.RouteSlot
		if !st.Removed || st.WithdrawPending != noWithdraw || pub.withdrawn[slotA] == noWithdraw {
			t.Fatalf("removed A (noWithdraw=%v): %+v withdrawn=%v", noWithdraw, st, pub.withdrawn[slotA])
		}
		if noWithdraw && pub.routes[slotA].Generation != 2 {
			t.Fatalf("A's last-good route changed: %+v", pub.routes[slotA])
		}
		// The retained slot is never handed to a new binding before teardown.
		if n.host.scopeSlots[slotA] != a.account {
			t.Fatal("removed binding's route slot was released")
		}
		sharedRequirePublished(t, b, 1)
		if pub.routes[sb.RouteSlot] != bRoute {
			t.Fatal("A's removal touched B's route")
		}
		if _, err := b.Publish(t.Context(), SharedBindingPolicy{Class: 1, Fallback: 1, Rules: 1}); err != nil {
			t.Fatalf("B republish after A removal: %v", err)
		}
		sharedRequirePublished(t, b, 2)
		if err := n.StopNode(t.Context()); err != nil {
			t.Fatalf("stop (noWithdraw=%v): %v", noWithdraw, err)
		}
		if pub.closes != 1 || len(n.scopes) != 0 || n.host.scopeSlots[slotA] != nil {
			t.Fatalf("cleanup: closes=%d scopes=%d", pub.closes, len(n.scopes))
		}
	}
}

func TestSharedPublishIndependentFault(t *testing.T) {
	pub := newSharedFakePublisher()
	n, _, a, b := sharedStartPublishingNode(t, pub)
	sa, sb := sharedRequirePublished(t, a, 1), sharedRequirePublished(t, b, 1)
	aRoute, bRoute := pub.routes[sa.RouteSlot], pub.routes[sb.RouteSlot]
	injected := errors.New("injected mid-publication fault")
	pub.fault[sa.RouteSlot] = injected
	if state, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 1, Rules: 1}); !errors.Is(err, injected) || state != aRoute {
		t.Fatalf("faulted publish: %+v %v", state, err)
	}
	sharedRequirePublished(t, a, 1)
	sharedRequirePublished(t, b, 1)
	if pub.routes[sa.RouteSlot] != aRoute || pub.routes[sb.RouteSlot] != bRoute {
		t.Fatal("faulted publication changed a route")
	}
	// A publisher that reports a non-advancing tuple is a fault, not success.
	delete(pub.fault, sa.RouteSlot)
	pub.routes[sa.RouteSlot] = SharedRouteState{Cgroup: 99, Generation: 7, Class: 2}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 1, Rules: 1}); err == nil {
		t.Fatal("foreign route tuple accepted")
	}
	if st := a.Inspect(); st.Fault == nil || st.Generation != 1 {
		t.Fatalf("A must stay on last-good with the divergence reported: %+v", st)
	}
	sharedRequirePublished(t, b, 1)
	pub.routes[sa.RouteSlot] = aRoute
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestSharedPublishFirstFailureReadsKernelBack: a first publication that
// failed is read back. A committed kernel route Go never accepted is recorded
// as published with a fault (Inspect reports it, Remove withdraws it at its
// generation); a publication that committed nothing leaves the binding clean.
func TestSharedPublishFirstFailureReadsKernelBack(t *testing.T) {
	sharedEnableQualification(t)
	pub := newSharedFakePublisher()
	pub.commitThenFail = map[uint32]bool{}
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
	b, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 22, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatal(err)
	}
	strict := SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}
	// B: refused before any commit: nothing recorded, no fault.
	pub.fault[b.Inspect().RouteSlot] = errors.New("refused")
	if _, err := b.Publish(t.Context(), strict); err == nil {
		t.Fatal("refused publish succeeded")
	}
	if s := b.Inspect(); s.Fault != nil || s.RoutePublished || !s.Attached {
		t.Fatalf("B after a refused first publish: %+v", s)
	}
	// A: committed, then failed.
	slot := a.Inspect().RouteSlot
	pub.commitThenFail[slot] = true
	state, err := a.Publish(t.Context(), strict)
	if err == nil || state != pub.routes[slot] || state.Generation != 1 {
		t.Fatalf("committed-then-failed publish: %+v %v", state, err)
	}
	s := a.Inspect()
	if s.Fault == nil || !strings.Contains(s.Fault.Error(), "from a failed first publication") || !s.RoutePublished || s.Generation != 1 || s.Ready {
		t.Fatalf("A after a committed-then-failed first publish: %+v", s)
	}
	// Removal of a route left by a failed first publication: see
	// TestSharedRemoveNeverWithdrawsFailedAdoption (a latched Strict route
	// is never withdrawn by Remove).
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestSharedPublishCarriesInitIdentityAndWithdrawnIsTerminal: Publish passes
// the binding's pinned init identity (ticks unchanged), and a withdrawn
// cgroup is terminal: neither Publish nor a rebind may reuse it.
func TestSharedPublishCarriesInitIdentityAndWithdrawnIsTerminal(t *testing.T) {
	pub := newSharedFakePublisher()
	pub.inits = map[uint32]SharedInitIdentity{}
	n, _, a, b := sharedStartPublishingNode(t, pub)
	slotA := a.Inspect().RouteSlot
	if got, want := pub.inits[slotA], (SharedInitIdentity{TGID: 1, StartTicks: 4242, MountNS: 4026531840 + 21}); got != want {
		t.Fatalf("init identity %+v, want %+v", got, want)
	}
	if err := a.Remove(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if !pub.withdrawn[slotA] {
		t.Fatal("route not withdrawn")
	}
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}); err == nil {
		t.Fatal("removed session published")
	}
	lease := func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }
	if s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 21, InitHostPID: 1, Acquire: lease}); s != nil || !errors.Is(err, ErrSharedBindingWithdrawn) {
		t.Fatalf("rebind of a withdrawn cgroup: session=%v err=%v", s, err)
	}
	sharedRequirePublished(t, b, 1)
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestSharedInitIdentityFromPins(t *testing.T) {
	a := &sharedPhysicalScope{}
	if _, err := a.initIdentity(); err == nil {
		t.Fatal("identity without pins")
	}
	a.pins = &sharedPhysicalPins{initPID: 7, start: "not-ticks"}
	if _, err := a.initIdentity(); err == nil {
		t.Fatal("identity without a mount pin")
	}
	mount, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer mount.Close()
	a.pins.mount = mount
	if _, err := a.initIdentity(); err == nil {
		t.Fatal("non-numeric start time accepted")
	}
	a.pins.start = "123456"
	id, err := a.initIdentity()
	var st unix.Stat_t
	if err != nil || unix.Fstat(int(mount.Fd()), &st) != nil || id != (SharedInitIdentity{TGID: 7, StartTicks: 123456, MountNS: st.Ino}) {
		t.Fatalf("identity %+v err %v", id, err)
	}
}

// TestSharedPublishCompiledPolicyRefusals: a compiled-policy publication
// without a root role or a container is refused before any command runs
// (decision A: init_role is the compiled root role, never a default), and a
// complete one is compiled at the route's next generation, keeping its root
// epoch across revisions.
func TestSharedPublishCompiledPolicyRefusals(t *testing.T) {
	pub := newSharedFakePublisher()
	n, _, a, _ := sharedStartPublishingNode(t, pub)
	slot := a.Inspect().RouteSlot
	before := pub.publishes[slot]
	for name, policy := range map[string]SharedBindingPolicy{
		"no root role": {Source: &fullpolicy.Policy{ID: "p", Mode: fullpolicy.Enforce}, Container: "app"},
		"no container": {Source: &fullpolicy.Policy{ID: "p", Mode: fullpolicy.Enforce, RootRole: "app"}},
		"no rules":     {Source: &fullpolicy.Policy{ID: "p", Mode: fullpolicy.Enforce, RootRole: "app"}, Container: "app"},
	} {
		if _, err := a.Publish(t.Context(), policy); err == nil {
			t.Fatalf("%s: published", name)
		}
		if pub.publishes[slot] != before {
			t.Fatalf("%s: a command ran before the refusal", name)
		}
	}
	source := sharedTestSourcePolicy("p", "1", "app")
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Source: source, Container: "app"}); err != nil {
		t.Fatal(err)
	}
	epoch := a.account.route.epoch
	if epoch == 0 || a.account.route.policy.program == nil {
		t.Fatalf("compiled publication kept epoch %d program %v", epoch, a.account.route.policy.program != nil)
	}
	source2 := *source
	source2.Revision = "2"
	if _, err := a.Publish(t.Context(), SharedBindingPolicy{Source: &source2, Container: "app"}); err != nil {
		t.Fatal(err)
	}
	if got := a.account.route.epoch; got != epoch {
		t.Fatalf("revision root epoch %d, want retained %d", got, epoch)
	}
	// A revision changing the root role under the same policy UID, or the
	// UID, is refused (terminal) before any command runs.
	published := pub.publishes[slot]
	for _, changed := range []*fullpolicy.Policy{sharedTestSourcePolicy("p", "3", "web"), sharedTestSourcePolicy("q", "1", "app")} {
		if _, err := a.Publish(t.Context(), SharedBindingPolicy{Source: changed, Container: "app"}); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "UID or root role") {
			t.Fatalf("%s/%s revision: %v", changed.ID, changed.RootRole, err)
		}
	}
	if pub.publishes[slot] != published || a.account.route.epoch != epoch {
		t.Fatal("a refused identity change reached the publisher or changed the route")
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}
