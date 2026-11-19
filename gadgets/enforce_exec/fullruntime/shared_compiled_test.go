// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"sync"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// TestSharedCompileThenPublishCompiled: Compile gives the next generation's
// exact program and root epoch without committing anything; PublishCompiled
// commits it at that generation, and a revision keeps the epoch.
func TestSharedCompileThenPublishCompiled(t *testing.T) {
	pub := newSharedFakePublisher()
	n, _, a, _ := sharedStartPublishingNode(t, pub)
	defer func() { _ = n.StopNode(t.Context()) }()
	slot := a.Inspect().RouteSlot
	before := pub.publishes[slot]
	policy := SharedBindingPolicy{Source: sharedTestSourcePolicy("p", "1", "app"), Container: "app"}
	c, err := a.Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if c.Generation != 2 || c.Program == nil || len(c.Program.Rules) != 1 || c.Program.Rules[0].Name != "root" || c.Epochs["p"] == 0 || len(c.Epochs) != 1 {
		t.Fatalf("compiled %+v epochs %v", c, c.Epochs)
	}
	if pub.publishes[slot] != before {
		t.Fatal("Compile ran a command")
	}
	sharedRequirePublished(t, a, 1)
	state, err := a.PublishCompiled(t.Context(), c)
	if err != nil || state.Generation != c.Generation {
		t.Fatalf("PublishCompiled: %+v %v", state, err)
	}
	sharedRequirePublished(t, a, 2)
	if a.account.route.epoch != c.Epochs["p"] || a.account.route.policy.program == nil {
		t.Fatalf("route epoch %d, compiled %d", a.account.route.epoch, c.Epochs["p"])
	}
	// A revision of the same policy UID retains the epoch.
	revision := policy
	revision.Source = sharedTestSourcePolicy("p", "2", "app")
	c2, err := a.Compile(revision)
	if err != nil || c2.Generation != 3 || c2.Epochs["p"] != c.Epochs["p"] {
		t.Fatalf("revision compiled %+v %v", c2, err)
	}
	// Publish is Compile + PublishCompiled.
	if state, err := a.Publish(t.Context(), revision); err != nil || state.Generation != 3 || a.account.route.epoch != c.Epochs["p"] {
		t.Fatalf("Publish: %+v %v", state, err)
	}
}

// TestSharedPublishCompiledStale: of two compilations against the same
// route only the first PublishCompiled commits; the second, a compilation
// whose inputs or program changed, one of another binding and the zero value
// are refused with ErrSharedCompiledStale before any command runs.
func TestSharedPublishCompiledStale(t *testing.T) {
	pub := newSharedFakePublisher()
	n, _, a, b := sharedStartPublishingNode(t, pub)
	defer func() { _ = n.StopNode(t.Context()) }()
	slot := a.Inspect().RouteSlot
	compile := func(revision string) SharedCompiled {
		t.Helper()
		c, err := a.Compile(SharedBindingPolicy{Source: sharedTestSourcePolicy("p", revision, "app"), Container: "app"})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	refused := func(name string, s *BindingSession, c SharedCompiled) {
		t.Helper()
		published, route := pub.publishes[slot], a.account.route.state
		if _, err := s.PublishCompiled(t.Context(), c); !errors.Is(err, ErrSharedCompiledStale) {
			t.Fatalf("%s: %v, want ErrSharedCompiledStale", name, err)
		}
		if pub.publishes[slot] != published || a.account.route.state != route {
			t.Fatalf("%s: a stale compilation reached the publisher", name)
		}
	}

	first, second := compile("1"), compile("2")
	if first.Generation != second.Generation {
		t.Fatalf("generations %d, %d", first.Generation, second.Generation)
	}
	if _, err := a.PublishCompiled(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	refused("second of a race", a, second)
	refused("replayed", a, first)

	changed := compile("3")
	changed.input.Source.Rules[0].Actor.UID = []int64{1000} // the authored policy changed
	refused("policy changed", a, changed)
	container := compile("3")
	container.input.Container = "other"
	refused("container changed", a, container)
	program := compile("3")
	program.Program.Rules = nil
	refused("program changed", a, program)
	refused("another binding", b, compile("3"))
	refused("zero value", a, SharedCompiled{})

	// Concurrent: of two compilations made against the same route, exactly
	// one commits.
	x, y := compile("4"), compile("5")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, c := range []SharedCompiled{x, y} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = a.PublishCompiled(t.Context(), c)
		}()
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("concurrent PublishCompiled: %v, %v; want exactly one commit", errs[0], errs[1])
	}
	for _, err := range errs {
		if err != nil && !errors.Is(err, ErrSharedCompiledStale) {
			t.Fatalf("losing PublishCompiled: %v", err)
		}
	}
	sharedRequirePublished(t, a, x.Generation)
}

// TestSharedCompileRefusals: Compile runs the product admission and the
// revision refusals Publish runs, and changes nothing.
func TestSharedCompileRefusals(t *testing.T) {
	pub := newSharedFakePublisher()
	n, _, a, _ := sharedStartPublishingNode(t, pub)
	slot := a.Inspect().RouteSlot
	argv := sharedTestSourcePolicy("p", "1", "app")
	argv.Rules[0].Target.Argv = &fullpolicy.Argv{Contains: []string{"-c"}}
	if _, err := a.Compile(SharedBindingPolicy{Source: argv, Container: "app"}); !errors.Is(err, ErrSharedPredicateUnsupported) {
		t.Fatalf("argv predicate: %v", err)
	}
	audit := sharedTestSourcePolicy("p", "1", "app")
	audit.Mode = fullpolicy.Audit
	if _, err := a.Compile(SharedBindingPolicy{Source: audit, Container: "app"}); !errors.Is(err, ErrSharedClassChange) {
		t.Fatalf("class change: %v", err)
	}
	if _, err := a.Compile(SharedBindingPolicy{Source: &fullpolicy.Policy{ID: "p", Mode: fullpolicy.Enforce}, Container: "app"}); err == nil {
		t.Fatal("compiled a policy without a root role")
	}
	if pub.publishes[slot] != 1 {
		t.Fatal("a refused Compile ran a command")
	}
	sharedRequirePublished(t, a, 1)
	c, err := a.Compile(SharedBindingPolicy{Source: sharedTestSourcePolicy("p", "1", "app"), Container: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Compile(SharedBindingPolicy{Source: sharedTestSourcePolicy("p", "1", "app"), Container: "app"}); err == nil {
		t.Fatal("Compile on a stopped node")
	}
	if _, err := a.PublishCompiled(t.Context(), c); err == nil {
		t.Fatal("PublishCompiled on a stopped node")
	}
}

// TestSharedSinglePolicy (D3): a plan binds exactly one policy.
func TestSharedSinglePolicy(t *testing.T) {
	p := *sharedTestSourcePolicy("p", "1", "app")
	got, err := SharedSinglePolicy([]fullpolicy.Policy{p})
	if err != nil || got.ID != "p" {
		t.Fatalf("one policy: %v %v", got, err)
	}
	if _, err := SharedSinglePolicy([]fullpolicy.Policy{p, *sharedTestSourcePolicy("q", "1", "app")}); !errors.Is(err, ErrSharedMultiPolicyUnsupported) {
		t.Fatalf("two policies: %v", err)
	}
	if _, err := SharedSinglePolicy(nil); err == nil || errors.Is(err, ErrSharedMultiPolicyUnsupported) {
		t.Fatalf("no policy: %v", err)
	}
}
