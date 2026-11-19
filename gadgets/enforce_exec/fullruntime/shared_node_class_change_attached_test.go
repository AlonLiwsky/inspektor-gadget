// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// TestSharedNodeClassChangeRefusedAttached (G019 gap 6, accepted: a class
// change needs a new binding): a Strict binding with an adopted init is
// revised to Audit, the same policy UID and root role.
//
//  1. Through BindingSession.Publish: refused in Go before any command,
//     ErrSharedClassChange (terminal).
//  2. Straight to the product publisher (no Go pre-check), compiled at the
//     next generation: the kernel revise refuses (frozen route class) and
//     the publisher names it ErrSharedClassChange; the staged object is
//     settled. When the compiler binds the class into the policy UID, the
//     commander refuses first (policy UID) and the kernel step is logged as
//     unreachable.
//
// After each refusal the binding keeps its last-good route (generation,
// kernel tuple, Strict verdicts by the adopted init), no policy object
// leaks, the fail-closed witness counts nothing and stays Healthy, and
// the MigrationOutUnenforced label stays. A same-class revision then still
// commits. Isolated exact-kernel VM only, with the M4 environment
// (IG_SHARED_M4_OBJECT, IG_SHARED_M4_CGROUP_ROOT,
// IG_SHARED_M4_HANDLER_SYMBOL).
func TestSharedNodeClassChangeRefusedAttached(t *testing.T) {
	e := sharedM4Start(t)
	init := startSharedPipeInit(t, e.cgroup("class"), "ig15-g019-m4-class-init")
	s := e.bind(init)
	strict := sharedM4Policy("m4-class", "1", fullpolicy.Enforce, fullpolicy.Deny)
	if _, err := s.Publish(e.ctx, SharedBindingPolicy{Source: strict, Container: "class"}); err != nil {
		t.Fatalf("publish Strict (adoption): %v", err)
	}
	before := s.Inspect()
	if before.Fault != nil || !before.RoutePublished || before.Adoption != nil || !before.MigrationOutUnenforced {
		t.Fatalf("Strict binding: %+v", before)
	}
	slot := before.RouteSlot
	sharedM4RequireAdopted(t, e.gc, slot)
	publisher, err := e.node.livePublisher(false)
	if err != nil {
		t.Fatal(err)
	}
	route := mustRoute(t, publisher, slot)
	if route.Class != sharedClassStrict {
		t.Fatalf("kernel route %+v, want Strict", route)
	}
	var verdict string
	sharedM4RequireCountedE(t, e.gc, "Strict smoke", e.cmd, func() error {
		var err error
		verdict, err = init.smokeE(e.ctx)
		return err
	})
	if verdict != "r0=0 r1000=126" {
		t.Fatalf("Strict verdicts %q, want r0=0 r1000=126", verdict)
	}
	objects := e.liveObjects()
	health, err := e.node.FailClosedHealth()
	if err != nil || !health.Gated || health.State != SharedFailClosedHealthy {
		t.Fatalf("fail-closed witness before: %+v %v", health, err)
	}

	requireLastGood := func(step string) {
		t.Helper()
		if st := s.Inspect(); st.Fault != nil || st.Generation != before.Generation || !st.MigrationOutUnenforced {
			t.Fatalf("%s: binding %+v, last-good %+v", step, st, before)
		}
		if have := mustRoute(t, publisher, slot); have != route {
			t.Fatalf("%s: kernel route %+v, last-good %+v", step, have, route)
		}
		for deadline := time.Now().Add(5 * time.Second); e.liveObjects() != objects; time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d live policy objects, want %d (staged object leaked)", step, e.liveObjects(), objects)
			}
		}
		sharedM4RequireCountedE(t, e.gc, step+": Strict smoke", e.cmd, func() error {
			v, err := init.smokeE(e.ctx)
			if err == nil && v != verdict {
				return errors.New("verdicts " + v + ", want " + verdict)
			}
			return err
		})
		h, err := e.node.FailClosedHealth()
		if err != nil || h.State != SharedFailClosedHealthy || h.Counters != health.Counters {
			t.Fatalf("%s: fail-closed witness %+v %v, want Healthy with no new count (%v)", step, h, err, health.Counters)
		}
	}

	// 1. The Go refusal.
	audit := sharedM4Policy("m4-class", "2", fullpolicy.Audit, fullpolicy.Deny)
	_, err = s.Publish(e.ctx, SharedBindingPolicy{Source: audit, Container: "class"})
	if !errors.Is(err, ErrSharedClassChange) || !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "Strict -> Audit") {
		t.Fatalf("class-changing revision: %v, want ErrSharedClassChange", err)
	}
	t.Logf("class change (Go): %v", err)
	requireLastGood("Go refusal")

	// 2. The kernel refusal, at the next generation with the binding's
	// activated root epoch (as Publish would compile it).
	s.account.mu.Lock()
	last := s.account.route
	s.account.mu.Unlock()
	compiled, err := SharedBindingPolicy{Source: audit, Container: "class"}.compile(before.Generation+1, map[string]uint64{strict.ID: last.epoch})
	if err != nil {
		t.Fatal(err)
	}
	was, err := sharedCompiledPolicyOf(last.policy.program, last.policy.object)
	if err != nil {
		t.Fatal(err)
	}
	now, err := sharedCompiledPolicyOf(compiled.program, compiled.object)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.pub.Publish(e.ctx, slot, s.cgroup, compiled, false, SharedInitIdentity{})
	switch {
	case was.UID != now.UID || was.RootRole != now.RootRole:
		if !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "policy UID") {
			t.Fatalf("class change with another policy UID: %v", err)
		}
		t.Logf("kernel class refusal unreachable: the compiler binds the class into the policy UID (%#x -> %#x); the commander refused: %v", was.UID, now.UID, err)
	case !errors.Is(err, ErrSharedClassChange) || !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "Strict -> Audit"):
		t.Fatalf("kernel class-changing revise: %v, want ErrSharedClassChange", err)
	default:
		t.Logf("class change (kernel): %v", err)
	}
	requireLastGood("kernel refusal")

	// 3. A same-class revision still commits (fallback allow).
	revised := sharedM4Policy("m4-class", "2", fullpolicy.Enforce, fullpolicy.Allow)
	var state SharedRouteState
	for attempt := 0; ; attempt++ {
		state, err = s.Publish(e.ctx, SharedBindingPolicy{Source: revised, Container: "class"})
		if err == nil || attempt == 50 || !strings.Contains(err.Error(), "retryable") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || state.Generation != before.Generation+1 || state.Class != sharedClassStrict {
		t.Fatalf("same-class revision after the refusals: %+v %v", state, err)
	}
	if v := init.smoke(t, e.ctx); v != "r0=0 r1000=0" {
		t.Fatalf("revision gen %d not enforced: %s", state.Generation, v)
	}
	t.Log("PASS: class change refused in Go and by the kernel (ErrSharedClassChange), last-good kept, no object leaked, nothing counted; same-class revision commits")
}
