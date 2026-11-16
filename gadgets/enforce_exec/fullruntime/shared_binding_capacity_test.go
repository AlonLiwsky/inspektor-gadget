// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"testing"
)

// A Bind past the profile's binding count is refused with the
// typed ErrSharedBindingCapacity (a NotReady reason for the host), whether
// the bindings are being prepared or their physical scopes are retained.
func TestSharedBindCapacityIsTyped(t *testing.T) {
	lease := func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }
	for _, tc := range []struct {
		name string
		set  func(*NodeEnforcer)
	}{
		{"preparations in flight", func(n *NodeEnforcer) {
			n.preparations = map[*BindingSession]struct{}{{}: {}, {}: {}}
		}},
		{"scopes retained", func(n *NodeEnforcer) {
			n.scopes = map[uint64]*sharedPhysicalScope{21: {cgroup: 21}, 22: {cgroup: 22}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := NewNodeEnforcer(sharedQualifiedConfig())
			if err != nil {
				t.Fatal(err)
			}
			if n.config.Profile.Bindings != 2 {
				t.Fatalf("profile binds %d, want the product's 2", n.config.Profile.Bindings)
			}
			installSharedPinTest(n)
			tc.set(n)
			s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 11, InitHostPID: 1, Acquire: lease})
			if s != nil || !errors.Is(err, ErrSharedBindingCapacity) {
				t.Fatalf("Bind: session=%v err=%v, want ErrSharedBindingCapacity", s, err)
			}
			if n.scopes[11] != nil {
				t.Fatal("refused Bind retained a scope")
			}
		})
	}
}

// Defence in depth: a full route slot table is the same typed
// capacity refusal.
func TestSharedRouteSlotsExhaustedIsTyped(t *testing.T) {
	n, err := NewNodeEnforcer(sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	n.host.live = &sharedLiveCandidate{}
	n.host.scopeSlots = []*sharedPhysicalScope{{cgroup: 21}, {cgroup: 22}}
	if err := n.reserveLiveRoute(&sharedPhysicalScope{cgroup: 11}); !errors.Is(err, ErrSharedBindingCapacity) {
		t.Fatalf("reserveLiveRoute with every slot owned: %v, want ErrSharedBindingCapacity", err)
	}
}
