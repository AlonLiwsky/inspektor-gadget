// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"sync"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

func identityCandidate(t *testing.T, id string, generation uint64) *fullpolicy.KernelProgram {
	t.Helper()
	p, err := fullpolicy.CompileKernel([]fullpolicy.Policy{{ID: id, Revision: fmt.Sprint(generation), Mode: fullpolicy.Enforce, RootRole: "root"}}, generation, "app")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHistoricalIdentityReservation(t *testing.T) {
	var r IdentityRegistry
	p := identityCandidate(t, "uid-a", 1)
	if err := r.Reserve(p); err != nil {
		t.Fatal(err)
	}
	want := len(p.Identities)
	// Same names on another generation don't consume lifetime credits.
	if err := r.Reserve(identityCandidate(t, "uid-a", 2)); err != nil {
		t.Fatal(err)
	}
	if r.Len() != want {
		t.Fatalf("got %d want %d", r.Len(), want)
	}
	// Caller mutation cannot erase the registry after a failed publication.
	for id := range p.Identities {
		delete(p.Identities, id)
	}
	if r.Len() != want {
		t.Fatal("reservation aliased caller state")
	}
	if err := r.Reserve(nil); err == nil || r.Len() != want {
		t.Fatal("invalid candidate mutated history")
	}
}

func TestHistoricalCollisionAndCapacityAreAtomic(t *testing.T) {
	p := identityCandidate(t, "uid-a", 1)
	for id := range p.Identities {
		r := IdentityRegistry{names: map[uint64]string{id: "different retired identity"}}
		if err := r.Reserve(p); err == nil || r.Len() != 1 {
			t.Fatal("collision changed history")
		}
		break
	}
	r := IdentityRegistry{names: make(map[uint64]string, MaxHistoricalIdentities)}
	for i := uint64(0); i < MaxHistoricalIdentities; i++ {
		r.names[i] = "retired"
	}
	if err := r.Reserve(p); err == nil || r.Len() != MaxHistoricalIdentities {
		t.Fatal("capacity changed history")
	}
}

func TestHistoricalConcurrentReservation(t *testing.T) {
	var r IdentityRegistry
	p := identityCandidate(t, "uid-a", 1)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Reserve(p); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if r.Len() != len(p.Identities) {
		t.Fatal("duplicate reservations consumed credits")
	}
}
