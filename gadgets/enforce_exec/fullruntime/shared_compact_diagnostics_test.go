// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"reflect"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

func TestSharedRegistryCompactRejectionPreservesRetainedCandidate(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	transport := &sharedObjectUploadTransport{}
	lastGood, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, transport)
	if err != nil {
		t.Fatal(err)
	}
	before := n.objects.records[lastGood.record]
	retained := n.objects.retainedBytes
	commands := len(transport.commands)
	status := s.Inspect()
	for range 3 {
		p := sharedRegistryPolicy()
		p.ID = "invalid"
		p.Rules = []fullpolicy.Rule{{Name: "r", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{"/["}}}}
		candidate, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, transport)
		var diagnostic fullpolicy.CompactDiagnostic
		if !errors.As(err, &diagnostic) || diagnostic.Primary() != fullpolicy.DiagnosticInvalidInput {
			t.Fatalf("actual registry did not use compact compiler: %v", err)
		}
		if len(transport.commands) != commands || n.objects.retainedBytes != retained || !reflect.DeepEqual(before, n.objects.records[lastGood.record]) || !reflect.DeepEqual(status, s.Inspect()) {
			t.Fatal("rejection altered prior ownership, commands or publication status")
		}
		if err := candidate.discard(t.Context(), transport); err != nil {
			t.Fatal(err)
		}
	}
	if err := lastGood.discard(t.Context(), transport); err != nil {
		t.Fatal(err)
	}
	if len(transport.commands) != commands+2 {
		t.Fatal("retained object lost normal retire/reclaim")
	}
}
