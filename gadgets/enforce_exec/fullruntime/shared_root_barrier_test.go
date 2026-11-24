// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/common/rootbarrier"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// TestSharedRootBarrierPrograms pins the canary exemption: exactly the seven
// rb_* programs of rootbarrier.Hooks (every hook but task_alloc), each in
// the pinned attach set on its own hook; the task_alloc body is carried by
// the task_alloc source program, which the canary still waits for.
func TestSharedRootBarrierPrograms(t *testing.T) {
	var want []string
	for _, h := range rootbarrier.Hooks {
		if h.LSM == "task_alloc" {
			continue
		}
		want = append(want, h.Program)
		if got := sharedCandidateAttachSet[h.Program]; got != "bpf_lsm_"+h.LSM {
			t.Errorf("%s is attached to %q, want bpf_lsm_%s", h.Program, got, h.LSM)
		}
	}
	if got := slices.Sorted(maps.Keys(sharedRootBarrierPrograms)); !slices.Equal(got, slices.Sorted(slices.Values(want))) || len(got) != 7 {
		t.Fatalf("canary-exempt programs %v, want the 7 barrier programs %v", got, want)
	}
	if sharedRootBarrierPrograms[sharedRootBarrierTaskAlloc] || sharedCandidateAttachSet[sharedRootBarrierTaskAlloc] != "bpf_lsm_task_alloc" {
		t.Fatalf("%s must be attached to task_alloc and never exempt from the canary", sharedRootBarrierTaskAlloc)
	}
}

// sharedRootBarrierStart runs startLiveCandidate of a product node over fake
// receipts for programs, with the barrier check and the attach canary
// replaced by recorders. It stops at the canary (the recorder fails), so
// only the order up to the canary is exercised.
func sharedRootBarrierStart(t *testing.T, programs []string, verifyErr error) ([]string, map[string]*operators.NativeAttachment, error) {
	t.Helper()
	n, err := NewNodeEnforcer(sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	gc := gadgetcontext.New(context.Background(), "local/shared-candidate:abi3-development")
	// The fake object (its maps, the D1 witness map included), with only
	// the given attached programs.
	admitted := sharedCandidateFakeManifest()
	for name := range admitted.Programs {
		if sharedCandidateAttached(name) && !slices.Contains(programs, name) {
			delete(admitted.Programs, name)
		}
	}
	for k, name := range programs {
		gc.SetVar(operators.NativeAttachmentPrefix+name, &operators.NativeAttachment{
			LinkID: uint32(k + 1), ProgramID: uint32(k + 100), Check: func() error { return nil },
		})
	}
	var calls []string
	var verified map[string]*operators.NativeAttachment
	n.host.product = true
	n.host.rootBarrier = func(_ operators.GadgetContext, receipts map[string]*operators.NativeAttachment) error {
		calls = append(calls, "verify")
		verified = receipts
		return verifyErr
	}
	n.host.execMap = func(operators.GadgetContext) error {
		calls = append(calls, "execmap")
		return nil
	}
	old := sharedStartKernelWitness
	sharedStartKernelWitness = func(operators.GadgetContext, map[string]*operators.NativeAttachment, time.Duration, []string) (*sharedLiveKernelWitness, error) {
		calls = append(calls, "canary")
		return nil, errSharedRootBarrierCanaryReached
	}
	t.Cleanup(func() { sharedStartKernelWitness = old })
	return calls, verified, n.startLiveCandidate(gc, admitted)
}

var errSharedRootBarrierCanaryReached = errors.New("canary reached")

func sharedAttachedPrograms() []string {
	return append(slices.Collect(maps.Keys(sharedCandidateAttachSet)), slices.Collect(maps.Keys(sharedCandidateProbeSet))...)
}

// TestSharedRootBarrierVerifiedBeforeCanary: a product node verifies the
// barrier (rootbarrier.Verify, through the start check) once every receipt
// is present and BEFORE the attach canary, with every rb_* receipt and the
// task_alloc source receipt; a failed check is NotReady and the canary
// never runs; a missing rb_* program refuses the start before both.
func TestSharedRootBarrierVerifiedBeforeCanary(t *testing.T) {
	calls, verified, err := sharedRootBarrierStart(t, sharedAttachedPrograms(), nil)
	if !slices.Equal(calls, []string{"verify", "execmap", "canary"}) || !errors.Is(err, errSharedRootBarrierCanaryReached) {
		t.Fatalf("start order %v (%v), want the barrier check before the canary", calls, err)
	}
	for name := range sharedRootBarrierPrograms {
		if verified[name] == nil {
			t.Errorf("the barrier check did not get the receipt of %s", name)
		}
	}
	if verified[sharedRootBarrierTaskAlloc] == nil {
		t.Errorf("the barrier check did not get the receipt of %s", sharedRootBarrierTaskAlloc)
	}

	failed := errors.New("self-test failed")
	calls, _, err = sharedRootBarrierStart(t, sharedAttachedPrograms(), failed)
	if !slices.Equal(calls, []string{"verify"}) || !errors.Is(err, failed) {
		t.Fatalf("failed barrier check: calls %v, err %v; want the error and no canary", calls, err)
	}

	for name := range sharedRootBarrierPrograms {
		programs := slices.DeleteFunc(sharedAttachedPrograms(), func(p string) bool { return p == name })
		calls, _, err := sharedRootBarrierStart(t, programs, nil)
		if len(calls) != 0 || err == nil || !strings.Contains(err.Error(), "attach receipts") {
			t.Errorf("without %s: calls %v, err %v; want a refusal before the barrier check and the canary", name, calls, err)
		}
	}
}

// TestSharedRootBarrierStartCheckIsNotReady: the real start check wraps
// every failure in ErrSharedNodeNotReady (here: no receipt for the
// task_alloc source program, so no program ID to attest).
func TestSharedRootBarrierStartCheckIsNotReady(t *testing.T) {
	gc := gadgetcontext.New(context.Background(), "local/shared-candidate:abi3-development")
	err := verifySharedRootBarrier(gc, map[string]*operators.NativeAttachment{})
	if !errors.Is(err, ErrSharedNodeNotReady) {
		t.Fatalf("start check without receipts: %v, want ErrSharedNodeNotReady", err)
	}
}
