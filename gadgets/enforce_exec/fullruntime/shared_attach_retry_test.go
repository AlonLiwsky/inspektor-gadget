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

	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

// Review A2: the shared node never inherits the unbounded
// nativeattach.DefaultRetry: WithNodeEnforcer sets a retry with a finite
// attempt count and a total time budget, and admission refuses any other.
func TestSharedNodeAttachRetryIsBounded(t *testing.T) {
	n, err := NewNodeEnforcer(sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	gc := gadgetcontext.New(t.Context(), n.config.Image, WithNodeEnforcer(n))
	value, ok := gc.GetVar(operators.NativeAttachRetryKey)
	retry, isRetry := value.(nativeattach.Retry)
	if !ok || !isRetry || retry.MaxAttempts <= 0 || retry.Budget <= 0 || retry.State == nil {
		t.Fatalf("WithNodeEnforcer retry %T %+v, want an explicit bounded nativeattach.Retry", value, value)
	}
	// The waits alone stay within the budget's order (the budget also
	// stops a wait that would end past it).
	var waits time.Duration
	for d, k := retry.Initial, 1; k < retry.MaxAttempts; k++ {
		waits += d
		d = min(2*d, retry.Max)
	}
	if retry.Budget > time.Minute || waits > time.Minute {
		t.Fatalf("shared node retry may hold the lifecycle lock for %s (budget %s)", waits, retry.Budget)
	}

	validator, _ := gc.GetVar(operators.NativeResourceValidatorKey)
	validate := validator.(func(*operators.NativeResources) error)
	for name, v := range map[string]any{
		"opt-out":            false,
		"default unbounded":  nativeattach.DefaultRetry,
		"no attempt bound":   nativeattach.Retry{Initial: time.Millisecond, Max: time.Millisecond, Budget: time.Second},
		"no time budget":     nativeattach.Retry{Initial: time.Millisecond, Max: time.Millisecond, MaxAttempts: 3},
		"not a retry policy": "bounded",
	} {
		gc.SetVar(operators.NativeAttachRetryKey, v)
		if err := validate(sharedCandidateFakeManifest()); err == nil || !strings.Contains(err.Error(), "bounded native attach retry") {
			t.Fatalf("%s: admission %v, want the bounded-retry refusal", name, err)
		}
	}
	gc.SetVar(operators.NativeAttachRetryKey, retry)
	if err := sharedNodeAttachRetryBounded(gc); err != nil {
		t.Fatalf("default shared node retry refused: %v", err)
	}
}

// Review A2, through StartNode: while StartNode is blocked in the bounded
// retry the host sees every capacity refusal (SharedNodeConfig.AttachState),
// then nil once attached; an exhausted retry ends StartNode (it never
// hangs), fails closed (no node, one teardown) and is NotReady.
func TestSharedNodeAttachStateThroughStartNode(t *testing.T) {
	sharedEnableQualification(t)
	refusal := func() error { return &nativeattach.ErrAttachCapacity{Target: "bpf_lsm_task_alloc", Err: unix.E2BIG} }
	for _, tc := range []struct {
		name     string
		refusals int // refused attempts before success (-1: never)
	}{{"attached after two refusals", 2}, {"exhausted", -1}} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var states []error
			config := sharedQualifiedConfig()
			config.AttachState = func(err error) { mu.Lock(); states = append(states, err); mu.Unlock() }
			attempts, stops := 0, 0
			run := func(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
				gc := gadgetcontext.New(ctx, config.Image, opt)
				value, _ := gc.GetVar(operators.NativeAttachRetryKey)
				retry, ok := value.(nativeattach.Retry)
				if !ok {
					t.Fatalf("no explicit retry: %T", value)
				}
				done := make(chan error, 1)
				// The operator's attach transaction.
				err := retry.Run(ctx, func() error {
					attempts++
					if tc.refusals < 0 || attempts <= tc.refusals {
						return refusal()
					}
					return nil
				})
				if err == nil {
					err = errors.New("test gadget ends after attaching")
				}
				done <- err
				return func(context.Context) error { stops++; return nil }, done, nil
			}
			small := &nativeattach.Retry{Initial: time.Millisecond, Max: 2 * time.Millisecond, MaxAttempts: 3, Budget: time.Second}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			n, err := StartNode(WithSharedNodeQualification(ctx, SharedNodeQualification{Run: run, attachRetry: small}), config)
			if n != nil {
				t.Fatal("node returned")
			}
			mu.Lock()
			defer mu.Unlock()
			var capErr *nativeattach.ErrAttachCapacity
			if tc.refusals < 0 {
				if !errors.Is(err, ErrSharedNodeNotReady) || !errors.As(err, &capErr) || errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("exhausted attach: %v, want ErrSharedNodeNotReady wrapping the capacity refusal", err)
				}
				if attempts != 3 || stops != 1 || len(states) != 3 {
					t.Fatalf("attempts %d stops %d states %v, want 3 refusals reported and one teardown", attempts, stops, states)
				}
			} else if attempts != 3 || len(states) != 3 || states[2] != nil {
				t.Fatalf("attempts %d states %v, want two refusals then nil", attempts, states)
			}
			for _, s := range states[:2] {
				if !errors.As(s, &capErr) || capErr.Target != "bpf_lsm_task_alloc" {
					t.Fatalf("attach state %v does not name the refused target", s)
				}
			}
		})
	}
}
