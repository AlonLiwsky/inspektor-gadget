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

// The shared node never retries inside the gadget's Start (that would hold
// the host manager's lifecycle lock across every backoff wait):
// WithNodeEnforcer sets NativeAttachRetryKey to false and admission refuses
// any other value. StartNode's own retry is bounded, and StartNode refuses an
// unbounded one before running anything.
func TestSharedNodeAttachFailFastInStart(t *testing.T) {
	n, err := NewNodeEnforcer(sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	gc := gadgetcontext.New(t.Context(), n.config.Image, WithNodeEnforcer(n))
	if value, ok := gc.GetVar(operators.NativeAttachRetryKey); !ok || value != false {
		t.Fatalf("WithNodeEnforcer retry %T %+v, want false (no retry inside Start)", value, value)
	}
	retry := sharedNodeAttachRetry()
	if err := sharedNodeRetryBounded(retry); err != nil {
		t.Fatal(err)
	}
	var waits time.Duration
	for d, k := retry.Initial, 1; k < retry.MaxAttempts; k++ {
		waits += d
		d = min(2*d, retry.Max)
	}
	if retry.Budget > time.Minute || waits > time.Minute {
		t.Fatalf("shared node retry may delay StartNode for %s (budget %s)", waits, retry.Budget)
	}

	validator, _ := gc.GetVar(operators.NativeResourceValidatorKey)
	validate := validator.(func(*operators.NativeResources) error)
	for name, v := range map[string]any{
		"true":               true,
		"default unbounded":  nativeattach.DefaultRetry,
		"bounded in Start":   sharedNodeAttachRetry(),
		"not a retry policy": "bounded",
	} {
		gc.SetVar(operators.NativeAttachRetryKey, v)
		if err := validate(sharedCandidateFakeManifest()); err == nil || !strings.Contains(err.Error(), "fail-fast native attach") {
			t.Fatalf("%s: admission %v, want the fail-fast refusal", name, err)
		}
	}
	gc.SetVar(operators.NativeAttachRetryKey, false)
	if err := sharedNodeAttachFailFast(gc); err != nil {
		t.Fatalf("fail-fast shared node attach refused: %v", err)
	}

	sharedEnableQualification(t)
	for name, r := range map[string]nativeattach.Retry{
		"default unbounded": nativeattach.DefaultRetry,
		"no attempt bound":  {Initial: time.Millisecond, Max: time.Millisecond, Budget: time.Second},
		"no time budget":    {Initial: time.Millisecond, Max: time.Millisecond, MaxAttempts: 3},
	} {
		runs := 0
		run := func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
			runs++
			return nil, nil, errors.New("unexpected run")
		}
		_, err := StartNode(WithSharedNodeQualification(t.Context(), SharedNodeQualification{Run: run, attachRetry: &r}), sharedQualifiedConfig())
		if err == nil || !strings.Contains(err.Error(), "bounded native attach retry") || runs != 0 {
			t.Fatalf("%s: StartNode %v runs %d, want the bounded-retry refusal before any run", name, err, runs)
		}
	}
}

// Through StartNode: each attempt is one host Run (one StartGadget) that
// fails at once on a capacity refusal and is torn down before StartNode
// waits. The host sees every refusal (SharedNodeConfig.AttachState), then nil
// once started; an exhausted retry ends StartNode (it never hangs), fails
// closed (no node, every attempt torn down) and is NotReady.
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
			attempts, stops, live := 0, 0, 0
			run := func(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
				gc := gadgetcontext.New(ctx, config.Image, opt)
				if value, _ := gc.GetVar(operators.NativeAttachRetryKey); value != false {
					t.Fatalf("retry inside Start: %T %+v", value, value)
				}
				if live != 0 {
					t.Fatalf("attempt %d runs beside %d live attempt(s)", attempts+1, live)
				}
				attempts++
				live++
				stop := func(context.Context) error { stops++; live--; return nil }
				done := make(chan error, 1)
				// The operator's fail-fast attach transaction.
				if tc.refusals < 0 || attempts <= tc.refusals {
					return stop, done, refusal()
				}
				done <- errors.New("test gadget ends after attaching")
				return stop, done, nil
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
			if attempts != 3 || stops != 3 || live != 0 || len(states) != 3 {
				t.Fatalf("attempts %d stops %d live %d states %v, want 3 attempts, each torn down, 3 states", attempts, stops, live, states)
			}
			if tc.refusals < 0 {
				if !errors.Is(err, ErrSharedNodeNotReady) || !errors.As(err, &capErr) || errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("exhausted attach: %v, want ErrSharedNodeNotReady wrapping the capacity refusal", err)
				}
			} else if states[2] != nil || errors.As(err, &capErr) {
				t.Fatalf("states %v err %v, want two refusals then nil and a non-capacity end", states, err)
			}
			for _, s := range states[:2] {
				if !errors.As(s, &capErr) || capErr.Target != "bpf_lsm_task_alloc" {
					t.Fatalf("attach state %v does not name the refused target", s)
				}
			}
		})
	}
}

// A failed teardown of a refused attempt ends StartNode: no further attempt
// may run beside something possibly still attached.
func TestSharedNodeAttachRetryStopsOnTeardownFailure(t *testing.T) {
	sharedEnableQualification(t)
	runs := 0
	teardown := errors.New("injected teardown failure")
	run := func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
		runs++
		return func(context.Context) error { return teardown }, make(chan error, 1),
			&nativeattach.ErrAttachCapacity{Target: "bpf_lsm_task_alloc", Err: unix.E2BIG}
	}
	small := &nativeattach.Retry{Initial: time.Millisecond, Max: time.Millisecond, MaxAttempts: 5, Budget: time.Second}
	var states []error
	config := sharedQualifiedConfig()
	config.AttachState = func(err error) { states = append(states, err) }
	_, err := StartNode(WithSharedNodeQualification(t.Context(), SharedNodeQualification{Run: run, attachRetry: small}), config)
	var capErr *nativeattach.ErrAttachCapacity
	if runs != 1 || !errors.Is(err, teardown) || !errors.Is(err, ErrSharedNodeNotReady) || !errors.As(err, &capErr) {
		t.Fatalf("runs %d err %v, want one run and the typed refusal joined with the teardown failure", runs, err)
	}
	// The host sees the refusal the returned error wraps as the last state.
	if len(states) == 0 || !errors.As(states[len(states)-1], &capErr) || capErr.Target != "bpf_lsm_task_alloc" {
		t.Fatalf("attach states %v, want the refusal last", states)
	}
}
