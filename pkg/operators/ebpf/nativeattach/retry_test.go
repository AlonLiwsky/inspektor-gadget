// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package nativeattach

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func stubWait(t *testing.T, onWait func(time.Duration)) *[]time.Duration {
	t.Helper()
	old := wait
	t.Cleanup(func() { wait = old })
	var waits []time.Duration
	wait = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		if onWait != nil {
			onWait(d)
		}
		return ctx.Err()
	}
	return &waits
}

func capacityErr(target string) error {
	return &ErrAttachCapacity{Target: target, Err: unix.E2BIG}
}

func TestRetrySucceedsOnceCapacityFrees(t *testing.T) {
	waits := stubWait(t, nil)
	var states []error
	r := Retry{Initial: time.Second, Max: 4 * time.Second, State: func(err error) { states = append(states, err) }}
	attempts := 0
	err := r.Run(context.Background(), func() error {
		attempts++
		if attempts < 5 {
			return capacityErr("bprm_execve")
		}
		return nil
	})
	if err != nil || attempts != 5 {
		t.Fatalf("err %v after %d attempts", err, attempts)
	}
	if want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}; !slices.Equal(*waits, want) {
		t.Fatalf("backoff %v, want %v", *waits, want)
	}
	if len(states) != 5 || states[4] != nil {
		t.Fatalf("states %v", states)
	}
	for _, s := range states[:4] {
		var capErr *ErrAttachCapacity
		if !errors.As(s, &capErr) || capErr.Target != "bprm_execve" {
			t.Fatalf("NotReady state %v does not name the target", s)
		}
	}
}

func TestRetryStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stubWait(t, func(time.Duration) { cancel() })
	var states []error
	r := Retry{Initial: time.Millisecond, Max: time.Millisecond, State: func(err error) { states = append(states, err) }}
	attempts := 0
	err := r.Run(ctx, func() error { attempts++; return capacityErr("bpf_lsm_bprm_check_security") })
	var capErr *ErrAttachCapacity
	if !errors.Is(err, context.Canceled) || !errors.As(err, &capErr) || capErr.Target != "bpf_lsm_bprm_check_security" || attempts != 1 {
		t.Fatalf("err %v after %d attempts", err, attempts)
	}
	if len(states) != 1 || states[0] == nil {
		t.Fatalf("canceled retry reported Ready: %v", states)
	}
	if err := r.Run(ctx, func() error { t.Fatal("attempt after cancel"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
}

func TestRetryBoundsAndNonCapacityErrors(t *testing.T) {
	waits := stubWait(t, nil)
	attempts := 0
	err := Retry{Initial: time.Millisecond, Max: time.Second, MaxAttempts: 3}.Run(context.Background(), func() error {
		attempts++
		return capacityErr("bprm_execve")
	})
	if !errors.Is(err, unix.E2BIG) || attempts != 3 || len(*waits) != 2 {
		t.Fatalf("bounded retry: %v after %d attempts, %d waits", err, attempts, len(*waits))
	}
	other := errors.New("verifier")
	attempts = 0
	if err := DefaultRetry.Run(context.Background(), func() error { attempts++; return other }); !errors.Is(err, other) || attempts != 1 {
		t.Fatalf("non-capacity error retried: %v after %d", err, attempts)
	}
	for _, bad := range []Retry{{}, {Initial: time.Second, Max: time.Millisecond}, {Initial: 1, Max: 1, MaxAttempts: -1}} {
		if err := bad.Run(context.Background(), func() error { t.Fatal("attempt with invalid policy"); return nil }); err == nil {
			t.Fatalf("invalid policy %+v accepted", bad)
		}
	}
}

func TestRetryStateReportsFinalNonCapacityError(t *testing.T) {
	stubWait(t, nil)
	var states []error
	other := errors.New("verifier")
	attempts := 0
	r := Retry{Initial: time.Millisecond, Max: time.Millisecond, State: func(err error) { states = append(states, err) }}
	err := r.Run(context.Background(), func() error {
		attempts++
		if attempts == 1 {
			return capacityErr("bprm_execve")
		}
		return other
	})
	if !errors.Is(err, other) || attempts != 2 || len(states) != 2 || !errors.Is(states[1], other) {
		t.Fatalf("err %v after %d attempts, states %v", err, attempts, states)
	}
	// A first-attempt non-capacity error was never NotReady; State stays silent.
	states = nil
	if err := r.Run(context.Background(), func() error { return other }); !errors.Is(err, other) || len(states) != 0 {
		t.Fatalf("first-attempt error: %v states %v", err, states)
	}
}

func TestRetryBudgetBoundsTotalTime(t *testing.T) {
	clock := time.Unix(0, 0)
	oldNow := now
	t.Cleanup(func() { now = oldNow })
	now = func() time.Time { return clock }
	// Each attempt itself takes 100ms; each wait advances the clock by its delay.
	waits := stubWait(t, func(d time.Duration) { clock = clock.Add(d) })
	attempts := 0
	r := Retry{Initial: time.Second, Max: 4 * time.Second, Budget: 5 * time.Second}
	err := r.Run(context.Background(), func() error {
		attempts++
		clock = clock.Add(100 * time.Millisecond)
		return capacityErr("bprm_execve")
	})
	// 0.1 + 1 + 0.1 + 2 + 0.1 = 3.3s after attempt 3; a 4s wait would end at 7.3s > 5s.
	var capErr *ErrAttachCapacity
	if !errors.As(err, &capErr) || capErr.Target != "bprm_execve" || !errors.Is(err, unix.E2BIG) || attempts != 3 {
		t.Fatalf("budget: %v after %d attempts", err, attempts)
	}
	if want := []time.Duration{time.Second, 2 * time.Second}; !slices.Equal(*waits, want) {
		t.Fatalf("waits %v, want %v", *waits, want)
	}
	if clock.Sub(time.Unix(0, 0)) > r.Budget {
		t.Fatalf("retry ran %s past budget %s", clock.Sub(time.Unix(0, 0)), r.Budget)
	}
	if err := (Retry{Initial: 1, Max: 1, Budget: -1}).Run(context.Background(), func() error { t.Fatal("attempt with invalid budget"); return nil }); err == nil {
		t.Fatal("negative budget accepted")
	}
}
