// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package nativeattach

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Retry is the automatic retry of a whole family transaction refused for
// capacity (G009 user decision): the family stays NotReady, naming the
// trampoline that lacks capacity, and each attempt re-runs the capacity hint
// and then the full transaction. A refused attempt leaves nothing attached,
// so there is never a partial hook set between attempts.
type Retry struct {
	// Initial is the first wait; each further wait doubles, capped at Max.
	Initial, Max time.Duration
	// MaxAttempts bounds the attempts; 0 retries until the context is done.
	MaxAttempts int
	// Budget bounds the total time from the first attempt: a wait that would
	// end past it is not started and the last refusal is returned. 0 means no
	// time bound (only MaxAttempts and the context).
	Budget time.Duration
	// State, if set, is called with the *ErrAttachCapacity of every refused
	// attempt (NotReady, naming the target), with nil once the family is
	// attached (Ready), and with a final non-capacity error that follows a
	// capacity refusal.
	State func(error)
}

// DefaultRetry waits 500ms, 1s, 2s, ... up to 30s between attempts until the
// context is done.
var DefaultRetry = Retry{Initial: 500 * time.Millisecond, Max: 30 * time.Second}

// now is a test seam.
var now = time.Now

// wait is a test seam.
var wait = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run calls attempt until it succeeds. Only *ErrAttachCapacity is retried;
// any other error is returned at once. When ctx is done or MaxAttempts is
// reached, or the next wait would end past Budget, the error wraps both the
// context error (if any) and the last capacity refusal.
func (r Retry) Run(ctx context.Context, attempt func() error) error {
	if r.Initial <= 0 || r.Max < r.Initial || r.MaxAttempts < 0 || r.Budget < 0 {
		return fmt.Errorf("invalid native attach retry %+v", r)
	}
	delay := r.Initial
	start := now()
	for n := 1; ; n++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("native attach retry canceled before attempt %d: %w", n, err)
		}
		err := attempt()
		var capErr *ErrAttachCapacity
		if !errors.As(err, &capErr) {
			// Ready, or a final non-capacity error that replaces an earlier
			// capacity refusal as the last state.
			if r.State != nil && (err == nil || n > 1) {
				r.State(err)
			}
			return err
		}
		if r.State != nil {
			r.State(err)
		}
		if r.MaxAttempts > 0 && n >= r.MaxAttempts {
			return fmt.Errorf("native attach refused after %d attempt(s): %w", n, err)
		}
		if r.Budget > 0 && now().Sub(start)+delay > r.Budget {
			return fmt.Errorf("native attach refused after %d attempt(s), retry budget %s exhausted: %w", n, r.Budget, err)
		}
		if werr := wait(ctx, delay); werr != nil {
			return fmt.Errorf("native attach retry canceled after %d attempt(s): %w", n, errors.Join(werr, err))
		}
		delay = min(2*delay, r.Max)
	}
}
