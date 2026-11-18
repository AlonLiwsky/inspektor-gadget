// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Unit tests drive startLiveCandidate through fake native hosts whose gadget
// context publishes no kernel map and whose receipts carry fake program IDs:
// for those (and only those) the canary and the witness are skipped. A
// context that publishes the real d1_witness map always gets the real path.
func init() {
	start := sharedStartKernelWitness
	sharedStartKernelWitness = func(gc operators.GadgetContext, receipts map[string]*operators.NativeAttachment, interval time.Duration) (*sharedLiveKernelWitness, error) {
		value, _ := gc.GetVar(operators.MapPrefix + sharedKernelWitnessMap)
		if m, _ := value.(*ebpf.Map); m == nil {
			return nil, nil
		}
		return start(gc, receipts, interval)
	}
}

// TestSharedKernelWitnessVerdict: the latch rule of the D1 kernel witness.
func TestSharedKernelWitnessVerdict(t *testing.T) {
	for name, tc := range map[string]struct {
		cells [sharedKernelWitnessCells]uint64
		bad   bool
	}{
		"quiet":                        {},
		"balanced counts":              {cells: [11]uint64{10, 10, 7, 7}},
		"banked credit is no fault":    {cells: [11]uint64{9, 10, 7, 9}},
		"counts alone never latch":     {cells: [11]uint64{11, 10, 8, 7}},
		"healed frames are no fault":   {cells: [11]uint64{1, 1, 1, 1, 0, 5}},
		"mark failures alone":          {cells: [11]uint64{10: 3}},
		"exec without its mark":        {cells: [11]uint64{6: 1}, bad: true},
		"fork without its mark":        {cells: [11]uint64{7: 1}, bad: true},
		"ftrace seen off":              {cells: [11]uint64{10, 10, 7, 7, 1}, bad: true},
		"ksym unresolved":              {cells: [11]uint64{9: 1}, bad: true},
		"unmarked under banked credit": {cells: [11]uint64{0: 5, 1: 50, 2: 5, 3: 50, 6: 2, 7: 2}, bad: true},
	} {
		err := sharedKernelWitnessVerdict(tc.cells)
		if (err != nil) != tc.bad || (err != nil && !errors.Is(err, ErrSharedKernelWitness)) {
			t.Errorf("%s: %v, want fault %v", name, err, tc.bad)
		}
	}
	// The startup check: the ftrace ksym must have resolved.
	for name, tc := range map[string]struct {
		cells [sharedKernelWitnessCells]uint64
		ok    bool
	}{
		"armed":               {cells: [11]uint64{8: 1}, ok: true},
		"never saw a syscall": {},
		"unresolved":          {cells: [11]uint64{9: 1}},
		"both (impossible)":   {cells: [11]uint64{8: 1, 9: 1}},
		"armed but unmarked":  {cells: [11]uint64{6: 1, 8: 1}},
	} {
		if err := sharedKernelWitnessArmed(tc.cells); (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrSharedKernelWitness)) {
			t.Errorf("armed %s: %v, want ok %v", name, err, tc.ok)
		}
	}
	// N3: only an unmarked exec or fork at start (ftrace on, ksym armed) is
	// retryable; ftrace seen off or an unresolved ksym never is.
	for name, tc := range map[string]struct {
		cells     [sharedKernelWitnessCells]uint64
		retryable bool
	}{
		"unmarked exec at start":       {cells: [11]uint64{6: 1, 8: 1}, retryable: true},
		"unmarked fork at start":       {cells: [11]uint64{7: 2, 8: 1}, retryable: true},
		"ftrace seen off at start":     {cells: [11]uint64{4: 1, 6: 1, 8: 1}},
		"ksym unresolved":              {cells: [11]uint64{9: 1}},
		"unmarked with a mark failure": {cells: [11]uint64{6: 1, 8: 1, 10: 1}},
	} {
		err := sharedKernelWitnessArmed(tc.cells)
		if !errors.Is(err, ErrSharedKernelWitness) || errors.Is(err, ErrSharedKernelWitnessRetryable) != tc.retryable {
			t.Errorf("start %s: %v, want retryable %v", name, err, tc.retryable)
		}
	}
	// The latch: a later clean reading never clears a fault.
	readings := [][sharedKernelWitnessCells]uint64{{6: 1}, {}}
	w := &sharedLiveKernelWitness{read: func() ([sharedKernelWitnessCells]uint64, error) {
		r := readings[0]
		if len(readings) > 1 {
			readings = readings[1:]
		}
		return r, nil
	}}
	if err := w.check(); !errors.Is(err, ErrSharedKernelWitness) {
		t.Fatalf("first reading: %v", err)
	}
	if err := w.check(); !errors.Is(err, ErrSharedKernelWitness) {
		t.Fatalf("the fault was cleared by a clean reading: %v", err)
	}
}

// TestSharedKernelWitnessConcurrentClose: NodeEnforcer.stopLiveHealth runs
// from Stop (the gadget goroutine), Close and stopLiveCollection (StopNode),
// which can overlap. The witness closer must join its poller and take the
// final reading exactly once (it panicked with "close of closed channel" on
// Fedora 43, step m4-s9), and every caller must return after it is closed.
func TestSharedKernelWitnessConcurrentClose(t *testing.T) {
	for round := 0; round < 200; round++ {
		var reads atomic.Int64
		w := &sharedLiveKernelWitness{interval: time.Microsecond, read: func() ([sharedKernelWitnessCells]uint64, error) {
			reads.Add(1)
			return [sharedKernelWitnessCells]uint64{}, nil
		}}
		w.start()
		n := &NodeEnforcer{host: &sharedHostState{live: &sharedLiveCandidate{witness: w}}}
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(2)
			go func() { defer wg.Done(); n.stopLiveHealth() }()
			go func() { defer wg.Done(); w.close() }()
		}
		wg.Wait()
		w.mu.Lock()
		closed := w.closed
		w.mu.Unlock()
		if !closed {
			t.Fatalf("round %d: witness not closed", round)
		}
		// Closed: the maps are never read again.
		after := reads.Load()
		w.sample()
		if err := w.check(); err != nil || reads.Load() != after {
			t.Fatalf("round %d: read after close (%d -> %d), err %v", round, after, reads.Load(), err)
		}
	}
}

// TestStartNodeRetrying (S1 review N3): only ErrSharedKernelWitnessRetryable
// is retried, at most attempts times, with doubling capped backoff; any
// other refusal returns at once; a canceled context ends the wait.
func TestStartNodeRetrying(t *testing.T) {
	retryable := fmt.Errorf("start: %w (%w)", ErrSharedKernelWitness, ErrSharedKernelWitnessRetryable)
	permanent := fmt.Errorf("start: %w: ftrace off", ErrSharedKernelWitness)
	node := &NodeEnforcer{}
	for name, tc := range map[string]struct {
		errs     []error // per call; past the end: success
		attempts int
		calls    int
		ok       bool
	}{
		"first try":                {nil, 3, 1, true},
		"race then success":        {[]error{retryable, retryable}, 3, 3, true},
		"race every time, bounded": {[]error{retryable, retryable, retryable, retryable}, 3, 3, false},
		"permanent at once":        {[]error{permanent, nil}, 3, 1, false},
		"race then permanent":      {[]error{retryable, permanent}, 5, 2, false},
	} {
		calls := 0
		var waits []time.Duration
		last := time.Now()
		n, err := StartNodeRetrying(context.Background(), tc.attempts, time.Millisecond, 3*time.Millisecond, func(context.Context) (*NodeEnforcer, error) {
			waits = append(waits, time.Since(last))
			last = time.Now()
			calls++
			if calls <= len(tc.errs) && tc.errs[calls-1] != nil {
				return nil, tc.errs[calls-1]
			}
			return node, nil
		})
		if calls != tc.calls || (err == nil) != tc.ok || (tc.ok && n != node) {
			t.Errorf("%s: calls %d err %v, want calls %d ok %v", name, calls, err, tc.calls, tc.ok)
		}
		// Doubling, capped: waits before calls 2, 3, 4 are >= 1, 2, 3 ms.
		for i, min := range []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond} {
			if i+1 < len(waits) && waits[i+1] < min {
				t.Errorf("%s: wait before call %d was %v, want >= %v", name, i+2, waits[i+1], min)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StartNodeRetrying(ctx, 5, time.Hour, time.Hour, func(context.Context) (*NodeEnforcer, error) { return nil, retryable }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
}
