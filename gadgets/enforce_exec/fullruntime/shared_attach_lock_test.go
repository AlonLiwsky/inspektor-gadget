// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

// These tests run StartNode against a real instance manager. A fake
// trampoline with one free slot stands in for the kernel: an attach takes
// the slot or is refused with *nativeattach.ErrAttachCapacity, and the
// gadget's Stop frees it.

type attachLockRuntime struct{ runtime.Runtime }

func (attachLockRuntime) ParamDescs() params.ParamDescs { return nil }
func (attachLockRuntime) RunGadget(ctx runtime.GadgetContext, _ *params.Params, values api.ParamValues) error {
	return ctx.Run(values)
}

type fakeTrampoline struct {
	mu                sync.Mutex
	holders, attaches int
}

func (f *fakeTrampoline) acquire() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.holders >= 1 {
		return &nativeattach.ErrAttachCapacity{Target: "bpf_lsm_task_alloc", Err: unix.E2BIG}
	}
	f.holders++
	f.attaches++
	return nil
}

func (f *fakeTrampoline) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.holders--
}

func (f *fakeTrampoline) state() (holders, attaches int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.holders, f.attaches
}

// attachOperator mirrors the ebpf operator's native attach: with
// NativeAttachRetryKey false one attempt, with a nativeattach.Retry the
// retry inside Start; the gadget's Stop releases what Start attached.
func attachOperator(f *fakeTrampoline) operators.DataOperator {
	var mu sync.Mutex
	held := false
	attach := func() error {
		if err := f.acquire(); err != nil {
			return err
		}
		mu.Lock()
		held = true
		mu.Unlock()
		return nil
	}
	return simple.New("fake-native-attach",
		simple.OnStart(func(gc operators.GadgetContext) error {
			value, _ := gc.GetVar(operators.NativeAttachRetryKey)
			if retry, ok := value.(nativeattach.Retry); ok {
				return retry.Run(gc.Context(), attach)
			}
			return attach()
		}),
		simple.OnStop(func(operators.GadgetContext) error {
			mu.Lock()
			defer mu.Unlock()
			if held {
				held = false
				f.release()
			}
			return nil
		}))
}

func attachLockDesired(id string) *api.GadgetInstance {
	return &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: "test"}}
}

// managerHostRun is a host Run over m: one StartGadget call per attempt; the
// started gadget then ends as "attached" (the fake has no shared collection
// to report Ready), which StartNode returns as a non-capacity error.
func managerHostRun(m *instancemanager.Manager, id string, f *fakeTrampoline) func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
	return func(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
		stop := func(ctx context.Context) error {
			if err := m.StopGadget(ctx, id); err != nil && !errors.Is(err, instancemanager.ErrNotFound) {
				return err
			}
			return nil
		}
		done := make(chan error, 1)
		err := m.StartGadget(ctx, attachLockDesired(id), opt, gadgetcontext.WithAdditionalDataOperators(attachOperator(f)))
		if err == nil {
			done <- errAttachLockAttached
		}
		return stop, done, err
	}
}

var errAttachLockAttached = errors.New("fake gadget attached")

// attachStateRefused installs an AttachState that closes the returned
// channel on the first capacity refusal.
func attachStateRefused(config *SharedNodeConfig) <-chan struct{} {
	refused := make(chan struct{})
	var once sync.Once
	config.AttachState = func(err error) {
		var capErr *nativeattach.ErrAttachCapacity
		if errors.As(err, &capErr) {
			once.Do(func() { close(refused) })
		}
	}
	return refused
}

func attachLockReceive(t *testing.T, ch <-chan error, within time.Duration) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(within):
		t.Fatalf("StartNode did not return within %s", within)
		return nil
	}
}

// (a) While StartNode backs off after a capacity refusal, the manager's
// lifecycle lock is free: the stop that frees the trampoline returns at once
// (not after the retry budget), and the next attempt attaches.
func TestSharedNodeAttachBackoffReleasesLifecycleLock(t *testing.T) {
	sharedEnableQualification(t)
	m, err := instancemanager.New(attachLockRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTrampoline{}
	ctx := t.Context()
	if err := m.StartGadget(ctx, attachLockDesired("other"), gadgetcontext.WithAdditionalDataOperators(attachOperator(f))); err != nil {
		t.Fatal(err)
	}
	config := sharedQualifiedConfig()
	refused := attachStateRefused(&config)
	// Long waits: with the retry under the lock, StopGadget would block
	// for (at least) a whole wait.
	retry := &nativeattach.Retry{Initial: 3 * time.Second, Max: 3 * time.Second, MaxAttempts: 5, Budget: 20 * time.Second}
	result := make(chan error, 1)
	go func() {
		_, err := StartNode(WithSharedNodeQualification(ctx, SharedNodeQualification{Run: managerHostRun(m, "node", f), attachRetry: retry}), config)
		result <- err
	}()
	select {
	case <-refused:
	case <-time.After(10 * time.Second):
		t.Fatal("no capacity refusal reported")
	}
	if m.LookupInstance("node") != nil {
		t.Fatal("refused attempt still registered during the backoff")
	}
	stopCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	begin := time.Now()
	if err := m.StopGadget(stopCtx, "other"); err != nil {
		t.Fatalf("StopGadget during the attach backoff: %v after %s", err, time.Since(begin))
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("StopGadget took %s during the attach backoff", elapsed)
	}
	// The next attempt attaches; the fake gadget then ends and StartNode
	// tears it down.
	err = attachLockReceive(t, result, 10*time.Second)
	var capErr *nativeattach.ErrAttachCapacity
	if !errors.Is(err, errAttachLockAttached) || errors.As(err, &capErr) {
		t.Fatalf("StartNode %v, want the attached fake gadget's end", err)
	}
	holders, attaches := f.state()
	if holders != 0 || attaches != 2 || m.LookupInstance("node") != nil {
		t.Fatalf("holders %d attaches %d node %v, want everything released", holders, attaches, m.LookupInstance("node"))
	}
}

// (c) Canceling StartNode during the backoff returns promptly, fails closed
// with the typed refusal, and leaves nothing attached or registered.
func TestSharedNodeAttachBackoffCancelLeavesNothing(t *testing.T) {
	sharedEnableQualification(t)
	m, err := instancemanager.New(attachLockRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTrampoline{}
	if err := m.StartGadget(t.Context(), attachLockDesired("other"), gadgetcontext.WithAdditionalDataOperators(attachOperator(f))); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := m.StopGadget(context.Background(), "other"); err != nil {
			t.Error(err)
		}
	}()
	config := sharedQualifiedConfig()
	refused := attachStateRefused(&config)
	retry := &nativeattach.Retry{Initial: time.Minute, Max: time.Minute, MaxAttempts: 3, Budget: 5 * time.Minute}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := StartNode(WithSharedNodeQualification(ctx, SharedNodeQualification{Run: managerHostRun(m, "node", f), attachRetry: retry}), config)
		result <- err
	}()
	select {
	case <-refused:
	case <-time.After(10 * time.Second):
		t.Fatal("no capacity refusal reported")
	}
	begin := time.Now()
	cancel()
	err = attachLockReceive(t, result, time.Second)
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("canceled StartNode returned after %s", elapsed)
	}
	var capErr *nativeattach.ErrAttachCapacity
	if !errors.Is(err, ErrSharedNodeNotReady) || !errors.Is(err, context.Canceled) || !errors.As(err, &capErr) {
		t.Fatalf("canceled StartNode %v, want ErrSharedNodeNotReady wrapping the refusal and the cancel", err)
	}
	holders, attaches := f.state()
	if holders != 1 || attaches != 1 || m.LookupInstance("node") != nil {
		t.Fatalf("holders %d attaches %d node %v, want only the other gadget attached", holders, attaches, m.LookupInstance("node"))
	}
}

// (b) Concurrent StartNode calls on one manager never attach twice: each
// attempt attaches or is refused under the lifecycle lock as one
// StartGadget, and is torn down (stop returned) before its node waits and
// runs the next attempt, so a node never has two attempts alive. (The fake's
// one-slot capacity is enforced by the fake itself; holding it twice is not
// observable, so the checks are attempt overlap, attaches per node and
// leftovers.)
func TestSharedNodeAttachConcurrentStartsNoDoubleAttach(t *testing.T) {
	sharedEnableQualification(t)
	m, err := instancemanager.New(attachLockRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTrampoline{}
	const nodes = 4
	retry := &nativeattach.Retry{Initial: time.Millisecond, Max: 5 * time.Millisecond, MaxAttempts: 200, Budget: 10 * time.Second}
	results := make(chan error, nodes)
	var overlapMu sync.Mutex
	live, runs, overlaps := map[string]int{}, 0, 0
	for k := range nodes {
		go func() {
			id := fmt.Sprintf("node-%d", k)
			inner := managerHostRun(m, id, f)
			run := func(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
				overlapMu.Lock()
				live[id]++
				runs++
				if live[id] > 1 {
					overlaps++
				}
				overlapMu.Unlock()
				stop, done, err := inner(ctx, opt)
				return func(ctx context.Context) error {
					err := stop(ctx)
					if err == nil {
						overlapMu.Lock()
						live[id]--
						overlapMu.Unlock()
					}
					return err
				}, done, err
			}
			_, err := StartNode(WithSharedNodeQualification(t.Context(), SharedNodeQualification{Run: run, attachRetry: retry}), sharedQualifiedConfig())
			results <- err
		}()
	}
	attached := 0
	for range nodes {
		err := attachLockReceive(t, results, 20*time.Second)
		var capErr *nativeattach.ErrAttachCapacity
		switch {
		case errors.Is(err, errAttachLockAttached) && !errors.As(err, &capErr):
			attached++
		case errors.Is(err, ErrSharedNodeNotReady) && errors.As(err, &capErr):
		default:
			t.Fatalf("StartNode %v, want attached or a NotReady capacity refusal", err)
		}
	}
	holders, attaches := f.state()
	if holders != 0 || attaches != attached || attached == 0 {
		t.Fatalf("holders %d attaches %d attached nodes %d, want one attach per attached node and nothing left", holders, attaches, attached)
	}
	overlapMu.Lock()
	defer overlapMu.Unlock()
	if overlaps != 0 || runs <= nodes {
		t.Fatalf("overlapping attempts %d over %d runs (live %v), want every attempt torn down before the next and some retries", overlaps, runs, live)
	}
	for id, n := range live {
		if n != 0 {
			t.Fatalf("%s: %d attempt(s) never torn down", id, n)
		}
	}
	for k := range nodes {
		if m.LookupInstance(fmt.Sprintf("node-%d", k)) != nil {
			t.Fatalf("node-%d still registered", k)
		}
	}
}
