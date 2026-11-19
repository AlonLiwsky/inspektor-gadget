// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

type operationParent struct {
	context.Context
	registrations atomic.Int32
	doneReads     atomic.Int32
}

func (p *operationParent) Done() <-chan struct{} { p.doneReads.Add(1); return p.Context.Done() }
func (p *operationParent) AfterFunc(func()) func() bool {
	p.registrations.Add(1)
	return func() bool { return true }
}

// Hide the standard cancellation key so a WithCancel implementation cannot
// bypass this parent's observable AfterFunc registration.
func (p *operationParent) Value(any) any { return nil }

func TestSharedOperationRequiresCompletedHandshake(t *testing.T) {
	n, _, _ := sharedRegistryFixture(t)
	n.host.handshakeComplete = false
	refused := func() {
		ctx, finish, err := n.beginSharedObjectOperation(context.Background())
		if !errors.Is(err, ErrSharedNativeUnavailable) || ctx != nil || finish != nil || n.objects.operation.done != nil || n.objects.operation.cancel != nil {
			t.Fatal("incomplete handshake admitted or registered a worker operation", err)
		}
	}
	refused()
	if allocated := testing.AllocsPerRun(10, refused); allocated != 0 {
		t.Fatalf("handshake refusal allocated: %v", allocated)
	}
	// This fixture-only toggle exercises admission, not the real startup
	// handshake or its successful Program.Run feature-cache premise.
	n.host.handshakeComplete = true
	ctx, finish, err := n.beginSharedObjectOperation(context.Background())
	if err != nil || ctx == nil || finish == nil {
		t.Fatal("completed fixture handshake did not admit operation", err)
	}
	finished := false
	defer func() {
		if !finished {
			finish()
		}
	}()
	done := n.objects.operation.done
	if done == nil || n.objects.operation.cancel == nil {
		t.Fatal("admitted operation was not registered")
	}
	finish()
	finished = true
	select {
	case <-done:
	default:
		t.Fatal("operation was not joined")
	}
	n.host.handshakeComplete = false
	refused()
}

func TestSharedOperationNoParentRegistration(t *testing.T) {
	n, _, _ := sharedRegistryFixture(t)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &operationParent{Context: base}
	ctx, finish, err := n.beginSharedObjectOperation(p)
	if err != nil {
		t.Fatal(err)
	}
	finish()
	if p.registrations.Load() != 0 || p.doneReads.Load() != 1 {
		t.Fatalf("foreign registration=%d Done reads=%d", p.registrations.Load(), p.doneReads.Load())
	}
	if ctx.Err() != context.Canceled {
		t.Fatal(ctx.Err())
	}
}

func TestSharedOperationParentSemantics(t *testing.T) {
	type key struct{}
	deadline := time.Now().Add(time.Hour)
	base, stop := context.WithDeadline(context.WithValue(context.Background(), key{}, "value"), deadline)
	defer stop()
	parent, cancel := context.WithCancelCause(base)
	n, _, _ := sharedRegistryFixture(t)
	ctx, finish, err := n.beginSharedObjectOperation(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	if d, ok := ctx.Deadline(); !ok || d != deadline || ctx.Value(key{}) != "value" {
		t.Fatal("lost deadline/value")
	}
	cancel(errors.New("private caller cause"))
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("no cancellation")
	}
	if ctx.Err() != context.Canceled || context.Cause(ctx) != context.Canceled { //nolint:errorlint // Assert the exact Context/operation sentinel, not wrapping compatibility.
		t.Fatal("foreign cause leaked", ctx.Err(), context.Cause(ctx))
	}
}

type operationBlockingLease struct {
	BindingLease
	entered chan struct{}
}

func (l *operationBlockingLease) Check(ctx context.Context) error {
	close(l.entered)
	<-ctx.Done()
	return ctx.Err()
}

func TestSharedOperationStopWakesLease(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	lease := &operationBlockingLease{BindingLease: s.account.pins.lease, entered: make(chan struct{})}
	s.account.pins.lease = lease
	s.account.pins.checkTest = nil
	result := make(chan error, 1)
	go func() {
		_, err := s.prepareSharedObjectsUsing(context.Background(), []fullpolicy.Policy{sharedRegistryPolicy()}, &sharedObjectUploadTransport{})
		result <- err
	}()
	<-lease.entered
	if err := n.cancelAndJoinPreparations(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != context.Canceled { //nolint:errorlint // Assert the exact Context/operation sentinel, not wrapping compatibility.
		t.Fatal(err)
	}
}

func TestSharedOperationConcurrentTerminalStable(t *testing.T) {
	for range 50 {
		n, _, _ := sharedRegistryFixture(t)
		parent, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		ctx, finish, err := n.beginSharedObjectOperation(parent)
		if err != nil {
			t.Fatal(err)
		}
		n.mu.Lock()
		operation := n.objects.operation
		n.mu.Unlock()
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				cancel()
				operation.cancel()
				<-ctx.Done()
				if ctx.Err() != context.Canceled || context.Cause(ctx) != context.Canceled { //nolint:errorlint // Assert the exact Context/operation sentinel, not wrapping compatibility.
					t.Error("unstable terminal state")
				}
			})
		}
		wg.Wait()
		finish()
		select {
		case <-operation.done:
		default:
			t.Fatal("finish did not join")
		}
	}
}

// A valid, stable terminal Err whose caller deliberately delays returning lets
// the test hold the relay before its final acknowledgement without a hook.
type operationDelayedParent struct {
	context.Context
	done    chan struct{}
	entered chan struct{}
	release chan struct{}
}

func (p *operationDelayedParent) Done() <-chan struct{} { return p.done }
func (p *operationDelayedParent) Err() error {
	select {
	case <-p.done:
		close(p.entered)
		<-p.release
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func TestSharedOperationFinishWaitsForRelayFinalAccess(t *testing.T) {
	n, _, _ := sharedRegistryFixture(t)
	p := &operationDelayedParent{Context: context.Background(), done: make(chan struct{}), entered: make(chan struct{}), release: make(chan struct{})}
	ctx, finish, err := n.beginSharedObjectOperation(p)
	if err != nil {
		t.Fatal(err)
	}
	op := ctx.(*sharedOperationContext)
	close(p.done)
	<-p.entered
	finishing := make(chan struct{})
	go func() { finish(); close(finishing) }()
	<-ctx.Done() // finish has cancelled, but the relay has not returned.
	select {
	case <-op.operationDone:
		t.Fatal("published completion before relay exit")
	default:
	}
	n.mu.Lock()
	registered := n.objects.operation.done == op.operationDone
	n.mu.Unlock()
	if !registered {
		t.Fatal("lost registered operation")
	}
	if _, _, err := n.beginSharedObjectOperation(context.Background()); err != ErrSharedNativeUnavailable { //nolint:errorlint // Assert the exact Context/operation sentinel, not wrapping compatibility.
		t.Fatal("admitted overlapping operation", err)
	}
	if err := n.ReleaseAfterDetach(); err == nil {
		t.Fatal("released while relay still accessing operation")
	}
	close(p.release)
	<-finishing
	if ctx.Err() != context.Canceled {
		t.Fatal("later caller error changed winning cancellation")
	}
	select {
	case <-op.relayJoined:
	default:
		t.Fatal("relay not joined")
	}
	select {
	case <-op.operationDone:
	default:
		t.Fatal("operation not completed")
	}
}

func TestSharedOperationDeadlineAndAlreadyCancelled(t *testing.T) {
	n, _, _ := sharedRegistryFixture(t)
	parent, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Millisecond))
	defer cancel()
	ctx, finish, err := n.beginSharedObjectOperation(parent)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("deadline not propagated")
	}
	if ctx.Err() != context.DeadlineExceeded || context.Cause(ctx) != context.DeadlineExceeded { //nolint:errorlint // Assert the exact Context/operation sentinel, not wrapping compatibility.
		t.Fatal("deadline sentinel lost")
	}
	finish()
	if _, _, err := n.beginSharedObjectOperation(parent); err != context.DeadlineExceeded { //nolint:errorlint // Assert the exact Context/operation sentinel, not wrapping compatibility.
		t.Fatal("already cancelled parent admitted", err)
	}
	if n.objects.operation.done != nil {
		t.Fatal("refusal changed registration")
	}
}

func TestSharedOperationErrObservesSynchronousCallerCancellation(t *testing.T) {
	for range 100 {
		n, _, _ := sharedRegistryFixture(t)
		parent, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		ctx, finish, err := n.beginSharedObjectOperation(parent)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		if ctx.Err() != context.Canceled {
			t.Fatal("command-boundary cancellation delayed until relay scheduling")
		}
		finish()
	}
}
