// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"os"
	"testing"
)

func sharedPreparedHost(t *testing.T) (*NodeEnforcer, *sharedHostContext) {
	t.Helper()
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "development"})
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	gc := &sharedHostContext{vars: map[string]any{}, image: "development"}
	n.host.context = gc
	n.host.claimed = true
	thread, err := startControlThread(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	n.host.control = &sharedControl{thread: thread}
	t.Cleanup(func() { _ = thread.close() })
	return n, gc
}

func TestSharedHostPreparedStartupFailureCleanup(t *testing.T) {
	n, gc := sharedPreparedHost(t)
	lease := &sharedTestLease{}
	s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 42, InitHostPID: 10, Acquire: func(context.Context) (BindingLease, error) { return lease, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Ready(gc); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatal("unexpected readiness", err)
	}
	if err := n.BeforeStop(t.Context()); err != nil {
		t.Fatal("prepared binding deadlocked cleanup", err)
	}
	if !s.Inspect().Removed || !n.host.commandsJoined || lease.closes != 0 {
		t.Fatal("preparation not retired or pin dropped before detach")
	}
	if err := n.ReleaseAfterDetach(); err == nil {
		t.Fatal("BeforeStop inferred operator teardown")
	}
	if err := n.Close(gc); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	if lease.closes != 1 {
		t.Fatal("retained physical pins not closed after detach")
	}
	if err := n.ReleaseAfterDetach(); err != nil || lease.closes != 1 {
		t.Fatal("duplicate physical close", err)
	}
}

func TestSharedHostCancelsAndJoinsPreparation(t *testing.T) {
	n, gc := sharedPreparedHost(t)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	lease := &sharedTestLease{}
	go func() {
		_, err := n.Bind(context.Background(), SharedBindingConfig{CgroupID: 42, InitHostPID: 10, Acquire: func(ctx context.Context) (BindingLease, error) {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
			return lease, ctx.Err()
		}})
		done <- err
	}()
	<-entered
	stopCtx, cancel := context.WithCancel(context.Background())
	stopDone := make(chan error, 1)
	go func() { stopDone <- n.BeforeStop(stopCtx) }()
	<-canceled
	cancel()
	if err := <-stopDone; !errors.Is(err, context.Canceled) {
		t.Fatal("unjoined preparation not retained", err)
	}
	if n.host.commandsJoined || n.host.operatorClosed || n.host.released || lease.closes != 0 {
		t.Fatal("timeout discarded ownership")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("canceled preparation succeeded")
	}
	if err := n.Close(gc); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	if lease.closes != 1 {
		t.Fatal("partial lease cleanup count")
	}
}

// Real unprivileged file descriptors model the host's borrowed-FD close
// boundary; this is not a BPF descriptor/attachment proof.
type sharedTestBorrowedFD struct{ file *os.File }

func (f sharedTestBorrowedFD) FD() int { return int(f.file.Fd()) }
func TestSharedHostWaitsForBorrowedDescriptorClosure(t *testing.T) {
	n, gc := sharedPreparedHost(t)
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n.host.borrowed = []sharedBorrowedFD{sharedTestBorrowedFD{f}}
	lease := &sharedTestLease{}
	if _, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 42, InitHostPID: 10, Acquire: func(context.Context) (BindingLease, error) { return lease, nil }}); err != nil {
		t.Fatal(err)
	}
	if err := n.Close(gc); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err == nil || lease.closes != 0 {
		t.Fatal("live borrowed descriptor released physical pins")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err != nil || lease.closes != 1 {
		t.Fatal("closed borrowed descriptor did not permit cleanup", err)
	}
}

func TestSharedHostRegisteredAuthorityStillRequiresWithdrawal(t *testing.T) {
	n, gc := sharedPreparedHost(t)
	lease := &sharedTestLease{}
	s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 42, InitHostPID: 10, Acquire: func(context.Context) (BindingLease, error) { return lease, nil }})
	if err != nil {
		t.Fatal(err)
	}
	s.account.registration = sharedReceiptWire{Operation: sharedBindingOpen, Sequence: 450} // test-only receipt injection
	if err := n.BeforeStop(t.Context()); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatal("registered binding bypassed withdrawal", err)
	}
	if n.host.commandsJoined || n.host.operatorClosed || lease.closes != 0 {
		t.Fatal("registered authority discarded")
	}
	if err := n.Close(gc); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatal("Close bypassed registered authority", err)
	}
	if err := n.ReleaseAfterDetach(); err == nil {
		t.Fatal("unjoined registered authority released")
	}
}

func TestSharedHostPreparedPanicKeepsDiagnosticNotOwnership(t *testing.T) {
	n, gc := sharedPreparedHost(t)
	lease := &sharedTestLease{}
	if _, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 42, InitHostPID: 10, Acquire: func(context.Context) (BindingLease, error) { return lease, nil }}); err != nil {
		t.Fatal(err)
	}
	if err := n.host.control.thread.do(t.Context(), func() error { panic("sticky failure") }); err == nil {
		t.Fatal("panic diagnostic lost")
	}
	if err := n.Close(gc); err == nil {
		t.Fatal("joined sticky diagnostic lost")
	}
	if !n.host.operatorClosed || !n.host.commandsJoined || lease.closes != 0 {
		t.Fatal("joined completion confused with diagnostic")
	}
	if err := n.ReleaseAfterDetach(); err != nil || lease.closes != 1 {
		t.Fatal("joined diagnostic leaked physical pins", err)
	}
}

func TestSharedHostPartialStartCannotReplaceBorrowedLedger(t *testing.T) {
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "development"})
	if err != nil {
		t.Fatal(err)
	}
	gc := &sharedHostContext{vars: map[string]any{}, image: "development"}
	n.host.claimed = true
	n.host.context = gc
	if err := n.Start(gc); err == nil || !n.host.startAttempted {
		t.Fatal("missing actual resources accepted or attempt lost")
	}
	f, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n.host.borrowed = []sharedBorrowedFD{sharedTestBorrowedFD{f}}
	if err := n.Start(gc); err == nil || len(n.host.borrowed) != 1 {
		t.Fatal("retry replaced partial borrowed-handle ownership")
	}
	if err := n.Close(gc); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err == nil {
		t.Fatal("partial live handle ignored")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
}
