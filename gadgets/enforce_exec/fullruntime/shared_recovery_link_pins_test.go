// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type recoveryPinTestLease struct {
	name   string
	fd     int
	closed bool
	check  error
}

func (l *recoveryPinTestLease) FD() int         { return l.fd }
func (l *recoveryPinTestLease) PinName() string { return l.name }
func (l *recoveryPinTestLease) Check() error    { return l.check }
func (l *recoveryPinTestLease) Close() error {
	l.closed = true
	return nil
}

func recoveryPinTestContext(t *testing.T, pin func(string, int) (operators.NativePinnedLink, error)) (SharedProfile, *sharedHostContext) {
	t.Helper()
	profile, manifest := sharedRecoveryFixture(t)
	gc := &sharedHostContext{vars: map[string]any{}}
	gc.SetVar(operators.NativeRecoveryTestRunKey, true)
	gc.SetVar(operators.NativeResourcesKey, manifest)
	for idx, entry := range sharedRecoveryTaskLinks {
		name := entry.program
		gc.SetVar(operators.NativeAttachmentPrefix+name, &operators.NativeAttachment{
			Type: uint32(ebpf.LSM), Target: entry.target,
			LinkID: uint32(idx + 1), ProgramID: uint32(idx + 11),
			Check: func() error { return nil },
			PinAt: func(fd int) (operators.NativePinnedLink, error) { return pin(name, fd) },
		})
	}
	return profile, gc
}

func TestSharedRecoveryLinkPinLedgerRetainsPartialFailure(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	var calls []string
	first := &recoveryPinTestLease{name: "se_task_alloc.link", fd: 42}
	second := &recoveryPinTestLease{name: "se_task_free.link", fd: 43}
	profile, gc := recoveryPinTestContext(t, func(name string, fd int) (operators.NativePinnedLink, error) {
		if fd == int(dir.Fd()) || fd < 0 {
			t.Fatal("ledger did not retain its own directory FD")
		}
		calls = append(calls, name)
		if name == "se_task_alloc" {
			return first, nil
		}
		return second, errors.New("ambiguous pin/reopen")
	})
	ledger, err := newSharedRecoveryLinkPins(gc, profile, int(dir.Fd()))
	if err == nil || ledger == nil || len(ledger.attempts) != 2 ||
		len(ledger.links) != 2 || first.closed || second.closed || len(calls) != 2 {
		t.Fatalf("partial pin lost: ledger=%+v err=%v calls=%v", ledger, err, calls)
	}
	if _, err := unix.FcntlInt(uintptr(ledger.dirFD), unix.F_GETFD, 0); err != nil {
		t.Fatal("owned directory FD closed on partial failure", err)
	}
	owned := ledger.dirFD
	if err := ledger.closeFDs(); err != nil || !first.closed || !second.closed {
		t.Fatalf("retained FD cleanup failed: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(owned), unix.F_GETFD, 0); err == nil {
		t.Fatal("ledger directory FD remains after close")
	}
}

func TestSharedRecoveryLinkPinLedgerPreflightsBothHooks(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	calls := 0
	profile, gc := recoveryPinTestContext(t, func(string, int) (operators.NativePinnedLink, error) {
		calls++
		return nil, nil
	})
	gc.SetVar(operators.NativeAttachmentPrefix+"se_task_free", nil)
	if ledger, err := newSharedRecoveryLinkPins(gc, profile, int(dir.Fd())); err == nil || ledger != nil || calls != 0 {
		t.Fatalf("missing second hook pinned first: ledger=%+v err=%v", ledger, err)
	}
	profile, gc = recoveryPinTestContext(t, func(name string, _ int) (operators.NativePinnedLink, error) {
		calls++
		return &recoveryPinTestLease{name: name + ".link", fd: 42}, nil
	})
	alloc, _ := gc.GetVar(operators.NativeAttachmentPrefix + "se_task_alloc")
	free, _ := gc.GetVar(operators.NativeAttachmentPrefix + "se_task_free")
	free.(*operators.NativeAttachment).LinkID = alloc.(*operators.NativeAttachment).LinkID
	if ledger, err := newSharedRecoveryLinkPins(gc, profile, int(dir.Fd())); err == nil || ledger != nil || calls != 0 {
		t.Fatalf("aliased links pinned: ledger=%+v err=%v", ledger, err)
	}
	profile, gc = recoveryPinTestContext(t, func(string, int) (operators.NativePinnedLink, error) {
		calls++
		return nil, nil
	})
	gc.SetVar(operators.NativeRecoveryTestRunKey, false)
	if ledger, err := newSharedRecoveryLinkPins(gc, profile, int(dir.Fd())); err == nil || ledger != nil || calls != 0 {
		t.Fatalf("unselected recovery pinned a hook: ledger=%+v err=%v", ledger, err)
	}
	gc.SetVar(operators.NativeRecoveryTestRunKey, true)
	gc.SetVar(operators.NativeResourcesKey, (*operators.NativeResources)(nil))
	if ledger, err := newSharedRecoveryLinkPins(gc, profile, int(dir.Fd())); err == nil || ledger != nil || calls != 0 {
		t.Fatalf("missing exact manifest pinned a hook: ledger=%+v err=%v", ledger, err)
	}
}

func TestSharedRecoveryLinkPinLedgerHappyAndMismatch(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	profile, gc := recoveryPinTestContext(t, func(name string, _ int) (operators.NativePinnedLink, error) {
		return &recoveryPinTestLease{name: name + ".link", fd: 42}, nil
	})
	ledger, err := newSharedRecoveryLinkPins(gc, profile, int(dir.Fd()))
	if err != nil || ledger == nil || len(ledger.links) != 2 || ledger.fault != nil {
		t.Fatalf("exact two-link pin ledger failed: ledger=%+v err=%v", ledger, err)
	}
	if err := ledger.closeFDs(); err != nil {
		t.Fatal(err)
	}
	profile, gc = recoveryPinTestContext(t, func(name string, _ int) (operators.NativePinnedLink, error) {
		return &recoveryPinTestLease{name: name + ".wrong", fd: 42}, nil
	})
	ledger, err = newSharedRecoveryLinkPins(gc, profile, int(dir.Fd()))
	if err == nil || ledger == nil || len(ledger.attempts) != 1 || len(ledger.links) != 1 {
		t.Fatalf("mismatched pinned link not retained: ledger=%+v err=%v", ledger, err)
	}
	if err := ledger.closeFDs(); err != nil {
		t.Fatal(err)
	}
}
