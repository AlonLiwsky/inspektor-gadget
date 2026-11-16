// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type privateHostileError struct {
	t            *testing.T
	uncomparable []byte
}

func (e privateHostileError) Error() string { e.t.Error("foreign Error invoked"); return "hostile" }

func (e privateHostileError) String() string { e.t.Error("foreign String invoked"); return "hostile" }
func (e privateHostileError) Is(error) bool  { e.t.Error("foreign Is invoked"); return false }
func (e privateHostileError) As(any) bool    { e.t.Error("foreign As invoked"); return false }
func (e privateHostileError) Unwrap() error  { e.t.Error("foreign Unwrap invoked"); return nil }

type privatePanicTransport struct {
	sharedCommandFaultTransport
	value any
}

func (f *privatePanicTransport) runSharedCommand() (uint32, error) { panic(f.value) }

func privateTestControl(t *testing.T) *sharedControl {
	t.Helper()
	thread, err := startControlThread(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = thread.close() })
	return &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}, thread: thread}
}

func TestPrivateCommandScalarOnly(t *testing.T) {
	typ := reflect.TypeOf(sharedCommandOutcome{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() != reflect.Uint8 {
			t.Fatalf("outcome retains nonscalar field %s", typ.Field(i).Name)
		}
	}
	if _, ok := any(sharedCommandOutcome{}).(error); ok {
		t.Fatal("private outcome must never implement error")
	}
}

func TestPrivateCommandFaultsAndReconciliation(t *testing.T) {
	for _, stage := range []sharedOutcomeCode{sharedOutcomeWriteFailed, sharedOutcomeRunFailed, sharedOutcomeReadFailed} {
		t.Run(string(rune('a'+stage)), func(t *testing.T) {
			c := privateTestControl(t)
			f := &sharedCommandFaultTransport{}
			hostile := privateHostileError{t: t}
			switch stage {
			case sharedOutcomeWriteFailed:
				f.writeErr = hostile
			case sharedOutcomeRunFailed:
				f.runErr = hostile
			case sharedOutcomeReadFailed:
				f.readErr = hostile
			}
			request := sharedCommandWire{Operation: 8}
			receipt, outcome := c.callPrivate(t.Context(), request, f)
			if receipt.Sequence != 0 || outcome.code != stage {
				t.Fatalf("incorrect scalar outcome: %+v", outcome)
			}
			if stage == sharedOutcomeWriteFailed {
				if f.runs != 0 || c.pending != nil {
					t.Fatal("failed write ran or retained new pending")
				}
				return
			}
			if c.pending == nil {
				t.Fatal("uncertain command lost pending owner")
			}
			f.runErr = nil
			f.readErr = nil
			receipt, outcome = c.callPrivate(t.Context(), request, f)
			if outcome.code != sharedOutcomeOK || receipt.Sequence == 0 || c.pending != nil || f.runs != 1 {
				t.Fatalf("reconciliation replayed or failed: %+v", outcome)
			}
		})
	}
}

func TestPrivateCommandCancellationJoinsAndKeepsReceipt(t *testing.T) {
	c := privateTestControl(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	f := &sharedCommandFaultTransport{afterRun: func() { close(entered); <-release }}
	type result struct {
		receipt sharedReceiptWire
		outcome sharedCommandOutcome
	}
	done := make(chan result, 1)
	go func() { r, o := c.callPrivate(ctx, sharedCommandWire{Operation: 8}, f); done <- result{r, o} }()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("canceled call did not join")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	got := <-done
	if got.receipt.Sequence == 0 || got.outcome.code != sharedOutcomeOK || !got.outcome.hasIdentity(context.Canceled) || c.pending != nil {
		t.Fatalf("completed canceled receipt lost: %+v", got)
	}
}

func TestPrivateCommandPanicIsTerminalWithoutPayload(t *testing.T) {
	c := privateTestControl(t)
	f := &privatePanicTransport{value: privateHostileError{t: t}}
	_, outcome := c.callPrivate(t.Context(), sharedCommandWire{Operation: 8}, f)
	if outcome.code != sharedOutcomePanic || c.pending == nil {
		t.Fatalf("panic ownership lost: %+v", outcome)
	}
	if failure := c.thread.failure.Load(); failure != privateControlPanicFailure {
		t.Fatal("terminal failure not published before outcome")
	}
	g := &sharedCommandFaultTransport{}
	_, next := c.callPrivate(t.Context(), sharedCommandWire{Operation: 8}, g)
	if next.code != sharedOutcomePanic || g.writes != 0 || g.runs != 0 {
		t.Fatalf("terminal thread accepted next job: %+v", next)
	}
	if err := c.thread.close(); err != errPrivateControlPanic { //nolint:errorlint // Exact fixed terminal identity, not wrapping compatibility.
		t.Fatal("private panic terminal identity lost")
	}
}

func TestPrivateCommandReceiptAndObjectOwnership(t *testing.T) {
	c := privateTestControl(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := &sharedCommandFaultTransport{readErr: privateHostileError{t: t}, afterRun: cancel}
	slot := &sharedObjectSlot{generation: 4}
	n := &NodeEnforcer{host: &sharedHostState{control: c}}
	request := sharedCommandWire{Operation: 1, Generation: 4}
	primary := n.runSharedObjectCommandPrivate(ctx, slot, request, f)
	if primary.code != sharedOutcomeReadFailed || primary.receipt != sharedReceiptUnresolved || !primary.hasIdentity(context.Canceled) || !slot.pending {
		t.Fatalf("primary state lost: %+v", primary)
	}
	f.readErr = nil
	f.receipt.Sequence++
	cleanup := n.runSharedObjectCommandPrivate(context.WithoutCancel(ctx), slot, request, f)
	if cleanup.code != sharedOutcomeContradictory || cleanup.identities != 0 || !slot.pending || primary.code != sharedOutcomeReadFailed || !primary.hasIdentity(context.Canceled) {
		t.Fatalf("paired scalar outcomes lost: %+v %+v", primary, cleanup)
	}
	f.receipt.Sequence--
	f.receipt.Serial = 0
	f.receipt.Generation = 5
	f.receipt.Value = 1
	done := n.runSharedObjectCommandPrivate(t.Context(), slot, request, f)
	if done.code != sharedOutcomeOK || slot.pending || slot.generation != 5 || f.runs != 1 {
		t.Fatalf("exact reconcile failed: %+v", done)
	}
}

func TestRichControlPreAdmissionErrorIdentity(t *testing.T) {
	c := privateTestControl(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := c.thread.do(ctx, func() error { t.Fatal("canceled callback ran"); return nil }); got != context.Canceled { //nolint:errorlint // Assert the rich pre-admission error remains direct.
		t.Fatal("rich direct error became joined")
	}
	sentinel := errors.New("callback marker")
	got := c.thread.do(t.Context(), func() error { return sentinel })
	if got == sentinel || !errors.Is(got, sentinel) { //nolint:errorlint // Accepted rich calls must retain their existing Join wrapper.
		t.Fatal("rich accepted result lost existing join")
	}
}

type privateDeadlineContext struct {
	context.Context
	done chan struct{}
}

func (c *privateDeadlineContext) Done() <-chan struct{} { return c.done }
func (c *privateDeadlineContext) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func TestPrivateCommandDeadlineAndDirectTransportIdentities(t *testing.T) {
	for _, identity := range []error{context.Canceled, context.DeadlineExceeded, ErrControlClosed, ErrSharedNativeUnavailable} {
		c := privateTestControl(t)
		ctx := &privateDeadlineContext{Context: t.Context(), done: make(chan struct{})}
		f := &sharedCommandFaultTransport{runErr: identity, afterRun: func() { close(ctx.done) }}
		_, outcome := c.callPrivate(ctx, sharedCommandWire{Operation: 8}, f)
		if outcome.code != sharedOutcomeRunFailed || !outcome.hasIdentity(identity) || !outcome.hasIdentity(context.DeadlineExceeded) || c.pending == nil {
			t.Fatalf("identity combination lost: %+v", outcome)
		}
	}
	c := privateTestControl(t)
	ctx := &privateDeadlineContext{Context: t.Context(), done: make(chan struct{})}
	f := &sharedCommandFaultTransport{afterRun: func() { close(ctx.done) }}
	receipt, outcome := c.callPrivate(ctx, sharedCommandWire{Operation: 8}, f)
	if receipt.Sequence == 0 || outcome.code != sharedOutcomeOK || !outcome.hasIdentity(context.DeadlineExceeded) || c.pending != nil {
		t.Fatalf("deadline erased receipt: %+v", outcome)
	}
}

func TestPrivateCommandValidationRefusalAndPendingConflict(t *testing.T) {
	c := privateTestControl(t)
	f := &sharedCommandFaultTransport{}
	_, outcome := c.callPrivate(t.Context(), sharedCommandWire{}, f)
	if outcome.code != sharedOutcomeUnsupported || f.writes != 0 {
		t.Fatal("unsupported command submitted")
	}
	c.sequence = ^uint64(0) - 1
	_, outcome = c.callPrivate(t.Context(), sharedCommandWire{Operation: 8}, f)
	if outcome.code != sharedOutcomeSequenceExhausted || f.writes != 0 {
		t.Fatal("exhausted command submitted")
	}
	c.sequence = 0
	f.readErr = privateHostileError{t: t}
	request := sharedCommandWire{Operation: 8}
	_, _ = c.callPrivate(t.Context(), request, f)
	_, outcome = c.callPrivate(t.Context(), sharedCommandWire{Operation: 9}, f)
	if outcome.code != sharedOutcomePendingConflict || f.writes != 1 || f.runs != 1 {
		t.Fatal("pending conflict replayed")
	}
	f.readErr = nil
	f.receipt.Status = 1
	c.pending.runKnown = false
	receipt, outcome := c.callPrivate(t.Context(), request, f)
	if receipt.Sequence == 0 || outcome.code != sharedOutcomeRefused || outcome.receipt != sharedReceiptRefused || c.pending != nil {
		t.Fatal("validated refusal lost")
	}
	var absent *sharedControl
	_, outcome = absent.callPrivate(t.Context(), request, f)
	if outcome.code != sharedOutcomeUnavailable || !outcome.hasIdentity(ErrSharedNativeUnavailable) {
		t.Fatal("missing control identity lost")
	}
}

func TestPrivateCommandObjectIncompatibleRetainsOwnership(t *testing.T) {
	c := privateTestControl(t)
	n := &NodeEnforcer{host: &sharedHostState{control: c}}
	slot := &sharedObjectSlot{generation: 4}
	f := &sharedCommandFaultTransport{}
	outcome := n.runSharedObjectCommandPrivate(t.Context(), slot, sharedCommandWire{Operation: 1, Generation: 4}, f)
	if outcome.receipt != sharedReceiptIncompatible || !slot.poisoned || !slot.pending || c.pending != nil {
		t.Fatalf("incompatible completed ownership lost: %+v", outcome)
	}
	next := n.runSharedObjectCommandPrivate(t.Context(), slot, slot.command, f)
	if next.code != sharedOutcomeObjectPoisoned || f.runs != 1 {
		t.Fatal("poisoned slot reused")
	}
	slot = &sharedObjectSlot{pending: true, command: sharedCommandWire{Operation: 1}}
	next = n.runSharedObjectCommandPrivate(t.Context(), slot, sharedCommandWire{Operation: 2}, f)
	if next.code != sharedOutcomeObjectPendingConflict || f.runs != 1 {
		t.Fatal("slot pending conflict reused")
	}
}

func TestPrivateCommandFinishDoesNotInventCancellation(t *testing.T) {
	n, _, _ := sharedRegistryFixture(t)
	ctx, finish, err := n.beginSharedObjectOperation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c := privateTestControl(t)
	f := &sharedCommandFaultTransport{}
	_, outcome := c.callPrivate(ctx, sharedCommandWire{Operation: 8}, f)
	finish()
	if ctx.Err() != context.Canceled || outcome.code != sharedOutcomeOK || outcome.identities != 0 {
		t.Fatalf("finish changed prior success: %+v", outcome)
	}
}

func TestPrivateCommandClosedAndCanceledAdmission(t *testing.T) {
	c := privateTestControl(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	f := &sharedCommandFaultTransport{}
	_, outcome := c.callPrivate(ctx, sharedCommandWire{Operation: 8}, f)
	if outcome.code != sharedOutcomeCanceledAdmission || !outcome.hasIdentity(context.Canceled) || f.writes != 0 {
		t.Fatal("canceled admission ran")
	}
	if err := c.thread.close(); err != nil {
		t.Fatal(err)
	}
	_, outcome = c.callPrivate(t.Context(), sharedCommandWire{Operation: 8}, f)
	if outcome.code != sharedOutcomeClosed || !outcome.hasIdentity(ErrControlClosed) || f.writes != 0 {
		t.Fatal("closed admission ran")
	}
}
