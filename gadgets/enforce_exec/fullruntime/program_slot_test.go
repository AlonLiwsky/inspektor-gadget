// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

var errSlotFailure = errors.New("injected slot failure")

type fakeSlotImage struct {
	closed   int
	closeErr error
}

func (m *fakeSlotImage) Close() error { m.closed++; return m.closeErr }

type fakeSlotWriter struct {
	rows              map[interface{}]interface{}
	putErr, deleteErr error
	failKey           interface{}
	puts, deletes     int
}

func (m *fakeSlotWriter) Put(k, v interface{}) error {
	m.puts++
	if m.putErr != nil && (m.failKey == nil || m.failKey == k) {
		return m.putErr
	}
	m.rows[k] = v
	return nil
}

func (m *fakeSlotWriter) Delete(k interface{}) error {
	m.deletes++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.rows[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.rows, k)
	return nil
}

func slotFixture(t *testing.T) (*ProgramSlot, *fakeSlotWriter, *fakeSlotWriter, *[]*fakeSlotImage) {
	t.Helper()
	g, _ := testGate(t)
	outer := &fakeSlotWriter{rows: map[interface{}]interface{}{}}
	epochs := &fakeSlotWriter{rows: map[interface{}]interface{}{}}
	images := new([]*fakeSlotImage)
	p, err := newProgramSlot(g, outer, epochs, func(*fullpolicy.KernelProgram) (slotResource, error) {
		m := new(fakeSlotImage)
		*images = append(*images, m)
		return m, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, outer, epochs, images
}

func slotProgram(t *testing.T, p *ProgramSlot, generation uint64, ids ...string) *fullpolicy.KernelProgram {
	t.Helper()
	var policies []fullpolicy.Policy
	for _, id := range ids {
		policies = append(policies, fullpolicy.Policy{ID: id, Revision: "revision", Mode: fullpolicy.Enforce, RootRole: "root"})
	}
	program, err := fullpolicy.CompileKernelWithRoleEpochs(policies, generation, "app", p.Epochs())
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func publishSlot(t *testing.T, p *ProgramSlot, program *fullpolicy.KernelProgram) *ProgramUpdate {
	t.Helper()
	u, err := p.Begin(t.Context(), program)
	if err != nil {
		t.Fatal(err)
	}
	r, err := u.Commit()
	if err != nil || !r.Committed {
		t.Fatal(r, err)
	}
	if err = u.Finish(); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestProgramSlotCommitBoundaryAndRetainedEpochs(t *testing.T) {
	p, outer, epochs, images := slotFixture(t)
	a := slotProgram(t, p, 1, "uid-a")
	u, err := p.Begin(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	requireState(t, p.gate, true, 0)
	if u.NewUIDMask() != 1 || p.Generation() != 0 || len(p.Epochs()) != 0 || outer.rows[uint32(0)] != nil {
		t.Fatal("precommit publication")
	}
	if _, err = p.Begin(t.Context(), a); !errors.Is(err, ErrGateBusy) {
		t.Fatal(err)
	}
	copyHandle := *u
	result, err := u.Commit()
	if err != nil || !result.Committed || result.Generation != 1 {
		t.Fatal(result, err)
	}
	requireState(t, p.gate, true, 0) // map commit is NOT permission to reopen early
	if p.Generation() != 1 || p.Epochs()["uid-a"] != 1 || len(epochs.rows) != 1 {
		t.Fatal("committed epoch missing")
	}
	if err = u.Abort(); err == nil {
		t.Fatal("committed program rolled back")
	}
	if err = copyHandle.Finish(); err != nil {
		t.Fatal(err)
	}
	if err = u.Finish(); !errors.Is(err, ErrStaleLease) {
		t.Fatal("copied handle completed twice", err)
	}
	requireState(t, p.gate, false, 0)
	b := slotProgram(t, p, 2, "uid-b")
	publishSlot(t, p, b)
	if (*images)[0].closed != 1 || (*images)[1].closed != 0 {
		t.Fatal("wrong inner map lifetime")
	}
	if p.Epochs()["uid-a"] != 1 || p.Epochs()["uid-b"] != 2 {
		t.Fatal("removed UID epoch forgotten")
	}
	u, err = p.Begin(t.Context(), slotProgram(t, p, 3, "uid-a"))
	if err != nil {
		t.Fatal(err)
	}
	if u.NewUIDMask() != 0 {
		t.Fatal("re-addition reroots UID")
	}
	if err = u.Abort(); err != nil {
		t.Fatal(err)
	}
	if p.Generation() != 2 || len(p.Epochs()) != 2 {
		t.Fatal("abort changed accepted history")
	}
}

func TestProgramSlotFailedCandidateDoesNotEstablishRoot(t *testing.T) {
	p, outer, epochs, images := slotFixture(t)
	publishSlot(t, p, slotProgram(t, p, 1, "old"))
	u, err := p.Begin(t.Context(), slotProgram(t, p, 9, "new"))
	if err != nil {
		t.Fatal(err)
	}
	outer.putErr = errSlotFailure
	outer.failKey = uint32(0)
	result, err := u.Commit()
	if !errors.Is(err, errSlotFailure) || result.Committed {
		t.Fatal(result, err)
	}
	if len(epochs.rows) != 1 || p.Epochs()["new"] != 0 || p.Generation() != 1 {
		t.Fatal("failed attempt became accepted")
	}
	outer.putErr = nil
	if err = u.Abort(); err != nil {
		t.Fatal(err)
	}
	if (*images)[1].closed != 1 || (*images)[0].closed != 0 {
		t.Fatal("abort closed last good")
	}
	if _, err = p.Begin(t.Context(), slotProgram(t, p, 9, "new")); err == nil {
		t.Fatal("failed generation reused")
	}
	next, err := p.Begin(t.Context(), slotProgram(t, p, 10, "new"))
	if err != nil {
		t.Fatal(err)
	}
	if next.NewUIDMask() != 1 {
		t.Fatal("failed attempt classified accepted")
	}
	if err = next.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestProgramSlotHistoryFailureIsCommittedAndClosed(t *testing.T) {
	p, outer, epochs, images := slotFixture(t)
	publishSlot(t, p, slotProgram(t, p, 1, "old"))
	u, err := p.Begin(t.Context(), slotProgram(t, p, 2, "new"))
	if err != nil {
		t.Fatal(err)
	}
	epochs.putErr = errSlotFailure
	result, err := u.Commit()
	if !result.Committed || result.Generation != 2 || !errors.Is(err, errSlotFailure) {
		t.Fatal(result, err)
	}
	if p.Generation() != 2 || p.Epochs()["new"] != 2 || outer.rows[uint32(0)] != (*images)[1] {
		t.Fatal("irreversible commit forgotten")
	}
	requireState(t, p.gate, true, 0)
	if err = u.Finish(); err == nil {
		t.Fatal("partial history reopened admission")
	}
	if err = u.Abort(); err == nil {
		t.Fatal("postcommit history failure rolled back")
	}
	if epochs.deletes != 0 {
		t.Fatal("successful history deleted")
	}
	if _, err = p.Begin(t.Context(), slotProgram(t, p, 3, "other")); !errors.Is(err, ErrGateBusy) {
		t.Fatal("pending committed publication bypassed", err)
	}
	epochs.putErr = nil
	if result, err = u.Commit(); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	if err = u.Finish(); err != nil {
		t.Fatal(err)
	}
	requireState(t, p.gate, false, 0)
	if len(epochs.rows) != 2 || epochs.deletes != 0 || (*images)[0].closed != 1 {
		t.Fatal("history resume/lifetime")
	}
}

func TestProgramSlotStagingCleanupRetainsExactlyOneResource(t *testing.T) {
	p, outer, _, images := slotFixture(t)
	publishSlot(t, p, slotProgram(t, p, 1, "old"))
	u, err := p.Begin(t.Context(), slotProgram(t, p, 2, "new"))
	if err != nil {
		t.Fatal(err)
	}
	outer.deleteErr = errSlotFailure
	if err = u.Abort(); !errors.Is(err, errSlotFailure) {
		t.Fatal(err)
	}
	if len(p.garbage) != 1 || (*images)[1].closed != 0 || (*images)[0].closed != 0 {
		t.Fatal("untracked staging resource")
	}
	if _, err = p.Begin(t.Context(), slotProgram(t, p, 3, "new")); !errors.Is(err, errSlotFailure) {
		t.Fatal("cleanup bypass", err)
	}
	if len(*images) != 2 {
		t.Fatal("new maps allocated while cleanup pending")
	}
	outer.deleteErr = nil
	if err = p.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if len(p.garbage) != 0 || (*images)[1].closed != 1 || (*images)[0].closed != 0 {
		t.Fatal("staging cleanup lifetime")
	}
}

func TestProgramSlotPostcommitCleanupDoesNotRollback(t *testing.T) {
	p, outer, _, images := slotFixture(t)
	publishSlot(t, p, slotProgram(t, p, 1, "old"))
	u, err := p.Begin(t.Context(), slotProgram(t, p, 2, "new"))
	if err != nil {
		t.Fatal(err)
	}
	if r, err := u.Commit(); err != nil || !r.Committed {
		t.Fatal(r, err)
	}
	outer.deleteErr = errSlotFailure
	if err = u.Finish(); !errors.Is(err, errSlotFailure) {
		t.Fatal(err)
	}
	if p.Generation() != 2 || p.Epochs()["new"] != 2 || (*images)[0].closed != 1 || (*images)[1].closed != 0 {
		t.Fatal("postcommit error rolled back")
	}
	outer.deleteErr = nil
	if err = p.Cleanup(); err != nil {
		t.Fatal(err)
	}
	requireState(t, p.gate, false, 0)
}

func TestProgramSlotTimeoutAndEpochRefusal(t *testing.T) {
	p, _, _, images := slotFixture(t)
	publishSlot(t, p, slotProgram(t, p, 1, "old"))
	if err := p.gate.Enter(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if _, err := p.Begin(ctx, slotProgram(t, p, 2, "new")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	requireState(t, p.gate, false, 1)
	if (*images)[1].closed != 1 || p.Generation() != 1 {
		t.Fatal("timeout changed policy")
	}
	if err := p.gate.Leave(); err != nil {
		t.Fatal(err)
	}
	fresh, err := fullpolicy.CompileKernel([]fullpolicy.Policy{{ID: "old", Revision: "new", Mode: fullpolicy.Enforce}}, 3, "app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Begin(t.Context(), fresh); err == nil {
		t.Fatal("accepted UID rerooted")
	}
	if p.Epochs()["old"] != 1 {
		t.Fatal("refusal mutated history")
	}
}

func TestProgramSlotCloseAfterDetachOwnsOnlyItsResources(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[committed], func(t *testing.T) {
			p, _, _, images := slotFixture(t)
			publishSlot(t, p, slotProgram(t, p, 1, "old"))
			u, err := p.Begin(t.Context(), slotProgram(t, p, 2, "new"))
			if err != nil {
				t.Fatal(err)
			}
			if committed {
				if r, err := u.Commit(); err != nil || !r.Committed {
					t.Fatal(r, err)
				}
			}
			// Represents confirmed runtime hook detach; not a production drain shortcut.
			if err = p.CloseAfterDetach(); err != nil {
				t.Fatal(err)
			}
			for _, m := range *images {
				if m.closed != 1 {
					t.Fatalf("FD consumed %d times", m.closed)
				}
			}
			if err = p.CloseAfterDetach(); err != nil {
				t.Fatal(err)
			}
			if _, err = p.Begin(t.Context(), slotProgram(t, p, 3, "new")); err == nil {
				t.Fatal("closed owner reused")
			}
		})
	}
}

func TestProgramSlotRetirePendingUpdateWithoutReopening(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "candidate", true: "committed"}[committed], func(t *testing.T) {
			p, _, _, images := slotFixture(t)
			publishSlot(t, p, slotProgram(t, p, 1, "old"))
			u, err := p.Begin(t.Context(), slotProgram(t, p, 2, "new"))
			if err != nil {
				t.Fatal(err)
			}
			if committed {
				if r, err := u.Commit(); err != nil || !r.Committed {
					t.Fatal(r, err)
				}
			}
			if err = p.Retire(t.Context()); err != nil {
				t.Fatal(err)
			}
			requireState(t, p.gate, true, 0)
			if err = p.gate.Enter(); !errors.Is(err, ErrGateRetired) {
				t.Fatal(err)
			}
			if _, err = p.Begin(t.Context(), slotProgram(t, p, 3, "new")); err == nil {
				t.Fatal("retired publisher reused")
			}
			if err = u.Finish(); !errors.Is(err, ErrStaleLease) {
				t.Fatal("retired update reopened admission", err)
			}
			if err = p.CloseAfterDetach(); err != nil {
				t.Fatal(err)
			}
			for _, m := range *images {
				if m.closed != 1 {
					t.Fatal("map consumed more than once", m.closed)
				}
			}
		})
	}
}

func TestProgramSlotRetireTimeoutKeepsLastGood(t *testing.T) {
	p, _, _, images := slotFixture(t)
	publishSlot(t, p, slotProgram(t, p, 1, "old"))
	if err := p.gate.Enter(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if err := p.Retire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	requireState(t, p.gate, false, 1)
	if p.retiring || (*images)[0].closed != 0 {
		t.Fatal("timeout retired old policy")
	}
	if err := p.gate.Leave(); err != nil {
		t.Fatal(err)
	}
	if err := p.Retire(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireState(t, p.gate, true, 0)
	if err := p.CloseAfterDetach(); err != nil {
		t.Fatal(err)
	}
}

func TestProgramSlotCleanupRefusesInFlightStaging(t *testing.T) {
	p, outer, epochs, _ := slotFixture(t)
	publishSlot(t, p, slotProgram(t, p, 1, "uid"))
	update, err := p.Begin(t.Context(), slotProgram(t, p, 2, "uid", "new"))
	if err != nil {
		t.Fatal(err)
	}
	deletes := outer.deletes
	if err = p.Cleanup(); !errors.Is(err, ErrGateBusy) || outer.deletes != deletes || !p.staging {
		t.Fatal("cleanup removed precommit staging", err)
	}
	if result, err := update.Commit(); err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	if err = p.Cleanup(); !errors.Is(err, ErrGateBusy) || outer.deletes != deletes || !p.staging || epochs.deletes != 0 {
		t.Fatal("cleanup removed committed unfinalized staging", err)
	}
	requireState(t, p.gate, true, 0)
	if err = update.Finish(); err != nil {
		t.Fatal(err)
	}
	if err = p.Cleanup(); err != nil {
		t.Fatal(err)
	}
	requireState(t, p.gate, false, 0)
}
