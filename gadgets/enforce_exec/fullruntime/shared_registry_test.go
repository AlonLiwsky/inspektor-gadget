// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

type sharedObjectUploadTransport struct {
	sharedCommandFaultTransport
	commands []sharedCommandWire
}

func (f *sharedObjectUploadTransport) runSharedCommand() (uint32, error) {
	f.commands = append(f.commands, f.command)
	result, err := f.sharedCommandFaultTransport.runSharedCommand()
	c := f.command
	f.receipt.Serial = 0
	f.receipt.Generation = c.Generation
	switch c.Operation {
	case 1:
		f.receipt.Generation++
		f.receipt.Value = 1
	case 2:
		f.receipt.Generation = 0
		f.receipt.Value = 0
	case 3:
		f.receipt.Value = 2
	case 4, 6:
		f.receipt.Value = 0
	case 5:
		f.receipt.Value = 3
	}
	return result, err
}

func TestSharedRegistryUploadsPhysicalObjectsAndRetainsAuthoredInputs(t *testing.T) {
	n, _ := sharedRegistrationHost(t)
	s, _ := sharedRegistrationSession(t, n, 42)
	if err := s.registerSharedScopeUsing(t.Context(), &sharedRegistrationTransport{}); err != nil {
		t.Fatal(err)
	}
	n.objects = newSharedObjectRegistry(n.config.Profile)
	f := &sharedObjectUploadTransport{}
	p := fullpolicy.Policy{ID: "uid", Revision: "revision", Mode: fullpolicy.Audit, Default: fullpolicy.Allow}
	candidate, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.commands) < 3 || f.commands[0].Operation != 1 || f.commands[len(f.commands)-1].Operation != 3 {
		t.Fatal("no actual upload sequence")
	}
	runs := len(f.commands)
	other, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != runs {
		t.Fatal("identical physical content uploaded twice")
	}
	if err := candidate.discard(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != runs {
		t.Fatal("first reference retired shared object")
	}
	if err := other.discard(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != runs+2 || f.commands[runs].Operation != 5 || f.commands[runs+1].Operation != 6 {
		t.Fatal("last reference missing exact retire/reclaim")
	}
	if err := candidate.discard(context.Background(), f); err == nil {
		t.Fatal("stale record replay accepted")
	}
	if status := s.Inspect(); status.Ready || status.RootAuthorized || status.Generation != 0 {
		t.Fatal("upload granted publication authority")
	}
}

func TestSharedRegistryLogicalAccountingAndAdmission(t *testing.T) {
	p := sharedTestProfile()
	r := newSharedObjectRegistry(p)
	got, err := sharedObjectRegistryBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(unsafe.Sizeof(*r)+unsafe.Sizeof(r)+unsafe.Sizeof(sharedStartupOperation{})) + uint64(len(r.slots))*uint64(unsafe.Sizeof(sharedObjectSlot{})) + uint64(len(r.records))*uint64(unsafe.Sizeof(sharedObjectRecord{})) + uint64(len(r.scopes))*uint64(unsafe.Sizeof(sharedSnapshotScopeState{}))
	if got != want {
		t.Fatalf("registry bytes=%d want=%d", got, want)
	}
	if r.retainedBytes != 0 {
		t.Fatal("unowned retained bytes charged")
	}
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: p, ABI3Development: true, Image: "development"})
	if err != nil {
		t.Fatal(err)
	}
	if n.objects != nil {
		t.Fatal("fixed registry allocated before resource admission")
	}
	p.PolicySlots[3] = ^uint64(0)
	if _, err = sharedObjectRegistryBytes(p); err == nil {
		t.Fatal("registry overflow accepted")
	}
}

func sharedRegistryFixture(t *testing.T) (*NodeEnforcer, *BindingSession, *sharedHostContext) {
	t.Helper()
	n, gc := sharedRegistrationHost(t)
	s, _ := sharedRegistrationSession(t, n, 42)
	if err := s.registerSharedScopeUsing(t.Context(), &sharedRegistrationTransport{}); err != nil {
		t.Fatal(err)
	}
	n.objects = newSharedObjectRegistry(n.config.Profile)
	return n, s, gc
}

func sharedRegistryPolicy() fullpolicy.Policy {
	return fullpolicy.Policy{ID: "uid", Revision: "revision", Mode: fullpolicy.Audit, Default: fullpolicy.Allow}
}

func TestSharedRegistryLostUploadAcknowledgementsNeverReplay(t *testing.T) {
	for _, operation := range []uint32{1, 2, 3} {
		t.Run(fmt.Sprint(operation), func(t *testing.T) {
			n, s, _ := sharedRegistryFixture(t)
			f := &sharedObjectUploadTransport{}
			f.afterRun = func() {
				if f.command.Operation == operation {
					f.readErr = errors.New("lost outcome")
				}
			}
			c, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
			if err == nil || c.node == nil || !n.objects.records[c.record].live {
				t.Fatal("ambiguous upload lost ownership")
			}
			before := len(f.commands)
			f.afterRun = nil
			f.readErr = nil
			if err = c.discard(t.Context(), f); err != nil {
				t.Fatal(err)
			}
			extra := 1
			if operation == 3 {
				extra = 2
			}
			if len(f.commands) != before+extra {
				t.Fatal("unknown upload blindly replayed")
			}
			if n.objects.records[c.record].live {
				t.Fatal("exact cleanup retained record")
			}
		})
	}
}

func TestSharedRegistryLostCleanupAcknowledgementsNeverReplay(t *testing.T) {
	for _, operation := range []uint32{4, 5, 6} {
		t.Run(fmt.Sprint(operation), func(t *testing.T) {
			n, s, _ := sharedRegistryFixture(t)
			f := &sharedObjectUploadTransport{}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if operation == 4 {
				f.afterRun = func() {
					if f.command.Operation == 2 {
						cancel()
					}
				}
			}
			c, err := s.prepareSharedObjectsUsing(ctx, []fullpolicy.Policy{sharedRegistryPolicy()}, f)
			if operation == 4 && !errors.Is(err, context.Canceled) {
				t.Fatal("missing completed canceled write", err)
			}
			if operation != 4 && err != nil {
				t.Fatal(err)
			}
			f.afterRun = func() {
				if f.command.Operation == operation {
					f.readErr = errors.New("lost cleanup")
				}
			}
			if err = c.discard(t.Context(), f); err == nil {
				t.Fatal("unknown cleanup accepted")
			}
			before := len(f.commands)
			f.afterRun = nil
			f.readErr = nil
			if err = c.discard(t.Context(), f); err != nil {
				t.Fatal(err)
			}
			extra := 0
			if operation == 5 {
				extra = 1
			}
			if len(f.commands) != before+extra || n.objects.records[c.record].live {
				t.Fatal("cleanup replay or leaked record")
			}
		})
	}
}

func TestSharedRegistrySlotOrdinalAndBoundedRecords(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	n.config.Profile.CandidateBytes = 64 << 20
	n.objects = newSharedObjectRegistry(n.config.Profile)
	policies := make([]fullpolicy.Policy, 5)
	for i := range policies {
		policies[i] = sharedRegistryPolicy()
		policies[i].ID = fmt.Sprint("uid", i)
	}
	f := &sharedObjectUploadTransport{}
	c, err := s.prepareSharedObjectsUsing(t.Context(), policies, f)
	if err != nil {
		t.Fatal(err)
	}
	record := &n.objects.records[c.record]
	if record.slots[4] != 4 || n.objects.slots[4].capacity != 1024 {
		t.Fatal("slot ordinal confused with cell offset")
	}
	p := policies[0]
	p.Revision = "another-authored-revision"
	other, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal(err)
	}
	authored := n.objects.records[other.record].source[0]
	physical := n.objects.slots[0].object
	if authored == physical || !authored.Equal(physical) {
		t.Fatal("physical dedup replaced authored source")
	}
	before := len(f.commands)
	if _, err = s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f); err == nil || len(f.commands) != before {
		t.Fatal("more than two records admitted")
	}
	if err = c.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if err = other.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	next, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal(err)
	}
	if next.token == c.token || n.objects.slots[0].generation != 2 {
		t.Fatal("record/object ABA generation reused")
	}
	if err = c.discard(t.Context(), f); err == nil {
		t.Fatal("stale token freed replacement")
	}
	if err = next.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
}

func TestSharedRegistryStopJoinsUploadBeforeCleanupAndDestruction(t *testing.T) {
	n, s, gc := sharedRegistryFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f := &sharedObjectUploadTransport{}
	f.afterRun = func() {
		if f.command.Operation == 1 {
			close(entered)
			<-release
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.prepareSharedObjectsUsing(context.Background(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
		done <- err
	}()
	<-entered
	if _, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{{}}, f); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatal("queued native operation or compiled before reservation", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := n.beforeStopProtocolUsing(canceled, f); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if n.host.commandsJoined {
		t.Fatal("unjoined upload closed native owner")
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("stopped upload lost cancellation", err)
	}
	f.afterRun = nil
	if err := n.beforeStopProtocolUsing(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if n.objects.destroyed {
		t.Fatal("logical cleanup claimed actual collection destruction")
	}
	if err := n.Close(gc); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	if !n.objects.destroyed {
		t.Fatal("actual protocol destruction not recorded")
	}
}

func TestSharedRegistryBudgetAndRefusalRetainExactOwnership(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	n.config.Profile.CandidateBytes = 1
	f := &sharedObjectUploadTransport{}
	c, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
	if err == nil || len(f.commands) != 0 || !n.objects.records[c.record].live {
		t.Fatal("storage refusal uploaded or forgot record")
	}
	if err = c.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	n.config.Profile.CandidateBytes = 1 << 20
	n.objects = newSharedObjectRegistry(n.config.Profile)
	f.afterRun = func() { f.receipt.Status = 1 }
	c, err = s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
	if err == nil || !n.objects.records[c.record].live {
		t.Fatal("known refusal lost ownership")
	}
	before := len(f.commands)
	if err = c.discard(t.Context(), f); err == nil || len(f.commands) != before {
		t.Fatal("incompatible receipt blindly retried")
	}
}

func TestSharedRegistryAdmitsFullRulePolicyWithGlobalRetainedBudget(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	f := &sharedObjectUploadTransport{}
	lastGood, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
	if err != nil {
		t.Fatal(err)
	}
	p := sharedRegistryPolicy()
	p.ID = "large"
	p.Rules = make([]fullpolicy.Rule, fullpolicy.MaxRules)
	for i := range p.Rules {
		p.Rules[i] = fullpolicy.Rule{Name: fmt.Sprintf("rule-%03d", i), Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{fmt.Sprintf("/tool/%03d", i), fmt.Sprintf("/other/%03d", i)}}}
	}
	compiled, err := fullpolicy.CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := compiled.RetainedBytes()
	if err != nil {
		t.Fatal(err)
	}
	n.config.Profile.CandidateBytes = n.objects.retainedBytes + bytes
	if bytes <= n.config.Profile.CandidateBytes/uint64(len(n.objects.slots)+len(n.objects.records)) {
		t.Fatal("regression budget no longer distinguishes rejected equal partition")
	}
	t.Logf("full256 cells=%d retained=%d advertised-global=%d", compiled.EntryCount(), bytes, n.config.Profile.CandidateBytes)
	c, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal("adequate global budget rejected full 256-rule policy", err)
	}
	r := &n.objects.records[c.record]
	slot := &n.objects.slots[r.slots[0]]
	if slot.capacity != 16384 {
		t.Fatal("full policy did not exercise the largest arena class")
	}
	if !n.objects.records[lastGood.record].live || s.Inspect().Generation != 0 {
		t.Fatal("candidate disturbed retained prior record/history")
	}
	if err = c.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if err = lastGood.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
}

func TestSharedRegistryGlobalLedgerAliasTransferAndExhaustion(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	f := &sharedObjectUploadTransport{}
	p := sharedRegistryPolicy()
	compiled, err := fullpolicy.CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	size, err := compiled.RetainedBytes()
	if err != nil {
		t.Fatal(err)
	}
	n.config.Profile.CandidateBytes = 2*size - 1
	first, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal(err)
	}
	if n.objects.retainedBytes != size {
		t.Fatal("representative alias double charged")
	}
	before := len(f.commands)
	refused, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err == nil || len(f.commands) != before || n.objects.retainedBytes != size || n.objects.slots[0].refs != 1 {
		t.Fatal("aggregate refusal changed last retained object")
	}
	if err = refused.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	n.config.Profile.CandidateBytes = 2 * size
	second, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal(err)
	}
	if n.objects.retainedBytes != 2*size || len(f.commands) != before {
		t.Fatal("dedup discarded independent authored-source charge")
	}
	if err = first.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if n.objects.retainedBytes != 2*size {
		t.Fatal("representative charge released while still referenced")
	}
	if err = second.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if n.objects.retainedBytes != 0 {
		t.Fatal("exact final cleanup leaked retained-byte charge")
	}
}

func TestSharedRegistryHashCollisionRequiresCanonicalEquality(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	f := &sharedObjectUploadTransport{}
	p := sharedRegistryPolicy()
	first, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = "different"
	other, err := fullpolicy.CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	// Controlled test-only digest collision injection; there is no production
	// mutator or caller-supplied compiled-object upload API.
	object := n.objects.slots[0].object
	field, ok := reflect.TypeOf(*object).FieldByName("digest")
	if !ok {
		t.Fatal("digest field missing")
	}
	*(*[32]byte)(unsafe.Add(unsafe.Pointer(object), field.Offset)) = other.Digest()
	second, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal(err)
	}
	if n.objects.records[first.record].slots[0] == n.objects.records[second.record].slots[0] {
		t.Fatal("hash collision reused unequal canonical content")
	}
	if err = first.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if err = second.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
}

func TestSharedRegistryUnknownOwnershipRetainedUntilActualProtocolDestruction(t *testing.T) {
	n, s, gc := sharedRegistryFixture(t)
	f := &sharedObjectUploadTransport{}
	f.afterRun = func() { f.readErr = errors.New("unresolved") }
	c, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
	if err == nil || n.objects.retainedBytes == 0 {
		t.Fatal("unknown upload became uncharged")
	}
	if err = n.beforeStopProtocolUsing(t.Context(), f); err == nil {
		t.Fatal("lost sticky cleanup diagnostic")
	}
	if !n.host.commandsJoined || !n.objects.records[c.record].live || n.objects.retainedBytes == 0 {
		t.Fatal("joining fabricated cleanup acknowledgement")
	}
	if err = n.Close(gc); err == nil {
		t.Fatal("operator close lost sticky outcome error")
	}
	if err = n.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	if !n.objects.destroyed || n.objects.retainedBytes != 0 || n.objects.records[c.record].live {
		t.Fatal("actual destruction did not discard terminal ownership")
	}
	if err = n.releaseSharedRetainedBytes(1); err == nil || n.objects.retainedBytes != 0 {
		t.Fatal("retained ledger subtraction wrapped")
	}
}
