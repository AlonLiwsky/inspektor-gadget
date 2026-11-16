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

// Exchange fixture for the actual sharedControl coordinator, not a production
// kernel/qualification substitute. Production has NO intent producer yet.
type sharedSnapshotTransport struct {
	refuseRelease    bool
	corruptOperation uint32
	sharedObjectUploadTransport
	nextSerial uint64
	serial     [2]uint64
	phase      [2]uint32
	tickets    [2][8]uint32
	refusePin  int
}

func (f *sharedSnapshotTransport) runSharedCommand() (uint32, error) {
	c := f.command
	if c.Operation <= 6 {
		return f.sharedObjectUploadTransport.runSharedCommand()
	}
	f.commands = append(f.commands, c)
	_, err := f.sharedCommandFaultTransport.runSharedCommand()
	f.receipt.Generation, f.receipt.Serial, f.receipt.Value = 0, 0, 0
	refuse := false
	switch c.Operation {
	case 8:
		if c.Serial != f.nextSerial || f.phase[c.Record] != 0 || (f.phase[c.Record^1] != 0 && f.phase[c.Record^1] != 3) {
			refuse = true
			break
		}
		f.nextSerial++
		f.serial[c.Record] = f.nextSerial
		f.phase[c.Record] = 1
		f.receipt.Serial = f.nextSerial
		f.receipt.Value = 1
	case 9:
		if int(c.Index) == f.refusePin {
			refuse = true
			break
		}
		f.tickets[c.Record][c.Index] = 1
		f.receipt.Value = 1
	case 10:
		f.phase[c.Record] = 2
		f.receipt.Serial = f.serial[c.Record]
		f.receipt.Value = 2
	case 11:
		f.phase[c.Record] = 4
		f.receipt.Serial = f.serial[c.Record]
		f.receipt.Value = 4
	case 12:
		if f.refuseRelease {
			refuse = true
			break
		}
		f.tickets[c.Record][c.Index] = 2
		f.receipt.Value = 2
	case 13:
		f.phase[c.Record] = 0
		f.serial[c.Record] = 0
		f.tickets[c.Record] = [8]uint32{}
	case 15:
		f.receipt.Value = f.tickets[c.Record][c.Index]
	default:
		refuse = true
	}
	if refuse {
		f.receipt.Status = 1
		if c.Operation == f.corruptOperation {
			f.receipt.Value = 99
		}
		return 1, err
	}
	if c.Operation == f.corruptOperation {
		f.receipt.Value = 99
	}
	return 0, err
}

func sharedSnapshotFixture(t *testing.T, count int) (*NodeEnforcer, *BindingSession, sharedObjectCandidate, *sharedSnapshotIntent, *sharedSnapshotTransport) {
	t.Helper()
	n, s, _ := sharedRegistryFixture(t)
	f := &sharedSnapshotTransport{refusePin: -1}
	policies := make([]fullpolicy.Policy, count)
	for i := range policies {
		policies[i] = sharedRegistryPolicy()
		policies[i].ID = fmt.Sprint("policy-", i)
	}
	c, err := s.prepareSharedObjectsUsing(t.Context(), policies, f)
	if err != nil {
		t.Fatal(err)
	}
	record := &n.objects.records[c.record]
	refs := make([]fullpolicy.SharedPolicyRef, count)
	for i := range refs {
		refs[i] = fullpolicy.SharedPolicyRef{Object: record.source[i], RootEpoch: 1}
	}
	proposal, err := fullpolicy.NewSharedSnapshot(s.ScopeCookie(), 1, "container", refs)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit test-only proposed epoch provenance. No production factory exists.
	intent := &sharedSnapshotIntent{candidate: c, account: s.account, proposal: proposal}
	return n, s, c, intent, f
}

func TestSharedSnapshotAllEightPinsSealAndCleanupBeforeObjectRetirement(t *testing.T) {
	n, s, c, intent, f := sharedSnapshotFixture(t, 8)
	start := len(f.commands)
	if err := c.prepareSnapshotUsing(t.Context(), intent, f); err != nil {
		t.Fatal(err)
	}
	got := f.commands[start:]
	if len(got) != 10 || got[0].Operation != 8 || got[9].Operation != 10 {
		t.Fatal("missing prepare/pin/seal sequence")
	}
	for i := range 8 {
		if got[i+1].Operation != 9 || got[i+1].Index != uint32(i) {
			t.Fatal("wrong ticket position")
		}
	}
	if n.objects.records[c.record].snapshot.phase != 2 || n.objects.scopes[0].nextSerial != 1 || s.Inspect().Generation != 0 || s.Inspect().Ready {
		t.Fatal("proposal became accepted facts or missed receipt")
	}
	start = len(f.commands)
	if err := c.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	got = f.commands[start:]
	if len(got) < 10 || got[0].Operation != 11 || got[9].Operation != 13 {
		t.Fatal("object cleanup overtook snapshot reclaim")
	}
	for i := range 8 {
		if got[i+1].Operation != 12 || got[i+1].Index != uint32(i) {
			t.Fatal("missing authoritative ticket release")
		}
	}
	if n.objects.retainedBytes != 0 || n.objects.scopes[0].nextSerial != 1 {
		t.Fatal("reclaim erased serial history or leaked source")
	}
}

func TestSharedSnapshotMissingIntentCannotManufactureEpochs(t *testing.T) {
	n, _, c, _, f := sharedSnapshotFixture(t, 1)
	before := len(f.commands)
	if err := c.prepareSnapshotUsing(t.Context(), nil, f); err == nil || len(f.commands) != before || !n.objects.records[c.record].live {
		t.Fatal("missing provenance manufactured a snapshot")
	}
	if err := c.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
}

func TestSharedSnapshotEveryPartialPinRefusalInspectsAndCleansOnlyCandidate(t *testing.T) {
	for failed := range 8 {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			n, _, c, intent, f := sharedSnapshotFixture(t, 8)
			f.refusePin = failed
			start := len(f.commands)
			if err := c.prepareSnapshotUsing(t.Context(), intent, f); err == nil {
				t.Fatal("pin refusal hidden")
			}
			if n.objects.records[c.record].live || n.objects.retainedBytes != 0 || n.objects.scopes[0].nextSerial != 1 {
				t.Fatal("partial candidate leaked or erased serial history")
			}
			seenInspect, releases := 0, 0
			for _, command := range f.commands[start:] {
				if command.Operation == 15 {
					seenInspect++
					if command.Index != uint32(failed) {
						t.Fatal("inspected wrong ticket")
					}
				}
				if command.Operation == 12 {
					releases++
					if command.Index >= uint32(failed) {
						t.Fatal("released unheld ticket")
					}
				}
			}
			if seenInspect != 1 || releases != failed {
				t.Fatalf("inspect=%d releases=%d", seenInspect, releases)
			}
		})
	}
}

func TestSharedSnapshotLostPreparePinSealReceiptsRetainOwnershipWithoutReplay(t *testing.T) {
	for _, operation := range []uint32{8, 9, 10, 15} {
		t.Run(fmt.Sprint(operation), func(t *testing.T) {
			n, _, c, intent, f := sharedSnapshotFixture(t, 3)
			if operation == 15 {
				f.refusePin = 1
			}
			f.afterRun = func() {
				if f.command.Operation == operation {
					f.readErr = errors.New("lost snapshot receipt")
				}
			}
			if err := c.prepareSnapshotUsing(t.Context(), intent, f); err == nil {
				t.Fatal("unknown outcome hidden")
			}
			if !n.objects.records[c.record].live || n.objects.retainedBytes == 0 {
				t.Fatal("unknown snapshot released object/source leases")
			}
			before := 0
			for _, command := range f.commands {
				if command.Operation == operation {
					before++
				}
			}
			f.afterRun = nil
			f.readErr = nil
			if err := c.discard(t.Context(), f); err != nil {
				t.Fatal(err)
			}
			after := 0
			for _, command := range f.commands {
				if command.Operation == operation {
					after++
				}
			}
			if after != before || n.objects.retainedBytes != 0 || n.objects.scopes[0].nextSerial != 1 {
				t.Fatal("lost snapshot command replayed or serial/source ownership lost")
			}
		})
	}
}

func TestSharedSnapshotLostAbortReleaseReclaimReceiptsNeverReplay(t *testing.T) {
	for _, operation := range []uint32{11, 12, 13} {
		t.Run(fmt.Sprint(operation), func(t *testing.T) {
			n, _, c, intent, f := sharedSnapshotFixture(t, 1)
			if err := c.prepareSnapshotUsing(t.Context(), intent, f); err != nil {
				t.Fatal(err)
			}
			f.afterRun = func() {
				if f.command.Operation == operation {
					f.readErr = errors.New("lost cleanup")
				}
			}
			if err := c.discard(t.Context(), f); err == nil {
				t.Fatal("unknown cleanup hidden")
			}
			if !n.objects.records[c.record].live || n.objects.slots[0].refs != 1 {
				t.Fatal("object lease dropped before snapshot reclaim")
			}
			before := 0
			for _, command := range f.commands {
				if command.Operation == operation {
					before++
				}
			}
			f.afterRun = nil
			f.readErr = nil
			if err := c.discard(t.Context(), f); err != nil {
				t.Fatal(err)
			}
			after := 0
			for _, command := range f.commands {
				if command.Operation == operation {
					after++
				}
			}
			if before != after || n.objects.retainedBytes != 0 {
				t.Fatal("cleanup replay or retained-source leak")
			}
		})
	}
}

func TestSharedSnapshotCompletedCanceledPinStillReleasesExactTicket(t *testing.T) {
	n, _, c, intent, f := sharedSnapshotFixture(t, 3)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.afterRun = func() {
		if f.command.Operation == 9 && f.command.Index == 1 {
			cancel()
		}
	}
	if err := c.prepareSnapshotUsing(ctx, intent, f); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	released := []uint32{}
	for _, command := range f.commands {
		if command.Operation == 12 {
			released = append(released, command.Index)
		}
	}
	if !reflect.DeepEqual(released, []uint32{0, 1}) || n.objects.records[c.record].live || n.objects.retainedBytes != 0 {
		t.Fatal("completed canceled PIN forgotten", released)
	}
}

func TestSharedSnapshotCandidateFixedAccounting(t *testing.T) {
	p := sharedTestProfile()
	r := newSharedObjectRegistry(p)
	delta := uint64(unsafe.Sizeof(sharedSnapshotCandidateState{}))*uint64(len(r.records)) + uint64(unsafe.Sizeof(sharedSnapshotScopeState{}))*uint64(len(r.scopes)) + uint64(unsafe.Sizeof(r.scopes))
	if delta != 4728 {
		t.Fatalf("amd64 fixed snapshot ownership changed: %d", delta)
	}
	got, err := sharedObjectRegistryBytes(p)
	if err != nil || got != 10160+delta {
		t.Fatal("snapshot journals/counters uncharged", got, err)
	}
}

func TestSharedSnapshotCannotPromotePartialUploadedInputSet(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	f := &sharedSnapshotTransport{refusePin: -1}
	policies := []fullpolicy.Policy{sharedRegistryPolicy(), {}}
	c, err := s.prepareSharedObjectsUsing(t.Context(), policies, f)
	if err == nil {
		t.Fatal("invalid tail compiled")
	}
	r := &n.objects.records[c.record]
	proposal, err := fullpolicy.NewSharedSnapshot(s.ScopeCookie(), 1, "container", []fullpolicy.SharedPolicyRef{{Object: r.source[0], RootEpoch: 1}})
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.commands)
	if err = c.prepareSnapshotUsing(t.Context(), &sharedSnapshotIntent{candidate: c, account: s.account, proposal: proposal}, f); err == nil || len(f.commands) != before {
		t.Fatal("failed upload promoted a valid prefix instead of whole original input")
	}
	if err = c.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
}

func TestSharedSnapshotRejectsForeignOrMutatedProvenanceBeforeCommands(t *testing.T) {
	cases := map[string]func(*sharedSnapshotIntent){
		"account":    func(i *sharedSnapshotIntent) { i.account = nil },
		"token":      func(i *sharedSnapshotIntent) { i.candidate.token++ },
		"scope":      func(i *sharedSnapshotIntent) { i.proposal.ScopeCookie++ },
		"generation": func(i *sharedSnapshotIntent) { i.proposal.Generation++ },
		"epoch":      func(i *sharedSnapshotIntent) { i.proposal.Policies[0].RootEpoch = 0 },
		"container":  func(i *sharedSnapshotIntent) { i.proposal.Container = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			n, _, c, intent, f := sharedSnapshotFixture(t, 1)
			before := len(f.commands)
			mutate(intent)
			if err := c.prepareSnapshotUsing(t.Context(), intent, f); err == nil || len(f.commands) != before || !n.objects.records[c.record].live {
				t.Fatal("invalid provenance emitted a command or lost ownership")
			}
			if err := c.discard(t.Context(), f); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedSnapshotPreparationAndRefusalPreserveActiveGeneration(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	f := &sharedSnapshotTransport{refusePin: -1}
	p := sharedRegistryPolicy()
	old, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal(err)
	}
	// Unit-only simulated accepted record. No runtime Commit producer exists;
	// the independent actual C held-reader test proves the kernel boundary.
	n.objects.scopes[0] = sharedSnapshotScopeState{generation: 7, nextSerial: 7}
	n.objects.records[old.record].snapshot = sharedSnapshotCandidateState{account: s.account, scope: s.ScopeCookie(), serial: 7, phase: 3}
	f.nextSerial = 7
	f.serial[0] = 7
	f.phase[0] = 3
	f.tickets[0][0] = 1
	c, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
	if err != nil {
		t.Fatal(err)
	}
	r := &n.objects.records[c.record]
	proposal, err := fullpolicy.NewSharedSnapshot(s.ScopeCookie(), 8, "container", []fullpolicy.SharedPolicyRef{{Object: r.source[0], RootEpoch: 3}})
	if err != nil {
		t.Fatal(err)
	}
	intent := &sharedSnapshotIntent{candidate: c, account: s.account, proposal: proposal}
	if err = c.prepareSnapshotUsing(t.Context(), intent, f); err != nil {
		t.Fatal(err)
	}
	if err = c.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if n.objects.scopes[0].generation != 7 || n.objects.scopes[0].nextSerial != 8 || f.phase[0] != 3 || f.serial[0] != 7 || f.tickets[0][0] != 1 || n.objects.slots[0].refs != 1 {
		t.Fatal("candidate preparation/cleanup modified retained active state")
	}
	before := len(f.commands)
	if err = old.discard(t.Context(), f); err == nil || len(f.commands) != before || !n.objects.records[old.record].live {
		t.Fatal("ordinary cleanup implicitly withdrew active record")
	}
}

func TestSharedSnapshotStopJoinsCompletedPinAndCleanup(t *testing.T) {
	n, _, c, intent, f := sharedSnapshotFixture(t, 3)
	entered, release := make(chan struct{}), make(chan struct{})
	f.afterRun = func() {
		if f.command.Operation == 9 && f.command.Index == 0 {
			close(entered)
			<-release
		}
	}
	done := make(chan error, 1)
	go func() { done <- c.prepareSnapshotUsing(context.Background(), intent, f) }()
	<-entered
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := n.beforeStopProtocolUsing(canceled, f); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if n.host.commandsJoined {
		t.Fatal("unjoined PIN allowed admin close")
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	f.afterRun = nil
	if err := n.beforeStopProtocolUsing(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if n.objects.records[c.record].live || n.objects.retainedBytes != 0 || !n.host.commandsJoined {
		t.Fatal("joined stop failed authoritative candidate cleanup")
	}
}

func TestSharedSnapshotUnresolvedStopRetainsLeasesUntilDestruction(t *testing.T) {
	n, _, c, intent, f := sharedSnapshotFixture(t, 1)
	f.afterRun = func() {
		if f.command.Operation == 9 {
			f.readErr = errors.New("unresolved pin")
		}
	}
	if err := c.prepareSnapshotUsing(t.Context(), intent, f); err == nil {
		t.Fatal("missing unknown outcome")
	}
	if err := n.beforeStopProtocolUsing(t.Context(), f); err == nil {
		t.Fatal("lost unresolved cleanup diagnostic")
	}
	if !n.host.commandsJoined || !n.objects.records[c.record].live || n.objects.slots[0].refs != 1 || n.objects.retainedBytes == 0 {
		t.Fatal("native join fabricated reclaim or dropped lease")
	}
	gc := n.host.context
	if err := n.Close(gc); err == nil {
		t.Fatal("sticky cleanup diagnostic lost")
	}
	if err := n.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	if !n.objects.destroyed || n.objects.retainedBytes != 0 || n.objects.records[c.record].live {
		t.Fatal("terminal protocol destruction did not release retained ownership")
	}
}

func TestSharedSnapshotReleaseRefusalRequiresAuthoritativeInspectionBeforeRetry(t *testing.T) {
	n, _, c, intent, f := sharedSnapshotFixture(t, 1)
	if err := c.prepareSnapshotUsing(t.Context(), intent, f); err != nil {
		t.Fatal(err)
	}
	f.refuseRelease = true
	if err := c.discard(t.Context(), f); err == nil || n.objects.slots[0].refs != 1 {
		t.Fatal("release refusal dropped object lease")
	}
	f.refuseRelease = false
	start := len(f.commands)
	if err := c.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if f.commands[start].Operation != 15 || f.commands[start+1].Operation != 12 || f.commands[start+2].Operation != 13 {
		t.Fatal("known refusal retried without authoritative ticket observation")
	}
	if n.objects.retainedBytes != 0 {
		t.Fatal("release retry leaked sources")
	}
}

func TestSharedSnapshotContradictoryTypedOutcomesPreserveOwnership(t *testing.T) {
	for _, operation := range []uint32{8, 9, 10} {
		t.Run(fmt.Sprint(operation), func(t *testing.T) {
			n, _, c, intent, f := sharedSnapshotFixture(t, 1)
			f.corruptOperation = operation
			if err := c.prepareSnapshotUsing(t.Context(), intent, f); err == nil {
				t.Fatal("contradictory native phase accepted")
			}
			if !n.objects.records[c.record].snapshot.poisoned || n.objects.slots[0].refs != 1 || n.objects.retainedBytes == 0 {
				t.Fatal("contradictory outcome lost ownership")
			}
			before := len(f.commands)
			if err := c.discard(t.Context(), f); err == nil || len(f.commands) != before {
				t.Fatal("poisoned candidate replayed cleanup")
			}
		})
	}
	t.Run("refused-pin", func(t *testing.T) {
		n, _, c, intent, f := sharedSnapshotFixture(t, 1)
		f.refusePin = 0
		f.corruptOperation = 9
		if err := c.prepareSnapshotUsing(t.Context(), intent, f); err == nil || !n.objects.records[c.record].snapshot.poisoned || n.objects.slots[0].refs != 1 {
			t.Fatal("incompatible refusal inferred empty ticket")
		}
	})
}

func TestSharedSnapshotKnownPrepareRefusalDoesNotAdvanceSerial(t *testing.T) {
	n, _, c, intent, f := sharedSnapshotFixture(t, 1)
	f.phase[c.record%2] = 3 // Native PREPARE guard refuses, without mutation.
	if err := c.prepareSnapshotUsing(t.Context(), intent, f); err == nil {
		t.Fatal("prepare refusal hidden")
	}
	if n.objects.scopes[0].nextSerial != 0 || f.nextSerial != 0 || f.phase[c.record%2] != 3 || n.objects.records[c.record].live {
		t.Fatal("refusal advanced serial or changed native admission")
	}
}

func TestSharedSnapshotRefusedSecondCandidatePreservesPreparedFirstAndSerialHistory(t *testing.T) {
	n, s, first, intent, f := sharedSnapshotFixture(t, 1)
	if err := first.prepareSnapshotUsing(t.Context(), intent, f); err != nil {
		t.Fatal(err)
	}
	prepareNext := func() (sharedObjectCandidate, *sharedSnapshotIntent) {
		t.Helper()
		p := sharedRegistryPolicy()
		p.ID = "policy-0"
		c, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{p}, f)
		if err != nil {
			t.Fatal(err)
		}
		proposal, err := fullpolicy.NewSharedSnapshot(s.ScopeCookie(), 1, "container", []fullpolicy.SharedPolicyRef{{Object: n.objects.records[c.record].source[0], RootEpoch: 1}})
		if err != nil {
			t.Fatal(err)
		}
		return c, &sharedSnapshotIntent{candidate: c, account: s.account, proposal: proposal}
	}
	second, secondIntent := prepareNext()
	if err := second.prepareSnapshotUsing(t.Context(), secondIntent, f); err == nil {
		t.Fatal("native second-candidate exclusion bypassed")
	}
	if !n.objects.records[first.record].live || n.objects.records[first.record].snapshot.phase != 2 || f.phase[first.record%2] != 2 || f.tickets[first.record%2][0] != 1 || n.objects.scopes[0].nextSerial != 1 || n.objects.slots[0].refs != 1 {
		t.Fatal("refused replacement modified retained prepared candidate")
	}
	if err := first.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	next, nextIntent := prepareNext()
	if err := next.prepareSnapshotUsing(t.Context(), nextIntent, f); err != nil {
		t.Fatal(err)
	}
	if n.objects.scopes[0].nextSerial != 2 || n.objects.scopes[0].generation != 0 {
		t.Fatal("reclaimed serial reused or preparation advanced accepted generation")
	}
	if err := next.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
}
