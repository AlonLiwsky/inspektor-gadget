// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func ownerTestConfig(t *testing.T) OwnerConfig {
	t.Helper()
	p, err := fullpolicy.CompileKernel([]fullpolicy.Policy{{ID: "uid", Revision: "1", Mode: fullpolicy.Enforce}}, 1, "app")
	if err != nil {
		t.Fatal(err)
	}
	return OwnerConfig{Program: p, CgroupID: 42, InitHostPID: 1, ControlRoot: "/sys/fs/cgroup", Acquire: func(context.Context) (BindingLease, error) {
		t.Error("Acquire before Start")
		return nil, errors.New("unexpected acquire")
	}}
}

func TestOwnerReservationsAndImmutableInput(t *testing.T) {
	budget := testBudget(t, 2)
	config := ownerTestConfig(t)
	owner, err := NewOwner(config, budget)
	if err != nil {
		t.Fatal(err)
	}
	config.Program.Entries[0][0] ^= 0xff
	if err = fullpolicy.ValidateKernelProgram(owner.config.Program); err != nil {
		t.Fatal("caller mutation retained", err)
	}
	if _, err = NewOwner(owner.config, budget); err == nil {
		t.Fatal("same cgroup acquired twice")
	}
	owner.claimed = true
	if err = owner.ReleaseAfterDetach(); err == nil {
		t.Fatal("released before operator close")
	}
	if budget.Usage().Owners != 1 {
		t.Fatal("reservation released early")
	}
	if err = owner.Close(nil); err != nil {
		t.Fatal(err)
	}
	if budget.Usage().Owners != 1 {
		t.Fatal("operator Close released before eBPF teardown")
	}
	if err = owner.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	if err = owner.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	if budget.Usage().Owners != 0 {
		t.Fatal("reservation leaked")
	}
	next, err := NewOwner(owner.config, budget)
	if err != nil {
		t.Fatal(err)
	}
	if err = next.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
}

// G009 step 6: the legacy per-cgroup Owner is hard-capped per node,
// fail-closed, before anything of a refused owner is loaded or attached.
func TestLegacyOwnerHardCap(t *testing.T) {
	n := uint64(LegacyOwnerHardCap + 1)
	if _, err := NewBudget(BudgetLimits{n, n * OwnerMapPayloadLimit, n * OwnerInstructionLimit, n * OwnerHistoryLimit}); !errors.Is(err, ErrLegacyOwnerCap) {
		t.Fatalf("budget above the hard cap: %v", err)
	}
	budget := testBudget(t, LegacyOwnerHardCap)
	var owners []*Owner
	for cgroup := uint64(1); cgroup <= LegacyOwnerHardCap; cgroup++ {
		config := ownerTestConfig(t)
		config.CgroupID = cgroup
		owner, err := NewOwner(config, budget)
		if err != nil {
			t.Fatalf("owner %d: %v", cgroup, err)
		}
		owners = append(owners, owner)
	}
	third := ownerTestConfig(t)
	third.CgroupID = LegacyOwnerHardCap + 1
	owner, err := NewOwner(third, budget)
	if !errors.Is(err, ErrLegacyOwnerCap) || owner != nil {
		t.Fatalf("owner 3 admitted: %v", err)
	}
	// Owner 3 got no handle (so no WithOwner, image load or attach) and holds
	// no reservation; owners 1-2 keep theirs.
	if budget.Usage().Owners != LegacyOwnerHardCap || budget.scopes[third.CgroupID] != nil {
		t.Fatal("refused owner left a reservation")
	}
	for k, o := range owners {
		if o.reservation == nil || budget.scopes[uint64(k+1)] != o.reservation.state {
			t.Fatalf("owner %d reservation disturbed", k+1)
		}
	}
	if err := owners[0].ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	owner, err = NewOwner(third, budget)
	if err != nil {
		t.Fatalf("freed capacity not reusable: %v", err)
	}
	for _, o := range []*Owner{owners[1], owner} {
		if err := o.ReleaseAfterDetach(); err != nil {
			t.Fatal(err)
		}
	}
	if budget.Usage() != (BudgetLimits{}) {
		t.Fatal("budget leaked")
	}
}

func TestFreshOwnerRejectsPastEpochAndMissingBudget(t *testing.T) {
	config := ownerTestConfig(t)
	if _, err := NewOwner(config, nil); err == nil {
		t.Fatal("missing aggregate budget accepted")
	}
	past, err := fullpolicy.CompileKernelWithRoleEpochs([]fullpolicy.Policy{{ID: "uid", Revision: "2", Mode: fullpolicy.Enforce}}, 2, "app", map[string]uint64{"uid": 1})
	if err != nil {
		t.Fatal(err)
	}
	config.Program = past
	budget := testBudget(t, 1)
	if _, err = NewOwner(config, budget); err == nil {
		t.Fatal("fresh owner adopted an old successful epoch")
	}
	if budget.Usage().Owners != 0 {
		t.Fatal("invalid program consumed reservation")
	}
}

func TestOwnerAdmissionBeforeAnyAcquire(t *testing.T) {
	budget := testBudget(t, 1)
	owner, err := NewOwner(ownerTestConfig(t), budget)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.ReleaseAfterDetach()
	gc := gadgetcontext.New(t.Context(), "trusted:test", WithOwner(owner))
	defer gc.Cancel()
	if required, _ := gc.GetVar(operators.NativeOwnerRequiredKey); required != true {
		t.Fatal("native-owner image admission requirement missing before OCI initialization")
	}
	// The legacy Owner opts out of the native default attach retry and keeps
	// refusing attach capacity at once.
	if retry, ok := gc.GetVar(operators.NativeAttachRetryKey); !ok || retry != false {
		t.Fatalf("legacy Owner attach retry %v, want explicit opt-out", retry)
	}
	cfg := viper.New()
	cfg.Set("annotations.enforce-exec-owner-abi", "2")
	gc.SetVar("config", cfg)
	// No native manifest: reject BEFORE kernel checking, map loading or acquiring.
	if _, err = New().InstantiateDataOperator(gc, nil); err == nil {
		t.Fatal("missing resource manifest accepted")
	}
	cfg.Set("annotations.enforce-exec-owner-abi", "3")
	if _, err = New().InstantiateDataOperator(gc, nil); err == nil {
		t.Fatal("foreign ABI accepted")
	}
	gc.SetVar(ownerKey, nil)
	cfg.Set("annotations.enforce-exec-owner-abi", "2")
	if _, err = New().InstantiateDataOperator(gc, nil); err == nil {
		t.Fatal("unconfigured owner image accepted")
	}
	cfg.Set("annotations.enforce-exec-owner-abi", "")
	if instance, err := New().InstantiateDataOperator(gc, nil); err != nil || instance != nil {
		t.Fatal(instance, err)
	}
}

func TestOwnerResumeTracksCommittedCandidate(t *testing.T) {
	publisher, control, _, _ := publicationFixture(t)
	candidate := slotProgram(t, publisher.slot, 2, "uid")
	control.fail = OwnerPhaseClear
	if result, err := publisher.Publish(t.Context(), candidate); err == nil || !result.Committed {
		t.Fatal(result, err)
	}
	owner := &Owner{publisher: publisher, slot: publisher.slot, prepared: true, pending: candidate}
	control.fail = 0
	result, err := owner.Resume(t.Context())
	if err != nil || !result.Admitting || owner.current != candidate || owner.pending != nil {
		t.Fatal(result, err)
	}
	next := slotProgram(t, publisher.slot, 3, "new")
	control.fail = OwnerBootstrapA
	result, err = owner.Update(t.Context(), next)
	if err == nil || result.Committed || owner.current != candidate || owner.pending != nil || owner.Generation() != 2 {
		t.Fatal("refusal changed native active provenance", result, err)
	}
}

func TestOwnerDrainTimeoutRetainsUsableLastGood(t *testing.T) {
	publisher, _, _, _ := publicationFixture(t)
	if _, err := publisher.Publish(t.Context(), slotProgram(t, publisher.slot, 1, "uid")); err != nil {
		t.Fatal(err)
	}
	owner := &Owner{publisher: publisher, slot: publisher.slot, gate: publisher.slot.gate}
	if err := owner.gate.Enter(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	if err := owner.BeforeStop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if owner.closing {
		t.Fatal("failed drain permanently closed native API")
	}
	requireState(t, owner.gate, false, 1)
	if err := owner.gate.Leave(); err != nil {
		t.Fatal(err)
	}
	if err := owner.BeforeStop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !owner.closing {
		t.Fatal("retired owner permits further publication")
	}
}

func TestOwnerRequiresEveryLiveHook(t *testing.T) {
	gc := gadgetcontext.New(t.Context(), "trusted:test")
	defer gc.Cancel()
	owner := &Owner{context: gc, attachments: map[string]*operators.NativeAttachment{}}
	if err := owner.captureAttachments(); err == nil {
		t.Fatal("missing hooks accepted")
	}
	for name, hook := range ownerHooks {
		gc.SetVar(operators.NativeAttachmentPrefix+name, &operators.NativeAttachment{Type: uint32(hook.kind), Target: hook.target, Check: func() error { return nil }})
	}
	if err := owner.captureAttachments(); err != nil {
		t.Fatal(err)
	}
	gc.SetVar(operators.NativeAttachmentPrefix+"eo_bprm_exit", &operators.NativeAttachment{Type: uint32(ownerHooks["eo_bprm_exit"].kind), Target: "wrong", Check: func() error { return nil }})
	if err := owner.captureAttachments(); err == nil {
		t.Fatal("wrong cleanup target accepted")
	}
}

func TestOwnerDiagnosticsUnavailable(t *testing.T) {
	for _, o := range []*Owner{{}, {closed: true}, {released: true}} {
		if _, err := o.Diagnostics(); err == nil {
			t.Fatal("unavailable resources supplied a diagnostic snapshot")
		}
	}
}

func TestOwnerCheckRetriesFinalizedCleanupWithoutRepublishing(t *testing.T) {
	publisher, _, outer, epochs := publicationFixture(t)
	initial := slotProgram(t, publisher.slot, 1, "uid")
	if _, err := publisher.Publish(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	owner := &Owner{publisher: publisher, slot: publisher.slot, gate: publisher.slot.gate, prepared: true, current: initial}
	candidate := slotProgram(t, publisher.slot, 2, "uid", "new")
	outer.deleteErr = errSlotFailure
	result, err := owner.Update(t.Context(), candidate)
	if !errors.Is(err, errSlotFailure) || !result.Committed || !result.Admitting || owner.pending != nil || !owner.slot.staging {
		t.Fatal("expected finalized commit with auxiliary cleanup pending", result, err)
	}
	generation, attempted, accepted := owner.Generation(), owner.slot.attempted, owner.Epochs()
	active := owner.current
	slotPuts, epochPuts, deletes := outer.puts, epochs.puts, outer.deletes
	if err = owner.Check(t.Context()); !errors.Is(err, errSlotFailure) || outer.deletes != deletes+1 {
		t.Fatal("same-generation health did not retry cleanup", err, outer.deletes)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err = owner.Check(canceled); !errors.Is(err, context.Canceled) || outer.deletes != deletes+1 {
		t.Fatal("canceled check mutated cleanup", err)
	}
	outer.deleteErr = nil
	// This unit owner has no native identity pins: cleanup success is not proof
	// of runtime health. Check must continue to attestation and still refuse Ready.
	if err = owner.Check(t.Context()); err == nil || errors.Is(err, errSlotFailure) || owner.slot.staging || outer.deletes != deletes+2 {
		t.Fatal("cleanup recovery skipped attestation or retained staging", err)
	}
	if err = owner.Check(t.Context()); err == nil || outer.deletes != deletes+2 {
		t.Fatal("clean slot retried delete or fake owner became ready", err)
	}
	if owner.Generation() != generation || generation != 2 || owner.slot.attempted != attempted || owner.current != active || !reflect.DeepEqual(owner.Epochs(), accepted) || accepted["uid"] != 1 || accepted["new"] != 2 || outer.puts != slotPuts || epochs.puts != epochPuts || epochs.deletes != 0 {
		t.Fatal("cleanup republished or reset accepted history")
	}
	requireState(t, owner.gate, false, 0)
}

func TestOwnerCheckDoesNotCleanPendingPublication(t *testing.T) {
	publisher, control, outer, _ := publicationFixture(t)
	initial := slotProgram(t, publisher.slot, 1, "uid")
	if _, err := publisher.Publish(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	owner := &Owner{publisher: publisher, slot: publisher.slot, gate: publisher.slot.gate, prepared: true, current: initial}
	control.fail = OwnerPhaseClear
	candidate := slotProgram(t, publisher.slot, 2, "uid", "new")
	if result, err := owner.Update(t.Context(), candidate); err == nil || !result.Committed || owner.pending == nil {
		t.Fatal(result, err)
	}
	deletes := outer.deletes
	if err := owner.Check(t.Context()); !errors.Is(err, ErrGateBusy) || outer.deletes != deletes || !owner.slot.staging || owner.PendingGeneration() != 2 {
		t.Fatal("health changed in-flight publication", err)
	}
	requireState(t, owner.gate, true, 0)
	control.fail = 0
	if result, err := owner.Resume(t.Context()); err != nil || !result.Admitting || owner.PendingGeneration() != 0 {
		t.Fatal(result, err)
	}
}

// protectionFixture publishes generation 1 through the fake control, then
// records the gate state at every later control command.
func protectionFixture(t *testing.T) (*Gate, *fakePublicationControl, *[]bool) {
	t.Helper()
	publisher, control, _, _ := publicationFixture(t)
	if _, err := publisher.Publish(t.Context(), slotProgram(t, publisher.slot, 1, "uid")); err != nil {
		t.Fatal(err)
	}
	gate := publisher.slot.gate
	requireState(t, gate, false, 0)
	control.calls = nil
	closedAtCall := new([]bool)
	control.hook = func(ControlCommand) {
		closed, _, err := gate.State()
		if err != nil {
			t.Error(err)
		}
		*closedAtCall = append(*closedAtCall, closed)
	}
	return gate, control, closedAtCall
}

// A same-plan heartbeat after unrelated node-wide cgroup motion must stay
// read-only: no re-attestation and no closed admission gate, so Audit execs
// and forks in the bound cgroup are never refused by a refresh.
func TestOwnerHeartbeatIsReadOnlyAfterNodeMovement(t *testing.T) {
	gate, control, closedAtCall := protectionFixture(t)
	validated := control.phase.ValidatedMovementSequence
	for i := uint64(1); i <= 5; i++ {
		// Each completed migration anywhere on the node adds two.
		control.health.MovementSequence = validated + 2*i
		if err := checkProtection(t.Context(), control, gate, 1); err != nil {
			t.Fatalf("heartbeat %d refused a stale movement receipt: %v", i, err)
		}
		requireState(t, gate, false, 0)
	}
	for _, op := range control.calls {
		if op != OwnerRootCheck {
			t.Fatalf("heartbeat sent control command %d, want only root checks: %v", op, control.calls)
		}
	}
	if len(control.calls) != 5 {
		t.Fatalf("calls=%v", control.calls)
	}
	for i, closed := range *closedAtCall {
		if closed {
			t.Fatalf("heartbeat closed the admission gate at call %d", i)
		}
	}
	if control.health.ReadyGeneration != 1 || control.phase.ValidatedMovementSequence != validated {
		t.Fatal("heartbeat changed the readiness receipt")
	}
}

// rootLostControl reports a root check that no longer matches the trusted init.
type rootLostControl struct{ *fakePublicationControl }

func (c rootLostControl) Call(ctx context.Context, cmd ControlCommand) (ControlHealth, error) {
	h, err := c.fakePublicationControl.Call(ctx, cmd)
	h.RootMatch = 0
	return h, err
}

// Read-only does not mean fail open: every drift the kernel exposes is NotReady,
// and reporting it never closes the gate either.
func TestOwnerHeartbeatReportsDrift(t *testing.T) {
	for name, drift := range map[string]func(*fakePublicationControl){
		"owner fault":        func(c *fakePublicationControl) { c.health.Faults = 1 },
		"movement fault":     func(c *fakePublicationControl) { c.health.MovementFault = 1 },
		"movement disarmed":  func(c *fakePublicationControl) { c.health.MovementArmed = 0 },
		"migration underway": func(c *fakePublicationControl) { c.health.MovementSequence = 3 },
		"retired":            func(c *fakePublicationControl) { c.health.Retired = 1 },
		"readiness lost":     func(c *fakePublicationControl) { c.health.ReadyGeneration = 0 },
		"other generation":   func(c *fakePublicationControl) { c.health.ActiveGeneration = 2 },
		"generation fault":   func(c *fakePublicationControl) { c.fault = 1 },
		"phase not idle":     func(c *fakePublicationControl) { c.phase.State = OwnerCommitted },
		"root check failed":  func(c *fakePublicationControl) { c.fail = OwnerRootCheck },
		"root lost":          func(*fakePublicationControl) {},
	} {
		t.Run(name, func(t *testing.T) {
			gate, control, _ := protectionFixture(t)
			drift(control)
			var checked publicationControl = control
			if name == "root lost" {
				checked = rootLostControl{control}
			}
			if err := checkProtection(t.Context(), checked, gate, 1); err == nil {
				t.Fatal("drift reported Ready")
			}
			requireState(t, gate, false, 0)
			for _, op := range control.calls {
				if op != OwnerRootCheck {
					t.Fatalf("drift check sent control command %d", op)
				}
			}
		})
	}
	t.Run("gate closed", func(t *testing.T) {
		gate, control, _ := protectionFixture(t)
		lease, err := gate.BeginUpdate(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err = checkProtection(t.Context(), control, gate, 1); err == nil {
			t.Fatal("closed gate reported Ready")
		}
		if err = lease.Reopen(); err != nil {
			t.Fatal(err)
		}
		if err = checkProtection(t.Context(), control, gate, 1); err != nil {
			t.Fatal(err)
		}
	})
}

type testKernelCounters struct {
	values        [3][]uint64
	fail          bool
	reads, closes int
}

func (m *testKernelCounters) Lookup(key interface{}, value interface{}) error {
	m.reads++
	if m.fail {
		return errors.New("counter read failed")
	}
	*value.(*[]uint64) = append([]uint64(nil), m.values[key.(uint32)]...)
	return nil
}
func (m *testKernelCounters) Close() error { m.closes++; return nil }

func TestKernelCounterLayout(t *testing.T) {
	valid := ebpf.MapInfo{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 3}
	if err := validateCounterMap(&valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ebpf.MapInfo){func(m *ebpf.MapInfo) { m.Type = ebpf.Array }, func(m *ebpf.MapInfo) { m.KeySize = 8 }, func(m *ebpf.MapInfo) { m.ValueSize = 4 }, func(m *ebpf.MapInfo) { m.MaxEntries = 2 }} {
		invalid := valid
		mutate(&invalid)
		if validateCounterMap(&invalid) == nil {
			t.Fatalf("accepted incompatible map: %+v", invalid)
		}
	}
	if validateCounterMap(nil) == nil {
		t.Fatal("accepted nil map info")
	}
}

func TestKernelCountersRetainFinalSnapshotAfterDetach(t *testing.T) {
	m := &testKernelCounters{values: [3][]uint64{{3, 4}, {5, 6}, {1, 2}}}
	owner := &Owner{counterMap: m}
	got, err := owner.KernelEventCounters()
	if err != nil || got.Submitted != 7 || got.Lost != 11 || got.ObservationErrors != 3 || got.Final {
		t.Fatalf("live snapshot: %+v %v", got, err)
	}
	if m.closes != 0 || owner.closing || owner.released {
		t.Fatal("diagnostics changed lifecycle")
	}
	owner.claimed = true
	if owner.ReleaseAfterDetach() == nil {
		t.Fatal("released live owner")
	}
	if m.closes != 0 {
		t.Fatal("closed counters before detach")
	}
	owner.closed = true
	m.values[1][0] = 10 // reserves occurring after the last live query are retained
	if err := owner.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	got, err = owner.KernelEventCounters()
	if err != nil || got.Lost != 16 || !got.Final || m.closes != 1 {
		t.Fatalf("final snapshot: %+v %v closes=%d", got, err, m.closes)
	}
	reads := m.reads
	if err := owner.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	_, _ = owner.KernelEventCounters()
	if m.reads != reads || m.closes != 1 {
		t.Fatal("final diagnostics reread/closed consumed map")
	}
}

func TestKernelCounterReadFailuresRemainUnavailable(t *testing.T) {
	m := &testKernelCounters{values: [3][]uint64{{3}, {7}, {2}}}
	owner := &Owner{counterMap: m}
	_, _ = owner.KernelEventCounters()
	m.fail = true
	got, err := owner.KernelEventCounters()
	if err == nil || got.Lost != 7 || got.Final {
		t.Fatalf("failed live read: %+v %v", got, err)
	}
	if err := owner.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	got, err = owner.KernelEventCounters()
	if err == nil || got.Lost != 7 || !got.Final {
		t.Fatalf("failed final read: %+v %v", got, err)
	}
	missing := &Owner{}
	if _, err := missing.KernelEventCounters(); err == nil {
		t.Fatal("missing map reported zero loss")
	}
	if err := missing.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	if got, err := missing.KernelEventCounters(); err == nil || !got.Final {
		t.Fatalf("missing final map: %+v %v", got, err)
	}
	empty := &Owner{counterMap: &testKernelCounters{}}
	if _, err := empty.KernelEventCounters(); err == nil {
		t.Fatal("empty per-CPU vector reported zero loss")
	}
}

func TestOwnerAbortPendingPreservesCommittedHistory(t *testing.T) {
	for _, cleanupFailure := range []bool{false, true} {
		t.Run(fmt.Sprint("cleanupFailure=", cleanupFailure), func(t *testing.T) {
			publisher, control, outer, epochs := publicationFixture(t)
			initial := slotProgram(t, publisher.slot, 1, "uid")
			if _, err := publisher.Publish(t.Context(), initial); err != nil {
				t.Fatal(err)
			}
			owner := &Owner{publisher: publisher, slot: publisher.slot, prepared: true, current: initial}
			candidate := slotProgram(t, publisher.slot, 2, "uid", "discarded")
			control.hook = func(cmd ControlCommand) {
				if cmd.Operation == OwnerBootstrapB || cmd.Operation == OwnerBootstrapAbort {
					control.fail = cmd.Operation
				}
			}
			if result, err := owner.Update(t.Context(), candidate); err == nil || result.Committed || owner.pending == nil {
				t.Fatal(result, err)
			}
			accepted := owner.Epochs()
			puts, epochPuts := outer.puts, epochs.puts
			if err := owner.AbortPending(t.Context()); err == nil || owner.PendingGeneration() != 2 || publisher.pending == nil {
				t.Fatal("failed abort lost candidate", err)
			}
			control.hook, control.fail = nil, 0
			if cleanupFailure {
				outer.deleteErr = errSlotFailure
			}
			err := owner.AbortPending(t.Context())
			if (cleanupFailure && !errors.Is(err, errSlotFailure)) || (!cleanupFailure && err != nil) {
				t.Fatal("unexpected abort result", err)
			}
			if owner.pending != nil || publisher.pending != nil || owner.Generation() != 1 || owner.current != initial || !reflect.DeepEqual(owner.Epochs(), accepted) || outer.puts != puts || epochs.puts != epochPuts || epochs.deletes != 0 {
				t.Fatal("abort changed committed provenance")
			}
			requireState(t, publisher.slot.gate, false, 0)
			if _, err := owner.Resume(t.Context()); err == nil {
				t.Fatal("aborted candidate resumed")
			}
			outer.deleteErr = nil
			next := slotProgram(t, publisher.slot, 3, "uid", "replacement")
			if result, err := owner.Update(t.Context(), next); err != nil || !result.Committed || !result.Admitting {
				t.Fatal(result, err)
			}
			if owner.Epochs()["uid"] != 1 || owner.Epochs()["replacement"] != 3 || owner.Epochs()["discarded"] != 0 {
				t.Fatal("aborted candidate changed UID epochs", owner.Epochs())
			}
		})
	}
}

func TestOwnerAbortPendingRefusesCommittedPublication(t *testing.T) {
	publisher, control, _, _ := publicationFixture(t)
	initial := slotProgram(t, publisher.slot, 1, "uid")
	if _, err := publisher.Publish(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	owner := &Owner{publisher: publisher, slot: publisher.slot, prepared: true, current: initial}
	candidate := slotProgram(t, publisher.slot, 2, "uid", "new")
	control.fail = OwnerPhaseClear
	if result, err := owner.Update(t.Context(), candidate); err == nil || !result.Committed {
		t.Fatal(result, err)
	}
	active, accepted := owner.current, owner.Epochs()
	if err := owner.AbortPending(t.Context()); err == nil || owner.current != active || owner.PendingGeneration() != 2 || owner.Generation() != 2 || !reflect.DeepEqual(owner.Epochs(), accepted) {
		t.Fatal("committed publication aborted", err)
	}
	control.fail = 0
	if result, err := owner.Resume(t.Context()); err != nil || !result.Admitting || owner.pending != nil || !reflect.DeepEqual(owner.Epochs(), accepted) {
		t.Fatal(result, err)
	}
}

func TestOwnerAbortPendingRequiresRunningOwner(t *testing.T) {
	for _, owner := range []*Owner{{}, {prepared: true}, {prepared: true, publisher: &Publisher{}, closing: true}, {prepared: true, publisher: &Publisher{}, closed: true}} {
		if err := owner.AbortPending(t.Context()); err == nil {
			t.Fatal("inactive owner accepted abort")
		}
	}
	publisher, _, _, _ := publicationFixture(t)
	owner := &Owner{publisher: publisher, prepared: true}
	if err := owner.AbortPending(t.Context()); err != nil {
		t.Fatal("no pending publication must be idempotent", err)
	}
}

// Metadata is not trusted consent: both the native option and the explicit
// development image marker must agree, before resources or Acquire are touched.
func TestOwnerDevelopmentAdmissionBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, abi             string
		opt, marker, accepted bool
	}{
		{"default", "2", false, false, true},
		{"abi3_without_opt", "3", false, true, false},
		{"abi3_without_marker", "3", true, false, false},
		{"abi2_with_opt", "2", true, false, false},
		{"abi2_with_marker", "2", false, true, false},
		{"development", "3", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := ownerTestConfig(t)
			config.ABI3Development = tc.opt
			budget := testBudget(t, 1)
			owner, err := NewOwner(config, budget)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.ReleaseAfterDetach()
			gc := gadgetcontext.New(t.Context(), "trusted:test", WithOwner(owner))
			defer gc.Cancel()
			metadata := viper.New()
			metadata.Set("annotations.enforce-exec-owner-abi", tc.abi)
			metadata.Set("annotations.enforce-exec-owner-development", tc.marker)
			gc.SetVar("config", metadata)
			_, err = New().InstantiateDataOperator(gc, nil)
			if err == nil {
				t.Fatal("missing manifest must still refuse admission")
			}
			// Accepted selector reaches resource admission; rejected selector must not.
			selectorError := strings.Contains(err.Error(), "configuration") || strings.Contains(err.Error(), "development")
			if selectorError == tc.accepted {
				t.Fatalf("selector accepted=%v: %v", tc.accepted, err)
			}
			if owner.claimed {
				t.Fatal("invalid admission claimed owner")
			}
		})
	}
}

func TestDevelopmentControlABIRequiresTrustedOption(t *testing.T) {
	cfg := ControlConfig{Cookie: 1, Cgroup: 1, InitHostPID: 1, TaskLimit: 1, ABI: OwnerDevelopmentABI}
	if _, err := NewOwnerControl(t.Context(), cfg, ControlResources{}, nil); err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("public ABI2 control constructor selected development ABI: %v", err)
	}
	if _, err := newOwnerControl(t.Context(), cfg, ControlResources{}, nil, true); err == nil || !strings.Contains(err.Error(), "gate required") {
		t.Fatalf("explicit development control selection: %v", err)
	}
	cfg.ABI = OwnerABI
	if _, err := newOwnerControl(t.Context(), cfg, ControlResources{}, nil, true); err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("development accepted ABI2 control: %v", err)
	}
}
