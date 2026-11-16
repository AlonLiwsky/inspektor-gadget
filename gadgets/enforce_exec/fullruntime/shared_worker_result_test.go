// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

func TestPrivateWorkerCompilerFailureRetainsPrefix(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	f := &sharedObjectUploadTransport{}
	good := sharedRegistryPolicy()
	bad := good
	bad.ID = "bad"
	bad.Rules = []fullpolicy.Rule{{Name: "r", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{"/["}}}}
	_, want := fullpolicy.CompileSharedPolicyCompact(bad)
	c, result, compilerOnly := s.prepareSharedObjectsPrivate(t.Context(), []fullpolicy.Policy{good, bad}, f)
	if compilerOnly != want { //nolint:errorlint // Preserve exact compiler static record identity, not wrapping compatibility.
		t.Fatal("compiler static identity changed")
	}
	var diagnostic fullpolicy.CompactDiagnostic
	if !errors.As(compilerOnly, &diagnostic) || result.primary.reason != workerCompiler || result.cleanupAttempted {
		t.Fatal("compiler failure lost or invented cleanup")
	}
	if !n.objects.records[c.record].live || n.objects.records[c.record].count != 1 || n.objects.retainedBytes == 0 {
		t.Fatal("failed prefix ownership lost")
	}
	for _, command := range f.commands {
		if command.Operation >= 4 {
			t.Fatal("preparation failure automatically discarded")
		}
	}
	if result := c.discardPrivate(t.Context(), f); result.failed() {
		t.Fatalf("explicit cleanup failed: %+v", result)
	}
}

func TestPrivateWorkerCompletedCanceledPinCleansActualTicket(t *testing.T) {
	n, _, c, intent, f := sharedSnapshotFixture(t, 2)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.afterRun = func() {
		if f.command.Operation == 9 {
			cancel()
		}
	}
	before := len(f.commands)
	result := c.prepareSnapshotPrivate(ctx, intent, f)
	if !result.failed() || !result.cleanupAttempted || result.cleanup.failed() || !result.primary.command.hasIdentity(context.Canceled) {
		t.Fatalf("lost composite: %+v", result)
	}
	release := false
	for _, command := range f.commands[before:] {
		if command.Operation == 12 && command.Index == 0 {
			release = true
		}
	}
	if !release || n.objects.records[c.record].live || n.objects.retainedBytes != 0 {
		t.Fatal("completed canceled PIN was not actually released")
	}
}

func TestPrivateWorkerCleanupUnderflowRetainsOwners(t *testing.T) {
	n, _, c, intent, f := sharedSnapshotFixture(t, 2)
	f.refusePin = 0
	n.objects.retainedBytes = 0
	result := c.prepareSnapshotPrivate(t.Context(), intent, f)
	record := &n.objects.records[c.record]
	if !result.cleanupAttempted || !result.primary.failed() || result.cleanup.reason != workerRetainedOwnership || !record.live {
		t.Fatalf("actual accounting cleanup lost: %+v", result)
	}
	if record.source[0] == nil || !record.associated[0] || n.objects.slots[record.slots[0]].object == nil {
		t.Fatal("underflow discarded retained source owner")
	}
}

type workerPanicTransport struct {
	*sharedSnapshotTransport
	payload any
}

func (f *workerPanicTransport) runSharedCommand() (uint32, error) {
	if f.command.Operation == 9 {
		panic(f.payload)
	}
	return f.sharedSnapshotTransport.runSharedCommand()
}

func TestPrivateWorkerPanicPrimaryAndCleanup(t *testing.T) {
	n, _, c, intent, base := sharedSnapshotFixture(t, 2)
	f := &workerPanicTransport{base, privateHostileError{t: t}}
	result := c.prepareSnapshotPrivate(t.Context(), intent, f)
	if result.primary.command.code != sharedOutcomePanic || !result.cleanupAttempted || !result.cleanup.failed() || result.cleanup.command.code != sharedOutcomePanic {
		t.Fatalf("panic composite lost: %+v", result)
	}
	if !n.objects.records[c.record].live || n.objects.records[c.record].source[0] == nil || n.host.control.pending == nil {
		t.Fatal("panic discarded uncertain owners")
	}
}

func TestPrivateWorkerScalarLayouts(t *testing.T) {
	if unsafe.Sizeof(workerDiagnostic{}) != 5 || unsafe.Sizeof(workerResult{}) != 11 {
		t.Fatal("worker results retain unexpected backing")
	}
	if _, ok := any(workerResult{}).(error); ok {
		t.Fatal("worker result implements error")
	}
}

// This checks source provenance, not an arbitrary exported diagnostic interface:
// the sole nonnil compiler-only return must be the direct controlled call result.
func TestPrivateWorkerCompilerReturnProvenance(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "shared_objects.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == "prepareSharedObjectsLocked" {
			fn = f
		}
	}
	if fn == nil {
		t.Fatal("missing locked shared preparation engine")
	}
	calls, outputs := 0, 0
	var compilerReturn token.Pos
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if ret, ok := node.(*ast.ReturnStmt); ok && len(ret.Results) == 3 {
			if id, ok := ret.Results[2].(*ast.Ident); ok && id.Name == "e" {
				compilerReturn = ret.Pos()
			}
		}
		return true
	})
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if assign, ok := node.(*ast.AssignStmt); ok && assign.Pos() < compilerReturn {
			for i, lhs := range assign.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name != "e" {
					continue
				}
				if len(assign.Rhs) != 1 {
					t.Fatal("compiler error has foreign assignment")
				}
				call, ok := assign.Rhs[0].(*ast.CallExpr)
				if !ok {
					t.Fatal("compiler error not direct call")
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					t.Fatal("compiler error not selected compiler")
				}
				pkg, ok := sel.X.(*ast.Ident)
				compact := sel.Sel.Name == "CompileSharedPolicyCompact" && i == 1 && len(assign.Lhs) == 2
				limited := sel.Sel.Name == "CompileSharedPolicyLimited" && i == 2 && len(assign.Lhs) == 3
				if !ok || pkg.Name != "fullpolicy" || (!compact && !limited) {
					t.Fatal("foreign error entered compiler-only slot")
				}
				calls++
			}
		}
		if ret, ok := node.(*ast.ReturnStmt); ok {
			if len(ret.Results) != 3 {
				t.Fatal("return arity")
			}
			id, ok := ret.Results[2].(*ast.Ident)
			if !ok || (id.Name != "nil" && id.Name != "e") {
				t.Fatal("compiler error wrapped or foreign")
			}
			if id.Name == "e" {
				outputs++
			}
		}
		return true
	})
	if calls != 2 || outputs != 1 {
		t.Fatal("controlled compiler provenance changed")
	}
}

type workerFaultTransport struct {
	*sharedSnapshotTransport
	operation uint32
	fault     string
	remaining int
}

func (f *workerFaultTransport) trigger(op uint32, phase string) bool {
	if op != f.operation || phase != f.fault || f.remaining == 0 {
		return false
	}
	if f.remaining > 0 {
		f.remaining--
	}
	return true
}

func (f *workerFaultTransport) writeSharedCommand(c sharedCommandWire) error {
	if f.trigger(c.Operation, "write") {
		f.writes++
		return errors.New("write fault")
	}
	return f.sharedSnapshotTransport.writeSharedCommand(c)
}

func (f *workerFaultTransport) runSharedCommand() (uint32, error) {
	if f.trigger(f.command.Operation, "refuse") {
		f.commands = append(f.commands, f.command)
		f.runs++
		f.receipt = sharedReceiptWire{NodeCookie: f.command.NodeCookie, Sequence: f.command.Sequence, Operation: f.command.Operation, Status: 1}
		return 1, nil
	}
	value, err := f.sharedSnapshotTransport.runSharedCommand()
	if f.trigger(f.command.Operation, "run") {
		return value, errors.New("run fault")
	}
	if f.trigger(f.command.Operation, "typed") {
		f.receipt.Value = 99
	}
	return value, err
}

func (f *workerFaultTransport) readSharedReceipt() (sharedReceiptWire, error) {
	if f.trigger(f.command.Operation, "read") {
		f.reads++
		return sharedReceiptWire{}, errors.New("read fault")
	}
	return f.sharedSnapshotTransport.readSharedReceipt()
}

type workerRecordView struct {
	State   sharedObjectRecord
	Sources [8]bool
	Account bool
	Digests [8][32]byte
}
type workerSlotView struct {
	State  sharedObjectSlot
	Object bool
	Digest [32]byte
}
type workerStateView struct {
	ControlSequence uint64
	Pending         sharedPendingCommand
	PendingValid    bool
	Records         []workerRecordView
	Slots           []workerSlotView
	Scopes          []sharedSnapshotScopeState
	Retained        uint64
}

func workerView(n *NodeEnforcer) workerStateView {
	v := workerStateView{Retained: n.objects.retainedBytes, Scopes: append([]sharedSnapshotScopeState(nil), n.objects.scopes...)}
	v.ControlSequence = n.host.control.sequence
	if n.host.control.pending != nil {
		v.Pending = *n.host.control.pending
		v.PendingValid = true
	}
	for _, r := range n.objects.records {
		x := workerRecordView{State: r, Account: r.snapshot.account != nil}
		x.State.snapshot.account = nil
		for i, p := range r.source {
			if p != nil {
				x.Sources[i] = true
				x.Digests[i] = p.Digest()
			}
			x.State.source[i] = nil
		}
		v.Records = append(v.Records, x)
	}
	for _, s := range n.objects.slots {
		x := workerSlotView{State: s, Object: s.object != nil}
		if s.object != nil {
			x.Digest = s.object.Digest()
		}
		x.State.object = nil
		v.Slots = append(v.Slots, x)
	}
	return v
}

func TestPrivateWorkerActualStageFaultDifferential(t *testing.T) {
	for _, op := range []uint32{8, 9, 10} {
		for _, fault := range []string{"write", "run", "read", "refuse", "typed"} {
			for _, remaining := range []int{1, -1} {
				t.Run(fmt.Sprintf("%d/%s/%d", op, fault, remaining), func(t *testing.T) {
					rich, _, rc, ri, rf := sharedSnapshotFixture(t, 2)
					priv, _, pc, pi, pf := sharedSnapshotFixture(t, 2)
					rtransport := &workerFaultTransport{rf, op, fault, remaining}
					ptransport := &workerFaultTransport{pf, op, fault, remaining}
					err := rc.prepareSnapshotUsing(t.Context(), ri, rtransport)
					result := pc.prepareSnapshotPrivate(t.Context(), pi, ptransport)
					if (err != nil) != result.failed() || !result.cleanupAttempted {
						t.Fatalf("failure/cleanup mismatch: %+v", result)
					}
					if !reflect.DeepEqual(workerView(rich), workerView(priv)) || !reflect.DeepEqual(rf.commands, pf.commands) || [3]int{rf.writes, rf.runs, rf.reads} != [3]int{pf.writes, pf.runs, pf.reads} {
						t.Fatal("private engine diverged from rich ownership/history")
					}
				})
			}
		}
	}
}

func TestPrivateWorkerActualCleanupFaultDifferential(t *testing.T) {
	for _, op := range []uint32{11, 12, 13, 5, 6} {
		for _, fault := range []string{"write", "run", "read", "refuse", "typed"} {
			t.Run(fmt.Sprintf("%d/%s", op, fault), func(t *testing.T) {
				rich, _, rc, ri, rf := sharedSnapshotFixture(t, 2)
				priv, _, pc, pi, pf := sharedSnapshotFixture(t, 2)
				if err := rc.prepareSnapshotUsing(t.Context(), ri, rf); err != nil {
					t.Fatal(err)
				}
				if result := pc.prepareSnapshotPrivate(t.Context(), pi, pf); result.failed() {
					t.Fatal(result)
				}
				err := rc.discard(t.Context(), &workerFaultTransport{rf, op, fault, -1})
				result := pc.discardPrivate(t.Context(), &workerFaultTransport{pf, op, fault, -1})
				if (err != nil) != result.failed() || result.cleanupAttempted {
					t.Fatal("explicit discard invented nested cleanup")
				}
				if !reflect.DeepEqual(workerView(rich), workerView(priv)) || !reflect.DeepEqual(rf.commands, pf.commands) || [3]int{rf.writes, rf.runs, rf.reads} != [3]int{pf.writes, pf.runs, pf.reads} {
					t.Fatal("private cleanup diverged from rich state/history")
				}
			})
		}
	}
}

func TestPrivateWorkerPrecommandRejectionsDoNotDiscard(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*NodeEnforcer, *sharedObjectCandidate, *sharedSnapshotIntent)
		site   workerSite
	}{
		{"foreign", func(n *NodeEnforcer, c *sharedObjectCandidate, _ *sharedSnapshotIntent) {
			c.record = uint32(len(n.objects.records))
		}, workerSnapshotCandidate},
		{"stale", func(_ *NodeEnforcer, c *sharedObjectCandidate, _ *sharedSnapshotIntent) { c.token++ }, workerSnapshotCandidate},
		{"attempted", func(n *NodeEnforcer, c *sharedObjectCandidate, _ *sharedSnapshotIntent) {
			n.objects.records[c.record].snapshot.phase = 1
		}, workerSnapshotUnused},
		{"account", func(_ *NodeEnforcer, _ *sharedObjectCandidate, i *sharedSnapshotIntent) { i.account = nil }, workerSnapshotAccount},
		{"scope", func(_ *NodeEnforcer, _ *sharedObjectCandidate, i *sharedSnapshotIntent) { i.proposal.ScopeCookie++ }, workerSnapshotScope},
		{"count", func(_ *NodeEnforcer, _ *sharedObjectCandidate, i *sharedSnapshotIntent) { i.proposal.Policies = nil }, workerSnapshotScope},
		{"summary", func(_ *NodeEnforcer, _ *sharedObjectCandidate, i *sharedSnapshotIntent) {
			i.proposal.Policies[0].Object = nil
		}, workerSnapshotSummary},
		{"metadata", func(_ *NodeEnforcer, _ *sharedObjectCandidate, i *sharedSnapshotIntent) { i.proposal.Container = "" }, workerSnapshotMetadata},
		{"authored", func(n *NodeEnforcer, c *sharedObjectCandidate, _ *sharedSnapshotIntent) {
			n.objects.records[c.record].held[0] = false
		}, workerSnapshotAuthored},
		{"upload", func(n *NodeEnforcer, c *sharedObjectCandidate, _ *sharedSnapshotIntent) {
			r := &n.objects.records[c.record]
			n.objects.slots[r.slots[0]].pending = true
		}, workerSnapshotReady},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, _, c, intent, f := sharedSnapshotFixture(t, 1)
			tt.mutate(n, &c, intent)
			before := workerView(n)
			commands := len(f.commands)
			result := c.prepareSnapshotPrivate(t.Context(), intent, f)
			if !result.failed() || result.primary.site != tt.site || result.cleanupAttempted || len(f.commands) != commands || !reflect.DeepEqual(before, workerView(n)) {
				t.Fatalf("precommand rejection mutated/discarded: %+v", result)
			}
		})
	}
}

func TestPrivateWorkerPreparationRejections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*NodeEnforcer, *BindingSession)
		site   workerSite
	}{
		{"removed", func(_ *NodeEnforcer, s *BindingSession) { s.removed = true }, workerBinding},
		{"pins", func(_ *NodeEnforcer, s *BindingSession) {
			s.account.pins.checkTest = func(context.Context) error { return privateHostileError{t: t} }
		}, workerPins},
		{"records", func(n *NodeEnforcer, _ *BindingSession) {
			for i := range n.objects.records {
				n.objects.records[i].live = true
			}
		}, workerRecord},
		{"retained-limit", func(n *NodeEnforcer, _ *BindingSession) { n.config.Profile.CompileBytes = 1 }, workerRetainedLimit},
		{"retained-capacity", func(n *NodeEnforcer, _ *BindingSession) { n.config.Profile.CandidateBytes = 1 }, workerReserve},
		{"retained-overflow", func(n *NodeEnforcer, _ *BindingSession) { n.objects.retainedBytes = ^uint64(0) }, workerReserve},
		{"slots", func(n *NodeEnforcer, _ *BindingSession) {
			for i := range n.objects.slots {
				n.objects.slots[i].capacity = 0
			}
		}, workerAcquire},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, s, _ := sharedRegistryFixture(t)
			tt.mutate(n, s)
			f := &sharedObjectUploadTransport{}
			_, result, compilerOnly := s.prepareSharedObjectsPrivate(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
			if !result.failed() || result.primary.site != tt.site || compilerOnly != nil || result.cleanupAttempted || len(f.commands) != 0 {
				t.Fatalf("incorrect preparation rejection: %+v", result)
			}
		})
	}
}

func TestPrivateWorkerAccountingFailurePreservesIndependentOwners(t *testing.T) {
	t.Run("independent-final", func(t *testing.T) {
		n, s, _ := sharedRegistryFixture(t)
		f := &sharedObjectUploadTransport{}
		p := sharedRegistryPolicy()
		c, result, compilerOnly := s.prepareSharedObjectsPrivate(t.Context(), []fullpolicy.Policy{p, p}, f)
		if result.failed() || compilerOnly != nil {
			t.Fatal("prepare failed")
		}
		r := &n.objects.records[c.record]
		if r.source[0] == r.source[1] || r.sourceBytes[1] == 0 {
			t.Fatal("independent authored source collapsed")
		}
		n.objects.retainedBytes = n.objects.slots[r.slots[0]].sourceBytes
		result = c.discardPrivate(t.Context(), f)
		if result.primary.site != workerAuthoredFinal || !r.live || r.source[0] != nil || r.source[1] == nil || r.sourceBytes[1] == 0 || r.associated[1] {
			t.Fatalf("independent final owner lost: %+v", result)
		}
	})
	t.Run("shared-source", func(t *testing.T) {
		n, s, _ := sharedRegistryFixture(t)
		f := &sharedObjectUploadTransport{}
		p := sharedRegistryPolicy()
		first, _, _ := s.prepareSharedObjectsPrivate(t.Context(), []fullpolicy.Policy{p}, f)
		second, _, _ := s.prepareSharedObjectsPrivate(t.Context(), []fullpolicy.Policy{p}, f)
		r := &n.objects.records[second.record]
		n.objects.retainedBytes = 0
		result := second.discardPrivate(t.Context(), f)
		if result.primary.site != workerAuthoredShared || !r.live || r.source[0] == nil || r.associated[0] || n.objects.slots[r.slots[0]].refs != 1 || !n.objects.records[first.record].held[0] {
			t.Fatalf("shared independent charge lost: %+v", result)
		}
	})
	t.Run("partial-prefix", func(t *testing.T) {
		n, s, _ := sharedRegistryFixture(t)
		f := &sharedObjectUploadTransport{}
		p, q := sharedRegistryPolicy(), sharedRegistryPolicy()
		q.ID = "different"
		c, result, compilerOnly := s.prepareSharedObjectsPrivate(t.Context(), []fullpolicy.Policy{p, q}, f)
		if result.failed() || compilerOnly != nil {
			t.Fatal("prepare failed")
		}
		r := &n.objects.records[c.record]
		n.objects.retainedBytes = n.objects.slots[r.slots[0]].sourceBytes
		result = c.discardPrivate(t.Context(), f)
		if result.primary.site != workerSlotSource || !r.live || r.source[0] != nil || r.source[1] == nil || n.objects.slots[r.slots[1]].object == nil {
			t.Fatalf("partial cleanup owners lost: %+v", result)
		}
	})
	t.Run("unassociated", func(t *testing.T) {
		n, s, _ := sharedRegistryFixture(t)
		for i := range n.objects.slots {
			n.objects.slots[i].capacity = 0
		}
		f := &sharedObjectUploadTransport{}
		c, _, _ := s.prepareSharedObjectsPrivate(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
		r := &n.objects.records[c.record]
		n.objects.retainedBytes = 0
		result := c.discardPrivate(t.Context(), f)
		if result.primary.site != workerAuthoredUnassociated || !r.live || r.source[0] == nil || r.sourceBytes[0] == 0 {
			t.Fatalf("unassociated source lost: %+v", result)
		}
	})
}

func TestPrivateWorkerInspectAndPartialUploadCleanup(t *testing.T) {
	t.Run("inspect", func(t *testing.T) {
		n, _, c, intent, base := sharedSnapshotFixture(t, 1)
		base.refusePin = 0
		f := &workerFaultTransport{base, 15, "read", -1}
		result := c.prepareSnapshotPrivate(t.Context(), intent, f)
		if !result.cleanupAttempted || result.primary.site != workerSnapshotPin || result.cleanup.site != workerSnapshotInspect || !n.objects.records[c.record].snapshot.inspect[0] || n.objects.records[c.record].source[0] == nil {
			t.Fatalf("inspect failure ownership lost: %+v", result)
		}
	})
	t.Run("object-abort", func(t *testing.T) {
		n, s, _ := sharedRegistryFixture(t)
		base := &sharedSnapshotTransport{refusePin: -1}
		f := &workerFaultTransport{base, 2, "read", -1}
		c, result, _ := s.prepareSharedObjectsPrivate(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
		if result.primary.site != workerObjectCell {
			t.Fatal(result)
		}
		f.operation = 4
		f.fault = "read"
		result = c.discardPrivate(t.Context(), f)
		if result.primary.site != workerObjectAbort || !n.objects.records[c.record].live || n.objects.records[c.record].source[0] == nil {
			t.Fatalf("partial upload cleanup lost: %+v", result)
		}
	})
}

func TestPrivateWorkerRichSnapshotExceptionsRemainDirect(t *testing.T) {
	for _, operation := range []uint32{14, 15} {
		t.Run(fmt.Sprint(operation), func(t *testing.T) {
			n, _, c, _, _ := sharedSnapshotFixture(t, 1)
			r := &n.objects.records[c.record]
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f := &sharedCommandFaultTransport{}
			f.afterRun = func() { cancel(); f.receipt.Serial = 0; f.receipt.Generation = 0; f.receipt.Value = 2 }
			err := n.runSharedSnapshotCommand(ctx, r, sharedCommandWire{Operation: operation}, f)
			want := "unsupported snapshot operation"
			if operation == 15 {
				want = "ticket receipt incompatible with candidate phase"
			}
			if err == nil || err.Error() != want || errors.Is(err, context.Canceled) {
				t.Fatal("existing direct rich exception became joined")
			}
		})
	}
}

var privateWorkerResultSink workerResult

func TestPrivateWorkerOutputRepresentationDoesNotAllocate(t *testing.T) {
	hostile := privateHostileError{t: t}
	if got := testing.AllocsPerRun(100, func() {
		a := workerPrivate.failure(workerPins, workerOpaque, hostile)
		b := workerPrivate.failure(workerSlotSource, workerRetainedOwnership, nil)
		privateWorkerResultSink = workerResult{primary: a.diagnostic, cleanup: b.diagnostic, cleanupAttempted: true}
	}); got != 0 {
		t.Fatalf("scalar result construction allocated: %v", got)
	}
	// This is only output representation, NOT a bound on whole worker/provider work.
}

func TestPrivateWorkerActualStageCancellationMatrix(t *testing.T) {
	for _, op := range []uint32{8, 9, 10} {
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/deadline=%v", op, deadline), func(t *testing.T) {
				n, _, c, intent, f := sharedSnapshotFixture(t, 2)
				var ctx context.Context
				var trigger func()
				wantIdentity := error(context.Canceled)
				if deadline {
					d := &privateDeadlineContext{Context: t.Context(), done: make(chan struct{})}
					ctx = d
					trigger = func() { close(d.done) }
					wantIdentity = context.DeadlineExceeded
				} else {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(t.Context())
					defer cancel()
					trigger = cancel
				}
				f.afterRun = func() {
					if f.command.Operation == op {
						trigger()
					}
				}
				before := len(f.commands)
				result := c.prepareSnapshotPrivate(ctx, intent, f)
				if !result.cleanupAttempted || result.cleanup.failed() || !result.primary.command.hasIdentity(wantIdentity) || n.objects.records[c.record].live || n.objects.retainedBytes != 0 || n.objects.scopes[0].nextSerial != 1 {
					t.Fatalf("completed canceled state lost: %+v", result)
				}
				releases := 0
				for _, command := range f.commands[before:] {
					if command.Operation == 12 {
						releases++
					}
				}
				want := 0
				if op == 9 {
					want = 1
				}
				if op == 10 {
					want = 2
				}
				if releases != want {
					t.Fatalf("released %d tickets, want %d", releases, want)
				}
			})
		}
	}
}
