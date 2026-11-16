// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"math"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

type sharedNamedTestLease struct {
	BindingLease
	name string
}

func (l sharedNamedTestLease) SharedContainerName() (string, error) { return l.name, nil }

func runSharedIntegratedTest(t *testing.T, s *BindingSession, policies []fullpolicy.Policy, remaining uint64, f sharedCommandTransport) (sharedObjectCandidate, workerResult, uint64, error) {
	t.Helper()
	ctx, finish, err := s.node.beginSharedObjectOperation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.account.mu.Lock()
	defer s.account.mu.Unlock()
	budget := sharedWorkerBudget{remaining: remaining}
	c, r, e := s.prepareSharedWorkerLocked(ctx, policies, f, &budget)
	return c, r, budget.remaining, e
}

func TestSharedIntegratedOuterUnavailableBeforeAllocation(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	if a := testing.AllocsPerRun(10, func() {
		c, r, e := s.prepareSharedWorker(context.Background(), []fullpolicy.Policy{{ID: "test"}})
		if c.node != nil || !r.failed() || e != nil {
			panic("unexpected admission")
		}
	}); a != 0 {
		t.Fatalf("unavailable outer allocated: %v", a)
	}
	if n.objects.operation.done != nil {
		t.Fatal("registered unavailable operation")
	}
}

func TestSharedIntegratedNumericalObjectsUnionStage(t *testing.T) {
	p := sharedRegistryPolicy()
	object, d, e := fullpolicy.CompileSharedPolicyLimited(p, math.MaxUint64)
	if e != nil {
		t.Fatal(e)
	}
	_, u, e := fullpolicy.NewSharedSnapshotLimited(1, 1, "app", []fullpolicy.SharedPolicyRef{{Object: object, RootEpoch: 1}}, math.MaxUint64)
	if e != nil {
		t.Fatal(e)
	}
	for _, short := range []uint64{0, 1} {
		n, s, _ := sharedRegistryFixture(t)
		s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: "app"}
		f := &sharedSnapshotTransport{refusePin: -1}
		c, r, left, e := runSharedIntegratedTest(t, s, []fullpolicy.Policy{p}, d+u-short, f)
		if short == 0 {
			if e != nil || r.failed() || left != 0 || n.objects.records[c.record].snapshot.phase != 2 {
				t.Fatalf("cohesive result: %+v %v remaining%d", r, e, left)
			}
			if n.objects.scopes[s.account.native.slot].generation != 0 {
				t.Fatal("proposed epoch became accepted")
			}
		} else {
			if e == nil || !r.failed() || left != u-1 {
				t.Fatalf("one-short lost debit: %+v %v %d", r, e, left)
			}
			for _, cmd := range f.commands {
				if cmd.Operation >= 8 {
					t.Fatal("union rejection staged")
				}
			}
		}
		if n.objects.operation.done != nil {
			t.Fatal("operation not joined")
		}
	}
}

func TestSharedIntegratedRejectsHistoryAndMissingFact(t *testing.T) {
	for _, kind := range []string{"generation", "serial", "value", "reserved", "operation", "cookie", "scope-generation", "name"} {
		t.Run(kind, func(t *testing.T) {
			n, s, _ := sharedRegistryFixture(t)
			s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: "app"}
			switch kind {
			case "generation":
				s.account.registration.Generation = 1
			case "serial":
				s.account.registration.Serial = 1
			case "value":
				s.account.registration.Value = 1
			case "reserved":
				s.account.registration.Reserved = 1
			case "operation":
				s.account.registration.Operation = 8
			case "cookie":
				s.account.registration.NodeCookie++
			case "scope-generation":
				n.objects.scopes[s.account.native.slot].generation = 1
			case "name":
				s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: ""}
			}
			f := &sharedSnapshotTransport{refusePin: -1}
			c, r, _, e := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
			if !r.failed() || e != nil || r.cleanupAttempted {
				t.Fatal("invalid fact/history admitted")
			}
			if kind != "name" && (len(f.commands) != 0 || c.node != nil) {
				t.Fatal("history rejection allocated candidate/uploaded")
			}
			for _, cmd := range f.commands {
				if cmd.Operation >= 4 {
					t.Fatal("precommand rejection cleaned or staged")
				}
			}
		})
	}
}

func TestSharedIntegratedFailureDebitDedupAndPins(t *testing.T) {
	for _, kind := range []string{"compiler", "dedup", "retained", "pin", "stage"} {
		t.Run(kind, func(t *testing.T) {
			n, s, _ := sharedRegistryFixture(t)
			s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: "app"}
			p := sharedRegistryPolicy()
			policies := []fullpolicy.Policy{p}
			_, d, err := fullpolicy.CompileSharedPolicyLimited(p, math.MaxUint64)
			if err != nil {
				t.Fatal(err)
			}
			var expectedCompiler error
			calls := 0
			s.account.pins.checkTest = func(context.Context) error {
				calls++
				if kind == "pin" && calls == 2 {
					return context.Canceled
				}
				return nil
			}
			switch kind {
			case "compiler":
				bad := p
				bad.ID = "bad"
				bad.Rules = []fullpolicy.Rule{{Name: "bad", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{"/["}}}}
				_, badD, e := fullpolicy.CompileSharedPolicyLimited(bad, math.MaxUint64)
				d += badD
				expectedCompiler = e
				policies = append(policies, bad)
			case "dedup":
				policies = append(policies, p)
				d *= 2
			case "retained":
				n.config.Profile.CandidateBytes = 1
			}
			f := &sharedSnapshotTransport{refusePin: -1}
			if kind == "stage" {
				f.refusePin = 0
			}
			c, r, left, e := runSharedIntegratedTest(t, s, policies, math.MaxUint64, f)
			if !r.failed() {
				t.Fatal("expected bounded failure")
			}
			if math.MaxUint64-left < d {
				t.Fatal("compiler debit refunded")
			}
			if kind == "compiler" && e != expectedCompiler { //nolint:errorlint // Preserve exact compiler static diagnostic identity.
				t.Fatal("compiler static identity lost")
			}
			if (kind == "compiler" || kind == "retained") && math.MaxUint64-left != d {
				t.Fatal("unexpected compiler debit")
			}
			if kind == "stage" {
				if !r.cleanupAttempted || r.cleanup.failed() || n.objects.records[c.record].live {
					t.Fatalf("actual cleanup missing: %+v", r)
				}
			} else if r.cleanupAttempted {
				t.Fatal("precommand rejection cleaned")
			}
			if kind == "pin" && calls != 2 {
				t.Fatal("second pin check missing")
			}
			if kind == "dedup" {
				record := &n.objects.records[c.record]
				if record.source[0] == record.source[1] || record.slots[0] != record.slots[1] || n.objects.retainedBytes == 0 {
					t.Fatal("authored ownership/dedup changed")
				}
			}
		})
	}
}

func TestSharedIntegratedOneRegistrationAndStopJoin(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: "app"}
	entered := make(chan struct{})
	done := make(chan struct{})
	var operationDone <-chan struct{}
	checks := 0
	s.account.pins.checkTest = func(ctx context.Context) error {
		checks++
		n.mu.Lock()
		current := n.objects.operation.done
		n.mu.Unlock()
		if current == nil {
			panic("unregistered inner phase")
		}
		if checks == 1 {
			operationDone = current
			return nil
		}
		if current != operationDone {
			panic("operation restarted before stage")
		}
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	go func() {
		defer close(done)
		ctx, finish, err := n.beginSharedObjectOperation(context.Background())
		if err != nil {
			panic(err)
		}
		defer finish()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.account.mu.Lock()
		defer s.account.mu.Unlock()
		b := sharedWorkerBudget{remaining: math.MaxUint64}
		_, r, e := s.prepareSharedWorkerLocked(ctx, []fullpolicy.Policy{sharedRegistryPolicy()}, &sharedSnapshotTransport{refusePin: -1}, &b)
		if e != nil || !r.failed() || r.cleanupAttempted {
			panic("stop changed precommand ownership")
		}
	}()
	<-entered
	if err := n.cancelAndJoinPreparations(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-done
	if checks != 2 || n.objects.operation.done != nil {
		t.Fatal("stop did not join sole operation")
	}
	select {
	case <-operationDone:
	default:
		t.Fatal("operation completion not published")
	}
}

func TestSharedIntegratedInputAndMissingAccountRefuseWithoutRegistration(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	for _, policies := range [][]fullpolicy.Policy{nil, make([]fullpolicy.Policy, fullpolicy.MaxPolicies+1)} {
		_, r, e := s.prepareSharedWorker(t.Context(), policies)
		if e != nil || r.primary.reason != workerInvalidCount || n.objects.operation.done != nil {
			t.Fatal("count guard after registration")
		}
	}
	s.account = nil
	_, r, e := s.prepareSharedWorker(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()})
	if e != nil || !r.failed() || n.objects.operation.done != nil {
		t.Fatal("missing account admitted")
	}
}

func TestSharedIntegratedTwoObjectsExactCumulativeDebit(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: "app"}
	p, q := sharedRegistryPolicy(), sharedRegistryPolicy()
	q.ID = "second"
	var total uint64
	refs := make([]fullpolicy.SharedPolicyRef, 2)
	for i, policy := range []fullpolicy.Policy{p, q} {
		object, d, err := fullpolicy.CompileSharedPolicyLimited(policy, math.MaxUint64)
		if err != nil {
			t.Fatal(err)
		}
		total += d
		refs[i] = fullpolicy.SharedPolicyRef{Object: object, RootEpoch: 1}
	}
	_, d, err := fullpolicy.NewSharedSnapshotLimited(s.account.registration.Sequence, 1, "app", refs, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	total += d
	c, r, left, e := runSharedIntegratedTest(t, s, []fullpolicy.Policy{p, q}, total, &sharedSnapshotTransport{refusePin: -1})
	if e != nil || r.failed() || left != 0 || n.objects.records[c.record].count != 2 {
		t.Fatalf("cumulative two-object result %+v %v %d", r, e, left)
	}
}

// Preparation serials survive reclaim; they must not permanently prevent a
// generation-zero binding from retrying. This is only the fake Go protocol.
func TestSharedIntegratedCleanPreparationRetry(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(map[bool]string{false: "discard", true: "refusal"}[refused], func(t *testing.T) {
			n, s, _ := sharedRegistryFixture(t)
			s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: "app"}
			f := &sharedSnapshotTransport{refusePin: -1}
			if refused {
				f.refusePin = 0
			}
			c, r, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
			if err != nil || r.failed() != refused {
				t.Fatalf("first attempt: %+v %v", r, err)
			}
			if !refused {
				before := len(f.commands)
				_, blocked, _, e := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
				if e != nil || !blocked.failed() || len(f.commands) != before {
					t.Fatal("retained candidate overwritten")
				}
				if err := c.discard(t.Context(), f); err != nil {
					t.Fatal(err)
				}
			}
			scope := &n.objects.scopes[s.account.native.slot]
			previous := scope.nextSerial
			if previous == 0 || scope.generation != 0 || n.objects.records[c.record].live {
				t.Fatal("first cleanup did not retain only serial history")
			}
			f.refusePin = -1
			next, result, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
			if err != nil || result.failed() || scope.nextSerial != previous+1 || scope.generation != 0 {
				t.Fatalf("retry: %+v %v serial%d", result, err, scope.nextSerial)
			}
			if s.Inspect().Ready {
				t.Fatal("preparation became Ready")
			}
			if err := next.discard(t.Context(), f); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedIntegratedSerialExhaustionBeforeAllocation(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	n.objects.scopes[s.account.native.slot].nextSerial = math.MaxUint64 - 1
	f := &sharedSnapshotTransport{refusePin: -1}
	c, r, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
	if err != nil || !r.failed() || c.node != nil || len(f.commands) != 0 || n.objects.scopes[s.account.native.slot].nextSerial != math.MaxUint64-1 {
		t.Fatal("exhausted serial allocated or wrapped")
	}
}

func TestSharedIntegratedRetryWaitsForFailedDiscardRecovery(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: "app"}
	f := &sharedSnapshotTransport{refusePin: -1}
	c, r, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
	if err != nil || r.failed() {
		t.Fatalf("prepare: %+v %v", r, err)
	}
	f.refuseRelease = true
	if err := c.discard(t.Context(), f); err == nil {
		t.Fatal("failed cleanup hidden")
	}
	before := len(f.commands)
	serial := n.objects.scopes[s.account.native.slot].nextSerial
	_, blocked, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
	if err != nil || !blocked.failed() || len(f.commands) != before || !n.objects.records[c.record].live || n.objects.scopes[s.account.native.slot].nextSerial != serial {
		t.Fatal("retry disturbed retained cleanup")
	}
	f.refuseRelease = false
	if err := c.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	next, result, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
	if err != nil || result.failed() || n.objects.scopes[s.account.native.slot].nextSerial != serial+1 {
		t.Fatalf("recovered retry: %+v %v", result, err)
	}
	if err := next.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
}

func TestSharedIntegratedRetryPreservesNeighborAndBothRecords(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: "app"}
	neighbor, _ := sharedRegistrationSession(t, n, 43)
	if err := neighbor.registerSharedScopeUsing(t.Context(), &sharedRegistrationTransport{}); err != nil {
		t.Fatal(err)
	}
	neighbor.account.pins.lease = sharedNamedTestLease{BindingLease: neighbor.account.pins.lease, name: "neighbor"}
	nf := &sharedSnapshotTransport{refusePin: -1}
	nc, nr, _, err := runSharedIntegratedTest(t, neighbor, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, nf)
	if err != nil || nr.failed() {
		t.Fatalf("neighbor: %+v %v", nr, err)
	}
	saved := n.objects.records[nc.record]
	ns := n.objects.scopes[neighbor.account.native.slot]
	ncommands := len(nf.commands)
	f := &sharedSnapshotTransport{refusePin: -1}
	// The existing object-only coordinator can own either candidate record.
	first, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.prepareSharedObjectsUsing(t.Context(), []fullpolicy.Policy{sharedRegistryPolicy()}, f)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	before := len(f.commands)
	_, r, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
	if err != nil || !r.failed() || len(f.commands) != before {
		t.Fatal("occupied second record was overwritten")
	}
	if err := second.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		c, r, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
		if err != nil || r.failed() {
			t.Fatalf("retry: %+v %v", r, err)
		}
		if err := c.discard(t.Context(), f); err != nil {
			t.Fatal(err)
		}
	}
	if n.objects.records[nc.record] != saved || n.objects.scopes[neighbor.account.native.slot] != ns || len(nf.commands) != ncommands {
		t.Fatal("neighbor ownership or history changed")
	}
	if err := nc.discard(t.Context(), nf); err != nil {
		t.Fatal(err)
	}
	if n.objects.retainedBytes != 0 {
		t.Fatal("retained source leaked")
	}
}

func TestSharedIntegratedLastSerialDoesNotWrap(t *testing.T) {
	n, s, _ := sharedRegistryFixture(t)
	s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: "app"}
	scope := &n.objects.scopes[s.account.native.slot]
	scope.nextSerial = math.MaxUint64 - 2
	f := &sharedSnapshotTransport{refusePin: -1, nextSerial: scope.nextSerial}
	c, r, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
	if err != nil || r.failed() || scope.nextSerial != math.MaxUint64-1 {
		t.Fatalf("last serial refused: %+v %v", r, err)
	}
	if err := c.discard(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	for _, exhausted := range []uint64{math.MaxUint64 - 1, math.MaxUint64} {
		scope.nextSerial = exhausted
		before := len(f.commands)
		_, r, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{sharedRegistryPolicy()}, math.MaxUint64, f)
		if err != nil || !r.failed() || len(f.commands) != before || scope.nextSerial != exhausted || n.objects.retainedBytes != 0 {
			t.Fatal("exhaustion mutated state")
		}
	}
}
