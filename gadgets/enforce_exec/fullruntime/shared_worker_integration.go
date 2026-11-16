// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

type sharedWorkerBudget struct{ remaining uint64 }

func (b *sharedWorkerBudget) consume(debit uint64) bool {
	if debit > b.remaining {
		return false
	}
	b.remaining -= debit
	return true
}

// No authority is inferred from this fact. The checked lease remains its owner.
func checkedSharedContainerName(lease BindingLease) (string, bool) {
	source, ok := lease.(interface{ SharedContainerName() (string, error) })
	if !ok {
		return "", false
	}
	name, err := source.SharedContainerName()
	if err != nil || len(name) == 0 || len(name) > fullpolicy.MaxStringBytes || !utf8.ValidString(name) || strings.IndexByte(name, 0) >= 0 {
		return "", false
	}
	return name, true
}

// The production outer remains unavailable until genuine producing evidence
// exists. No positive H is invented to execute the numerical inner engine.
func (s *BindingSession) prepareSharedWorker(ctx context.Context, policies []fullpolicy.Policy) (sharedObjectCandidate, workerResult, error) {
	var candidate sharedObjectCandidate
	unavailable := workerResult{primary: workerDiagnostic{site: workerBegin, reason: workerUnavailable}}
	if len(policies) == 0 || len(policies) > fullpolicy.MaxPolicies {
		return candidate, workerResult{primary: workerDiagnostic{site: workerObjectCount, reason: workerInvalidCount}}, nil
	}
	if ctx.Err() != nil || s == nil || s.node == nil || s.account == nil {
		return candidate, unavailable, nil
	}
	n := s.node
	n.mu.Lock()
	d, ok := decodeSharedWorkerDescriptor()
	limit := n.config.Profile.CompileBytes
	if !ok || d.bootstrap > limit || d.tail > limit-d.bootstrap {
		n.mu.Unlock()
		return candidate, unavailable, nil
	}
	budget := sharedWorkerBudget{remaining: limit - d.bootstrap - d.tail}
	op, finish, err := n.beginSharedObjectOperationLocked(ctx)
	n.mu.Unlock()
	if err != nil {
		return candidate, workerResult{primary: workerPrivate.failure(workerBegin, workerOpaque, err).diagnostic}, nil
	}
	defer finish()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.account.mu.Lock()
	defer s.account.mu.Unlock()
	return s.prepareSharedWorkerLocked(op, policies, nil, &budget)
}

// Same actual compiler/upload/stage engines, one registered operation and one
// session/account lock scope. Union proposal remains local; stage copies only
// fixed metadata and retains original authored objects through existing owners.
func (s *BindingSession) prepareSharedWorkerLocked(ctx context.Context, policies []fullpolicy.Policy, transport sharedCommandTransport, budget *sharedWorkerBudget) (sharedObjectCandidate, workerResult, error) {
	var candidate sharedObjectCandidate
	fail := func(site workerSite, reason workerReason) (sharedObjectCandidate, workerResult, error) {
		return candidate, workerResult{primary: workerDiagnostic{site: site, reason: reason}}, nil
	}
	if len(policies) == 0 || len(policies) > fullpolicy.MaxPolicies {
		return fail(workerObjectCount, workerInvalidCount)
	}
	n, a := s.node, s.account
	r := a.registration
	if s.removed || !a.native.reserved || r.Sequence == 0 || r.Operation != sharedBindingOpen ||
		r.NodeCookie != n.host.control.config.NodeCookie || r.Status != 0 ||
		r.Generation != 0 || r.Serial != 0 || r.Value != 0 || r.Reserved != 0 ||
		int(a.native.slot) >= len(n.objects.scopes) {
		return fail(workerBinding, workerUnavailable)
	}
	scope := &n.objects.scopes[a.native.slot]
	if scope.generation != 0 || scope.nextSerial >= math.MaxUint64-1 {
		return fail(workerSnapshotScope, workerScopeMismatch)
	}
	// A serial records preparation history, not accepted authority. Retry only
	// after both candidate records have been reclaimed; never overwrite retained
	// ownership from a successful preparation or an incomplete rollback.
	first := int(a.native.slot) * 2
	for i := first; i < first+2; i++ {
		if n.objects.records[i].live {
			return fail(workerSnapshotUnused, workerAlreadyAttempted)
		}
	}
	// First pin check is performed inside the shared object engine.
	var step workerStep
	var compilerOnly error
	candidate, step, compilerOnly = s.prepareSharedObjectsLocked(ctx, policies, transport, workerPrivate, budget)
	if step.failed() || compilerOnly != nil {
		return candidate, workerResult{primary: step.diagnostic}, compilerOnly
	}
	container, ok := checkedSharedContainerName(a.pins.lease)
	if !ok {
		return fail(workerSnapshotMetadata, workerMetadataInvalid)
	}
	record := &n.objects.records[candidate.record]
	var refs [fullpolicy.MaxPolicies]fullpolicy.SharedPolicyRef
	for i := uint32(0); i < record.count; i++ {
		// Fresh scope only: proposed epochs, not accepted historical state.
		refs[i] = fullpolicy.SharedPolicyRef{Object: record.source[i], RootEpoch: scope.generation + 1}
	}
	proposal, debit, err := fullpolicy.NewSharedSnapshotLimited(r.Sequence, scope.generation+1, container, refs[:record.count], budget.remaining)
	if !budget.consume(debit) {
		return fail(workerCompile, workerRetainedOwnership)
	}
	if err != nil {
		return candidate, workerResult{primary: workerDiagnostic{site: workerCompile, reason: workerCompiler}}, err
	}
	intent := sharedSnapshotIntent{candidate: candidate, account: a, proposal: proposal}
	// The shared stage engine performs the second pin check. It neither begins
	// another operation nor reacquires account.mu.
	result, _ := candidate.prepareSnapshotLocked(ctx, &intent, transport, workerPrivate)
	return candidate, result, nil
}
