// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import "unsafe"

// Existing objects remain under their existing owners. This bounded stack copy
// borrows original authored sources solely for the preallocation scan; it neither
// clones their backing nor substitutes expression/digest representatives.
func sharedSnapshotModelDebit(container string, refs []SharedPolicyRef) (sharedPolicyModel, error) {
	var policies [MaxPolicies]Policy
	count := min(len(refs), MaxPolicies)
	for i, ref := range refs[:count] {
		if ref.Object != nil && ref.Object.source != nil {
			policies[i] = *ref.Object.source
		}
	}
	return nativeModelDebit(policies[:count], false, container)
}

// Private numerical union core, NOT qualified runtime or activation authority.
// One original whole-union scan and one workspace cover all policies together.
// An admitted failure returns its full debit and a zero snapshot; no refund is
// inferred from failed prefixes, object deduplication or local token cleanup.
func newSharedSnapshotModel(scope, generation uint64, container string, refs []SharedPolicyRef, remaining uint64) (snapshot SharedSnapshot, debit uint64, err error) {
	model, modelErr := sharedSnapshotModelDebit(container, refs)
	if modelErr != nil {
		return SharedSnapshot{}, 0, compactFailure(DiagnosticInternal, DiagnosticNone)
	}
	if model.total > remaining {
		return SharedSnapshot{}, 0, compactFailure(DiagnosticCapacity, DiagnosticNone)
	}
	debit = model.total
	work := compilerWorkspace{limit: model.total - uint64(unsafe.Sizeof(compilerWorkspace{}))}
	bulk, reserveErr := work.reserve(model.bulk)
	if reserveErr != nil {
		return SharedSnapshot{}, debit, compactDiagnosticsPolicy.forward(reserveErr)
	}
	defer func() {
		if releaseErr := bulk.release(); releaseErr != nil {
			snapshot = SharedSnapshot{}
			err = compactDiagnosticsPolicy.join(err, releaseErr)
		}
		if work.used != work.metadata {
			snapshot = SharedSnapshot{}
			err = compactDiagnosticsPolicy.join(err, errWorkspaceOwner)
		}
	}()
	snapshot, err = newSharedSnapshotWithWorkspace(scope, generation, container, refs, compactDiagnosticsPolicy, &work, true)
	return snapshot, debit, err
}
