// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

// CompileSharedPolicyLimited executes the numerical shared-object model.
// Debit is cumulative on admitted success and failure; it is not refunded by
// deduplication or local cleanup. This API confers no runtime applicability,
// source/build qualification, root provenance or activation authority.
func CompileSharedPolicyLimited(policy Policy, remaining uint64) (*SharedPolicy, uint64, error) {
	return compileSharedPolicyModel(policy, remaining)
}

// NewSharedSnapshotLimited executes the whole-union numerical model, rather
// than adding object debits. Its output owns container/ref/metadata backing.
// Numerical admission is not accepted-epoch or runtime activation authority.
func NewSharedSnapshotLimited(scope, generation uint64, container string, refs []SharedPolicyRef, remaining uint64) (SharedSnapshot, uint64, error) {
	return newSharedSnapshotModel(scope, generation, container, refs, remaining)
}
