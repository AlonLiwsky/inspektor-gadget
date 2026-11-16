// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
)

// SharedCompilerABI identifies scope-neutral objects, not legacy KernelProgram
// images. Objects retain local Rule.PolicyIndex=0; the shared evaluator must map
// that index through the whole binding snapshot and evaluate one policy union.
const SharedCompilerABI uint32 = 1

// SharedPolicy is immutable compiler-owned content. It is NOT installable as a
// legacy KernelProgram: generation, observed container and root epoch live in
// the binding snapshot. Verdict provenance is separately retained by each caller;
// compiler-owned authored source is private whole-set admission evidence.
type SharedPolicy struct {
	entries []Blob
	digest  [32]byte
	uid     uint64
	// source is compiler-owned immutable admission provenance, not digest input.
	source *Policy
}

func (p *SharedPolicy) Entries() []Blob {
	if p == nil {
		return nil
	}
	return slices.Clone(p.entries)
}

func (p *SharedPolicy) UID() uint64 {
	if p == nil {
		return 0
	}
	return p.uid
}

func (p *SharedPolicy) Digest() [32]byte {
	if p == nil {
		return [32]byte{}
	}
	return p.digest
}

// Equal checks actual canonical content, not hash equality alone.
func (p *SharedPolicy) Equal(q *SharedPolicy) bool {
	return p != nil && q != nil && p.digest == q.digest && slices.Equal(p.entries, q.entries)
}

// CompileSharedPolicy reuses the complete native compiler/validator. Authored
// container predicates remain in the object; only the observed container is
// removed. No scope epoch or image-readiness authority enters this API.
func CompileSharedPolicy(policy Policy) (*SharedPolicy, error) {
	return compileSharedPolicy(policy, richDiagnostics)
}

func compileSharedPolicy(policy Policy, d diagnosticPolicy) (*SharedPolicy, error) {
	return compileSharedPolicyWithWorkspace(policy, d, nil)
}

func compileSharedPolicyWithWorkspace(policy Policy, d diagnosticPolicy, work *compilerWorkspace) (result *SharedPolicy, resultErr error) {
	var entriesOwner *workspaceReservation
	defer func() {
		if entriesOwner != nil {
			if err := entriesOwner.release(); err != nil {
				result = nil
				resultErr = d.join(resultErr, err)
			}
		}
	}()
	// Validate and deep-copy once using the private native preparation backend.
	// Reference matcher objects are not needed for immutable native emission.
	compiled, err := prepareNativePolicies([]Policy{policy}, d)
	if err != nil {
		return nil, d.forward(err)
	}
	owned := compiled.policies[0]
	source := owned.source
	source.Rules = make([]Rule, len(owned.rules))
	for i, rule := range owned.rules {
		source.Rules[i] = rule.source
	}
	p, err := compilePreparedKernelWithWorkspace(compiled, 1, "shared-object", stableHash, d, work, &entriesOwner)
	if err != nil {
		return nil, d.forward(err)
	}
	if err := validateKernelDataWithDiagnostics(p.Entries, p.Rules, identityView{fixed: &p.identities}, work, d.invariant()); err != nil {
		return nil, d.forward(err)
	}
	h := decodeKernelHeader(p.Entries[0])
	k := decodeKernelPolicy(p.Entries[KernelPolicyBase])
	// The compiler emits a dedicated observation cell. It remains zero
	// padding so absolute predicate/instruction references need no relocation.
	p.Entries[h.ContainerRef] = Blob{}
	h.Generation = 0
	h.ContainerRef = 0
	k.RootEpoch = 0
	p.Entries[0] = encodeKernelHeader(h)
	p.Entries[KernelPolicyBase] = encodeKernelPolicy(k)
	hash := sha256.New()
	_, _ = hash.Write([]byte{byte(SharedCompilerABI), 0, 0, 0})
	for i := range p.Entries {
		_, _ = hash.Write(p.Entries[i][:])
	}
	result = newSharedOwnedPolicy(p.Entries, k.UID, source)
	copy(result.digest[:], hash.Sum(nil))
	return result, nil
}

type SharedPolicyRef struct {
	Object    *SharedPolicy
	RootEpoch uint64
}

// SharedSnapshot is a native preparation value, not an activation receipt.
// Accepted epochs must come from the exact scope's trusted retained catalogue.
type SharedSnapshot struct {
	ScopeCookie, Generation uint64
	Container               string
	Policies                []SharedPolicyRef
	execution               *sharedSnapshotExecution
}

func NewSharedSnapshot(scope, generation uint64, container string, refs []SharedPolicyRef) (SharedSnapshot, error) {
	return newSharedSnapshot(scope, generation, container, refs, richDiagnostics)
}

func newSharedSnapshot(scope, generation uint64, container string, refs []SharedPolicyRef, d diagnosticPolicy) (SharedSnapshot, error) {
	return newSharedSnapshotWithWorkspace(scope, generation, container, refs, d, nil, false)
}

func newSharedSnapshotWithWorkspace(scope, generation uint64, container string, refs []SharedPolicyRef, d diagnosticPolicy, work *compilerWorkspace, ownContainer bool) (result SharedSnapshot, resultErr error) {
	var entriesOwner *workspaceReservation
	defer func() {
		if entriesOwner != nil {
			if err := entriesOwner.release(); err != nil {
				result = SharedSnapshot{}
				resultErr = d.join(resultErr, err)
			}
		}
	}()
	if scope == 0 || scope == UnknownRoleEpoch || generation == 0 || generation == UnknownRoleEpoch || len(refs) == 0 || len(refs) > MaxPolicies {
		if d.compact {
			if scope != 0 && scope != UnknownRoleEpoch && generation != 0 && generation != UnknownRoleEpoch && len(refs) > MaxPolicies {
				return SharedSnapshot{}, compactFailure(DiagnosticCapacity, DiagnosticNone)
			}
			return SharedSnapshot{}, d.reject()
		}
		return SharedSnapshot{}, fmt.Errorf("invalid shared snapshot identity/count")
	}
	if err := validateStringWithDiagnostics(container, d); err != nil {
		return SharedSnapshot{}, d.forward(err)
	}
	policies := make([]Policy, len(refs))
	for i, r := range refs {
		if r.Object == nil || r.Object.uid == 0 || r.Object.source == nil || r.RootEpoch == 0 || r.RootEpoch > generation {
			if d.compact {
				if r.Object != nil && (r.Object.uid == 0 || r.Object.source == nil) {
					return SharedSnapshot{}, compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return SharedSnapshot{}, d.reject()
			}
			return SharedSnapshot{}, fmt.Errorf("invalid scoped policy epoch")
		}
		for _, prior := range refs[:i] {
			if prior.Object.uid == r.Object.uid {
				if d.compact {
					return SharedSnapshot{}, d.reject()
				}
				return SharedSnapshot{}, fmt.Errorf("duplicate scoped policy UID")
			}
		}
		policies[i] = *r.Object.source
	}
	// Independently compiled objects are not an admission receipt for their
	// union. Run the SAME native compiler over its owned authored inputs so
	// patterns, matcher code, strings/values and all blob budgets remain global.
	// This also preserves whole-set UID/role validation without reconstructing IR.
	prepared, err := prepareNativePolicies(policies, d)
	if err != nil {
		if d.compact {
			return SharedSnapshot{}, d.forward(err)
		}
		return SharedSnapshot{}, fmt.Errorf("shared policy union: %w", err)
	}
	program, err := compilePreparedKernelWithWorkspace(prepared, generation, container, stableHash, d, work, &entriesOwner)
	if err != nil {
		if d.compact {
			return SharedSnapshot{}, d.forward(err)
		}
		return SharedSnapshot{}, fmt.Errorf("shared policy union: %w", err)
	}
	if err := validateKernelDataWithDiagnostics(program.Entries, program.Rules, identityView{fixed: &program.identities}, work, d.invariant()); err != nil {
		if d.compact {
			return SharedSnapshot{}, d.forward(err)
		}
		return SharedSnapshot{}, fmt.Errorf("shared policy union: %w", err)
	}
	execution, err := sharedExecutionMetadataWithDiagnostics(program.Entries, refs, d.invariant())
	if err != nil {
		return SharedSnapshot{}, d.forward(err)
	}
	if ownContainer {
		container = strings.Clone(container)
	}
	return SharedSnapshot{ScopeCookie: scope, Generation: generation, Container: container, Policies: slices.Clone(refs), execution: execution}, nil
}

// SharedExecutionMetadata is compiler-derived execution/dependency information
// in the snapshot's reference order, not the compiler's sorted UID order. It
// grants no root, accepted-epoch, image-completeness or publication authority.
type SharedExecutionMetadata struct {
	PolicyCount, ExecutionClass, RoleWriters, RequiredKnown uint32
}
type sharedSnapshotExecution struct {
	metadata SharedExecutionMetadata
	objects  [MaxPolicies]*SharedPolicy
}

// ExecutionMetadata returns a copy of the compiler-owned summary. SharedSnapshot
// retains exported preparation fields for its existing API; changing object
// references/order invalidates this summary instead of silently reindexing it.
// A coordinator must still validate scoped epochs/identity at publication.
func (s SharedSnapshot) ExecutionMetadata() (SharedExecutionMetadata, error) {
	if s.execution == nil || len(s.Policies) != int(s.execution.metadata.PolicyCount) {
		return SharedExecutionMetadata{}, fmt.Errorf("snapshot has no matching compiled execution metadata")
	}
	for i, ref := range s.Policies {
		if ref.Object != s.execution.objects[i] {
			return SharedExecutionMetadata{}, fmt.Errorf("snapshot policy references changed after compilation")
		}
	}
	return s.execution.metadata, nil
}

// Reuse the already validated WHOLE original authored union. Equal physical
// objects can have different authored admission provenance, so deduplication
// must never replace refs before NewSharedSnapshot reaches this boundary.
func sharedExecutionMetadata(entries []Blob, refs []SharedPolicyRef) (*sharedSnapshotExecution, error) {
	return sharedExecutionMetadataWithDiagnostics(entries, refs, richDiagnostics)
}

func sharedExecutionMetadataWithDiagnostics(entries []Blob, refs []SharedPolicyRef, d diagnosticPolicy) (*sharedSnapshotExecution, error) {
	h := decodeKernelHeader(entries[0])
	result := &sharedSnapshotExecution{metadata: SharedExecutionMetadata{PolicyCount: uint32(len(refs)), ExecutionClass: 1}}
	var positions [MaxPolicies]uint32
	var roles, enforcedRoles, writers, enforcedWriters, roleWriters, roleDenies uint32
	var defaultDeny, enforcedDefaultDeny bool
	for i, ref := range refs {
		result.objects[i] = ref.Object
	}
	for i := uint32(0); i < h.PolicyCount; i++ {
		p := decodeKernelPolicy(entries[KernelPolicyBase+i])
		found := false
		for j, ref := range refs {
			if ref.Object.UID() == p.UID {
				positions[i] = uint32(j)
				found = true
				break
			}
		}
		if !found {
			if d.compact {
				return nil, compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return nil, fmt.Errorf("compiled union UID missing from shared references")
		}
		result.metadata.ExecutionClass = max(result.metadata.ExecutionClass, p.Mode)
		if p.Default == 2 {
			defaultDeny = true
			if p.Mode == 2 {
				enforcedDefaultDeny = true
			}
		}
	}
	for i := uint32(0); i < h.RuleCount; i++ {
		r := decodeKernelRule(entries[KernelRuleBase+i])
		bit := uint32(1) << positions[r.PolicyIndex]
		result.metadata.ExecutionClass = max(result.metadata.ExecutionClass, r.Mode)
		if r.ActorRole.Count != 0 {
			roles |= bit
			if r.Mode == 2 {
				enforcedRoles |= bit
			}
			if r.Deny != 0 {
				roleDenies |= bit
			}
			if r.SetRole != 0 {
				roleWriters |= bit
			}
		}
		if r.SetRole != 0 {
			writers |= bit
			if r.Mode == 2 {
				enforcedWriters |= bit
			}
		}
	}
	result.metadata.RoleWriters = writers
	required := enforcedRoles
	if enforcedDefaultDeny {
		required |= roles
	}
	// Same monotone eight-policy closure as eo_required_known_mask. Audit-only
	// dependencies are required only when they can affect enforced authority.
	for round := 0; round <= MaxPolicies; round++ {
		demand := enforcedWriters | (required & writers)
		next := required | (demand & roleWriters)
		if demand != 0 {
			next |= roleDenies
			if defaultDeny {
				next |= roles
			}
		}
		if next == required {
			result.metadata.RequiredKnown = required
			return result, nil
		}
		required = next
	}
	if d.compact {
		return nil, compactFailure(DiagnosticInternal, DiagnosticNone)
	}
	return nil, fmt.Errorf("shared role dependency closure did not converge")
}

// CompileSharedPolicyCompact uses the same compiler with scalar-only failure
// diagnostics. It does not guarantee memory admission or a bounded allocation
// lifetime; callers still own runtime fault handling and last-good state.
func CompileSharedPolicyCompact(policy Policy) (*SharedPolicy, error) {
	return compileSharedPolicy(policy, compactDiagnosticsPolicy)
}

// NewSharedSnapshotCompact validates the original authored policy union using
// compact diagnostics. This is not an activation receipt or a memory guarantee.
func NewSharedSnapshotCompact(scope, generation uint64, container string, refs []SharedPolicyRef) (SharedSnapshot, error) {
	return newSharedSnapshot(scope, generation, container, refs, compactDiagnosticsPolicy)
}

func prepareNativePolicies(policies []Policy, d diagnosticPolicy) (*preparedProgram[nativePath], error) {
	if d.compact {
		return preparePoliciesWithDiagnostics(policies, nativeGlobCompact, d)
	}
	return preparePoliciesWithDiagnostics(policies, nativeGlob, d)
}
