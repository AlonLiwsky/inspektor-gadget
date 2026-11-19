// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import "fmt"

// Fixed tables borrow immutable source/expression strings during compilation.
// They neither clone backing strings nor grant reservation/lifetime authority.
// Slots never resize; capacities come from validated original call occurrences,
// not distinct keys or the validator's independent occupied-identity limit.
// The private model core covers backing allocations in its bulk reservation;
// unrestricted nil-workspace paths do not. Neither path establishes a qualified
// production runtime budget.
type identitySlot struct {
	ID   uint64
	Name string
}
type fixedIdentities struct {
	slots []identitySlot
	count int
}

func (t *fixedIdentities) lookup(id uint64) (string, bool) {
	if id == 0 || len(t.slots) == 0 {
		return "", false
	}
	start := int(id % uint64(len(t.slots)))
	for probe := 0; probe < len(t.slots); probe++ {
		slot := t.slots[(start+probe)%len(t.slots)]
		if slot.ID == 0 {
			return "", false
		}
		if slot.ID == id {
			return slot.Name, true
		}
	}
	return "", false
}

func (t *fixedIdentities) insert(id uint64, name string) error {
	return t.insertWithDiagnostics(id, name, richDiagnostics)
}

func (t *fixedIdentities) insertWithDiagnostics(id uint64, name string, d diagnosticPolicy) error {
	if id == 0 {
		if d.compact {
			return d.reject()
		}
		return fmt.Errorf("stable identity hash is reserved zero")
	}
	if len(t.slots) > 0 {
		start := int(id % uint64(len(t.slots)))
		for probe := 0; probe < len(t.slots); probe++ {
			slot := &t.slots[(start+probe)%len(t.slots)]
			if slot.ID == id {
				if slot.Name != name {
					if d.compact {
						return d.reject()
					}
					return fmt.Errorf("stable identity hash collision between %q and %q", slot.Name, name)
				}
				return nil
			}
			if slot.ID == 0 {
				*slot = identitySlot{ID: id, Name: name}
				t.count++
				return nil
			}
		}
	}
	if d.compact {
		return compactFailure(DiagnosticInternal, DiagnosticNone)
	}
	return fmt.Errorf("fixed identity capacity exceeded")
}

type expressionSlot struct {
	expression             string
	codeBase, start, count uint32
	occupied               bool
}
type fixedExpressions struct{ slots []expressionSlot }

func expressionHash(expression string) uint64 {
	// FNV-1a, deterministic without temporary byte conversion or allocation.
	hash := uint64(14695981039346656037)
	for i := 0; i < len(expression); i++ {
		hash ^= uint64(expression[i])
		hash *= 1099511628211
	}
	return hash
}

func (t *fixedExpressions) lookup(expression string) (KernelPattern, bool) {
	if len(t.slots) == 0 {
		return KernelPattern{}, false
	}
	start := int(expressionHash(expression) % uint64(len(t.slots)))
	for probe := 0; probe < len(t.slots); probe++ {
		slot := t.slots[(start+probe)%len(t.slots)]
		if !slot.occupied {
			return KernelPattern{}, false
		}
		if slot.expression == expression {
			return KernelPattern{CodeBase: slot.codeBase, Start: slot.start, Count: slot.count}, true
		}
	}
	return KernelPattern{}, false
}

func (t *fixedExpressions) insert(expression string, p KernelPattern) error {
	return t.insertWithDiagnostics(expression, p, richDiagnostics)
}

func (t *fixedExpressions) insertWithDiagnostics(expression string, p KernelPattern, d diagnosticPolicy) error {
	if len(t.slots) > 0 {
		start := int(expressionHash(expression) % uint64(len(t.slots)))
		for probe := 0; probe < len(t.slots); probe++ {
			slot := &t.slots[(start+probe)%len(t.slots)]
			if !slot.occupied || slot.expression == expression {
				*slot = expressionSlot{expression: expression, codeBase: p.CodeBase, start: p.Start, count: p.Count, occupied: true}
				return nil
			}
		}
	}
	if d.compact {
		return compactFailure(DiagnosticInternal, DiagnosticNone)
	}
	return fmt.Errorf("fixed expression capacity exceeded")
}

func preparedLookupCapacities(program *preparedProgram[nativePath]) (identities, expressions int) {
	identities = 2 * len(program.policies)
	for _, p := range program.policies {
		for _, r := range p.rules {
			identities += len(r.source.Actor.Role)
			if r.source.Target.SetRole != "" {
				identities++
			}
			expressions += len(r.actor) + len(r.target) + len(r.ancestor)
		}
	}
	return
}

type emittedKernel struct {
	Entries    []Blob
	Rules      []RuleMetadata
	identities fixedIdentities
}

// legacy is the ONLY map materialization boundary. Shared object/union paths
// retain private tables through validation and never need this compatibility map.
func (p *emittedKernel) legacy() *KernelProgram {
	identities := make(map[uint64]string, p.identities.count)
	for _, slot := range p.identities.slots {
		if slot.ID != 0 {
			identities[slot.ID] = slot.Name
		}
	}
	return &KernelProgram{Entries: p.Entries, Rules: p.Rules, Identities: identities}
}

func (p *emittedKernel) validate() error {
	return validateKernelData(p.Entries, p.Rules, identityView{fixed: &p.identities}, nil)
}

// A nonnil fixed pointer is the concrete tag; otherwise preserve legacy map
// lookup/iteration semantics (including its original first-error behavior).
type identityView struct {
	legacy map[uint64]string
	fixed  *fixedIdentities
}

func (v identityView) lookup(id uint64) (string, bool) {
	if v.fixed != nil {
		return v.fixed.lookup(id)
	}
	value, ok := v.legacy[id]
	return value, ok
}

func (v identityView) validate() error {
	return v.validateWithDiagnostics(richDiagnostics)
}

func (v identityView) validateWithDiagnostics(d diagnosticPolicy) error {
	count := len(v.legacy)
	if v.fixed != nil {
		count = v.fixed.count
	}
	if count == 0 || count > MaxKernelEntries+2*MaxPolicies {
		if d.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("invalid identity registry budget")
	}
	check := func(hash uint64, name string) error {
		if err := validateStringWithDiagnostics(name, d.invariant()); err != nil {
			return err
		}
		if hash == 0 || stableHash(name) != hash {
			if d.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("invalid stable identity hash")
		}
		return nil
	}
	if v.fixed == nil {
		for hash, name := range v.legacy {
			if err := check(hash, name); err != nil {
				return err
			}
		}
		return nil
	}
	occupied := 0
	for _, slot := range v.fixed.slots {
		if slot.ID == 0 {
			if slot.Name != "" {
				if d.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("invalid stable identity hash")
			}
			continue
		}
		occupied++
		if err := check(slot.ID, slot.Name); err != nil {
			return err
		}
	}
	if occupied != count {
		if d.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("invalid identity registry budget")
	}
	return nil
}
