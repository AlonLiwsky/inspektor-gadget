// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Facts are authoritative inputs for the pure reference evaluator. Nil pointers
// mean unknown, not false. A kernel implementation must acquire the same facts at
// the pre-exec hook; syscall-entry userspace snapshots are not equivalent.
type Facts struct {
	ActorPath         string
	ActorFromImage    *bool
	Ancestors         []string          // immediate parent first; completeness checked against depth
	AncestorsComplete bool              // true when traversal reached its genuine root
	Roles             map[string]string // policy ID -> inherited role; absence means root bootstrap
	// RoleBootstrap is proof from the backend that this is the policy root task;
	// it must not be used to hide map loss or missing inherited state.
	RoleBootstrap   bool
	EffectiveUID    *uint32
	Container       string
	TargetPath      string
	TargetFromImage *bool
	FSType          string
	// FSType and FileKinds contain known-positive simultaneous classes.
	// Missing positives do not prove false. FileKindsKnown explicitly lists
	// classes with authoritative true/false observations. Positives are known.
	FileKinds      []string
	FileKindsKnown []string
	Argv           []string
	ArgvComplete   bool
	StdinIsPipe    *bool
}
type Match struct {
	PolicyID, Revision, Rule, Origin string
	Action                           Action
	Mode                             Mode
}
type Decision struct {
	Action  Action // semantic deny, including audit-only denies
	Mode    Mode   // strongest denying mode, or audit for an allowed decision
	Block   bool
	Matches []Match
	// Role updates are policy-local and must be committed only on successful exec.
	SetRoles map[string]string
	// AuditUnknown records diagnostic uncertainty without making it a denial.
	AuditUnknown   map[string]bool
	UncertainRoles map[string]bool
	RoleWrites     map[string]bool
	// SuppressRoles also cancels proposals from earlier checks in this exec.
	SuppressRoles     bool
	UncertainFallback bool // Audit fallback deny may be suppressed by an unknown allow.
}

// ReferenceMetadata is source-only diagnostic/provenance output. It is not
// encoded in the current native verdict ABI.
type ReferenceMetadata struct {
	DefaultOrigins     []string
	RuleOrigins        []RuleOriginMetadata // One per matched rule, including omitted origins.
	DisabledExceptions map[string]bool      // keyed by policy ID
}

type RuleOriginMetadata struct {
	PolicyID, Rule string
	Origins        []string // [] omitted, [""] explicitly empty, [label] nonempty.
}

// executionClass is conservative declared capability, not a partial decision.
func (p *Program) executionClass() Mode {
	for _, policy := range p.policies {
		if policy.source.Mode == Enforce {
			return Enforce
		}
		if policy.source.DefaultMode == Enforce {
			return Enforce
		}
		for _, rule := range policy.rules {
			if rule.source.Mode == Enforce {
				return Enforce
			}
		}
	}
	return Audit
}

// Evaluate is a reference oracle for kernel parity tests, not a userspace
// enforcement fallback. Audit-local unknowns are diagnostics, never known matches;
// enforced or shared uncertainty fails evaluation.
func (p *Program) Evaluate(f Facts) (Decision, error) {
	return p.evaluate(f, nil)
}

func (p *Program) EvaluateWithMetadata(f Facts) (Decision, ReferenceMetadata, error) {
	m := ReferenceMetadata{DefaultOrigins: []string{}, RuleOrigins: []RuleOriginMetadata{}, DisabledExceptions: map[string]bool{}}
	d, err := p.evaluate(f, &m)
	return d, m, err
}

func (p *Program) evaluate(f Facts, metadata *ReferenceMetadata) (Decision, error) {
	for _, v := range append([]string{f.ActorPath, f.TargetPath}, f.Ancestors...) {
		if len(v) > MaxStringBytes || strings.ContainsRune(v, 0) || !utf8.ValidString(v) {
			return Decision{Block: p.executionClass() == Enforce}, fmt.Errorf("path observation invalid or exceeds %d bytes", MaxStringBytes)
		}
	}
	d := Decision{Action: Allow, Mode: Audit, SetRoles: map[string]string{}, AuditUnknown: map[string]bool{}, UncertainRoles: map[string]bool{}, RoleWrites: map[string]bool{}}
	var evaluationError error
	uncertainDeny, uncertainAllow := false, false
	matched := false
	allowMode, denyMode := Audit, Audit
	for _, policy := range p.policies {
		ps := policy.source
		role := f.Roles[ps.ID]
		if role == "" && f.RoleBootstrap {
			role = ps.RootRole
		}
		roles := map[string]bool{}
		enforcedGrant := false
		for _, rule := range policy.rules {
			r := rule.source
			mode := r.Mode
			if mode == "" {
				mode = ps.Mode
			}
			ok, err := ruleMatches(rule, f, role)
			if err != nil {
				if mode == Audit {
					d.AuditUnknown[ps.ID] = true
					if r.Target.SetRole != "" {
						d.UncertainRoles[ps.ID] = true
						d.RoleWrites[ps.ID] = true
					}
					uncertainDeny = uncertainDeny || r.Action == Deny
					uncertainAllow = uncertainAllow || r.Action == Allow
				} else {
					evaluationError = errors.Join(evaluationError, fmt.Errorf("policy %s rule %s: %w", ps.ID, r.Name, err))
				}
				continue
			}
			if !ok {
				continue
			}
			suppressed := false
			for _, ex := range rule.exceptions {
				exMatch, exErr := ruleMatches(ex, f, role)
				if exErr != nil {
					if metadata != nil {
						metadata.DisabledExceptions[ps.ID] = true
					}
					continue // An unknown exception never lifts a known deny.
				}
				if exMatch {
					suppressed = true
					break
				}
			}
			if suppressed {
				continue
			}
			matched = true
			d.Matches = append(d.Matches, Match{PolicyID: ps.ID, Revision: ps.Revision, Rule: r.Name, Origin: r.Origin, Action: r.Action, Mode: mode})
			if metadata != nil {
				metadata.RuleOrigins = append(metadata.RuleOrigins, RuleOriginMetadata{PolicyID: ps.ID, Rule: r.Name, Origins: originList(r.Origin, r.OriginPresent)})
			}
			if r.Action == Deny {
				d.Action = Deny
				if mode == Enforce {
					denyMode = Enforce
					d.Block = true
				}
			} else {
				if mode == Enforce {
					allowMode = Enforce
				}
				if r.Target.SetRole != "" {
					roles[r.Target.SetRole] = true
					d.RoleWrites[ps.ID] = true
					enforcedGrant = enforcedGrant || mode == Enforce
				}
			}
		}
		if len(roles) > 1 {
			if enforcedGrant {
				evaluationError = errors.Join(evaluationError, fmt.Errorf("policy %s: overlapping allows assign conflicting roles", ps.ID))
			} else {
				d.AuditUnknown[ps.ID] = true
				d.UncertainRoles[ps.ID] = true
			}
		}
		for role := range roles {
			d.SetRoles[ps.ID] = role
		}
	}
	// Defaults merge strictly, but are consulted only when the entire merged rule
	// union has no match. A default deny in one policy cannot shadow another's allow.
	if !matched {
		winner := Allow
		for _, policy := range p.policies {
			if policy.source.Default == Deny {
				winner = Deny
				break
			}
		}
		origins := map[string]bool{}
		for _, policy := range p.policies {
			ps := policy.source
			if ps.Default != winner {
				continue
			}
			if ps.DefaultOriginPresent || ps.DefaultOrigin != "" {
				origins[ps.DefaultOrigin] = true
			}
			mode := ps.DefaultMode
			if mode == "" {
				mode = ps.Mode
			}
			if winner == Deny {
				d.Action = Deny
				if mode == Enforce {
					denyMode = Enforce
					d.Block = true
				}
				d.Matches = append(d.Matches, Match{PolicyID: ps.ID, Revision: ps.Revision, Action: Deny, Mode: mode})
			} else if mode == Enforce {
				allowMode = Enforce
			}
		}
		if metadata != nil {
			for origin := range origins {
				metadata.DefaultOrigins = append(metadata.DefaultOrigins, origin)
			}
			slices.Sort(metadata.DefaultOrigins)
		}
	}
	if !matched && uncertainAllow && d.Action == Deny && denyMode == Audit {
		d.UncertainFallback = true
		uncertainDeny = true
	}
	if d.Action == Deny {
		d.Mode = denyMode
		clear(d.SetRoles)
	} else {
		d.Mode = allowMode
	}
	slices.SortFunc(d.Matches, func(a, b Match) int {
		if n := strings.Compare(a.PolicyID, b.PolicyID); n != 0 {
			return n
		}
		return strings.Compare(a.Rule, b.Rule)
	})
	if metadata != nil {
		slices.SortFunc(metadata.RuleOrigins, func(a, b RuleOriginMetadata) int {
			if n := strings.Compare(a.PolicyID, b.PolicyID); n != 0 {
				return n
			}
			return strings.Compare(a.Rule, b.Rule)
		})
	}
	d.SuppressRoles = uncertainDeny || d.Action == Deny || evaluationError != nil
	if d.SuppressRoles {
		clear(d.SetRoles)
	}
	if uncertainDeny {
		for uid := range d.RoleWrites {
			d.UncertainRoles[uid] = true
		}
	}
	for uid := range d.UncertainRoles {
		delete(d.SetRoles, uid)
	}
	if evaluationError != nil {
		d.Block = p.executionClass() == Enforce
	}
	return d, evaluationError
}

func originList(value string, present bool) []string {
	if !present && value == "" {
		return []string{}
	}
	return []string{value}
}

func ruleMatches(r compiledRule, f Facts, role string) (bool, error) {
	a, t := r.source.Actor, r.source.Target
	if len(r.actor) > 0 {
		if f.ActorPath == "" {
			return false, fmt.Errorf("actor executable unavailable")
		}
		if !pathMatches(r.actor, f.ActorPath) {
			return false, nil
		}
	}
	if len(r.target) > 0 {
		if f.TargetPath == "" {
			return false, fmt.Errorf("target executable unavailable")
		}
		if !pathMatches(r.target, f.TargetPath) {
			return false, nil
		}
	}
	if len(a.Role) > 0 {
		if role == "" {
			return false, fmt.Errorf("inherited role unavailable")
		}
		if !slices.Contains(a.Role, role) {
			return false, nil
		}
	}
	if len(a.Container) > 0 {
		if f.Container == "" {
			return false, fmt.Errorf("container name unavailable")
		}
		if !slices.Contains(a.Container, f.Container) {
			return false, nil
		}
	}
	if len(a.UID) > 0 {
		if f.EffectiveUID == nil {
			return false, fmt.Errorf("effective UID unavailable")
		}
		if !slices.Contains(a.UID, int64(*f.EffectiveUID)) {
			return false, nil
		}
	}
	if a.FromImage != nil {
		if f.ActorFromImage == nil {
			return false, fmt.Errorf("actor image provenance unavailable")
		}
		if *a.FromImage != *f.ActorFromImage {
			return false, nil
		}
	}
	if t.FromImage != nil {
		if f.TargetFromImage == nil {
			return false, fmt.Errorf("target image provenance unavailable")
		}
		if *t.FromImage != *f.TargetFromImage {
			return false, nil
		}
	}
	if len(t.FSType) > 0 {
		found, unknown := false, false
		for _, kind := range t.FSType {
			positive := kind == f.FSType || slices.Contains(f.FileKinds, kind)
			found = found || positive
			unknown = unknown || (!positive && !slices.Contains(f.FileKindsKnown, kind))
		}
		// OR accepts a known positive even if another class is unknown.
		if !found {
			if unknown {
				return false, fmt.Errorf("target filesystem classification unavailable")
			}
			return false, nil
		}
	}
	if a.Ancestor != nil {
		depth := int(a.Ancestor.Depth)
		found := false
		for i, path := range f.Ancestors {
			if i >= depth {
				break
			}
			if path == "" {
				return false, fmt.Errorf("ancestor executable unavailable")
			}
			if pathMatches(r.ancestor, path) {
				found = true
				break
			}
		}
		if !found {
			if len(f.Ancestors) < depth && !f.AncestorsComplete {
				return false, fmt.Errorf("ancestor traversal incomplete")
			}
			return false, nil
		}
	}
	if a := t.Argv; a != nil {
		if len(a.Contains) > 0 || len(a.Prefix) > 0 {
			if !f.ArgvComplete || len(f.Argv) > MaxArgc {
				return false, fmt.Errorf("staged argv incomplete or oversized")
			}
			size := 0
			for _, arg := range f.Argv {
				if strings.ContainsRune(arg, 0) {
					return false, fmt.Errorf("invalid staged argument")
				}
				size += len(arg) + 1
			}
			if size > MaxArgBytes {
				return false, fmt.Errorf("staged argv exceeds %d bytes", MaxArgBytes)
			}
			// Lists are alternatives. Contains matches a complete argument, prefix matches
			// the beginning of an argument (not a lossy space-joined command line).
			if len(a.Contains) > 0 {
				found := false
				for _, v := range a.Contains {
					if slices.Contains(f.Argv, v) {
						found = true
						break
					}
				}
				if !found {
					return false, nil
				}
			}
			if len(a.Prefix) > 0 {
				found := false
				for _, v := range a.Prefix {
					for _, arg := range f.Argv {
						if strings.HasPrefix(arg, v) {
							found = true
							break
						}
					}
				}
				if !found {
					return false, nil
				}
			}
		}
		if a.StdinIsPipe != nil {
			if f.StdinIsPipe == nil {
				return false, fmt.Errorf("stdin identity unavailable")
			}
			if *a.StdinIsPipe != *f.StdinIsPipe {
				return false, nil
			}
		}
	}
	return true, nil
}

func pathMatches(patterns []*regexp.Regexp, s string) bool {
	for _, p := range patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}
