// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package fullpolicy defines the complete, runtime-independent exec contract.
// It is not a kernel capability declaration: a backend must validate all required
// capabilities before installing a compiled policy.
package fullpolicy

import (
	"fmt"
	"math"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	MaxPolicies      = 8
	MaxRules         = 256
	MaxPatterns      = 1024
	MaxValues        = 256
	MaxStringBytes   = 255
	MaxAncestorDepth = 16
	MaxArgc          = 64
	MaxArgBytes      = 4096
)

type Mode string

const (
	Audit   Mode = "audit"
	Enforce Mode = "enforce"
)

type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

type Policy struct {
	ID            string
	Revision      string
	Mode          Mode
	RootRole      string
	Default       Action // Empty means that no exec section default was authored.
	DefaultMode   Mode   // Empty inherits Mode. Reference-only until native ABI support.
	DefaultOrigin string // Optional provenance of the section default.
	// DefaultOriginPresent distinguishes an explicitly authored empty label from omission.
	// Nonempty DefaultOrigin is present even when this flag is false (legacy callers).
	DefaultOriginPresent bool
	Rules                []Rule
}
type Rule struct {
	Name   string
	Origin string
	// OriginPresent distinguishes an explicitly authored empty label from omission.
	// Nonempty Origin is present even when this flag is false (legacy callers).
	OriginPresent bool
	Action        Action
	Mode          Mode
	Actor         Actor
	Target        Target
	Except        []Exception // Deny-only predicates; each entry suppresses this rule only.
}
type Exception struct {
	Actor  Actor
	Target Target // Predicate-only: SetRole is forbidden.
}
type Actor struct {
	Path      []string
	FromImage *bool
	Ancestor  *Ancestor
	Role      []string
	UID       []int64
	Container []string
}
type Ancestor struct {
	Path  []string
	Depth int32
}
type Target struct {
	Path      []string
	FromImage *bool
	FSType    []string
	Argv      *Argv
	SetRole   string
}
type Argv struct {
	Contains, Prefix []string
	StdinIsPipe      *bool
}

// prepared records are private: only the regexp-backed specialization can be
// exposed as an evaluable Program. Native preparation retains identical glob
// expressions without constructing unused reference matcher machinery.
type preparedRule[P any] struct {
	source                  Rule
	actor, target, ancestor []P
	exceptions              []preparedRule[P]
}
type preparedPolicy[P any] struct {
	source Policy
	rules  []preparedRule[P]
}
type (
	preparedProgram[P any] struct{ policies []preparedPolicy[P] }
	compiledRule           = preparedRule[*regexp.Regexp]
	compiledPolicy         = preparedPolicy[*regexp.Regexp]
	Program                struct{ policies []compiledPolicy }
)

// Compile validates the entire immutable candidate, without retaining caller-owned
// slices/pointers. List order has no effect on matching or verdict precedence.
func Compile(policies []Policy) (*Program, error) {
	prepared, err := preparePolicies(policies, glob)
	if err != nil {
		return nil, err
	}
	return &Program{policies: prepared.policies}, nil
}

// CompileReference accepts the source-only exec contract for reference evaluation.
// It does not produce uploadable native policy. Compile and native compilation reject
// these fields until the Go/C ABI and live BPF matcher implement them atomically.
func CompileReference(policies []Policy) (*Program, error) {
	prepared, err := preparePoliciesWithDiagnosticsSemantic(policies, glob, richDiagnostics, true)
	if err != nil {
		return nil, err
	}
	return &Program{policies: prepared.policies}, nil
}

// preparePolicies preserves common validation, normalization and deep-copy order
// for both backends. Native limits are checked only by native emission.
func preparePolicies[P any](policies []Policy, compilePath func(string) (P, error)) (*preparedProgram[P], error) {
	return preparePoliciesWithDiagnostics(policies, compilePath, richDiagnostics)
}

func preparePoliciesWithDiagnostics[P any](policies []Policy, compilePath func(string) (P, error), d diagnosticPolicy) (*preparedProgram[P], error) {
	return preparePoliciesWithDiagnosticsSemantic(policies, compilePath, d, false)
}

func preparePoliciesWithDiagnosticsSemantic[P any](policies []Policy, compilePath func(string) (P, error), d diagnosticPolicy, referenceOnly bool) (*preparedProgram[P], error) {
	if len(policies) == 0 || len(policies) > MaxPolicies {
		if d.compact {
			if len(policies) > MaxPolicies {
				return nil, compactFailure(DiagnosticCapacity, DiagnosticNone)
			}
			return nil, d.reject()
		}
		return nil, fmt.Errorf("require 1..%d policies", MaxPolicies)
	}
	p := &preparedProgram[P]{policies: make([]preparedPolicy[P], 0, len(policies))}
	rules, patterns, exceptions := 0, 0, 0
	for _, policy := range policies {
		if !referenceOnly && (policy.DefaultMode != "" || policy.DefaultOrigin != "" || policy.DefaultOriginPresent || hasExceptions(policy.Rules) || hasExplicitEmptyRuleOrigin(policy.Rules)) {
			if d.compact {
				return nil, d.reject()
			}
			return nil, fmt.Errorf("exec default metadata and exceptions are not Ready: native ABI unsupported")
		}
		duplicateID := false
		for _, prior := range p.policies {
			if prior.source.ID == policy.ID {
				duplicateID = true
				break
			}
		}
		if policy.ID == "" || policy.Revision == "" || duplicateID {
			if d.compact {
				return nil, d.reject()
			}
			return nil, fmt.Errorf("policy identity/revision must be nonempty and identity unique")
		}
		if err := validateStringWithDiagnostics(policy.ID, d); err != nil {
			return nil, err
		}
		if err := validateStringWithDiagnostics(policy.Revision, d); err != nil {
			return nil, err
		}
		if policy.Mode != Audit && policy.Mode != Enforce {
			if d.compact {
				return nil, d.reject()
			}
			return nil, fmt.Errorf("policy %s: invalid mode", policy.ID)
		}
		if policy.Default != "" && policy.Default != Allow && policy.Default != Deny {
			if d.compact {
				return nil, d.reject()
			}
			return nil, fmt.Errorf("policy %s: invalid default", policy.ID)
		}
		if policy.DefaultMode != "" && policy.DefaultMode != Audit && policy.DefaultMode != Enforce {
			if d.compact {
				return nil, d.reject()
			}
			return nil, fmt.Errorf("policy %s: invalid default mode", policy.ID)
		}
		if policy.DefaultOrigin != "" {
			if err := validateStringWithDiagnostics(policy.DefaultOrigin, d); err != nil {
				return nil, err
			}
		}
		if policy.RootRole == "" {
			policy.RootRole = "agent"
		}
		if err := validateStringWithDiagnostics(policy.RootRole, d); err != nil {
			return nil, err
		}
		cp := preparedPolicy[P]{source: policy}
		cp.source.DefaultOrigin = strings.Clone(policy.DefaultOrigin)
		cp.source.Rules = nil
		// Bound allocation by remaining global capacity, not untrusted authored
		// length. Keep rejection inside the loop to preserve earlier error order.
		if capacity := min(len(policy.Rules), MaxRules-rules); capacity > 0 {
			cp.rules = make([]preparedRule[P], 0, capacity)
		}
		for _, r := range policy.Rules {
			rules++
			if rules > MaxRules {
				if d.compact {
					return nil, compactFailure(DiagnosticCapacity, DiagnosticNone)
				}
				return nil, fmt.Errorf("exec rule capacity exceeds %d", MaxRules)
			}
			duplicateName := false
			for _, prior := range cp.rules {
				if prior.source.Name == r.Name {
					duplicateName = true
					break
				}
			}
			if r.Name == "" || duplicateName {
				if d.compact {
					return nil, d.reject()
				}
				return nil, fmt.Errorf("rule name must be nonempty and unique")
			}
			if err := validateStringWithDiagnostics(r.Name, d); err != nil {
				return nil, err
			}
			if r.Origin != "" {
				if err := validateStringWithDiagnostics(r.Origin, d); err != nil {
					return nil, err
				}
			}
			if r.Action != Allow && r.Action != Deny {
				if d.compact {
					return nil, d.reject()
				}
				return nil, fmt.Errorf("rule %s: invalid action", r.Name)
			}
			if len(r.Except) != 0 && r.Action != Deny {
				if d.compact {
					return nil, d.reject()
				}
				return nil, fmt.Errorf("rule %s: except requires deny", r.Name)
			}
			if len(r.Except) > MaxValues || exceptions+len(r.Except) > MaxRules {
				if d.compact {
					return nil, compactFailure(DiagnosticCapacity, DiagnosticNone)
				}
				return nil, fmt.Errorf("exec exception capacity exceeds %d", MaxRules)
			}
			exceptions += len(r.Except)
			if r.Mode != "" && r.Mode != Audit && r.Mode != Enforce {
				if d.compact {
					return nil, d.reject()
				}
				return nil, fmt.Errorf("rule %s: invalid mode", r.Name)
			}
			if r.Target.SetRole != "" {
				if r.Action != Allow {
					if d.compact {
						return nil, d.reject()
					}
					return nil, fmt.Errorf("rule %s: setRole requires allow", r.Name)
				}
				if err := validateStringWithDiagnostics(r.Target.SetRole, d); err != nil {
					return nil, err
				}
			}
			cr := preparedRule[P]{source: r}
			cr.source.Origin = strings.Clone(r.Origin)
			var err error
			cr.source.Actor.FromImage = cloneBool(r.Actor.FromImage)
			cr.source.Target.FromImage = cloneBool(r.Target.FromImage)
			cr.actor, err = preparePathsWithDiagnostics(r.Actor.Path, &patterns, compilePath, d)
			if err != nil {
				if d.compact {
					return nil, d.forward(err)
				}
				return nil, fmt.Errorf("rule %s actor: %w", r.Name, err)
			}
			cr.target, err = preparePathsWithDiagnostics(r.Target.Path, &patterns, compilePath, d)
			if err != nil {
				if d.compact {
					return nil, d.forward(err)
				}
				return nil, fmt.Errorf("rule %s target: %w", r.Name, err)
			}
			cr.source.Actor.Path = nil
			if len(r.Actor.Path) != 0 {
				cr.source.Actor.Path = make([]string, len(r.Actor.Path))
				copy(cr.source.Actor.Path, r.Actor.Path)
			}
			cr.source.Target.Path = nil
			if len(r.Target.Path) != 0 {
				cr.source.Target.Path = make([]string, len(r.Target.Path))
				copy(cr.source.Target.Path, r.Target.Path)
			}
			cr.source.Actor.Role, err = cloneStringsWithDiagnostics(r.Actor.Role, d)
			if err != nil {
				return nil, err
			}
			cr.source.Actor.Container, err = cloneStringsWithDiagnostics(r.Actor.Container, d)
			if err != nil {
				return nil, err
			}
			cr.source.Target.FSType, err = cloneStringsWithDiagnostics(r.Target.FSType, d)
			if err != nil {
				return nil, err
			}
			for _, kind := range cr.source.Target.FSType {
				if !fileType(kind) {
					if d.compact {
						return nil, d.reject()
					}
					return nil, fmt.Errorf("unknown filesystem class %q", kind)
				}
			}
			if len(r.Actor.UID) > MaxValues {
				if d.compact {
					return nil, compactFailure(DiagnosticCapacity, DiagnosticNone)
				}
				return nil, fmt.Errorf("UID list exceeds %d", MaxValues)
			}
			cr.source.Actor.UID = nil
			if len(r.Actor.UID) != 0 {
				cr.source.Actor.UID = make([]int64, len(r.Actor.UID))
				copy(cr.source.Actor.UID, r.Actor.UID)
			}
			for _, uid := range r.Actor.UID {
				if uid < 0 || uid > math.MaxUint32 {
					if d.compact {
						return nil, d.reject()
					}
					return nil, fmt.Errorf("effective UID is out of range")
				}
			}
			if a := r.Actor.Ancestor; a != nil {
				if a.Depth < 1 || a.Depth > MaxAncestorDepth || len(a.Path) == 0 {
					if d.compact {
						return nil, d.reject()
					}
					return nil, fmt.Errorf("ancestor requires paths and depth 1..%d", MaxAncestorDepth)
				}
				cr.ancestor, err = preparePathsWithDiagnostics(a.Path, &patterns, compilePath, d)
				if err != nil {
					return nil, err
				}
				cr.source.Actor.Ancestor = &Ancestor{Depth: a.Depth, Path: make([]string, len(a.Path))}
				copy(cr.source.Actor.Ancestor.Path, a.Path)
			}
			if a := r.Target.Argv; a != nil {
				contains, e := cloneStringsWithDiagnostics(a.Contains, d)
				if e != nil {
					return nil, e
				}
				prefix, e := cloneStringsWithDiagnostics(a.Prefix, d)
				if e != nil {
					return nil, e
				}
				if len(contains) == 0 && len(prefix) == 0 && a.StdinIsPipe == nil {
					if d.compact {
						return nil, d.reject()
					}
					return nil, fmt.Errorf("empty argv predicate")
				}
				cr.source.Target.Argv = &Argv{Contains: contains, Prefix: prefix, StdinIsPipe: cloneBool(a.StdinIsPipe)}
			}
			cr.source.Except = nil
			for _, ex := range r.Except {
				if exceptionEmpty(ex) || ex.Target.SetRole != "" {
					if d.compact {
						return nil, d.reject()
					}
					return nil, fmt.Errorf("rule %s: exception requires actor or target predicates and cannot setRole", r.Name)
				}
				// Reuse the complete rule validator and deep-copy path for every predicate.
				ep := Policy{ID: "exception", Revision: "reference", Mode: Audit, Rules: []Rule{{Name: "predicate", Action: Deny, Actor: ex.Actor, Target: ex.Target}}}
				prepared, e := preparePoliciesWithDiagnosticsSemantic([]Policy{ep}, compilePath, d, true)
				if e != nil {
					if d.compact {
						return nil, d.forward(e)
					}
					return nil, fmt.Errorf("rule %s exception: %w", r.Name, e)
				}
				er := prepared.policies[0].rules[0]
				patterns += len(ex.Actor.Path) + len(ex.Target.Path)
				if ex.Actor.Ancestor != nil {
					patterns += len(ex.Actor.Ancestor.Path)
				}
				if patterns > MaxPatterns {
					if d.compact {
						return nil, compactFailure(DiagnosticCapacity, DiagnosticNone)
					}
					return nil, fmt.Errorf("pattern capacity exceeds %d", MaxPatterns)
				}
				cr.exceptions = append(cr.exceptions, er)
				cr.source.Except = append(cr.source.Except, Exception{Actor: er.source.Actor, Target: er.source.Target})
			}
			cp.rules = append(cp.rules, cr)
		}
		p.policies = append(p.policies, cp)
	}
	slices.SortFunc(p.policies, func(a, b preparedPolicy[P]) int { return strings.Compare(a.source.ID, b.source.ID) })
	return p, nil
}

func hasExceptions(rules []Rule) bool {
	for _, r := range rules {
		if r.Except != nil {
			return true
		}
	}
	return false
}

func hasExplicitEmptyRuleOrigin(rules []Rule) bool {
	for _, r := range rules {
		if r.OriginPresent && r.Origin == "" {
			return true
		}
	}
	return false
}

func exceptionEmpty(e Exception) bool {
	a, t := e.Actor, e.Target
	return len(a.Path) == 0 && a.FromImage == nil && a.Ancestor == nil && len(a.Role) == 0 && len(a.UID) == 0 && len(a.Container) == 0 && len(t.Path) == 0 && t.FromImage == nil && len(t.FSType) == 0 && t.Argv == nil && t.SetRole == ""
}

func cloneBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	c := *b
	return &c
}

func validateString(s string) error {
	return validateStringWithDiagnostics(s, richDiagnostics)
}

func validateStringWithDiagnostics(s string, d diagnosticPolicy) error {
	if s == "" || len(s) > MaxStringBytes || strings.ContainsRune(s, 0) || !utf8.ValidString(s) {
		if d.compact {
			return d.reject()
		}
		return fmt.Errorf("string must contain 1..%d non-NUL bytes", MaxStringBytes)
	}
	return nil
}

func cloneStrings(in []string) ([]string, error) {
	return cloneStringsWithDiagnostics(in, richDiagnostics)
}

func cloneStringsWithDiagnostics(in []string, d diagnosticPolicy) ([]string, error) {
	if len(in) > MaxValues {
		if d.compact {
			return nil, compactFailure(DiagnosticCapacity, DiagnosticNone)
		}
		return nil, fmt.Errorf("list capacity exceeds %d", MaxValues)
	}
	for _, s := range in {
		if err := validateStringWithDiagnostics(s, d); err != nil {
			return nil, err
		}
	}
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out, nil
}

func preparePaths[P any](in []string, total *int, compilePath func(string) (P, error)) ([]P, error) {
	return preparePathsWithDiagnostics(in, total, compilePath, richDiagnostics)
}

func preparePathsWithDiagnostics[P any](in []string, total *int, compilePath func(string) (P, error), d diagnosticPolicy) ([]P, error) {
	if len(in) > MaxValues {
		if d.compact {
			return nil, compactFailure(DiagnosticCapacity, DiagnosticNone)
		}
		return nil, fmt.Errorf("path list exceeds %d", MaxValues)
	}
	result := make([]P, 0, len(in))
	for _, s := range in {
		*total++
		if *total > MaxPatterns {
			if d.compact {
				return nil, compactFailure(DiagnosticCapacity, DiagnosticNone)
			}
			return nil, fmt.Errorf("pattern capacity exceeds %d", MaxPatterns)
		}
		if err := validateStringWithDiagnostics(s, d); err != nil {
			return nil, err
		}
		if !path.IsAbs(s) {
			if d.compact {
				return nil, d.reject()
			}
			return nil, fmt.Errorf("path must be absolute")
		}
		re, err := compilePath(s)
		if err != nil {
			return nil, d.forward(err)
		}
		result = append(result, re)
	}
	return result, nil
}

// glob keeps the reference evaluator regexp-backed. Native expression consumers
// must use the same conversion rather than reimplement pathname semantics.
func glob(pattern string) (*regexp.Regexp, error) {
	expression, err := globExpression(pattern)
	if err != nil {
		return nil, err
	}
	r, err := regexp.Compile(expression)
	if err != nil {
		return nil, fmt.Errorf("malformed glob %q: %w", pattern, err)
	}
	return r, nil
}
