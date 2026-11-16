// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
	"unsafe"
)

// ValidateKernelProgram checks the public compiled-data boundary before any map
// write or binding. It does not attest kernel capabilities or original authoring
// provenance. All referenced objects, bytecode and metadata are validated; no
// partial program is usable on failure.
func ValidateKernelProgram(p *KernelProgram) error {
	return validateKernelProgram(p, nil)
}

// validateKernelProgram charges only the two private scratch backing arrays to
// an existing attempt. Header decoding and other work are not admitted here;
// public callers still use nil work until complete compiler ownership is wired.
func validateKernelProgram(p *KernelProgram, work *compilerWorkspace) error {
	if p == nil {
		return fmt.Errorf("invalid full program entry budget")
	}
	return validateKernelData(p.Entries, p.Rules, identityView{legacy: p.Identities}, work)
}

func validateKernelData(entries []Blob, rules []RuleMetadata, identities identityView, work *compilerWorkspace) (result error) {
	return validateKernelDataWithDiagnostics(entries, rules, identities, work, richDiagnostics)
}

func validateKernelDataWithDiagnostics(entries []Blob, rules []RuleMetadata, identities identityView, work *compilerWorkspace, d diagnosticPolicy) (result error) {
	if len(entries) < KernelRuleBase || len(entries) > MaxKernelEntries {
		if d.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("invalid full program entry budget")
	}
	h := decodeKernelHeader(entries[0])
	if h.Generation == 0 || h.Generation == UnknownRoleEpoch || h.PolicyCount == 0 || h.PolicyCount > MaxPolicies || h.RuleBase != KernelRuleBase || h.RuleCount > MaxRules || uint64(h.RuleBase)+uint64(h.RuleCount) > uint64(len(entries)) || !zero(h.Padding[:]) {
		if d.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("invalid full header")
	}
	if len(rules) != int(h.RuleCount) {
		if d.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("rule metadata count mismatch")
	}
	if err := identities.validateWithDiagnostics(d); err != nil {
		return d.forward(err)
	}
	// Existing entry/policy bounds make both products and their sum bounded
	// before reserve. Reserve also charges its cumulative token metadata.
	scratch := uint64(len(entries))*uint64(unsafe.Sizeof(false)) + uint64(h.PolicyCount)*uint64(unsafe.Sizeof(KernelPolicy{}))
	reservation, err := work.reserve(scratch)
	if err != nil {
		return d.forward(err)
	}
	if reservation != nil {
		// Scratch never escapes validation. Release on every subsequent return;
		// never hide an ownership failure behind a validation error or success.
		defer func() {
			if releaseErr := reservation.release(); releaseErr != nil {
				result = d.join(result, releaseErr)
			}
		}()
	}
	// Both dense domains are bounded before allocation/indexing: entry count
	// above, and each rule PolicyIndex below before revision lookup.
	v := programValidator{diagnostics: d, entries: entries, identities: identities, code: make([]bool, len(entries)), policy: make([]KernelPolicy, h.PolicyCount)}
	if err := v.stringAt(h.ContainerRef); err != nil {
		if d.compact {
			return d.forward(err)
		}
		return fmt.Errorf("container: %w", err)
	}
	for i := uint32(0); i < MaxPolicies; i++ {
		b := entries[KernelPolicyBase+i]
		if i >= h.PolicyCount {
			if !zero(b[:]) {
				if d.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("unused policy slot is not zero")
			}
			continue
		}
		policy := decodeKernelPolicy(b)
		if policy.UID == 0 || policy.RootRole == 0 || policy.RootEpoch == 0 || policy.RootEpoch > h.Generation || policy.Default > 2 || policy.Mode < 1 || policy.Mode > 2 || !zero(policy.Padding[:]) {
			if d.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("invalid policy entry")
		}
		if err = v.identity(policy.UID); err != nil {
			return d.forward(err)
		}
		if err = v.identity(policy.RootRole); err != nil {
			return d.forward(err)
		}
		for j := uint32(0); j < i; j++ {
			if v.policy[j].UID == policy.UID {
				if d.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("duplicate policy UID")
			}
		}
		v.policy[i] = policy
	}
	for i := uint32(0); i < h.RuleCount; i++ {
		rule := decodeKernelRule(entries[h.RuleBase+i])
		if rule.PolicyIndex >= h.PolicyCount || rule.Mode < 1 || rule.Mode > 2 || rule.Deny > 1 || !validTri(rule.ActorImage) || !validTri(rule.TargetImage) || !validTri(rule.Stdin) || rule.AncestorDepth > MaxAncestorDepth || rule.Reserved != 0 || !zero(rule.Padding[:]) {
			if d.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("invalid rule %d scalars", i)
		}
		if (rule.AncestorDepth == 0) != (rule.AncestorPath.Count == 0) {
			if d.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("ancestor depth/list mismatch")
		}
		if rule.SetRole != 0 {
			if rule.Deny != 0 {
				if d.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("deny assigns role")
			}
			if err = v.identity(rule.SetRole); err != nil {
				return d.forward(err)
			}
		}
		for _, list := range []KernelList{rule.ActorPath, rule.TargetPath, rule.AncestorPath} {
			if err = v.list(list, "pattern"); err != nil {
				if d.compact {
					return d.forward(err)
				}
				return fmt.Errorf("rule %d: %w", i, err)
			}
		}
		if err = v.list(rule.ActorRole, "identity"); err != nil {
			return d.forward(err)
		}
		if err = v.list(rule.UID, "uid"); err != nil {
			return d.forward(err)
		}
		for _, list := range []KernelList{rule.Container, rule.ArgContains, rule.ArgPrefix} {
			if err = v.list(list, "string"); err != nil {
				return d.forward(err)
			}
		}
		if err = v.list(rule.FSType, "filesystem"); err != nil {
			return d.forward(err)
		}
		meta := rules[i]
		if meta.PolicyIndex != rule.PolicyIndex || stableHash(meta.PolicyID) != v.policy[rule.PolicyIndex].UID {
			if d.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("rule policy metadata mismatch")
		}
		policyName, _ := identities.lookup(v.policy[rule.PolicyIndex].UID)
		if policyName != meta.PolicyID {
			if d.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("rule policy metadata mismatch")
		}
		for _, s := range []string{meta.PolicyID, meta.Revision, meta.Name} {
			if err = validateStringWithDiagnostics(s, d.invariant()); err != nil {
				return d.forward(err)
			}
		}
		if meta.Origin != "" {
			if err = validateStringWithDiagnostics(meta.Origin, d.invariant()); err != nil {
				return d.forward(err)
			}
		}
		// Rule count is bounded by MaxRules and every prior record has already
		// passed metadata/name validation. Compare the original pair directly;
		// no formatted key or hash-table growth is needed for this small domain.
		for _, prior := range rules[:i] {
			if prior.PolicyIndex == rule.PolicyIndex && prior.Name == meta.Name {
				if d.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("duplicate rule name")
			}
		}
		if previous := v.revisions[rule.PolicyIndex]; previous != "" && previous != meta.Revision {
			if d.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("inconsistent policy revisions")
		}
		v.revisions[rule.PolicyIndex] = meta.Revision
	}
	return nil
}

func zero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
func validTri(v int32) bool { return v >= -1 && v <= 1 }

type programValidator struct {
	diagnostics  diagnosticPolicy
	identities   identityView
	entries      []Blob
	code         []bool
	instructions int
	patterns     int
	policy       []KernelPolicy
	revisions    [MaxPolicies]string
}

func (v *programValidator) identity(id uint64) error {
	if _, ok := v.identities.lookup(id); !ok {
		if v.diagnostics.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("unregistered identity")
	}
	return nil
}

func (v *programValidator) stringAt(key uint32) error {
	if uint64(key) >= uint64(len(v.entries)) {
		if v.diagnostics.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("string reference out of range")
	}
	s := decodeKernelString(v.entries[key])
	if s.Length == 0 || s.Length > MaxStringBytes || !zero(s.Bytes[s.Length:]) || !zero(s.Padding[:]) {
		if v.diagnostics.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("invalid string length/padding")
	}
	text := string(s.Bytes[:s.Length])
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		if v.diagnostics.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("invalid string encoding")
	}
	return nil
}

func (v *programValidator) list(l KernelList, kind string) error {
	if l.Count == 0 {
		if l.Base != 0 {
			if v.diagnostics.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("empty list has nonzero reference")
		}
		return nil
	}
	if l.Count > MaxValues || l.Base == 0 || uint64(l.Base)+uint64(l.Count) > uint64(len(v.entries)) {
		if v.diagnostics.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("invalid list reference/budget")
	}
	for i := uint32(0); i < l.Count; i++ {
		key := l.Base + i
		switch kind {
		case "string", "filesystem":
			if err := v.stringAt(key); err != nil {
				return v.diagnostics.forward(err)
			}
			if kind == "filesystem" {
				s := decodeKernelString(v.entries[key])
				if !fileType(string(s.Bytes[:s.Length])) {
					if v.diagnostics.compact {
						return compactFailure(DiagnosticInternal, DiagnosticNone)
					}
					return fmt.Errorf("unknown filesystem class")
				}
			}
		case "identity", "uid":
			val := decodeKernelValue(v.entries[key])
			if !zero(val.Padding[:]) {
				if v.diagnostics.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("nonzero value padding")
			}
			if kind == "identity" {
				if err := v.identity(val.Value); err != nil {
					return v.diagnostics.forward(err)
				}
			} else if val.Value > math.MaxUint32 {
				if v.diagnostics.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("UID out of range")
			}
		case "pattern":
			if err := v.patternAt(key); err != nil {
				return v.diagnostics.forward(err)
			}
		default:
			if v.diagnostics.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("unknown list kind")
		}
	}
	return nil
}

func fileType(s string) bool { return s == "tmpfs" || s == "memfd" || s == "deleted" || s == "overlay" }

func (v *programValidator) patternAt(key uint32) error {
	v.patterns++
	if v.patterns > MaxPatterns {
		if v.diagnostics.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("pattern budget exceeded")
	}
	p := decodeKernelPattern(v.entries[key])
	if p.Count == 0 || p.Count > MaxRegexStates || p.Start >= p.Count || p.CodeBase == 0 || uint64(p.CodeBase)+uint64(p.Count) > uint64(len(v.entries)) || !zero(p.Padding[:]) {
		if v.diagnostics.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("invalid pattern descriptor")
	}
	for pc := uint32(0); pc < p.Count; pc++ {
		key := p.CodeBase + pc
		// The descriptor bounds check above proves key is an entry index. Count
		// shared instructions once, but revalidate them for EVERY descriptor's
		// local PC bounds below; visitation is not a validation-result cache.
		if !v.code[key] {
			v.code[key] = true
			v.instructions++
		}
		if v.instructions > MaxRegexInstructions {
			if v.diagnostics.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("instruction budget exceeded")
		}
		inst := decodeKernelInstruction(v.entries[key])
		if !zero(inst.Padding[:]) {
			if v.diagnostics.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("instruction padding")
		}
		switch inst.Op {
		case KernelAlt:
			if inst.Out >= p.Count || inst.Arg >= p.Count || inst.Count != 0 {
				if v.diagnostics.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("invalid alternate")
			}
		case KernelEmptyWidth:
			if inst.Out >= p.Count || inst.Arg == 0 || inst.Arg & ^uint32(KernelBeginText|KernelEndText) != 0 || inst.Count != 0 {
				if v.diagnostics.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("invalid assertion")
			}
		case KernelNop:
			if inst.Out >= p.Count || inst.Arg != 0 || inst.Count != 0 {
				if v.diagnostics.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("invalid jump")
			}
		case KernelMatch, KernelFail:
			if inst.Out != 0 || inst.Arg != 0 || inst.Count != 0 {
				if v.diagnostics.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("invalid terminal")
			}
		case KernelRune:
			if inst.Out >= p.Count || inst.Arg != 0 || inst.Count == 0 || inst.Count > MaxRuneRanges {
				if v.diagnostics.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("invalid rune instruction")
			}
			var end uint32
			for i := uint32(0); i < inst.Count; i++ {
				lo, hi := inst.Ranges[2*i], inst.Ranges[2*i+1]
				if lo > hi || hi > 0x10ffff || (i > 0 && lo <= end) {
					if v.diagnostics.compact {
						return compactFailure(DiagnosticInternal, DiagnosticNone)
					}
					return fmt.Errorf("invalid rune ranges")
				}
				end = hi
			}
		default:
			if v.diagnostics.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("invalid opcode")
		}
		used := inst.Count * 2
		if used > 16 {
			if v.diagnostics.compact {
				return compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return fmt.Errorf("invalid range budget")
		}
		for _, value := range inst.Ranges[used:] {
			if value != 0 {
				if v.diagnostics.compact {
					return compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return fmt.Errorf("unused range data")
			}
		}
	}
	return nil
}
