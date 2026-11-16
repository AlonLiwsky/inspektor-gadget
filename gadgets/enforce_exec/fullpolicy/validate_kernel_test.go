// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"math"
	"testing"
)

func cloneKernel(p *KernelProgram) *KernelProgram {
	q := *p
	q.Entries = append([]Blob(nil), p.Entries...)
	q.Rules = append([]RuleMetadata(nil), p.Rules...)
	q.Identities = map[uint64]string{}
	for k, v := range p.Identities {
		q.Identities[k] = v
	}
	return &q
}

func mutateEntry[T any](t *testing.T, p *KernelProgram, key uint32, fn func(*T)) {
	t.Helper()
	v, err := Decode[T](p.Entries[key])
	if err != nil {
		t.Fatal(err)
	}
	fn(&v)
	p.Entries[key], err = encode(v)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateKernelProgram(t *testing.T) {
	p, err := CompileKernel(kernelFixture(), 42, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateKernelProgram(p); err != nil {
		t.Fatal(err)
	}
	rule := mustDecode[KernelRule](t, p, KernelRuleBase+1)
	cases := map[string]func(*KernelProgram){
		"generation":     func(p *KernelProgram) { mutateEntry(t, p, 0, func(h *KernelHeader) { h.Generation = 0 }) },
		"header-budget":  func(p *KernelProgram) { mutateEntry(t, p, 0, func(h *KernelHeader) { h.RuleCount = MaxRules + 1 }) },
		"header-padding": func(p *KernelProgram) { p.Entries[0][287] = 1 },
		"unused-policy":  func(p *KernelProgram) { p.Entries[KernelPolicyBase+2][0] = 1 },
		"policy-mode":    func(p *KernelProgram) { mutateEntry(t, p, 1, func(h *KernelPolicy) { h.Mode = 3 }) },
		"rule-policy": func(p *KernelProgram) {
			mutateEntry(t, p, KernelRuleBase, func(r *KernelRule) { r.PolicyIndex = MaxPolicies })
		},
		"rule-mode":    func(p *KernelProgram) { mutateEntry(t, p, KernelRuleBase, func(r *KernelRule) { r.Mode = 0 }) },
		"rule-tri":     func(p *KernelProgram) { mutateEntry(t, p, KernelRuleBase, func(r *KernelRule) { r.TargetImage = 2 }) },
		"rule-padding": func(p *KernelProgram) { p.Entries[KernelRuleBase][287] = 1 },
		"empty-list": func(p *KernelProgram) {
			mutateEntry(t, p, KernelRuleBase, func(r *KernelRule) { r.ActorRole = KernelList{Base: 1} })
		},
		"list-reference": func(p *KernelProgram) {
			mutateEntry(t, p, KernelRuleBase, func(r *KernelRule) { r.ActorPath = KernelList{Base: math.MaxUint32, Count: 2} })
		},
		"depth": func(p *KernelProgram) {
			mutateEntry(t, p, KernelRuleBase+1, func(r *KernelRule) { r.AncestorDepth = MaxAncestorDepth + 1 })
		},
		"UID": func(p *KernelProgram) {
			mutateEntry(t, p, rule.UID.Base, func(v *KernelValue) { v.Value = math.MaxUint64 })
		},
		"string-length": func(p *KernelProgram) {
			mutateEntry(t, p, rule.Container.Base, func(s *KernelString) { s.Length = 256 })
		},
		"string-NUL":     func(p *KernelProgram) { p.Entries[rule.Container.Base][4] = 0 },
		"string-padding": func(p *KernelProgram) { p.Entries[rule.Container.Base][287] = 1 },
		"pattern-start": func(p *KernelProgram) {
			mutateEntry(t, p, rule.TargetPath.Base, func(r *KernelPattern) { r.Start = r.Count })
		},
		"pattern-ref": func(p *KernelProgram) {
			mutateEntry(t, p, rule.TargetPath.Base, func(r *KernelPattern) { r.CodeBase = math.MaxUint32 })
		},
		"pattern-padding": func(p *KernelProgram) { p.Entries[rule.TargetPath.Base][287] = 1 },
		"identities":      func(p *KernelProgram) { p.Identities[123] = "forged" },
		"missing-identity": func(p *KernelProgram) {
			for k := range p.Identities {
				delete(p.Identities, k)
				break
			}
		},
		"metadata-count":  func(p *KernelProgram) { p.Rules = nil },
		"metadata-policy": func(p *KernelProgram) { p.Rules[0].PolicyID = "not-the-policy" },
		"metadata-name":   func(p *KernelProgram) { p.Rules[0].Name = "" },
	}
	pattern := mustDecode[KernelPattern](t, p, rule.TargetPath.Base)
	cases["opcode"] = func(p *KernelProgram) { mutateEntry(t, p, pattern.CodeBase, func(i *KernelInstruction) { i.Op = 99 }) }
	cases["terminal-padding"] = func(p *KernelProgram) { p.Entries[pattern.CodeBase][287] = 1 }
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			q := cloneKernel(p)
			fn(q)
			if err := ValidateKernelProgram(q); err == nil {
				t.Fatal("forged program accepted")
			}
		})
	}
	if err := ValidateKernelProgram(nil); err == nil {
		t.Fatal("nil accepted")
	}
}
