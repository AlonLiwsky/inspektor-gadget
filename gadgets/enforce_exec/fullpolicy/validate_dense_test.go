// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"
	"testing"
)

// The fingerprint freezes the prior validator's exact result for deterministic
// byte corruptions. Identity maps are unmodified, avoiding map-order ambiguity.
func TestDenseValidatorFrozenCorpus(t *testing.T) {
	p, err := CompileKernel(kernelFixture(), 42, "worker")
	if err != nil {
		t.Fatal(err)
	}
	fixed := fixedIdentities{slots: make([]identitySlot, len(p.Identities))}
	for id, name := range p.Identities {
		if err := fixed.insert(id, name); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.New()
	for key := range p.Entries {
		for _, offset := range []int{0, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 80, 160, 287} {
			for _, mask := range []byte{1, 128, 255} {
				q := cloneKernel(p)
				q.Entries[key][offset] ^= mask
				err := ValidateKernelProgram(q)
				fixedErr := validateKernelData(q.Entries, q.Rules, identityView{fixed: &fixed}, nil)
				if fmt.Sprint(err) != fmt.Sprint(fixedErr) {
					t.Fatalf("identity views diverged at %d/%d/%d: %v / %v", key, offset, mask, err, fixedErr)
				}
				fmt.Fprintf(digest, "%d/%d/%d:%v\n", key, offset, mask, err)
			}
		}
	}
	got := fmt.Sprintf("%x", digest.Sum(nil))
	const want = "e3450ed41d26dcda0051bba7684935ec3f147ae7ffed6963f667ac4cb5ad0308"
	if got != want {
		t.Fatalf("validator behavior changed: got %s want %s", got, want)
	}
}

func denseValidatorFixture(t *testing.T) *KernelProgram {
	t.Helper()
	p := base()
	p.Rules = []Rule{{Name: "first", Action: Allow, Target: Target{Path: []string{"/same", "/same"}}}, {Name: "second", Action: Allow}}
	program, err := CompileKernel([]Policy{p}, 1, "worker")
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func TestDenseValidatorDomains(t *testing.T) {
	cases := []struct {
		name, want string
		change     func(*KernelProgram)
	}{
		{"duplicate name", "duplicate rule name", func(p *KernelProgram) { p.Rules[1].Name = p.Rules[0].Name }},
		{"revision mismatch", "inconsistent policy revisions", func(p *KernelProgram) { p.Rules[1].Revision = "changed" }},
		{"policy index boundary", "invalid rule 0 scalars", func(p *KernelProgram) {
			mutateEntry(t, p, KernelRuleBase, func(r *KernelRule) { r.PolicyIndex = MaxPolicies })
		}},
		{"policy index overflow", "invalid rule 0 scalars", func(p *KernelProgram) {
			mutateEntry(t, p, KernelRuleBase, func(r *KernelRule) { r.PolicyIndex = math.MaxUint32 })
		}},
		{"policy count", "invalid full header", func(p *KernelProgram) {
			mutateEntry(t, p, 0, func(h *KernelHeader) { h.PolicyCount = MaxPolicies + 1 })
		}},
		{"list overflow", "rule 0: invalid list reference/budget", func(p *KernelProgram) {
			mutateEntry(t, p, KernelRuleBase, func(r *KernelRule) { r.TargetPath = KernelList{Base: math.MaxUint32, Count: 2} })
		}},
		{"code overflow", "rule 0: invalid pattern descriptor", func(p *KernelProgram) {
			r := mustDecode[KernelRule](t, p, KernelRuleBase)
			mutateEntry(t, p, r.TargetPath.Base, func(d *KernelPattern) { d.CodeBase = math.MaxUint32 })
		}},
		{"code past end", "rule 0: invalid pattern descriptor", func(p *KernelProgram) {
			r := mustDecode[KernelRule](t, p, KernelRuleBase)
			mutateEntry(t, p, r.TargetPath.Base, func(d *KernelPattern) { d.CodeBase = uint32(len(p.Entries)); d.Count = 1; d.Start = 0 })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := denseValidatorFixture(t)
			tc.change(p)
			err := ValidateKernelProgram(p)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v want %s", err, tc.want)
			}
		})
	}
}

func TestDenseValidatorSharedCodeRevalidated(t *testing.T) {
	p := denseValidatorFixture(t)
	r := mustDecode[KernelRule](t, p, KernelRuleBase)
	base := uint32(len(p.Entries))
	jump, _ := encode(KernelInstruction{Op: KernelNop, Out: 1})
	end, _ := encode(KernelInstruction{Op: KernelMatch})
	p.Entries = append(p.Entries, jump, end)
	p.Entries[r.TargetPath.Base], _ = encode(KernelPattern{CodeBase: base, Count: 2})
	p.Entries[r.TargetPath.Base+1], _ = encode(KernelPattern{CodeBase: base, Count: 1})
	if err := ValidateKernelProgram(p); err == nil || err.Error() != "rule 0: invalid jump" {
		t.Fatalf("shared code skipped descriptor-local validation: %v", err)
	}
	// A self-cycle is structurally accepted by the existing data validator. This
	// storage refactor must not invent a graph reachability/cycle restriction.
	p.Entries[base], _ = encode(KernelInstruction{Op: KernelNop})
	if err := ValidateKernelProgram(p); err != nil {
		t.Fatal("cycle behavior changed", err)
	}
}

func TestDenseValidatorUniqueInstructionBudget(t *testing.T) {
	authored := base()
	paths := make([]string, 17)
	for i := range paths {
		paths[i] = "/same"
	}
	authored.Rules = []Rule{{Name: "code", Action: Allow, Target: Target{Path: paths}}}
	p, err := CompileKernel([]Policy{authored}, 1, "worker")
	if err != nil {
		t.Fatal(err)
	}
	rule := mustDecode[KernelRule](t, p, KernelRuleBase)
	start := len(p.Entries)
	instruction, _ := encode(KernelInstruction{Op: KernelMatch})
	for i := 0; i < MaxRegexInstructions+1; i++ {
		p.Entries = append(p.Entries, instruction)
	}
	for i := 0; i < 16; i++ {
		p.Entries[rule.TargetPath.Base+uint32(i)], _ = encode(KernelPattern{CodeBase: uint32(start + i*MaxRegexStates), Count: MaxRegexStates})
	}
	p.Entries[rule.TargetPath.Base+16] = p.Entries[rule.TargetPath.Base] // shared code counts once
	if err = ValidateKernelProgram(p); err != nil {
		t.Fatal("exact unique budget rejected", err)
	}
	p.Entries[rule.TargetPath.Base+16], _ = encode(KernelPattern{CodeBase: uint32(start + MaxRegexInstructions), Count: 1})
	if err = ValidateKernelProgram(p); err == nil || !strings.Contains(err.Error(), "instruction budget exceeded") {
		t.Fatal("excess unique instruction admitted", err)
	}
}

func TestDenseValidatorAllocationBounds(t *testing.T) {
	for _, count := range []int{0, KernelRuleBase - 1, MaxKernelEntries + 1} {
		p := &KernelProgram{Entries: make([]Blob, count)}
		if err := ValidateKernelProgram(p); err == nil || err.Error() != "invalid full program entry budget" {
			t.Fatalf("count %d: %v", count, err)
		}
	}
	policies := make([]Policy, MaxPolicies)
	for i := range policies {
		policies[i] = base()
		policies[i].ID = fmt.Sprintf("policy-%d", i)
		policies[i].Rules = []Rule{{Name: "first", Action: Allow}, {Name: "second", Action: Allow}}
	}
	p, err := CompileKernel(policies, 1, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateKernelProgram(p); err != nil {
		t.Fatal("final policy index rejected", err)
	}
	p.Rules[len(p.Rules)-1].Revision = "changed"
	if err = ValidateKernelProgram(p); err == nil || err.Error() != "inconsistent policy revisions" {
		t.Fatal("final policy revision check changed", err)
	}
}
