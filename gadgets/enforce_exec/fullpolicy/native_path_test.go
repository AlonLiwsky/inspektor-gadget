// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import "testing"

func TestNativePathOriginalProvenance(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "paths", Action: Allow, Actor: Actor{Path: []string{"/[a]"}, Ancestor: &Ancestor{Depth: 1, Path: []string{"/[a-a]"}}}, Target: Target{Path: []string{"/[a]", "/[a-a]", "/[a]", "/界"}}}}
	prepared, err := preparePolicies([]Policy{p}, nativeGlob)
	if err != nil {
		t.Fatal(err)
	}
	r := prepared.policies[0].rules[0]
	for _, list := range []struct {
		values   []nativePath
		authored []string
	}{{r.actor, p.Rules[0].Actor.Path}, {r.ancestor, p.Rules[0].Actor.Ancestor.Path}, {r.target, p.Rules[0].Target.Path}} {
		if len(list.values) != len(list.authored) {
			t.Fatal("lost original occurrences")
		}
		for i, value := range list.values {
			expression, err := globExpression(list.authored[i])
			if err != nil {
				t.Fatal(err)
			}
			if value.expression != expression || value.authoredBytes != uint64(len(list.authored[i])) {
				t.Fatalf("lost original bytes for %q", list.authored[i])
			}
		}
	}
	if r.target[0].expression != r.target[1].expression || r.target[0].authoredBytes == r.target[1].authoredBytes {
		t.Fatal("equivalent expressions collapsed distinct authored lengths")
	}
	p.Rules[0].Actor.Path[0] = "/changed"
	p.Rules[0].Actor.Ancestor.Path[0] = "/changed"
	p.Rules[0].Target.Path[0] = "/changed"
	if r.source.Actor.Path[0] != "/[a]" || r.source.Actor.Ancestor.Path[0] != "/[a-a]" || r.source.Target.Path[0] != "/[a]" {
		t.Fatal("preparation retained mutable caller slices")
	}
	// Native emission must still key ONLY by expression, never authored length.
	program, err := compilePreparedKernel(prepared, 1, "worker", stableHash)
	if err != nil {
		t.Fatal(err)
	}
	if err = program.validate(); err != nil {
		t.Fatal(err)
	}
	view := &KernelProgram{Entries: program.Entries}
	rule := mustDecode[KernelRule](t, view, KernelRuleBase)
	a := mustDecode[KernelPattern](t, view, rule.TargetPath.Base)
	b := mustDecode[KernelPattern](t, view, rule.TargetPath.Base+1)
	if a != b {
		t.Fatal("authored metadata changed expression dedup")
	}
}

func TestNativePathRequiresValidatedInput(t *testing.T) {
	for _, pattern := range []string{"", "relative", "/\x00", "/[", "/\\"} {
		p := base()
		p.Rules = []Rule{{Name: "bad", Action: Allow, Target: Target{Path: []string{pattern}}}}
		reference, referenceErr := Compile([]Policy{p})
		native, nativeErr := preparePolicies([]Policy{p}, nativeGlob)
		if reference != nil || native != nil || referenceErr == nil || nativeErr == nil || referenceErr.Error() != nativeErr.Error() {
			t.Fatalf("validation changed for %q: %v / %v", pattern, referenceErr, nativeErr)
		}
	}
}
