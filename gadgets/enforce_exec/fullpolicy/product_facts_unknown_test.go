// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import "testing"

// TestProductFactUnknownEncodingsFailClosed (G020): each encoding the shared
// product's per-pass collector (full/shared_pass_facts.h) leaves for a fact
// it could not collect is UNKNOWN to the evaluator, never "empty matches" or
// "not equal": an enforced rule consulting it fails the evaluation (the
// kernel's error verdict: Strict denies), whether the rule allows or denies;
// an Audit rule records the unknown. The encodings are those of
// evaluatorFactBytes: a path "" is length 0, a nil stdin is -1, an fs class
// absent from FileKinds/FileKindsKnown has its fs_known bit clear, nil
// incomplete ancestors are count 0 with ancestors_complete 0. The C evaluator
// is held to the Go oracle on the same unknown-* facts by
// TestCEvaluator*Parity.
func TestProductFactUnknownEncodingsFailClosed(t *testing.T) {
	yes := true
	uid := uint32(0)
	known := Facts{
		ActorPath: "/usr/bin/sh", TargetPath: "/usr/bin/true", EffectiveUID: &uid,
		Ancestors: []string{"/usr/bin/init"}, AncestorsComplete: true, Roles: map[string]string{"p": "root"},
		FSType: "tmpfs", FileKindsKnown: []string{"tmpfs", "overlay", "deleted"}, StdinIsPipe: &yes,
	}
	cases := []struct {
		name    string
		actor   Actor
		target  Target
		unknown func(*Facts)
	}{
		{"target path (d_path failure, too long, outside root)", Actor{}, Target{Path: []string{"/usr/bin/true"}}, func(f *Facts) { f.TargetPath = "" }},
		{"actor path (no exe, outside root)", Actor{Path: []string{"/usr/bin/sh"}}, Target{}, func(f *Facts) { f.ActorPath = "" }},
		{"ancestor (failed walk)", Actor{Ancestor: &Ancestor{Path: []string{"/usr/bin/init"}, Depth: 1}}, Target{}, func(f *Facts) { f.Ancestors, f.AncestorsComplete = nil, false }},
		{"fs class (no target file)", Actor{}, Target{FSType: []string{"tmpfs"}}, func(f *Facts) { f.FSType, f.FileKinds, f.FileKindsKnown = "", nil, nil }},
		{"stdin (shared files table)", Actor{}, Target{Argv: &Argv{StdinIsPipe: &yes}}, func(f *Facts) { f.StdinIsPipe = nil }},
	}
	for _, c := range cases {
		for _, action := range []Action{Allow, Deny} {
			fallback := Deny
			if action == Deny {
				fallback = Allow
			}
			rule := Rule{Name: "r", Action: action, Actor: c.actor, Target: c.target}
			for _, mode := range []Mode{Enforce, Audit} {
				p, err := Compile([]Policy{{ID: "p", Revision: "1", Mode: mode, RootRole: "root", Default: fallback, Rules: []Rule{rule}}})
				if err != nil {
					t.Fatalf("%s: %v", c.name, err)
				}
				// The known facts decide the rule.
				d, err := p.Evaluate(known)
				if err != nil || len(d.Matches) != 1 {
					t.Fatalf("%s %s %s: known facts %+v, %v", c.name, action, mode, d, err)
				}
				f := known
				c.unknown(&f)
				d, err = p.Evaluate(f)
				switch mode {
				case Enforce:
					if err == nil {
						t.Fatalf("%s %s Enforce: unknown fact decided %+v, want the evaluation to fail closed", c.name, action, d)
					}
				case Audit:
					if err != nil || !d.AuditUnknown["p"] || d.Block {
						t.Fatalf("%s %s Audit: %+v, %v: want the unknown recorded, nonblocking", c.name, action, d, err)
					}
					for _, m := range d.Matches {
						if m.Rule == "r" {
							t.Fatalf("%s %s Audit: the rule matched an unknown fact: %+v", c.name, action, d)
						}
					}
				}
			}
		}
	}
}
