// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import "testing"

type roleEntryCase struct {
	name      string
	policies  []Policy
	facts     Facts
	wantRole  string
	wantDeny  bool
	wantBlock bool
	wantError bool
}

// These authoring regressions also feed both native C evaluator parity modes.
// They prove proposal semantics, not kernel observation or successful-exec commit.
func roleEntryCases() []roleEntryCase {
	p := base()
	p.Default = Deny
	target := Target{Path: []string{"/usr/bin/bwrap"}, FromImage: ptr(true), SetRole: "sandbox-helper"}
	grant := Rule{
		Name: "enter-sandbox-helper", Action: Allow,
		Actor:  Actor{Role: []string{"trusted-launcher"}, Path: []string{"/usr/libexec/sandbox-launcher"}, FromImage: ptr(true)},
		Target: target,
	}
	facts := Facts{
		ActorPath: "/usr/libexec/sandbox-launcher", ActorFromImage: ptr(true),
		Roles:      map[string]string{p.ID: "trusted-launcher"},
		TargetPath: "/usr/bin/bwrap", TargetFromImage: ptr(true),
	}
	var cases []roleEntryCase
	for name, rule := range map[string]Rule{
		"omitted-actor":       {Name: grant.Name, Action: Allow, Target: target},
		"empty-actor":         {Name: grant.Name, Action: Allow, Actor: Actor{}, Target: target},
		"wildcard-only-actor": {Name: grant.Name, Action: Allow, Actor: Actor{Path: []string{"/**"}}, Target: target},
	} {
		broad := p
		broad.Rules = []Rule{rule}
		untrusted := facts
		untrusted.ActorPath = "/tmp/untrusted-agent"
		untrusted.ActorFromImage = ptr(false)
		untrusted.Roles = map[string]string{p.ID: "agent"}
		cases = append(cases, roleEntryCase{name: name, policies: []Policy{broad}, facts: untrusted, wantRole: "sandbox-helper"})
	}
	p.Rules = []Rule{grant}
	cases = append(cases, roleEntryCase{name: "authorized-actor", policies: []Policy{p}, facts: facts, wantRole: "sandbox-helper"})
	for name, change := range map[string]func(*Facts){
		"wrong-actor-path":     func(f *Facts) { f.ActorPath = "/tmp/untrusted-agent" },
		"actor-not-from-image": func(f *Facts) { f.ActorFromImage = ptr(false) },
		"wrong-actor-role":     func(f *Facts) { f.Roles = map[string]string{p.ID: "agent"} },
	} {
		mismatch := facts
		change(&mismatch)
		cases = append(cases, roleEntryCase{name: name, policies: []Policy{p}, facts: mismatch, wantDeny: true, wantBlock: true})
	}
	for name, change := range map[string]func(*Facts){
		"unknown-actor-image": func(f *Facts) { f.ActorFromImage = nil },
		"unknown-actor-role":  func(f *Facts) { f.Roles = nil },
	} {
		unknown := facts
		change(&unknown)
		cases = append(cases, roleEntryCase{name: name, policies: []Policy{p}, facts: unknown, wantError: true})
	}
	for _, mode := range []Mode{Audit, Enforce} {
		denied := p
		denied.Rules = append([]Rule{grant}, Rule{Name: "deny-helper", Action: Deny, Mode: mode, Target: Target{Path: target.Path}})
		cases = append(cases, roleEntryCase{name: string(mode) + "-deny-suppresses-role", policies: []Policy{denied}, facts: facts, wantDeny: true, wantBlock: mode == Enforce})
	}
	conflict := grant
	conflict.Name = "conflicting-role"
	conflict.Target.SetRole = "other-helper"
	p.Rules = []Rule{grant, conflict}
	cases = append(cases, roleEntryCase{name: "conflict-suppresses-role", policies: []Policy{p}, facts: facts, wantError: true})
	return cases
}

func TestRoleEntryAuthoring(t *testing.T) {
	for _, tc := range roleEntryCases() {
		t.Run(tc.name, func(t *testing.T) {
			program := compile(t, tc.policies...)
			decision, err := program.Evaluate(tc.facts)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v, wantError=%v", err, tc.wantError)
			}
			if got := decision.SetRoles[tc.policies[0].ID]; got != tc.wantRole {
				t.Fatalf("role=%q, want %q; decision=%+v", got, tc.wantRole, decision)
			}
			if !tc.wantError && ((decision.Action == Deny) != tc.wantDeny || decision.Block != tc.wantBlock) {
				t.Fatalf("decision=%+v, wantDeny=%v wantBlock=%v", decision, tc.wantDeny, tc.wantBlock)
			}
		})
	}
}
