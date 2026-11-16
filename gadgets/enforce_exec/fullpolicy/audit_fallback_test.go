// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"reflect"
	"testing"
)

func TestAuditUncertainFallbackDecision(t *testing.T) {
	const id = "audit-policy"
	for _, tc := range []struct {
		name                                        string
		mode                                        Mode
		fallback                                    Action
		fromImage                                   *bool
		setRole                                     string
		knownDeny                                   bool
		wantAction                                  Action
		wantMode                                    Mode
		wantBlock, wantFallback, wantSuppress       bool
		wantUnknown, wantUncertainRole, wantWriting bool
		wantRole, wantRule                          string
	}{
		{name: "unknown-audit-allow", mode: Audit, fallback: Deny, setRole: "tool", wantAction: Deny, wantMode: Audit, wantFallback: true, wantSuppress: true, wantUnknown: true, wantUncertainRole: true, wantWriting: true},
		{name: "unknown-allow-without-role", mode: Audit, fallback: Deny, wantAction: Deny, wantMode: Audit, wantFallback: true, wantSuppress: true, wantUnknown: true},
		{name: "known-matching-allow", mode: Audit, fallback: Deny, fromImage: ptr(true), setRole: "tool", wantAction: Allow, wantMode: Audit, wantWriting: true, wantRole: "tool", wantRule: "image-allow"},
		{name: "known-nonmatching-allow", mode: Audit, fallback: Deny, fromImage: ptr(false), setRole: "tool", wantAction: Deny, wantMode: Audit, wantSuppress: true},
		{name: "unknown-allow-with-allow-default", mode: Audit, fallback: Allow, setRole: "tool", wantAction: Allow, wantMode: Audit, wantUnknown: true, wantUncertainRole: true, wantWriting: true},
		{name: "enforced-default-is-not-uncertain-audit-fallback", mode: Enforce, fallback: Deny, setRole: "tool", wantAction: Deny, wantMode: Enforce, wantBlock: true, wantSuppress: true, wantUnknown: true, wantUncertainRole: true, wantWriting: true},
		{name: "known-audit-deny-is-not-fallback", mode: Audit, fallback: Deny, setRole: "tool", knownDeny: true, wantAction: Deny, wantMode: Audit, wantSuppress: true, wantUnknown: true, wantUncertainRole: true, wantWriting: true, wantRule: "known-deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{
				ID: id, Revision: "revision", Mode: tc.mode, RootRole: "agent", Default: tc.fallback,
				Rules: []Rule{{Name: "image-allow", Mode: Audit, Action: Allow, Target: Target{FromImage: ptr(true), SetRole: tc.setRole}}},
			}
			if tc.knownDeny {
				p.Rules = append(p.Rules, Rule{Name: "known-deny", Mode: Audit, Action: Deny})
			}
			facts := Facts{TargetFromImage: tc.fromImage, Roles: map[string]string{id: "existing-role"}}
			got, err := compile(t, p).Evaluate(facts)
			if err != nil {
				t.Fatalf("audit-local unknown became an evaluation error: %v", err)
			}
			want := Decision{
				Action: tc.wantAction, Mode: tc.wantMode, Block: tc.wantBlock,
				UncertainFallback: tc.wantFallback, SuppressRoles: tc.wantSuppress,
				SetRoles: map[string]string{}, AuditUnknown: map[string]bool{},
				UncertainRoles: map[string]bool{}, RoleWrites: map[string]bool{},
			}
			if tc.wantUnknown {
				want.AuditUnknown[id] = true
			}
			if tc.wantUncertainRole {
				want.UncertainRoles[id] = true
			}
			if tc.wantWriting {
				want.RoleWrites[id] = true
			}
			if tc.wantRole != "" {
				want.SetRoles[id] = tc.wantRole
			}
			if tc.wantRule != "" || tc.wantAction == Deny {
				want.Matches = []Match{{PolicyID: id, Revision: p.Revision, Rule: tc.wantRule, Action: tc.wantAction, Mode: tc.wantMode}}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("decision = %+v, want %+v", got, want)
			}
			if !reflect.DeepEqual(facts.Roles, map[string]string{id: "existing-role"}) {
				t.Fatalf("evaluation mutated inherited role state: %v", facts.Roles)
			}
		})
	}
}

func TestAuditUncertainFallbackMergedPolicyOrder(t *testing.T) {
	unknown := Policy{
		ID: "unknown", Revision: "unknown-revision", Mode: Audit, RootRole: "agent",
		Rules: []Rule{{Name: "unknown-allow", Action: Allow, Target: Target{FromImage: ptr(true), SetRole: "uncertain-role"}}},
	}
	fallback := Policy{ID: "fallback", Revision: "fallback-revision", Mode: Audit, Default: Deny}
	for _, tc := range []struct {
		name  string
		extra Policy
		want  Decision
	}{
		{name: "audit-default", extra: Policy{ID: "empty", Revision: "empty-revision", Mode: Audit}, want: Decision{
			Action: Deny, Mode: Audit, UncertainFallback: true, SuppressRoles: true,
			Matches:  []Match{{PolicyID: fallback.ID, Revision: fallback.Revision, Action: Deny, Mode: Audit}},
			SetRoles: map[string]string{}, AuditUnknown: map[string]bool{unknown.ID: true}, UncertainRoles: map[string]bool{unknown.ID: true}, RoleWrites: map[string]bool{unknown.ID: true},
		}},
		{name: "known-allow-suppresses-all-defaults", extra: Policy{
			ID: "known", Revision: "known-revision", Mode: Audit, RootRole: "agent",
			Rules: []Rule{{Name: "known-allow", Action: Allow, Target: Target{SetRole: "known-role"}}},
		}, want: Decision{
			Action: Allow, Mode: Audit,
			Matches:  []Match{{PolicyID: "known", Revision: "known-revision", Rule: "known-allow", Action: Allow, Mode: Audit}},
			SetRoles: map[string]string{"known": "known-role"}, AuditUnknown: map[string]bool{unknown.ID: true}, UncertainRoles: map[string]bool{unknown.ID: true}, RoleWrites: map[string]bool{unknown.ID: true, "known": true},
		}},
		{name: "enforced-default-remains-blocking", extra: Policy{ID: "enforced", Revision: "enforced-revision", Mode: Enforce, Default: Deny}, want: Decision{
			Action: Deny, Mode: Enforce, Block: true, SuppressRoles: true,
			Matches:  []Match{{PolicyID: "enforced", Revision: "enforced-revision", Action: Deny, Mode: Enforce}, {PolicyID: fallback.ID, Revision: fallback.Revision, Action: Deny, Mode: Audit}},
			SetRoles: map[string]string{}, AuditUnknown: map[string]bool{unknown.ID: true}, UncertainRoles: map[string]bool{unknown.ID: true}, RoleWrites: map[string]bool{unknown.ID: true},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policies := []Policy{unknown, fallback, tc.extra}
			for first := range policies {
				for second := range policies {
					if first == second {
						continue
					}
					third := 3 - first - second
					got, err := compile(t, policies[first], policies[second], policies[third]).Evaluate(Facts{})
					if err != nil || !reflect.DeepEqual(got, tc.want) {
						t.Fatalf("order %d,%d,%d: decision = %+v, err = %v; want %+v", first, second, third, got, err, tc.want)
					}
				}
			}
		})
	}
}
