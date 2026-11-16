// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"testing"
)

func capacityPolicies(count, rules int) []Policy {
	policies := make([]Policy, count)
	for i := range policies {
		policies[i] = base()
		policies[i].ID = fmt.Sprintf("policy-%d", i)
		for j := 0; j < rules; j++ {
			policies[i].Rules = append(policies[i].Rules, Rule{Name: fmt.Sprintf("rule-%d", j), Action: Allow})
		}
	}
	return policies
}

func TestPreparedExactCapacities(t *testing.T) {
	for _, shape := range [][2]int{{1, 0}, {1, 3}, {3, 3}, {8, 32}, {1, 256}} {
		authored := capacityPolicies(shape[0], shape[1])
		reference, err := Compile(authored)
		if err != nil {
			t.Fatal(err)
		}
		native, err := preparePolicies(authored, nativeGlob)
		if err != nil {
			t.Fatal(err)
		}
		if cap(reference.policies) != len(authored) || cap(native.policies) != len(authored) {
			t.Fatalf("policy backing grew beyond exact count %v", shape)
		}
		for i := range authored {
			if cap(reference.policies[i].rules) != shape[1] || cap(native.policies[i].rules) != shape[1] {
				t.Fatalf("rule backing grew beyond exact count %v", shape)
			}
			if shape[1] == 0 && (reference.policies[i].rules != nil || native.policies[i].rules != nil) {
				t.Fatal("zero rules changed nil shape")
			}
		}
	}
}

func TestPreparedCapacityValidationPrecedence(t *testing.T) {
	authored := capacityPolicies(2, 0)
	authored[0].Rules = make([]Rule, MaxRules+10000)
	authored[0].Rules[0] = Rule{Name: "first", Action: "invalid"}
	authored[1].ID = ""
	if p, err := Compile(authored); p != nil || err == nil || err.Error() != "rule first: invalid action" {
		t.Fatal("oversize preparation hid first rule error", err)
	}
	authored = capacityPolicies(2, 128)
	authored[1].Rules = append(authored[1].Rules, Rule{Name: "later", Action: "invalid"})
	if p, err := Compile(authored); p != nil || err == nil || err.Error() != "exec rule capacity exceeds 256" {
		t.Fatal("global overflow validation order changed", err)
	}
	authored[1].Mode = "invalid"
	if p, err := Compile(authored); p != nil || err == nil || err.Error() != "policy policy-1: invalid mode" {
		t.Fatal("policy error must precede rule capacity", err)
	}
	for _, count := range []int{0, MaxPolicies + 1} {
		if p, err := Compile(capacityPolicies(count, 0)); p != nil || err == nil {
			t.Fatal("invalid policy count admitted")
		}
	}
}

func TestPreparedCapacityOwnedRules(t *testing.T) {
	authored := capacityPolicies(1, 3)
	authored[0].Rules[0].Target.Path = []string{"/safe"}
	compiled, err := Compile(authored)
	if err != nil {
		t.Fatal(err)
	}
	native, err := preparePolicies(authored, nativeGlob)
	if err != nil {
		t.Fatal(err)
	}
	authored[0].Rules[0].Name = "changed"
	authored[0].Rules[0].Target.Path[0] = "/changed"
	if compiled.policies[0].rules[0].source.Name != "rule-0" || native.policies[0].rules[0].source.Name != "rule-0" || compiled.policies[0].rules[0].source.Target.Path[0] != "/safe" || native.policies[0].rules[0].source.Target.Path[0] != "/safe" {
		t.Fatal("preallocation aliased authored storage")
	}
}

func TestPreparedOversizedAuthoredProcessingBound(t *testing.T) {
	authored := capacityPolicies(1, 0)
	authored[0].Rules = make([]Rule, MaxRules+10000)
	for i := range authored[0].Rules {
		authored[0].Rules[i] = Rule{Name: fmt.Sprintf("rule-%d", i), Action: Allow, Target: Target{Path: []string{"/same"}}}
	}
	calls := 0
	prepared, err := preparePolicies(authored, func(pattern string) (nativePath, error) { calls++; return nativeGlob(pattern) })
	if prepared != nil || err == nil || err.Error() != "exec rule capacity exceeds 256" || calls != MaxRules {
		t.Fatal("oversized authoring processed beyond bounded capacity", calls, err)
	}
	// No empty slice is introduced for either spelling of zero authored rules.
	for _, rules := range [][]Rule{nil, {}} {
		authored[0].Rules = rules
		prepared, err = preparePolicies(authored, nativeGlob)
		if err != nil || prepared.policies[0].rules != nil || prepared.policies[0].source.Rules != nil {
			t.Fatal("nil/empty rule behavior changed", err)
		}
	}
}
