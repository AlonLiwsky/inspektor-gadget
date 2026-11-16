// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"strings"
	"testing"
)

func nameValidatorFixture(t *testing.T, names []string) *KernelProgram {
	t.Helper()
	p := base()
	for i := range names {
		p.Rules = append(p.Rules, Rule{Name: fmt.Sprintf("initial-%d", i), Action: Allow})
	}
	program, err := CompileKernel([]Policy{p}, 1, "worker")
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range names {
		program.Rules[i].Name = name
	}
	return program
}

func TestValidatorRuleNameSemantics(t *testing.T) {
	for name, values := range map[string][]string{
		"same": {"same", "same"}, "delimiter": {"1/a/b", "1/a/b"}, "unicode": {"界/λ", "界/λ"},
		"maximum bytes": {strings.Repeat("x", MaxStringBytes), strings.Repeat("x", MaxStringBytes)},
	} {
		t.Run(name, func(t *testing.T) {
			p := nameValidatorFixture(t, values)
			if err := ValidateKernelProgram(p); err == nil || err.Error() != "duplicate rule name" {
				t.Fatalf("duplicate result: %v", err)
			}
		})
	}
	p := nameValidatorFixture(t, []string{"0/x", "1/x", "x", "/x", "x/", "界", "λ"})
	if err := ValidateKernelProgram(p); err != nil {
		t.Fatal("distinct hostile names collided", err)
	}
	policies := []Policy{base(), base()}
	policies[1].ID = "other"
	for i := range policies {
		policies[i].Rules = []Rule{{Name: "same", Action: Allow}}
	}
	p, err := CompileKernel(policies, 1, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateKernelProgram(p); err != nil {
		t.Fatal("same name across policies rejected", err)
	}
}

func TestValidatorRuleNameErrorOrder(t *testing.T) {
	cases := []struct {
		name, want string
		change     func(*KernelProgram)
	}{
		{"duplicate before revision", "duplicate rule name", func(p *KernelProgram) { p.Rules[1].Revision = "changed" }},
		{"metadata before duplicate", "rule policy metadata mismatch", func(p *KernelProgram) { p.Rules[1].PolicyID = "different" }},
		{"revision before duplicate", "string must contain 1..255 non-NUL bytes", func(p *KernelProgram) { p.Rules[1].Revision = "" }},
		{"name before duplicate", "string must contain 1..255 non-NUL bytes", func(p *KernelProgram) { p.Rules[1].Name = "" }},
		{"origin before duplicate", "string must contain 1..255 non-NUL bytes", func(p *KernelProgram) { p.Rules[1].Origin = "\x00" }},
		{"invalid first record", "string must contain 1..255 non-NUL bytes", func(p *KernelProgram) { p.Rules[0].Name = "\x00" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := nameValidatorFixture(t, []string{"same", "same"})
			tc.change(p)
			err := ValidateKernelProgram(p)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v want %s", err, tc.want)
			}
		})
	}
}

func TestValidatorRuleNamesFullCapacity(t *testing.T) {
	names := make([]string, MaxRules)
	for i := range names {
		names[i] = fmt.Sprintf("%03d/λ", i)
	}
	p := nameValidatorFixture(t, names)
	if err := ValidateKernelProgram(p); err != nil {
		t.Fatal("full rule capacity rejected", err)
	}
	p.Rules[MaxRules-1].Name = p.Rules[0].Name
	if err := ValidateKernelProgram(p); err == nil || err.Error() != "duplicate rule name" {
		t.Fatal("last/first duplicate missed", err)
	}
}
