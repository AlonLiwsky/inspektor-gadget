// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

func TestSharedPolicyPrepareFailureInvalidatesView(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "policy-prepare")
			args := []string{
				"-std=gnu11", optimization, "-Wall", "-Wextra", "-Werror",
				"-iquote", root, "-iquote", filepath.Join(root, "../fullpolicy/bpf"),
				"testdata/shared_policy_prepare.c", "-o", binary,
			}
			if out, err := exec.CommandContext(t.Context(), cc, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile policy prepare: %v\n%s", err, out)
			}
			if out, err := exec.CommandContext(t.Context(), binary).CombinedOutput(); err != nil {
				t.Fatalf("policy prepare: %v\n%s", err, out)
			}
		})
	}
}

// Runs the existing evaluator/matcher over both unchanged native union blobs
// and shared objects, including the GLOBAL matcher refetch path. This is host
// helper parity, not verifier, retained-map lifetime or kernel readiness proof.
func TestSharedPolicyLookupActualEvaluator(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binaries := map[string]string{}
	for _, mode := range []string{"oracle", "context", "global"} {
		binary := filepath.Join(t.TempDir(), mode)
		args := []string{"-std=gnu11", "-DENFORCE_EXEC_ABI3_DEVELOPMENT", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "-iquote", filepath.Join(root, "../fullpolicy/bpf")}
		if mode == "oracle" {
			args = append(args, "-DSE_LOOKUP_ORACLE")
		}
		if mode == "global" {
			args = append(args, "-DSE_LOOKUP_GLOBAL")
		}
		args = append(args, "testdata/shared_policy_lookup.c", "-o", binary)
		if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
			t.Fatalf("compile %s: %v\n%s", mode, err, out)
		}
		binaries[mode] = binary
	}
	if out, err := exec.Command(binaries["context"], "--layout").CombinedOutput(); err != nil {
		t.Fatal(err)
	} else {
		t.Log(string(out))
	}
	base := func(id string) fullpolicy.Policy {
		return fullpolicy.Policy{ID: id, Revision: "r", Mode: fullpolicy.Enforce, RootRole: "agent", Default: fullpolicy.Deny}
	}
	rule := func(name string, action fullpolicy.Action) fullpolicy.Rule {
		return fullpolicy.Rule{Name: name, Action: action, Target: fullpolicy.Target{Path: []string{"/allowed"}}}
	}
	type fixture struct {
		name      string
		policies  []fullpolicy.Policy
		container string
		scenario  uint32
	}
	a, b := base("p0"), base("p1")
	b.Rules = []fullpolicy.Rule{rule("allow", fullpolicy.Allow)}
	cases := []fixture{{"known-allow-suppresses-union-default", []fullpolicy.Policy{a, b}, "app", 0}}
	cases = append(cases, fixture{"defaults-only-no-selected-object", []fullpolicy.Policy{base("p0"), base("p1")}, "app", 0})
	a.Rules = []fullpolicy.Rule{rule("allow", fullpolicy.Allow)}
	b.Rules = []fullpolicy.Rule{rule("deny", fullpolicy.Deny)}
	cases = append(cases, fixture{"known-deny-wins", []fullpolicy.Policy{a, b}, "app", 0})
	b.Mode = fullpolicy.Audit
	cases = append(cases, fixture{"audit-deny-not-enforced", []fullpolicy.Policy{a, b}, "app", 0})
	a = base("p0")
	b = base("p1")
	b.Mode = fullpolicy.Audit
	b.Rules = []fullpolicy.Rule{rule("audit-path", fullpolicy.Allow)}
	cases = append(cases, fixture{"audit-object-data-fault", []fullpolicy.Policy{a, b}, "app", 32})
	truth := true
	b.Rules = []fullpolicy.Rule{{Name: "audit-image", Action: fullpolicy.Allow, Target: fullpolicy.Target{FromImage: &truth}}}
	cases = append(cases, fixture{"audit-unknown-not-known-match", []fullpolicy.Policy{a, b}, "app", 16})
	a = base("p0")
	b = base("p1")
	b.Default = fullpolicy.Allow
	a.Rules = []fullpolicy.Rule{{Name: "role", Action: fullpolicy.Allow, Actor: fullpolicy.Actor{Role: []string{"agent"}}}}
	cases = append(cases, fixture{"unknown-role-no-bootstrap", []fullpolicy.Policy{a, b}, "app", 1})
	a.Rules = []fullpolicy.Rule{{
		Name: "all", Action: fullpolicy.Allow,
		Actor:  fullpolicy.Actor{Path: []string{"/act*"}, Container: []string{"app"}, Role: []string{"agent"}, UID: []int64{1000}, FromImage: &truth},
		Target: fullpolicy.Target{Path: []string{"/allow?d"}, FromImage: &truth, FSType: []string{"memfd"}, Argv: &fullpolicy.Argv{Contains: []string{"arg"}, Prefix: []string{"ar"}, StdinIsPipe: &truth}, SetRole: "child"},
	}}
	b = base("p1")
	b.Rules = []fullpolicy.Rule{rule("miss-one", fullpolicy.Deny), rule("miss-two", fullpolicy.Allow)}
	b.Rules[0].Target.Path = []string{"/different"}
	b.Rules[1].Target.Path = []string{"/other"}
	for _, variant := range []struct {
		name, container string
		scenario        uint32
	}{{"match", "app", 0}, {"container-miss", "sidecar", 0}, {"uid-miss", "app", 8}, {"actor-unknown", "app", 4}} {
		cases = append(cases, fixture{"local-pattern-numeric-string-" + variant.name, []fullpolicy.Policy{a, b}, variant.container, variant.scenario})
	}
	eight := make([]fullpolicy.Policy, 8)
	for i := range eight {
		eight[i] = base(fmt.Sprintf("p%d", i))
		if i%2 == 1 {
			eight[i].Rules = []fullpolicy.Rule{rule("match", fullpolicy.Allow)}
		}
	}
	cases = append(cases, fixture{"eight-objects-with-empty-rule-ranges", eight, "app", 0})
	writer := func(name, role string) fullpolicy.Rule {
		r := rule(name, fullpolicy.Allow)
		r.Target.SetRole = role
		return r
	}
	a, b = base("p0"), base("p1")
	a.Rules = []fullpolicy.Rule{writer("known", "first")}
	cases = append(cases, fixture{"enforced-write-and-witness", []fullpolicy.Policy{a, b}, "app", 64})
	a.Rules = []fullpolicy.Rule{writer("first", "first"), writer("second", "second")}
	cases = append(cases, fixture{"enforced-role-conflict", []fullpolicy.Policy{a, b}, "app", 128})
	a.Mode = fullpolicy.Audit
	cases = append(cases, fixture{"audit-role-conflict", []fullpolicy.Policy{a, b}, "app", 512})
	a = base("p0")
	a.Rules = []fullpolicy.Rule{writer("known", "first")}
	b.Mode = fullpolicy.Audit
	b.Rules = []fullpolicy.Rule{{Name: "unknown-deny", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{Path: []string{"/actor"}}}}
	cases = append(cases, fixture{"audit-unknown-suppresses-known-proposal", []fullpolicy.Policy{a, b}, "app", 256 | 4})
	b.Mode = fullpolicy.Enforce
	cases = append(cases, fixture{"enforced-unknown-suppresses-known-proposal", []fullpolicy.Policy{a, b}, "app", 1024 | 4})
	b.Mode = fullpolicy.Audit
	b.Rules = []fullpolicy.Rule{{Name: "unknown-write", Action: fullpolicy.Allow, Target: fullpolicy.Target{FromImage: &truth, SetRole: "uncertain"}}}
	cases = append(cases, fixture{"audit-uncertain-write-preserves-known-witness", []fullpolicy.Policy{a, b}, "app", 2048 | 16})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			union, err := fullpolicy.CompileKernel(tc.policies, 9, tc.container)
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.CreateTemp(t.TempDir(), "input")
			if err != nil {
				t.Fatal(err)
			}
			write := func(value any) {
				t.Helper()
				if err := binary.Write(file, binary.LittleEndian, value); err != nil {
					t.Fatal(err)
				}
			}
			write(uint32(len(tc.policies)))
			write(tc.scenario)
			for _, policy := range tc.policies {
				object, err := fullpolicy.CompileSharedPolicy(policy)
				if err != nil {
					t.Fatal(err)
				}
				entries := object.Entries()
				write(uint32(len(entries)))
				write(entries)
			}
			write(uint32(len(union.Entries)))
			write(union.Entries)
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			expected, err := exec.Command(binaries["oracle"], file.Name()).CombinedOutput()
			if err != nil {
				t.Fatalf("oracle: %v\n%s", err, expected)
			}
			for _, mode := range []string{"context", "global"} {
				got, err := exec.Command(binaries[mode], file.Name()).CombinedOutput()
				if err != nil || string(got) != string(expected) {
					t.Fatalf("%s shared evaluator mismatch: %v\ngot %s\nwant %s", mode, err, got, expected)
				}
			}
		})
	}
}
