// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
)

var compatibilityGlobs = []string{
	"/bin/tool", "/bin/*", "/bin/**", "/bin/?", "/λ/界*", "/[abc]", "/[a-c]", "/[^a-c]", "/[α-ω]", `/[\d]`, `/\*`, `/\?`, `/[\-]`, "/[a]", "/a", "/[a-a]", "/[", "/[]", "/[z-a]", "/trailing\\",
}

type globCompatibility struct {
	Pattern, Expression, Error string
	Matches                    []bool
}
type nativeCompatibility struct {
	Name, ProgramHash string
	EntryCount        int
	Digests           []string
	Classes           []uint32
	Execution         SharedExecutionMetadata
}
type globCompatibilityFixture struct {
	Globs  []globCompatibility
	Native []nativeCompatibility
}

func compatibilityPolicies() map[string][]Policy {
	p := base()
	p.Rules = []Rule{{Name: "patterns", Action: Allow, Actor: Actor{Path: []string{"/usr/**"}, Ancestor: &Ancestor{Path: []string{"/sbin/?nit"}, Depth: 2}}, Target: Target{Path: compatibilityGlobs[:16]}}}
	large := base()
	for i := 0; i < MaxRules; i++ {
		large.Rules = append(large.Rules, Rule{Name: fmt.Sprintf("rule-%03d", i), Action: Allow, Target: Target{Path: []string{fmt.Sprintf("/long/path/number/%03d", i)}}})
	}
	return map[string][]Policy{"vocabulary": kernelFixture(), "patterns": {p}, "large-256": {large}}
}

func captureGlobCompatibility(t *testing.T) globCompatibilityFixture {
	t.Helper()
	var got globCompatibilityFixture
	for _, pattern := range compatibilityGlobs {
		row := globCompatibility{Pattern: pattern}
		re, err := glob(pattern)
		if err != nil {
			row.Error = err.Error()
		} else {
			row.Expression = re.String()
			for _, path := range []string{"/bin/tool", "/bin/sub/tool", "/λ/界foo", "/a", "/b", "/d", "/*", "/?", "/-", "/α"} {
				row.Matches = append(row.Matches, re.MatchString(path))
			}
		}
		got.Globs = append(got.Globs, row)
	}
	fixtures := compatibilityPolicies()
	for _, name := range []string{"vocabulary", "patterns", "large-256"} {
		policies := fixtures[name]
		program, err := CompileKernel(policies, 77, "worker")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, err := json.Marshal(program)
		if err != nil {
			t.Fatal(err)
		}
		row := nativeCompatibility{Name: name, ProgramHash: fmt.Sprintf("%x", sha256.Sum256(data)), EntryCount: len(program.Entries)}
		var refs []SharedPolicyRef
		for _, policy := range policies {
			object, err := CompileSharedPolicy(policy)
			if err != nil {
				t.Fatal(err)
			}
			row.Digests = append(row.Digests, fmt.Sprintf("%x", object.Digest()))
			class, err := object.ExecutionClass()
			if err != nil {
				t.Fatal(err)
			}
			row.Classes = append(row.Classes, class)
			refs = append(refs, SharedPolicyRef{Object: object, RootEpoch: 1})
		}
		snapshot, err := NewSharedSnapshot(1, 77, "worker", refs)
		if err != nil {
			t.Fatal(err)
		}
		row.Execution, err = snapshot.ExecutionMetadata()
		if err != nil {
			t.Fatal(err)
		}
		got.Native = append(got.Native, row)
	}
	return got
}

func TestGlobAndNativeCompatibility(t *testing.T) {
	got := captureGlobCompatibility(t)
	data, err := os.ReadFile("testdata/glob_compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	var want globCompatibilityFixture
	if err = json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compiler compatibility changed\ngot: %+v\nwant: %+v", got, want)
	}
}

// The expression is an internal compatibility boundary, not a new glob parser.
func TestGlobExpressionCompatibility(t *testing.T) {
	data, err := os.ReadFile("testdata/glob_compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture globCompatibilityFixture
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Globs {
		t.Run(row.Pattern, func(t *testing.T) {
			expression, err := globExpression(row.Pattern)
			if row.Error != "" {
				if err == nil || err.Error() != row.Error {
					t.Fatalf("error=%v want=%s", err, row.Error)
				}
				return
			}
			if err != nil || expression != row.Expression {
				t.Fatalf("expression=%q err=%v want=%q", expression, err, row.Expression)
			}
		})
	}
}

func TestGlobExpressionDedupAndOrder(t *testing.T) {
	p := base()
	// Equivalent expression spellings must share matcher code while retaining
	// authored list positions/count; semantic equivalence alone is not dedup.
	p.Rules = []Rule{{Name: "dedup", Action: Allow, Target: Target{Path: []string{"/a", "/[a]", "/[a-a]", "/b", "/a"}}}}
	program, err := CompileKernel([]Policy{p}, 1, "worker")
	if err != nil {
		t.Fatal(err)
	}
	rule := mustDecode[KernelRule](t, program, KernelRuleBase)
	if rule.TargetPath.Count != 5 {
		t.Fatal("authored list changed")
	}
	var descriptors [5]KernelPattern
	for i := range descriptors {
		descriptors[i] = mustDecode[KernelPattern](t, program, rule.TargetPath.Base+uint32(i))
	}
	if descriptors[0] != descriptors[4] || descriptors[0] == descriptors[3] {
		t.Fatal("expression dedup/order changed")
	}
	// Compare expression equivalence directly; singleton classes retain their
	// canonical range spelling and need not collapse to a literal expression.
	expressions := make([]string, 5)
	for i, path := range p.Rules[0].Target.Path {
		expressions[i], err = globExpression(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range descriptors {
		for j := range descriptors {
			if (expressions[i] == expressions[j]) != (descriptors[i] == descriptors[j]) {
				t.Fatalf("dedup differs at %d,%d", i, j)
			}
		}
	}
}

func TestNativePreparationCommonValidation(t *testing.T) {
	cases := map[string]func(*Policy){
		"actor path":    func(p *Policy) { p.Rules[0].Actor.Path = []string{"/["} },
		"target path":   func(p *Policy) { p.Rules[0].Target.Path = []string{"relative"} },
		"ancestor path": func(p *Policy) { p.Rules[0].Actor.Ancestor = &Ancestor{Depth: 1, Path: []string{"/["}} },
		"ancestor depth": func(p *Policy) {
			p.Rules[0].Actor.Ancestor = &Ancestor{Depth: MaxAncestorDepth + 1, Path: []string{"/ok"}}
		},
		"uid":           func(p *Policy) { p.Rules[0].Actor.UID = []int64{-1} },
		"filesystem":    func(p *Policy) { p.Rules[0].Target.FSType = []string{"invalid"} },
		"argv empty":    func(p *Policy) { p.Rules[0].Target.Argv = &Argv{} },
		"argv invalid":  func(p *Policy) { p.Rules[0].Target.Argv = &Argv{Contains: []string{""}} },
		"container":     func(p *Policy) { p.Rules[0].Actor.Container = []string{""} },
		"role":          func(p *Policy) { p.Rules[0].Actor.Role = []string{""} },
		"deny set role": func(p *Policy) { p.Rules[0].Action = Deny; p.Rules[0].Target.SetRole = "worker" },
		"rule mode":     func(p *Policy) { p.Rules[0].Mode = "invalid" },
		"policy mode":   func(p *Policy) { p.Mode = "invalid" },
		"default":       func(p *Policy) { p.Default = "invalid" },
		"name":          func(p *Policy) { p.Rules[0].Name = "" },
		"origin":        func(p *Policy) { p.Rules[0].Origin = "\x00" },
		"revision":      func(p *Policy) { p.Revision = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base()
			p.Mode = Audit
			// A preceding unconditional rule must not short-circuit source validation.
			p.Rules = []Rule{{Name: "invalid", Action: Allow}}
			mutate(&p)
			p.Rules = append([]Rule{{Name: "first", Action: Deny}}, p.Rules...)
			reference, referenceErr := Compile([]Policy{p})
			native, nativeErr := CompileKernel([]Policy{p}, 1, "worker")
			shared, sharedErr := CompileSharedPolicy(p)
			if reference != nil || native != nil || shared != nil || referenceErr == nil || nativeErr == nil || sharedErr == nil {
				t.Fatal("invalid source reached a backend")
			}
			if referenceErr.Error() != nativeErr.Error() || referenceErr.Error() != sharedErr.Error() {
				t.Fatalf("validation divergence: reference=%v native=%v shared=%v", referenceErr, nativeErr, sharedErr)
			}
		})
	}
}

func TestNativeLimitsDoNotRestrictReferenceCompile(t *testing.T) {
	p := base()
	// Nine disjoint ranges are valid reference glob syntax, but exceed the native
	// instruction's eight-range representation. That must remain a native limit.
	p.Rules = []Rule{{Name: "ranges", Action: Allow, Target: Target{Path: []string{"/[acegikmoq]"}}}}
	reference, err := Compile([]Policy{p})
	if err != nil || reference == nil {
		t.Fatalf("reference rejected: %v", err)
	}
	if !reference.policies[0].rules[0].target[0].MatchString("/a") || reference.policies[0].rules[0].target[0].MatchString("/b") {
		t.Fatal("reference matcher missing or changed")
	}
	if _, err = CompileKernel([]Policy{p}, 1, "worker"); err == nil {
		t.Fatal("native accepted excess ranges")
	}
	if _, err = CompileSharedPolicy(p); err == nil {
		t.Fatal("shared native accepted excess ranges")
	}
}
