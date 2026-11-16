// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullpolicy

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSharedPolicyScopeNeutral(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "container", Action: Allow, Actor: Actor{Container: []string{"app"}}}}
	a, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("identical content differs")
	}
	legacyBefore, err := CompileKernelWithRoleEpochs([]Policy{p}, 9, "scope-observation", map[string]uint64{p.ID: 3})
	if err != nil {
		t.Fatal(err)
	}
	entries := a.Entries()
	rule, _ := Decode[KernelRule](entries[KernelRuleBase])
	authored, _ := Decode[KernelString](entries[rule.Container.Base])
	if rule.PolicyIndex != 0 || string(authored.Bytes[:authored.Length]) != "app" {
		t.Fatal("authored predicate/index changed")
	}
	legacyAfter, err := CompileKernelWithRoleEpochs([]Policy{p}, 9, "scope-observation", map[string]uint64{p.ID: 3})
	if err != nil || !reflect.DeepEqual(legacyBefore, legacyAfter) {
		t.Fatal("legacy compiler changed", err)
	}
	h, _ := Decode[KernelHeader](entries[0])
	k, _ := Decode[KernelPolicy](entries[1])
	if h.Generation != 0 || h.ContainerRef != 0 || k.RootEpoch != 0 {
		t.Fatal("scope facts embedded")
	}
	entries[1][0] ^= 1
	if !a.Equal(b) {
		t.Fatal("caller mutated immutable object")
	}
	sa, err := NewSharedSnapshot(11, 7, "app", []SharedPolicyRef{{Object: a, RootEpoch: 2}})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := NewSharedSnapshot(12, 9, "sidecar", []SharedPolicyRef{{Object: b, RootEpoch: 8}})
	if err != nil {
		t.Fatal(err)
	}
	if sa.ScopeCookie == sb.ScopeCookie || sa.Policies[0].RootEpoch == sb.Policies[0].RootEpoch || !sa.Policies[0].Object.Equal(sb.Policies[0].Object) {
		t.Fatal("scope/compiled ownership conflated")
	}
	for _, epoch := range []uint64{0, 10, UnknownRoleEpoch} {
		if _, err := NewSharedSnapshot(12, 9, "app", []SharedPolicyRef{{Object: a, RootEpoch: epoch}}); err == nil {
			t.Fatal("invalid epoch admitted")
		}
	}
	p.Rules[0].Action = Deny
	c, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(c) {
		t.Fatal("semantic change deduplicated")
	}
}

func TestSharedPolicyIdentityModeAndUnionCaps(t *testing.T) {
	p := base()
	a, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Policy){func(p *Policy) { p.ID = "other" }, func(p *Policy) { p.Mode = Audit }, func(p *Policy) { p.Default = Deny }, func(p *Policy) { p.RootRole = "other-role" }} {
		q := p
		change(&q)
		b, e := CompileSharedPolicy(q)
		if e != nil {
			t.Fatal(e)
		}
		if a.Equal(b) {
			t.Fatal("distinct identity/semantics deduplicated")
		}
	}
	q := p
	q.Revision = "next-provenance"
	b, err := CompileSharedPolicy(q)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("revision provenance entered object")
	}
	if _, err := NewSharedSnapshot(1, 1, "app", []SharedPolicyRef{{a, 1}, {a, 1}}); err == nil {
		t.Fatal("duplicate UID")
	}
	p.Rules = make([]Rule, 129)
	for i := range p.Rules {
		p.Rules[i] = Rule{Name: fmt.Sprint(i), Action: Allow}
	}
	a, err = CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = "other"
	b, err = CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSharedSnapshot(1, 1, "app", []SharedPolicyRef{{a, 1}, {b, 1}}); err == nil {
		t.Fatal("union exceeded 256 rules")
	}
}

func sharedCapacityPolicies(kind string, count, amount int) []Policy {
	policies := make([]Policy, count)
	for n := range policies {
		p := base()
		p.ID = fmt.Sprintf("policy-%d", n)
		switch kind {
		case "patterns":
			for left := amount; left > 0; {
				size := min(left, MaxValues)
				paths := make([]string, size)
				for i := range paths {
					paths[i] = "/same"
				}
				p.Rules = append(p.Rules, Rule{Name: fmt.Sprint(left), Action: Allow, Target: Target{Path: paths}})
				left -= size
			}
		case "instructions":
			paths := make([]string, amount)
			for i := range paths {
				paths[i] = fmt.Sprintf("/%s-%d-%03d", strings.Repeat("x", 50), n, i)
			}
			p.Rules = []Rule{{Name: "long-paths", Action: Allow, Target: Target{Path: paths}}}
		case "strings":
			values := make([]string, MaxValues)
			for i := range values {
				values[i] = "literal"
			}
			for i := 0; i < amount; i++ {
				p.Rules = append(p.Rules, Rule{Name: fmt.Sprint(i), Action: Allow, Actor: Actor{Container: values}, Target: Target{Argv: &Argv{Contains: values, Prefix: values}}})
			}
		case "values":
			values := make([]int64, MaxValues)
			for i := 0; i < amount; i++ {
				p.Rules = append(p.Rules, Rule{Name: fmt.Sprint(i), Action: Allow, Actor: Actor{UID: values}})
			}
		}
		policies[n] = p
	}
	return policies
}

func TestSharedSnapshotWholeUnionCapacity(t *testing.T) {
	cases := []struct {
		name, kind, diagnostic string
		count, valid, invalid  int
	}{
		{"pattern-count-two", "patterns", "pattern capacity", 2, 512, 513},
		{"pattern-count-eight", "patterns", "pattern capacity", 8, 128, 129},
		{"matcher-instructions", "instructions", "regex instructions", 2, 60, 80},
		{"string-blob-entries", "strings", "entry capacity", 2, 10, 11},
		{"value-blob-entries", "values", "entry capacity", 2, 31, 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, over := range []bool{false, true} {
				amount := tc.valid
				if over {
					amount = tc.invalid
				}
				policies := sharedCapacityPolicies(tc.kind, tc.count, amount)
				_, unionErr := CompileKernel(policies, 1, "app")
				if over && (unionErr == nil || !strings.Contains(unionErr.Error(), tc.diagnostic)) {
					t.Fatalf("fixture failed to exceed intended union cap: %v", unionErr)
				}
				if !over && unionErr != nil {
					t.Fatalf("within-boundary fixture: %v", unionErr)
				}
				refs := make([]SharedPolicyRef, len(policies))
				for i, p := range policies {
					object, err := CompileSharedPolicy(p)
					if err != nil {
						t.Fatalf("individual object %d invalid: %v", i, err)
					}
					refs[i] = SharedPolicyRef{Object: object, RootEpoch: 1}
				}
				// Caller cannot erase the authored capacity demand after the
				// independently compiled objects have retained their provenance.
				if over {
					for _, p := range policies {
						for i := range p.Rules {
							p.Rules[i] = Rule{Name: fmt.Sprint(i), Action: Allow}
						}
					}
				}
				_, err := NewSharedSnapshot(1, 1, "app", refs)
				if (err != nil) != over {
					t.Fatalf("snapshot did not match whole native union admission: over=%v error=%v", over, err)
				}
			}
		})
	}
}

func TestSharedPolicyRetainsOnlyCompilerOwnedSource(t *testing.T) {
	p := base()
	p.Rules = []Rule{{
		Name: "all", Origin: "authored", Action: Allow, Mode: Audit,
		Actor:  Actor{Path: []string{"/actor"}, FromImage: ptr(true), Ancestor: &Ancestor{Path: []string{"/init"}, Depth: 2}, Role: []string{"agent"}, UID: []int64{1000}, Container: []string{"app"}},
		Target: Target{Path: []string{"/target"}, FromImage: ptr(false), FSType: []string{"tmpfs"}, Argv: &Argv{Contains: []string{"--arg"}, Prefix: []string{"--key="}, StdinIsPipe: ptr(true)}, SetRole: "child"},
	}}
	before, err := CompileKernel([]Policy{p}, 7, "app")
	if err != nil {
		t.Fatal(err)
	}
	object, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	twin, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	r := &p.Rules[0]
	r.Actor.Path[0] = "relative"
	*r.Actor.FromImage = false
	r.Actor.Ancestor.Path[0] = "relative"
	r.Actor.Ancestor.Depth = 0
	r.Actor.Role[0] = "changed"
	r.Actor.UID[0] = -1
	r.Actor.Container[0] = "changed"
	r.Target.Path[0] = "relative"
	*r.Target.FromImage = true
	r.Target.FSType[0] = "invalid"
	r.Target.Argv.Contains[0] = "changed"
	r.Target.Argv.Prefix[0] = "changed"
	*r.Target.Argv.StdinIsPipe = false
	r.Target.SetRole = "changed"
	r.Name = ""
	r.Origin = "changed"
	r.Action = Deny
	r.Mode = Enforce
	p.ID = "changed"
	p.Revision = "changed"
	p.Mode = Audit
	p.RootRole = "changed"
	p.Default = Deny
	p.Rules[0] = Rule{}
	p.Rules = nil
	refs := []SharedPolicyRef{{Object: object, RootEpoch: 2}}
	snapshot, err := NewSharedSnapshot(11, 7, "app", refs)
	if err != nil {
		t.Fatal("caller mutation changed admission", err)
	}
	refs[0] = SharedPolicyRef{}
	if snapshot.Policies[0].Object != object || snapshot.Policies[0].RootEpoch != 2 {
		t.Fatal("snapshot retained caller ref slice")
	}
	retained, err := CompileKernel([]Policy{*object.source}, 7, "app")
	if err != nil || !reflect.DeepEqual(before, retained) || !object.Equal(twin) {
		t.Fatal("compiler source or canonical content aliases authored policy", err)
	}
	forged := *object
	forged.source = nil
	if _, err := NewSharedSnapshot(11, 7, "app", []SharedPolicyRef{{Object: &forged, RootEpoch: 2}}); err == nil {
		t.Fatal("snapshot admitted object without compiler-owned provenance")
	}
}

func TestSharedSnapshotPreservesUnionDefaults(t *testing.T) {
	a := base()
	a.ID = "default-deny"
	a.Default = Deny
	b := base()
	b.ID = "allow-rule"
	b.Default = ""
	b.Rules = []Rule{{Name: "known-match", Action: Allow, Target: Target{Path: []string{"/allowed"}}}}
	var refs []SharedPolicyRef
	for _, p := range []Policy{a, b} {
		object, err := CompileSharedPolicy(p)
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, SharedPolicyRef{Object: object, RootEpoch: 1})
	}
	snapshot, err := NewSharedSnapshot(1, 1, "app", refs)
	if err != nil {
		t.Fatal(err)
	}
	sources := make([]Policy, len(snapshot.Policies))
	for i, ref := range snapshot.Policies {
		sources[i] = *ref.Object.source
	}
	// Reuse the existing union evaluator as a semantic oracle, not a shared
	// kernel execution claim or independent-per-policy deny composition.
	for _, path := range []string{"/allowed", "/unmatched"} {
		want, err := compile(t, a, b).Evaluate(Facts{TargetPath: path})
		if err != nil {
			t.Fatal(err)
		}
		got, err := compile(t, sources...).Evaluate(Facts{TargetPath: path})
		if err != nil || !reflect.DeepEqual(want, got) {
			t.Fatal("source admission changed union defaults", got, want, err)
		}
		if got.Block != (path == "/unmatched") {
			t.Fatal("known allow failed to suppress cross-policy default", got)
		}
	}
}

func TestSharedSnapshotUsesNativeMatcherDedupBudget(t *testing.T) {
	policies := sharedCapacityPolicies("instructions", 2, 80)
	policies[1].Rules[0].Target.Path = append([]string(nil), policies[0].Rules[0].Target.Path...)
	if _, err := CompileKernel(policies, 1, "app"); err != nil {
		t.Fatal("deduplicated union must fit", err)
	}
	refs := make([]SharedPolicyRef, len(policies))
	for i, p := range policies {
		object, err := CompileSharedPolicy(p)
		if err != nil {
			t.Fatal(err)
		}
		refs[i] = SharedPolicyRef{Object: object, RootEpoch: 1}
	}
	if _, err := NewSharedSnapshot(1, 1, "app", refs); err != nil {
		t.Fatal("independent-object instruction sums replaced native dedup admission", err)
	}
}

func TestSharedSnapshotExecutionMetadataOrderAndOwnership(t *testing.T) {
	policies := []Policy{
		{ID: "z-writer", Revision: "r", RootRole: "root", Mode: Enforce, Rules: []Rule{{Name: "write", Action: Allow, Target: Target{SetRole: "next"}}}},
		{ID: "a-deny", Revision: "r", RootRole: "root", Mode: Audit, Rules: []Rule{{Name: "deny", Action: Deny, Actor: Actor{Role: []string{"root"}}}}},
		{ID: "b-default", Revision: "r", RootRole: "root", Mode: Audit, Default: Deny},
		{ID: "c-exception", Revision: "r", RootRole: "root", Mode: Audit, Rules: []Rule{{Name: "exception", Action: Allow, Actor: Actor{Role: []string{"root"}}}}},
		{ID: "d-writer", Revision: "r", RootRole: "root", Mode: Audit, Rules: []Rule{{Name: "write", Action: Allow, Actor: Actor{Role: []string{"root"}}, Target: Target{SetRole: "next"}}}},
		{ID: "e-plain", Revision: "r", RootRole: "root", Mode: Audit, Default: Allow},
		{ID: "f-role", Revision: "r", RootRole: "root", Mode: Enforce, Rules: []Rule{{Name: "role", Action: Allow, Actor: Actor{Role: []string{"root"}}}}},
		{ID: "g-audit", Revision: "r", RootRole: "root", Mode: Audit},
	}
	refs := make([]SharedPolicyRef, len(policies))
	for i, p := range policies {
		object, err := CompileSharedPolicy(p)
		if err != nil {
			t.Fatal(err)
		}
		refs[i] = SharedPolicyRef{Object: object, RootEpoch: 1}
	}
	for rotation := 0; rotation < len(refs); rotation++ {
		ordered := append(append([]SharedPolicyRef(nil), refs[rotation:]...), refs[:rotation]...)
		snapshot, err := NewSharedSnapshot(7, 2, "app", ordered)
		if err != nil {
			t.Fatal(err)
		}
		summary, err := snapshot.ExecutionMetadata()
		if err != nil {
			t.Fatal(err)
		}
		var writers, required uint32
		for i, ref := range ordered {
			for original, source := range refs {
				if ref.Object == source.Object {
					if original == 0 || original == 4 {
						writers |= 1 << i
					}
					if original == 1 || original == 3 || original == 4 || original == 6 {
						required |= 1 << i
					}
				}
			}
		}
		if summary.PolicyCount != 8 || summary.ExecutionClass != 2 || summary.RoleWriters != writers || summary.RequiredKnown != required {
			t.Fatalf("rotation%d summary%+v want writers%x required%x", rotation, summary, writers, required)
		}
		summary.RequiredKnown = 0
		again, err := snapshot.ExecutionMetadata()
		if err != nil || again.RequiredKnown != required {
			t.Fatal("returned summary aliases compiler state")
		}
		snapshot.Policies[0], snapshot.Policies[1] = snapshot.Policies[1], snapshot.Policies[0]
		if _, err := snapshot.ExecutionMetadata(); err == nil {
			t.Fatal("reordered mutable refs used stale metadata")
		}
	}
	if _, err := (SharedSnapshot{}).ExecutionMetadata(); err == nil {
		t.Fatal("uncompiled snapshot supplied metadata")
	}
}
