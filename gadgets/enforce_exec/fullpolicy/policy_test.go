// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"path"
	"reflect"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }
func base() Policy {
	return Policy{ID: "policy-uid", Revision: "revision", Mode: Enforce, RootRole: "agent", Default: Allow}
}

func compile(t *testing.T, policies ...Policy) *Program {
	t.Helper()
	p, e := Compile(policies)
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestFullPredicateConjunction(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "combined", Action: Deny, Actor: Actor{Path: []string{"/usr/bin/*"}, FromImage: ptr(true), Ancestor: &Ancestor{Path: []string{"/init"}, Depth: 2}, Role: []string{"agent"}, UID: []int64{1000}, Container: []string{"app"}}, Target: Target{Path: []string{"/tmp/**/tool?"}, FromImage: ptr(false), FSType: []string{"tmpfs"}, Argv: &Argv{Contains: []string{"-c", "--unsafe"}, Prefix: []string{"--option="}, StdinIsPipe: ptr(true)}}}}
	facts := Facts{RoleBootstrap: true, ActorPath: "/usr/bin/sh", ActorFromImage: ptr(true), Ancestors: []string{"/parent", "/init"}, EffectiveUID: ptr(uint32(1000)), Container: "app", TargetPath: "/tmp/sub/tool1", TargetFromImage: ptr(false), FSType: "tmpfs", Argv: []string{"tool1", "-c", "--option=value"}, ArgvComplete: true, StdinIsPipe: ptr(true)}
	prog := compile(t, p)
	d, e := prog.Evaluate(facts)
	if e != nil || !d.Block {
		t.Fatalf("combined deny: %+v %v", d, e)
	}
	cases := map[string]func(*Facts){"actor": func(f *Facts) { f.ActorPath = "/usr/bin/sub/sh" }, "actorImage": func(f *Facts) { f.ActorFromImage = ptr(false) }, "ancestor": func(f *Facts) { f.Ancestors = []string{"/other", "/not-init"} }, "role": func(f *Facts) { f.Roles = map[string]string{p.ID: "tool"} }, "uid": func(f *Facts) { f.EffectiveUID = ptr(uint32(0)) }, "container": func(f *Facts) { f.Container = "sidecar" }, "target": func(f *Facts) { f.TargetPath = "/opt/tool1" }, "targetImage": func(f *Facts) { f.TargetFromImage = ptr(true) }, "fs": func(f *Facts) { f.FSType = "ext4"; f.FileKindsKnown = []string{"tmpfs"} }, "contains": func(f *Facts) { f.Argv = []string{"--option=value", "prefix-c-suffix"} }, "prefix": func(f *Facts) { f.Argv = []string{"-c", "x--option=value"} }, "stdin": func(f *Facts) { f.StdinIsPipe = ptr(false) }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := facts
			change(&f)
			d, e := prog.Evaluate(f)
			if e != nil || d.Block || d.Action != Allow {
				t.Fatalf("non-match: %+v %v", d, e)
			}
		})
	}
}

func TestUnknownFactsNeverBecomeFalse(t *testing.T) {
	for name, target := range map[string]Target{"image": {FromImage: ptr(false)}, "fs": {FSType: []string{"tmpfs"}}, "argv": {Argv: &Argv{Contains: []string{"-c"}}}, "stdin": {Argv: &Argv{StdinIsPipe: ptr(false)}}} {
		t.Run(name, func(t *testing.T) {
			p := base()
			p.Rules = []Rule{{Name: name, Action: Deny, Target: target}}
			if _, e := compile(t, p).Evaluate(Facts{}); e == nil {
				t.Fatal("unknown fact matched as false")
			}
		})
	}
	p := base()
	p.Rules = []Rule{{Name: "ancestor", Action: Deny, Actor: Actor{Ancestor: &Ancestor{Path: []string{"/root"}, Depth: 3}}}}
	prog := compile(t, p)
	if _, e := prog.Evaluate(Facts{Ancestors: []string{"/one"}}); e == nil {
		t.Fatal("incomplete ancestry accepted")
	}
	if d, e := prog.Evaluate(Facts{Ancestors: []string{"/one"}, AncestorsComplete: true}); e != nil || d.Block {
		t.Fatalf("genuine root: %+v %v", d, e)
	}
}

func TestOrderFreeMixedModesAndDefaults(t *testing.T) {
	p := base()
	p.Default = Deny
	p.Rules = []Rule{{Name: "audit-deny", Action: Deny, Mode: Audit}, {Name: "allow", Action: Allow}, {Name: "enforce-deny", Action: Deny, Mode: Enforce}}
	want, e := compile(t, p).Evaluate(Facts{})
	if e != nil || !want.Block || want.Mode != Enforce {
		t.Fatalf("deny precedence: %+v %v", want, e)
	}
	for i := range p.Rules {
		p.Rules[0], p.Rules[i] = p.Rules[i], p.Rules[0]
		got, e := compile(t, p).Evaluate(Facts{})
		if e != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("order changed decision: %+v %v", got, e)
		}
	}
	p.Rules = []Rule{{Name: "audit-deny", Action: Deny, Mode: Audit}, {Name: "allow", Action: Allow}}
	d, e := compile(t, p).Evaluate(Facts{})
	if e != nil || d.Block || d.Action != Deny || d.Mode != Audit {
		t.Fatalf("audit cannot inherit enforce default: %+v %v", d, e)
	}
	p.Rules = []Rule{{Name: "allow", Action: Allow}}
	d, e = compile(t, p).Evaluate(Facts{})
	if e != nil || d.Block || d.Action != Allow {
		t.Fatalf("matched allow suppresses default: %+v %v", d, e)
	}
	q := base()
	q.ID = "second"
	q.Default = Deny
	d, e = compile(t, p, q).Evaluate(Facts{RoleBootstrap: true})
	if e != nil || d.Block || d.Action != Allow {
		t.Fatalf("merged matching allow shadowed by unrelated default: %+v %v", d, e)
	}
}

func TestPolicyLocalRolesAndSuccessfulExecStaging(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "transition", Action: Allow, Actor: Actor{Role: []string{"agent"}}, Target: Target{SetRole: "tool"}}}
	q := base()
	q.ID = "other"
	q.RootRole = "worker"
	q.Rules = []Rule{{Name: "other-transition", Action: Allow, Actor: Actor{Role: []string{"worker"}}, Target: Target{SetRole: "helper"}}}
	d, e := compile(t, p, q).Evaluate(Facts{RoleBootstrap: true})
	if e != nil || d.SetRoles[p.ID] != "tool" || d.SetRoles[q.ID] != "helper" {
		t.Fatalf("role namespaces: %+v %v", d, e)
	}
	q.Rules = append(q.Rules, Rule{Name: "block", Action: Deny})
	d, e = compile(t, p, q).Evaluate(Facts{RoleBootstrap: true})
	if e != nil || !d.Block || len(d.SetRoles) != 0 {
		t.Fatalf("blocked exec grants role: %+v %v", d, e)
	}
	p.Rules = append(p.Rules, Rule{Name: "conflict", Action: Allow, Target: Target{SetRole: "other"}})
	if _, e := compile(t, p).Evaluate(Facts{RoleBootstrap: true}); e == nil {
		t.Fatal("conflicting roles chosen by order")
	}
}

func TestGlobs(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{{"/bin/*", "/bin/sh", true}, {"/bin/*", "/bin/sub/sh", false}, {"/**", "/a\nb", true}, {"/x?", "/xé", true}, {"/é/*", "/é/工具", true}, {"/bin/[a-z]h", "/bin/sh", true}, {"/[^a]", "/b", true}, {"/[^a]", "//", true}, {"/[.-0]", "//", true}, {"/[/]", "//", true}, {"/a\\*", "/a*", true}, {"/bin/*", "/bin/sh\nother", true}, {"/bin/sh", "/bin/sh-other", false}}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q-%q", tt.pattern, tt.value), func(t *testing.T) {
			r, e := glob(tt.pattern)
			if e != nil {
				t.Fatal(e)
			}
			if got := r.MatchString(tt.value); got != tt.want {
				t.Fatalf("match=%v want %v regex %s", got, tt.want, r)
			}
		})
	}
	for _, s := range []string{"/[", "/[z-a]", "/a\\", "/[]"} {
		if _, e := glob(s); e == nil {
			t.Errorf("malformed glob accepted: %q", s)
		}
	}
}

func TestBudgetsAndOwnership(t *testing.T) {
	p := base()
	for i := range MaxRules {
		p.Rules = append(p.Rules, Rule{Name: fmt.Sprint(i), Action: Allow, Target: Target{Path: []string{fmt.Sprintf("/tool%d", i)}}})
	}
	prog := compile(t, p)
	p.Rules[MaxRules-1].Target.Path[0] = "/mutated"
	d, e := prog.Evaluate(Facts{TargetPath: fmt.Sprintf("/tool%d", MaxRules-1)})
	if e != nil || len(d.Matches) != 1 {
		t.Fatalf("256th path or immutable ownership: %+v %v", d, e)
	}
	p.Rules = append(p.Rules, Rule{Name: "over", Action: Allow})
	if _, e := Compile([]Policy{p}); e == nil {
		t.Fatal("rule budget ignored")
	}
	p = base()
	p.Rules = []Rule{{Name: "argv", Action: Deny, Target: Target{Argv: &Argv{Contains: []string{"-c"}}}}}
	prog = compile(t, p)
	for _, f := range []Facts{{Argv: []string{strings.Repeat("x", MaxArgBytes), "-c"}, ArgvComplete: true}, {Argv: make([]string, MaxArgc+1), ArgvComplete: true}, {Argv: []string{"a\x00b", "-c"}, ArgvComplete: true}} {
		if _, e := prog.Evaluate(f); e == nil {
			t.Fatal("invalid argv accepted")
		}
	}
	for _, mutate := range []func(*Policy){func(p *Policy) { p.Mode = "off" }, func(p *Policy) { p.Rules[0].Actor.UID = []int64{-1} }, func(p *Policy) { p.Rules[0].Target.Path = []string{"relative"} }, func(p *Policy) { p.Rules[0].Target.Path = []string{string([]byte{'/', 255})} }, func(p *Policy) { p.Rules[0].Target.Argv = &Argv{} }, func(p *Policy) { p.Rules[0].Target.SetRole = "not-allowed" }} {
		p = base()
		p.Rules = []Rule{{Name: "test", Action: Deny}}
		mutate(&p)
		if _, e := Compile([]Policy{p}); e == nil {
			t.Fatal("invalid candidate accepted")
		}
	}
}

func TestPathClassEscapes(t *testing.T) {
	for _, pattern := range []string{`/[\d]`, `/[\n]`, `/[\-a]`, `/[a-c]`, `/[^a-c]`, `/[é-ê]`, `/[[]`} {
		re, err := glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"/d", "/4", "/n", "/\n", "/-", "/a", "/b", "/z", "//", "/é", "/["} {
			want, err := path.Match(pattern, value)
			if err != nil {
				t.Fatal(err)
			}
			if got := re.MatchString(value); got != want {
				t.Errorf("%q %q: got %v want %v", pattern, value, got, want)
			}
		}
	}
}

func TestMissingRoleIsNotRoot(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "root-only", Action: Allow, Actor: Actor{Role: []string{"agent"}}}}
	if _, err := compile(t, p).Evaluate(Facts{}); err == nil {
		t.Fatal("missing inherited role became root")
	}
}

func TestInvalidObservedUTF8CannotAliasPath(t *testing.T) {
	p := base()
	p.Default = Deny
	p.Rules = []Rule{{Name: "exact", Action: Allow, Target: Target{Path: []string{"/x�"}}}}
	if _, err := compile(t, p).Evaluate(Facts{TargetPath: string([]byte{'/', 'x', 255})}); err == nil {
		t.Fatal("invalid bytes aliased an exact allowed path")
	}
}

func TestMetadataBudgets(t *testing.T) {
	for _, mutate := range []func(*Policy){func(p *Policy) { p.ID = strings.Repeat("x", MaxStringBytes+1) }, func(p *Policy) { p.Revision = "x\x00y" }, func(p *Policy) { p.Rules[0].Name = strings.Repeat("n", MaxStringBytes+1) }, func(p *Policy) { p.Rules[0].Origin = strings.Repeat("o", MaxStringBytes+1) }} {
		p := base()
		p.Rules = []Rule{{Name: "rule", Action: Allow}}
		mutate(&p)
		if _, e := Compile([]Policy{p}); e == nil {
			t.Fatal("unbounded metadata accepted")
		}
	}
}

func TestAllowedModeAndOverlappingFilesystemKinds(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "allowed", Action: Allow, Mode: Enforce, Target: Target{FSType: []string{"deleted"}}}}
	d, e := compile(t, p).Evaluate(Facts{FSType: "tmpfs", FileKinds: []string{"memfd", "deleted"}})
	if e != nil || d.Mode != Enforce || d.Action != Allow || len(d.Matches) != 1 {
		t.Fatalf("filesystem classifications/allowed mode: %+v %v", d, e)
	}
	p.Rules = append(p.Rules, Rule{Name: "audit-deny", Action: Deny, Mode: Audit})
	d, e = compile(t, p).Evaluate(Facts{FSType: "tmpfs", FileKinds: []string{"deleted"}})
	if e != nil || d.Mode != Audit || d.Block {
		t.Fatalf("enforced allow masked audit deny mode: %+v %v", d, e)
	}
}

func TestAuditEvaluationFaultsDoNotBlock(t *testing.T) {
	audit := Policy{ID: "a", Revision: "1", Mode: Audit, Rules: []Rule{
		{Name: "one", Action: Allow, Target: Target{SetRole: "one"}},
		{Name: "two", Action: Allow, Target: Target{SetRole: "two"}},
	}}
	strict := Policy{ID: "b", Revision: "1", Mode: Enforce, Rules: []Rule{{Name: "grant", Action: Allow, Target: Target{SetRole: "known"}}}}
	for _, policies := range [][]Policy{{audit}, {audit, strict}} {
		d, err := compile(t, policies...).Evaluate(Facts{})
		if err != nil || d.Block || d.SetRoles["a"] != "" || !d.AuditUnknown["a"] {
			t.Fatalf("audit-local conflict: %+v %v", d, err)
		}
		if len(policies) == 2 && d.SetRoles["b"] != "known" {
			t.Fatalf("unrelated grant poisoned: %+v", d)
		}
	}
	d, err := compile(t, audit).Evaluate(Facts{ActorPath: "/bad\x00"})
	if err == nil || d.Block {
		t.Fatalf("shared audit-only error introduced denial: %+v %v", d, err)
	}
}

func TestAuditPredicateUncertaintyWithoutRoleWritePreservesKnownGrant(t *testing.T) {
	p := Policy{ID: "a", Revision: "1", Mode: Audit, Rules: []Rule{
		{Name: "observe", Action: Allow, Actor: Actor{UID: []int64{1}}},
		{Name: "known", Action: Allow, Target: Target{SetRole: "known"}},
	}}
	d, err := compile(t, p).Evaluate(Facts{})
	if err != nil || d.Block || d.SetRoles["a"] != "known" || !d.AuditUnknown["a"] {
		t.Fatalf("non-causal uncertainty erased grant: %+v %v", d, err)
	}
}
