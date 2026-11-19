// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type evaluatorPath struct {
	Length uint32
	Bytes  [256]byte
}
type (
	evaluatorRole  struct{ PolicyUID, Role uint64 }
	evaluatorFacts struct {
		ActorPath, TargetPath            evaluatorPath
		ActorImage, TargetImage          int32
		UID, UIDKnown                    uint32
		Ancestors                        [16]evaluatorPath
		AncestorCount, AncestorsComplete uint32
		Roles                            [8]evaluatorRole
		RoleCount, FSMask, FSKnown       uint32
		Argv                             [4096]byte
		Argc                             uint32
		Offsets                          [64]uint32
		ArgBytes, ArgComplete            uint32
		Stdin                            int32
		Padding                          uint32
	}
)

func evaluatorPathOf(s string) evaluatorPath {
	p := evaluatorPath{Length: uint32(len(s))}
	copy(p.Bytes[:], s)
	return p
}

func evaluatorTri(p *bool) int32 {
	if p == nil {
		return -1
	}
	if *p {
		return 1
	}
	return 0
}

func evaluatorFactBytes(t *testing.T, p *KernelProgram, policies []Policy, f Facts) evaluatorFacts {
	t.Helper()
	out := evaluatorFacts{ActorPath: evaluatorPathOf(f.ActorPath), TargetPath: evaluatorPathOf(f.TargetPath), ActorImage: evaluatorTri(f.ActorFromImage), TargetImage: evaluatorTri(f.TargetFromImage), Stdin: evaluatorTri(f.StdinIsPipe), AncestorCount: uint32(len(f.Ancestors))}
	if f.EffectiveUID != nil {
		out.UID = *f.EffectiveUID
		out.UIDKnown = 1
	}
	if f.AncestorsComplete {
		out.AncestorsComplete = 1
	}
	for i, s := range f.Ancestors {
		if i < 16 {
			out.Ancestors[i] = evaluatorPathOf(s)
		}
	}
	header := mustDecode[KernelHeader](t, p, 0)
	if int(header.PolicyCount) != len(policies) {
		t.Fatal("compiled policy count mismatch")
	}
	for i := uint32(0); i < header.PolicyCount; i++ {
		policy := mustDecode[KernelPolicy](t, p, KernelPolicyBase+i)
		if role := f.Roles[p.Identities[policy.UID]]; role != "" {
			out.Roles[out.RoleCount] = evaluatorRole{policy.UID, stableHash(role)}
			out.RoleCount++
		}
	}
	for _, kind := range append([]string{f.FSType}, f.FileKinds...) {
		switch kind {
		case "tmpfs":
			out.FSMask |= 1
		case "memfd":
			out.FSMask |= 2
		case "deleted":
			out.FSMask |= 4
		case "overlay":
			out.FSMask |= 8
		}
	}
	out.FSKnown = out.FSMask
	for _, kind := range f.FileKindsKnown {
		switch kind {
		case "tmpfs":
			out.FSKnown |= 1
		case "memfd":
			out.FSKnown |= 2
		case "deleted":
			out.FSKnown |= 4
		case "overlay":
			out.FSKnown |= 8
		}
	}
	out.Argc = uint32(len(f.Argv))
	if f.ArgvComplete {
		out.ArgComplete = 1
	}
	for i, arg := range f.Argv {
		if i < 64 {
			out.Offsets[i] = out.ArgBytes
		}
		if out.ArgBytes < 4096 {
			copy(out.Argv[out.ArgBytes:], arg)
		}
		out.ArgBytes += uint32(len(arg) + 1)
	}
	return out
}

func buildEvaluatorRunner(t *testing.T, flags ...string) string {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("C evaluator tests require clang")
	}
	path := filepath.Join(t.TempDir(), "evaluator")
	args := append([]string{"-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"}, flags...)
	args = append(args, kleeneMutantSource(t, "testdata/evaluator_runner.c"), "-o", path)
	if out, err := exec.Command(clang, args...).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	return path
}

func runCEvaluator(t *testing.T, runner string, p *KernelProgram, facts evaluatorFacts) []uint64 {
	t.Helper()
	dir := t.TempDir()
	var program bytes.Buffer
	for _, entry := range p.Entries {
		program.Write(entry[:])
	}
	if err := os.WriteFile(filepath.Join(dir, "program"), program.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, facts); err != nil {
		t.Fatal(err)
	}
	if data.Len() != 9216 {
		t.Fatalf("facts ABI size %d", data.Len())
	}
	if err := os.WriteFile(filepath.Join(dir, "facts"), data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(runner, filepath.Join(dir, "program"), filepath.Join(dir, "facts")).CombinedOutput()
	if err != nil {
		t.Fatalf("runner %v: %s", err, output)
	}
	fields := strings.Fields(string(output))
	if len(fields) != 21 {
		t.Fatalf("bad response: %s", output)
	}
	values := make([]uint64, 21)
	for i, field := range fields {
		if i == 0 && field == "-1" {
			values[i] = ^uint64(0)
			continue
		}
		v, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		values[i] = v
	}
	return values
}

func TestCEvaluatorReferenceParity(t *testing.T) {
	runner := buildEvaluatorRunner(t)
	runEvaluatorParity(t, func(t *testing.T, p *KernelProgram, facts evaluatorFacts) []uint64 {
		return runCEvaluator(t, runner, p, facts)
	})
}

// Exercise the exact fixed-map global-rule sequencing in ordinary C too; BPF
// verifier acceptance remains a separate opt-in real-kernel test.
func TestCEvaluatorFixedMapReferenceParity(t *testing.T) {
	runner := buildEvaluatorRunner(t, "-DFE_FIXED_MAP_TEST")
	runEvaluatorParity(t, func(t *testing.T, p *KernelProgram, facts evaluatorFacts) []uint64 {
		return runCEvaluator(t, runner, p, facts)
	})
}

func TestCEvaluatorStageCandidateParity(t *testing.T) {
	runner := buildEvaluatorRunner(t, "-DFE_STAGE_CANDIDATE")
	runEvaluatorParity(t, func(t *testing.T, p *KernelProgram, facts evaluatorFacts) []uint64 {
		return runCEvaluator(t, runner, p, facts)
	})
}

func TestCEvaluatorBoundedLoopStageCandidateParity(t *testing.T) {
	runner := buildEvaluatorRunner(t, "-DFE_STAGE_CANDIDATE", "-DFE_BOUNDED_LOOP_CANDIDATE")
	runEvaluatorParity(t, func(t *testing.T, p *KernelProgram, facts evaluatorFacts) []uint64 {
		return runCEvaluator(t, runner, p, facts)
	})
}

func TestCEvaluatorBoundedLoopFixedMapStageCandidateParity(t *testing.T) {
	runner := buildEvaluatorRunner(t, "-DFE_STAGE_CANDIDATE", "-DFE_BOUNDED_LOOP_CANDIDATE", "-DFE_FIXED_MAP_TEST")
	runEvaluatorParity(t, func(t *testing.T, p *KernelProgram, facts evaluatorFacts) []uint64 {
		return runCEvaluator(t, runner, p, facts)
	})
}

func TestCEvaluatorStageHeaderRelookupCandidateParity(t *testing.T) {
	runner := buildEvaluatorRunner(t, "-DFE_STAGE_CANDIDATE", "-DFE_BOUNDED_LOOP_CANDIDATE",
		"-DFE_FIXED_MAP_TEST", "-DFE_STAGE_RELOOKUP_HEADER_CANDIDATE")
	runEvaluatorParity(t, func(t *testing.T, p *KernelProgram, facts evaluatorFacts) []uint64 {
		return runCEvaluator(t, runner, p, facts)
	})
}

func runEvaluatorParity(t *testing.T, run func(*testing.T, *KernelProgram, evaluatorFacts) []uint64) {
	yes, no := true, false
	uid := uint32(1000)
	base := Facts{ActorPath: "/usr/bin/shell", TargetPath: "/bin/tool", ActorFromImage: &yes, TargetFromImage: &no, EffectiveUID: &uid, Ancestors: []string{"/bin/init"}, AncestorsComplete: true, Roles: map[string]string{"p": "root"}, Container: "worker", FSType: "tmpfs", FileKinds: []string{"memfd", "deleted"}, Argv: []string{"tool", "--name=one", "complete argument"}, ArgvComplete: true, StdinIsPipe: &yes}
	rule := Rule{Name: "match", Action: Allow}
	tests := []struct {
		name     string
		policies []Policy
		facts    Facts
	}{}
	add := func(name string, r Rule, f Facts) {
		tests = append(tests, struct {
			name     string
			policies []Policy
			facts    Facts
		}{name, []Policy{{ID: "p", Revision: "r", Mode: Enforce, RootRole: "root", Default: Deny, Rules: []Rule{r}}}, f})
	}
	add("unconditional", rule, base)
	for _, tc := range []struct {
		name            string
		query           []string
		positive, known []string
	}{
		{"unknown-before-positive", []string{"memfd", "tmpfs"}, []string{"tmpfs"}, nil},
		{"positive-before-unknown", []string{"tmpfs", "memfd"}, []string{"tmpfs"}, nil},
		{"unknown-with-known-negative", []string{"memfd", "overlay"}, nil, []string{"overlay"}},
		{"all-known-negative", []string{"memfd", "overlay"}, nil, []string{"memfd", "overlay"}},
		{"positive-no-base-fstype", []string{"deleted"}, []string{"deleted"}, nil},
	} {
		f := base
		f.FSType = ""
		f.FileKinds = tc.positive
		f.FileKindsKnown = tc.known
		add("fs-"+tc.name, Rule{Name: "fs", Action: Allow, Target: Target{FSType: tc.query}}, f)
	}

	variants := []Rule{
		{Actor: Actor{Path: []string{"/wrong", "/usr/**"}}},
		{Target: Target{Path: []string{"/bin/*"}}},
		{Actor: Actor{Role: []string{"root", "child"}}},
		{Actor: Actor{Container: []string{"other", "worker"}}},
		{Actor: Actor{UID: []int64{1, 1000}}},
		{Actor: Actor{FromImage: &yes}},
		{Target: Target{FromImage: &no}},
		{Target: Target{FSType: []string{"overlay", "memfd"}}},
		{Actor: Actor{Ancestor: &Ancestor{Path: []string{"/bin/init"}, Depth: 2}}},
		{Target: Target{Argv: &Argv{Contains: []string{"no", "complete argument"}, Prefix: []string{"--name="}, StdinIsPipe: &yes}}},
		{Target: Target{SetRole: "child"}},
	}
	for i, r := range variants {
		r.Name = "match"
		r.Action = Allow
		add(fmt.Sprintf("predicate-%d", i), r, base)
	}
	all := Rule{Name: "all", Action: Allow, Actor: Actor{Path: []string{"/usr/**"}, Role: []string{"root"}, Container: []string{"worker"}, UID: []int64{1000}, FromImage: &yes, Ancestor: &Ancestor{Path: []string{"/bin/init"}, Depth: 16}}, Target: Target{Path: []string{"/bin/*"}, FromImage: &no, FSType: []string{"deleted"}, Argv: &Argv{Contains: []string{"complete argument"}, Prefix: []string{"--name="}, StdinIsPipe: &yes}, SetRole: "child"}}
	add("all", all, base)
	for _, name := range []string{"actor-image", "target-image", "uid", "role", "ancestor", "argv", "stdin", "filesystem", "actor-path", "target-path"} {
		f := base
		switch name {
		case "actor-image":
			f.ActorFromImage = nil
		case "target-image":
			f.TargetFromImage = nil
		case "uid":
			f.EffectiveUID = nil
		case "role":
			f.Roles = nil
		case "ancestor":
			f.Ancestors = nil
			f.AncestorsComplete = false
		case "argv":
			f.ArgvComplete = false
		case "stdin":
			f.StdinIsPipe = nil
		case "filesystem":
			f.FSType = ""
			f.FileKinds = nil
			f.FileKindsKnown = nil
		case "actor-path":
			f.ActorPath = ""
		case "target-path":
			f.TargetPath = ""
		}
		add("unknown-"+name, all, f)
	}
	f := base
	f.TargetPath = "/different"
	add("mismatch", all, f)
	f = base
	f.Argv = []string{"prefix complete argument suffix"}
	add("contains-whole-argument", variants[9], f)
	// Keep generated variants compilable when reused directly.
	tests[len(tests)-1].policies[0].Rules[0].Name = "match"
	tests[len(tests)-1].policies[0].Rules[0].Action = Allow
	multi := func(name string, p []Policy) {
		tests = append(tests, struct {
			name     string
			policies []Policy
			facts    Facts
		}{name, p, base})
	}
	multi("default-not-per-policy", []Policy{{ID: "p", Revision: "r", Mode: Enforce, Default: Deny}, {ID: "q", Revision: "r", Mode: Audit, Rules: []Rule{rule}}})
	multi("mixed-deny-mode", []Policy{{ID: "p", Revision: "r", Mode: Enforce, Rules: []Rule{rule}}, {ID: "q", Revision: "r", Mode: Audit, Rules: []Rule{{Name: "deny", Action: Deny}}}})
	multi("merged-default", []Policy{{ID: "p", Revision: "r", Mode: Audit, Default: Deny}, {ID: "q", Revision: "r", Mode: Enforce, Default: Allow}})
	multi("conflicting-roles", []Policy{{ID: "p", Revision: "r", Mode: Enforce, Rules: []Rule{{Name: "a", Action: Allow, Target: Target{SetRole: "one"}}, {Name: "b", Action: Allow, Target: Target{SetRole: "two"}}}}})
	multi("audit-conflicting-roles", []Policy{{ID: "p", Revision: "r", Mode: Audit, Rules: []Rule{{Name: "a", Action: Allow, Target: Target{SetRole: "one"}}, {Name: "b", Action: Allow, Target: Target{SetRole: "two"}}}}, {ID: "q", Revision: "r", Mode: Enforce, Rules: []Rule{{Name: "grant", Action: Allow, Target: Target{SetRole: "known"}}}}})
	multi("audit-conflict-then-enforced-grant", []Policy{{ID: "p", Revision: "r", Mode: Audit, Rules: []Rule{{Name: "a", Action: Allow, Target: Target{SetRole: "one"}}, {Name: "b", Action: Allow, Target: Target{SetRole: "two"}}, {Name: "c", Action: Allow, Mode: Enforce, Target: Target{SetRole: "one"}}}}})
	multi("deny-clears-role", []Policy{{ID: "p", Revision: "r", Mode: Enforce, Rules: []Rule{{Name: "a", Action: Allow, Target: Target{SetRole: "one"}}, {Name: "b", Action: Deny}}}})
	boundaryRules := make([]Rule, 17)
	for i := range boundaryRules {
		boundaryRules[i] = Rule{Name: fmt.Sprintf("boundary-%02d", i), Action: Allow}
	}
	boundaryRules[0].Target.SetRole = "one"
	boundaryRules[16].Target.SetRole = "two"
	multi("role-conflict-across-stage", []Policy{{ID: "p", Revision: "r", Mode: Enforce, Rules: boundaryRules}})
	auditBoundary := append([]Rule(nil), boundaryRules...)
	auditBoundary[0] = Rule{Name: "uncertain-first", Action: Deny, Actor: Actor{Path: []string{"/usr/**"}}}
	auditBoundary[16] = Rule{Name: "known-last", Action: Allow}
	unknownBoundaryFacts := base
	unknownBoundaryFacts.ActorPath = ""
	tests = append(tests, struct {
		name     string
		policies []Policy
		facts    Facts
	}{"audit-unknown-across-stage", []Policy{{ID: "p", Revision: "r", Mode: Audit, Rules: auditBoundary}}, unknownBoundaryFacts})
	paths := make([]string, 128)
	for i := range paths {
		paths[i] = fmt.Sprintf("/allowed/%d", i)
	}
	paths[127] = "/bin/tool"
	add("128-paths", Rule{Name: "many", Action: Allow, Target: Target{Path: paths}}, base)
	fullList := make([]string, 256)
	for i := range fullList {
		fullList[i] = fmt.Sprintf("/alternative/%03d", i)
	}
	fullList[255] = "/bin/tool"
	add("256-paths-last-match", Rule{Name: "full-list", Action: Allow, Target: Target{Path: fullList}}, base)
	for i := 0; i < 10; i++ {
		r := variants[i]
		r.Name = "mismatch"
		r.Action = Allow
		f := base
		switch i {
		case 0:
			f.ActorPath = "/not/actor"
		case 1:
			f.TargetPath = "/not/target"
		case 2:
			r.Actor.Role = []string{"child"}
		case 3:
			r.Actor.Container = []string{"not-worker"}
		case 4:
			other := uint32(42)
			f.EffectiveUID = &other
		case 5:
			f.ActorFromImage = &no
		case 6:
			f.TargetFromImage = &yes
		case 7:
			f.FSType = "ext4"
			f.FileKinds = nil
		case 8:
			f.Ancestors = []string{"/other"}
		case 9:
			f.Argv = []string{"complete argument", "embedded--name="}
		}
		add(fmt.Sprintf("predicate-mismatch-%d", i), r, f)
	}
	f = base
	f.ActorFromImage = nil
	f.ActorPath = "/does-not-match"
	add("unknown-short-circuited", all, f)
	// G004 Kleene AND: an UNKNOWN conjunct consulted BEFORE a known false
	// one. The rule is known false (not an error); with no known false
	// conjunct it stays an error. Each case names the unknown, then the
	// known false conjunct (check order: actor path, target path, role,
	// container, uid, actor image, target image, fs, ancestor, argv, stdin).
	kleene := []struct {
		name          string
		unknown, miss func(*Facts, *Rule)
	}{}
	unk := map[string]func(*Facts, *Rule){
		"actor-path":  func(f *Facts, _ *Rule) { f.ActorPath = "" },
		"target-path": func(f *Facts, _ *Rule) { f.TargetPath = "" },
		"role":        func(f *Facts, _ *Rule) { f.Roles = nil },
		"uid":         func(f *Facts, _ *Rule) { f.EffectiveUID = nil },
		"actor-image": func(f *Facts, _ *Rule) { f.ActorFromImage = nil },
		"filesystem":  func(f *Facts, _ *Rule) { f.FSType, f.FileKinds, f.FileKindsKnown = "", nil, nil },
		"ancestor":    func(f *Facts, _ *Rule) { f.Ancestors, f.AncestorsComplete = nil, false },
		"argv":        func(f *Facts, _ *Rule) { f.ArgvComplete = false },
	}
	miss := map[string]func(*Facts, *Rule){
		"target-path":  func(f *Facts, _ *Rule) { f.TargetPath = "/not/target" },
		"container":    func(_ *Facts, r *Rule) { r.Actor.Container = []string{"not-worker"} },
		"uid":          func(f *Facts, _ *Rule) { other := uint32(42); f.EffectiveUID = &other },
		"target-image": func(f *Facts, _ *Rule) { f.TargetFromImage = &yes },
		"filesystem":   func(f *Facts, _ *Rule) { f.FSType, f.FileKinds = "ext4", nil },
		"ancestor":     func(f *Facts, _ *Rule) { f.Ancestors = []string{"/other"} },
		"argv":         func(f *Facts, _ *Rule) { f.Argv = []string{"complete argument", "embedded--name="} },
		"stdin":        func(f *Facts, _ *Rule) { f.StdinIsPipe = &no },
	}
	for _, pair := range [][2]string{
		{"actor-path", "target-path"}, // the G004 init-exec case
		{"actor-path", "stdin"},
		{"target-path", "uid"},
		{"role", "container"},
		{"uid", "target-image"},
		{"actor-image", "filesystem"},
		{"filesystem", "ancestor"},
		{"ancestor", "argv"},
		{"argv", "stdin"},
	} {
		kleene = append(kleene, struct {
			name          string
			unknown, miss func(*Facts, *Rule)
		}{pair[0] + "-then-" + pair[1], unk[pair[0]], miss[pair[1]]})
	}
	for _, k := range kleene {
		for _, action := range []Action{Allow, Deny} {
			f, r := base, all
			r.Actor.Container = append([]string(nil), all.Actor.Container...)
			if action == Deny {
				r.Action, r.Target.SetRole = Deny, ""
			}
			k.unknown(&f, &r)
			k.miss(&f, &r)
			add(fmt.Sprintf("kleene-%s-unknown-and-false-%s", k.name, action), r, f)
			// Without the known false conjunct it stays an error.
			f2, r2 := base, r
			k.unknown(&f2, &r2)
			add(fmt.Sprintf("kleene-%s-unknown-alone-%s", k.name, action), r2, f2)
		}
	}
	f = base
	f.ActorPath, f.StdinIsPipe = "", nil
	add("kleene-two-unknowns-no-false", all, f)
	// Audit: an unknown AND a known false is not audit-unknown.
	f = base
	f.ActorPath, f.TargetPath = "", "/not/target"
	tests = append(tests, struct {
		name     string
		policies []Policy
		facts    Facts
	}{"kleene-audit-unknown-and-false", []Policy{{ID: "p", Revision: "r", Mode: Audit, RootRole: "root", Default: Allow, Rules: []Rule{{Name: "d", Action: Deny, Actor: Actor{Path: []string{"/usr/**"}}, Target: Target{Path: []string{"/bin/*"}}}}}}, f})
	f = base
	f.Ancestors = []string{"/wrong", "/bin/init"}
	f.AncestorsComplete = false
	add("ancestor-found-in-incomplete-walk", all, f)
	f = base
	f.Argv = []string{strings.Repeat("x", 4095)}
	add("4096-argv-bytes", Rule{Name: "longarg", Action: Allow, Target: Target{Argv: &Argv{Prefix: []string{"xxx"}}}}, f)
	f.Argv = []string{strings.Repeat("x", 4096)}
	add("oversized-argv", Rule{Name: "longarg", Action: Allow, Target: Target{Argv: &Argv{Prefix: []string{"xxx"}}}}, f)
	f = base
	f.Argv = make([]string, 64)
	f.Argv[63] = "last"
	add("64-arguments", Rule{Name: "lastarg", Action: Allow, Target: Target{Argv: &Argv{Contains: []string{"last"}}}}, f)
	f = base
	f.TargetPath = "/bad\xff"
	add("invalid-path-even-unconsulted", rule, f)
	rules := make([]Rule, 256)
	for i := range rules {
		rules[i] = Rule{Name: fmt.Sprintf("rule-%03d", i), Action: Allow}
	}
	rules[255].Action = Deny
	multi("256-rules", []Policy{{ID: "p", Revision: "r", Mode: Enforce, Rules: rules}})
	multi("policy-local-roles", []Policy{{ID: "p", Revision: "r", Mode: Audit, Rules: []Rule{{Name: "a", Action: Allow, Target: Target{SetRole: "one"}}}}, {ID: "q", Revision: "r", Mode: Enforce, Rules: []Rule{{Name: "b", Action: Allow, Target: Target{SetRole: "two"}}}}})
	f = base
	f.Ancestors = make([]string, 16)
	for i := range f.Ancestors {
		f.Ancestors[i] = "/wrong"
	}
	f.Ancestors[15] = "/bin/init"
	add("sixteenth-ancestor", all, f)
	manyPolicies := make([]Policy, 8)
	f = base
	f.Roles = map[string]string{}
	for i := range manyPolicies {
		id := fmt.Sprintf("policy-%d", i)
		f.Roles[id] = "root"
		manyPolicies[i] = Policy{ID: id, Revision: "r", Mode: Enforce, RootRole: "root", Rules: []Rule{{Name: "role", Action: Allow, Actor: Actor{Role: []string{"root"}}, Target: Target{SetRole: "child"}}}}
	}
	multi("eight-policy-roles", manyPolicies)
	tests[len(tests)-1].facts = f
	for _, tc := range roleEntryCases() {
		tests = append(tests, struct {
			name     string
			policies []Policy
			facts    Facts
		}{"role-entry-" + tc.name, tc.policies, tc.facts})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := CompileKernel(tc.policies, 1, "worker")
			if err != nil {
				t.Fatal(err)
			}
			oracle, err := Compile(tc.policies)
			if err != nil {
				t.Fatal(err)
			}
			want, werr := oracle.Evaluate(tc.facts)
			got := run(t, p, evaluatorFactBytes(t, p, tc.policies, tc.facts))
			if werr != nil {
				if got[0] != ^uint64(0) || got[3] == 0 {
					t.Fatalf("want error %v, got %v", werr, got)
				}
				for i, role := range got[8:16] {
					if role != 0 {
						t.Fatalf("C error retained role proposal at policy %d: %v", i, got)
					}
				}
				return
			}
			if got[0] != 0 {
				t.Fatalf("unexpected C error %v want %+v", got, want)
			}
			deny := uint64(0)
			if want.Action == Deny {
				deny = 1
			}
			mode := uint64(1)
			if want.Mode == Enforce {
				mode = 2
			}
			if got[1] != deny || got[2] != mode {
				t.Fatalf("C %v want %+v", got, want)
			}
			var bits [4]uint64
			for i, meta := range p.Rules {
				for _, m := range want.Matches {
					if m.PolicyID == meta.PolicyID && m.Rule == meta.Name {
						bits[i/64] |= 1 << uint(i%64)
					}
				}
			}
			for i, b := range bits {
				if got[4+i] != b {
					t.Fatalf("bitmap %v want %v", got[4:8], bits)
				}
			}
			for i, policy := range tc.policies {
				role := want.SetRoles[policy.ID]
				hash := got[8+i]
				if (role == "" && hash != 0) || (role != "" && p.Identities[hash] != role) {
					t.Fatalf("role hash %d (%q), want %q", hash, p.Identities[hash], role)
				}
			}
		})
	}
}

// Compilation checks instruction/stack generation, not verifier acceptance or
// attachment. The same harness can be loaded only on an isolated BPF test host.
func TestCEvaluatorBPFCompile(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("requires clang BPF backend")
	}
	object := filepath.Join(t.TempDir(), "evaluator.bpf.o")
	if output, err := exec.Command(clang, "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-c", "testdata/evaluator_runner.c", "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile evaluator BPF: %v\n%s", err, output)
	}
}

func TestCEvaluatorMalformedBounds(t *testing.T) {
	runner := buildEvaluatorRunner(t)
	policies := []Policy{{ID: "p", Revision: "r", Mode: Enforce, Rules: []Rule{{Name: "args", Action: Allow, Target: Target{Argv: &Argv{Contains: []string{"safe"}}}}}}}
	p, err := CompileKernel(policies, 1, "worker")
	if err != nil {
		t.Fatal(err)
	}
	facts := evaluatorFactBytes(t, p, policies, Facts{Argv: []string{"safe"}, ArgvComplete: true})
	tests := []struct {
		name   string
		mutate func(*KernelProgram, *evaluatorFacts)
	}{
		{"ancestor-count", func(_ *KernelProgram, f *evaluatorFacts) { f.AncestorCount = 17 }},
		{"role-count", func(_ *KernelProgram, f *evaluatorFacts) { f.RoleCount = 9 }},
		{"argument-count", func(_ *KernelProgram, f *evaluatorFacts) { f.Argc = 65 }},
		{"argument-offset", func(_ *KernelProgram, f *evaluatorFacts) { f.Offsets[0] = 4096 }},
		{"argument-byte-count", func(_ *KernelProgram, f *evaluatorFacts) { f.ArgBytes = 4097 }},
		{"unterminated-argument", func(_ *KernelProgram, f *evaluatorFacts) { f.ArgBytes = 4 }},
		{"embedded-nul", func(_ *KernelProgram, f *evaluatorFacts) { f.Argv[1] = 0 }},
		{"path-byte-count", func(_ *KernelProgram, f *evaluatorFacts) { f.ActorPath.Length = 256 }},
		{"rule-count", func(p *KernelProgram, _ *evaluatorFacts) { binary.LittleEndian.PutUint32(p.Entries[0][16:20], 257) }},
		{"policy-count", func(p *KernelProgram, _ *evaluatorFacts) { binary.LittleEndian.PutUint32(p.Entries[0][8:12], 9) }},
		{"list-count", func(p *KernelProgram, _ *evaluatorFacts) {
			binary.LittleEndian.PutUint32(p.Entries[KernelRuleBase][100:104], 257)
		}},
		{"list-base", func(p *KernelProgram, _ *evaluatorFacts) {
			binary.LittleEndian.PutUint32(p.Entries[KernelRuleBase][96:100], 16384)
		}},
		{"missing-blob", func(p *KernelProgram, _ *evaluatorFacts) { p.Entries = p.Entries[:KernelRuleBase+1] }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			copyP := *p
			copyP.Entries = append([]Blob(nil), p.Entries...)
			copyF := facts
			tc.mutate(&copyP, &copyF)
			got := runCEvaluator(t, runner, &copyP, copyF)
			if got[0] != ^uint64(0) || got[3] == 0 {
				t.Fatalf("malformed input accepted: %v", got)
			}
			for _, role := range got[8:16] {
				if role != 0 {
					t.Fatalf("error retained role proposal: %v", got)
				}
			}
		})
	}
}

func TestAuditUncertaintyKnownResults(t *testing.T) {
	for _, flags := range [][]string{nil, {"-DFE_FIXED_MAP_TEST"}} {
		runner := buildEvaluatorRunner(t, flags...)
		unknown := Rule{Name: "unknown", Action: Allow, Actor: Actor{Role: []string{"root"}}, Target: Target{SetRole: "uncertain"}}
		for _, tc := range []struct {
			name            string
			audit           Rule
			strict          []Rule
			fallback        Action
			block, proposal bool
		}{
			{"known-deny", unknown, []Rule{{Name: "deny", Action: Deny}}, Allow, true, false},
			{"local-role", unknown, []Rule{{Name: "allow", Action: Allow, Target: Target{SetRole: "known"}}}, Deny, false, true},
			{"unproved-exception", unknown, nil, Deny, true, false},
			{"unknown-deny-cancels-proposal", Rule{Name: "unknown", Action: Deny, Actor: Actor{Role: []string{"root"}}}, []Rule{{Name: "allow", Action: Allow, Target: Target{SetRole: "known"}}}, Deny, false, false},
		} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/reverse=%v/flags=%v", tc.name, reverse, flags), func(t *testing.T) {
					policies := []Policy{{ID: "audit", Revision: "1", Mode: Audit, RootRole: "root", Rules: []Rule{tc.audit}}, {ID: "strict", Revision: "1", Mode: Enforce, Default: tc.fallback, Rules: tc.strict}}
					if reverse {
						policies[0].ID = "z-audit"
						policies[1].ID = "a-strict"
					}
					auditID, strictID := policies[0].ID, policies[1].ID
					p := compile(t, policies...)
					d, err := p.Evaluate(Facts{})
					if err != nil || d.Block != tc.block || (d.SetRoles[strictID] != "") != tc.proposal || d.SetRoles[auditID] != "" {
						t.Errorf("Go result: %+v, %v", d, err)
					}
					kp, err := CompileKernel(policies, 1, "app")
					if err != nil {
						t.Fatal(err)
					}
					got := runCEvaluator(t, runner, kp, evaluatorFactBytes(t, kp, policies, Facts{}))
					if got[16]&(1<<31) != 0 != (tc.audit.Action == Deny) {
						t.Errorf("global uncertainty flag: %v", got)
					}
					if got[0] != 0 || (got[1] != 0 && got[2] == 2) != tc.block {
						t.Errorf("C result: %v", got)
					}
					for i := range policies {
						policy := mustDecode[KernelPolicy](t, kp, uint32(i+1))
						name := kp.Identities[policy.UID]
						want := name == strictID && tc.proposal
						if (got[8+i] != 0) != want {
							t.Errorf("C proposal %s: %v", name, got)
						}
					}
				})
			}
		}
	}
}

func TestEnforcedAndSharedUncertaintyRemainErrors(t *testing.T) {
	for _, flags := range [][]string{nil, {"-DFE_FIXED_MAP_TEST"}} {
		runner := buildEvaluatorRunner(t, flags...)
		for _, reverse := range []bool{false, true} {
			policies := []Policy{
				{ID: "a", Revision: "1", Mode: Audit, Rules: []Rule{{Name: "audit-unknown", Action: Allow, Actor: Actor{Role: []string{"root"}}}}},
				{ID: "b", Revision: "1", Mode: Enforce, Rules: []Rule{{Name: "enforced-unknown", Action: Deny, Actor: Actor{UID: []int64{1}}}}},
			}
			if reverse {
				policies[0].ID, policies[1].ID = "b", "a"
			}
			for _, facts := range []Facts{{}, {ActorPath: "/bad\x00"}} {
				oracle := compile(t, policies...)
				if _, err := oracle.Evaluate(facts); err == nil {
					t.Fatal("enforced/shared uncertainty accepted")
				}
				program, err := CompileKernel(policies, 1, "app")
				if err != nil {
					t.Fatal(err)
				}
				got := runCEvaluator(t, runner, program, evaluatorFactBytes(t, program, policies, facts))
				if got[0] != ^uint64(0) || got[3] == 0 || got[3] == 4 {
					t.Fatalf("enforced/shared error became audit diagnostic: %v", got)
				}
				for _, role := range got[8:16] {
					if role != 0 {
						t.Fatalf("error grants role: %v", got)
					}
				}
			}
		}
	}
}

func TestLSMResultPreservesSignedPriorDenials(t *testing.T) {
	runner := buildEvaluatorRunner(t)
	for _, tc := range []struct{ prior, want int }{{0, 0}, {-1, -1}, {-13, -13}, {-4095, -4095}, {-4096, -1}, {1, -1}, {2147483647, -1}, {-2147483648, -1}} {
		out, err := exec.Command(runner, strconv.Itoa(tc.prior)).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != strconv.Itoa(tc.want) {
			t.Fatalf("prior=%d want=%d: %s %v", tc.prior, tc.want, out, err)
		}
	}
}

// TestLegacyOwnerLSMVerdictTable pins the fe_lsm_verdict rows the legacy
// (non-ABI3) owner relies on. The owner passes class 1 for an Audit-only
// generation and 2 otherwise, and an error never forces the decision's deny
// or mode. The legacy call always passes prior 0, because a nonzero ret
// returns before the call; the prior rows only pin fe_lsm_verdict itself.
// Audit never blocks once the generation is classified.
func TestLegacyOwnerLSMVerdictTable(t *testing.T) {
	runner := buildEvaluatorRunner(t)
	for _, tc := range []struct {
		name                             string
		class, prior, failed, deny, mode int
		want                             int
	}{
		{"audit-evaluator-error-allow-decision", 1, 0, 1, 0, 1, 0},
		{"audit-error-partial-strict-mode", 1, 0, 1, 1, 2, 0},
		{"audit-known-deny", 1, 0, 0, 1, 1, 0},
		{"strict-error-allow-decision", 2, 0, 1, 0, 2, -1},
		{"strict-error-partial-audit-mode", 2, 0, 1, 1, 1, -1},
		{"strict-known-deny", 2, 0, 0, 1, 2, -1},
		{"strict-audit-rule-deny", 2, 0, 0, 1, 1, 0},
		{"strict-allow", 2, 0, 0, 0, 2, 0},
		{"unclassified-zero", 0, 0, 0, 0, 1, -1},
		{"unclassified-three", 3, 0, 0, 0, 1, -1},
		{"prior-kept-audit", 1, -13, 1, 0, 1, -13},
		{"prior-kept-strict", 2, -13, 0, 0, 2, -13},
	} {
		out, err := exec.Command(runner, "verdict", strconv.Itoa(tc.class), strconv.Itoa(tc.prior), strconv.Itoa(tc.failed), strconv.Itoa(tc.deny), strconv.Itoa(tc.mode)).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != strconv.Itoa(tc.want) {
			t.Fatalf("%s: want %d, got %s (%v)", tc.name, tc.want, out, err)
		}
	}
}

func TestImmutableClassLSMFaultMatrix(t *testing.T) {
	runner := buildEvaluatorRunner(t)
	for _, class := range []int{1, 2} {
		for _, prior := range []int{0, -13} {
			for _, failed := range []int{0, 1} {
				for _, mode := range []int{1, 2} {
					want := prior
					if prior == 0 && class == 2 && (failed == 1 || mode == 2) {
						want = -1
					}
					out, err := exec.Command(runner, "verdict", strconv.Itoa(class), strconv.Itoa(prior), strconv.Itoa(failed), "1", strconv.Itoa(mode)).CombinedOutput()
					if err != nil || strings.TrimSpace(string(out)) != strconv.Itoa(want) {
						t.Fatalf("class=%d prior=%d failed=%d denyMode=%d want=%d got=%s err=%v", class, prior, failed, mode, want, out, err)
					}
				}
			}
		}
	}
	for _, declared := range []Mode{Audit, Enforce} {
		for _, override := range []Mode{Audit, Enforce} {
			rules := make([]Rule, 256)
			for i := range rules {
				rules[i] = Rule{Name: fmt.Sprintf("r%03d", i), Action: Allow, Mode: Audit}
			}
			rules[255].Mode = override
			policies := []Policy{{ID: "a", Revision: "1", Mode: declared, Rules: rules}}
			program, err := CompileKernel(policies, 1, "app")
			if err != nil {
				t.Fatal(err)
			}
			got := runCEvaluator(t, runner, program, evaluatorFactBytes(t, program, policies, Facts{}))
			want := uint64(1)
			if declared == Enforce || override == Enforce {
				want = 2
			}
			if got[17] != want {
				t.Fatalf("complete immutable class ignored policy/last rule: %v", got)
			}
		}
	}
}

func TestRoleConflictVersusUnknownProvenance(t *testing.T) {
	for _, flags := range [][]string{nil, {"-DFE_FIXED_MAP_TEST"}} {
		runner := buildEvaluatorRunner(t, flags...)
		for _, conflict := range []bool{false, true} {
			for _, enforced := range []bool{false, true} {
				rules := []Rule{{Name: "a", Action: Allow, Target: Target{SetRole: "one"}}, {Name: "b", Action: Allow, Target: Target{SetRole: "two"}}}
				if !conflict {
					rules[1].Actor.Role = []string{"missing"}
				}
				if enforced {
					rules = append(rules, Rule{Name: "c", Action: Allow, Mode: Enforce, Target: Target{SetRole: "one"}})
				}
				policies := []Policy{{ID: "a", Revision: "1", Mode: Audit, Rules: rules}}
				_, oracleErr := compile(t, policies...).Evaluate(Facts{})
				program, err := CompileKernel(policies, 1, "app")
				if err != nil {
					t.Fatal(err)
				}
				got := runCEvaluator(t, runner, program, evaluatorFactBytes(t, program, policies, Facts{}))
				wantError := conflict && enforced
				if (oracleErr != nil) != wantError || (got[0] != 0) != wantError || (got[19] != 0) != enforced || (got[20] != 0) != conflict {
					t.Fatalf("conflict=%v enforced=%v oracle=%v C=%v", conflict, enforced, oracleErr, got)
				}
			}
		}
	}
}

func TestAuditFallbackDenyUncertaintyParity(t *testing.T) {
	yes, no := true, false
	for _, fixed := range []bool{false, true} {
		flags := []string{}
		if fixed {
			flags = append(flags, "-DFE_FIXED_MAP_TEST")
		}
		runner := buildEvaluatorRunner(t, flags...)
		for _, tc := range []struct {
			name                                string
			action                              Action
			fallback                            Action
			mode                                Mode
			observed                            *bool
			knownDeny, wantUncertain, wantBlock bool
		}{
			{"unknown allow audit fallback", Allow, Deny, Audit, nil, false, true, false},
			{"unknown allow enforced fallback", Allow, Deny, Enforce, nil, false, false, true},
			{"known false deterministic fallback", Allow, Deny, Audit, &no, false, false, false},
			{"unknown deny deterministic fallback", Deny, Deny, Audit, nil, false, false, false},
			{"known audit deny", Allow, Deny, Audit, nil, true, false, false},
			{"unknown allow without fallback", Allow, "", Audit, nil, false, false, false},
		} {
			t.Run(fmt.Sprintf("%v/%s", fixed, tc.name), func(t *testing.T) {
				policies := []Policy{{ID: "a", Revision: "r", Mode: Audit, RootRole: "root", Rules: []Rule{{Name: "maybe", Action: tc.action, Actor: Actor{FromImage: &yes}}}}, {ID: "fallback", Revision: "r", Mode: tc.mode, RootRole: "root", Default: tc.fallback}}
				if tc.knownDeny {
					policies[0].Rules = append(policies[0].Rules, Rule{Name: "known", Action: Deny})
				}
				facts := Facts{ActorFromImage: tc.observed}
				oracle, err := Compile(policies)
				if err != nil {
					t.Fatal(err)
				}
				want, err := oracle.Evaluate(facts)
				if err != nil {
					t.Fatal(err)
				}
				if want.UncertainFallback != tc.wantUncertain || want.Block != tc.wantBlock {
					t.Errorf("oracle provenance/block: %+v", want)
				}
				program, err := CompileKernel(policies, 7, "app")
				if err != nil {
					t.Fatal(err)
				}
				got := runCEvaluator(t, runner, program, evaluatorFactBytes(t, program, policies, facts))
				if got[16]&(1<<30) != 0 != tc.wantUncertain {
					t.Errorf("C uncertain fallback flags: %#x", got[16])
				}
				if tc.wantUncertain && got[16]&(1<<31) == 0 {
					t.Error("uncertain fallback did not suppress earlier proposals")
				}
				if (got[1] != 0) != (want.Action == Deny) || (got[1] != 0 && got[2] == 2) != tc.wantBlock {
					t.Errorf("C decision: %v; oracle %+v", got, want)
				}
			})
		}
	}
}

func TestEvaluatorKnownRolesSurvivePolicyReorder(t *testing.T) {
	policies := []Policy{
		{ID: "z", Revision: "r", Mode: Audit, RootRole: "zroot", Rules: []Rule{{Name: "allow-z", Action: Allow, Actor: Actor{Role: []string{"zroot"}}}}},
		{ID: "a", Revision: "r", Mode: Enforce, RootRole: "aroot", Rules: []Rule{{Name: "deny-a", Action: Deny, Actor: Actor{Role: []string{"aroot"}}}}},
	}
	facts := Facts{Roles: map[string]string{"a": "aroot", "z": "zroot"}}
	for _, fixed := range []bool{false, true} {
		flags := []string{}
		if fixed {
			flags = append(flags, "-DFE_FIXED_MAP_TEST")
		}
		runner := buildEvaluatorRunner(t, flags...)
		for reverse := 0; reverse < 2; reverse++ {
			if reverse != 0 {
				policies[0], policies[1] = policies[1], policies[0]
			}
			program, err := CompileKernel(policies, 7, "app")
			if err != nil {
				t.Fatal(err)
			}
			encoded := evaluatorFactBytes(t, program, policies, facts)
			for i := uint32(0); i < encoded.RoleCount; i++ {
				role := encoded.Roles[i]
				name := program.Identities[role.PolicyUID]
				if role.Role != stableHash(facts.Roles[name]) {
					t.Errorf("policy %q received wrong role hash %#x", name, role.Role)
				}
			}
			oracle, err := Compile(policies)
			if err != nil {
				t.Fatal(err)
			}
			want, err := oracle.Evaluate(facts)
			if err != nil || !want.Block {
				t.Fatalf("oracle %+v %v", want, err)
			}
			got := runCEvaluator(t, runner, program, encoded)
			if got[1] != 1 || got[2] != 2 {
				t.Errorf("known-role parity fixed=%v reverse=%d: %v", fixed, reverse, got)
			}
		}
	}
}
