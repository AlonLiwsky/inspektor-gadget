// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"regexp/syntax"
	"strings"
	"testing"
	"unsafe"
)

func TestKernelLayouts(t *testing.T) {
	if uint32(syntax.EmptyBeginText) != KernelBeginText || uint32(syntax.EmptyEndText) != KernelEndText {
		t.Fatal("regexp boundary constants changed")
	}
	entries := []any{KernelHeader{}, KernelPolicy{}, KernelRule{}, KernelString{}, KernelValue{}, KernelPattern{}, KernelInstruction{}}
	for _, entry := range entries {
		if size := binary.Size(entry); size != KernelBlobSize {
			t.Fatalf("%T size%d", entry, size)
		}
	}
	if unsafe.Offsetof(KernelHeader{}.ContainerRef) != 20 || unsafe.Offsetof(KernelPolicy{}.Default) != 16 || unsafe.Offsetof(KernelPolicy{}.RootEpoch) != 24 || unsafe.Offsetof(KernelRule{}.ActorImage) != 12 || unsafe.Offsetof(KernelRule{}.SetRole) != 32 || unsafe.Offsetof(KernelRule{}.ActorPath) != 40 || unsafe.Offsetof(KernelRule{}.ArgPrefix) != 104 || unsafe.Offsetof(KernelInstruction{}.Ranges) != 16 || unsafe.Offsetof(KernelString{}.Bytes) != 4 {
		t.Fatal("kernel C layout offsets changed")
	}
	original := KernelHeader{Generation: 0x0102030405060708, PolicyCount: 3, RuleBase: 9, RuleCount: 20, ContainerRef: 29}
	blob, err := encode(original)
	if err != nil {
		t.Fatal(err)
	}
	if blob[0] != 8 || blob[7] != 1 || binary.LittleEndian.Uint32(blob[20:24]) != 29 {
		t.Fatal("encoding is not specified little endian layout")
	}
	decoded, err := Decode[KernelHeader](blob)
	if err != nil || decoded != original {
		t.Fatal(decoded, err)
	}
	if _, err := Decode[uint64](blob); err == nil {
		t.Fatal("wrong layout accepted")
	}
	if _, err := encode(uint64(1)); err == nil {
		t.Fatal("wrong encode layout accepted")
	}
}

func kernelFixture() []Policy {
	yes, no := true, false
	return []Policy{
		{ID: "policy-z", Revision: "r2", Mode: Audit, RootRole: "runner", Rules: []Rule{{
			Name: "all-fields", Origin: "test-source", Action: Allow, Mode: Enforce,
			Actor:  Actor{Path: []string{"/usr/**"}, FromImage: &no, Ancestor: &Ancestor{Path: []string{"/sbin/init"}, Depth: 3}, Role: []string{"agent", "runner"}, UID: []int64{0, 4294967295}, Container: []string{"worker"}},
			Target: Target{Path: []string{"/bin/t?ol"}, FromImage: &yes, FSType: []string{"overlay"}, Argv: &Argv{Contains: []string{"--safe"}, Prefix: []string{"tool", "run"}, StdinIsPipe: &no}, SetRole: "worker"},
		}}},
		{ID: "policy-a", Revision: "r1", Mode: Enforce, Default: Deny, Rules: []Rule{{Name: "deny", Action: Deny, Target: Target{Path: []string{"/blocked"}}}}},
	}
}

func mustDecode[T any](t *testing.T, p *KernelProgram, key uint32) T {
	t.Helper()
	if int(key) >= len(p.Entries) {
		t.Fatal("reference out of bounds")
	}
	out, err := Decode[T](p.Entries[key])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCompileKernelFullVocabulary(t *testing.T) {
	program, err := CompileKernel(kernelFixture(), 77, "worker")
	if err != nil {
		t.Fatal(err)
	}
	header := mustDecode[KernelHeader](t, program, 0)
	if header.Generation != 77 || header.PolicyCount != 2 || header.RuleBase != 9 || header.RuleCount != 2 {
		t.Fatal(header)
	}
	container := mustDecode[KernelString](t, program, header.ContainerRef)
	if string(container.Bytes[:container.Length]) != "worker" {
		t.Fatal(container)
	}
	first := mustDecode[KernelPolicy](t, program, 1)
	second := mustDecode[KernelPolicy](t, program, 2)
	if first.UID != stableHash("policy-a") || first.RootRole != stableHash("agent") || first.Mode != 2 || first.Default != 2 || second.Mode != 1 || second.Default != 0 {
		t.Fatal(first, second)
	}
	for _, entry := range program.Entries[3:9] {
		if entry != (Blob{}) {
			t.Fatal("unused policy descriptor not zero")
		}
	}
	deny := mustDecode[KernelRule](t, program, 9)
	if deny.Deny != 1 || deny.Mode != 2 || deny.ActorImage != -1 || deny.TargetImage != -1 || deny.Stdin != -1 {
		t.Fatal(deny)
	}
	rule := mustDecode[KernelRule](t, program, 10)
	if rule.PolicyIndex != 1 || rule.Mode != 2 || rule.ActorImage != 0 || rule.TargetImage != 1 || rule.Stdin != 0 || rule.AncestorDepth != 3 || rule.SetRole != stableHash("worker") {
		t.Fatal(rule)
	}
	for _, list := range []KernelList{rule.ActorPath, rule.TargetPath, rule.AncestorPath, rule.ActorRole, rule.UID, rule.Container, rule.FSType, rule.ArgContains, rule.ArgPrefix} {
		if list.Count == 0 || int(list.Base+list.Count) > len(program.Entries) {
			t.Fatal("invalid list", list)
		}
	}
	if value := mustDecode[KernelValue](t, program, rule.ActorRole.Base); value.Value != stableHash("agent") {
		t.Fatal(value)
	}
	if value := mustDecode[KernelValue](t, program, rule.UID.Base+1); value.Value != 4294967295 {
		t.Fatal(value)
	}
	if got := program.Rules[1]; got.PolicyID != "policy-z" || got.Revision != "r2" || got.Name != "all-fields" || got.Origin != "test-source" {
		t.Fatal(got)
	}
	secondProgram, err := CompileKernel(kernelFixture(), 77, "worker")
	if err != nil || !reflect.DeepEqual(program, secondProgram) {
		t.Fatal("nondeterministic compilation", err)
	}
}

func TestKernelStableRolesAcrossGenerationsAndPolicyOrder(t *testing.T) {
	policies := kernelFixture()
	a, err := CompileKernel(policies, 1, "worker")
	if err != nil {
		t.Fatal(err)
	}
	policies[0], policies[1] = policies[1], policies[0]
	policies[0].Revision = "new-revision"
	// This is a revision of the same successful UID activations, not a fresh
	// owner: retain the original root epochs while hashes remain stable.
	epochs := map[string]uint64{}
	for _, p := range policies {
		epochs[p.ID] = 1
	}
	b, err := CompileKernelWithRoleEpochs(policies, 2, "worker", epochs)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Entries[1:], b.Entries[1:]) {
		t.Fatal("roles or policy hashes depend on order/generation/revision")
	}
	if _, err := compileKernel(policies, 1, "worker", func(string) uint64 { return 7 }); err == nil {
		t.Fatal("distinct names collided without rejection")
	}
	if _, err := compileKernel(policies, 1, "worker", func(string) uint64 { return 0 }); err == nil {
		t.Fatal("reserved zero ID accepted")
	}
}

func TestKernelBoundariesAndNoPartialResult(t *testing.T) {
	p := []Policy{{ID: "p", Revision: "r", Mode: Enforce, Rules: []Rule{{Name: "allow", Action: Allow}}}}
	for i := 0; i < 128; i++ {
		p[0].Rules[0].Target.Path = append(p[0].Rules[0].Target.Path, fmt.Sprintf("/bin/tool-%d", i))
	}
	compiled, err := CompileKernel(p, 1, "container")
	if err != nil {
		t.Fatal(err)
	}
	rule := mustDecode[KernelRule](t, compiled, 9)
	if rule.TargetPath.Count != 128 {
		t.Fatal("paths silently truncated")
	}
	last := mustDecode[KernelPattern](t, compiled, rule.TargetPath.Base+127)
	if !runKernelPattern(t, compiled, last, "/bin/tool-127") {
		t.Fatal("last pattern lost")
	}
	for _, tc := range []struct {
		generation uint64
		container  string
	}{{0, "container"}, {1, ""}, {1, strings.Repeat("c", 256)}} {
		got, err := CompileKernel(p, tc.generation, tc.container)
		if err == nil || got != nil {
			t.Fatal("invalid candidate returned data")
		}
	}
	// Unique, long exact paths exceed the total code budget, not path-list count.
	p[0].Rules[0].Target.Path = nil
	for i := 0; i < 256; i++ {
		p[0].Rules[0].Target.Path = append(p[0].Rules[0].Target.Path, fmt.Sprintf("/%s-%03d", strings.Repeat("x", 50), i))
	}
	if got, err := CompileKernel(p, 1, "worker"); err == nil || got != nil || !strings.Contains(err.Error(), "instructions") {
		t.Fatal("instruction budget not enforced", err)
	}
	// Non-path values also have a finite aggregate entry budget.
	p[0].Rules = nil
	values := make([]string, MaxValues)
	for i := range values {
		values[i] = "v"
	}
	for i := 0; i < 24; i++ {
		p[0].Rules = append(p[0].Rules, Rule{Name: fmt.Sprint(i), Action: Allow, Actor: Actor{Container: values}, Target: Target{FSType: []string{"tmpfs"}, Argv: &Argv{Contains: values, Prefix: values}}})
	}
	if got, err := CompileKernel(p, 1, "worker"); err == nil || got != nil || !strings.Contains(err.Error(), "entry capacity") {
		t.Fatal("entry budget not enforced", err)
	}
}

func TestKernelPatternDedupAndRangeLimit(t *testing.T) {
	p := []Policy{{ID: "p", Revision: "r", Mode: Audit, Rules: []Rule{{Name: "r", Action: Deny, Actor: Actor{Path: []string{"/same"}}, Target: Target{Path: []string{"/same"}}}}}}
	compiled, err := CompileKernel(p, 1, "worker")
	if err != nil {
		t.Fatal(err)
	}
	rule := mustDecode[KernelRule](t, compiled, 9)
	a, b := mustDecode[KernelPattern](t, compiled, rule.ActorPath.Base), mustDecode[KernelPattern](t, compiled, rule.TargetPath.Base)
	if a != b {
		t.Fatal("identical regex code not reused")
	}
	p[0].Rules[0].Target.Path = []string{"/[acegikmoqs]"}
	if got, err := CompileKernel(p, 1, "worker"); err == nil || got != nil || !strings.Contains(err.Error(), "rune ranges") {
		t.Fatal("oversized rune class broadened", err)
	}
	c := &kernelCompiler{}
	if _, err := c.regex(strings.Repeat("a", MaxRegexStates)); err == nil {
		t.Fatal("per-pattern state limit missing")
	}
	if _, err := packInstruction(syntax.Inst{Op: syntax.InstEmptyWidth, Arg: uint32(syntax.EmptyWordBoundary)}); err == nil {
		t.Fatal("unsupported boundary silently dropped")
	}
}

// Interpret only the packed kernel representation. This verifies code addresses,
// normalized opcodes, Unicode ranges and anchors against the reference regex.
func runKernelPattern(t *testing.T, program *KernelProgram, pattern KernelPattern, text string) bool {
	t.Helper()
	input := []rune(text)
	closure := func(initial []uint32, pos int) ([]uint32, bool) {
		queue := append([]uint32(nil), initial...)
		seen := map[uint32]bool{}
		var consuming []uint32
		matched := false
		for len(queue) > 0 {
			pc := queue[0]
			queue = queue[1:]
			if seen[pc] {
				continue
			}
			seen[pc] = true
			if pc >= pattern.Count {
				t.Fatal("invalid relative PC")
			}
			inst := mustDecode[KernelInstruction](t, program, pattern.CodeBase+pc)
			switch inst.Op {
			case KernelAlt:
				queue = append(queue, inst.Out, inst.Arg)
			case KernelNop:
				queue = append(queue, inst.Out)
			case KernelEmptyWidth:
				if (inst.Arg&KernelBeginText == 0 || pos == 0) && (inst.Arg&KernelEndText == 0 || pos == len(input)) {
					queue = append(queue, inst.Out)
				}
			case KernelRune:
				consuming = append(consuming, pc)
			case KernelMatch:
				matched = true
			case KernelFail:
			default:
				t.Fatal("unknown packed opcode")
			}
		}
		return consuming, matched
	}
	states := []uint32{pattern.Start}
	for pos, r := range input {
		active, _ := closure(states, pos)
		states = nil
		for _, pc := range active {
			inst := mustDecode[KernelInstruction](t, program, pattern.CodeBase+pc)
			for i := uint32(0); i < inst.Count; i++ {
				if uint32(r) >= inst.Ranges[2*i] && uint32(r) <= inst.Ranges[2*i+1] {
					states = append(states, inst.Out)
					break
				}
			}
		}
	}
	_, matched := closure(states, len(input))
	return matched
}

func TestPackedRegexParity(t *testing.T) {
	patterns := []string{"/**", "/usr/*", "/a?/x", "/[a-cx-z]", "/[^a-c]", "/[\\d]", "/工具/**", "/file\\*", "/line?"}
	observations := []string{"/", "/usr/tool", "/usr/tool/sub", "/ab/x", "/a/x", "/b", "/z", "/d", "/5", "/工具/甲", "/file*", "/file1", "/line\n", "prefix/usr/tool"}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			re, err := glob(pattern)
			if err != nil {
				t.Fatal(err)
			}
			p, err := CompileKernel([]Policy{{ID: "p", Revision: "r", Mode: Audit, Rules: []Rule{{Name: "r", Action: Allow, Target: Target{Path: []string{pattern}}}}}}, 1, "worker")
			if err != nil {
				t.Fatal(err)
			}
			rule := mustDecode[KernelRule](t, p, 9)
			descriptor := mustDecode[KernelPattern](t, p, rule.TargetPath.Base)
			for _, observation := range observations {
				if got, want := runKernelPattern(t, p, descriptor, observation), re.MatchString(observation); got != want {
					t.Errorf("%q got%t want%t", observation, got, want)
				}
			}
		})
	}
}

func TestPackInstructionNormalizations(t *testing.T) {
	cases := []struct {
		in        syntax.Inst
		op, count uint32
	}{
		{syntax.Inst{Op: syntax.InstAltMatch, Out: 1, Arg: 2}, KernelAlt, 0},
		{syntax.Inst{Op: syntax.InstCapture, Out: 3, Arg: 4}, KernelNop, 0},
		{syntax.Inst{Op: syntax.InstRune1, Rune: []rune{'é'}}, KernelRune, 1},
		{syntax.Inst{Op: syntax.InstRuneAny}, KernelRune, 1},
		{syntax.Inst{Op: syntax.InstRuneAnyNotNL}, KernelRune, 2},
	}
	for _, tc := range cases {
		out, err := packInstruction(tc.in)
		if err != nil || out.Op != tc.op || out.Count != tc.count {
			t.Fatal(out, err)
		}
	}
	if _, err := packInstruction(syntax.Inst{Op: syntax.InstRune, Arg: uint32(syntax.FoldCase), Rune: []rune{'a'}}); err == nil {
		t.Fatal("unsupported folding accepted")
	}
	if _, err := packInstruction(syntax.Inst{Op: syntax.InstRune, Rune: []rune{-1}}); err == nil {
		t.Fatal("invalid rune accepted")
	}
	if _, err := packInstruction(syntax.Inst{Op: syntax.InstOp(255)}); err == nil {
		t.Fatal("unknown opcode accepted")
	}
}
