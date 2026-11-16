// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func buildMatcherRunner(t *testing.T, flags ...string) string {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("plain-C matcher validation requires clang")
	}
	binary := filepath.Join(t.TempDir(), "matcher")
	args := []string{"-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"}
	args = append(args, flags...)
	args = append(args, "testdata/matcher_runner.c", "-o", binary)
	if output, err := exec.Command(clang, args...).CombinedOutput(); err != nil {
		t.Fatalf("compile matcher: %v\n%s", err, output)
	}
	return binary
}

func TestScalarGlobalMatcherContext(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("plain-C scalar matcher validation requires clang")
	}
	binary := filepath.Join(t.TempDir(), "matcher-scalar")
	if output, err := exec.Command(clang, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "testdata/matcher_scalar_context.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile scalar matcher: %v\n%s", err, output)
	}
	if output, err := exec.Command(binary).CombinedOutput(); err != nil || !strings.Contains(string(output), "scalar matcher context PASS") {
		t.Fatalf("scalar matcher: %v\n%s", err, output)
	}
}

func TestWorkRunStateMatcherContext(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("plain-C WORK matcher validation requires clang")
	}
	for _, opt := range []string{"-O0", "-O2"} {
		t.Run(opt, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "matcher-work-run")
			if output, err := exec.Command(clang, "-std=c11", opt, "-Wall", "-Wextra", "-Werror", "testdata/matcher_work_run_state.c", "-o", binary).CombinedOutput(); err != nil {
				t.Fatalf("compile WORK matcher: %v\n%s", err, output)
			}
			if output, err := exec.Command(binary).CombinedOutput(); err != nil || !strings.Contains(string(output), "WORK run state PASS") {
				t.Fatalf("WORK matcher: %v\n%s", err, output)
			}
		})
	}
}

func runCMatcher(t *testing.T, runner string, entries []Blob, key uint32, input []byte) int {
	t.Helper()
	path := filepath.Join(t.TempDir(), "program.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if _, err := file.Write(entry[:]); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(runner, path, strconv.FormatUint(uint64(key), 10), hex.EncodeToString(input)).CombinedOutput()
	if err != nil {
		t.Fatalf("run matcher: %v\n%s", err, output)
	}
	result, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatal(err, string(output))
	}
	return result
}

func compileMatcherPattern(t *testing.T, pattern string) (*KernelProgram, uint32) {
	t.Helper()
	p, err := CompileKernel([]Policy{{ID: "policy", Revision: "revision", Mode: Enforce, Rules: []Rule{{Name: "rule", Action: Allow, Target: Target{Path: []string{pattern}}}}}}, 1, "container")
	if err != nil {
		t.Fatal(err)
	}
	rule := mustDecode[KernelRule](t, p, KernelRuleBase)
	return p, rule.TargetPath.Base
}

func TestCMatcherReferenceParity(t *testing.T) {
	runMatcherReferenceParity(t, buildMatcherRunner(t))
}

func TestCMatcherBoundedGlobalReferenceParity(t *testing.T) {
	runMatcherReferenceParity(t, buildMatcherRunner(t,
		"-DFE_BOUNDED_LOOP_CANDIDATE", "-DFM_CANDIDATE_GLOBAL_TEST"))
}

func TestCMatcherWorkRunStateReferenceParity(t *testing.T) {
	runMatcherReferenceParity(t, buildMatcherRunner(t,
		"-DFE_BOUNDED_LOOP_CANDIDATE", "-DFM_WORK_RUN_STATE_DIAGNOSTIC"))
}

func runMatcherReferenceParity(t *testing.T, runner string) {
	patterns := []string{"/**", "/usr/*", "/a?/x", "/[a-cx-z]", "/[^a-c]", "/[\\d]", "/工具/**", "/file\\*", "/line?", "/*a*a*a*a*a*", "/**/**/**", "/😀?", "/[α-ω]"}
	inputs := []string{"", "/", "/usr/tool", "/usr/tool/sub", "/ab/x", "/a/x", "/b", "/z", "/d", "/5", "/工具/甲", "/file*", "/file1", "/line\n", "prefix/usr/tool", "/aaaaa", "/aaaaab", "/😀é", "/λ", "/x/y/z", "/" + strings.Repeat("a", 254)}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			p, key := compileMatcherPattern(t, pattern)
			oracle, err := glob(pattern)
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range inputs {
				got := runCMatcher(t, runner, p.Entries, key, []byte(input))
				want := 0
				if oracle.MatchString(input) {
					want = 1
				}
				if got != want {
					t.Errorf("%q got%d want%d", input, got, want)
				}
			}
		})
	}
}

func TestCMatcherRejectsInvalidOrIncompleteBytes(t *testing.T) {
	runner := buildMatcherRunner(t)
	p, key := compileMatcherPattern(t, "/**")
	malformed := [][]byte{{'/', 0}, {'/', 0x80}, {'/', 0xc0, 0xaf}, {'/', 0xc1, 0xbf}, {'/', 0xc2}, {'/', 0xe2, 0x82}, {'/', 0xe0, 0x80, 0xaf}, {'/', 0xed, 0xa0, 0x80}, {'/', 0xf0, 0x80, 0x80, 0xaf}, {'/', 0xf4, 0x90, 0x80, 0x80}, {'/', 0xf5, 0x80, 0x80, 0x80}, []byte("/" + strings.Repeat("a", 255))}
	for i, input := range malformed {
		if got := runCMatcher(t, runner, p.Entries, key, input); got != -1 {
			t.Errorf("case%d got%d; malformed input must error", i, got)
		}
	}
	// Invalid suffix remains an error even after the automaton has no live states.
	p, key = compileMatcherPattern(t, "/exact")
	if got := runCMatcher(t, runner, p.Entries, key, []byte{'/', 'z', 0xff}); got != -1 {
		t.Fatal("invalid suffix treated as ordinary mismatch", got)
	}
}

func TestCMatcherBoundsAndEpsilonCycles(t *testing.T) {
	runMatcherBoundsAndEpsilonCycles(t, buildMatcherRunner(t))
}

func TestCMatcherBoundedGlobalBoundsAndEpsilonCycles(t *testing.T) {
	runMatcherBoundsAndEpsilonCycles(t, buildMatcherRunner(t,
		"-DFE_BOUNDED_LOOP_CANDIDATE", "-DFM_CANDIDATE_GLOBAL_TEST"))
}

func TestCMatcherWorkRunStateBoundsAndEpsilonCycles(t *testing.T) {
	runMatcherBoundsAndEpsilonCycles(t, buildMatcherRunner(t,
		"-DFE_BOUNDED_LOOP_CANDIDATE", "-DFM_WORK_RUN_STATE_DIAGNOSTIC"))
}

func runMatcherBoundsAndEpsilonCycles(t *testing.T, runner string) {
	makeEntries := func(pattern KernelPattern, code []KernelInstruction) []Blob {
		entries := make([]Blob, 2+len(code))
		var err error
		entries[1], err = encode(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for i, inst := range code {
			entries[2+i], err = encode(inst)
			if err != nil {
				t.Fatal(err)
			}
		}
		return entries
	}
	// A cycle is valid and terminates; matching must not depend on recursion limits.
	code := []KernelInstruction{{Op: KernelAlt, Out: 0, Arg: 1}, {Op: KernelMatch}}
	entries := makeEntries(KernelPattern{CodeBase: 2, Start: 0, Count: 2}, code)
	if got := runCMatcher(t, runner, entries, 1, nil); got != 1 {
		t.Fatal("epsilon cycle failed", got)
	}
	if got := runCMatcher(t, runner, entries, 1, []byte("x")); got != 0 {
		t.Fatal("matched a substring", got)
	}
	// Exactly512 reachable states fit;513 must fail before any out-of-bounds access.
	code = make([]KernelInstruction, MaxRegexStates)
	for i := range code {
		code[i] = KernelInstruction{Op: KernelNop, Out: uint32(i + 1)}
	}
	code[len(code)-1] = KernelInstruction{Op: KernelMatch}
	entries = makeEntries(KernelPattern{CodeBase: 2, Count: MaxRegexStates}, code)
	if got := runCMatcher(t, runner, entries, 1, nil); got != 1 {
		t.Fatal("512-state closure failed", got)
	}
	invalid := []struct {
		name    string
		pattern KernelPattern
		code    []KernelInstruction
	}{
		{"too-many-states", KernelPattern{CodeBase: 2, Count: 513}, code},
		{"zero-states", KernelPattern{CodeBase: 2}, code},
		{"bad-start", KernelPattern{CodeBase: 2, Count: 1, Start: 1}, code},
		{"address-overflow", KernelPattern{CodeBase: ^uint32(0), Count: 1}, code},
		{"missing-map-entry", KernelPattern{CodeBase: 10, Count: 1}, []KernelInstruction{{Op: KernelMatch}}},
		{"bad-next-pc", KernelPattern{CodeBase: 2, Count: 1}, []KernelInstruction{{Op: KernelNop, Out: 1}}},
		{"bad-alt-pc", KernelPattern{CodeBase: 2, Count: 1}, []KernelInstruction{{Op: KernelAlt, Arg: 1}}},
		{"bad-boundary", KernelPattern{CodeBase: 2, Count: 1}, []KernelInstruction{{Op: KernelEmptyWidth, Arg: 16}}},
		{"unknown-op", KernelPattern{CodeBase: 2, Count: 1}, []KernelInstruction{{Op: 100}}},
		{"too-many-ranges", KernelPattern{CodeBase: 2, Count: 1}, []KernelInstruction{{Op: KernelRune, Count: 9}}},
		{"reversed-range", KernelPattern{CodeBase: 2, Count: 1}, []KernelInstruction{{Op: KernelRune, Count: 1, Ranges: [16]uint32{10, 1}}}},
		{"non-unicode-range", KernelPattern{CodeBase: 2, Count: 1}, []KernelInstruction{{Op: KernelRune, Count: 1, Ranges: [16]uint32{0, 0x110000}}}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			entries := makeEntries(tc.pattern, tc.code)
			if got := runCMatcher(t, runner, entries, 1, nil); got != -1 {
				t.Fatal("malformed program accepted", got)
			}
		})
	}
}

func TestMatcherCompilesForBPF(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("BPF compile-only check requires clang")
	}
	header, err := filepath.Abs("bpf/matcher.h")
	if err != nil {
		t.Fatal(err)
	}
	// Minimal map-backed harness. This compiles code generation only: it neither
	// loads the object into a kernel verifier nor attaches any BPF program.
	source := fmt.Sprintf(`
struct fm_blob;
static inline const struct fm_blob *lookup(void *, unsigned int);
#define FM_BLOB_LOOKUP(context, key) lookup(context, key)
#include %q
#define SEC(name) __attribute__((section(name), used))
#define MAP_UINT(name, value) int (*name)[value]
#define MAP_TYPE(name, value) value *name
struct { MAP_UINT(type, 2); MAP_UINT(max_entries, FM_MAX_ENTRIES); MAP_TYPE(key, fm_u32); MAP_TYPE(value, struct fm_blob); } policy SEC(".maps");
struct { MAP_UINT(type, 2); MAP_UINT(max_entries, 1); MAP_TYPE(key, fm_u32); MAP_TYPE(value, struct fm_scratch); } scratch_map SEC(".maps");
struct input { struct fm_pattern pattern; fm_u8 bytes[256]; fm_u32 length; };
struct { MAP_UINT(type, 2); MAP_UINT(max_entries, 1); MAP_TYPE(key, fm_u32); MAP_TYPE(value, struct input); } input_map SEC(".maps");
static void *(*map_lookup)(void *, const void *) = (void *)1;
static inline const struct fm_blob *lookup(void *context, unsigned int key) { return map_lookup(context, &key); }
SEC("socket") int matcher(void *unused) {
 (void)unused;
 fm_u32 zero=0;
 struct input *input=map_lookup(&input_map,&zero);
 struct fm_scratch *scratch=map_lookup(&scratch_map,&zero);
 if (!input || !scratch) return 0;
 return fm_match(&policy,&input->pattern,input->bytes,input->length,scratch);
}
char LICENSE[] SEC("license") = "GPL";
`, header)
	dir := t.TempDir()
	cpath := filepath.Join(dir, "matcher.bpf.c")
	object := filepath.Join(dir, "matcher.bpf.o")
	if err := os.WriteFile(cpath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(clang, "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-c", cpath, "-o", object).CombinedOutput()
	if err != nil {
		t.Fatalf("BPF compile-only check failed: %v\n%s", err, output)
	}
	info, err := os.Stat(object)
	if err != nil || info.Size() == 0 {
		t.Fatal("missing BPF artifact", err)
	}
}
