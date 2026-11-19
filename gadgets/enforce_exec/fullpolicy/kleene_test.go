// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// G004 Kleene AND (user decision): a rule is the Kleene AND of its
// conjuncts. These tests prove the change is a refinement of the previous
// sequential evaluation: a known result never changes, an error becomes known
// false only when some conjunct is known false, never true; and that an
// evaluator treating "unknown AND false" as an error, or "unknown" as true,
// is caught (Go here, C in TestKleeneCMutantsCaught).

// kleeneConj is one conjunct: it sets the rule's predicate and the fact
// that makes it known true (1), known false (0) or UNKNOWN (-1).
type kleeneConj struct {
	name string
	set  func(r *Rule, f *Facts, role *string, v int)
}

// kleeneContainer is the container conjunct's index (structural when
// UNKNOWN).
const kleeneContainer = 3

func kleeneConjuncts() []kleeneConj {
	yes, no := true, false
	pick := func(v int, t, f, u string) string { return map[int]string{1: t, 0: f, -1: u}[v] }
	return []kleeneConj{
		{"actor-path", func(r *Rule, f *Facts, _ *string, v int) {
			r.Actor.Path = []string{"/usr/**"}
			f.ActorPath = pick(v, "/usr/bin/x", "/opt/x", "")
		}},
		{"target-path", func(r *Rule, f *Facts, _ *string, v int) {
			r.Target.Path = []string{"/bin/*"}
			f.TargetPath = pick(v, "/bin/tool", "/sbin/tool", "")
		}},
		{"role", func(r *Rule, _ *Facts, role *string, v int) {
			r.Actor.Role = []string{"root"}
			*role = pick(v, "root", "child", "")
		}},
		{"container", func(r *Rule, f *Facts, _ *string, v int) {
			r.Actor.Container = []string{"worker"}
			f.Container = pick(v, "worker", "other", "")
		}},
		{"uid", func(r *Rule, f *Facts, _ *string, v int) {
			r.Actor.UID = []int64{1000}
			u := map[int]uint32{1: 1000, 0: 42}[v]
			f.EffectiveUID = &u
			if v < 0 {
				f.EffectiveUID = nil
			}
		}},
		{"actor-image", func(r *Rule, f *Facts, _ *string, v int) {
			r.Actor.FromImage = &yes
			f.ActorFromImage = map[int]*bool{1: &yes, 0: &no, -1: nil}[v]
		}},
		{"target-image", func(r *Rule, f *Facts, _ *string, v int) {
			r.Target.FromImage = &no
			f.TargetFromImage = map[int]*bool{1: &no, 0: &yes, -1: nil}[v]
		}},
		{"filesystem", func(r *Rule, f *Facts, _ *string, v int) {
			r.Target.FSType = []string{"tmpfs"}
			f.FSType, f.FileKindsKnown = pick(v, "tmpfs", "ext4", ""), nil
			if v == 0 {
				f.FileKindsKnown = []string{"tmpfs"}
			}
		}},
		{"ancestor", func(r *Rule, f *Facts, _ *string, v int) {
			r.Actor.Ancestor = &Ancestor{Path: []string{"/bin/init"}, Depth: 2}
			f.Ancestors, f.AncestorsComplete = map[int][]string{1: {"/bin/init"}, 0: {"/other"}, -1: nil}[v], v >= 0
		}},
		{"argv", func(r *Rule, f *Facts, _ *string, v int) {
			if r.Target.Argv == nil {
				r.Target.Argv = &Argv{}
			}
			r.Target.Argv.Contains = []string{"--x"}
			f.Argv, f.ArgvComplete = map[int][]string{1: {"a", "--x"}, 0: {"a"}, -1: {"a", "--x"}}[v], v >= 0
		}},
		{"stdin", func(r *Rule, f *Facts, _ *string, v int) {
			if r.Target.Argv == nil {
				r.Target.Argv = &Argv{}
			}
			r.Target.Argv.StdinIsPipe = &yes
			f.StdinIsPipe = map[int]*bool{1: &yes, 0: &no, -1: nil}[v]
		}},
	}
}

// kleeneCase builds a rule and facts from per-conjunct states (2: absent).
func kleeneCase(t *testing.T, states []int) (compiledRule, Facts, string) {
	t.Helper()
	r := Rule{Name: "k", Action: Deny}
	f := Facts{ArgvComplete: true}
	role := "root"
	for i, c := range kleeneConjuncts() {
		if states[i] != 2 {
			c.set(&r, &f, &role, states[i])
		}
	}
	p, err := CompileReference([]Policy{{ID: "p", Revision: "r", Mode: Enforce, RootRole: "root", Rules: []Rule{r}}})
	if err != nil {
		t.Fatalf("%v: %v", states, err)
	}
	return p.policies[0].rules[0], f, role
}

// kleeneViolations checks eval against the Kleene AND of states and
// against the previous sequential evaluation; it returns the violations.
func kleeneViolations(t *testing.T, eval func(compiledRule, Facts, string) (bool, error), cases [][]int) []string {
	var out []string
	for _, states := range cases {
		r, f, role := kleeneCase(t, states)
		want, anyFalse := 1, false
		for _, s := range states {
			switch s {
			case 0:
				anyFalse = true
			case -1:
				want = -1
			}
		}
		if anyFalse {
			want = 0
		}
		// An unavailable container name is structural (the native
		// program compiles it in): an error, unless a conjunct checked
		// BEFORE it is known false (the previous sequential evaluator
		// stopped there too; reporting it would change a known result).
		if states[kleeneContainer] == -1 && !slices.Contains(states[:kleeneContainer], 0) {
			want = -1
		}
		ok, err := eval(r, f, role)
		got := map[bool]int{true: 1, false: 0}[ok]
		if err != nil {
			got = -1
		}
		if got != want {
			out = append(out, fmt.Sprintf("%v: got %d want %d", states, got, want))
		}
		sok, serr := ruleMatchesSequential(r, f, role)
		switch {
		case serr == nil && (err != nil || ok != sok):
			out = append(out, fmt.Sprintf("%v: known result changed %v -> %v %v", states, sok, ok, err))
		case serr != nil && err == nil && ok:
			out = append(out, fmt.Sprintf("%v: error became true", states))
		case serr != nil && err == nil && !anyFalse:
			out = append(out, fmt.Sprintf("%v: error became false with no known false conjunct", states))
		}
	}
	return out
}

func kleeneCases() [][]int {
	n := len(kleeneConjuncts())
	var cases [][]int
	// Every pair of conjuncts in every state, the rest absent.
	for i := 0; i < n; i++ {
		for j := i; j < n; j++ {
			for _, a := range []int{1, 0, -1} {
				for _, b := range []int{1, 0, -1} {
					c := slices.Repeat([]int{2}, n)
					c[i], c[j] = a, b
					cases = append(cases, c)
				}
			}
		}
	}
	// Random full combinations.
	rnd := rand.New(rand.NewSource(4004))
	for k := 0; k < 20000; k++ {
		c := make([]int, n)
		for i := range c {
			c[i] = []int{2, 1, 0, -1}[rnd.Intn(4)]
		}
		cases = append(cases, c)
	}
	return cases
}

func TestKleeneANDRefinesSequential(t *testing.T) {
	cases := kleeneCases()
	if v := kleeneViolations(t, ruleMatches, cases); len(v) != 0 {
		t.Fatalf("%d violations, first: %s", len(v), v[0])
	}
	t.Logf("%d rule/fact combinations over %d conjuncts", len(cases), len(kleeneConjuncts()))
}

func TestKleeneGoMutantsCaught(t *testing.T) {
	cases := kleeneCases()
	for name, m := range map[string]func(compiledRule, Facts, string) (bool, error){
		// unknown AND false = error: the previous sequential evaluator.
		"unknown-and-false-is-error": ruleMatchesSequential,
		// unknown = true.
		"unknown-is-true": func(r compiledRule, f Facts, role string) (bool, error) {
			ok, err := ruleMatches(r, f, role)
			if err != nil {
				return true, nil
			}
			return ok, nil
		},
	} {
		if v := kleeneViolations(t, m, cases); len(v) == 0 {
			t.Errorf("mutant %s not caught", name)
		} else {
			t.Logf("mutant %s caught: %d violations (%s)", name, len(v), v[0])
		}
	}
}

// TestKleeneCMutantsCaught rebuilds the C evaluator from a copy of
// bpf/evaluator.h whose Kleene AND is mutated, for both C matchers (the
// global matcher of the product and option C builds, and the predicate
// callback matcher), and runs the Go-vs-C parity (default build and the
// exact E1 option C compat set) on its Kleene cases in a child process: it
// must fail.
func TestKleeneCMutantsCaught(t *testing.T) {
	if os.Getenv("FE_KLEENE_MUTANT") != "" {
		t.Skip("child")
	}
	for _, m := range []string{"error", "true"} {
		for _, test := range []string{"TestCEvaluatorReferenceParity", "TestCEvaluatorE1OptionCCompatParity"} {
			cmd := exec.Command(os.Args[0], "-test.run", "^"+test+"$/kleene", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(), "FE_KLEENE_MUTANT="+m)
			out, err := cmd.CombinedOutput()
			fails := regexp.MustCompile(`--- FAIL: \S+/kleene-\S+`).FindAllString(string(out), -1)
			if err == nil || len(fails) == 0 {
				t.Errorf("mutant %s in %s not caught (err %v):\n%s", m, test, err, out)
				continue
			}
			t.Logf("mutant %s in %s caught: %d Kleene cases fail, e.g. %s", m, test, len(fails), fails[0])
		}
	}
}

// kleeneMutantSource returns runner (a testdata C file) in a copy of the
// evaluator sources whose Kleene AND is mutated, when FE_KLEENE_MUTANT is
// set ("error": an UNKNOWN conjunct is an error at once; "true": it is
// ignored), else runner itself.
func kleeneMutantSource(t *testing.T, runner string) string {
	m := os.Getenv("FE_KLEENE_MUTANT")
	if m == "" {
		return runner
	}
	dir := t.TempDir()
	for _, d := range []string{"bpf", "testdata"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"bpf/evaluator.h", "bpf/evaluator_stage_candidate.h", "bpf/matcher.h", runner} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if name == "bpf/evaluator.h" {
			plain := regexp.MustCompile(`(^|[^\w>])unknown = 1;`)
			callback := "pc->unknown = 1;\n\treturn 0;"
			if !strings.Contains(s, callback) || len(plain.FindAllString(s, -1)) < 10 {
				t.Fatal("evaluator.h no longer has the Kleene AND this mutant rewrites")
			}
			switch m {
			case "error":
				s = plain.ReplaceAllString(s, "${1}return -1;")
				s = strings.Replace(s, callback, "pc->result = -1;\n\treturn 1;", 1)
			case "true":
				s = plain.ReplaceAllString(s, "${1}(void)0;")
				s = strings.Replace(s, callback, "(void)pc;\n\treturn 0;", 1)
			default:
				t.Fatalf("mutant %q", m)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, runner)
}

func ruleMatchesSequential(r compiledRule, f Facts, role string) (bool, error) {
	a, t := r.source.Actor, r.source.Target
	if len(r.actor) > 0 {
		if f.ActorPath == "" {
			return false, fmt.Errorf("actor executable unavailable")
		}
		if !pathMatches(r.actor, f.ActorPath) {
			return false, nil
		}
	}
	if len(r.target) > 0 {
		if f.TargetPath == "" {
			return false, fmt.Errorf("target executable unavailable")
		}
		if !pathMatches(r.target, f.TargetPath) {
			return false, nil
		}
	}
	if len(a.Role) > 0 {
		if role == "" {
			return false, fmt.Errorf("inherited role unavailable")
		}
		if !slices.Contains(a.Role, role) {
			return false, nil
		}
	}
	if len(a.Container) > 0 {
		if f.Container == "" {
			return false, fmt.Errorf("container name unavailable")
		}
		if !slices.Contains(a.Container, f.Container) {
			return false, nil
		}
	}
	if len(a.UID) > 0 {
		if f.EffectiveUID == nil {
			return false, fmt.Errorf("effective UID unavailable")
		}
		if !slices.Contains(a.UID, int64(*f.EffectiveUID)) {
			return false, nil
		}
	}
	if a.FromImage != nil {
		if f.ActorFromImage == nil {
			return false, fmt.Errorf("actor image provenance unavailable")
		}
		if *a.FromImage != *f.ActorFromImage {
			return false, nil
		}
	}
	if t.FromImage != nil {
		if f.TargetFromImage == nil {
			return false, fmt.Errorf("target image provenance unavailable")
		}
		if *t.FromImage != *f.TargetFromImage {
			return false, nil
		}
	}
	if len(t.FSType) > 0 {
		found, unknown := false, false
		for _, kind := range t.FSType {
			positive := kind == f.FSType || slices.Contains(f.FileKinds, kind)
			found = found || positive
			unknown = unknown || (!positive && !slices.Contains(f.FileKindsKnown, kind))
		}
		// OR accepts a known positive even if another class is unknown.
		if !found {
			if unknown {
				return false, fmt.Errorf("target filesystem classification unavailable")
			}
			return false, nil
		}
	}
	if a.Ancestor != nil {
		depth := int(a.Ancestor.Depth)
		found := false
		for i, path := range f.Ancestors {
			if i >= depth {
				break
			}
			if path == "" {
				return false, fmt.Errorf("ancestor executable unavailable")
			}
			if pathMatches(r.ancestor, path) {
				found = true
				break
			}
		}
		if !found {
			if len(f.Ancestors) < depth && !f.AncestorsComplete {
				return false, fmt.Errorf("ancestor traversal incomplete")
			}
			return false, nil
		}
	}
	if a := t.Argv; a != nil {
		if len(a.Contains) > 0 || len(a.Prefix) > 0 {
			if !f.ArgvComplete || len(f.Argv) > MaxArgc {
				return false, fmt.Errorf("staged argv incomplete or oversized")
			}
			size := 0
			for _, arg := range f.Argv {
				if strings.ContainsRune(arg, 0) {
					return false, fmt.Errorf("invalid staged argument")
				}
				size += len(arg) + 1
			}
			if size > MaxArgBytes {
				return false, fmt.Errorf("staged argv exceeds %d bytes", MaxArgBytes)
			}
			// Lists are alternatives. Contains matches a complete argument, prefix matches
			// the beginning of an argument (not a lossy space-joined command line).
			if len(a.Contains) > 0 {
				found := false
				for _, v := range a.Contains {
					if slices.Contains(f.Argv, v) {
						found = true
						break
					}
				}
				if !found {
					return false, nil
				}
			}
			if len(a.Prefix) > 0 {
				found := false
				for _, v := range a.Prefix {
					for _, arg := range f.Argv {
						if strings.HasPrefix(arg, v) {
							found = true
							break
						}
					}
				}
				if !found {
					return false, nil
				}
			}
		}
		if a.StdinIsPipe != nil {
			if f.StdinIsPipe == nil {
				return false, fmt.Errorf("stdin identity unavailable")
			}
			if *a.StdinIsPipe != *f.StdinIsPipe {
				return false, nil
			}
		}
	}
	return true, nil
}

// kleeneCRunners builds every C evaluator runner variant the parity tests
// use: the default build (predicate-callback matcher), the fixed-map, staged,
// bounded-loop and header-relookup builds, and the exact E1 option C compat
// set (global matcher, as in optc.bpf.c).
func kleeneCRunners(t *testing.T) map[string]string {
	t.Helper()
	runners := map[string]string{"e1-compat": buildE1CompatRunner(t)}
	for name, flags := range map[string][]string{
		"default":             nil,
		"fixed-map":           {"-DFE_FIXED_MAP_TEST"},
		"stage":               {"-DFE_STAGE_CANDIDATE"},
		"stage-bounded":       {"-DFE_STAGE_CANDIDATE", "-DFE_BOUNDED_LOOP_CANDIDATE"},
		"stage-bounded-fixed": {"-DFE_STAGE_CANDIDATE", "-DFE_BOUNDED_LOOP_CANDIDATE", "-DFE_FIXED_MAP_TEST"},
		"stage-relookup":      {"-DFE_STAGE_CANDIDATE", "-DFE_BOUNDED_LOOP_CANDIDATE", "-DFE_FIXED_MAP_TEST", "-DFE_STAGE_RELOOKUP_HEADER_CANDIDATE"},
	} {
		runners[name] = buildEvaluatorRunner(t, flags...)
	}
	return runners
}

// runCEvaluatorIn is runCEvaluator in a caller-owned directory (no t).
func runCEvaluatorIn(dir, runner string, p *KernelProgram, facts evaluatorFacts) ([]uint64, error) {
	var program, data bytes.Buffer
	for _, entry := range p.Entries {
		program.Write(entry[:])
	}
	if err := binary.Write(&data, binary.LittleEndian, facts); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "program"), program.Bytes(), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "facts"), data.Bytes(), 0o600); err != nil {
		return nil, err
	}
	out, err := exec.Command(runner, filepath.Join(dir, "program"), filepath.Join(dir, "facts")).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("runner %w: %s", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) != 21 {
		return nil, fmt.Errorf("bad response: %s", out)
	}
	values := make([]uint64, 21)
	for i, field := range fields {
		if i == 0 && field == "-1" {
			values[i] = ^uint64(0)
			continue
		}
		if values[i], err = strconv.ParseUint(field, 10, 64); err != nil {
			return nil, err
		}
	}
	return values, nil
}

// kleeneDecision is the Go reference's decision for one rule: -1 error, 1
// deny (the rule matched), 0 allow; and the C runner's.
func kleeneGoDecision(policies []Policy, f Facts) (int, error) {
	prog, err := Compile(policies)
	if err != nil {
		return 0, err
	}
	d, err := prog.Evaluate(f)
	if err != nil {
		return -1, nil
	}
	if d.Action == Deny {
		return 1, nil
	}
	return 0, nil
}

func kleeneCDecision(got []uint64) int {
	if got[0] == ^uint64(0) || got[0] != 0 {
		return -1
	}
	return int(got[1])
}

// kleenePolicy wraps one deny rule: default allow, Strict.
func kleenePolicy(r Rule) []Policy {
	return []Policy{{ID: "p", Revision: "r", Mode: Enforce, RootRole: "root", Default: Allow, Rules: []Rule{r}}}
}

// TestKleeneCorpusGoVsEveryCRunner (review C2): the 20594-case Kleene corpus,
// the Go reference against every C runner variant. Container UNKNOWN cases
// are left out here (the C container is compiled in, so its absence is a
// malformed program: TestKleeneStructuralNotMasked covers it).
func TestKleeneCorpusGoVsEveryCRunner(t *testing.T) {
	runners := kleeneCRunners(t)
	type item struct {
		states []int
		prog   *KernelProgram
		facts  evaluatorFacts
		want   int
	}
	var items []item
	for _, states := range kleeneCases() {
		if states[kleeneContainer] == -1 {
			continue
		}
		cr, f, role := kleeneCase(t, states)
		r := cr.source
		if role != "" {
			f.Roles = map[string]string{"p": role}
		}
		container := "worker"
		if states[kleeneContainer] == 2 {
			f.Container = "worker"
		}
		policies := kleenePolicy(r)
		prog, err := CompileKernel(policies, 1, container)
		if err != nil {
			t.Fatalf("%v: %v", states, err)
		}
		if f.Container == "other" {
			// The C container is the compiled one: compile the false
			// case with the other name.
			if prog, err = CompileKernel(policies, 1, "other"); err != nil {
				t.Fatal(err)
			}
		}
		want, err := kleeneGoDecision(policies, f)
		if err != nil {
			t.Fatalf("%v: %v", states, err)
		}
		items = append(items, item{states, prog, evaluatorFactBytes(t, prog, policies, f), want})
	}
	for name, runner := range runners {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			const workers = 8
			work := make(chan item)
			var mu sync.Mutex
			var bad []string
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				dir := t.TempDir()
				wg.Add(1)
				go func() {
					defer wg.Done()
					for it := range work {
						got, err := runCEvaluatorIn(dir, runner, it.prog, it.facts)
						mu.Lock()
						if err != nil {
							bad = append(bad, fmt.Sprintf("%v: %v", it.states, err))
						} else if c := kleeneCDecision(got); c != it.want {
							bad = append(bad, fmt.Sprintf("%v: C %d, Go %d", it.states, c, it.want))
						}
						mu.Unlock()
					}
				}()
			}
			for _, it := range items {
				work <- it
			}
			close(work)
			wg.Wait()
			if len(bad) != 0 {
				t.Fatalf("%d of %d differ, first: %s", len(bad), len(items), bad[0])
			}
			t.Logf("%s: %d cases, Go == C", name, len(items))
		})
	}
}

// TestKleeneStructuralNotMasked (review C1): a malformed program or rule
// next to a LATER known-false conjunct is an error (Strict denies), in Go and
// in every C runner; Kleene AND defers only facts the backend could not
// acquire.
func TestKleeneStructuralNotMasked(t *testing.T) {
	uid := uint32(1000)
	no := false
	base := Facts{
		ActorPath: "/usr/bin/x", TargetPath: "/bin/tool", EffectiveUID: &uid, Container: "worker", StdinIsPipe: &no,
		Ancestors: []string{"/bin/init"}, AncestorsComplete: true, ArgvComplete: true,
	}
	yes := true
	// Every rule ends with a known-false stdin conjunct (the last one).
	falseTail := func(r Rule) Rule {
		r.Name, r.Action = "k", Deny
		if r.Target.Argv == nil {
			r.Target.Argv = &Argv{}
		}
		r.Target.Argv.StdinIsPipe = &yes
		return r
	}
	// Go: structural faults the reference can see.
	{
		r := falseTail(Rule{Actor: Actor{Ancestor: &Ancestor{Path: []string{"/bin/init"}, Depth: 2}}})
		p, err := CompileReference(kleenePolicy(r))
		if err != nil {
			t.Fatal(err)
		}
		cr := p.policies[0].rules[0]
		cr.source.Actor.Ancestor = &Ancestor{Path: []string{"/bin/init"}, Depth: 0} // malformed
		if ok, err := ruleMatches(cr, base, "root"); ok || err == nil {
			t.Errorf("Go: malformed ancestor depth next to a known false: %v %v, want an error", ok, err)
		}
		r = falseTail(Rule{Actor: Actor{Container: []string{"worker"}}})
		f := base
		f.Container = ""
		if d, _ := kleeneGoDecision(kleenePolicy(r), f); d != -1 {
			t.Errorf("Go: container unavailable next to a known false: decision %d, want error", d)
		}
	}
	// C: corrupt the compiled program.
	type corruption struct {
		name string
		rule Rule
		edit func(t *testing.T, p *KernelProgram)
	}
	ruleKey := func(p *KernelProgram) uint32 { return KernelRuleBase }
	editRule := func(f func(*KernelRule)) func(*testing.T, *KernelProgram) {
		return func(t *testing.T, p *KernelProgram) {
			r := mustDecode[KernelRule](t, p, ruleKey(p))
			f(&r)
			p.Entries[ruleKey(p)] = encodeKernelRule(r)
		}
	}
	editString := func(list func(KernelRule) KernelList, f func(*KernelString)) func(*testing.T, *KernelProgram) {
		return func(t *testing.T, p *KernelProgram) {
			key := list(mustDecode[KernelRule](t, p, ruleKey(p))).Base
			s := mustDecode[KernelString](t, p, key)
			f(&s)
			p.Entries[key] = encodeKernelString(s)
		}
	}
	for _, c := range []corruption{
		{"invalid-target-list", Rule{Target: Target{Path: []string{"/bin/*"}}}, editRule(func(r *KernelRule) { r.TargetPath.Count = 300 })},
		{"missing-target-blob", Rule{Target: Target{Path: []string{"/bin/*"}}}, editRule(func(r *KernelRule) { r.TargetPath.Base = 70000 })},
		{"uid-list-past-the-program", Rule{Actor: Actor{UID: []int64{1000}}}, editRule(func(r *KernelRule) { r.UID.Base = 65000 })},
		{"container-string-over-255", Rule{Actor: Actor{Container: []string{"worker"}}}, editString(func(r KernelRule) KernelList { return r.Container }, func(s *KernelString) { s.Length = 300 })},
		{"unknown-fs-class", Rule{Target: Target{FSType: []string{"tmpfs"}}}, editString(func(r KernelRule) KernelList { return r.FSType }, func(s *KernelString) { copy(s.Bytes[:], "zzzzz") })},
		{"ancestor-depth-zero", Rule{Actor: Actor{Ancestor: &Ancestor{Path: []string{"/bin/init"}, Depth: 2}}}, editRule(func(r *KernelRule) { r.AncestorDepth = 0 })},
	} {
		r := falseTail(c.rule)
		policies := kleenePolicy(r)
		for name, runner := range kleeneCRunners(t) {
			prog, err := CompileKernel(policies, 1, "worker")
			if err != nil {
				t.Fatal(err)
			}
			f := base
			f.FSType = "tmpfs"
			// Control: unmodified, the known-false tail decides (allow).
			got := runCEvaluator(t, runner, prog, evaluatorFactBytes(t, prog, policies, f))
			if d := kleeneCDecision(got); d != 0 {
				t.Errorf("%s/%s: control decision %d, want allow", c.name, name, d)
			}
			c.edit(t, prog)
			got = runCEvaluator(t, runner, prog, evaluatorFactBytes(t, prog, policies, f))
			if d := kleeneCDecision(got); d != -1 {
				t.Errorf("%s/%s: decision %d with a malformed program next to a known false, want an error", c.name, name, d)
			}
		}
	}
}

// TestKleeneArgvPrefixOnInvalidArgvIsUnknown (review F2): a prefix-only argv
// rule over an argv that is not valid is UNKNOWN (an error with nothing known
// false), never a known no-match, in Go and every C runner.
func TestKleeneArgvPrefixOnInvalidArgvIsUnknown(t *testing.T) {
	r := Rule{Name: "k", Action: Deny, Target: Target{Argv: &Argv{Prefix: []string{"--evil"}}}}
	// The incomplete argv has no matching argument: a scan of it would say
	// "known no-match", which is wrong (the rest of argv is unknown).
	f := Facts{Argv: []string{"tool", "--ok"}, ArgvComplete: false}
	policies := kleenePolicy(r)
	if d, _ := kleeneGoDecision(policies, f); d != -1 {
		t.Fatalf("Go: decision %d, want error", d)
	}
	prog, err := CompileKernel(policies, 1, "worker")
	if err != nil {
		t.Fatal(err)
	}
	for name, runner := range kleeneCRunners(t) {
		if d := kleeneCDecision(runCEvaluator(t, runner, prog, evaluatorFactBytes(t, prog, policies, f))); d != -1 {
			t.Errorf("%s: decision %d on an invalid argv, want error", name, d)
		}
	}
}

// TestKleeneCorpusCatchesMutants (review 2): the corpus run is itself
// checked: with either Kleene mutant compiled into every C runner, the
// Go-vs-C corpus must report differences in every runner variant.
func TestKleeneCorpusCatchesMutants(t *testing.T) {
	if os.Getenv("FE_KLEENE_MUTANT") != "" {
		t.Skip("child")
	}
	for _, m := range []string{"error", "true"} {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestKleeneCorpusGoVsEveryCRunner$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), "FE_KLEENE_MUTANT="+m)
		out, err := cmd.CombinedOutput()
		failed := regexp.MustCompile(`--- FAIL: TestKleeneCorpusGoVsEveryCRunner/(\S+)`).FindAllStringSubmatch(string(out), -1)
		if err == nil || len(failed) != 7 {
			t.Errorf("mutant %s: %d of 7 runner variants caught it (err %v):\n%s", m, len(failed), err, out)
			continue
		}
		t.Logf("mutant %s caught by all 7 runner variants", m)
	}
}
