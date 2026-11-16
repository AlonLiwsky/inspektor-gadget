// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp/syntax"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

func TestSyntaxWorkspaceQualification(t *testing.T) {
	for _, raw := range []string{"", "greenteagc"} {
		if !syntaxWorkspaceQualified("go1.27.3", "linux", "amd64", raw, syntaxWorkspaceRevision, false) {
			t.Fatalf("audited raw profile %q rejected", raw)
		}
		if syntaxWorkspaceQualified("go1.27.3", "linux", "amd64", raw, syntaxWorkspaceRevision, true) {
			t.Fatalf("instrumented raw profile %q accepted", raw)
		}
	}
	for _, raw := range []string{"none", "nogreenteagc", "greenteagc,none", "greenteagc,greenteagc", "greenteagc,arenas", " greenteagc", "greenteagc ", "GREENTEAGC"} {
		if syntaxWorkspaceQualified("go1.27.3", "linux", "amd64", raw, syntaxWorkspaceRevision, false) {
			t.Fatalf("unsupported raw profile %q accepted", raw)
		}
	}
	for _, q := range [][6]string{
		{"go1.27.4", "linux", "amd64", "", syntaxWorkspaceRevision, ""},
		{"go1.27.4", "linux", "amd64", "greenteagc", syntaxWorkspaceRevision, ""},
		{"go1.27.3", "darwin", "amd64", "greenteagc", syntaxWorkspaceRevision, ""},
		{"go1.27.3", "linux", "arm64", "greenteagc", syntaxWorkspaceRevision, ""},
		{"go1.27.3", "darwin", "amd64", "", syntaxWorkspaceRevision, ""},
		{"go1.27.3", "linux", "arm64", "", syntaxWorkspaceRevision, ""},
		{"go1.27.3", "linux", "amd64", "arenas", syntaxWorkspaceRevision, ""},
		{"go1.27.3", "linux", "amd64", "", "unknown", ""},
		{"go1.27.3", "linux", "amd64", "", syntaxWorkspaceRevision, "race"},
	} {
		if syntaxWorkspaceQualified(q[0], q[1], q[2], q[3], q[4], q[5] != "") {
			t.Fatalf("qualified unsupported model: %v", q)
		}
	}
}

func checkSyntaxCapacities[T any](t *testing.T, kind syntaxWorkspaceSlice) {
	t.Helper()
	var zero T
	size := uint64(unsafe.Sizeof(zero))
	// Exhaustively exercise old capacities and both single/bulk append, rather
	// than only the doubling sequence. Include header and large-object boundaries.
	for old := 0; old <= 1100; old++ {
		for _, more := range []int{1, 2, 7, 256, 1030} {
			s := make([]T, old)
			s = append(s, make([]T, more)...)
			got, err := syntaxWorkspaceGrow(uint64(old+more), uint64(old), kind)
			if err != nil || got != uint64(cap(s)) {
				t.Fatalf("kind %v old %d more %d: got %d (%v), actual %d size %d", kind, old, more, got, err, cap(s), size)
			}
		}
	}
}

func TestSyntaxWorkspaceRuntimeCapacities(t *testing.T) {
	if runtime.Version() != "go1.27.3" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("corroboration requires audited runtime; qualification is tested separately")
	}
	if unsafe.Sizeof(syntax.Regexp{}) != 112 || unsafe.Sizeof(syntax.Prog{}) != 40 || unsafe.Sizeof(syntax.Inst{}) != 40 || unsafe.Sizeof(syntax.Error{}) != 32 {
		t.Fatal("audited structure sizes changed")
	}
	checkSyntaxCapacities[rune](t, syntaxWorkspaceRunes)
	checkSyntaxCapacities[*syntax.Regexp](t, syntaxWorkspacePointers)
	checkSyntaxCapacities[syntax.Inst](t, syntaxWorkspaceInstructions)
}

func TestSyntaxWorkspaceHistories(t *testing.T) {
	// Rune0 is inline: not a separate allocation. A negation appends two
	// endpoints after in-place cleaning; compaction starts from Rune0 again.
	h := syntaxWorkspaceHistory{capacity: 2}
	for length := uint64(2); length <= 110; length += 2 {
		before := h
		var err error
		h, err = h.appendTo(length, syntaxWorkspaceRunes)
		if err != nil || h.bytes < before.bytes {
			t.Fatalf("append: %v %+v", err, h)
		}
	}
	before := h
	// cleanClass can shrink to four endpoints; negateClass adds two in place.
	h, err := h.appendTo(6, syntaxWorkspaceRunes)
	if err != nil || h != before {
		t.Fatal("in-place negation should not allocate")
	}
	h, err = h.copyFromInline(6, 2, syntaxWorkspaceRunes)
	if err != nil || h.bytes <= before.bytes || h.capacity >= before.capacity {
		t.Fatalf("compact-copy overlap lost: %+v -> %+v (%v)", before, h, err)
	}
	// Dropping a rejected parse prefix must not subtract previous allocations.
	prefix := h
	h, err = h.copyFromInline(1, 2, syntaxWorkspaceRunes)
	if err != nil || h.bytes != prefix.bytes || h.capacity != 2 {
		t.Fatal("inline copy refunded earlier backing")
	}
	// Sub0 and stack are separate pointer backing histories.
	sub := syntaxWorkspaceHistory{capacity: 1}
	stack := syntaxWorkspaceHistory{}
	sub, err = sub.appendTo(1, syntaxWorkspacePointers)
	if err != nil || sub.bytes != 0 {
		t.Fatal("Sub0 double charged")
	}
	stack, err = stack.appendTo(1, syntaxWorkspacePointers)
	if err != nil || stack.bytes != 8 {
		t.Fatal("stack backing not charged independently")
	}
}

func TestSyntaxWorkspaceKnownCosts(t *testing.T) {
	var previous syntaxWorkspaceCosts
	for n := uint64(1); n <= 255; n++ {
		cost, err := syntaxWorkspaceKnownCosts(n)
		if err != nil || cost.regexpBytes != 112*(2*n+6) || cost.instructions != 2*n+5 || cost.instructionBytes < 40*cost.instructions || cost.progBytes != 40 {
			t.Fatalf("n=%d: %+v %v", n, cost, err)
		}
		if cost.instructionBytes < previous.instructionBytes {
			t.Fatal("prefix cost decreased")
		}
		previous = cost
	}
	for _, n := range []uint64{0, 256, math.MaxUint64} {
		if _, err := syntaxWorkspaceKnownCosts(n); err == nil {
			t.Fatalf("accepted unsupported authored length %d", n)
		}
	}
}

func TestSyntaxWorkspaceOverflow(t *testing.T) {
	for _, tc := range [][3]uint64{{math.MaxUint64, 0, 0}, {1, math.MaxUint64, 0}, {1 << 62, 0, 2}, {1, 0, 99}} {
		if _, err := syntaxWorkspaceGrow(tc[0], tc[1], syntaxWorkspaceSlice(tc[2])); err == nil {
			t.Fatalf("accepted invalid growth %v", tc)
		}
	}
	h := syntaxWorkspaceHistory{bytes: math.MaxUint64}
	if got, err := h.appendTo(1, syntaxWorkspaceRunes); err == nil || got != h {
		t.Fatal("overflow must leave history unchanged")
	}
	if got, err := h.copyFromInline(3, 2, syntaxWorkspaceRunes); err == nil || got != h {
		t.Fatal("copy overflow must leave history unchanged")
	}
}

func TestSyntaxWorkspaceNonallocating(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() {
		if _, err := syntaxWorkspaceKnownCosts(255); err != nil {
			panic(err)
		}
	}); n != 0 {
		t.Fatalf("numeric helper allocated: %g", n)
	}
}

func TestSyntaxWorkspaceHeaderRounding(t *testing.T) {
	for _, tc := range []struct {
		kind                syntaxWorkspaceSlice
		old, required, want uint64
	}{
		{syntaxWorkspacePointers, 32, 33, 64},     // exactly 512 bytes: no header
		{syntaxWorkspacePointers, 64, 65, 143},    // 1024+header rounds to 1152, less header
		{syntaxWorkspaceRunes, 128, 129, 256},     // noscan: no header
		{syntaxWorkspaceInstructions, 12, 13, 25}, // truncates partial element after header
		{syntaxWorkspaceRunes, 0, 8191, 8192},     // large-object page alignment
	} {
		got, err := syntaxWorkspaceGrow(tc.required, tc.old, tc.kind)
		if err != nil || got != tc.want {
			t.Fatalf("%+v: %d %v", tc, got, err)
		}
	}
}

func TestSyntaxWorkspaceInstructionOverlap(t *testing.T) {
	if runtime.Version() != "go1.27.3" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("audited runtime only")
	}
	var instructions []syntax.Inst
	var cumulative uint64
	h := syntaxWorkspaceHistory{}
	for length := uint64(1); length <= 515; length++ {
		old := cap(instructions)
		instructions = append(instructions, syntax.Inst{})
		if cap(instructions) != old {
			cumulative += 40 * uint64(cap(instructions))
		}
		var err error
		h, err = h.appendTo(length, syntaxWorkspaceInstructions)
		if err != nil || h.bytes != cumulative || h.capacity != uint64(cap(instructions)) {
			t.Fatalf("prefix %d: %+v actual %d (%v)", length, h, cumulative, err)
		}
	}
	if h.bytes <= 40*h.capacity {
		t.Fatal("only final backing counted; replacement overlap missing")
	}
}

func TestSyntaxWorkspaceGrowthSupremum(t *testing.T) {
	for _, kind := range []syntaxWorkspaceSlice{syntaxWorkspaceRunes, syntaxWorkspacePointers} {
		var want uint64
		size, _ := kind.layout()
		for d := uint64(1); d <= 512; d++ {
			// Include every possible allocating old capacity, not one append schedule.
			for c := uint64(0); c < d; c++ {
				capacity, err := syntaxWorkspaceGrow(d, c, kind)
				if err != nil {
					t.Fatal(err)
				}
				want = max(want, capacity*size)
			}
			if d <= 8 || d == 255 || d == 256 || d == 511 || d == 512 {
				got, err := syntaxWorkspaceGrowthSupremum(d, kind)
				if err != nil || got != want {
					t.Fatalf("D=%d kind=%d got=%d want=%d err=%v", d, kind, got, want, err)
				}
			}
		}
	}
	for _, d := range []uint64{0, 513, math.MaxUint64} {
		if _, err := syntaxWorkspaceGrowthSupremum(d, syntaxWorkspaceRunes); err == nil {
			t.Fatalf("accepted unsupported D=%d", d)
		}
	}
	if _, err := syntaxWorkspaceGrowthSupremum(1, 99); err == nil {
		t.Fatal("unknown slice kind accepted")
	}
}

func TestSyntaxWorkspaceParserComposition(t *testing.T) {
	var previousFull, previousClasses uint64
	for n := uint64(1); n <= 255; n++ {
		full, err := syntaxWorkspaceFullParse(n)
		if err != nil {
			t.Fatal(err)
		}
		classes, err := syntaxWorkspaceAllClassCalls(n)
		if err != nil {
			t.Fatal(err)
		}
		bRune, err := syntaxWorkspaceGrowthSupremum(n, syntaxWorkspaceRunes)
		if err != nil {
			t.Fatal(err)
		}
		bClass, err := syntaxWorkspaceGrowthSupremum(2*n+2, syntaxWorkspaceRunes)
		if err != nil {
			t.Fatal(err)
		}
		stack := syntaxWorkspaceHistory{}
		for d := uint64(1); d <= n+3; d++ {
			stack, err = stack.appendTo(d, syntaxWorkspacePointers)
			if err != nil {
				t.Fatal(err)
			}
		}
		concat, err := syntaxWorkspaceConcat(n)
		if err != nil {
			t.Fatal(err)
		}
		want := 112*(2*n+6) + stack.bytes + (n+10)*bRune + (3*n+2)*bClass + concat + 32
		if full != want || classes != 152*n+3*n*bClass {
			t.Fatalf("n=%d full=%d want=%d classes=%d", n, full, want, classes)
		}
		if full < previousFull || classes < previousClasses {
			t.Fatal("rejecting prefix envelope decreased")
		}
		previousFull, previousClasses = full, classes
	}
	for _, n := range []uint64{0, 256, math.MaxUint64} {
		if _, err := syntaxWorkspaceFullParse(n); err == nil {
			t.Fatal("unsupported full-parse input accepted")
		}
		if _, err := syntaxWorkspaceAllClassCalls(n); err == nil {
			t.Fatal("unsupported class-call input accepted")
		}
	}
}

func TestSyntaxWorkspaceConcatHistories(t *testing.T) {
	if runtime.Version() != "go1.27.3" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("audited runtime only")
	}
	var want uint64
	for n := uint64(0); n <= 255; n++ {
		var innerInline, outerInline [1]*syntax.Regexp
		inner, outer := innerInline[:0], outerInline[:0]
		var bytes uint64
		appendPointers := func(s []*syntax.Regexp, values ...*syntax.Regexp) []*syntax.Regexp {
			old := cap(s)
			s = append(s, values...)
			if cap(s) != old {
				bytes += 8 * uint64(cap(s))
			}
			return s
		}
		if n >= 2 {
			for i := uint64(0); i < n; i++ {
				inner = appendPointers(inner, nil)
			}
		}
		outer = appendPointers(outer, nil)
		if n >= 2 {
			outer = appendPointers(outer, inner...)
		} else {
			outer = appendPointers(outer, nil)
		}
		_ = appendPointers(outer, nil)
		want = max(want, bytes)
		got, err := syntaxWorkspaceConcat(n)
		if err != nil || got != want {
			t.Fatalf("n=%d got=%d want=%d err=%v", n, got, want, err)
		}
	}
}

func TestSyntaxWorkspaceCheckedComposition(t *testing.T) {
	if _, err := syntaxWorkspaceSum(math.MaxUint64, 1); err == nil {
		t.Fatal("sum overflow accepted")
	}
	if _, err := syntaxWorkspaceProduct(math.MaxUint64, 2); err == nil {
		t.Fatal("product overflow accepted")
	}
	if got, err := syntaxWorkspaceProduct(math.MaxUint64, 0); err != nil || got != 0 {
		t.Fatal("zero product rejected")
	}
	if n := testing.AllocsPerRun(2, func() {
		if _, err := syntaxWorkspaceFullParse(255); err != nil {
			panic(err)
		}
		if _, err := syntaxWorkspaceAllClassCalls(255); err != nil {
			panic(err)
		}
	}); n != 0 {
		t.Fatalf("preflight allocated %g", n)
	}
}

func TestSyntaxWorkspaceResetAndRejectPrefixes(t *testing.T) {
	const limit = 512
	bound, err := syntaxWorkspaceGrowthSupremum(limit, syntaxWorkspaceRunes)
	if err != nil {
		t.Fatal(err)
	}
	var charged, attempts uint64
	for i := uint64(1); i <= 255; i++ {
		// Independent class/node histories: allocation, in-place cleaning shrink,
		// negation, compact copy, reset to inline, then another bulk merge. A rejected
		// prefix can stop at ANY step; cumulative allocation is never refunded.
		h := syntaxWorkspaceHistory{capacity: 2}
		for step, d := range [...]uint64{2, 2 * i, 4, 6, 2*i + 2, 1, limit} {
			before := h.bytes
			if step == 3 || step == 5 {
				h, err = h.copyFromInline(d, 2, syntaxWorkspaceRunes)
			} else {
				h, err = h.appendTo(d, syntaxWorkspaceRunes)
			}
			if err != nil {
				t.Fatal(err)
			}
			attempts++
			delta := h.bytes - before
			charged += delta
			if delta > bound || charged > attempts*bound {
				t.Fatalf("history %d step %d exceeds source-attempt bound", i, step)
			}
		}
	}
}

func TestSyntaxWorkspaceGeneratedGrammar(t *testing.T) {
	cases := []string{
		"/", "/" + strings.Repeat("a*", 127), "/" + strings.Repeat("?", 254),
		"/" + strings.Repeat("[a]", 84), "/[" + strings.Repeat("zay", 83) + "]",
		"/[^" + strings.Repeat("az", 124) + "]", "/[Aa]*", "/[α-ω]?**",
		"/" + strings.Repeat("界", 84) + "ab",
	}
	for _, pattern := range cases {
		n := uint64(len(pattern))
		if n > 255 {
			t.Fatalf("bad test authored length %d", n)
		}
		full, err := syntaxWorkspaceFullParse(n)
		if err != nil {
			t.Fatal(err)
		}
		classes, err := syntaxWorkspaceAllClassCalls(n)
		if err != nil || classes == 0 || full == 0 {
			t.Fatal("missing parser preflight")
		}
		expression, err := globExpression(pattern)
		if err != nil {
			t.Fatalf("glob %q: %v", pattern, err)
		}
		re, err := syntax.Parse(expression, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		if re.Simplify() != re {
			t.Fatalf("Simplify not identity for %q", pattern)
		}
		prog, err := syntax.Compile(re)
		if err != nil {
			t.Fatal(err)
		}
		if uint64(len(prog.Inst)) > 2*n+5 {
			t.Fatalf("instruction structural bound: %q", pattern)
		}
	}
	// Failed conversion prefixes are still preflighted; model evaluation does
	// not consume the pattern or change the existing malformed-glob behavior.
	for _, pattern := range []string{"/[", "/[z-a]", "/\\"} {
		if _, err := syntaxWorkspaceAllClassCalls(uint64(len(pattern))); err != nil {
			t.Fatal(err)
		}
		if _, err := syntaxWorkspaceFullParse(uint64(len(pattern))); err != nil {
			t.Fatal(err)
		}
		if _, err := globExpression(pattern); err == nil {
			t.Fatalf("malformed glob accepted: %q", pattern)
		}
	}
	// These are class-only stdlib cases (not authored NUL-containing paths).
	// Empty complement, full universe and folded pair remain leaf identities.
	for _, expression := range []string{`[^\x{0}-\x{10ffff}]`, `[\x{0}-\x{10ffff}]`, `[Aa]`} {
		re, err := syntax.Parse(expression, syntax.Perl)
		if err != nil || re.Simplify() != re {
			t.Fatalf("awkward class %q: %v", expression, err)
		}
	}
}

func TestSyntaxWorkspaceParserSourceIdentity(t *testing.T) {
	if runtime.Version() != "go1.27.3" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("audited source identity only")
	}
	toolchain, err := exec.Command("go", "env", "GOROOT", "GOVERSION").Output()
	if err != nil {
		t.Skipf("local Go source identity unavailable: %v", err)
	}
	fields := strings.Split(strings.TrimSpace(string(toolchain)), "\n")
	if len(fields) != 2 || fields[1] != runtime.Version() {
		t.Skip("local Go source version differs from test binary")
	}
	// Source identity is a regression alarm, not runtime qualification of an
	// arbitrary binary with this version string. Tests never gate public APIs.
	files := map[string]string{
		"regexp/syntax/parse.go":    "f93b85f4b63a6f6ecb5c1452a6c0ded1fef5953f9c73e5d814dfc08207e7d1b6",
		"regexp/syntax/simplify.go": "d22b48ecde668bc22cd8998492c752ec088da5d027d61b7f04f7a9298796eec0",
		"sort/sort.go":              "100e49103d23dd6b8335a50b17ae6e9db2b056cb1217d964dcf58852c3c6f8a1",
		"sort/zsortinterface.go":    "8978a49cc4174b0c35a84a2ddf73175d41254eb340ebeda29f21d3e546088a3b",
	}
	for name, want := range files {
		contents, err := os.ReadFile(filepath.Join(fields[0], "src", filepath.FromSlash(name)))
		if os.IsNotExist(err) {
			t.Skip("toolchain sources unavailable for identity corroboration")
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != want {
			t.Fatalf("audited source %s changed: %s", name, got)
		}
	}
}
