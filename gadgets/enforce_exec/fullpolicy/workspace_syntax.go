// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import "errors"

// This is a PRIVATE syntax-data model, not compiler admission. It models
// logical usable slice capacity, including allocator rounding exposed by cap,
// and cumulative old/new backing overlap without assuming garbage collection.
// Parser composition covers the audited generated grammar, including reuse,
// class negation, compact copies and rejected prefixes. Neither caller/source/
// builder/maps/validator/reservation metadata nor execution stacks, GC or RSS is
// covered. Nothing here changes a compiler entrypoint or accepted policy.
//
// Audited source: golang/go@2aae1000ea1d4b28923b96db28acf4e3b99d6aff,
// runtime/{slice,msize}.go and internal/runtime/gc/{sizeclasses,malloc}.go.
// This revision identifier names this model, not an automatic source attestation.
const syntaxWorkspaceRevision = "go1.27.3-linux-amd64-syntax-data-v2"

var errSyntaxWorkspaceModel = errors.New("syntax workspace model unavailable")

// Qualification is an explicit input predicate, not runtime detection or proof
// that a compiler binary matches the audited sources. Instrumented builds and
// nondefault effective experiments need separate qualification. The exact raw
// greenteagc alias enables the already-on pinned default, without changing this
// numerical model or attesting a consuming artifact; generic Compile is unrestricted.
func syntaxWorkspaceQualified(version, os, arch, experiments, revision string, instrumented bool) bool {
	return version == "go1.27.3" && os == "linux" && arch == "amd64" && (experiments == "" || experiments == "greenteagc") && revision == syntaxWorkspaceRevision && !instrumented
}

type syntaxWorkspaceSlice uint8

const (
	syntaxWorkspaceRunes syntaxWorkspaceSlice = iota
	syntaxWorkspacePointers
	syntaxWorkspaceInstructions
	syntaxWorkspaceBytes
)

func (kind syntaxWorkspaceSlice) layout() (size uint64, pointers bool) {
	switch kind {
	case syntaxWorkspaceBytes:
		return 1, false
	case syntaxWorkspaceRunes:
		return 4, false
	case syntaxWorkspacePointers:
		return 8, true
	case syntaxWorkspaceInstructions:
		return 40, true
	default:
		return 0, false
	}
}

// syntaxWorkspaceGrow implements nextslicecap followed by growslice's rounding
// and integer division. It deliberately declines oversized arithmetic rather
// than emulating runtime allocation panics. No allocation is performed.
func syntaxWorkspaceGrow(required, old uint64, kind syntaxWorkspaceSlice) (uint64, error) {
	size, pointers := kind.layout()
	const maxInt = uint64(1<<63 - 1)
	if size == 0 || required > maxInt || old > maxInt {
		return 0, errSyntaxWorkspaceModel
	}
	if required <= old {
		return old, nil
	}
	if old > maxInt/2 {
		return 0, errSyntaxWorkspaceModel
	}
	capacity := old * 2
	if required > capacity {
		capacity = required
	} else if old >= 256 {
		capacity = old
		for capacity < required {
			if capacity > maxInt-768 {
				return 0, errSyntaxWorkspaceModel
			}
			increment := (capacity + 768) >> 2
			if capacity > maxInt-increment {
				return 0, errSyntaxWorkspaceModel
			}
			capacity += increment
		}
	}
	if capacity > maxInt/size {
		return 0, errSyntaxWorkspaceModel
	}
	bytes := capacity * size
	// runtime.msize: small allocation rounding may add an 8-byte header for
	// pointer-bearing objects >512 bytes, then subtract it from usable storage.
	if bytes <= 32768-8 {
		header := uint64(0)
		if pointers && bytes > 512 {
			header = 8
		}
		requested := bytes + header
		// Exact audited size classes. Linear lookup is equivalent to the runtime's
		// two lookup tables for these requests; no general allocator API is exposed.
		classes := [...]uint64{8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792, 2048, 2304, 2688, 3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192, 9472, 9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072, 20480, 21760, 24576, 27264, 28672, 32768}
		for _, class := range classes {
			if class >= requested {
				return (class - header) / size, nil
			}
		}
		return 0, errSyntaxWorkspaceModel
	}
	if bytes > maxInt-8191 {
		return 0, errSyntaxWorkspaceModel
	}
	return ((bytes + 8191) &^ uint64(8191)) / size, nil
}

// One history per backing family, NEVER one shared capacity across different
// Regexp nodes, parser.stack or Prog.Inst. Initial inline capacity (Rune0=2,
// Sub0=1) has zero bytes here because it is already inside the Regexp node.
// bytes is cumulative, not live: dropping/replacing a slice never refunds it.
// Callers must supply the actual append-required length, including bulk appends
// and post-cleaning lengths; this helper does not infer grammar event counts.
type syntaxWorkspaceHistory struct{ capacity, bytes uint64 }

func (h syntaxWorkspaceHistory) appendTo(required uint64, kind syntaxWorkspaceSlice) (syntaxWorkspaceHistory, error) {
	capacity, err := syntaxWorkspaceGrow(required, h.capacity, kind)
	if err != nil {
		return h, err
	}
	if capacity == h.capacity {
		return h, nil
	}
	size, _ := kind.layout()
	charge := capacity * size // multiplication was checked by Grow, including rounding below maxInt.
	if charge > ^uint64(0)-h.bytes {
		return h, errSyntaxWorkspaceModel
	}
	return syntaxWorkspaceHistory{capacity: capacity, bytes: h.bytes + charge}, nil
}

// cleanAlt uses append(re.Rune0[:0], re.Rune...) for compact copies. Starting a
// fresh inline-backed history while retaining old cumulative bytes models the
// copy overlap, even when the replacement becomes inline and allocates nothing.
func (h syntaxWorkspaceHistory) copyFromInline(length, inline uint64, kind syntaxWorkspaceSlice) (syntaxWorkspaceHistory, error) {
	copyHistory, err := (syntaxWorkspaceHistory{capacity: inline, bytes: h.bytes}).appendTo(length, kind)
	if err != nil {
		return h, err
	}
	return copyHistory, nil
}

// Deliberately no Total field: these are ONLY node and Compile costs, not a
// parser envelope. Regexp pointer/rune backing histories are NOT included.
type syntaxWorkspaceCosts struct {
	regexpBytes      uint64
	instructions     uint64
	instructionBytes uint64
	progBytes        uint64
}

func syntaxWorkspaceKnownCosts(authoredBytes uint64) (syntaxWorkspaceCosts, error) {
	// Existing native authored-path premise, NOT a new compiler restriction.
	if authoredBytes == 0 || authoredBytes > 255 {
		return syntaxWorkspaceCosts{}, errSyntaxWorkspaceModel
	}
	// Generated grammar: A atoms, S stars, E ordinary escaped-literal scratch
	// requests. Stars and escaped literals belong to disjoint atoms, so S+E<=A
	// and A<=n authored bytes: requests<=A+S+E+6<=2n+6. Requests include
	// freelist reuse; actual new heap nodes can only be fewer. Instructions are
	// <=A+S+5 (includes empty-body Nop allowance). Simplify is identity.
	instructions := 2*authoredBytes + 5
	h := syntaxWorkspaceHistory{}
	for length := uint64(1); length <= instructions; length++ {
		var err error
		h, err = h.appendTo(length, syntaxWorkspaceInstructions)
		if err != nil {
			return syntaxWorkspaceCosts{}, err
		}
	}
	// Compile creates one Prog. Inst.Rune aliases parser storage, not a copy.
	return syntaxWorkspaceCosts{regexpBytes: 112 * (2*authoredBytes + 6), instructions: instructions, instructionBytes: h.bytes, progBytes: 40}, nil
}

// The following composition implements the source-derived allocation HISTORY
// bounds for the frozen glob-generated grammar (regexp/syntax/parse.go at the
// source revision above). All counts include allocation attempts, not just the
// final AST. The 255-byte premise bounds every small count expression below;
// larger byte products and sums are explicitly checked.
func syntaxWorkspaceSum(a, b uint64) (uint64, error) {
	if b > ^uint64(0)-a {
		return 0, errSyntaxWorkspaceModel
	}
	return a + b, nil
}

func syntaxWorkspaceProduct(a, b uint64) (uint64, error) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, errSyntaxWorkspaceModel
	}
	return a * b, nil
}

// B_t(D): exhaustive finite maximum of sizeof(t)*G_t(d,c), 1<=d<=D,
// 0<=c<d. Every allocating append with required length<=D is represented,
// including bulk appends after shrinking/resetting a different backing array.
// This is NOT an append-one approximation or empirical capacity multiplier.
func syntaxWorkspaceGrowthSupremum(limit uint64, kind syntaxWorkspaceSlice) (uint64, error) {
	if limit == 0 || limit > 512 {
		return 0, errSyntaxWorkspaceModel
	}
	size, _ := kind.layout()
	if size == 0 {
		return 0, errSyntaxWorkspaceModel
	}
	var largest uint64
	for required := uint64(1); required <= limit; required++ {
		for old := uint64(0); old < required; old++ {
			capacity, err := syntaxWorkspaceGrow(required, old, kind)
			if err != nil {
				return 0, err
			}
			bytes, err := syntaxWorkspaceProduct(capacity, size)
			if err != nil {
				return 0, err
			}
			largest = max(largest, bytes)
		}
	}
	return largest, nil
}

// Two independent concat histories. The inner concat appends children singly;
// the outer appends anchor, the entire inner child list in bulk, then anchor.
// Take the maximum over all possible body slot counts, including early prefixes.
func syntaxWorkspaceConcat(n uint64) (uint64, error) {
	if n > 255 {
		return 0, errSyntaxWorkspaceModel
	}
	var largest uint64
	for m := uint64(0); m <= n; m++ {
		inner := syntaxWorkspaceHistory{capacity: 1}
		if m >= 2 {
			for length := uint64(1); length <= m; length++ {
				var err error
				inner, err = inner.appendTo(length, syntaxWorkspacePointers)
				if err != nil {
					return 0, err
				}
			}
		}
		outer := syntaxWorkspaceHistory{capacity: 1}
		body := max(m, uint64(1))
		for _, length := range [...]uint64{1, body + 1, body + 2} {
			var err error
			outer, err = outer.appendTo(length, syntaxWorkspacePointers)
			if err != nil {
				return 0, err
			}
		}
		bytes, err := syntaxWorkspaceSum(inner.bytes, outer.bytes)
		if err != nil {
			return 0, err
		}
		largest = max(largest, bytes)
	}
	return largest, nil
}

// FullParse(n): parser-owned logical DATA only, not expression construction,
// errors' formatted text, runtime stacks or complete compilation. Does not call
// Parse. Node requests <=2n+6 keep private parser maps unreachable. Simplify is
// identity. A later native rejection does not reduce any term.
func syntaxWorkspaceFullParse(n uint64) (uint64, error) {
	if n == 0 || n > 255 {
		return 0, errSyntaxWorkspaceModel
	}
	stack := syntaxWorkspaceHistory{}
	// One append-one stack history: reductions shrink length, never capacity;
	// at most n body slots plus three anchor/group slots are simultaneously used.
	for length := uint64(1); length <= n+3; length++ {
		var err error
		stack, err = stack.appendTo(length, syntaxWorkspacePointers)
		if err != nil {
			return 0, err
		}
	}
	literalGrowth, err := syntaxWorkspaceGrowthSupremum(n, syntaxWorkspaceRunes)
	if err != nil {
		return 0, err
	}
	classGrowth, err := syntaxWorkspaceGrowthSupremum(2*n+2, syntaxWorkspaceRunes)
	if err != nil {
		return 0, err
	}
	concat, err := syntaxWorkspaceConcat(n)
	if err != nil {
		return 0, err
	}
	// <=n+8 push calls + two direct concat maybeConcat calls; each contains
	// at most one Rune append with required length<=n, even after class-to-literal
	// conversion or Rune0 reset. Count all attempts; never refund old storage.
	literals, err := syntaxWorkspaceProduct(n+10, literalGrowth)
	if err != nil {
		return 0, err
	}
	// <=2n class range attempts +n negation attempts +two cleanAlt copies;
	// every required class length<=2(n+1), across all independent classes.
	classes, err := syntaxWorkspaceProduct(3*n+2, classGrowth)
	if err != nil {
		return 0, err
	}
	total := uint64(0)
	// Node inline storage is included in112; Error32 is the one returned object,
	// whose Expr aliases input. Sub backing is counted only in concat above.
	for _, term := range [...]uint64{112 * (2*n + 6), stack.bytes, literals, classes, concat, 32} {
		total, err = syntaxWorkspaceSum(total, term)
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

// AllClassCalls(n): before conversion, K<=n separate class calls and disjoint
// character counts sum(q_j)<=n. Per call node112+stack8+Error32; total Rune
// append/copy attempts sum(q_j+2)<=3n. Class strings/builders/range adapters are
// caller allocations and excluded. FullParse already includes its own nodes:
// do not add syntaxWorkspaceKnownCosts.regexpBytes to these parser costs again.
func syntaxWorkspaceAllClassCalls(n uint64) (uint64, error) {
	if n == 0 || n > 255 {
		return 0, errSyntaxWorkspaceModel
	}
	growth, err := syntaxWorkspaceGrowthSupremum(2*n+2, syntaxWorkspaceRunes)
	if err != nil {
		return 0, err
	}
	bytes, err := syntaxWorkspaceProduct(3*n, growth)
	if err != nil {
		return 0, err
	}
	return syntaxWorkspaceSum(152*n, bytes)
}
