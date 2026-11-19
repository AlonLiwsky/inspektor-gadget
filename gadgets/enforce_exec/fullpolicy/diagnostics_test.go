// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"errors"
	"fmt"
	"reflect"
	"regexp/syntax"
	"strings"
	"sync"
	"testing"
	"unicode"
)

func requireCompact(t *testing.T, err error, primary, cleanup DiagnosticCode) {
	t.Helper()
	var d CompactDiagnostic
	if !errors.As(err, &d) || d.Primary() != primary || d.Cleanup() != cleanup {
		t.Fatalf("compact category got %v, want %d/%d", err, primary, cleanup)
	}
}

func TestCompactDiagnosticsParity(t *testing.T) {
	fixtures := kernelFixture()
	p := base()
	fixtures = append(fixtures, p)
	for _, mode := range []Mode{Audit, Enforce} {
		p.Mode = mode
		p.Rules = []Rule{{Name: "paths", Action: Allow, Target: Target{Path: []string{"/你好/[a-z]", "/a/**", "/[acegikmo]", "/a/\\*"}}}}
		fixtures = append(fixtures, p)
	}
	for _, p := range fixtures {
		rich, re := CompileSharedPolicy(p)
		compact, ce := CompileSharedPolicyCompact(p)
		if re != nil || ce != nil {
			t.Fatalf("valid fixture: %v / %v", re, ce)
		}
		if !reflect.DeepEqual(rich, compact) || !rich.Equal(compact) {
			t.Fatal("canonical/ownership inputs differ")
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*Policy)
		code   DiagnosticCode
	}{
		{"identity", func(p *Policy) { p.ID = "" }, DiagnosticInvalidInput},
		{"mode", func(p *Policy) { p.Mode = "unknown" }, DiagnosticInvalidInput},
		{"path", func(p *Policy) { p.Rules[0].Target.Path = []string{"/["} }, DiagnosticInvalidInput},
		{"syntax", func(p *Policy) { p.Rules[0].Target.Path = []string{"/[z-a]"} }, DiagnosticInvalidInput},
		{"rules", func(p *Policy) {
			p.Rules = make([]Rule, MaxRules+1)
			for i := range p.Rules {
				p.Rules[i] = Rule{Name: fmt.Sprint(i), Action: Allow}
			}
		}, DiagnosticCapacity},
		{"paths", func(p *Policy) { p.Rules[0].Target.Path = make([]string, MaxValues+1) }, DiagnosticCapacity},
		{"ranges", func(p *Policy) { p.Rules[0].Target.Path = []string{"/[acegikmoqs]"} }, DiagnosticCapacity},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := base()
			p.Rules = []Rule{{Name: "r", Action: Allow}}
			test.mutate(&p)
			r, re := CompileSharedPolicy(p)
			c, ce := CompileSharedPolicyCompact(p)
			if re == nil || r != nil || c != nil {
				t.Fatalf("acceptance differs: %v / %v", re, ce)
			}
			requireCompact(t, ce, test.code, DiagnosticNone)
		})
	}
}

func TestCompactUnionOriginalBudgets(t *testing.T) {
	for _, tc := range []struct {
		kind                  string
		count, valid, invalid int
	}{
		{"patterns", 2, 512, 513}, {"patterns", 8, 128, 129}, {"instructions", 2, 60, 80}, {"strings", 2, 10, 11}, {"values", 2, 31, 32},
	} {
		for _, over := range []bool{false, true} {
			amount := tc.valid
			if over {
				amount = tc.invalid
			}
			policies := sharedCapacityPolicies(tc.kind, tc.count, amount)
			refs := make([]SharedPolicyRef, len(policies))
			for i, p := range policies {
				object, err := CompileSharedPolicyCompact(p)
				if err != nil {
					t.Fatal(err)
				}
				refs[i] = SharedPolicyRef{Object: object, RootEpoch: 1}
			}
			// Erasing caller source must not erase retained original-occurrence demand.
			for _, p := range policies {
				for i := range p.Rules {
					p.Rules[i] = Rule{Name: fmt.Sprint(i), Action: Allow}
				}
			}
			rich, re := NewSharedSnapshot(1, 1, "app", refs)
			compact, ce := NewSharedSnapshotCompact(1, 1, "app", refs)
			if (re != nil) != over || (ce != nil) != over {
				t.Fatalf("%s over=%v rich=%v compact=%v", tc.kind, over, re, ce)
			}
			if over {
				requireCompact(t, ce, DiagnosticCapacity, DiagnosticNone)
			} else if !reflect.DeepEqual(rich, compact) {
				t.Fatal("snapshot differs")
			}
		}
	}
}

func TestCompactDiagnosticsScalarImmutable(t *testing.T) {
	typ := reflect.TypeFor[compactDiagnosticError]()
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() != reflect.Uint8 {
			t.Fatal("diagnostic retains reference")
		}
	}
	d := compactDiagnosticsPolicy
	requireCompact(t, d.forward(errors.New("unknown authored-looking fault")), DiagnosticInternal, DiagnosticNone)
	requireCompact(t, d.forward(errWorkspaceOwner), DiagnosticOwnership, DiagnosticNone)
	requireCompact(t, d.join(compactFailure(DiagnosticInvalidInput, DiagnosticNone), errWorkspaceOwner), DiagnosticInvalidInput, DiagnosticOwnership)
	requireCompact(t, d.join(nil, errWorkspaceOwner), DiagnosticNone, DiagnosticOwnership)
	requireCompact(t, d.join(errWorkspaceLimit, errWorkspaceOwner), DiagnosticCapacity, DiagnosticOwnership)
	if got := testing.AllocsPerRun(100, func() { _ = d.join(errWorkspaceLimit, errWorkspaceOwner) }); got != 0 {
		t.Fatalf("static pair allocates %v", got)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 50 {
				p := base()
				p.Rules = []Rule{{Name: "r", Action: Allow, Target: Target{Path: []string{"/[z-a]"}}}}
				_, err := CompileSharedPolicyCompact(p)
				requireCompact(t, err, DiagnosticInvalidInput, DiagnosticNone)
			}
		})
	}
	wg.Wait()
	requireCompact(t, d.forward(errWorkspaceOwner), DiagnosticOwnership, DiagnosticNone)
}

func TestCompactValidatorCorpus(t *testing.T) {
	p, err := CompileKernel(kernelFixture(), 42, "worker")
	if err != nil {
		t.Fatal(err)
	}
	fixed := fixedIdentities{slots: make([]identitySlot, len(p.Identities))}
	for id, name := range p.Identities {
		if err := fixed.insert(id, name); err != nil {
			t.Fatal(err)
		}
	}
	for key := range p.Entries {
		for _, offset := range []int{0, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 80, 160, 287} {
			for _, mask := range []byte{1, 128, 255} {
				q := cloneKernel(p)
				q.Entries[key][offset] ^= mask
				rich := ValidateKernelProgram(q)
				for _, view := range []identityView{{legacy: q.Identities}, {fixed: &fixed}} {
					compact := validateKernelDataWithDiagnostics(q.Entries, q.Rules, view, nil, compactDiagnosticsPolicy.invariant())
					if (rich == nil) != (compact == nil) {
						t.Fatalf("acceptance at %d/%d/%d: %v / %v", key, offset, mask, rich, compact)
					}
					if compact != nil {
						requireCompact(t, compact, DiagnosticInternal, DiagnosticNone)
					}
				}
			}
		}
	}
}

func TestRuneEscapeFixedScratch(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		var scratch [10]byte
		encoded, ok := runeEscape(r, &scratch)
		if !ok || string(encoded) != fmt.Sprintf("\\x{%x}", r) {
			t.Fatalf("rune %x encoded %q", r, encoded)
		}
	}
	scratch := [10]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	before := scratch
	for _, r := range []rune{-1, unicode.MaxRune + 1} {
		if _, ok := runeEscape(r, &scratch); ok || scratch != before {
			t.Fatal("invalid endpoint wrote scratch")
		}
	}
	if got := testing.AllocsPerRun(100, func() { _, _ = runeEscape(unicode.MaxRune, &scratch) }); got != 0 {
		t.Fatalf("escape allocates: %v", got)
	}
	// Preserve width and canonical lower-case hex at the Unicode endpoint.
	expression, err := globExpression("/[" + string(unicode.MaxRune) + "]")
	if err != nil || !strings.Contains(expression, "\\x{10ffff}-\\x{10ffff}") {
		t.Fatalf("max endpoint %q %v", expression, err)
	}
}

func TestCompactValidatorScratchCategories(t *testing.T) {
	p := denseValidatorFixture(t)
	view := identityView{legacy: p.Identities}
	d := compactDiagnosticsPolicy.invariant()
	w := compilerWorkspace{limit: validatorScratchBytes(t, p) + reservationMetadata - 1}
	err := validateKernelDataWithDiagnostics(p.Entries, p.Rules, view, &w, d)
	requireCompact(t, err, DiagnosticCapacity, DiagnosticNone)
	if w.used != 0 {
		t.Fatal("refusal charged workspace")
	}
	w.limit++
	p.Rules[1].Name = p.Rules[0].Name
	err = validateKernelDataWithDiagnostics(p.Entries, p.Rules, view, &w, d)
	requireCompact(t, err, DiagnosticInternal, DiagnosticNone)
	if w.used != reservationMetadata {
		t.Fatal("validation failure leaked scratch")
	}
	w.metadata = w.used + 1
	err = validateKernelDataWithDiagnostics(p.Entries, p.Rules, view, &w, d)
	requireCompact(t, err, DiagnosticOwnership, DiagnosticNone)
}

func TestCompactPreparationBoundaryAndPrecedence(t *testing.T) {
	policies := make([]Policy, MaxPolicies)
	for i := range policies {
		policies[i] = base()
		policies[i].ID = fmt.Sprint(i)
		policies[i].Rules = make([]Rule, MaxRules/MaxPolicies)
		for j := range policies[i].Rules {
			policies[i].Rules[j] = Rule{Name: fmt.Sprint(j), Action: Allow}
		}
	}
	for _, d := range []diagnosticPolicy{richDiagnostics, compactDiagnosticsPolicy} {
		prepared, err := prepareNativePolicies(policies, d)
		if err != nil {
			t.Fatal(err)
		}
		emitted, err := compilePreparedKernelWithDiagnostics(prepared, 1, "worker", stableHash, d)
		if err != nil || len(emitted.Rules) != MaxRules {
			t.Fatal("maximum lost", err)
		}
	}
	policies = append(policies, base())
	_, err := prepareNativePolicies(policies, compactDiagnosticsPolicy)
	requireCompact(t, err, DiagnosticCapacity, DiagnosticNone)
	policies = policies[:MaxPolicies]
	policies[0].Mode = "invalid"
	policies[MaxPolicies-1].Rules = append(policies[MaxPolicies-1].Rules, Rule{Name: "over", Action: Allow})
	_, err = prepareNativePolicies(policies, compactDiagnosticsPolicy)
	requireCompact(t, err, DiagnosticInvalidInput, DiagnosticNone)
}

func TestCompactCodecUnknownLayoutIsInternal(t *testing.T) {
	_, err := decodeWithDiagnostics[uint32](Blob{}, compactDiagnosticsPolicy)
	requireCompact(t, err, DiagnosticInternal, DiagnosticNone)
	_, err = encodeWithDiagnostics(uint32(0), compactDiagnosticsPolicy)
	requireCompact(t, err, DiagnosticInternal, DiagnosticNone)
	// Generic decoding still has its result/reflection allocation; compare the
	// diagnostic path rather than claiming the whole codec is allocation-free.
	compact := testing.AllocsPerRun(100, func() { _, _ = decodeWithDiagnostics[uint32](Blob{}, compactDiagnosticsPolicy) })
	rich := testing.AllocsPerRun(100, func() { _, _ = Decode[uint32](Blob{}) })
	if compact >= rich {
		t.Fatalf("compact refusal did not remove rich diagnostic allocation: compact=%v rich=%v", compact, rich)
	}
	t.Logf("layout refusal allocations: compact=%v rich=%v", compact, rich)
	compact = testing.AllocsPerRun(100, func() { _, _ = encodeWithDiagnostics(uint32(0), compactDiagnosticsPolicy) })
	rich = testing.AllocsPerRun(100, func() { _, _ = encode(uint32(0)) })
	if compact >= rich {
		t.Fatalf("compact encode refusal did not remove rich diagnostic allocation: compact=%v rich=%v", compact, rich)
	}
	t.Logf("encode layout refusal allocations: compact=%v rich=%v", compact, rich)
}

// A raw internal failure must not be rendered or traversed during classification.
type opaqueClassParseFailure struct{}

func (opaqueClassParseFailure) Error() string { panic("class parser error rendered") }
func (opaqueClassParseFailure) Unwrap() error { panic("class parser error traversed") }

func TestCompactClassParseFailureWhitelist(t *testing.T) {
	codes := []syntax.ErrorCode{syntax.ErrInternalError, syntax.ErrInvalidCharClass, syntax.ErrInvalidCharRange, syntax.ErrInvalidEscape, syntax.ErrInvalidNamedCapture, syntax.ErrInvalidPerlOp, syntax.ErrInvalidRepeatOp, syntax.ErrInvalidRepeatSize, syntax.ErrInvalidUTF8, syntax.ErrMissingBracket, syntax.ErrMissingParen, syntax.ErrMissingRepeatArgument, syntax.ErrTrailingBackslash, syntax.ErrUnexpectedParen, syntax.ErrNestingDepth, syntax.ErrLarge, syntax.ErrorCode("future unknown parser failure")}
	for _, code := range codes {
		t.Run(string(code), func(t *testing.T) {
			raw := &syntax.Error{Code: code, Expr: "borrowed authored/parser storage"}
			want := DiagnosticInternal
			if code == syntax.ErrInvalidCharRange {
				want = DiagnosticInvalidInput
			}
			got := compactClassParseFailure(raw)
			requireCompact(t, got, want, DiagnosticNone)
			if got != compactFailure(want, DiagnosticNone) { //nolint:errorlint // Require the exact static record, not any wrapper retaining a raw cause.
				t.Fatal("classifier retained a dynamic error")
			}
			raw.Code = syntax.ErrInternalError
			raw.Expr = "mutated"
			requireCompact(t, got, want, DiagnosticNone)
		})
	}
	var typedNil *syntax.Error
	for _, raw := range []error{nil, typedNil, opaqueClassParseFailure{}, errors.New("arbitrary raw failure")} {
		requireCompact(t, compactClassParseFailure(raw), DiagnosticInternal, DiagnosticNone)
	}
}
