// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// zeroFailClosedVerdict is the steady-state/burst gate input, all taken from
// the same per-run witness delta the RATE line prints.
type zeroFailClosedVerdict struct {
	Rates          FailClosedRateVerdict
	RetryExhausted uint64
	Unevaluated    uint64
	// Entry is the ENTRY delta (product-publisher objects only): an exec by
	// a task with no TASK. Every child of these runs is born managed, so it
	// must be 0.
	Entry uint64
	// Admission is the ADMISSION delta (product-publisher objects only): an
	// exec admission fault on a published, settled route; must be 0.
	Admission uint64
}

// failClosedWitnessCells requires both snapshots to have one witness size:
// FailClosedRateCounters with the product publisher, or
// FailClosedRateLegacyCounters without (no ENTRY cell).
func failClosedWitnessCells(before, after []uint64) error {
	n, err := FailClosedRateCells(uint32(len(after)))
	if err != nil || len(before) != n {
		return fmt.Errorf("fail-closed rate witness has %d/%d cells, want %d or %d: a missing witness is unknown, never zero",
			len(before), len(after), FailClosedRateCounters, FailClosedRateLegacyCounters)
	}
	return nil
}

// failClosedAdmissionDelta is the ADMISSION delta (product-publisher
// witness), or MaxUint64 when it moved backwards; 0 without the cell.
func failClosedAdmissionDelta(before, after []uint64) uint64 {
	if len(after) <= FailClosedRateAdmission {
		return 0
	}
	if after[FailClosedRateAdmission] < before[FailClosedRateAdmission] {
		return ^uint64(0)
	}
	return after[FailClosedRateAdmission] - before[FailClosedRateAdmission]
}

// failClosedEntryDelta is the ENTRY delta, or MaxUint64 when it moved
// backwards (always a gate failure); 0 without the ENTRY cell.
func failClosedEntryDelta(before, after []uint64) uint64 {
	if len(after) <= FailClosedRateEntry {
		return 0
	}
	if after[FailClosedRateEntry] < before[FailClosedRateEntry] {
		return ^uint64(0)
	}
	return after[FailClosedRateEntry] - before[FailClosedRateEntry]
}

// zeroFailClosedGate is the REQUIRE_ZERO_FAIL_CLOSED (and burst) gate. before
// and after are the opaque_real_fail_closed_rates witness snapshots
// (FailClosedRateCounters cells) bracketing the run; a missing witness is
// unknown, never zero. The gate passes only when every fail-closed class
// delta is 0 (Total, excluding the separate retry subset, which must be 0
// too), every born child was evaluated (evaluated == births), no fork was
// refused and the test's own fail-closed count is 0.
func zeroFailClosedGate(before, after []uint64, attempts, births, evaluated, forkRefusals, testFailClosed uint64) (zeroFailClosedVerdict, error) {
	var g zeroFailClosedVerdict
	if err := failClosedWitnessCells(before, after); err != nil {
		return g, err
	}
	var b, a [FailClosedRateClasses]uint64
	copy(b[:], before)
	copy(a[:], after)
	rates, err := FailClosedRate(b, a, attempts, 0)
	g.Rates = rates
	if err != nil {
		return g, fmt.Errorf("fail-closed rate witness: %w", err)
	}
	if after[FailClosedRateWorkRetry] < before[FailClosedRateWorkRetry] {
		return g, fmt.Errorf("retry witness went backwards %d -> %d", before[FailClosedRateWorkRetry], after[FailClosedRateWorkRetry])
	}
	g.RetryExhausted = after[FailClosedRateWorkRetry] - before[FailClosedRateWorkRetry]
	g.Entry = failClosedEntryDelta(before, after)
	g.Admission = failClosedAdmissionDelta(before, after)
	g.Unevaluated = births - min(evaluated, births)
	var errs []string
	if rates.Total != 0 || rates.Degraded {
		errs = append(errs, fmt.Sprintf("witness fail_closed=%d %v degraded=%v", rates.Total, rates.Failures, rates.Degraded))
	}
	if g.RetryExhausted != 0 {
		errs = append(errs, fmt.Sprintf("retry_exhausted=%d", g.RetryExhausted))
	}
	if g.Entry != 0 {
		errs = append(errs, fmt.Sprintf("entry=%d", g.Entry))
	}
	if g.Admission != 0 {
		errs = append(errs, fmt.Sprintf("admission=%d", g.Admission))
	}
	if evaluated != births {
		errs = append(errs, fmt.Sprintf("evaluated=%d of %d births (unevaluated=%d)", evaluated, births, g.Unevaluated))
	}
	if forkRefusals != 0 {
		errs = append(errs, fmt.Sprintf("fork refusals=%d", forkRefusals))
	}
	if testFailClosed != 0 {
		errs = append(errs, fmt.Sprintf("test fail_closed=%d", testFailClosed))
	}
	if len(errs) != 0 {
		return g, fmt.Errorf("%s; want all 0 and evaluated == births", strings.Join(errs, ", "))
	}
	return g, nil
}

func TestZeroFailClosedGate(t *testing.T) {
	zero := make([]uint64, FailClosedRateCounters)
	cells := func(vals map[int]uint64) []uint64 {
		out := make([]uint64, FailClosedRateCounters)
		for i, n := range vals {
			out[i] = n
		}
		return out
	}
	// Nonzero baselines: the gate must use the per-run delta, not the
	// absolute after-snapshot nor a reset.
	base := cells(map[int]uint64{1: 50, 3: 7, FailClosedRateWorkRetry: 4})
	for _, tc := range []struct {
		name                                             string
		before, after                                    []uint64
		attempts, births, evaluated, refusals, testTotal uint64
		wantErr                                          string
	}{
		{name: "clean", before: zero, after: zero, attempts: 10000, births: 10000, evaluated: 10000},
		{name: "clean over nonzero baseline", before: base, after: base, attempts: 1000, births: 1000, evaluated: 1000},
		// G019 burst evidence (g19m1-6.18-burst-s3-c1-r2): RATE
		// witness=0/973/0/9/..., 18 of 1000 births evaluated.
		{
			name: "burst 973 source refusals", before: base,
			after:    cells(map[int]uint64{1: 50 + 973, 3: 7 + 9, FailClosedRateWorkRetry: 4}),
			attempts: 1000, births: 1000, evaluated: 18, testTotal: 982,
			wantErr: "witness fail_closed=982",
		},
		{
			name: "single LIMIT refusal", before: zero, after: cells(map[int]uint64{0: 1}),
			attempts: 1000, births: 1000, evaluated: 1000, wantErr: "witness fail_closed=1",
		},
		{
			name: "gap class counts", before: zero, after: cells(map[int]uint64{FailClosedRateGap: 1}),
			attempts: 1000, births: 1000, evaluated: 1000, wantErr: "witness fail_closed=1",
		},
		{
			name: "retry subset alone", before: base, after: cells(map[int]uint64{1: 50, 3: 7, FailClosedRateWorkRetry: 5}),
			attempts: 1000, births: 1000, evaluated: 1000, wantErr: "retry_exhausted=1",
		},
		{
			name: "unevaluated child", before: zero, after: zero,
			attempts: 1000, births: 1000, evaluated: 999, wantErr: "evaluated=999 of 1000",
		},
		{
			name: "evaluated exceeds births", before: zero, after: zero,
			attempts: 1000, births: 1000, evaluated: 1001, wantErr: "evaluated=1001 of 1000",
		},
		{
			name: "fork refused", before: zero, after: zero,
			attempts: 1000, births: 999, evaluated: 999, refusals: 1, wantErr: "fork refusals=1",
		},
		{
			name: "test-only fail-closed", before: zero, after: zero,
			attempts: 1000, births: 1000, evaluated: 1000, testTotal: 1, wantErr: "test fail_closed=1",
		},
		{
			name: "missing witness", before: nil, after: nil,
			attempts: 1000, births: 1000, evaluated: 1000, wantErr: "missing witness",
		},
		{
			name: "witness reset mid-run", before: base, after: zero,
			attempts: 1000, births: 1000, evaluated: 1000, wantErr: "fail-closed rate witness",
		},
		{
			name: "entry outside Total still fails", before: zero, after: cells(map[int]uint64{FailClosedRateEntry: 1}),
			attempts: 1000, births: 1000, evaluated: 1000, wantErr: "entry=1",
		},
		{
			name: "admission fault outside Total still fails", before: zero, after: cells(map[int]uint64{FailClosedRateAdmission: 1}),
			attempts: 1000, births: 1000, evaluated: 1000, wantErr: "admission=1",
		},
		{
			name: "legacy witness without ENTRY", before: make([]uint64, FailClosedRateLegacyCounters), after: make([]uint64, FailClosedRateLegacyCounters),
			attempts: 1000, births: 1000, evaluated: 1000,
		},
		{
			name: "mixed witness sizes", before: make([]uint64, FailClosedRateLegacyCounters), after: zero,
			attempts: 1000, births: 1000, evaluated: 1000, wantErr: "missing witness",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := zeroFailClosedGate(tc.before, tc.after, tc.attempts, tc.births, tc.evaluated, tc.refusals, tc.testTotal)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("gate failed: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("gate passed, want failure containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("gate error %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// burstOverCapacityGate is the G019 burst gate above the burst capacity
// (streams > ConcurrentBirthCapacity(WORK quota); user decision "gate at
// capacity"). Refusals are expected there; the run is measured, and it passes
// only when none is hidden. The witness must be present and readable (a
// missing witness is unknown, never zero) and Degraded exactly when a refusal
// was counted. The refusal accounting is checked against quantities that are
// independent of the product witness's BPF increment sites:
//   - births (user space: the helper's per-child fork reports) minus
//     evaluated (the evaluator's own rule_eval_count, not a refusal site)
//     must EQUAL the witness Total, in Strict and Audit: an unevaluated birth
//     with no counted class (Unevaluated > Total) or a count with no
//     unevaluated birth (double count, Total > Unevaluated) both fail;
//   - in Strict, testFailClosed (user space: refused forks, failed threads,
//     children exiting 77) must also EQUAL the Total. In Audit nothing is
//     visible to user space (every child exits 0), so testFailClosed is built
//     from BPF witnesses and is not used here.
//
// exact (every class equal to its test-only witness) is required too, but it
// is a self-consistency check of the counting code only: those witnesses are
// incremented at the same BPF sites as the product classes. The caller still
// fails the run on a reaper fault, a missing drain to the baseline accounts,
// or a child left after quiescence.
func burstOverCapacityGate(before, after []uint64, attempts, births, evaluated, testFailClosed uint64, strict, exact bool) (zeroFailClosedVerdict, error) {
	var g zeroFailClosedVerdict
	if err := failClosedWitnessCells(before, after); err != nil {
		return g, err
	}
	var b, a [FailClosedRateClasses]uint64
	copy(b[:], before)
	copy(a[:], after)
	rates, err := FailClosedRate(b, a, attempts, FailClosedRateDegradedThreshold)
	g.Rates = rates
	if err != nil {
		return g, fmt.Errorf("fail-closed rate witness: %w", err)
	}
	if after[FailClosedRateWorkRetry] < before[FailClosedRateWorkRetry] {
		return g, fmt.Errorf("retry witness went backwards %d -> %d", before[FailClosedRateWorkRetry], after[FailClosedRateWorkRetry])
	}
	g.RetryExhausted = after[FailClosedRateWorkRetry] - before[FailClosedRateWorkRetry]
	g.Entry = failClosedEntryDelta(before, after)
	g.Admission = failClosedAdmissionDelta(before, after)
	g.Unevaluated = births - min(evaluated, births)
	var errs []string
	if evaluated > births {
		errs = append(errs, fmt.Sprintf("evaluated=%d of %d births", evaluated, births))
	}
	if g.Entry != 0 {
		errs = append(errs, fmt.Sprintf("entry=%d (every burst child is born managed)", g.Entry))
	}
	if g.Admission != 0 {
		errs = append(errs, fmt.Sprintf("admission=%d (no exec admission fault on a published route)", g.Admission))
	}
	if !exact {
		errs = append(errs, fmt.Sprintf("witness classes %v not exactly matched by the test-only witnesses", rates.Failures))
	}
	if g.Unevaluated != rates.Total {
		errs = append(errs, fmt.Sprintf("unevaluated=%d != witness fail_closed=%d (every unevaluated birth must be exactly one counted class)", g.Unevaluated, rates.Total))
	}
	if strict && testFailClosed != rates.Total {
		errs = append(errs, fmt.Sprintf("user-space fail_closed=%d != witness fail_closed=%d (Strict refusals seen by the helper)", testFailClosed, rates.Total))
	}
	if rates.Degraded != (rates.Total != 0) {
		errs = append(errs, fmt.Sprintf("witness fail_closed=%d degraded=%v", rates.Total, rates.Degraded))
	}
	if len(errs) != 0 {
		return g, fmt.Errorf("%s; want every refusal counted in its class and Degraded on any", strings.Join(errs, ", "))
	}
	return g, nil
}

func TestBurstOverCapacityGate(t *testing.T) {
	zero := make([]uint64, FailClosedRateCounters)
	cells := func(vals map[int]uint64) []uint64 {
		out := make([]uint64, FailClosedRateCounters)
		for i, n := range vals {
			out[i] = n
		}
		return out
	}
	base := cells(map[int]uint64{1: 50, 3: 7, FailClosedRateWorkRetry: 4})
	for _, tc := range []struct {
		name                                   string
		before, after                          []uint64
		attempts, births, evaluated, testTotal uint64
		strict, exact                          bool
		wantErr                                string
		wantDegraded                           bool
	}{
		{name: "no refusal over capacity", before: zero, after: zero, attempts: 1000, births: 1000, evaluated: 1000, strict: true, exact: true},
		{
			name: "counted Strict evaluation refusals", before: base, after: cells(map[int]uint64{1: 50, 3: 7 + 12, FailClosedRateWorkRetry: 5}),
			attempts: 1000, births: 1000, evaluated: 988, testTotal: 12, strict: true, exact: true, wantDegraded: true,
		},
		{
			// G019 chain7 g19dec2-6.12-burst-s6-c1-r1: witness [0 2 0 2 ...],
			// evaluated 996 of 1000.
			name: "counted Audit source and evaluation refusals", before: zero, after: cells(map[int]uint64{1: 2, 3: 2}),
			attempts: 1000, births: 1000, evaluated: 996, testTotal: 4, exact: true, wantDegraded: true,
		},
		{
			name: "Audit ignores the BPF-derived test total", before: zero, after: cells(map[int]uint64{3: 3}),
			attempts: 1000, births: 1000, evaluated: 997, testTotal: 0, exact: true, wantDegraded: true,
		},
		{
			name: "class not matched by its test-only witness", before: zero, after: cells(map[int]uint64{3: 12}),
			attempts: 1000, births: 1000, evaluated: 988, testTotal: 12, strict: true, exact: false, wantErr: "not exactly matched",
		},
		{
			name: "Strict refusal the witness missed", before: zero, after: cells(map[int]uint64{3: 11}),
			attempts: 1000, births: 1000, evaluated: 989, testTotal: 12, strict: true, exact: true, wantErr: "user-space fail_closed=12 != witness fail_closed=11",
		},
		{
			name: "unevaluated birth without a class", before: zero, after: cells(map[int]uint64{3: 1}),
			attempts: 1000, births: 1000, evaluated: 998, testTotal: 1, exact: true, wantErr: "unevaluated=2 != witness fail_closed=1",
		},
		{
			// A double count must not cover a missing count elsewhere.
			name: "double count", before: zero, after: cells(map[int]uint64{1: 1, 6: 1}),
			attempts: 1000, births: 1000, evaluated: 999, testTotal: 1, exact: true, wantErr: "unevaluated=1 != witness fail_closed=2",
		},
		{
			name: "evaluated exceeds births", before: zero, after: zero,
			attempts: 1000, births: 1000, evaluated: 1001, exact: true, wantErr: "evaluated=1001 of 1000",
		},
		{
			name: "missing witness", before: nil, after: nil,
			attempts: 1000, births: 1000, evaluated: 1000, exact: true, wantErr: "missing witness",
		},
		{
			name: "witness reset mid-run", before: base, after: zero,
			attempts: 1000, births: 1000, evaluated: 1000, exact: true, wantErr: "fail-closed rate witness",
		},
		{
			name: "more refusals than attempts", before: zero, after: cells(map[int]uint64{0: 1001}),
			attempts: 1000, births: 1000, evaluated: 0, testTotal: 1000, exact: true, wantErr: "exceeds 1000 attempts",
		},
		{
			name: "retry witness reset", before: base, after: cells(map[int]uint64{1: 50, 3: 7}),
			attempts: 1000, births: 1000, evaluated: 1000, exact: true, wantErr: "retry witness went backwards",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := burstOverCapacityGate(tc.before, tc.after, tc.attempts, tc.births, tc.evaluated, tc.testTotal, tc.strict, tc.exact)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("gate failed: %v", err)
				}
				if g.Rates.Degraded != tc.wantDegraded || g.Rates.Degraded != (g.Rates.Total != 0) {
					t.Fatalf("verdict %+v, want degraded=%v", g.Rates, tc.wantDegraded)
				}
				return
			}
			if err == nil {
				t.Fatalf("gate passed, want failure containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("gate error %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestConcurrentBirthCapacity(t *testing.T) {
	// Without the synchronous WORK return: (W-3)/2, one late child reserved.
	for quota, want := range map[uint32]uint32{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 1, 8: 2, 16: 6, 32: 14} {
		if got := ConcurrentBirthCapacity(quota, false); got != want {
			t.Errorf("ConcurrentBirthCapacity(%d, false) = %d, want %d", quota, got, want)
		}
		// At capacity the quota holds the parent's WORK, both WORKs of
		// every concurrent birth and both WORKs of one late child whose
		// credits are still in the reaper; one birth more does not fit.
		if quota >= 5 && (1+2*(want+1) > quota || 1+2*(want+2) <= quota) {
			t.Errorf("capacity %d does not fit WORK quota %d with one late child exactly", want, quota)
		}
	}
	// With it: the static bound (W-1)/2.
	for quota, want := range map[uint32]uint32{0: 0, 1: 0, 2: 0, 3: 1, 8: 3, 16: 7, 32: 15} {
		if got := ConcurrentBirthCapacity(quota, true); got != want {
			t.Errorf("ConcurrentBirthCapacity(%d, true) = %d, want %d", quota, got, want)
		}
		if quota >= 1 && (1+2*want > quota || 1+2*(want+1) <= quota) {
			t.Errorf("capacity %d does not fit WORK quota %d exactly", want, quota)
		}
	}
}

// TestConcurrentBirthCapacityNonSyncTestOnly pins G019 lead decision (b): the
// product object requires the synchronous WORK return, so no non-test code
// in the module calls ConcurrentBirthCapacity with anything but a literal
// true (the non-sync branch is advisory and test-only).
func TestConcurrentBirthCapacityNonSyncTestOnly(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %s: %v", root, err)
	}
	files := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil || !bytes.Contains(src, []byte("ConcurrentBirthCapacity")) {
			return err
		}
		files++
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			}
			if name != "ConcurrentBirthCapacity" {
				return true
			}
			if len(call.Args) != 2 {
				t.Errorf("%s: ConcurrentBirthCapacity call with %d arguments", fset.Position(call.Pos()), len(call.Args))
				return true
			}
			if sync, ok := call.Args[1].(*ast.Ident); !ok || sync.Name != "true" {
				t.Errorf("%s: non-test ConcurrentBirthCapacity call without a literal true (the non-sync branch is test-only)", fset.Position(call.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("ConcurrentBirthCapacity's definition was not found: the scan covers nothing")
	}
}
