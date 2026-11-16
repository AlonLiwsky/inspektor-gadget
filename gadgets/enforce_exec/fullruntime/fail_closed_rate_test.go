// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFailClosedRate(t *testing.T) {
	base := [FailClosedRateClasses]uint64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	plus := func(d [FailClosedRateClasses]uint64) [FailClosedRateClasses]uint64 {
		out := base
		for i := range out {
			out[i] += d[i]
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		delta     [FailClosedRateClasses]uint64
		attempts  uint64
		threshold float64
		total     uint64
		rate      float64
		degraded  bool
	}{
		{"clean", [FailClosedRateClasses]uint64{}, 1000, 0, 0, 0, false},
		{"clean without attempts", [FailClosedRateClasses]uint64{}, 0, 0, 0, 0, false},
		{"any failure at zero threshold", [FailClosedRateClasses]uint64{0, 0, 0, 1}, 1000, 0, 1, 0.001, true},
		{"below threshold", [FailClosedRateClasses]uint64{1, 1, 0, 0, 0, 0}, 1000, 0.01, 2, 0.002, false},
		{"at threshold", [FailClosedRateClasses]uint64{5, 5}, 1000, 0.01, 10, 0.01, false},
		{"above threshold", [FailClosedRateClasses]uint64{494, 0, 0, 13, 0, 0}, 1000, 0.01, 507, 0.507, true},
		{"every class counts", [FailClosedRateClasses]uint64{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 10, 0.99, 10, 1, true},
		{"qualification fault degrades", [FailClosedRateClasses]uint64{FailClosedRateQualify: 1}, 1000, 0, 1, 0.001, true},
		{"pending quarantine degrades", [FailClosedRateClasses]uint64{FailClosedRatePending: 1}, 1000, 0, 1, 0.001, true},
		{"open-parent failure degrades", [FailClosedRateClasses]uint64{FailClosedRateOpenParent: 1}, 1000, 0, 1, 0.001, true},
		{"gap refusal degrades", [FailClosedRateClasses]uint64{FailClosedRateGap: 1}, 1000, 0, 1, 0.001, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := FailClosedRate(base, plus(tc.delta), tc.attempts, tc.threshold)
			if err != nil {
				t.Fatal(err)
			}
			if v.Failures != tc.delta || v.Total != tc.total || math.Abs(v.Rate-tc.rate) > 1e-12 || v.Degraded != tc.degraded {
				t.Fatalf("verdict %+v, want failures %v total %d rate %v degraded %v", v, tc.delta, tc.total, tc.rate, tc.degraded)
			}
		})
	}
}

// The user-approved reporting rule: any failure in the 60 s window is
// Degraded; NotReady needs more than 0.1% over the 5 min window.
func TestFailClosedRateReportingRule(t *testing.T) {
	if FailClosedRateDegradedWindow != time.Minute || FailClosedRateDegradedThreshold != 0 ||
		FailClosedRateNotReadyWindow != 5*time.Minute || FailClosedRateNotReadyThreshold != 0.001 {
		t.Fatal("fail-closed reporting rule drifted from the approved 60 s / any and 5 min / 0.1%")
	}
	var before [FailClosedRateClasses]uint64
	for _, tc := range []struct {
		failures, attempts uint64
		degraded, notReady bool
	}{
		{0, 120000, false, false},
		{1, 120000, true, false},
		{120, 120000, true, false},
		{121, 120000, true, true},
	} {
		after := [FailClosedRateClasses]uint64{0, tc.failures}
		degraded, err := FailClosedRate(before, after, tc.attempts, FailClosedRateDegradedThreshold)
		if err != nil {
			t.Fatal(err)
		}
		notReady, err := FailClosedRate(before, after, tc.attempts, FailClosedRateNotReadyThreshold)
		if err != nil {
			t.Fatal(err)
		}
		if degraded.Degraded != tc.degraded || notReady.Degraded != tc.notReady {
			t.Fatalf("%d failures / %d attempts: degraded=%v notReady=%v, want %v %v",
				tc.failures, tc.attempts, degraded.Degraded, notReady.Degraded, tc.degraded, tc.notReady)
		}
	}
}

func TestFailClosedRateRefusesInvalidInput(t *testing.T) {
	before := [FailClosedRateClasses]uint64{0, 5}
	if _, err := FailClosedRate(before, [FailClosedRateClasses]uint64{0, 4}, 10, 0); err == nil {
		t.Fatal("a counter moving backwards must be an error, not a zero rate")
	}
	overflow := [FailClosedRateClasses]uint64{math.MaxUint64, 1}
	if _, err := FailClosedRate([FailClosedRateClasses]uint64{}, overflow, 10, 0); err == nil {
		t.Fatal("an overflowing total must be an error")
	}
	// More failures than attempts (including failures without attempts)
	// is unknown, never a rate.
	for _, attempts := range []uint64{0, 4} {
		if _, err := FailClosedRate(before, [FailClosedRateClasses]uint64{2, 8}, attempts, 0); err == nil {
			t.Fatalf("5 failures over %d attempts accepted", attempts)
		}
	}
	if v, err := FailClosedRate(before, [FailClosedRateClasses]uint64{2, 8}, 5, 0); err != nil || v.Total != 5 || v.Rate != 1 {
		t.Fatalf("5 failures over 5 attempts: %+v, %v", v, err)
	}
	// A G019 M0 class moving backwards is unknown too.
	gapBefore := [FailClosedRateClasses]uint64{FailClosedRateGap: 3}
	if _, err := FailClosedRate(gapBefore, [FailClosedRateClasses]uint64{FailClosedRateGap: 2}, 10, 0); err == nil {
		t.Fatal("a gap-refusal counter moving backwards must be an error, not a zero rate")
	}
	for _, threshold := range []float64{-0.1, 1.1, math.NaN()} {
		if _, err := FailClosedRate(before, before, 10, threshold); err == nil {
			t.Fatalf("threshold %v accepted", threshold)
		}
	}
}

// TestFailClosedRateLayoutMatchesWitness pins the Go class indices to the
// witness map layout in the candidate source: the classes first, then the
// WORK retry subset, and the map sized to hold all of them.
func TestFailClosedRateLayoutMatchesWitness(t *testing.T) {
	raw, err := os.ReadFile("bpf/opaque_real_owner_child_candidate.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for name, index := range map[string]int{
		"LIMIT": 0, "SOURCE": 1, "MISSING_TARGET": 2, "EVAL_WORK": 3,
		"STORAGE": 4, "CONSTRUCT": 5,
		"QUALIFY":     FailClosedRateQualify,
		"PENDING":     FailClosedRatePending,
		"OPEN_PARENT": FailClosedRateOpenParent,
		"GAP":         FailClosedRateGap,
		"WORK_RETRY":  FailClosedRateWorkRetry,
		"ENTRY":       FailClosedRateEntry,
		"ADMISSION":   FailClosedRateAdmission,
		"CLASSES":     FailClosedRateCounters,
	} {
		define := fmt.Sprintf("#define REAL_OWNER_RATE_%s %d\n", name, index)
		if !strings.Contains(source, define) {
			t.Errorf("candidate source lacks %q", strings.TrimSpace(define))
		}
	}
	if FailClosedRateWorkRetry != FailClosedRateClasses || FailClosedRateEntry != FailClosedRateClasses+1 ||
		FailClosedRateAdmission != FailClosedRateClasses+2 ||
		FailClosedRateCounters != FailClosedRateClasses+3 || FailClosedRateLegacyCounters != FailClosedRateClasses+1 {
		t.Fatalf("witness layout %d classes, retry %d, entry %d, counters %d/%d", FailClosedRateClasses, FailClosedRateWorkRetry,
			FailClosedRateEntry, FailClosedRateCounters, FailClosedRateLegacyCounters)
	}
	// ENTRY, ADMISSION and the 13-cell witness exist only with the product publisher;
	// other objects keep 11 cells. attempts has births [0] and execs [1].
	squashed := squashSpace(source)
	for _, want := range []string{
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n#define REAL_OWNER_RATE_ENTRY 11\n#define REAL_OWNER_RATE_ADMISSION 12\n#define REAL_OWNER_RATE_CLASSES 13\n#else\n#define REAL_OWNER_RATE_CLASSES 11\n#endif",
		"__uint(max_entries, 2); __uint(map_flags, BPF_F_RDONLY); __type(key, __u32); __type(value, __u64); } opaque_real_attempts SEC(\".maps\");",
	} {
		if !strings.Contains(squashed, squashSpace(want)) {
			t.Errorf("candidate source lacks %q", want)
		}
	}
	for _, cells := range []uint32{FailClosedRateCounters, FailClosedRateLegacyCounters} {
		if n, err := FailClosedRateCells(cells); err != nil || n != int(cells) {
			t.Errorf("FailClosedRateCells(%d) = %d, %v", cells, n, err)
		}
	}
	if _, err := FailClosedRateCells(FailClosedRateClasses); err == nil {
		t.Error("10-cell witness accepted")
	}
	// Every G019 M0 class is counted (the reserved gap class excepted).
	for _, site := range []string{
		"SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_OPEN_PARENT)",
		"REAL_OWNER_RATE_QUALIFY :",
		"REAL_OWNER_RATE_PENDING)",
	} {
		if !strings.Contains(squashSpace(source), squashSpace(site)) {
			t.Errorf("candidate source lacks rate site %q", site)
		}
	}
}

// TestFailClosedProductRate: ENTRY is reported apart (never in Total, never
// Degraded), the attempts witness is the shared denominator, and a counter
// moving backwards or more failures than attempts is unknown, not zero.
func TestFailClosedProductRate(t *testing.T) {
	var zero [FailClosedRateCounters]uint64
	after := zero
	after[FailClosedRateOpenParent], after[FailClosedRateEntry] = 1, 3
	v, err := FailClosedProductRate(zero, after, [2]uint64{10, 5}, [2]uint64{510, 505}, FailClosedRateNotReadyThreshold)
	if err != nil || v.Total != 1 || v.Entry != 3 || v.Rate != 0.001 || v.EntryRate != 0.003 || v.Degraded {
		t.Fatalf("verdict %+v %v", v, err)
	}
	onlyEntry := zero
	onlyEntry[FailClosedRateEntry] = 2
	if v, err := FailClosedProductRate(zero, onlyEntry, [2]uint64{}, [2]uint64{1, 1}, 0); err != nil || v.Degraded || v.Total != 0 || v.Entry != 2 {
		t.Fatalf("ENTRY-only verdict %+v %v", v, err)
	}
	for name, tc := range map[string]struct {
		after          [FailClosedRateCounters]uint64
		attemptsBefore [2]uint64
	}{
		"attempts backwards":     {zero, [2]uint64{1, 0}},
		"entry exceeds attempts": {onlyEntry, [2]uint64{}},
	} {
		if _, err := FailClosedProductRate(zero, tc.after, tc.attemptsBefore, [2]uint64{0, 1}, 0); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	both := zero
	both[1], both[FailClosedRateEntry] = 1, 1 // [1] source refusal
	if _, err := FailClosedProductRate(zero, both, [2]uint64{}, [2]uint64{1, 0}, 0); err == nil {
		t.Error("Total + Entry above attempts accepted")
	}
	if _, err := FailClosedProductRate(onlyEntry, zero, [2]uint64{}, [2]uint64{1, 1}, 0); err == nil {
		t.Error("entry moving backwards accepted")
	}
}

// TestFailClosedProductRateAdmission: ADMISSION (every exec admission fault)
// is reported apart from Total, shares the attempts denominator, and
// degrades the node by its own rate; it can never exceed the attempts left
// after ENTRY.
func TestFailClosedProductRateAdmission(t *testing.T) {
	var zero [FailClosedRateCounters]uint64
	after := zero
	after[FailClosedRateAdmission] = 2
	v, err := FailClosedProductRate(zero, after, [2]uint64{}, [2]uint64{8, 2}, FailClosedRateNotReadyThreshold)
	if err != nil || v.Total != 0 || v.Admission != 2 || v.AdmissionRate != 0.2 || !v.Degraded {
		t.Fatalf("admission verdict %+v %v", v, err)
	}
	if v, err := FailClosedProductRate(zero, zero, [2]uint64{}, [2]uint64{8, 2}, 0); err != nil || v.Degraded || v.Admission != 0 {
		t.Fatalf("no admission fault: %+v %v", v, err)
	}
	both := zero
	both[FailClosedRateEntry], both[FailClosedRateAdmission] = 1, 1
	if _, err := FailClosedProductRate(zero, both, [2]uint64{}, [2]uint64{0, 1}, 0); err == nil {
		t.Error("ENTRY + ADMISSION above attempts accepted")
	}
	if _, err := FailClosedProductRate(after, zero, [2]uint64{}, [2]uint64{1, 1}, 0); err == nil {
		t.Error("admission moving backwards accepted")
	}
	// Total shares the denominator left after ENTRY and ADMISSION.
	mixed := zero
	mixed[1], mixed[FailClosedRateAdmission] = 1, 1
	if _, err := FailClosedProductRate(zero, mixed, [2]uint64{}, [2]uint64{1, 0}, 0); err == nil {
		t.Error("Total + ADMISSION above attempts accepted")
	}
}
