// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// packagingShapeFor is an object that carries every program the merged
// metadata names (disabled or a tail-call target) and every tail-call
// array, minus the given programs and maps.
func packagingShapeFor(t *testing.T, diagnostic, product bool, without ...string) sharedObjectShape {
	t.Helper()
	merged := mergedSharedCandidateMetadataFor(t, diagnostic)
	shape := sharedObjectShape{Programs: map[string]bool{}, Maps: map[string]bool{}, Product: product}
	for name := range candidateDisabled(merged) {
		shape.Programs[name] = true
	}
	for _, c := range sharedMergedTailCalls(t, merged) {
		shape.Programs[c.Program] = true
		shape.Maps[c.Map] = true
	}
	for _, name := range without {
		delete(shape.Programs, name)
		delete(shape.Maps, name)
	}
	return shape
}

func withoutInterp() []string {
	var out []string
	for _, c := range sharedInterpContinuationTailCalls {
		out = append(out, c.Map, c.Program)
	}
	return out
}

// tailCallsFit reports whether every declared tail call names an array and
// a target of the object (the qualification check "does not fit").
func tailCallsFit(calls []operators.NativeTailCall, shape sharedObjectShape) bool {
	for _, c := range calls {
		if !shape.Maps[c.Map] || !shape.Programs[c.Program] {
			return false
		}
	}
	return true
}

func TestSharedPackagingInterpContinuationProductExact(t *testing.T) {
	for _, diagnostic := range []bool{false, true} {
		merged := mergedSharedCandidateMetadataFor(t, diagnostic)
		// A product object carrying the continuation gets the exact merge.
		out, err := sharedPackagingForObject(merged, packagingShapeFor(t, diagnostic, true))
		if err != nil || out != merged {
			t.Fatalf("diagnostic %v: product object with the continuation: %v (same metadata %v)", diagnostic, err, out == merged)
		}
		if got := sharedMergedTailCalls(t, out); !reflect.DeepEqual(got, sharedProductTailCalls) {
			t.Fatalf("product tail calls %+v, pinned %+v", got, sharedProductTailCalls)
		}
		// A product object missing them is refused, never adapted.
		if _, err := sharedPackagingForObject(merged, packagingShapeFor(t, diagnostic, true, withoutInterp()...)); err == nil ||
			!strings.Contains(err.Error(), "product object lacks the interpreter continuation") {
			t.Fatalf("diagnostic %v: product object without the continuation accepted: %v", diagnostic, err)
		}
	}
}

func TestSharedPackagingInterpContinuationFrozenDiagnostic(t *testing.T) {
	for _, diagnostic := range []bool{false, true} {
		merged := mergedSharedCandidateMetadataFor(t, diagnostic)
		shape := packagingShapeFor(t, diagnostic, false, withoutInterp()...)
		out, err := sharedPackagingForObject(merged, shape)
		if err != nil {
			t.Fatalf("diagnostic %v: frozen non-product object refused: %v", diagnostic, err)
		}
		// Exactly the two continuation slots are dropped, in order.
		want := slices.DeleteFunc(slices.Clone(sharedProductTailCalls), func(c operators.NativeTailCall) bool {
			return slices.Contains(sharedInterpContinuationTailCalls, c)
		})
		if got := sharedMergedTailCalls(t, out); !reflect.DeepEqual(got, want) || len(got) != len(sharedProductTailCalls)-2 {
			t.Fatalf("diagnostic %v: tail calls %+v, want %+v", diagnostic, got, want)
		}
		if !tailCallsFit(sharedMergedTailCalls(t, out), shape) {
			t.Fatalf("diagnostic %v: dropped metadata does not fit the object", diagnostic)
		}
		// Exactly the two continuation disables are dropped.
		before, after := candidateDisabled(merged), candidateDisabled(out)
		for _, c := range sharedInterpContinuationTailCalls {
			delete(before, c.Program)
		}
		if !maps.Equal(before, after) {
			t.Fatalf("diagnostic %v: disabled %v, want %v", diagnostic, after, before)
		}
		// The input is unchanged and the result still takes the
		// per-node probe symbols the harnesses set.
		if len(candidateDisabled(merged)) != len(after)+2 {
			t.Fatalf("diagnostic %v: input metadata changed", diagnostic)
		}
		out.Set("programs.opaque_real_owner_failure_outer_enter.attach_to", "kprobe/x")
		if out.GetString("programs.opaque_real_owner_failure_outer_enter.attach_to") != "kprobe/x" ||
			out.GetString("programs.opaque_real_owner_policy_audit.attach_to") != sharedProgramDisabled {
			t.Fatalf("diagnostic %v: dropped metadata lost its program entries", diagnostic)
		}
	}
	// The packaging-only declaration (no tail_calls) drops the disables.
	packaging := loadCandidatePackaging(t)
	out, err := sharedPackagingForObject(packaging, packagingShapeFor(t, false, false, withoutInterp()...))
	if err != nil || out.IsSet("tail_calls") || len(candidateDisabled(out)) != len(candidateDisabled(packaging))-2 {
		t.Fatalf("packaging-only drop: %v", err)
	}
}

func TestSharedPackagingInterpContinuationOtherEntriesStillRefused(t *testing.T) {
	merged := mergedSharedCandidateMetadataFor(t, true)
	// Part of the continuation is refused.
	for _, missing := range withoutInterp() {
		if _, err := sharedPackagingForObject(merged, packagingShapeFor(t, true, false, missing)); err == nil {
			t.Errorf("object without only %s accepted", missing)
		}
	}
	// Any other missing entry is never dropped: the result still declares
	// it, so the object checks refuse the object.
	for _, missing := range []string{"opaque_real_owner_stage_audit", "opaque_real_stage_audit", "opaque_real_owner_child_target_candidate"} {
		shape := packagingShapeFor(t, true, false, append(withoutInterp(), missing)...)
		out, err := sharedPackagingForObject(merged, shape)
		if err != nil {
			t.Fatalf("%s: %v", missing, err)
		}
		if tailCallsFit(sharedMergedTailCalls(t, out), shape) {
			t.Errorf("object without %s fits the dropped metadata", missing)
		}
	}
	// A metadata that declares only one continuation slot is refused.
	var half []any
	for _, c := range sharedMergedTailCalls(t, merged) {
		if c != sharedInterpContinuationTailCalls[1] {
			half = append(half, map[string]any{"map": c.Map, "index": c.Index, "program": c.Program})
		}
	}
	broken := mergedSharedCandidateMetadataFor(t, true)
	broken.Set("tail_calls", half)
	if _, err := sharedPackagingForObject(broken, packagingShapeFor(t, true, false, withoutInterp()...)); err == nil ||
		!strings.Contains(err.Error(), "declares 1 of the 2") {
		t.Fatalf("half-declared continuation accepted: %v", err)
	}
}
