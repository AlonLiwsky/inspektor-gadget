// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func modelUnionRefs(t *testing.T, count, rules, paths int) []SharedPolicyRef {
	t.Helper()
	refs := make([]SharedPolicyRef, count)
	for i := range refs {
		p := base()
		p.ID = fmt.Sprintf("policy-%d", i)
		for j := 0; j < rules; j++ {
			r := Rule{Name: fmt.Sprint(j), Action: Allow}
			for k := 0; k < paths; k++ {
				r.Actor.Path = append(r.Actor.Path, "/a")
			}
			p.Rules = append(p.Rules, r)
		}
		object, err := CompileSharedPolicyCompact(p)
		if err != nil {
			t.Fatal(err)
		}
		refs[i] = SharedPolicyRef{Object: object, RootEpoch: 1}
	}
	return refs
}

func TestSharedSnapshotModelBoundary(t *testing.T) {
	refs := modelUnionRefs(t, 8, 1, 1)
	model, err := sharedSnapshotModelDebit("app", refs)
	if err != nil {
		t.Fatal(err)
	}
	got, debit, err := newSharedSnapshotModel(1, 2, "app", refs, model.total)
	want, wantErr := NewSharedSnapshotCompact(1, 2, "app", refs)
	if err != nil || wantErr != nil || debit != model.total || !reflect.DeepEqual(got, want) {
		t.Fatalf("exact: %d %v %v", debit, err, wantErr)
	}
	zero, debit, err := newSharedSnapshotModel(1, 2, "app", refs, model.total-1)
	if !reflect.DeepEqual(zero, SharedSnapshot{}) || debit != 0 || err != compactFailure(DiagnosticCapacity, DiagnosticNone) { //nolint:errorlint // Exact static refusal sentinel.
		t.Fatalf("short: %+v %d %v", zero, debit, err)
	}
	if allocs := testing.AllocsPerRun(10, func() { _, _, _ = newSharedSnapshotModel(1, 2, "app", refs, 0) }); allocs != 0 {
		t.Fatalf("refusal allocates %v", allocs)
	}
}

func TestSharedSnapshotModelGlobalPrefixes(t *testing.T) {
	for _, fixture := range []struct{ policies, rules, paths int }{{5, 1, 256}, {8, 33, 0}} {
		refs := modelUnionRefs(t, fixture.policies, fixture.rules, fixture.paths)
		model, err := sharedSnapshotModelDebit("app", refs)
		if err != nil {
			t.Fatal(err)
		}
		if fixture.paths != 0 && model.pathSlots != 1280 {
			t.Fatalf("global slots=%d", model.pathSlots)
		}
		got, debit, err := newSharedSnapshotModel(1, 2, "app", refs, model.total)
		_, want := NewSharedSnapshotCompact(1, 2, "app", refs)
		if !reflect.DeepEqual(got, SharedSnapshot{}) || debit != model.total || err != want || err == nil { //nolint:errorlint // Original whole-union diagnostic identity.
			t.Fatalf("global prefix: %d %v want=%v", debit, err, want)
		}
	}
}

func TestSharedSnapshotModelLateFailureAndOwnership(t *testing.T) {
	refs := modelUnionRefs(t, 2, 1, 1)
	storage := []byte(strings.Repeat("c", 100))
	container := unsafe.String(unsafe.SliceData(storage), len(storage))
	got, _, err := newSharedSnapshotModel(1, 2, container, refs, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	storage[0] = 'x'
	if got.Container[0] != 'c' {
		t.Fatal("container backing borrowed")
	}
	refs[0], refs[1] = refs[1], refs[0]
	if got.Policies[0].Object == refs[0].Object {
		t.Fatal("reference slice borrowed")
	}
	// A private corrupt fixture survives ordinary source compilation and fails
	// metadata lookup after validation, exercising final Blob-token cleanup.
	refs[0].Object.uid++
	model, err := sharedSnapshotModelDebit("app", refs)
	if err != nil {
		t.Fatal(err)
	}
	failed, debit, err := newSharedSnapshotModel(1, 2, "app", refs, model.total)
	_, want := NewSharedSnapshotCompact(1, 2, "app", refs)
	if !reflect.DeepEqual(failed, SharedSnapshot{}) || debit != model.total || err != want || err == nil { //nolint:errorlint // Exact internal failure, without cleanup contamination.
		t.Fatalf("metadata failure: %d %v want=%v", debit, err, want)
	}
}

func TestSharedSnapshotModelObjectDebitLocks(t *testing.T) {
	totals := map[int]uint64{0: 8925, 1: 40288, 8: 304637, 256: 9662287}
	for n, want := range totals {
		p := base()
		for i := 0; i < n; i++ {
			p.Rules = append(p.Rules, Rule{Name: fmt.Sprint(i), Action: Allow, Actor: Actor{Path: []string{"/[a-z]/**"}, Role: []string{"agent"}, UID: []int64{0}}})
		}
		m, err := sharedPolicyModelDebit(p)
		if err != nil || m.total != want {
			t.Fatalf("object n=%d: %+v %v want=%d", n, m, err, want)
		}
	}
}

func TestSharedSnapshotModelReferenceOrderAndCapacity(t *testing.T) {
	refs := modelUnionRefs(t, 8, 1, 0)
	p := base()
	p.ID = "writer"
	p.Rules = []Rule{{Name: "write", Action: Allow, Actor: Actor{Role: []string{"agent"}}, Target: Target{SetRole: "next"}}}
	writer, err := CompileSharedPolicyCompact(p)
	if err != nil {
		t.Fatal(err)
	}
	refs[0].Object = writer
	for i, j := 0, len(refs)-1; i < j; i, j = i+1, j-1 {
		refs[i], refs[j] = refs[j], refs[i]
	}
	for count := 1; count <= 8; count++ {
		model, err := sharedSnapshotModelDebit(strings.Repeat("c", 255), refs[:count])
		if err != nil {
			t.Fatal(err)
		}
		got, debit, err := newSharedSnapshotModel(1, 2, strings.Repeat("c", 255), refs[:count], model.total)
		want, wantErr := NewSharedSnapshotCompact(1, 2, strings.Repeat("c", 255), refs[:count])
		if err != nil || wantErr != nil || debit != model.total || !reflect.DeepEqual(got, want) || cap(got.Policies) != count {
			t.Fatalf("count%d: %d/%d %v %v cap%d", count, debit, model.total, err, wantErr, cap(got.Policies))
		}
		if count == 8 {
			metadata, err := got.ExecutionMetadata()
			if err != nil || metadata.RoleWriters != 1<<7 {
				t.Fatalf("reference writer bit: %+v %v", metadata, err)
			}
		}
	}
}

func TestSharedSnapshotModelInvalidReferenceOrder(t *testing.T) {
	valid := modelUnionRefs(t, 2, 0, 0)
	fixtures := [][]SharedPolicyRef{nil, {{}}, append(append([]SharedPolicyRef{}, valid...), valid[0]), make([]SharedPolicyRef, 9)}
	for _, refs := range fixtures {
		model, err := sharedSnapshotModelDebit("app", refs)
		if err != nil {
			t.Fatal(err)
		}
		got, debit, err := newSharedSnapshotModel(1, 2, "app", refs, model.total)
		_, want := NewSharedSnapshotCompact(1, 2, "app", refs)
		if !reflect.DeepEqual(got, SharedSnapshot{}) || debit != model.total || err != want || err == nil { //nolint:errorlint // Exact original reference-validation order.
			t.Fatalf("refs%d: %d %v want%v", len(refs), debit, err, want)
		}
	}
	// Earlier bad epoch must win over duplicate UID, with original ordering.
	duplicate := []SharedPolicyRef{valid[0], valid[0]}
	duplicate[0].RootEpoch = 0
	model, err := sharedSnapshotModelDebit("app", duplicate)
	if err != nil {
		t.Fatal(err)
	}
	got, debit, err := newSharedSnapshotModel(1, 2, "app", duplicate, model.total)
	_, want := NewSharedSnapshotCompact(1, 2, "app", duplicate)
	if !reflect.DeepEqual(got, SharedSnapshot{}) || debit != model.total || err != want { //nolint:errorlint // Exact static diagnostic comparison.
		t.Fatalf("epoch order: %d %v want%v", debit, err, want)
	}
}

func TestSharedSnapshotModelGlobalUIDGrowth(t *testing.T) {
	for _, rules := range []int{31, 32} {
		refs := make([]SharedPolicyRef, 2)
		for i := range refs {
			p := base()
			p.ID = fmt.Sprint(i)
			for j := 0; j < rules; j++ {
				p.Rules = append(p.Rules, Rule{Name: fmt.Sprint(j), Action: Allow, Actor: Actor{UID: make([]int64, 256)}})
			}
			object, err := CompileSharedPolicyCompact(p)
			if err != nil {
				t.Fatal(err)
			}
			refs[i] = SharedPolicyRef{Object: object, RootEpoch: 1}
		}
		model, err := sharedSnapshotModelDebit("app", refs)
		if err != nil {
			t.Fatal(err)
		}
		got, debit, err := newSharedSnapshotModel(1, 2, "app", refs, model.total)
		want, wantErr := NewSharedSnapshotCompact(1, 2, "app", refs)
		if err != wantErr || debit != model.total || (err == nil && !reflect.DeepEqual(got, want)) { //nolint:errorlint // Exact global capacity and cleanup categories.
			t.Fatalf("global UID growth%d: %d %v want%v", rules, debit, err, wantErr)
		}
		if rules == 32 && (err == nil || !reflect.DeepEqual(got, SharedSnapshot{})) {
			t.Fatal("global UID overflow accepted")
		}
	}
}
