// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"testing"
)

func TestCoexFillersAtReserveBoundary(t *testing.T) {
	for _, c := range []struct {
		k, reserve, pre int
		want            []int
	}{
		{3, 8, 0, []int{0, 10, 20, 27, 28}},
		{1, 8, 0, []int{0, 10, 20, 29, 30}},
		{1, 8, 1, []int{0, 10, 20, 28, 29}},
		{1, 8, 20, []int{0, 9, 10}},
	} {
		if got := coexFillers(c.k, c.reserve, c.pre); !slices.Equal(got, c.want) {
			t.Errorf("coexFillers(%d, %d, %d) = %v, want %v", c.k, c.reserve, c.pre, got, c.want)
		}
	}
}

// TestCandidateAttachSetProductShape pins the runner's attach set to the
// product's 8-link shape (fullruntime sharedCandidateAttachSet), including
// the exec capsule's death retire on task_free.
func TestCandidateAttachSetProductShape(t *testing.T) {
	want := []string{
		"opaque_real_owner_child_final_free_candidate",
		"opaque_real_owner_child_source_candidate",
		"opaque_real_owner_failure_fexit_probe",
		"opaque_real_owner_reader_begin_probe",
		"real_owner_capsule_begin",
		"real_owner_capsule_entry",
		"real_owner_capsule_free",
		"real_owner_capsule_terminal",
	}
	if got := slices.Sorted(slices.Values(candidateAttachSet)); !slices.Equal(got, want) {
		t.Fatalf("candidateAttachSet %v, want %v", got, want)
	}
}
