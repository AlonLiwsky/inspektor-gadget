// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestReaperDirectoryStageMovePins pins the premise of the reaper visit's
// CORRUPT -> PENDING rule (se_or_task_directory_step in
// full/shared_pool_opaque_reaper_visit_candidate.h): a CORRUPT stage is a
// fault only while directory_state still equals the snapshot that selected
// it, and a moved state is PENDING. That is sound only if no stage that
// returns CORRUPT has itself moved directory_state, and if moves are bounded
// per charge:
//   - in every reaper directory stage, each directory_state assignment sits
//     in `if (exact)` and the stage's only return after it is
//     `return exact ? SE_OL_OK : ...`; delete_withdrawn_zero alone assigns
//     unconditionally, after its successful delete, and then returns
//     SE_OL_OK;
//   - every writer of directory_state in the candidate sources is pinned by
//     file and count (each is a forward move along PUBLISH_INTENT ->
//     PUBLISHED/ZERO_OWNED -> WITHDRAW_CLAIM -> WITHDRAWN_ZERO -> DELETED,
//     so moved-PENDING repeats at most a few times per cookie); a new
//     writer, which could move backwards, fails until it is reviewed.
func TestReaperDirectoryStageMovePins(t *testing.T) {
	raw, err := os.ReadFile("../full/shared_pool_opaque_writer_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	writer := string(raw)
	assign := regexp.MustCompile(`directory_state = `)
	for _, stage := range []string{
		"se_ow_reconcile_publish_intent", "se_ow_mark_absent_deleted",
		"se_ow_claim_aborted_zero", "se_ow_claim_withdraw",
		"se_ow_advance_withdraw", "se_ow_delete_withdrawn_zero",
		"se_ow_zero_archive",
	} {
		start := strings.Index(writer, "static inline int "+stage+"(")
		if start < 0 {
			t.Errorf("%s: stage not found", stage)
			continue
		}
		end := strings.Index(writer[start:], "\n}\n")
		if end < 0 {
			t.Errorf("%s: end not found", stage)
			continue
		}
		body := writer[start : start+end]
		// Each stage moves directory_state once; zero_archive never does.
		if n, want := len(assign.FindAllStringIndex(body, -1)), map[bool]int{true: 0, false: 1}[stage == "se_ow_zero_archive"]; n != want {
			t.Errorf("%s: %d directory_state assignments, want %d", stage, n, want)
		}
		for _, at := range assign.FindAllStringIndex(body, -1) {
			before, after := body[:at[0]], body[at[0]:]
			if returns := strings.Count(after, "return"); returns != 1 {
				t.Errorf("%s: %d returns after a directory_state assignment, want 1", stage, returns)
				continue
			}
			ret := after[strings.Index(after, "return"):]
			if stage == "se_ow_delete_withdrawn_zero" {
				if !strings.HasPrefix(ret, "return SE_OL_OK;") ||
					!strings.Contains(squashSpace(before), squashSpace("int deleted = SE_OW_DELETE(archived_key);\n\tif (deleted != SE_OL_OK)\n\t\treturn deleted;")) {
					t.Errorf("%s: the unconditional assignment must follow the successful delete and return SE_OL_OK", stage)
				}
				continue
			}
			if !strings.HasPrefix(ret, "return exact ? SE_OL_OK :") {
				t.Errorf("%s: assignment followed by %q, want return exact ? SE_OL_OK : ...", stage, ret[:min(len(ret), 40)])
			}
			last := strings.LastIndex(before, "if (")
			if last < 0 || !strings.HasPrefix(before[last:], "if (exact)") {
				t.Errorf("%s: directory_state assignment not guarded by if (exact)", stage)
			}
		}
	}
	want := map[string]int{
		"shared_pool_opaque_writer_candidate.h":     11,
		"shared_pool_opaque_final_free_candidate.h": 3,
		"shared_pool_opaque_replace_candidate.h":    2,
	}
	got := map[string]int{}
	for _, pattern := range []string{"../full/*.h", "bpf/*.c", "bpf/*.h"} {
		files, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if n := len(assign.FindAllIndex(raw, -1)); n != 0 {
				got[filepath.Base(file)] = n
			}
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("directory_state writers %v, pinned %v: review any new writer for backward moves", got, want)
	}
}
