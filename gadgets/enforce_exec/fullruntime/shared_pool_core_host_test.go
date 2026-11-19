// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The candidate cores are not selected by BPF hooks. Keep their real C
// transitions under ordinary Go CI while the selected lifecycle is built.
func runSharedPoolCoreHostCandidate(t *testing.T, filename, marker string, defines ...string) {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "test/host", filename)
	policyRoot, err := filepath.Abs("../fullpolicy/bpf")
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "pool-core")
			args := []string{
				"-std=gnu11", optimization,
				"-Wall", "-Wextra", "-Werror", "-iquote", root,
				"-iquote", policyRoot,
			}
			args = append(args, defines...)
			args = append(args, source, "-o", binary)
			command := exec.CommandContext(t.Context(), cc, args...)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("compile candidate pool core: %v\n%s", err, out)
			}
			out, err := exec.CommandContext(t.Context(), binary).CombinedOutput()
			if err != nil || !strings.Contains(string(out), marker) {
				t.Fatalf("candidate pool core: %v\n%s", err, out)
			}
		})
	}
}

func TestSharedPoolWorkCoreHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "pool_work_core_candidate.c", "work core host tests OK")
}

func TestSharedPoolTaskCoreHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "pool_task_core_candidate.c", "candidate task-core host regressions: PASS")
}

func TestSharedPoolSnapshotMatchBranchlessHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "pool_task_core_candidate.c", "branchless snapshot matcher oracle: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_SNAPSHOT_BRANCHLESS_DIAGNOSTIC=1")
}

func TestSharedPoolSemanticPrefixHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "pool_semantic_prefix_candidate.c", "typed pool semantic prefix candidate OK")
}

func TestSharedPoolInheritRolesHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "pool_inherit_roles_candidate.c", "pool inheritance role publication candidate OK")
}

func TestSharedOpaqueLocatorHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS")
}

// G025 batch F: the final-free directory withdrawal and the single insert
// retry are unconditional and also run in every other opaque locator host
// build; this variant adds the default-off fail-closed rate witness.
func TestSharedOpaqueLocatorFinalFreeWithdrawHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE=1")
}

func TestSharedOpaqueLocatorTypedBirthReuseHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE=1")
}

func TestSharedOpaqueLocatorHostB2T128Candidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DSE_OL_TASKS=128", "-DSE_OC_ACCOUNTS=2", "-DSE_OC_QUOTA=64", "-DSE_OWK_QUOTA=32")
}

func TestSharedOpaqueLocatorTypedWorkHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1")
}

func TestSharedOpaqueLocatorTypedWorkB2T128HostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		"-DSE_OL_TASKS=128", "-DSE_OC_ACCOUNTS=2", "-DSE_OC_QUOTA=64", "-DSE_OWK_QUOTA=16")
}

func TestSharedOpaqueLocatorReaderCatalogueHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE=1")
}

// G019 gap 3 (product publisher, per-record route holders): a reader and a
// parked birth claim of a RETIRING record evaluate against the identical
// write-once catalogue after the next commit; an epoch change (E+1 or 0)
// fails closed. This variant runs only those scenarios.
func TestSharedOpaqueLocatorRetiringCatalogueHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE=1",
		"-DENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE=1")
}

func TestSharedOpaqueLocatorReaderCatalogueB2T128HostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE=1",
		"-DSE_OL_TASKS=128", "-DSE_OC_ACCOUNTS=2", "-DSE_OC_QUOTA=64", "-DSE_OWK_QUOTA=8")
}

func TestSharedOpaqueLocatorWorkContinuationHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE=1")
}

func TestSharedOpaqueLocatorResumeOutputTicketHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_RESUME_OUTPUT_TICKET_DIAGNOSTIC=1")
}

func TestSharedOpaqueLocatorWorkStageOverlayHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE=1",
		"-DENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE=1")
}

func TestSharedOpaqueLocatorSuspendedReadHostCandidate(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE=1",
		"-DENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE=1",
		"-DENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE=1")
}

func TestSharedOpaqueLocatorSuspendedEvalReaderHostDiagnostic(t *testing.T) {
	runSharedPoolCoreHostCandidate(t, "opaque_locator_candidate.c", "opaque locator candidate host regressions: PASS",
		"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE=1",
		"-DENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE=1",
		"-DENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE=1",
		"-DENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC=1")
}
