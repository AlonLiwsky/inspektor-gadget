// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCEvaluatorE1OptionCCompatParity: the evaluator with the exact -D set
// of the E1 option C compat object (FE_BOUNDED_LOOP_CANDIDATE, staged, one
// rule per advance, the product's old-kernel window knobs), driven as that
// object drives it, against the Go reference over the parity vocabulary
// (paths, uid, container, ancestors, fs class, image, argv, stdin,
// multi-policy merge, roles, 256 rules).
func TestCEvaluatorE1OptionCCompatParity(t *testing.T) {
	runner := buildE1CompatRunner(t)
	runEvaluatorParity(t, func(t *testing.T, p *KernelProgram, facts evaluatorFacts) []uint64 {
		return runCEvaluator(t, runner, p, facts)
	})
}

// buildE1CompatRunner builds the evaluator runner with the exact -D set of
// the option C compat object.
func buildE1CompatRunner(t *testing.T) string {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Fatal("the E1 parity gate needs clang")
	}
	runner := filepath.Join(t.TempDir(), "e1-compat")
	if out, err := exec.Command(clang, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-pass-failed",
		kleeneMutantSource(t, "testdata/e1_optc_compat_runner.c"), "-o", runner).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	return runner
}
