// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScalarEvaluatorContextC(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "scalar-evaluator")
			out, err := exec.Command(cc, "-std=gnu11", optimization,
				"-Wall", "-Wextra", "-Werror",
				"testdata/evaluator_scalar_context.c", "-o", binary).CombinedOutput()
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, out)
			}
			out, err = exec.Command(binary).CombinedOutput()
			if err != nil || !strings.Contains(string(out), "scalar evaluator context: PASS") {
				t.Fatalf("execute: %v\n%s", err, out)
			}
		})
	}
}

func TestScalarEvaluatorBoundedLoopContextC(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "scalar-evaluator-bounded")
			out, err := exec.Command(cc, "-std=gnu11", optimization,
				"-Wall", "-Wextra", "-Werror", "-DFE_BOUNDED_LOOP_CANDIDATE",
				"testdata/evaluator_scalar_context.c", "-o", binary).CombinedOutput()
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, out)
			}
			out, err = exec.Command(binary).CombinedOutput()
			if err != nil || !strings.Contains(string(out), "scalar evaluator context: PASS") {
				t.Fatalf("execute: %v\n%s", err, out)
			}
		})
	}
}
