// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSharedExecCanonicalEvaluator(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct {
		name  string
		flags []string
	}{
		{name: "default"},
		{name: "typed-pool-candidate", flags: []string{
			"-DENFORCE_EXEC_POOL_DEVELOPMENT=1",
			"-DENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY=1",
			"-DENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE=1",
		}},
		{name: "opaque-task-semantic-candidate", flags: []string{
			"-DENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE=1",
			"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
		}},
		{name: "opaque-task-work-semantic-candidate", flags: []string{
			"-DENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE=1",
			"-DENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE=1",
			"-DENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE=1",
		}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "exec")
			args := []string{"-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", "../full", "-iquote", "../fullpolicy/bpf"}
			args = append(args, variant.flags...)
			args = append(args, "testdata/shared_exec.c", "-o", binary)
			if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile: %v %s", err, out)
			}
			if out, err := exec.Command(binary).CombinedOutput(); err != nil {
				t.Fatalf("exec: %v %s", err, out)
			}
		})
	}
}
