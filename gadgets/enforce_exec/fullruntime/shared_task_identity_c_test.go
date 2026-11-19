// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Executes the actual HASH task map-operation bodies with mock fixed-account
// callbacks. This is not the selected bounded TASK/WORK pool and does not prove
// kernel hook coverage, physical-reference exclusion, quota-account pins,
// frozen template setup or verifier acceptance.
func TestSharedTaskIdentityActualMapBodies(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "task-identity")
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", "../full", "-iquote", "../fullpolicy/bpf", "testdata/shared_task_identity.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("task identity: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
