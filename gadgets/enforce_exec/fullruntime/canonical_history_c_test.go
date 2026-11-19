// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Native execution covers pure merge/publication semantics only; this is not
// BPF verifier, task-storage locking, bootstrap lineage or live-kernel proof.
func TestCanonicalHistoryPreservation(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "epoch-roles")
	command := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "testdata/epoch_roles_canonical.c", "-o", binary)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("epoch roles: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
