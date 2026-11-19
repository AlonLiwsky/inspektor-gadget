// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Actual production-header transitions with fixed-pool callbacks, not kernel
// birth/death authentication, verifier, collection or concurrency proof.
func TestSharedInodeFactsActualHeader(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("C compiler required", err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "shared-inode-facts")
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "testdata/shared_inode_facts.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("inode facts: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
