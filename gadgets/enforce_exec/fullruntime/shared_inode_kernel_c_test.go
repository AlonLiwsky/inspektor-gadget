// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSharedInodeKernelActualHooks(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "inode")
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation", "-iquote", "../full", "testdata/shared_inode_kernel.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("hooks: %v %s", err, out)
	}
}
