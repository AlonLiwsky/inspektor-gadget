// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSharedKernelActualEntry(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct {
		name, define string
	}{{name: "legacy-global"}, {name: "scalar-token", define: "-DTEST_SHARED_SCALAR_EVAL=1"}} {
		t.Run(variant.name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "kernel")
			args := []string{"-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation", "-iquote", "../full", "-iquote", "../fullpolicy/bpf"}
			if variant.define != "" {
				args = append(args, variant.define)
			}
			args = append(args, "testdata/shared_kernel.c", "-o", binary)
			if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile: %v %s", err, out)
			}
			if out, err := exec.Command(binary).CombinedOutput(); err != nil {
				t.Fatalf("entry: %v %s", err, out)
			}
		})
	}
}
