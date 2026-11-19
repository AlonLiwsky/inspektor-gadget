// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpaqueExecProposalAdapter(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "proposal")
			args := []string{
				"-std=gnu11", optimization, "-Wall", "-Wextra", "-Werror",
				"-iquote", "../full", "-iquote", "../fullpolicy/bpf",
				"testdata/opaque_exec_propose.c", "-o", binary,
			}
			if out, err := exec.CommandContext(t.Context(), cc, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile: %v\n%s", err, out)
			}
			out, err := exec.CommandContext(t.Context(), binary).CombinedOutput()
			if err != nil || !strings.Contains(string(out), "opaque exec proposal adapter: PASS") {
				t.Fatalf("proposal: %v\n%s", err, out)
			}
		})
	}
}
