// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedRecoveryReapAdmissionHost(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "reap-auth")
			command := exec.CommandContext(t.Context(), cc, "-std=gnu11",
				optimization, "-Wall", "-Wextra", "-Werror", "-iquote", "../full",
				"testdata/shared_recovery_reap_auth.c", "-o", binary)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("compile recovery admission: %v\n%s", err, out)
			}
			out, err := exec.CommandContext(t.Context(), binary).CombinedOutput()
			if err != nil || !strings.Contains(string(out), "reaper admission: PASS") {
				t.Fatalf("recovery admission: %v\n%s", err, out)
			}
		})
	}
}
