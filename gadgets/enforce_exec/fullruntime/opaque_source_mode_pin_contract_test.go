// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runOpaqueSourceModeContract(t *testing.T, cases []string) {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "source-mode-contract")
			args := []string{
				"-std=gnu11", optimization, "-Wall", "-Wextra", "-Werror",
				"-iquote", "../full", "-iquote", "../fullpolicy/bpf",
				"testdata/opaque_source_mode_pin_contract.c", "-o", binary,
			}
			if out, err := exec.CommandContext(t.Context(), cc, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile actual-header fixture: %v\n%s", err, out)
			}
			for _, mode := range []string{"audit", "strict"} {
				for _, scenario := range cases {
					t.Run(mode+"/"+scenario, func(t *testing.T) {
						out, err := exec.CommandContext(t.Context(), binary, scenario, mode).CombinedOutput()
						if err != nil || !strings.Contains(string(out), "source mode publication contract: PASS") {
							t.Fatalf("actual-header contract: %v\n%s", err, out)
						}
					})
				}
			}
		})
	}
}

func TestOpaqueSourceModeExistingReaderControls(t *testing.T) {
	runOpaqueSourceModeContract(t, []string{
		"healthy-commit", "healthy-withdraw", "stale-release",
		"terminal-commit", "terminal-withdraw",
	})
}

func TestOpaqueSourceModePhysicalExecContract(t *testing.T) {
	if os.Getenv("IG_OPAQUE_SOURCE_MODE_PIN_CONTRACT") != "1" {
		t.Skip("set IG_OPAQUE_SOURCE_MODE_PIN_CONTRACT=1 for the known RED physical-source mode-pin contract")
	}
	// This is deliberately RED until the original source's mode protection
	// survives evaluator abort. A test-side counter would not repair the SUT.
	runOpaqueSourceModeContract(t, []string{"abort-commit", "abort-withdraw"})
}
