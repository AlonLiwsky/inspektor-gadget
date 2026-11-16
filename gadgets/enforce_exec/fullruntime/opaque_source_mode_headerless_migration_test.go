// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func runOpaqueSourceModeHeaderless(t *testing.T, scenario string) {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "headerless-source-mode")
			args := []string{
				"-std=gnu11", optimization, "-Wall", "-Wextra", "-Werror",
				"-iquote", "../full", "-iquote", "../fullpolicy/bpf",
				"testdata/opaque_source_mode_headerless_migration.c", "-o", binary,
			}
			if out, err := exec.CommandContext(t.Context(), cc, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile actual-route fixture: %v\n%s", err, out)
			}
			for _, mode := range []string{"audit", "strict"} {
				t.Run(mode, func(t *testing.T) {
					if out, err := exec.CommandContext(t.Context(), binary, scenario, mode).CombinedOutput(); err != nil {
						t.Fatalf("original-source class contract: %v\n%s", err, out)
					}
				})
			}
		})
	}
}

func TestOpaqueSourceModeHeaderlessSameScopeControl(t *testing.T) {
	runOpaqueSourceModeHeaderless(t, "headerless-same-scope")
}

func TestOpaqueSourceModeHeaderlessMigrationContract(t *testing.T) {
	if os.Getenv("IG_OPAQUE_SOURCE_MODE_HEADERLESS_CONTRACT") != "1" {
		t.Skip("set IG_OPAQUE_SOURCE_MODE_HEADERLESS_CONTRACT=1 for the known RED original-class recovery contract")
	}
	// Deliberately RED: a sticky original-route latch is a publication
	// barrier, not a way to identify a headerless migrated physical exec.
	// The replacement original-class authority is the source-only exec
	// capsule (TestOpaqueExecCapsuleContract, scenario headerless-migrated,
	// plus the exact-kernel test/al2023-exec-capsule fixture). It is not yet
	// wired into the verdict candidate, so the same-bprm compile prohibition
	// must remain until that integration is qualified.
	runOpaqueSourceModeHeaderless(t, "headerless-migrated")
}
