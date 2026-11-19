// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This is a process prerequisite, not a recovery/BPF authorization test. S
// must be a dedicated direct-parent waiter; a Go control goroutine cannot
// obtain these P_ALL and CLONE_PARENT ownership guarantees in-process.
func TestSharedRecoveryProcessTopology(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the recovery clone contract is currently amd64/Linux only")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "recovery-topology")
			build := exec.CommandContext(t.Context(), cc, "-std=gnu11", optimization,
				"-Wall", "-Wextra", "-Werror", "-iquote", "../full",
				"testdata/shared_recovery_process_topology.c", "-o", binary)
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("compile recovery topology: %v\n%s", err, output)
			}
			for _, mode := range []string{"normal", "guardian-death", "bad-fd"} {
				t.Run(mode, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
					defer cancel()
					output, err := exec.CommandContext(ctx, binary, mode).CombinedOutput()
					wantSignal := "proc_fd_signal=0"
					if mode == "bad-fd" {
						wantSignal = "proc_fd_signal=refused"
					}
					if err != nil || !strings.Contains(string(output), "topology PASS mode="+mode) ||
						!strings.Contains(string(output), "flags=0x8011") ||
						!strings.Contains(string(output), wantSignal) {
						t.Fatalf("recovery process topology: %v\n%s", err, output)
					}
				})
			}
		})
	}
}
