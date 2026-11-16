// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func TestRequireBPFLSM(t *testing.T) {
	for lsm, ok := range map[string]bool{
		"lockdown,capability,landlock,yama,safesetid,selinux,bpf\n": true,
		"bpf":                           true,
		"lockdown,capability,selinux\n": false,
		"bpfx,xbpf":                     false,
		"":                              false,
	} {
		if err := requireBPFLSM(lsm); (err == nil) != ok {
			t.Fatalf("%q: %v", lsm, err)
		}
	}
}

// EKS run 15: an unprivileged agent pod has no securityfs under its own
// /sys/kernel/security, so the LSM list is read under the host root first.
func TestReadKernelLSMHostRootFirstAndSecurityFSOnly(t *testing.T) {
	fake := t.TempDir()
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	require(os.MkdirAll(filepath.Join(fake, "sys/kernel/security"), 0o700))
	require(os.WriteFile(filepath.Join(fake, "sys/kernel/security/lsm"), []byte("capability,bpf\n"), 0o600))
	// A regular file is never trusted as the kernel's LSM list.
	if _, err := readKernelLSM([]string{fake}); err == nil || !strings.Contains(err.Error(), "not on securityfs") {
		t.Fatalf("non-securityfs LSM list accepted: %v", err)
	}
	// A host-side symlink resolves inside the host root, never outside it:
	// an absolute target naming the real securityfs stays under fake.
	var real unix.Statfs_t
	if unix.Statfs("/sys/kernel/security/lsm", &real) == nil && real.Type == unix.SECURITYFS_MAGIC {
		linked := t.TempDir()
		require(os.MkdirAll(filepath.Join(linked, "sys/kernel"), 0o700))
		require(os.Symlink("/sys/kernel/security", filepath.Join(linked, "sys/kernel/security")))
		if _, err := readKernelLSM([]string{linked}); err == nil {
			t.Fatal("host-root symlink escaped to the agent's own securityfs")
		}
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := readKernelLSM([]string{missing}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing host root: %v", err)
	}
	if _, err := readKernelLSM(nil); err == nil {
		t.Fatal("no roots accepted")
	}
	var fs unix.Statfs_t
	if unix.Statfs("/sys/kernel/security", &fs) != nil || fs.Type != unix.SECURITYFS_MAGIC {
		t.Skip("securityfs not mounted at /sys/kernel/security on this host")
	}
	want, err := os.ReadFile("/sys/kernel/security/lsm")
	require(err)
	// Host root without securityfs (the pod's own view), then a real one:
	// the first failure does not hide the working root, and a working host
	// root is used before any later root.
	got, err := readKernelLSM([]string{missing, "/"})
	require(err)
	if got != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
	got, err = readKernelLSM([]string{"/", fake})
	require(err)
	if got != string(want) {
		t.Fatalf("host root not preferred: %q", got)
	}
	// Duplicate roots are read once and fake trees still fail closed.
	if _, err = readKernelLSM([]string{fake, fake}); err == nil || strings.Count(err.Error(), "not on securityfs") != 1 {
		t.Fatalf("duplicate root: %v", err)
	}
}

func TestKernelLSMRootsUseHostRoot(t *testing.T) {
	roots := kernelLSMRoots()
	if len(roots) != 2 || roots[0] != host.HostRoot || roots[1] != "/" {
		t.Fatalf("roots %v", roots)
	}
}
