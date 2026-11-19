// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Actual-header state transitions only: no authenticated command dispatch,
// collection, verifier, locking/interleaving or physical-memory claim.
func TestSharedArenaActualHeader(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("C compiler required", err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "shared-arena")
	cmd := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "testdata/shared_arena.c", "-o", binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("arena: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func TestSharedSnapshotActualCommand(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "shared-snapshot")
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "testdata/shared_snapshot.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("snapshot: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func TestSharedPublicationActualHelpers(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "shared-publication")
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "testdata/shared_publication.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("publication: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func TestSharedControlActualEntry(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "shared-control")
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "testdata/shared_control.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("control: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
