// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Native execution covers pure merge/publication semantics only; this is not
// BPF verifier, task-storage locking, bootstrap lineage or live-kernel proof.
func TestEpochRolesNative(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "epoch-roles")
	command := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "testdata/epoch_roles.c", "-o", binary)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("epoch roles: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

// TestEpochRolesBound (G025) checks the UID-history bound proved in
// testdata/epoch_roles_bound.c: pruning, the tight ER_CAPACITY edge and
// 4096-merge churn against an ACCEPTED_UIDS=8 catalogue, in the ABI2 layout
// and the ABI3 development layout the verdict candidate builds.
func TestEpochRolesBound(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct{ name, define string }{
		{"abi2", "-UENFORCE_EXEC_ABI3_DEVELOPMENT"},
		{"abi3", "-DENFORCE_EXEC_ABI3_DEVELOPMENT=1"},
	} {
		binary := filepath.Join(t.TempDir(), "epoch-roles-bound-"+variant.name)
		if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", variant.define, "-iquote", root, "testdata/epoch_roles_bound.c", "-o", binary).CombinedOutput(); err != nil {
			t.Fatalf("%s compile: %v\n%s", variant.name, err, out)
		}
		if out, err := exec.Command(binary).CombinedOutput(); err != nil {
			t.Fatalf("%s bound: %v\n%s", variant.name, err, out)
		} else {
			t.Logf("%s: %s", variant.name, out)
		}
	}
}

func TestEpochRolesDevelopmentKnowledge(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "development-roles")
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-DENFORCE_EXEC_ABI3_DEVELOPMENT=1", "-iquote", root, "testdata/epoch_roles_development.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("knowledge: %v\n%s", err, out)
	}
}
