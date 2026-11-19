// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSharedRouteActualHeader(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "route")
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "testdata/shared_route.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("route: %v %s", err, out)
	}
}
