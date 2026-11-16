// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os/exec"
	"strings"
	"testing"
)

func TestOpaqueLifecycleFixtureCannotClaimRealControl(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-E", "-x", "c",
		"-DENFORCE_EXEC_POOL_OPAQUE_REAL_CONTROL_CANDIDATE=1",
		"-include", "bpf/opaque_locator_lifecycle_fixture.bpf.c", "/dev/null")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out),
		"synthetic lifecycle fixture cannot claim real control authority") {
		t.Fatalf("synthetic route seeding must not compile as real control: %v\n%s", err, out)
	}
}
