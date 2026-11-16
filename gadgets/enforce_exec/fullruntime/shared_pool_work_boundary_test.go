// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSharedPoolWorkCoreRejectsOpaqueTaskOwner(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-E", "-x", "c",
		"-DENFORCE_EXEC_POOL_DEVELOPMENT=1",
		"-DENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY=1",
		"-DENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE=1",
		"-include", "../full/shared_pool_work_core.h", "/dev/null")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out),
		"address-token WORK owner cannot be used with opaque TASK locator") {
		t.Fatalf("opaque/legacy WORK ABI mix must fail at preprocessing: %v\n%s", err, out)
	}
}

func TestSharedKernelRejectsOpaqueOwnerMix(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-E", "-x", "c",
		"-DENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE=1",
		"-include", "../full/shared_kernel.h", "/dev/null")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out),
		"legacy TASK/WORK maps cannot coexist with opaque owner") {
		t.Fatalf("opaque/legacy selected owner mix must fail at preprocessing: %v\n%s", err, out)
	}
}

func TestOpaqueRealControlRequiresCatalogueOrExplicitProbe(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-E", "-x", "c",
		"-DENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE=1",
		"-DENFORCE_EXEC_ABI3_DEVELOPMENT=1",
		"-DFULL_EPOCH_ROLES_H=1",
		"-DSE_PROFILE_BINDINGS=2", "-DSE_PROFILE_TASKS=128",
		"-DSE_PROFILE_TASK_QUOTA=64", "-DSE_PROFILE_SCRATCH=32",
		"-DSE_PROFILE_SCRATCH_QUOTA=16",
		"-include", "../full/shared_pool_opaque_real_control_candidate.h",
		"/dev/null")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out),
		"real-control opaque owner requires map-backed catalogue; the admission probe is not an enforcement image") {
		t.Fatalf("real-control image without catalogue must fail at preprocessing: %v\n%s", err, out)
	}
}
