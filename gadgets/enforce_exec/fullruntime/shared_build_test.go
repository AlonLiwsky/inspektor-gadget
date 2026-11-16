// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Build-context/negative archive admission only, no compiler or kernel load.
func TestSharedBuildSelection(t *testing.T) {
	root, err := filepath.Abs("../full/owner")
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{"build-selector-test.sh", "shared-build-selector-test.sh"} {
		if out, err := exec.Command("bash", filepath.Join(root, script)).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
	}
}
