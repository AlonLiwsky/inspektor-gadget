// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package cgroups

import (
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func TestIsCgroupV2RejectsOtherFilesystems(t *testing.T) {
	for _, path := range []string{t.TempDir(), "/does/not/exist"} {
		if IsCgroupV2(path) {
			t.Errorf("IsCgroupV2(%q) = true", path)
		}
	}
}

func TestGetHostCgroupV2RootUsesHostRoot(t *testing.T) {
	old := host.HostRoot
	t.Cleanup(func() { host.HostRoot = old })
	host.HostRoot = t.TempDir()
	_, err := GetHostCgroupV2Root()
	if err == nil || !strings.Contains(err.Error(), host.HostRoot+"/sys/fs/cgroup") {
		t.Fatalf("expected an error for %q, got %v", host.HostRoot, err)
	}
}
