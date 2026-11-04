// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"fmt"
	"path/filepath"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
)

// cgroupV2RootID is the cgroup ID of the cgroup-v2 root.
const cgroupV2RootID = 1

// Replaced in tests.
var (
	cgroupV2Mountpoint = cgroups.GetHostCgroupV2Mountpoint
	cgroupID           = cgroups.GetCgroupID
	isCgroupV2         = cgroups.IsCgroupV2
)

// cgroupAttachPath returns the cgroup that a cgroup program attaches to.
// Without an attach_to override it is the host's cgroup-v2 root. A cgroup
// namespace makes /sys/fs/cgroup show the caller's own cgroup, which would
// silently scope the program to it, so the root's ID is checked.
func cgroupAttachPath(attachTo string) (string, error) {
	if attachTo != "" {
		if !filepath.IsAbs(attachTo) || !isCgroupV2(attachTo) {
			return "", fmt.Errorf("attach_to %q is not an absolute cgroup v2 path", attachTo)
		}
		return attachTo, nil
	}
	path, err := cgroupV2Mountpoint()
	if err != nil {
		return "", err
	}
	id, err := cgroupID(path)
	if err != nil {
		return "", err
	}
	if id != cgroupV2RootID {
		return "", fmt.Errorf("%q is not the cgroup v2 root (cgroup id %d): set HOST_ROOT to the host filesystem or set attach_to", path, id)
	}
	return path, nil
}
