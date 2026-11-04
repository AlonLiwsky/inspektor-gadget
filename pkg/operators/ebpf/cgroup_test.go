// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"
)

func fakeCgroupFS(t *testing.T, mountpoint string, mountErr error, ids map[string]uint64, v2 map[string]bool) {
	t.Helper()
	oldMount, oldID, oldV2 := cgroupV2Mountpoint, cgroupID, isCgroupV2
	t.Cleanup(func() { cgroupV2Mountpoint, cgroupID, isCgroupV2 = oldMount, oldID, oldV2 })
	cgroupV2Mountpoint = func() (string, error) { return mountpoint, mountErr }
	cgroupID = func(path string) (uint64, error) {
		if id, ok := ids[path]; ok {
			return id, nil
		}
		return 0, errors.New("no such cgroup")
	}
	isCgroupV2 = func(path string) bool { return v2[path] }
}

func TestCgroupAttachPathDefaultsToHostRoot(t *testing.T) {
	fakeCgroupFS(t, "/host/sys/fs/cgroup", nil, map[string]uint64{"/host/sys/fs/cgroup": cgroupV2RootID}, nil)
	if got, err := cgroupAttachPath(""); err != nil || got != "/host/sys/fs/cgroup" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestCgroupAttachPathRejectsNamespacedRoot(t *testing.T) {
	// In a private cgroup namespace the mount shows the caller's own cgroup.
	fakeCgroupFS(t, "/sys/fs/cgroup", nil, map[string]uint64{"/sys/fs/cgroup": 4242}, nil)
	if _, err := cgroupAttachPath(""); err == nil || !strings.Contains(err.Error(), "not the cgroup v2 root") {
		t.Fatalf("expected root check error, got %v", err)
	}
}

func TestCgroupAttachPathMountError(t *testing.T) {
	fakeCgroupFS(t, "", errors.New("no cgroup v2 mount found"), nil, nil)
	if _, err := cgroupAttachPath(""); err == nil || !strings.Contains(err.Error(), "no cgroup v2 mount") {
		t.Fatalf("expected mount error, got %v", err)
	}
}

func TestCgroupAttachPathOverride(t *testing.T) {
	fakeCgroupFS(t, "", errors.New("must not be consulted"), nil, map[string]bool{"/sys/fs/cgroup/test.slice": true, "relative": true})
	if got, err := cgroupAttachPath("/sys/fs/cgroup/test.slice"); err != nil || got != "/sys/fs/cgroup/test.slice" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"relative", "/tmp/not-a-cgroup"} {
		if _, err := cgroupAttachPath(bad); err == nil {
			t.Errorf("override %q accepted", bad)
		}
	}
}

func TestAttachCgroupSockAddrUsesCgroupPath(t *testing.T) {
	fakeCgroupFS(t, "", nil, nil, nil)
	gc := newResolverGadgetCtx(t, nil)
	config := viper.New()
	config.Set("programs.deny_connect.attach_to", "/tmp/not-a-cgroup")
	i := &ebpfInstance{config: config, logger: gc.Logger()}
	spec := &ebpf.ProgramSpec{Name: "deny_connect", Type: ebpf.CGroupSockAddr, AttachType: ebpf.AttachCGroupInet4Connect, SectionName: "cgroup/connect4"}
	link, err := i.attachProgram(gc, spec, nil)
	if link != nil || err == nil || !strings.Contains(err.Error(), "attaching cgroup program") {
		t.Fatalf("expected cgroup path error, got %v, %v", link, err)
	}
}
