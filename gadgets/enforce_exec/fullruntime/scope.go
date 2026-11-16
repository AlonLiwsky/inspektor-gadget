// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func mountNamespaceIdentity(file *os.File) ([2]uint64, error) {
	if file == nil {
		return [2]uint64{}, fmt.Errorf("mount namespace pin required")
	}
	kind, err := unix.IoctlRetInt(int(file.Fd()), unix.NS_GET_NSTYPE)
	if err != nil {
		return [2]uint64{}, err
	}
	if kind != unix.CLONE_NEWNS {
		return [2]uint64{}, fmt.Errorf("not a mount namespace")
	}
	var stat unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &stat); err != nil {
		return [2]uint64{}, err
	}
	if stat.Ino == 0 || stat.Ino > uint64(^uint32(0)) {
		return [2]uint64{}, fmt.Errorf("unsupported mount namespace ID")
	}
	return [2]uint64{uint64(stat.Dev), stat.Ino}, nil
}

// Scope facts are file/kernel identities, never a cgroup-name heuristic or an
// inferred exemption. Host identity is supplied/authenticated by the trusted
// runtime lease; the native owner independently rejects equal host/workload NS.
func checkBindingScope(proc *os.File, lease BindingLease, cgroupID uint64) error {
	cg := lease.Cgroup()
	if cg == nil || proc == nil {
		return fmt.Errorf("cgroup and proc pins required")
	}
	fd := int(cg.Fd())
	var fs unix.Statfs_t
	var stat unix.Stat_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("scope is not cgroup v2")
	}
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Ino != cgroupID || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("cgroup identity changed")
	}
	parent, err := unix.Openat(fd, "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if err = unix.Fstatfs(parent, &fs); err != nil {
		return err
	}
	if err = unix.Fstat(parent, &stat); err != nil {
		return err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC || stat.Ino == cgroupID {
		return fmt.Errorf("root/delegated-root cgroup cannot be a strict binding")
	}
	mount, err := mountNamespaceIdentity(lease.MountNamespace())
	if err != nil {
		return err
	}
	host, err := mountNamespaceIdentity(lease.HostMountNamespace())
	if err != nil {
		return err
	}
	if mount == host {
		return fmt.Errorf("host mount namespace is unsupported; no inferred exemption")
	}
	current, err := unix.Openat(int(proc.Fd()), "ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(current), "current init mount namespace")
	defer file.Close()
	actual, err := mountNamespaceIdentity(file)
	if err != nil {
		return err
	}
	if actual != mount {
		return fmt.Errorf("init mount namespace changed")
	}
	return nil
}
