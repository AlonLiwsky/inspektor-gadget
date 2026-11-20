// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func selectedCases(selected string) ([]string, error) {
	cases := []string{"graceful", "sigkill", "partial-move", "abi-skew", "cgroup-exit", "selfexec", "thread-selfexec", "failed-selfexec", "uninstall", "load-failure", "nonce"}
	if selected == "" {
		return cases, nil
	}
	for _, name := range append(cases, "deep-cgroup") {
		if selected == name {
			return []string{selected}, nil
		}
	}
	return nil, fmt.Errorf("unknown FENCE_CASE %q", selected)
}

// This bounded fixture covers levels 64 and 65, not the much larger internal
// ancestry chunk width. Each independently managed root is a direct child of
// the host cgroup2 root, with no nested managed bindings.
func deepCgroupChain(root string, depth int) ([]string, error) {
	if filepath.Dir(root) != "/sys/fs/cgroup" || depth < 2 || depth > 65 {
		return nil, fmt.Errorf("unsupported deep fixture root/depth: %q/%d", root, depth)
	}
	chain := make([]string, 0, depth-1)
	path := root
	for level := 2; level <= depth; level++ {
		component := "d"
		if level == depth {
			component = "container"
		}
		path = filepath.Join(path, component)
		chain = append(chain, path)
	}
	return chain, nil
}

func checkRootCgroupMount(data string) error {
	matches := 0
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[4] != "/sys/fs/cgroup" {
			continue
		}
		parts := strings.SplitN(line, " - ", 2)
		if fields[3] != "/" || len(parts) != 2 || !strings.HasPrefix(parts[1], "cgroup2 ") {
			return fmt.Errorf("deep fixture requires root cgroup2 mount: %s", line)
		}
		matches++
	}
	if matches != 1 {
		return fmt.Errorf("expected one root cgroup2 mount, got %d", matches)
	}
	return nil
}

func checkDeepMembership(data, child string, depth int) error {
	relative, err := filepath.Rel("/sys/fs/cgroup", child)
	if err != nil || strings.HasPrefix(relative, "..") || len(strings.Split(relative, "/")) != depth {
		return fmt.Errorf("unexpected deep cgroup path %q at depth %d", child, depth)
	}
	if data != "0::/"+relative+"\n" {
		return fmt.Errorf("unexpected workload cgroup membership %q (want %q)", data, relative)
	}
	return nil
}

// Attest the actual probe PID membership and all directory identities, not just
// the planned path length. Failure is fatal, never a skipped qualification row.
func (f *fixture) attestDeepCgroups() error {
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	if err := checkRootCgroupMount(string(mounts)); err != nil {
		return err
	}
	for i := range f.pods {
		p := &f.pods[i]
		depth := []int{64, 65, 64, 65}[i]
		pid := p.probe.cmd.Process.Pid
		membership, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			return err
		}
		if err := checkDeepMembership(string(membership), p.child, depth); err != nil {
			return err
		}
		paths := append([]string{p.root}, p.ancestors...)
		paths = append(paths, p.child)
		ids := make([]uint64, 0, len(paths))
		seen := make(map[uint64]bool)
		for _, path := range paths {
			id, err := inode(path)
			if err != nil {
				return err
			}
			if id == 0 || seen[id] {
				return fmt.Errorf("invalid or repeated deep cgroup identity at %s", path)
			}
			seen[id] = true
			ids = append(ids, id)
		}
		if len(ids) != depth || ids[0] != p.id || ids[len(ids)-1] != p.childID {
			return fmt.Errorf("deep cgroup identity changed for %s", p.child)
		}
		if p.chainIDs == nil {
			p.chainIDs = slices.Clone(ids)
		} else if !slices.Equal(p.chainIDs, ids) {
			return fmt.Errorf("deep cgroup intermediate identity changed for %s", p.child)
		}
		if err := f.event("deep-cgroup-attestation", map[string]any{"pid": pid, "mode": p.mode, "depth": depth, "child": p.child, "chain_ids": ids}); err != nil {
			return err
		}
	}
	return nil
}

// Roll back only directories successfully created by this call, in reverse order.
// A refused/preexisting path is never included in cleanup.
func createDeepPaths(paths []string, mkdir, remove func(string) error) ([]string, error) {
	var created []string
	for _, path := range paths {
		if err := mkdir(path); err != nil {
			for i := len(created) - 1; i >= 0; i-- {
				err = errors.Join(err, remove(created[i]))
			}
			return nil, err
		}
		created = append(created, path)
	}
	return created, nil
}
