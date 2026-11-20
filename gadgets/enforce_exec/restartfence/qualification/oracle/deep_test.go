// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeepCgroupChainAndMembership(t *testing.T) {
	for _, depth := range []int{64, 65} {
		chain, err := deepCgroupChain("/sys/fs/cgroup/fixture", depth)
		if err != nil || len(chain) != depth-1 {
			t.Fatalf("depth %d: chain length %d, err %v", depth, len(chain), err)
		}
		child := chain[len(chain)-1]
		relative, _ := filepath.Rel("/sys/fs/cgroup", child)
		membership := "0::/" + relative + "\n"
		if err := checkDeepMembership(membership, child, depth); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"0::/\n", strings.TrimSuffix(membership, "\n"), membership + "1:cpu:/elsewhere\n"} {
			if checkDeepMembership(bad, child, depth) == nil {
				t.Fatalf("accepted mismatched membership %q", bad)
			}
		}
		if checkDeepMembership(membership, child, depth-1) == nil {
			t.Fatal("accepted wrong measured depth")
		}
	}
	for _, depth := range []int{0, 1, 66} {
		if _, err := deepCgroupChain("/sys/fs/cgroup/fixture", depth); err == nil {
			t.Fatalf("accepted depth %d", depth)
		}
	}
	if _, err := deepCgroupChain("/sys/fs/cgroup/nested/root", 64); err == nil {
		t.Fatal("accepted nested managed root")
	}
}

func TestDeepRequiresRootCgroupMount(t *testing.T) {
	valid := "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
	if err := checkRootCgroupMount(valid); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", valid + valid, strings.Replace(valid, "0:26 / ", "0:26 /nested ", 1), strings.Replace(valid, "cgroup2", "cgroup", 1)} {
		if checkRootCgroupMount(bad) == nil {
			t.Fatalf("accepted mount %q", bad)
		}
	}
}

func TestDeepScenarioSelection(t *testing.T) {
	cases, err := selectedCases("")
	if err != nil || len(cases) != 11 {
		t.Fatalf("historic cases changed: %v, %v", cases, err)
	}
	for _, name := range cases {
		if name == "deep-cgroup" {
			t.Fatal("deep case must be opt-in")
		}
	}
	cases, err = selectedCases("deep-cgroup")
	if err != nil || len(cases) != 1 || cases[0] != "deep-cgroup" {
		t.Fatalf("deep selection: %v, %v", cases, err)
	}
	if _, err := selectedCases("unknown"); err == nil {
		t.Fatal("unknown selection accepted")
	}
}

func TestDeepCreationRollbackOnlyCreatedPaths(t *testing.T) {
	paths := []string{"root", "root/a", "root/a/existing", "root/a/existing/child"}
	for failure := range paths {
		var created, removed []string
		_, err := createDeepPaths(paths, func(path string) error {
			if path == paths[failure] {
				return os.ErrExist
			}
			created = append(created, path)
			return nil
		}, func(path string) error {
			removed = append(removed, path)
			return nil
		})
		if !errors.Is(err, os.ErrExist) || len(removed) != len(created) {
			t.Fatalf("failure %d: created %v removed %v error %v", failure, created, removed, err)
		}
		for i, path := range removed {
			if path != created[len(created)-1-i] {
				t.Fatalf("wrong cleanup order: %v", removed)
			}
		}
	}
	var removed bool
	created, err := createDeepPaths(paths, func(string) error { return nil }, func(string) error { removed = true; return nil })
	if err != nil || removed || len(created) != len(paths) {
		t.Fatalf("success cleanup: %v %v %v", created, removed, err)
	}
}
