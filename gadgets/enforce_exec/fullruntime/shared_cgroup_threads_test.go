// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSharedCgroupThreads(t *testing.T) {
	dir := t.TempDir()
	pin, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if _, err := sharedCgroupThreads(pin); !errors.Is(err, errCgroupGone) {
		t.Fatalf("missing cgroup.threads: %v, want errCgroupGone", err)
	}
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "cgroup.threads"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("7\n9\n4242\n")
	if tids, err := sharedCgroupThreads(pin); err != nil || !reflect.DeepEqual(tids, []uint32{7, 9, 4242}) {
		t.Fatalf("tids %v %v", tids, err)
	}
	write("")
	if tids, err := sharedCgroupThreads(pin); err != nil || len(tids) != 0 {
		t.Fatalf("empty cgroup: %v %v", tids, err)
	}
	for _, bad := range []string{"0\n", "x\n", "-1\n", "4294967296\n"} {
		write(bad)
		if _, err := sharedCgroupThreads(pin); err == nil || errors.Is(err, errCgroupGone) {
			t.Fatalf("%q: %v, want a parse error", bad, err)
		}
	}
	if _, err := sharedCgroupThreads(nil); err == nil {
		t.Fatal("nil pin listed")
	}
}
