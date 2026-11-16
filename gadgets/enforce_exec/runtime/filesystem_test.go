// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

func fsConfig(t *testing.T) Config {
	c := fullConfig(t)
	p, err := fullpolicy.CompileKernel([]fullpolicy.Policy{{ID: "p", Revision: "r", Mode: fullpolicy.Enforce, Default: fullpolicy.Allow, Rules: []fullpolicy.Rule{{Name: "memfd", Action: fullpolicy.Deny, Target: fullpolicy.Target{FSType: []string{"memfd"}}}}}}, 7, "worker")
	require.NoError(t, err)
	c.Full = p
	return c
}

func TestFilesystemTrackerBeforeAnyBinding(t *testing.T) {
	for _, probeErr := range []error{nil, errors.New("tracker absent")} {
		b := newFullBindings(t, fsConfig(t))
		p, m, f, _ := fullMaps()
		faults := fullFaultMap()
		require.NoError(t, b.startMaps(p, m, f, faults, fakeImageMaps()))
		require.Empty(t, m.values)
		require.NoError(t, b.Bind(identity(2)))
		require.NoError(t, b.Bind(identity(3)))
		require.NoError(t, b.Unbind(identity(3)))
		require.Empty(t, m.values, "late startup binding cannot bypass tracker probe")
		b.fsProbe = func() error { require.Empty(t, m.values); return probeErr }
		b.fsHealth = func() error { return nil }
		err := b.Ready(nil)
		if probeErr != nil {
			require.Error(t, err)
			require.Empty(t, m.values)
			require.False(t, b.Status().Ready)
		} else {
			require.NoError(t, err)
			require.Len(t, m.values, 2)
			require.True(t, b.Status().Ready)
			faults.values[uint32(0)] = uint64(4)
			require.False(t, b.Status().Ready)
			require.Error(t, b.Status().Error)
			require.Len(t, m.values, 2, "unknown fs fact retains existing enforcement")
			require.Error(t, b.Bind(identity(4)))
			require.Len(t, m.values, 2, "faulted tracker cannot add new bindings")
		}
		require.NoError(t, b.Stop(nil))
	}
}

func TestFilesystemProbeMissingAndBudgetFault(t *testing.T) {
	b := newFullBindings(t, fsConfig(t))
	p, m, f, _ := fullMaps()
	require.NoError(t, b.startMaps(p, m, f, fullFaultMap(), fakeImageMaps()))
	require.ErrorContains(t, b.Ready(nil), "probe")
	require.Empty(t, m.values)
	b = newFullBindings(t, fsConfig(t))
	p, m, f, _ = fullMaps()
	b.fsProbe = func() error { return nil }
	b.fsHealth = func() error { return errors.New("tracker budget exhausted") }
	require.Error(t, b.startMaps(p, m, f, fullFaultMap(), fakeImageMaps()))
	require.Empty(t, m.values)
}

// Actual candidate-specific tracker lifecycle: a declared/map-present but
// unattached tracker must not publish any binding; an attached one must prove
// new inode classification before final Ready. Disposable guest only.
func TestFilesystemTrackerKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_FS_RUNTIME_KERNEL_TEST") != "1" {
		t.Skip("requires disposable kernel opt-in")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	tmp := t.TempDir()
	header, err := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "vmlinux.h"), header, 0o600))
	source := os.Getenv("IG_EXEC_FS_BPF_SOURCE")
	if source == "" {
		source = "../full/test/kernel/bpf/filesystem.bpf.c"
	}
	object := filepath.Join(tmp, "fs.o")
	out, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object).CombinedOutput()
	require.NoError(t, err, "%s", out)
	spec, err := ebpf.LoadCollectionSpec(object)
	require.NoError(t, err)
	collection, err := ebpf.NewCollection(spec)
	require.NoError(t, err)
	defer collection.Close()
	candidate := func() (*Bindings, *fakeImmutableMap) {
		b := newFullBindings(t, fsConfig(t))
		require.NoError(t, b.configureFilesystem(collection.Maps["fs_inode_origins"], collection.Maps["fs_diagnostics"]))
		p, m, f, _ := fullMaps()
		require.NoError(t, b.startMaps(p, m, f, fullFaultMap(), fakeImageMaps()))
		require.Empty(t, m.values)
		return b, m
	}
	b, m := candidate()
	require.ErrorContains(t, b.Ready(nil), "not observing")
	require.Empty(t, m.values)
	require.NoError(t, b.Stop(nil))
	attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["fs_track"]})
	require.NoError(t, err)
	b, m = candidate()
	require.NoError(t, b.Ready(nil))
	require.Len(t, m.values, 1)
	require.True(t, b.Status().Ready)
	require.NoError(t, b.Stop(nil))
	require.NoError(t, attached.Close())
	b, m = candidate()
	require.Error(t, b.Ready(nil))
	require.Empty(t, m.values)
	require.NoError(t, b.Stop(nil))
	t.Log("unattached/detached candidate refused before binding; own attached inode tracker proven before Ready")
}
