// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// This checks compilation and emitted ABI only. It neither loads programs nor
// proves verifier acceptance, lineage coverage, publication safety or Ready.
func TestOwnerControlCompile(t *testing.T) {
	header := os.Getenv("IG_OWNER_CONTROL_VMLINUX")
	if header == "" {
		t.Skip("set IG_OWNER_CONTROL_VMLINUX to an exact generated vmlinux.h")
	}
	compiler, e := exec.LookPath("clang")
	require.NoError(t, e)
	temporary := t.TempDir()
	bytes, e := os.ReadFile(header)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(temporary, "vmlinux.h"), bytes, 0o600))
	source, e := filepath.Abs("bpf/owner_control_compile.bpf.c")
	require.NoError(t, e)
	object := filepath.Join(temporary, "owner-control.bpf.o")
	output, e := exec.Command(compiler, "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+temporary, "-c", source, "-o", object).CombinedOutput()
	require.NoError(t, e, string(output))
	spec, e := ebpf.LoadCollectionSpec(object)
	require.NoError(t, e)
	for _, name := range []string{"eo_command", "eo_migrate_enter", "eo_migrate_exit", "eo_reconfigure_enter", "eo_reconfigure_exit", "eo_movement_arm"} {
		require.NotNil(t, spec.Programs[name], name)
	}
	require.Equal(t, ebpf.Syscall, spec.Programs["eo_command"].Type)
	for name, size := range map[string]uint32{"eo_configuration": 32, "eo_commands": 32, "eo_health": 128, "eo_phase": 48, "eo_rows": 24, "eo_tasks": 680, "eo_work": 1096} {
		require.Equal(t, size, spec.Maps[name].ValueSize, name)
	}
	require.Equal(t, uint32(unix.BPF_F_RDONLY), spec.Maps["eo_phase"].Flags)
	require.Equal(t, uint32(unix.BPF_F_RDONLY), spec.Maps["eo_health"].Flags)
	require.Equal(t, uint32(unix.BPF_F_WRONLY), spec.Maps["eo_anchor"].Flags)
	require.Equal(t, ebpf.Hash, spec.Maps["eo_tasks"].Type)
	require.Equal(t, uint32(unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY), spec.Maps["eo_tasks"].Flags)
	require.Equal(t, uint32(8), spec.Maps["eo_task_ids"].ValueSize)
	require.Equal(t, uint32(0), spec.Maps["eo_programs"].Flags)
	require.Equal(t, ebpf.ArrayOfMaps, spec.Maps["eo_programs"].Type)
	require.Equal(t, uint32(unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG), spec.Maps["eo_programs"].InnerMap.Flags)
	for _, name := range []string{"eo_admin", "eo_task_ids", "eo_work"} {
		require.Equal(t, ebpf.TaskStorage, spec.Maps[name].Type)
		require.Equal(t, uint32(unix.BPF_F_NO_PREALLOC), spec.Maps[name].Flags)
	}
}
