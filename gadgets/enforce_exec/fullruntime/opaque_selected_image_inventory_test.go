// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Opt-in migration acceptance test for an emitted, not-yet-admitted image.
// A diagnostic opaque child fixture must fail this test: having the bounded
// owner maps is insufficient without the complete selected callback chain.
// This is ELF inventory only, never verifier, attachment or Ready proof.
func TestSelectedOpaqueImageInventory(t *testing.T) {
	path := os.Getenv("IG_SELECTED_OPAQUE_IMAGE_OBJECT")
	if path == "" {
		t.Skip("set IG_SELECTED_OPAQUE_IMAGE_OBJECT to the opt-in selected image")
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("emitted candidate inventory: maps=%d programs=%d", len(spec.Maps), len(spec.Programs))
	p := sharedTestProfile()
	p.Tasks, p.PerBinding.Tasks = 128, 64
	p.Scratch, p.PerBinding.Scratch = 16, 8
	r := &operators.NativeResources{
		Maps:     make(map[string]operators.NativeMapResource, len(spec.Maps)),
		Programs: make(map[string]operators.NativeProgramResource, len(spec.Programs)),
	}
	for name, m := range spec.Maps {
		if m.InnerMap != nil {
			t.Fatalf("unreviewed nested map %s", name)
		}
		r.Maps[name] = operators.NativeMapResource{
			Type: uint32(m.Type), KeySize: m.KeySize, ValueSize: m.ValueSize,
			MaxEntries: m.MaxEntries, Flags: m.Flags,
		}
	}
	for name, program := range spec.Programs {
		r.Programs[name] = operators.NativeProgramResource{
			Type: uint32(program.Type), Target: program.AttachTo,
			Instructions: program.Instructions.Size() / 8,
		}
	}
	if _, err := validateSharedOpaqueOwnerResources(p, r); err != nil {
		t.Fatalf("selected image lacks one exact opaque TASK/WORK owner: %v", err)
	}
	for _, name := range []string{
		"se_tasks", "se_zero_tasks", "se_task_sequences",
		"se_invocations", "se_zero_invocations", "se_pool_task_meta",
		"se_pool_work_meta", "opaque_real_live_bootstrap_gate",
	} {
		if spec.Maps[name] != nil {
			t.Fatalf("selected image retains legacy/diagnostic map %s", name)
		}
	}
	for name, want := range map[string]struct {
		kind   ebpf.ProgramType
		target string
	}{
		"enforce_exec_full":        {ebpf.LSM, "bprm_check_security"},
		"enforce_exec_track_memfd": {ebpf.LSM, "inode_init_security_anon"},
		"se_task_alloc":            {ebpf.LSM, "task_alloc"},
		"se_task_free":             {ebpf.LSM, "task_free"},
		"se_sched_exec":            {ebpf.Tracing, "sched_process_exec"},
		"se_bprm_exit":             {ebpf.Tracing, "bprm_execve"},
		"se_publication_arm":       {ebpf.Tracing, "cgroup_kn_lock_live"},
		"se_pool_reaper_entry":     {ebpf.SchedCLS, ""},
		"se_pool_reaper_chunk":     {ebpf.SchedCLS, ""},
	} {
		got := spec.Programs[name]
		if got == nil || got.Type != want.kind || got.AttachTo != want.target {
			t.Fatalf("selected image missing/incompatible %s: %+v", name, got)
		}
	}
	for _, name := range []string{"se_command", "se_rm_guardian", "se_rm_administrator"} {
		if spec.Programs[name] == nil {
			t.Fatalf("selected image missing recovered native control %s", name)
		}
	}
	for _, name := range []string{"opaque_real_live_bootstrap_birth", "opaque_real_live_bootstrap_qualify"} {
		if spec.Programs[name] != nil {
			t.Fatalf("test-only bootstrap program %s in selected image", name)
		}
	}
	t.Logf("selected opaque inventory shape: %d maps, %d programs; kernel and host admission still required",
		len(spec.Maps), len(spec.Programs))
}
