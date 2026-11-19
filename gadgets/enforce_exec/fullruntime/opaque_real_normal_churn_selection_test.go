// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestOpaqueNormalChurnBirthSelection(t *testing.T) {
	const birth = "opaque_real_owner_successful_birth_candidate"
	const cleanup = "opaque_real_owner_birth_free_task_candidate"
	const signal = "opaque_real_owner_birth_signal0_diagnostic"
	fixture := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{
			Maps: map[string]*ebpf.MapSpec{
				"opaque_birth_receipts": {}, "opaque_birth_receipt_zero": {},
			},
			Programs: map[string]*ebpf.ProgramSpec{
				birth:   {Type: ebpf.RawTracepoint, SectionName: "raw_tp/sched_process_fork"},
				cleanup: {Type: ebpf.Kprobe, SectionName: "kprobe/free_task"},
				signal:  {Type: ebpf.LSM, SectionName: "lsm/task_kill"},
			},
		}
	}
	t.Run("select source and cleanup only", func(t *testing.T) {
		spec := fixture()
		selected := map[string]*ebpf.ProgramSpec{}
		if err := selectOpaqueNormalChurnBirthPrograms(spec, selected); err != nil {
			t.Fatal(err)
		}
		if len(selected) != 2 || selected[birth] != spec.Programs[birth] || selected[cleanup] != spec.Programs[cleanup] || selected[signal] != nil {
			t.Fatalf("wrong birth qualification program selection: %v", selected)
		}
	})
	for _, tc := range []struct {
		name   string
		mutate func(*ebpf.CollectionSpec, map[string]*ebpf.ProgramSpec)
	}{
		{"missing receipt map", func(s *ebpf.CollectionSpec, _ map[string]*ebpf.ProgramSpec) { delete(s.Maps, "opaque_birth_receipts") }},
		{"missing zero template", func(s *ebpf.CollectionSpec, _ map[string]*ebpf.ProgramSpec) {
			delete(s.Maps, "opaque_birth_receipt_zero")
		}},
		{"missing success source", func(s *ebpf.CollectionSpec, _ map[string]*ebpf.ProgramSpec) { delete(s.Programs, birth) }},
		{"missing cleanup source", func(s *ebpf.CollectionSpec, _ map[string]*ebpf.ProgramSpec) { delete(s.Programs, cleanup) }},
		{"wrong success type", func(s *ebpf.CollectionSpec, _ map[string]*ebpf.ProgramSpec) { s.Programs[birth].Type = ebpf.Tracing }},
		{"wrong success hook", func(s *ebpf.CollectionSpec, _ map[string]*ebpf.ProgramSpec) {
			s.Programs[birth].SectionName = "raw_tp/sched_process_exit"
		}},
		{"wrong cleanup type", func(s *ebpf.CollectionSpec, _ map[string]*ebpf.ProgramSpec) { s.Programs[cleanup].Type = ebpf.LSM }},
		{"wrong cleanup hook", func(s *ebpf.CollectionSpec, _ map[string]*ebpf.ProgramSpec) {
			s.Programs[cleanup].SectionName = "kprobe/exit_task"
		}},
		{"flagged success source", func(s *ebpf.CollectionSpec, _ map[string]*ebpf.ProgramSpec) { s.Programs[birth].Flags = 16 }},
		{"flagged cleanup source", func(s *ebpf.CollectionSpec, _ map[string]*ebpf.ProgramSpec) { s.Programs[cleanup].Flags = 16 }},
		{"synthetic qualifier loaded", func(s *ebpf.CollectionSpec, selected map[string]*ebpf.ProgramSpec) {
			selected[signal] = s.Programs[signal]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := fixture()
			selected := map[string]*ebpf.ProgramSpec{}
			tc.mutate(spec, selected)
			if err := selectOpaqueNormalChurnBirthPrograms(spec, selected); err == nil {
				t.Fatal("unsafe or incomplete birth qualification object accepted")
			}
		})
	}
}
