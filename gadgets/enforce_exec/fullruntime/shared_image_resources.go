// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"maps"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

const (
	sharedTaskValueBytes       = 960
	sharedInvocationValueBytes = 19184
)

// This is the exact transitional reachable image, including its implicit .bss.
// Recognizing fixed-pool geometry is not kernel lifetime or qualification proof.
type sharedImageUsage struct {
	sharedResourceUsage
	PendingEnforcementQualification bool
}

func sharedImageGeometry(p SharedProfile) (map[string]operators.NativeMapResource, map[string]operators.NativeProgramResource) {
	return map[string]operators.NativeMapResource{
			"se_tasks":            {Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: sharedTaskValueBytes, MaxEntries: uint32(p.Tasks), Flags: unix.BPF_F_RDONLY},
			"se_zero_tasks":       {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: sharedTaskValueBytes, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
			"se_invocations":      {Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: sharedInvocationValueBytes, MaxEntries: uint32(p.Scratch), Flags: unix.BPF_F_RDONLY},
			"se_zero_invocations": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: sharedInvocationValueBytes, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
			"se_accepted_epochs":  {Type: uint32(ebpf.Hash), KeySize: 16, ValueSize: 8, MaxEntries: uint32(p.AcceptedUIDs), Flags: unix.BPF_F_RDONLY},
			"se_task_sequences":   {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 16, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
			"se_inode_facts":      {Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: 48, MaxEntries: uint32(p.InodeFacts), Flags: unix.BPF_F_RDONLY},
			"se_inode_accounts":   {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 48, MaxEntries: uint32(p.Bindings) + 1, Flags: unix.BPF_F_RDONLY},
			"image_origins":       {Type: uint32(ebpf.Hash), KeySize: 16, ValueSize: 1, MaxEntries: 65536, Flags: unix.BPF_F_NO_PREALLOC | unix.BPF_F_RDONLY_PROG},
			"image_ready":         {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 4, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
			"events":              {Type: uint32(ebpf.RingBuf), MaxEntries: 262144},
			"counters":            {Type: uint32(ebpf.PerCPUArray), KeySize: 4, ValueSize: 8, MaxEntries: 3},
			".bss":                {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 16, MaxEntries: 1},
		}, map[string]operators.NativeProgramResource{
			"se_command":               {Type: uint32(ebpf.Syscall)},
			"se_sched_exec":            {Type: uint32(ebpf.Tracing), Target: "sched_process_exec"},
			"se_bprm_exit":             {Type: uint32(ebpf.Tracing), Target: "bprm_execve"},
			"se_task_alloc":            {Type: uint32(ebpf.LSM), Target: "task_alloc"},
			"se_task_free":             {Type: uint32(ebpf.LSM), Target: "task_free"},
			"se_inode_free":            {Type: uint32(ebpf.LSM), Target: "inode_free_security"},
			"enforce_exec_full":        {Type: uint32(ebpf.LSM), Target: "bprm_check_security"},
			"enforce_exec_track_memfd": {Type: uint32(ebpf.LSM), Target: "inode_init_security_anon"},
		}
}

func validateSharedImageResources(p SharedProfile, r *operators.NativeResources) (sharedImageUsage, error) {
	var zero sharedImageUsage
	if _, err := p.Validate(); err != nil {
		return zero, err
	}
	if r == nil {
		return zero, fmt.Errorf("missing shared image manifest")
	}
	extra, programs := sharedImageGeometry(p)
	protocol := &operators.NativeResources{Maps: maps.Clone(r.Maps), Programs: map[string]operators.NativeProgramResource{"se_command": r.Programs["se_command"]}}
	for name, want := range extra {
		if got, ok := r.Maps[name]; !ok || got != want {
			return zero, fmt.Errorf("shared image map %s missing or incompatible", name)
		}
		delete(protocol.Maps, name)
	}
	base, err := validateSharedProtocolResources(p, protocol)
	if err != nil {
		return zero, err
	}
	if len(r.Programs) != len(programs) {
		return zero, fmt.Errorf("unexpected shared image program inventory")
	}
	if p.Images != 65536 || p.TelemetryBytes < 262144 {
		return zero, fmt.Errorf("transitional image/telemetry geometry exceeds declared profile")
	}
	usage := sharedImageUsage{sharedResourceUsage: base, PendingEnforcementQualification: true}
	usage.ProgramInstructions = 0
	for name, want := range programs {
		got, ok := r.Programs[name]
		if !ok || got.Type != want.Type || got.Target != want.Target || got.Instructions == 0 {
			return zero, fmt.Errorf("shared image program %s missing or incompatible", name)
		}
		usage.ProgramInstructions, err = checkedSharedResourceSum(usage.ProgramInstructions, got.Instructions)
		if err != nil {
			return zero, err
		}
	}
	for name, m := range extra {
		payload, err := checkedSharedProduct(uint64(m.ValueSize), uint64(m.MaxEntries))
		if err != nil {
			return zero, err
		}
		if name == "events" {
			payload = uint64(m.MaxEntries)
		}
		if name == "counters" {
			payload, err = checkedSharedProduct(payload, uint64(p.PossibleCPUs))
			if err != nil {
				return zero, err
			}
		}
		usage.MapPayloadBytes, err = checkedSharedResourceSum(usage.MapPayloadBytes, payload)
		if err != nil {
			return zero, err
		}
	}
	usage.ProgramBytes, err = checkedSharedProduct(usage.ProgramInstructions, 8)
	if err != nil {
		return zero, err
	}
	usage.LogicalBytes, err = checkedSharedResourceSum(usage.MapPayloadBytes, usage.AdminPayloadBytes, usage.ProgramBytes, usage.NativeAllowanceBytes)
	if err != nil {
		return zero, err
	}
	return usage, nil
}
