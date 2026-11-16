// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// This is the exact initial recovered-image inventory, before the later pool
// revision. It deliberately retains the old task/work maps while replacing
// se_admin with the six locked recovery records and two TEST_RUN endpoints.
func sharedRecoveryGeometry(p SharedProfile) (map[string]operators.NativeMapResource, map[string]operators.NativeProgramResource, error) {
	admission, err := p.Validate()
	if err != nil {
		return nil, nil, err
	}
	maps := sharedProtocolGeometry(p, admission)
	delete(maps, "se_admin")
	extra, programs := sharedImageGeometry(p)
	for name, shape := range extra {
		maps[name] = shape
	}
	array := func(valueSize uint32, flags uint32) operators.NativeMapResource {
		return operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: valueSize, MaxEntries: 1, Flags: flags}
	}
	maps["se_rm_configuration"] = array(32, unix.BPF_F_RDONLY_PROG)
	maps["se_rm_guardian_request"] = array(64, unix.BPF_F_RDONLY_PROG)
	maps["se_rm_admin_request"] = array(40, unix.BPF_F_RDONLY_PROG)
	maps["se_rm_control"] = array(192, unix.BPF_F_RDONLY)
	maps["se_rm_guardian_receipt"] = array(96, unix.BPF_F_RDONLY)
	maps["se_rm_admin_receipt"] = array(96, unix.BPF_F_RDONLY)
	programs["se_rm_guardian"] = operators.NativeProgramResource{Type: uint32(ebpf.SchedCLS)}
	programs["se_rm_administrator"] = operators.NativeProgramResource{Type: uint32(ebpf.SchedCLS)}
	return maps, programs, nil
}

// validateSharedRecoveryImageGeometry is source-only preflight. It does not
// authorize loading or Ready: IDs, referenced maps, BTF, resource budgets,
// pinned links and the native supervisor still require separate proof.
func validateSharedRecoveryImageGeometry(p SharedProfile, r *operators.NativeResources) error {
	wantMaps, wantPrograms, err := sharedRecoveryGeometry(p)
	if err != nil {
		return err
	}
	if r == nil || len(r.Maps) != len(wantMaps) || len(r.Programs) != len(wantPrograms) {
		return fmt.Errorf("recovered image inventory mismatch")
	}
	// G020: no legacy 65536-cell image_origins map pins Images any more.
	if p.TelemetryBytes < 262144 {
		return fmt.Errorf("recovered telemetry profile mismatch")
	}
	for name, want := range wantMaps {
		if got, ok := r.Maps[name]; !ok || got != want {
			return fmt.Errorf("recovered map %s missing or incompatible", name)
		}
	}
	for name, want := range wantPrograms {
		got, ok := r.Programs[name]
		if !ok || got.Type != want.Type || got.Target != want.Target || got.Instructions == 0 {
			return fmt.Errorf("recovered program %s missing or incompatible", name)
		}
	}
	return nil
}
