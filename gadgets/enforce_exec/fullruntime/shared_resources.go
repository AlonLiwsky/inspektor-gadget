// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"math"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedResourceUsage accounts logical payload and declared native allowances,
// not allocator/JIT overhead, physical RSS, kernel admission or protection Ready.
// AdminPayloadBytes covers ONE owned task-storage value, not a preallocated map;
// the startup adapter must enforce that lifetime/cardinality separately.
type sharedResourceUsage struct {
	MapPayloadBytes, AdminPayloadBytes, NativeAllowanceBytes uint64
	ProgramInstructions, ProgramBytes, LogicalBytes          uint64
}

const sharedProtocolRodataMaxBytes uint32 = 4096

// One pending admin request per NODE, not per binding or compile worker. This
// includes Go struct padding and its retained pointer (1136 bytes on admitted
// amd64), but not allocator overhead or any claim of physical RSS bounds.
const sharedPendingCommandNativeBytes = uint64(unsafe.Sizeof(sharedPendingCommand{})) + uint64(unsafe.Sizeof((*sharedPendingCommand)(nil)))

// The admitted amd64 compiler snapshot retains an 80-byte immutable execution
// summary and one 8-byte pointer. Reserve both records per binding before any
// coordinator can retain them; layout parity is locked by an independent test.
const sharedSnapshotMetadataNativeBytes uint64 = 88

func checkedSharedResourceSum(values ...uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return 0, fmt.Errorf("shared resource sum overflow")
		}
		total += value
	}
	return total, nil
}

// Account the fixed protocol ownership records, binding-slot pointer table and
// the bounded shutdown cancellation snapshot. Runtime/allocator overhead is
// separate from these logical fields and the declared RolloutBytes allowance.
func sharedProtocolOwnershipBytes(bindings uint64) (uint64, error) {
	perScope := uint64(unsafe.Sizeof(sharedScopeCommandState{})) + uint64(unsafe.Sizeof((*sharedPhysicalScope)(nil)))
	scopes, err := checkedSharedProduct(bindings, perScope)
	if err != nil {
		return 0, err
	}
	operations, err := checkedSharedResourceSum(bindings, 1)
	if err != nil {
		return 0, err
	}
	joining, err := checkedSharedProduct(operations, uint64(unsafe.Sizeof(sharedStartupOperation{})))
	if err != nil {
		return 0, err
	}
	return checkedSharedResourceSum(uint64(unsafe.Sizeof(sharedProtocolHostOwnership{})), scopes, joining)
}

// sharedProtocolGeometry is the common physical base for the protocol-only
// and recovered-image manifests. The recovered image removes se_admin and
// adds its own recovery maps; neither path may infer a map from a name prefix.
func sharedProtocolGeometry(profile SharedProfile, admission SharedAdmission) map[string]operators.NativeMapResource {
	return map[string]operators.NativeMapResource{
		"se_configuration": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 56, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
		"se_admin":         {Type: uint32(ebpf.TaskStorage), KeySize: 4, ValueSize: 8, Flags: unix.BPF_F_NO_PREALLOC},
		"se_commands":      {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 1112, MaxEntries: 1, Flags: unix.BPF_F_WRONLY},
		"se_receipts":      {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 48, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
		"se_objects":       {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 80, MaxEntries: uint32(admission.PolicyObjects), Flags: unix.BPF_F_RDONLY},
		"se_bindings":      {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 1632, MaxEntries: uint32(profile.Bindings), Flags: unix.BPF_F_RDONLY},
		"se_routes":        {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 88, MaxEntries: uint32(profile.Bindings), Flags: unix.BPF_F_RDONLY},
		"se_route_index":   {Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: 8, MaxEntries: uint32(profile.Bindings), Flags: unix.BPF_F_RDONLY},
		"se_arena":         {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 288, MaxEntries: uint32(admission.ArenaCells), Flags: unix.BPF_F_RDONLY},
	}
}

// validateSharedProtocolResources validates the current protocol-only manifest
// before allocation. It NEVER resizes or rewrites image resources. An image with
// legacy eo_* banks/hooks or future unaccounted canonical maps is rejected: the
// final shared runtime must explicitly extend this inventory and accounting.
// This is not a complete enforcement-image or attachment validator.
func validateSharedProtocolResources(profile SharedProfile, resources *operators.NativeResources) (sharedResourceUsage, error) {
	admission, err := profile.Validate()
	if err != nil {
		return sharedResourceUsage{}, err
	}
	if resources == nil {
		return sharedResourceUsage{}, fmt.Errorf("shared native resource manifest required")
	}
	expected := sharedProtocolGeometry(profile, admission)
	for name, want := range expected {
		if got, ok := resources.Maps[name]; !ok || got != want {
			return sharedResourceUsage{}, fmt.Errorf("shared map %s missing or incompatible", name)
		}
	}
	var usage sharedResourceUsage
	for name, resource := range resources.Maps {
		if _, ok := expected[name]; !ok {
			if name != ".rodata" || resource.Type != uint32(ebpf.Array) || resource.KeySize != 4 || resource.ValueSize == 0 || resource.ValueSize > sharedProtocolRodataMaxBytes || resource.MaxEntries != 1 || resource.Flags != unix.BPF_F_RDONLY_PROG || resource.InnerMap != nil {
				return sharedResourceUsage{}, fmt.Errorf("unaccounted or incompatible shared map %s", name)
			}
		}
		if name == "se_admin" {
			usage.AdminPayloadBytes = uint64(resource.ValueSize)
			continue
		}
		payload, err := checkedSharedProduct(uint64(resource.ValueSize), uint64(resource.MaxEntries))
		if err != nil {
			return sharedResourceUsage{}, err
		}
		usage.MapPayloadBytes, err = checkedSharedResourceSum(usage.MapPayloadBytes, payload)
		if err != nil {
			return sharedResourceUsage{}, err
		}
	}
	command, ok := resources.Programs["se_command"]
	if !ok || len(resources.Programs) != 1 || command.Type != uint32(ebpf.Syscall) || command.Target != "" || command.Instructions == 0 {
		return sharedResourceUsage{}, fmt.Errorf("shared protocol requires only the se_command syscall program")
	}
	usage.ProgramInstructions = command.Instructions
	usage.ProgramBytes, err = checkedSharedProduct(command.Instructions, 8)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	compileBytes, err := checkedSharedProduct(profile.CompileBytes, profile.CompileConcurrency)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	snapshotMetadataBytes, err := checkedSharedProduct(admission.Snapshots, sharedSnapshotMetadataNativeBytes)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	protocolOwnershipBytes, err := sharedProtocolOwnershipBytes(profile.Bindings)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	objectRegistryBytes, err := sharedObjectRegistryBytes(profile)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	usage.NativeAllowanceBytes, err = checkedSharedResourceSum(objectRegistryBytes, compileBytes, profile.CandidateBytes, profile.TelemetryBytes, profile.RolloutBytes, sharedPendingCommandNativeBytes, snapshotMetadataBytes, protocolOwnershipBytes)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	usage.LogicalBytes, err = checkedSharedResourceSum(usage.MapPayloadBytes, usage.AdminPayloadBytes, usage.ProgramBytes, usage.NativeAllowanceBytes)
	if err != nil {
		return sharedResourceUsage{}, err
	}
	return usage, nil
}
