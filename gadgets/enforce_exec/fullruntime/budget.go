// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// These are capacity/payload ceilings, NOT measurements or guarantees of RSS,
// kernel allocator overhead, BTF memory or JIT expansion. Mandatory owner and
// instruction bounds also cap those allocations on the supported kernel matrix.
const (
	OwnerMapPayloadLimit  uint64 = 128 << 20
	OwnerInstructionLimit uint64 = 1 << 20
	OwnerHistoryLimit     uint64 = 2 * fullpolicy.MaxRoleEpochHistory // identity registry + successful UID catalogue
)

type (
	BudgetLimits struct{ Owners, MapPayloadBytes, ProgramInstructions, HistoryEntries uint64 }
	Budget       struct {
		mu           sync.Mutex
		limits, used BudgetLimits
		scopes       map[uint64]*budgetAllocation
	}
)

type budgetAllocation struct {
	owner *Budget
	scope uint64
	done  bool
}
type budgetReservation struct{ state *budgetAllocation }

// LegacyOwnerHardCap is the most legacy per-cgroup Owners one node may run
// (G009). Each Owner attaches its own 10 trampoline links, so the cap keeps
// their total far below the 38-link trampoline limit. There is no support
// claim beyond it. An embedding must share one Budget per node.
const LegacyOwnerHardCap = 2

// ErrLegacyOwnerCap is returned, fail-closed, when a Budget would exceed
// LegacyOwnerHardCap: by NewBudget for larger limits and by owner admission
// (NewOwner) for an owner beyond the cap. Nothing of the refused owner is
// reserved, loaded or attached.
var ErrLegacyOwnerCap = fmt.Errorf("legacy per-cgroup Owner hard cap of %d per node reached", LegacyOwnerHardCap)

func NewBudget(limits BudgetLimits) (*Budget, error) {
	if limits.Owners > LegacyOwnerHardCap {
		return nil, fmt.Errorf("budget for %d owners: %w", limits.Owners, ErrLegacyOwnerCap)
	}
	if limits.Owners == 0 || limits.MapPayloadBytes < OwnerMapPayloadLimit || limits.ProgramInstructions < OwnerInstructionLimit || limits.HistoryEntries < OwnerHistoryLimit {
		return nil, fmt.Errorf("budget must admit at least one fully bounded owner")
	}
	return &Budget{limits: limits, scopes: map[uint64]*budgetAllocation{}}, nil
}

func (b *Budget) reserve(scope uint64) (*budgetReservation, error) {
	if b == nil || scope == 0 {
		return nil, fmt.Errorf("shared aggregate owner budget and exact scope required")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.scopes[scope] != nil {
		return nil, fmt.Errorf("cgroup already has a persistent owner")
	}
	if b.used.Owners >= LegacyOwnerHardCap {
		return nil, ErrLegacyOwnerCap
	}
	if b.used.Owners >= b.limits.Owners || b.used.MapPayloadBytes > b.limits.MapPayloadBytes-OwnerMapPayloadLimit || b.used.ProgramInstructions > b.limits.ProgramInstructions-OwnerInstructionLimit || b.used.HistoryEntries > b.limits.HistoryEntries-OwnerHistoryLimit {
		return nil, fmt.Errorf("aggregate persistent-owner budget exhausted")
	}
	b.used.Owners++
	b.used.MapPayloadBytes += OwnerMapPayloadLimit
	b.used.ProgramInstructions += OwnerInstructionLimit
	b.used.HistoryEntries += OwnerHistoryLimit
	allocation := &budgetAllocation{owner: b, scope: scope}
	b.scopes[scope] = allocation
	return &budgetReservation{state: allocation}, nil
}

func (r *budgetReservation) release() {
	if r == nil || r.state == nil {
		return
	}
	a := r.state
	b := a.owner
	b.mu.Lock()
	defer b.mu.Unlock()
	if a.done || b.scopes[a.scope] != a {
		return
	}
	a.done = true
	delete(b.scopes, a.scope)
	b.used.Owners--
	b.used.MapPayloadBytes -= OwnerMapPayloadLimit
	b.used.ProgramInstructions -= OwnerInstructionLimit
	b.used.HistoryEntries -= OwnerHistoryLimit
}
func (b *Budget) Usage() BudgetLimits { b.mu.Lock(); defer b.mu.Unlock(); return b.used }

// Validate all maps, not just the ones a caller knows by name. Called during
// data-operator instantiation, BEFORE the eBPF operator allocates its collection.
// Local-storage physical credits are explicit; unknown unbounded storage refuses.
func validateOwnerResources(r *operators.NativeResources, cpus int) error {
	if r == nil || len(r.Maps) == 0 || len(r.Maps) > 64 || len(r.Programs) == 0 || len(r.Programs) > 64 || cpus < 1 || cpus > 4096 {
		return fmt.Errorf("unsupported native resource manifest")
	}
	// Account separately allocated inner templates, even when they also appear
	// as top-level maps. Nested map-of-maps templates are not supported.
	type namedMap struct {
		name     string
		resource operators.NativeMapResource
	}
	resources := make([]namedMap, 0, 2*len(r.Maps))
	for name, m := range r.Maps {
		resources = append(resources, namedMap{name, m})
		if m.InnerMap != nil {
			if ebpf.MapType(m.Type) != ebpf.ArrayOfMaps || m.InnerMap.InnerMap != nil {
				return fmt.Errorf("unsupported inner template for %s", name)
			}
			resources = append(resources, namedMap{name + "/inner", *m.InnerMap})
		} else if ebpf.MapType(m.Type) == ebpf.ArrayOfMaps {
			return fmt.Errorf("missing inner template for %s", name)
		}
	}
	payload := uint64(2 * fullpolicy.MaxKernelEntries * fullpolicy.KernelBlobSize) // both native frozen program slots
	for _, resource := range resources {
		name, m := resource.name, resource.resource
		entries := uint64(m.MaxEntries)
		switch ebpf.MapType(m.Type) {
		case ebpf.Hash, ebpf.Array, ebpf.LRUHash, ebpf.ArrayOfMaps:
			if entries == 0 {
				return fmt.Errorf("unbounded map %s", name)
			}
		case ebpf.PerCPUArray, ebpf.PerCPUHash:
			if entries == 0 || entries > OwnerMapPayloadLimit/uint64(cpus) {
				return fmt.Errorf("invalid per-CPU map %s", name)
			}
			entries *= uint64(cpus)
		case ebpf.RingBuf:
			if entries == 0 || entries > OwnerMapPayloadLimit-payload {
				return fmt.Errorf("ring budget exceeded")
			}
			payload += entries
			continue
		case ebpf.TaskStorage:
			switch name {
			case "eo_task_ids":
				entries = OwnerTaskLimit
			case "eo_work":
				entries = OwnerTaskLimit + 1
			case "eo_admin":
				entries = 1
			default:
				return fmt.Errorf("unknown task storage %s", name)
			}
		case ebpf.InodeStorage:
			if name != "fs_inode_origins" {
				return fmt.Errorf("unknown inode storage %s", name)
			}
			entries = 65536
		default:
			return fmt.Errorf("unsupported owner map type for %s", name)
		}
		size := uint64(m.KeySize) + uint64(m.ValueSize)
		if size == 0 || entries > (OwnerMapPayloadLimit-payload)/size {
			return fmt.Errorf("map payload budget exceeded by %s", name)
		}
		payload += entries * size
	}
	var instructions uint64
	for name, p := range r.Programs {
		if p.Instructions == 0 || p.Instructions > OwnerInstructionLimit-instructions {
			return fmt.Errorf("program instruction budget exceeded by %s", name)
		}
		instructions += p.Instructions
	}
	for name, requirement := range ownerHooks {
		p, ok := r.Programs[name]
		if !ok || p.Type != uint32(requirement.kind) || p.Target != requirement.target {
			return fmt.Errorf("missing/mismatched owner program %s", name)
		}
	}
	command, ok := r.Programs["eo_command"]
	if !ok || command.Type != uint32(ebpf.Syscall) || command.Target != "" {
		return fmt.Errorf("missing owner syscall command")
	}
	return nil
}

// admitOwnerResources checks the initial manifest and requires the same budget
// contract at the allocation boundary, after parameter and context rewrites.
func admitOwnerResources(gc operators.GadgetContext, r *operators.NativeResources, cpus int) error {
	if err := validateOwnerResources(r, cpus); err != nil {
		return err
	}
	gc.SetVar(operators.NativeResourceValidatorKey, func(final *operators.NativeResources) error {
		return validateOwnerResources(final, cpus)
	})
	return nil
}
