// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/common/rootbarrier"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// The root barrier of the product object (gadgets/common/root_barrier.h,
// kubescape/inspektor-gadget#26): seven rb_* programs in the pinned attach
// set (sharedCandidateAttachSet) and the task_alloc body inline in the
// product's task_alloc source program. README, "Root barrier".
const (
	// sharedRootBarrierTaskAlloc carries the barrier's task_alloc body. Its
	// kernel name (15 characters) is not unique, so the attestation matches
	// it by program ID (rootbarrier.WithProgramID).
	sharedRootBarrierTaskAlloc = "opaque_real_owner_child_source_candidate"
)

// sharedRootBarrierPrograms are the barrier's own programs in the attach set:
// every rootbarrier.Hooks program except the task_alloc one (inline in the
// source program). Their hooks (chroot, pivot_root, userns_create, capable,
// sb_mount, move_mount, sb_umount) need not fire during a fork, exec and
// exit, so the attach canary does not wait for them (runSharedAttachCanary):
// the barrier self-test (verifySharedRootBarrier, before the canary on a
// product node) proves that each of them ran, by its denial of a real
// operation.
var sharedRootBarrierPrograms = func() map[string]bool {
	out := map[string]bool{}
	for _, h := range rootbarrier.Hooks {
		if h.LSM != "task_alloc" {
			out[h.Program] = true
		}
	}
	return out
}()

// sharedRootBarrierHooks is rootbarrier.Hooks with the task_alloc hook
// matched by the kernel ID of the source program that carries it.
func sharedRootBarrierHooks(receipts map[string]*operators.NativeAttachment) ([]rootbarrier.Hook, error) {
	receipt := receipts[sharedRootBarrierTaskAlloc]
	if receipt == nil || receipt.ProgramID == 0 {
		return nil, fmt.Errorf("root barrier: no attach receipt for %s", sharedRootBarrierTaskAlloc)
	}
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(receipt.ProgramID))
	if err != nil {
		return nil, fmt.Errorf("root barrier: program %s (ID %d): %w", sharedRootBarrierTaskAlloc, receipt.ProgramID, err)
	}
	defer prog.Close()
	return rootbarrier.WithProgramID(rootbarrier.Hooks, "task_alloc", prog)
}

// verifySharedRootBarrier is the barrier's start check of a product node.
// It runs in startLiveCandidate after the kernel gate admitted the build
// (admitSharedProductImage) and after every attach receipt passed its
// presence check (nativeattach.CheckPresent): rootbarrier.Verify attests
// that BPF LSM is active, ftrace is enabled, each hook signature matches and
// each barrier program has a live LSM link, then runs the self-test, which
// sees real operations denied. Any failure is node NotReady
// (ErrSharedNodeNotReady): the node never starts. After start, the link of
// each rb_* program is a pinned attach receipt, checked on every Ready like
// the others (sharedLiveHealth.checks).
func verifySharedRootBarrier(gc operators.GadgetContext, receipts map[string]*operators.NativeAttachment) error {
	hooks, err := sharedRootBarrierHooks(receipts)
	if err == nil {
		err = rootbarrier.Verify(gc, hooks)
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSharedNodeNotReady, err)
	}
	return nil
}

// sharedRootBarrierFaultRead reads the barrier's predicate faults: both
// cells of root_barrier_faults (Strict faults denied, Audit faults
// allowed), summed over CPUs and cells.
type sharedRootBarrierFaultRead func() (uint64, error)

// borrowSharedRootBarrierFaults reads root_barrier_faults through the map
// handle the eBPF operator published; the operator owns it.
func borrowSharedRootBarrierFaults(gc operators.GadgetContext) (sharedRootBarrierFaultRead, error) {
	value, _ := gc.GetVar(operators.MapPrefix + rootbarrier.FaultsMap)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		return nil, fmt.Errorf("shared candidate map %s was not published", rootbarrier.FaultsMap)
	}
	return func() (uint64, error) {
		faults, err := rootbarrier.Faults(m)
		if err != nil {
			return 0, err
		}
		var total uint64
		for _, n := range faults {
			if total+n < total {
				return 0, fmt.Errorf("%s overflows", rootbarrier.FaultsMap)
			}
			total += n
		}
		return total, nil
	}, nil
}
