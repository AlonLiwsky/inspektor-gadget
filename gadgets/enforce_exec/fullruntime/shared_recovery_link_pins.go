// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedRecoveryLinkPins is an H-owned, pre-enrollment partial ledger. An
// attempted pin remains recorded even if the syscall or reopen failed: that
// outcome is ambiguous and must be reconciled from the exact bpffs path.
// This does not own normal unlink or prove host-visible mount persistence.
type sharedRecoveryLinkPins struct {
	dirFD    int
	attempts []string
	links    map[string]operators.NativePinnedLink
	fault    error
}

var sharedRecoveryTaskLinks = [...]struct{ program, target string }{
	{"se_task_alloc", "task_alloc"},
	{"se_task_free", "task_free"},
}

func newSharedRecoveryLinkPins(gc operators.GadgetContext, profile SharedProfile, dirFD int) (*sharedRecoveryLinkPins, error) {
	if gc == nil || dirFD < 0 {
		return nil, fmt.Errorf("missing recovery pin context or directory")
	}
	if selected, _ := gc.GetVar(operators.NativeRecoveryTestRunKey); selected != true {
		return nil, fmt.Errorf("recovery link pinning requires trusted selection")
	}
	value, _ := gc.GetVar(operators.NativeResourcesKey)
	manifest, _ := value.(*operators.NativeResources)
	if err := validateSharedRecoveryImageGeometry(profile, manifest); err != nil {
		return nil, err
	}
	// Validate both receipts before any pin operation. A missing hook cannot
	// leave the first hook pinned by this constructor.
	var receipts [len(sharedRecoveryTaskLinks)]*operators.NativeAttachment
	for idx, entry := range sharedRecoveryTaskLinks {
		value, _ := gc.GetVar(operators.NativeAttachmentPrefix + entry.program)
		receipt, _ := value.(*operators.NativeAttachment)
		if receipt == nil || receipt.Type != uint32(ebpf.LSM) ||
			receipt.Target != entry.target || receipt.LinkID == 0 ||
			receipt.ProgramID == 0 || receipt.Check == nil || receipt.PinAt == nil {
			return nil, fmt.Errorf("recovery hook %s lacks exact pin capability", entry.program)
		}
		if err := receipt.Check(); err != nil {
			return nil, fmt.Errorf("recovery hook %s changed before pin: %w", entry.program, err)
		}
		receipts[idx] = receipt
	}
	if receipts[0].LinkID == receipts[1].LinkID ||
		receipts[0].ProgramID == receipts[1].ProgramID {
		return nil, fmt.Errorf("recovery task hooks alias an identity")
	}
	ownedFD, err := unix.FcntlInt(uintptr(dirFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ledger := &sharedRecoveryLinkPins{
		dirFD: ownedFD,
		links: make(map[string]operators.NativePinnedLink, len(receipts)),
	}
	for idx, entry := range sharedRecoveryTaskLinks {
		ledger.attempts = append(ledger.attempts, entry.program)
		lease, err := receipts[idx].PinAt(ownedFD)
		if lease != nil {
			ledger.links[entry.program] = lease
		}
		if err != nil {
			ledger.fault = fmt.Errorf("pin recovery hook %s (retain ledger): %w", entry.program, err)
			return ledger, ledger.fault
		}
		if lease == nil || lease.PinName() != entry.program+".link" ||
			lease.FD() < 0 || lease.Check() != nil {
			ledger.fault = fmt.Errorf("recovery hook %s pinned lease mismatch (retain ledger)", entry.program)
			return ledger, ledger.fault
		}
	}
	return ledger, nil
}

// Closing relinquishes H's reopened FDs and directory FD only. It never
// unlinks a pin; S must first have accepted its own FD/path ledger or the
// operator must retain this H ledger and classify an inconclusive outcome.
func (p *sharedRecoveryLinkPins) closeFDs() error {
	if p == nil || p.dirFD < 0 {
		return fmt.Errorf("recovery link pin ledger already closed")
	}
	var result error
	for _, link := range p.links {
		result = errors.Join(result, link.Close())
	}
	p.links = nil
	result = errors.Join(result, unix.Close(p.dirFD))
	p.dirFD = -1
	return result
}
