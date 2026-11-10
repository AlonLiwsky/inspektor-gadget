// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// dropDisabledPrograms removes the disabled programs from the collection spec
// before it is loaded. A program is disabled when programAttachTarget is
// gadget_program_disabled. Such a program is neither loaded nor attached, so
// the kernel does not verify it: a gadget can carry programs for a hook or a
// program type that some kernels lack and disable them there. A tail call
// target (a program that a PROG_ARRAY map lists in its contents) cannot be
// disabled: the map would refer to a program that is not loaded.
func (i *ebpfInstance) dropDisabledPrograms() error {
	dropped := map[string]bool{}
	for name, p := range i.collectionSpec.Programs {
		if i.programAttachTarget(p) == disabledProgram {
			i.logger.Debugf("Not loading program %q as it is disabled", name)
			delete(i.collectionSpec.Programs, name)
			dropped[name] = true
		}
	}
	for name, m := range i.collectionSpec.Maps {
		if m.Type != ebpf.ProgramArray {
			continue
		}
		for _, kv := range m.Contents {
			if prog, ok := kv.Value.(string); ok && dropped[prog] {
				return fmt.Errorf("program %q is disabled, but map %q lists it as a tail call target", prog, name)
			}
		}
	}
	return nil
}
