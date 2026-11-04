// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (i *ebpfInstance) programAttachTarget(spec *ebpf.ProgramSpec) string {
	if i.config != nil {
		if target := i.config.GetString("programs." + spec.Name + ".attach_to"); target != "" {
			// LSM and tracing targets are bound from the spec at load time;
			// attach only receives the loaded program, not a target override.
			// Disabling still applies to all program types before attachment.
			if target == disabledProgram || (spec.Type != ebpf.LSM && spec.Type != ebpf.Tracing) {
				return target
			}
		}
	}
	return spec.AttachTo
}

// dropDisabledPrograms removes the disabled programs from the spec before the
// collection is loaded. A disabled program is neither loaded nor attached, so
// the kernel never verifies it: a gadget can carry programs for a program type
// or a hook that the kernel lacks (for example LSM programs on a kernel without
// CONFIG_BPF_LSM) and disable them there.
func (i *ebpfInstance) dropDisabledPrograms() {
	for name, spec := range i.collectionSpec.Programs {
		if i.programAttachTarget(spec) == disabledProgram {
			i.logger.Debugf("Not loading program %q as it is disabled", name)
			delete(i.collectionSpec.Programs, name)
		}
	}
}

// Only enabled syscall commands are exposed. The owning collection retains every FD;
// callers borrow handles and must join command invocations before teardown.
func (i *ebpfInstance) publishCommandPrograms(gc operators.GadgetContext) {
	for name, spec := range i.collectionSpec.Programs {
		if spec.Type == ebpf.Syscall && i.programAttachTarget(spec) != disabledProgram {
			gc.SetVar(operators.ProgramPrefix+name, i.collection.Programs[name])
		}
	}
}

func (i *ebpfInstance) unpublishCommandPrograms(gc operators.GadgetContext) {
	for name, program := range i.collection.Programs {
		key := operators.ProgramPrefix + name
		if current, ok := gc.GetVar(key); ok && current == program {
			gc.SetVar(key, nil)
		}
	}
}
