// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

// dropDisabledPrograms removes the disabled programs from the collection spec
// before it is loaded. A program is disabled when its attach target, after the
// programs.<name>.attach_to override, is gadget_program_disabled. Such a
// program is never attached, and now it is not loaded either, so the kernel
// does not verify it: a gadget can carry programs for a hook or a program type
// that some kernels lack and disable them there.
func (i *ebpfInstance) dropDisabledPrograms() {
	for name, p := range i.collectionSpec.Programs {
		attachTo := p.AttachTo
		if i.config != nil {
			if cfg := i.config.GetString("programs." + p.Name + ".attach_to"); cfg != "" {
				attachTo = cfg
			}
		}
		if attachTo == disabledProgram {
			i.logger.Debugf("Not loading program %q as it is disabled", name)
			delete(i.collectionSpec.Programs, name)
		}
	}
}
