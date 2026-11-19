// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Only the recovered native owner may load these exact TC programs without
// attaching them. Their BPF section is deliberately "tc" rather than a
// classifier/ingress or classifier/egress attachment section.
func (i *ebpfInstance) nativeRecoveryTestRunProgram(gc operators.GadgetContext, spec *ebpf.ProgramSpec) (bool, error) {
	poolReaper := spec.Name == "se_pool_reaper_entry" || spec.Name == "se_pool_reaper_chunk"
	if i.recoveryTestRunFault {
		return false, fmt.Errorf("recovery TEST_RUN selection fault")
	}
	value, _ := gc.GetVar(operators.NativeRecoveryTestRunKey)
	enabled, valid := value.(bool)
	if value != nil && !valid {
		i.recoveryTestRunFault = true
		return false, fmt.Errorf("invalid recovery TEST_RUN selection")
	}
	if i.recoveryTestRunFrozen && enabled != i.recoveryTestRunSelected {
		i.recoveryTestRunFault = true
		return false, fmt.Errorf("recovery TEST_RUN selection changed after analysis")
	}
	if !i.recoveryTestRunFrozen {
		i.recoveryTestRunSelected = enabled
		i.recoveryTestRunFrozen = true
	}
	if !enabled {
		if poolReaper {
			// This candidate is never an ordinary TC attachment, even when
			// an image is loaded without its trusted recovery owner.
			i.recoveryTestRunFault = true
			return false, fmt.Errorf("pool reaper TEST_RUN requires trusted recovery selection")
		}
		return false, nil
	}
	owner, _ := gc.GetVar(operators.NativeOwnerRequiredKey)
	if owner != true {
		i.recoveryTestRunFault = true
		return false, fmt.Errorf("recovery TEST_RUN requires native owner")
	}
	validator, _ := gc.GetVar(operators.NativeResourceValidatorKey)
	validate, ok := validator.(func(*operators.NativeResources) error)
	if !ok || validate == nil || i.config == nil || i.config.GetString("annotations.enforce-exec-shared-recovery") != "1" {
		i.recoveryTestRunFault = true
		return false, fmt.Errorf("recovery TEST_RUN requires admitted recovered image")
	}
	if spec.Name != "se_rm_guardian" && spec.Name != "se_rm_administrator" && !poolReaper {
		return false, nil
	}
	if spec.Type != ebpf.SchedCLS || spec.SectionName != "tc" || spec.AttachTo != "" || i.programAttachTarget(spec) != "" {
		i.recoveryTestRunFault = true
		return false, fmt.Errorf("invalid recovery TEST_RUN program %q", spec.Name)
	}
	return true, nil
}

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

// Only enabled syscall commands and explicitly selected recovery TEST_RUN
// programs are exposed. The owning collection retains every FD;
// callers borrow handles and must join command invocations before teardown.
func (i *ebpfInstance) publishCommandPrograms(gc operators.GadgetContext) error {
	selected := make(map[string]*ebpf.Program)
	native := make(map[string]*ebpf.Program)
	if i.recoveryTestRunSelected && (!i.recoveryTestRunAdmitted || i.recoveryTestRunFault) {
		return fmt.Errorf("recovery loaded programs require final admission")
	}
	for name, spec := range i.collectionSpec.Programs {
		recovery, err := i.nativeRecoveryTestRunProgram(gc, spec)
		if err != nil {
			return err
		}
		if recovery && !i.recoveryTestRunAdmitted {
			return fmt.Errorf("recovery TEST_RUN program not admitted")
		}
		if (spec.Type == ebpf.Syscall && i.programAttachTarget(spec) != disabledProgram) || recovery {
			selected[name] = i.collection.Programs[name]
		}
		if i.recoveryTestRunSelected {
			program := i.collection.Programs[name]
			if program == nil {
				return fmt.Errorf("missing admitted recovery program %s", name)
			}
			native[name] = program
		}
	}
	if i.recoveryTestRunSelected && (!i.recoveryTestRunAdmitted || i.recoveryTestRunFault) {
		return fmt.Errorf("recovery loaded programs require final admission")
	}
	for name, program := range selected {
		gc.SetVar(operators.ProgramPrefix+name, program)
	}
	for name, program := range native {
		gc.SetVar(operators.NativeLoadedProgramPrefix+name, program)
	}
	return nil
}

func (i *ebpfInstance) unpublishCommandPrograms(gc operators.GadgetContext) {
	for name, program := range i.collection.Programs {
		key := operators.ProgramPrefix + name
		if current, ok := gc.GetVar(key); ok && current == program {
			gc.SetVar(key, nil)
		}
		key = operators.NativeLoadedProgramPrefix + name
		if current, ok := gc.GetVar(key); ok && current == program {
			gc.SetVar(key, nil)
		}
	}
}
