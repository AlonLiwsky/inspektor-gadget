// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"fmt"
	"strconv"

	"github.com/cilium/ebpf"
)

// programLoaded reports whether a program is loaded. The gadget configuration
// opts a program out with programs.<name>.load set to false. A disabled
// program (attach target gadget_program_disabled) is still loaded: user space
// can install it in a PROG_ARRAY or attach it itself. A value that is not a
// boolean is an error, so a typo never drops a program silently.
func (i *ebpfInstance) programLoaded(p *ebpf.ProgramSpec) (bool, error) {
	if i.config == nil {
		return true, nil
	}
	key := "programs." + p.Name + ".load"
	switch v := i.config.Get(key).(type) {
	case nil:
		return true, nil
	case bool:
		return v, nil
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return b, nil
		}
	}
	return false, fmt.Errorf("%s: invalid value %v, want true or false", key, i.config.Get(key))
}

// dropUnloadedPrograms removes the programs that are not loaded from the
// collection spec before it is loaded, so the kernel does not verify them: a
// gadget can carry programs for a hook or a program type that some kernels
// lack and not load them there. A tail call target that a PROG_ARRAY map
// lists in its ELF contents must be loaded: the map would refer to a program
// that does not exist.
func (i *ebpfInstance) dropUnloadedPrograms() error {
	dropped := map[string]bool{}
	for name, p := range i.collectionSpec.Programs {
		loaded, err := i.programLoaded(p)
		if err != nil {
			return err
		}
		if !loaded {
			i.logger.Debugf("Not loading program %q", name)
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
				return fmt.Errorf("program %q is not loaded, but map %q lists it as a tail call target", prog, name)
			}
		}
	}
	return nil
}
