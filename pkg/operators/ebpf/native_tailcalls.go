// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// nativeTailCalls reads the metadata `tail_calls` declarations: the
// PROG_ARRAY slots of a native image, each with the exact program installed
// there. They are part of the admitted native manifest
// (NativeResources.TailCalls), so the host decides which slots exist.
func (i *ebpfInstance) nativeTailCalls() ([]operators.NativeTailCall, error) {
	if i.config == nil || !i.config.IsSet("tail_calls") {
		return nil, nil
	}
	var calls []operators.NativeTailCall
	if err := i.config.UnmarshalKey("tail_calls", &calls); err != nil {
		return nil, fmt.Errorf("invalid tail_calls metadata: %w", err)
	}
	seen := map[string]bool{}
	for _, c := range calls {
		if c.Map == "" || c.Program == "" {
			return nil, fmt.Errorf("tail call %+v names no map or program", c)
		}
		key := fmt.Sprintf("%s[%d]", c.Map, c.Index)
		if seen[key] {
			return nil, fmt.Errorf("tail call slot %s declared twice", key)
		}
		seen[key] = true
	}
	return calls, nil
}

// installNativeTailCalls installs every declared tail-call slot after the
// collection is loaded and before any handle is published or hook attached,
// so no hook ever runs with a missing target. Each slot must exist, start
// empty, take a loaded program that is never attached itself, and read
// back as exactly that program; the arrays are then frozen against later
// userspace changes. Any failure fails the load.
func (i *ebpfInstance) installNativeTailCalls() error {
	calls, err := i.nativeTailCalls()
	if err != nil || len(calls) == 0 {
		return err
	}
	if i.collection == nil || i.collectionSpec == nil {
		return fmt.Errorf("missing loaded collection for tail calls")
	}
	frozen := map[string]*ebpf.Map{}
	for _, c := range calls {
		mapSpec, progSpec := i.collectionSpec.Maps[c.Map], i.collectionSpec.Programs[c.Program]
		if mapSpec == nil || mapSpec.Type != ebpf.ProgramArray || mapSpec.KeySize != 4 || mapSpec.ValueSize != 4 ||
			c.Index >= mapSpec.MaxEntries || mapSpec.InnerMap != nil || len(mapSpec.Contents) != 0 {
			return fmt.Errorf("tail call %s[%d]: not an empty program array slot", c.Map, c.Index)
		}
		if progSpec == nil || i.programAttachTarget(progSpec) != disabledProgram {
			return fmt.Errorf("tail call %s[%d]: target %s missing or attached", c.Map, c.Index, c.Program)
		}
		array, program := i.collection.Maps[c.Map], i.collection.Programs[c.Program]
		if array == nil || program == nil || array.FD() < 0 || program.FD() < 0 || array.Type() != ebpf.ProgramArray {
			return fmt.Errorf("tail call %s[%d]: loaded map or program %s unavailable", c.Map, c.Index, c.Program)
		}
		info, err := program.Info()
		if err != nil {
			return fmt.Errorf("tail call target %s identity: %w", c.Program, err)
		}
		want, ok := info.ID()
		if !ok || want == 0 {
			return fmt.Errorf("tail call target %s identity unavailable", c.Program)
		}
		var previous *ebpf.Program
		err = array.Lookup(c.Index, &previous)
		if previous != nil {
			previous.Close()
		}
		if err == nil || !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("tail call %s[%d] is not initially empty: %w", c.Map, c.Index, err)
		}
		if err := array.Update(c.Index, program, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("installing tail call %s[%d] = %s: %w", c.Map, c.Index, c.Program, err)
		}
		var installed *ebpf.Program
		if err := array.Lookup(c.Index, &installed); err != nil || installed == nil {
			return fmt.Errorf("reading tail call %s[%d]: %w", c.Map, c.Index, err)
		}
		got, err := installed.Info()
		installed.Close()
		if err != nil {
			return fmt.Errorf("tail call %s[%d] identity: %w", c.Map, c.Index, err)
		}
		if id, ok := got.ID(); !ok || id != want {
			return fmt.Errorf("tail call %s[%d] holds program %d, want %s (%d)", c.Map, c.Index, id, c.Program, want)
		}
		frozen[c.Map] = array
	}
	for name, array := range frozen {
		if err := array.Freeze(); err != nil {
			return fmt.Errorf("freezing tail call array %s: %w", name, err)
		}
	}
	return nil
}
