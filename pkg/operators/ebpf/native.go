// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// recordNativeProgramDigest sets operators.NativeProgramDigestKey to the
// sha256 of program for a native owner (NativeOwnerRequiredKey true) only.
// Native ownership supports one eBPF layer: a second one invalidates the
// digest (sticky ""), so it never names only part of the image.
func recordNativeProgramDigest(gc operators.GadgetContext, program []byte) {
	if owner, _ := gc.GetVar(operators.NativeOwnerRequiredKey); owner != true {
		return
	}
	if _, exists := gc.GetVar(operators.NativeProgramDigestKey); exists {
		gc.SetVar(operators.NativeProgramDigestKey, "")
		return
	}
	sum := sha256.Sum256(program)
	gc.SetVar(operators.NativeProgramDigestKey, hex.EncodeToString(sum[:]))
}

func (i *ebpfInstance) publishNativeResources(gc operators.GadgetContext) {
	if _, exists := gc.GetVar(operators.NativeResourcesKey); exists {
		// Native ownership supports one collection only. Keep this invalidation
		// sticky across additional layers, including ones with duplicate names.
		// Ordinary multi-layer images do not consume this optional manifest.
		gc.SetVar(operators.NativeResourcesKey, (*operators.NativeResources)(nil))
		return
	}
	r := i.nativeResources()
	// Preflight admission runs before load: report the constants the load
	// will set (an invalid set reports none; the load then refuses it).
	r.Constants, _ = i.nativeConstantPlan(gc, false)
	gc.SetVar(operators.NativeResourcesKey, r)
}

func (i *ebpfInstance) nativeResources() *operators.NativeResources {
	r := &operators.NativeResources{Maps: map[string]operators.NativeMapResource{}, Programs: map[string]operators.NativeProgramResource{}}
	for n, m := range i.collectionSpec.Maps {
		r.Maps[n] = nativeMapResource(m, 0)
	}
	for n, p := range i.collectionSpec.Programs {
		r.Programs[n] = operators.NativeProgramResource{Type: uint32(p.Type), Target: i.programAttachTarget(p), Instructions: uint64(len(p.Instructions)) * 2}
	}
	// Invalid declarations are refused by validateNativeResources.
	r.TailCalls, _ = i.nativeTailCalls()
	r.Constants = maps.Clone(i.nativeConstants)
	return r
}

func nativeMapResource(m *ebpf.MapSpec, depth int) operators.NativeMapResource {
	// Bound malformed/cyclic templates without silently omitting resources.
	// The unknown map type is rejected by native resource admission.
	if m == nil || depth >= 8 {
		return operators.NativeMapResource{}
	}
	r := operators.NativeMapResource{Type: uint32(m.Type), KeySize: m.KeySize, ValueSize: m.ValueSize, MaxEntries: m.MaxEntries, Flags: m.Flags}
	if m.InnerMap != nil {
		inner := nativeMapResource(m.InnerMap, depth+1)
		r.InnerMap = &inner
	}
	return r
}

// applyNativeConstants sets the native owner's read-only constants
// (operators.NativeConstantsKey) in the final collection spec and records
// the ones it set (name -> byte size) for native admission.
func (i *ebpfInstance) applyNativeConstants(gc operators.GadgetContext) error {
	applied, err := i.nativeConstantPlan(gc, true)
	i.nativeConstants = applied
	return err
}

// nativeConstantPlan checks the NativeConstantsKey constants against the
// collection spec and returns the ones present (name -> byte size), setting
// them when apply. Preflight (publishNativeResources) and load share it, so
// admission sees exactly the constants the load sets.
func (i *ebpfInstance) nativeConstantPlan(gc operators.GadgetContext, apply bool) (map[string]uint32, error) {
	value, exists := gc.GetVar(operators.NativeConstantsKey)
	if !exists {
		return nil, nil
	}
	constants := map[string]any{}
	switch typed := value.(type) {
	case map[string]uint32:
		for name, v := range typed {
			constants[name] = v
		}
	case map[string]uint64:
		for name, v := range typed {
			constants[name] = v
		}
	case map[string]any:
		constants = typed
	default:
		return nil, fmt.Errorf("invalid native constants %T", value)
	}
	applied := map[string]uint32{}
	for name, v := range constants {
		var size uint32
		switch v.(type) {
		case uint32:
			size = 4
		case uint64:
			size = 8
		default:
			return nil, fmt.Errorf("native constant %s: invalid value %T", name, v)
		}
		variable, ok := i.collectionSpec.Variables[name]
		if !ok {
			continue
		}
		if !variable.Constant() || variable.Size() != size {
			return nil, fmt.Errorf("native constant %s is not a %d-byte read-only constant", name, size)
		}
		if apply {
			if err := variable.Set(v); err != nil {
				return nil, fmt.Errorf("native constant %s: %w", name, err)
			}
		}
		applied[name] = size
	}
	return applied, nil
}

func (i *ebpfInstance) validateNativeResources(gc operators.GadgetContext) error {
	value, exists := gc.GetVar(operators.NativeResourceValidatorKey)
	if !exists {
		if i.recoveryTestRunSelected {
			return fmt.Errorf("recovery TEST_RUN requires final native admission")
		}
		return nil
	}
	validate, ok := value.(func(*operators.NativeResources) error)
	if !ok || validate == nil {
		return fmt.Errorf("invalid native resource validator")
	}
	if _, err := i.nativeTailCalls(); err != nil {
		return err
	}
	for name, m := range i.collectionSpec.Maps {
		if err := validateNativeMapPinning(name, m, 0); err != nil {
			return err
		}
	}
	if err := validate(i.nativeResources()); err != nil {
		return err
	}
	if i.recoveryTestRunSelected {
		if i.recoveryTestRunFault || !i.recoveryTestRunFrozen {
			return fmt.Errorf("recovery TEST_RUN selection changed before admission")
		}
		i.recoveryTestRunAdmitted = true
	}
	i.nativeTxn = true
	return nil
}

func validateNativeMapPinning(name string, m *ebpf.MapSpec, depth int) error {
	// Match the manifest's traversal bound, rejecting malformed templates
	// rather than overlooking pinning beyond the admitted shape.
	if m == nil || depth >= 8 {
		return fmt.Errorf("native map %q has an invalid inner-map template", name)
	}
	// Automatic pinning can reopen unrelated global state or retain a new map
	// beyond collection close. Native ownership admits neither lifecycle. This
	// does not restrict ordinary gadgets or explicit verified recovery links.
	if m.Pinning != ebpf.PinNone {
		return fmt.Errorf("native map %q requests unsupported automatic pinning %d", name, m.Pinning)
	}
	if m.InnerMap != nil {
		return validateNativeMapPinning(name+".inner", m.InnerMap, depth+1)
	}
	return nil
}

func (i *ebpfInstance) publishNativeAttachment(gc operators.GadgetContext, name string, p *ebpf.ProgramSpec, l link.Link) error {
	// Optional receipts must not regress ordinary tracers on link types/kernels
	// without Info support. Native consumers fail closed on the absent receipt.
	// Native transactions also receipt their kprobe and raw_tp links.
	if p.Type != ebpf.LSM && p.Type != ebpf.Tracing && (!i.nativeTxn || (p.Type != ebpf.Kprobe && p.Type != ebpf.RawTracepoint)) {
		return nil
	}
	info, err := l.Info()
	if err != nil || info == nil || info.ID == 0 || info.Program == 0 {
		if i.nativeTxn {
			// Native consumers require every receipt; never publish a partial set.
			if err == nil {
				err = errors.New("incomplete link info")
			}
			return fmt.Errorf("native receipt for %s unavailable: %w", name, err)
		}
		return nil
	}
	receipt := &operators.NativeAttachment{
		Type: uint32(p.Type), LinkID: uint32(info.ID), ProgramID: uint32(info.Program),
		Target: i.programAttachTarget(p),
		Check:  nativeAttachmentCheck(name, info.ID, info.Type, info.Program, l.Info),
	}
	if i.nativeTxn {
		receipt.Check = nativeReadinessCheck(name, receipt.Target, info, receipt.Check, nativeLinkLookup)
	}
	if i.recoveryTestRunSelected && i.recoveryTestRunAdmitted &&
		p.Type == ebpf.LSM && info.Type == link.TracingType &&
		((name == "se_task_alloc" && p.SectionName == "lsm/task_alloc" && p.AttachTo == "task_alloc") ||
			(name == "se_task_free" && p.SectionName == "lsm/task_free" && p.AttachTo == "task_free")) {
		receipt.PinAt = newNativeRecoveryPin(l, name, info)
	}
	if i.nativeAttachments == nil {
		i.nativeAttachments = map[string]*operators.NativeAttachment{}
	}
	i.nativeAttachments[name] = receipt
	gc.SetVar(operators.NativeAttachmentPrefix+name, receipt)
	return nil
}

func (i *ebpfInstance) unpublishNativeAttachments(gc operators.GadgetContext) {
	for name, receipt := range i.nativeAttachments {
		if current, _ := gc.GetVar(operators.NativeAttachmentPrefix + name); current == receipt {
			gc.SetVar(operators.NativeAttachmentPrefix+name, nil)
		}
	}
	i.nativeAttachments = nil
}

func nativeAttachmentCheck(name string, expectedLink link.ID, expectedType link.Type, expectedProgram ebpf.ProgramID, read func() (*link.Info, error)) func() error {
	return func() error {
		current, err := read()
		if err != nil {
			return err
		}
		if current == nil || current.ID != expectedLink || current.Type != expectedType || current.Program != expectedProgram {
			return fmt.Errorf("attachment %s identity changed", name)
		}
		return nil
	}
}
