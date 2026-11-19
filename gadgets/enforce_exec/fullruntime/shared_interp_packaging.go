// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedInterpContinuationTailCalls is exactly the packaging that the
// interpreter continuation (G019 gap 4, review H1;
// ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE) adds to the
// candidate image metadata: two tail-call slots, whose program arrays and
// targets exist only in an object built with it, and whose targets the
// packaging disables. Every product object carries them (the source refuses
// a product publisher without the continuation, and the product control
// requires all of sharedProductTailCalls).
var sharedInterpContinuationTailCalls = []operators.NativeTailCall{
	{Map: "opaque_real_continue_strict", Index: 0, Program: "opaque_real_owner_continue_strict"},
	{Map: "opaque_real_continue_audit", Index: 0, Program: "opaque_real_owner_continue_audit"},
}

// sharedObjectShape is what the packaging decision needs to know of one
// object: its programs and maps, and whether it is a product object (it
// carries the product publisher's se_admin map or commands).
type sharedObjectShape struct {
	Programs, Maps map[string]bool
	Product        bool
}

// sharedObjectShapeOf is the packaging decision's view of an object
// (sharedPackagingForObject): a product object carries se_admin or the
// product publisher commands.
func sharedObjectShapeOf(spec *ebpf.CollectionSpec) sharedObjectShape {
	shape := sharedObjectShape{Programs: map[string]bool{}, Maps: map[string]bool{}}
	for name := range spec.Programs {
		shape.Programs[name] = true
	}
	for name := range spec.Maps {
		shape.Maps[name] = true
	}
	_, admin := spec.Maps["se_admin"]
	commands := 0
	for _, name := range sharedProductCommands {
		if shape.Programs[name] {
			commands++
		}
	}
	shape.Product = admin || commands == len(sharedProductCommands)
	return shape
}

// sharedPackagingForObject returns the candidate image metadata for one
// object. A product object, and any object that carries the interpreter
// continuation, gets the merged metadata unchanged. A non-product
// (frozen diagnostic or qualification) object built before the continuation
// gets the merged metadata without EXACTLY the sharedInterpContinuationTailCalls
// slots and the disables of their targets: no other entry is ever dropped,
// so every other stale or missing entry is still refused by the packaging
// and admission checks. A product object without the continuation, and an
// object carrying only part of it, are refused.
func sharedPackagingForObject(merged *viper.Viper, object sharedObjectShape) (*viper.Viper, error) {
	present := 0
	for _, c := range sharedInterpContinuationTailCalls {
		if object.Maps[c.Map] {
			present++
		}
		if object.Programs[c.Program] {
			present++
		}
	}
	all := 2 * len(sharedInterpContinuationTailCalls)
	switch {
	case present == all:
		return merged, nil
	case present != 0:
		return nil, fmt.Errorf("object carries %d of the %d interpreter continuation programs and arrays", present, all)
	case object.Product:
		return nil, fmt.Errorf("product object lacks the interpreter continuation (%v)", sharedInterpContinuationTailCalls)
	}
	// A packaging-only file (the attach declaration) has no tail_calls; any
	// declaration of tail calls must name both continuation slots.
	declared := merged.IsSet("tail_calls")
	var calls []operators.NativeTailCall
	if err := merged.UnmarshalKey("tail_calls", &calls); err != nil {
		return nil, fmt.Errorf("invalid tail_calls metadata: %w", err)
	}
	kept := make([]any, 0, len(calls))
	dropped := 0
	for _, c := range calls {
		if slices.Contains(sharedInterpContinuationTailCalls, c) {
			dropped++
			continue
		}
		kept = append(kept, map[string]any{"map": c.Map, "index": c.Index, "program": c.Program})
	}
	if declared && dropped != len(sharedInterpContinuationTailCalls) {
		return nil, fmt.Errorf("metadata declares %d of the %d interpreter continuation tail calls", dropped, len(sharedInterpContinuationTailCalls))
	}
	programs := map[string]any{}
	for name, entry := range merged.GetStringMap("programs") {
		programs[name] = entry
	}
	for _, c := range sharedInterpContinuationTailCalls {
		if merged.GetString("programs."+c.Program+".attach_to") != sharedProgramDisabled {
			return nil, fmt.Errorf("metadata does not disable the interpreter continuation target %s", c.Program)
		}
		delete(programs, c.Program)
	}
	out := viper.New()
	if err := out.MergeConfigMap(merged.AllSettings()); err != nil {
		return nil, err
	}
	if declared {
		out.Set("tail_calls", kept)
	}
	out.Set("programs", programs)
	return out, nil
}
