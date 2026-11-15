// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedProductExactManifest is sharedProductFakeManifest completed to the
// generated product name sets: every name the fake lacks is added (a map
// of no checked geometry, a disabled program), so the exact-manifest check
// and every live validator pass.
func sharedProductExactManifest() *operators.NativeResources {
	r := sharedProductFakeManifest()
	for _, name := range sharedProductManifestMaps {
		if _, ok := r.Maps[name]; !ok {
			r.Maps[name] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 4, MaxEntries: 1}
		}
	}
	for _, name := range sharedProductManifestPrograms {
		if _, ok := r.Programs[name]; !ok {
			r.Programs[name] = operators.NativeProgramResource{Type: uint32(ebpf.LSM), Target: sharedProgramDisabled}
		}
	}
	return r
}

// newSharedProductNode is an unstarted product node (as startProductSharedNode
// sets it up) in a product build.
func newSharedProductNode(t *testing.T) *NodeEnforcer {
	t.Helper()
	sharedProductBuild(t)
	n, err := NewNodeEnforcer(sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	n.host.product = true
	return n
}

// TestSharedProductAdmissionExactManifest (plan 3.3): the product node
// admits exactly the generated name sets; anything else is refused with
// ErrSharedNativeUnavailable.
func TestSharedProductAdmissionExactManifest(t *testing.T) {
	if err := newSharedProductNode(t).admitSharedResources(sharedProductExactManifest()); err != nil {
		t.Fatalf("exact product manifest refused: %v", err)
	}
	cases := map[string]func(*operators.NativeResources){
		"extra map":     func(r *operators.NativeResources) { r.Maps["se_extra"] = r.Maps["se_admin"] },
		"missing map":   func(r *operators.NativeResources) { delete(r.Maps, "opaque_real_reap_events") },
		"extra program": func(r *operators.NativeResources) { r.Programs["se_extra"] = r.Programs["se_command"] },
		"twin map": func(r *operators.NativeResources) {
			r.Maps[sharedProductForbiddenMaps[0]] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 4, MaxEntries: 1}
		},
		"SchedCLS program": func(r *operators.NativeResources) {
			r.Programs["se_pool_reaper_entry"] = operators.NativeProgramResource{Type: uint32(ebpf.SchedCLS), Target: sharedProgramDisabled}
		},
		"se_rm program": func(r *operators.NativeResources) {
			r.Programs["se_rm_guardian"] = operators.NativeProgramResource{Type: uint32(ebpf.SchedCLS), Target: sharedProgramDisabled}
		},
		"missing product command": func(r *operators.NativeResources) { delete(r.Programs, sharedProductCommands[0]) },
		"missing reaper command":  func(r *operators.NativeResources) { delete(r.Programs, "opaque_real_reap") },
		"nil":                     nil,
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var r *operators.NativeResources
			if mutate != nil {
				r = sharedProductExactManifest()
				mutate(r)
			}
			if err := newSharedProductNode(t).admitSharedResources(r); !errors.Is(err, ErrSharedNativeUnavailable) {
				t.Fatalf("admitted or untyped: %v", err)
			}
		})
	}
	// The same exact manifest is refused by a product node in a
	// qualification build (mutual exclusion).
	n := newSharedProductNode(t)
	sharedQualificationBuild = true
	if err := n.admitSharedResources(sharedProductExactManifest()); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("product node admitted in a qualification build: %v", err)
	}
}

// sharedProductImageContext is a gadget context carrying the native program
// digest the eBPF operator records (unset when digest is nil).
func sharedProductImageContext(digest any) *gadgetcontext.GadgetContext {
	gc := gadgetcontext.New(context.Background(), "local/shared-product:abi3-development")
	if digest != nil {
		gc.SetVar(operators.NativeProgramDigestKey, digest)
	}
	return gc
}

// sharedProductImageMetadata is image metadata with the failure-frame
// attach_to targets of outer and handler ("" leaves a target unset).
func sharedProductImageMetadata(outer, handler string) *viper.Viper {
	v := viper.New()
	for name, isOuter := range sharedProductFailureTargets {
		symbol := handler
		if isOuter {
			symbol = outer
		}
		if symbol != "" {
			v.Set("programs."+name+".attach_to", symbol)
		}
	}
	return v
}

// sharedProductPinnedResources is the exact product manifest with every
// probe target as the eBPF operator reports it for an image built for pin
// (failure frames on the pin's symbols, the other probes on their section
// targets).
func sharedProductPinnedResources(pin sharedProductPin) *operators.NativeResources {
	r := sharedProductExactManifest()
	for name, section := range sharedCandidateProbeSet {
		_, target, _ := strings.Cut(section, "/")
		if outer, failure := sharedProductFailureTargets[name]; failure {
			target = pin.HandlerSymbol
			if outer {
				target = pin.OuterSymbol
			}
		}
		p := r.Programs[name]
		p.Target = target
		r.Programs[name] = p
	}
	return r
}

// withProbeTarget is r with program name retargeted (as an attach_to
// override does), or removed when target is "".
func withProbeTarget(r *operators.NativeResources, name, target string) *operators.NativeResources {
	if target == "" {
		delete(r.Programs, name)
		return r
	}
	p := r.Programs[name]
	p.Target = target
	r.Programs[name] = p
	return r
}

func anyProductELF(pin sharedProductPin) string {
	for sum := range pin.ProductELF {
		return sum
	}
	return ""
}

// TestSharedProductFailureTargets (plan 3.4) and the O1 byte binding: the
// image's failure-frame targets must be the running pin's symbols and the
// loaded object's sha256 one of its product objects.
func TestSharedProductFailureTargets(t *testing.T) {
	digests := sharedProductPinDigests()
	var d612, d618 string
	for _, d := range digests {
		if strings.HasPrefix(sharedProductPins[d].Release, "6.12.") {
			d612 = d
		} else {
			d618 = d
		}
	}
	p612, p618 := sharedProductPins[d612], sharedProductPins[d618]
	for _, d := range digests {
		pin := sharedProductPins[d]
		useProductKernel(t, pinnedProductKernel(d))
		if err := admitSharedProductImage(sharedProductImageContext(anyProductELF(pin)), sharedProductImageMetadata(pin.OuterSymbol, pin.HandlerSymbol), sharedProductPinnedResources(pin)); err != nil {
			t.Fatalf("%s: pinned image refused: %v", pin.Release, err)
		}
	}
	useProductKernel(t, pinnedProductKernel(d618))
	elf618 := anyProductELF(p618)
	good := func() *operators.NativeResources { return sharedProductPinnedResources(p618) }
	cases := map[string]struct {
		gc        *gadgetcontext.GadgetContext
		metadata  *viper.Viper
		resources *operators.NativeResources
		reason    string
	}{
		"6.12 symbols on the 6.18 pin": {sharedProductImageContext(elf618), sharedProductImageMetadata(p612.OuterSymbol, p612.HandlerSymbol), good(), "failure-frame"},
		"missing handler target":       {sharedProductImageContext(elf618), sharedProductImageMetadata(p618.OuterSymbol, ""), good(), "failure-frame"},
		"missing outer target":         {sharedProductImageContext(elf618), sharedProductImageMetadata("", p618.HandlerSymbol), good(), "failure-frame"},
		"mangled isra suffix":          {sharedProductImageContext(elf618), sharedProductImageMetadata("do_execveat_common.isra.38", p618.HandlerSymbol), good(), "failure-frame"},
		"unsuffixed outer":             {sharedProductImageContext(elf618), sharedProductImageMetadata("do_execveat_common", p618.HandlerSymbol), good(), "failure-frame"},
		"no object digest":             {sharedProductImageContext(nil), sharedProductImageMetadata(p618.OuterSymbol, p618.HandlerSymbol), good(), "digest unavailable"},
		"multi-layer digest":           {sharedProductImageContext(""), sharedProductImageMetadata(p618.OuterSymbol, p618.HandlerSymbol), good(), "digest unavailable"},
		"non-string digest":            {sharedProductImageContext([]byte(elf618)), sharedProductImageMetadata(p618.OuterSymbol, p618.HandlerSymbol), good(), "digest unavailable"},
		"6.12 object on 6.18":          {sharedProductImageContext(anyProductELF(p612)), sharedProductImageMetadata(p618.OuterSymbol, p618.HandlerSymbol), good(), "not a qualified product object"},
		"unknown object":               {sharedProductImageContext(strings.Repeat("ab", 32)), sharedProductImageMetadata(p618.OuterSymbol, p618.HandlerSymbol), good(), "not a qualified product object"},
		"uppercase digest":             {sharedProductImageContext(strings.ToUpper(elf618)), sharedProductImageMetadata(p618.OuterSymbol, p618.HandlerSymbol), good(), "not a qualified product object"},
	}
	moved := map[string]*operators.NativeResources{
		"free_task birth hook moved":          withProbeTarget(good(), "opaque_real_owner_birth_free_task_candidate", "do_exit"),
		"sched_process_fork birth hook moved": withProbeTarget(good(), "opaque_real_owner_successful_birth_candidate", "sched_process_exec"),
		"failure handler moved in resources":  withProbeTarget(good(), "opaque_real_owner_failure_handler_enter", p612.HandlerSymbol),
		"probe program missing":               withProbeTarget(good(), "opaque_real_owner_birth_free_task_candidate", ""),
		"no resources":                        nil,
	}
	for name, r := range moved {
		reason := "probe opaque_real_owner_"
		if r == nil {
			reason = "missing native resources"
		}
		cases[name] = struct {
			gc        *gadgetcontext.GadgetContext
			metadata  *viper.Viper
			resources *operators.NativeResources
			reason    string
		}{sharedProductImageContext(elf618), sharedProductImageMetadata(p618.OuterSymbol, p618.HandlerSymbol), r, reason}
	}
	for name, tc := range cases {
		if err := admitSharedProductImage(tc.gc, tc.metadata, tc.resources); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: %v, want ErrSharedNativeUnavailable with %q", name, err, tc.reason)
		}
	}
	// The kernel gate runs again at instantiation.
	k := pinnedProductKernel(d618)
	k.ftrace = "0"
	useProductKernel(t, k)
	if err := admitSharedProductImage(sharedProductImageContext(elf618), sharedProductImageMetadata(p618.OuterSymbol, p618.HandlerSymbol), good()); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "ftrace") {
		t.Fatalf("instantiation kernel gate: %v", err)
	}
	if !slices.Contains(sharedProductManifestPrograms, "opaque_real_owner_failure_outer_enter") {
		t.Fatal("failure-frame program not in the product manifest")
	}
}
