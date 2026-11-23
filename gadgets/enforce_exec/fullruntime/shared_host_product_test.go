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

// sharedProductImageMetadata is image metadata with an attach_to override
// for each named program ("" overrides nothing). D1: a product image
// carries no attach_to override for any probe.
func sharedProductImageMetadata(overrides ...string) *viper.Viper {
	v := viper.New()
	for _, name := range overrides {
		v.Set("programs."+name+".attach_to", "do_execveat_common.isra.0")
	}
	return v
}

// sharedProductResources is the exact product manifest with every probe
// target as the eBPF operator reports it: each probe on its section target
// (D1: tracepoints only, the same on every kernel).
func sharedProductResources() *operators.NativeResources {
	r := sharedProductExactManifest()
	for name, section := range sharedCandidateProbeSet {
		_, target, _ := strings.Cut(section, "/")
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

// TestSharedProductImageObjectAdmission: the loaded object must be one of
// this release's product objects (sharedProductObjects), on every kernel
// alike: each is admitted on every pinned AL2023 build and on an arbitrary
// other kernel, also when the pins' recorded ProductObjects are empty (the
// qualification record never enters the admission); an unknown digest is
// refused everywhere; a kernel the gate refuses is refused whatever the
// object.
func TestSharedProductImageObjectAdmission(t *testing.T) {
	saved := sharedProductPins
	t.Cleanup(func() { sharedProductPins = saved })
	empty := make(map[string]sharedProductPin, len(saved))
	for d, pin := range saved {
		pin.ProductObjects = map[string]struct{}{}
		empty[d] = pin
	}
	kernels := []*fakeProductKernel{arbitraryProductKernel()}
	for _, d := range sharedProductPinDigests() {
		kernels = append(kernels, pinnedProductKernel(d))
	}
	for _, pins := range []map[string]sharedProductPin{saved, empty} {
		sharedProductPins = pins
		for _, k := range kernels {
			useProductKernel(t, k)
			for profile, obj := range sharedProductObjects {
				if err := admitSharedProductImage(sharedProductImageContext(obj), sharedProductImageMetadata(), sharedProductResources()); err != nil {
					t.Fatalf("%s: product object %s refused: %v", k.release, profile, err)
				}
			}
			err := admitSharedProductImage(sharedProductImageContext(strings.Repeat("cd", 32)), sharedProductImageMetadata(), sharedProductResources())
			if !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "not a product object of this release") {
				t.Fatalf("%s: unknown object: %v", k.release, err)
			}
		}
	}
	sharedProductPins = saved
	// A kernel without the bpf LSM: refused by the gate and by the image
	// admission, pinned or not.
	for _, healthy := range kernels {
		k := *healthy
		k.lsm = "lockdown,capability,selinux"
		useProductKernel(t, &k)
		if _, err := SharedProductKernel(); !errors.Is(err, ErrSharedNativeUnavailable) {
			t.Fatalf("%s without the bpf LSM admitted: %v", k.release, err)
		}
		err := admitSharedProductImage(sharedProductImageContext(sharedProductObjects["g19pkg128"]), sharedProductImageMetadata(), sharedProductResources())
		if !errors.Is(err, ErrSharedNativeUnavailable) {
			t.Fatalf("product image admitted on %s without the bpf LSM: %v", k.release, err)
		}
	}
	// In a default build the candidate gate's override cannot be enabled.
	if !sharedQualificationBuild && sharedProbedKernelOverride() {
		t.Fatal("probed-kernel override enabled in a default build")
	}
}

// TestSharedProductImageAdmissionRefusals (D1 form; was
// TestSharedProductFailureTargets): the image's probes are the
// tracepoint set on their own section targets (no per-kernel symbol, no
// attach_to override), and the loaded object's sha256 is one of the
// release's product objects (D3: the same set on every kernel).
func TestSharedProductImageAdmissionRefusals(t *testing.T) {
	useProductKernel(t, arbitraryProductKernel())
	elf := sharedProductObjects["g19pkg128"]
	good := sharedProductResources
	if err := admitSharedProductImage(sharedProductImageContext(elf), sharedProductImageMetadata(), good()); err != nil {
		t.Fatalf("product image refused: %v", err)
	}
	type tcase struct {
		gc        *gadgetcontext.GadgetContext
		metadata  *viper.Viper
		resources *operators.NativeResources
		reason    string
	}
	cases := map[string]tcase{
		"attach_to override on the fork witness":     {sharedProductImageContext(elf), sharedProductImageMetadata("d1_witness_fork"), good(), "attach_to override"},
		"attach_to override on the capsule terminal": {sharedProductImageContext(elf), sharedProductImageMetadata("real_owner_capsule_terminal"), good(), "attach_to override"},
		"no object digest":                           {sharedProductImageContext(nil), sharedProductImageMetadata(), good(), "digest unavailable"},
		"multi-layer digest":                         {sharedProductImageContext(""), sharedProductImageMetadata(), good(), "digest unavailable"},
		"non-string digest":                          {sharedProductImageContext([]byte(elf)), sharedProductImageMetadata(), good(), "digest unavailable"},
		"pre-D3 per-kernel object":                   {sharedProductImageContext("142ae885221167eaf258678f508999eb0528447b53355eb5d776ae009b6115ae"), sharedProductImageMetadata(), good(), "not a product object of this release"},
		"unknown object":                             {sharedProductImageContext(strings.Repeat("ab", 32)), sharedProductImageMetadata(), good(), "not a product object of this release"},
		"uppercase digest":                           {sharedProductImageContext(strings.ToUpper(elf)), sharedProductImageMetadata(), good(), "not a product object of this release"},
		"exec witness moved off sched_process_exec":  {sharedProductImageContext(elf), sharedProductImageMetadata(), withProbeTarget(good(), "d1_witness_exec", "sys_enter"), "probe d1_witness_exec"},
		"capsule terminal moved off sys_exit":        {sharedProductImageContext(elf), sharedProductImageMetadata(), withProbeTarget(good(), "real_owner_capsule_terminal", "sched_process_exec"), "probe real_owner_capsule_terminal"},
		"sched_process_fork birth hook moved":        {sharedProductImageContext(elf), sharedProductImageMetadata(), withProbeTarget(good(), "opaque_real_owner_successful_birth_candidate", "sched_process_exec"), "probe opaque_real_owner_"},
		"probe program missing":                      {sharedProductImageContext(elf), sharedProductImageMetadata(), withProbeTarget(good(), "opaque_real_owner_child_exit_candidate", ""), "probe opaque_real_owner_"},
		"no resources":                               {sharedProductImageContext(elf), sharedProductImageMetadata(), nil, "missing native resources"},
	}
	for name, tc := range cases {
		if err := admitSharedProductImage(tc.gc, tc.metadata, tc.resources); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: %v, want ErrSharedNativeUnavailable with %q", name, err, tc.reason)
		}
	}
	// The kernel gate runs again at instantiation.
	k := arbitraryProductKernel()
	k.ftrace = "0"
	useProductKernel(t, k)
	if err := admitSharedProductImage(sharedProductImageContext(elf), sharedProductImageMetadata(), good()); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "ftrace") {
		t.Fatalf("instantiation kernel gate: %v", err)
	}
	for _, gone := range []string{"opaque_real_owner_failure_outer_enter", "opaque_real_owner_failure_handler_enter", "real_owner_capsule_entry", "opaque_real_owner_birth_free_task_candidate"} {
		if slices.Contains(sharedProductManifestPrograms, gone) {
			t.Fatalf("exec-frame probe %s still in the product manifest", gone)
		}
	}
}
