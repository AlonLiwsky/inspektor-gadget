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

// sharedProductPinnedResources is the exact product manifest with every
// probe target as the eBPF operator reports it: each probe on its section
// target (D1: tracepoints only, the same on every kernel).
func sharedProductPinnedResources(sharedProductPin) *operators.NativeResources {
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

// qualifyAllProductObjectsForTest makes every product object of this release
// qualified on every pin for the rest of the test (the real pins qualify
// none), so the other refusal paths can be reached.
func qualifyAllProductObjectsForTest(t *testing.T) {
	t.Helper()
	saved := sharedProductPins
	t.Cleanup(func() { sharedProductPins = saved })
	pins := make(map[string]sharedProductPin, len(saved))
	for digest, pin := range saved {
		pin.ProductObjects = map[string]struct{}{}
		for _, obj := range sharedProductObjects {
			pin.ProductObjects[obj] = struct{}{}
		}
		pins[digest] = pin
	}
	sharedProductPins = pins
}

// TestSharedProductObjectPinBinding (S1 review F1): the product admits a
// (pinned kernel, object) pair only when that pair is qualified. The real
// pins list exactly the four qualified objects; with a reduced set, a product
// object of this release is refused on a pinned AL2023 kernel that does not
// list it, an unknown digest is refused even where every product object is
// qualified, and an unpinned kernel is admitted only as a probed kernel,
// with every product object of this release and nothing else.
func TestSharedProductObjectPinBinding(t *testing.T) {
	// The real pins: exactly the four stage-1 product objects, qualified
	// on both AL2023 pins by the S1 oracle; nothing else.
	for _, d := range sharedProductPinDigests() {
		pin := sharedProductPins[d]
		if len(pin.ProductObjects) != len(sharedProductObjects) {
			t.Fatalf("%s: qualified set %v", pin.Release, pin.ProductObjects)
		}
		for profile, obj := range sharedProductObjects {
			if !pin.qualifiesProductObject(obj) {
				t.Fatalf("%s: %s not qualified", pin.Release, profile)
			}
		}
		if pin.qualifiesProductObject(strings.Repeat("ab", 32)) {
			t.Fatalf("%s: an unknown digest qualifies", pin.Release)
		}
	}
	// One pair qualified: only that pair passes.
	digests := sharedProductPinDigests()
	saved := sharedProductPins
	t.Cleanup(func() { sharedProductPins = saved })
	pins := map[string]sharedProductPin{}
	for d, pin := range saved {
		pin.ProductObjects = map[string]struct{}{}
		pins[d] = pin
	}
	one := pins[digests[0]]
	one.ProductObjects[sharedProductObjects["g19pkg128"]] = struct{}{}
	pins[digests[0]] = one
	sharedProductPins = pins
	for _, tc := range []struct {
		name   string
		kernel string
		object string
		admit  bool
		reason string
	}{
		{"qualified pair", digests[0], sharedProductObjects["g19pkg128"], true, ""},
		{"other profile on the same pin", digests[0], sharedProductObjects["g19pkg256"], false, "not qualified on pinned kernel"},
		{"same object on the other pin", digests[1], sharedProductObjects["g19pkg128"], false, "not qualified on pinned kernel"},
		{"unknown digest", digests[0], strings.Repeat("cd", 32), false, "not a pinned product object"},
	} {
		useProductKernel(t, pinnedProductKernel(tc.kernel))
		pin := sharedProductPins[tc.kernel]
		err := admitSharedProductImage(sharedProductImageContext(tc.object), sharedProductImageMetadata(), sharedProductPinnedResources(pin))
		if tc.admit != (err == nil) || (!tc.admit && (!errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), tc.reason))) {
			t.Errorf("%s: %v, want admit=%v reason %q", tc.name, err, tc.admit, tc.reason)
		}
	}
	// An unpinned kernel: admitted by the product gate as a probed kernel,
	// whose synthetic pin qualifies every product object of this release
	// and nothing else.
	k := pinnedProductKernel(digests[0])
	k.digest, k.release, k.buildID = strings.Repeat("ef", 32), "6.12.48+deb13-cloud-amd64", "00"
	useProductKernel(t, k)
	_, probed, err := verifySharedProductKernel()
	if err != nil || probed.Tier != KernelTierProbed || probed.Release != k.release {
		t.Fatalf("unpinned kernel: pin %+v err %v, want a probed admission", probed, err)
	}
	for _, tc := range []struct {
		object string
		admit  bool
	}{{sharedProductObjects["g19pkg128"], true}, {sharedProductObjects["g19pkg512"], true}, {strings.Repeat("cd", 32), false}} {
		err := admitSharedProductImage(sharedProductImageContext(tc.object), sharedProductImageMetadata(), sharedProductPinnedResources(probed))
		if tc.admit != (err == nil) || (!tc.admit && !errors.Is(err, ErrSharedNativeUnavailable)) {
			t.Errorf("probed kernel, object %s: %v, want admit=%v", tc.object, err, tc.admit)
		}
	}
	// An unpinned kernel without the bpf LSM is still refused, by the
	// product gate and by the image admission.
	k.lsm = "lockdown,capability,selinux"
	useProductKernel(t, k)
	if _, _, err := verifySharedProductKernel(); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("unpinned kernel without the bpf LSM admitted: %v", err)
	}
	err = admitSharedProductImage(sharedProductImageContext(sharedProductObjects["g19pkg128"]), sharedProductImageMetadata(), sharedProductPinnedResources(one))
	if !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("product image admitted on a kernel without the bpf LSM: %v", err)
	}
	// In a default build the candidate gate refuses it too: the override
	// cannot be enabled there.
	if !sharedQualificationBuild && sharedProbedKernelOverride() {
		t.Fatal("probed-kernel override enabled in a default build")
	}
}

// anyProductELF is a product object digest (D3: the same set on every pin).
func anyProductELF(sharedProductPin) string {
	return sharedProductObjects["g19pkg128"]
}

// TestSharedProductImageAdmissionRefusals (D1 form; was
// TestSharedProductFailureTargets): the image's probes are the
// tracepoint set on their own section targets (no per-kernel symbol, no
// attach_to override), and the loaded object's sha256 is one of the
// release's product objects (D3: the same set on every pin).
func TestSharedProductImageAdmissionRefusals(t *testing.T) {
	digests := sharedProductPinDigests()
	var d618 string
	for _, d := range digests {
		if !strings.HasPrefix(sharedProductPins[d].Release, "6.12.") {
			d618 = d
		}
	}
	// The real pins qualify exactly this release's four product objects
	// (S1 AL2023 qualification): each is admitted on both; a digest that
	// is not a product object is refused.
	for _, d := range digests {
		pin := sharedProductPins[d]
		useProductKernel(t, pinnedProductKernel(d))
		for profile, obj := range sharedProductObjects {
			if err := admitSharedProductImage(sharedProductImageContext(obj), sharedProductImageMetadata(), sharedProductPinnedResources(pin)); err != nil {
				t.Fatalf("%s: qualified %s refused: %v", pin.Release, profile, err)
			}
		}
	}
	// The other refusals, on pins that qualify every product object.
	qualifyAllProductObjectsForTest(t)
	p618 := sharedProductPins[d618]
	for _, d := range digests {
		pin := sharedProductPins[d]
		useProductKernel(t, pinnedProductKernel(d))
		if err := admitSharedProductImage(sharedProductImageContext(anyProductELF(pin)), sharedProductImageMetadata(), sharedProductPinnedResources(pin)); err != nil {
			t.Fatalf("%s: qualified pinned image refused: %v", pin.Release, err)
		}
	}
	useProductKernel(t, pinnedProductKernel(d618))
	elf618 := anyProductELF(p618)
	good := func() *operators.NativeResources { return sharedProductPinnedResources(p618) }
	type tcase struct {
		gc        *gadgetcontext.GadgetContext
		metadata  *viper.Viper
		resources *operators.NativeResources
		reason    string
	}
	cases := map[string]tcase{
		"attach_to override on the fork witness":     {sharedProductImageContext(elf618), sharedProductImageMetadata("d1_witness_fork"), good(), "attach_to override"},
		"attach_to override on the capsule terminal": {sharedProductImageContext(elf618), sharedProductImageMetadata("real_owner_capsule_terminal"), good(), "attach_to override"},
		"no object digest":                           {sharedProductImageContext(nil), sharedProductImageMetadata(), good(), "digest unavailable"},
		"multi-layer digest":                         {sharedProductImageContext(""), sharedProductImageMetadata(), good(), "digest unavailable"},
		"non-string digest":                          {sharedProductImageContext([]byte(elf618)), sharedProductImageMetadata(), good(), "digest unavailable"},
		"pre-D3 per-kernel object":                   {sharedProductImageContext("142ae885221167eaf258678f508999eb0528447b53355eb5d776ae009b6115ae"), sharedProductImageMetadata(), good(), "not a pinned product object"},
		"unknown object":                             {sharedProductImageContext(strings.Repeat("ab", 32)), sharedProductImageMetadata(), good(), "not a pinned product object"},
		"uppercase digest":                           {sharedProductImageContext(strings.ToUpper(elf618)), sharedProductImageMetadata(), good(), "not a pinned product object"},
		"exec witness moved off sched_process_exec":  {sharedProductImageContext(elf618), sharedProductImageMetadata(), withProbeTarget(good(), "d1_witness_exec", "sys_enter"), "probe d1_witness_exec"},
		"capsule terminal moved off sys_exit":        {sharedProductImageContext(elf618), sharedProductImageMetadata(), withProbeTarget(good(), "real_owner_capsule_terminal", "sched_process_exec"), "probe real_owner_capsule_terminal"},
		"sched_process_fork birth hook moved":        {sharedProductImageContext(elf618), sharedProductImageMetadata(), withProbeTarget(good(), "opaque_real_owner_successful_birth_candidate", "sched_process_exec"), "probe opaque_real_owner_"},
		"probe program missing":                      {sharedProductImageContext(elf618), sharedProductImageMetadata(), withProbeTarget(good(), "opaque_real_owner_child_exit_candidate", ""), "probe opaque_real_owner_"},
		"no resources":                               {sharedProductImageContext(elf618), sharedProductImageMetadata(), nil, "missing native resources"},
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
	if err := admitSharedProductImage(sharedProductImageContext(elf618), sharedProductImageMetadata(), good()); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "ftrace") {
		t.Fatalf("instantiation kernel gate: %v", err)
	}
	for _, gone := range []string{"opaque_real_owner_failure_outer_enter", "opaque_real_owner_failure_handler_enter", "real_owner_capsule_entry", "opaque_real_owner_birth_free_task_candidate"} {
		if slices.Contains(sharedProductManifestPrograms, gone) {
			t.Fatalf("exec-frame probe %s still in the product manifest", gone)
		}
	}
}
