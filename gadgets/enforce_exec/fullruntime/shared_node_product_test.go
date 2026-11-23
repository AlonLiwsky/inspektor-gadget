// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

// sharedProductBuild makes the test binary a product build (no
// qualification tag in effect) for the test.
func sharedProductBuild(t *testing.T) {
	t.Helper()
	old := sharedQualificationBuild
	sharedQualificationBuild = false
	t.Cleanup(func() { sharedQualificationBuild = old })
}

// countingProductHost is a SharedNodeHost whose Run counts and refuses, so
// StartNode returns right after the host was reached.
type countingProductHost struct{ runs int }

var errCountingHostRefused = errors.New("counting host refuses the gadget")

func (h *countingProductHost) host() SharedNodeHost {
	return SharedNodeHost{Run: func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
		h.runs++
		return func(context.Context) error { return nil }, make(chan error), errCountingHostRefused
	}}
}

// TestSharedProductStartNodeKernelGate (plan 3.1, StartNode part): on each
// pin and on a probed kernel the host's Run is reached exactly once; on every
// refused kernel it is never reached and the error is
// ErrSharedNativeUnavailable.
func TestSharedProductStartNodeKernelGate(t *testing.T) {
	sharedProductBuild(t)
	for _, digest := range sharedProductPinDigests() {
		useProductKernel(t, pinnedProductKernel(digest))
		h := &countingProductHost{}
		n, err := StartNode(WithSharedNodeHost(t.Context(), h.host()), sharedQualifiedConfig())
		if n != nil || !errors.Is(err, errCountingHostRefused) || h.runs != 1 {
			t.Fatalf("pin %s: node=%v err=%v runs=%d, want the host reached once", digest, n, err, h.runs)
		}
	}
	// A probed kernel reaches the host too.
	k := pinnedProductKernel(sharedProductPinDigests()[0])
	k.digest, k.release, k.buildID = strings.Repeat("1", 64), "6.1.158-180.294.amzn2023.x86_64", strings.Repeat("0", 40)
	useProductKernel(t, k)
	h := &countingProductHost{}
	if n, err := StartNode(WithSharedNodeHost(t.Context(), h.host()), sharedQualifiedConfig()); n != nil || !errors.Is(err, errCountingHostRefused) || h.runs != 1 {
		t.Fatalf("probed kernel: node=%v err=%v runs=%d, want the host reached once", n, err, h.runs)
	}
	for name, mutate := range map[string]func(*fakeProductKernel){
		"unreadable BTF": func(k *fakeProductKernel) { k.digest, k.digestErr = "", os.ErrPermission },
		"livepatch":      func(k *fakeProductKernel) { k.tainted = "32768" },
		"no bpf LSM":     func(k *fakeProductKernel) { k.lsm = "selinux" },
		"ftrace off":     func(k *fakeProductKernel) { k.ftrace = "0" },
		"non-amd64":      func(k *fakeProductKernel) { k.arch = "arm64" },
	} {
		k := pinnedProductKernel(sharedProductPinDigests()[0])
		mutate(k)
		useProductKernel(t, k)
		h := &countingProductHost{}
		n, err := StartNode(WithSharedNodeHost(t.Context(), h.host()), sharedQualifiedConfig())
		if n != nil || !errors.Is(err, ErrSharedNativeUnavailable) || h.runs != 0 {
			t.Errorf("%s: node=%v err=%v runs=%d, want refusal before Run", name, n, err, h.runs)
		}
	}
}

// TestSharedProductHostExclusiveWithQualification (plan 3.2): a
// qualification build refuses the product host even on a pinned kernel; a
// product build ignores the qualification seam.
func TestSharedProductHostExclusiveWithQualification(t *testing.T) {
	useProductKernel(t, pinnedProductKernel(sharedProductPinDigests()[0]))
	old := sharedQualificationBuild
	t.Cleanup(func() { sharedQualificationBuild = old })
	sharedQualificationBuild = true
	h := &countingProductHost{}
	n, err := StartNode(WithSharedNodeHost(t.Context(), h.host()), sharedQualifiedConfig())
	if n != nil || !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "qualification build") || h.runs != 0 {
		t.Fatalf("qualification build with the product host: node=%v err=%v runs=%d", n, err, h.runs)
	}
	sharedQualificationBuild = false
	q := &countingProductHost{}
	ctx := WithSharedNodeQualification(WithSharedNodeHost(t.Context(), h.host()), SharedNodeQualification{Run: q.host().Run})
	if _, err := StartNode(ctx, sharedQualifiedConfig()); !errors.Is(err, errCountingHostRefused) || q.runs != 0 || h.runs != 1 {
		t.Fatalf("product build with both: err=%v qualification runs=%d product runs=%d", err, q.runs, h.runs)
	}
}

// TestSharedProductHostHasNoSeams (plan 3.6): the product host carries Run
// only.
func TestSharedProductHostHasNoSeams(t *testing.T) {
	typ := reflect.TypeFor[SharedNodeHost]()
	if typ.NumField() != 1 || typ.Field(0).Name != "Run" {
		t.Fatalf("SharedNodeHost has %d fields, want Run only", typ.NumField())
	}
	if _, ok := sharedNodeHostFrom(WithSharedNodeHost(t.Context(), SharedNodeHost{})); ok {
		t.Fatal("a host without Run selected the product path")
	}
}

// TestSelectSharedProductImage (plan 3.7): the entry of the running pinned
// digest is selected, and the SharedProbedKernelEntry entry on a probed
// kernel; no match, a digest-only match on the wrong build and an empty
// table are refused with ErrSharedNativeUnavailable.
func TestSelectSharedProductImage(t *testing.T) {
	type entry struct{ image, manifest string }
	digests := sharedProductPinDigests()
	table := map[string]entry{digests[0]: {"img-a", "sha256:a"}, digests[1]: {"img-b", "sha256:b"}}
	for k, digest := range digests {
		useProductKernel(t, pinnedProductKernel(digest))
		got, e, err := SelectSharedProductImage(table)
		if err != nil || got != digest || e != table[digest] {
			t.Fatalf("pin %d: %q %+v %v", k, got, e, err)
		}
	}
	useProductKernel(t, pinnedProductKernel(digests[0]))
	if _, e, err := SelectSharedProductImage(map[string]entry{digests[1]: {"img-b", "sha256:b"}}); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "no image entry") || e != (entry{}) {
		t.Fatalf("no match: %+v %v", e, err)
	}
	if _, _, err := SelectSharedProductImage(map[string]entry{}); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "no image entries") {
		t.Fatalf("empty table: %v", err)
	}
	if _, _, err := SelectSharedProductImage[entry](nil); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("nil table: %v", err)
	}
	// A probed kernel selects the SharedProbedKernelEntry entry, never a
	// digest entry, also when it shares a pinned BTF.
	probedTable := map[string]entry{digests[0]: {"img-a", "sha256:a"}, SharedProbedKernelEntry: {"img-p", "sha256:p"}}
	for name, mutate := range map[string]func(*fakeProductKernel){
		"unpinned BTF":              func(k *fakeProductKernel) { k.digest = strings.Repeat("2", 64) },
		"pinned BTF, other release": func(k *fakeProductKernel) { k.release = "6.12.114-139.210.amzn2023.x86_64" },
	} {
		k := pinnedProductKernel(digests[0])
		mutate(k)
		useProductKernel(t, k)
		got, e, err := SelectSharedProductImage(probedTable)
		if err != nil || got != k.digest || e != probedTable[SharedProbedKernelEntry] {
			t.Errorf("%s: %q %+v %v, want the probed entry", name, got, e, err)
		}
		if _, e, err := SelectSharedProductImage(table); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "no image entry for probed kernel") || e != (entry{}) {
			t.Errorf("%s without a probed entry: %+v %v", name, e, err)
		}
	}
	// On a pinned kernel the probed entry is never used.
	useProductKernel(t, pinnedProductKernel(digests[1]))
	if _, _, err := SelectSharedProductImage(probedTable); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("pinned kernel without its digest entry: %v", err)
	}
	for name, mutate := range map[string]func(*fakeProductKernel){
		"wrong release":  func(k *fakeProductKernel) { k.release = sharedProductPins[digests[1]].Release },
		"wrong build-id": func(k *fakeProductKernel) { k.buildID = sharedProductPins[digests[1]].BuildID },
	} {
		k := pinnedProductKernel(digests[0])
		mutate(k)
		useProductKernel(t, k)
		if _, e, err := SelectSharedProductImage(table); !errors.Is(err, ErrSharedNativeUnavailable) || e != (entry{}) {
			t.Errorf("%s: digest-only match selected %+v (%v)", name, e, err)
		}
	}
}
