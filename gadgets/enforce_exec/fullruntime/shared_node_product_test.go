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
// kernel the gate admits (a pinned AL2023 build or any other build) the
// host's Run is reached exactly once; on every refused kernel, pinned or
// not, it is never reached and the error is ErrSharedNativeUnavailable.
func TestSharedProductStartNodeKernelGate(t *testing.T) {
	sharedProductBuild(t)
	kernels := productGateKernels()
	for name, k := range kernels {
		useProductKernel(t, k)
		h := &countingProductHost{}
		n, err := StartNode(WithSharedNodeHost(t.Context(), h.host()), sharedQualifiedConfig())
		if n != nil || !errors.Is(err, errCountingHostRefused) || h.runs != 1 {
			t.Fatalf("%s: node=%v err=%v runs=%d, want the host reached once", name, n, err, h.runs)
		}
	}
	for name, mutate := range map[string]func(*fakeProductKernel){
		"unreadable BTF":      func(k *fakeProductKernel) { k.digest, k.digestErr = "", os.ErrPermission },
		"unreadable release":  func(k *fakeProductKernel) { k.releaseErr = os.ErrPermission },
		"unreadable build-id": func(k *fakeProductKernel) { k.buildIDErr = os.ErrPermission },
		"livepatch":           func(k *fakeProductKernel) { k.tainted = "32768" },
		"no bpf LSM":          func(k *fakeProductKernel) { k.lsm = "selinux" },
		"ftrace off":          func(k *fakeProductKernel) { k.ftrace = "0" },
		"non-amd64":           func(k *fakeProductKernel) { k.arch = "arm64" },
	} {
		for kname, healthy := range kernels {
			k := *healthy
			mutate(&k)
			useProductKernel(t, &k)
			h := &countingProductHost{}
			n, err := StartNode(WithSharedNodeHost(t.Context(), h.host()), sharedQualifiedConfig())
			if n != nil || !errors.Is(err, ErrSharedNativeUnavailable) || h.runs != 0 {
				t.Errorf("%s, %s: node=%v err=%v runs=%d, want refusal before Run", kname, name, n, err, h.runs)
			}
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
