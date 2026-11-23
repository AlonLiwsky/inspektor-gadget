// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// btfMemberOffsetAny reports whether structName has member (bitfields too).
func btfMemberOffsetAny(spec *btf.Spec, structName, member string) (uint32, error) {
	structs, err := btfStructs(spec, structName)
	if err != nil || len(structs) != 1 {
		return 0, fmt.Errorf("BTF struct %s: %d matches, %w", structName, len(structs), err)
	}
	for _, m := range structs[0].Members {
		if m.Name == member {
			return uint32(m.Offset), nil
		}
	}
	return 0, fmt.Errorf("BTF %s.%s: no such member", structName, member)
}

// TestSharedFmodeBackingProbeDecides: the live probe decides the
// FMODE_BACKING bit on every kernel; a failed probe refuses and is never cached, a success is cached.
func TestSharedFmodeBackingProbeDecides(t *testing.T) {
	oldProbe := fmodeBackingProbe
	reset := func() {
		sharedFmodeBackingMu.Lock()
		sharedFmodeBackingValue = 0
		sharedFmodeBackingMu.Unlock()
	}
	t.Cleanup(func() { fmodeBackingProbe = oldProbe; reset() })
	boom := errors.New("fsconfig overlay create: invalid argument")
	const layout = sharedImageOverlayLayoutRealFile
	kernels := []*fakeProductKernel{arbitraryProductKernel(), otherProductKernel()}
	for _, k := range kernels {
		useProductKernel(t, k)
		reset()
		calls := 0
		fmodeBackingProbe = func(uint32) (uint32, error) { calls++; return 0, boom }
		for i := 1; i <= 2; i++ {
			if got, err := sharedFmodeBacking(layout); !errors.Is(err, boom) || got != 0 || calls != i {
				t.Fatalf("%s, probe failed: %#x, %v, %d probes after %d calls (a refusal must not be cached)", k.release, got, err, calls, i)
			}
		}
		// The probe's bit is used, whatever the kernel's source says (25
		// here: the probe decides).
		fmodeBackingProbe = func(uint32) (uint32, error) { calls++; return sharedFmodeBacking25, nil }
		for range 2 {
			if got, err := sharedFmodeBacking(layout); err != nil || got != sharedFmodeBacking25 {
				t.Fatalf("%s, probe succeeded: %#x, %v", k.release, got, err)
			}
		}
		if calls != 3 {
			t.Fatalf("%s: a probed bit was not cached: %d probes", k.release, calls)
		}
		if note := sharedFmodeBackingNote.Load(); note == nil || *note != "probed 0x2000000" {
			t.Fatalf("%s: note %v", k.release, note)
		}
	}
}
