// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// TestSharedProbedKernelRefusals (D3 oracle: refusal on a kernel that fails
// the admission check): the probed-kernel admission is off unless the
// test-only override is set, and with it still refuses another
// architecture, a kernel without the bpf LSM, an unreadable LSM list, ftrace
// off and a livepatched kernel. Stage 1 (D1) has no failure frames to
// resolve.
func TestSharedProbedKernelRefusals(t *testing.T) {
	oldOverride := sharedProbedKernelOverride
	t.Cleanup(func() { sharedProbedKernelOverride = oldOverride })
	stock := func() sharedProductKernelProbe {
		return sharedProductKernelProbe{
			arch:      func() string { return "amd64" },
			btfDigest: func() (string, error) { return strings.Repeat("ab", 32), nil },
			release:   func() (string, error) { return "6.12.48+deb13-cloud-amd64", nil },
			buildID:   func() (string, error) { return "00", nil },
			lsm:       func() (string, error) { return "lockdown,capability,landlock,yama,apparmor,bpf", nil },
			ftrace:    func() (string, error) { return "1\n", nil },
			tainted:   func() (string, error) { return "0\n", nil },
		}
	}
	sharedProbedKernelOverride = func() bool { return false }
	if err := verifySharedProbedKernel(stock()); !errors.Is(err, ErrSharedKernelProbe) || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("override off: %v", err)
	}
	sharedProbedKernelOverride = func() bool { return true }
	if err := verifySharedProbedKernel(stock()); err != nil {
		t.Fatalf("stock kernel with every probe passing: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*sharedProductKernelProbe)
		reason string
	}{
		"arm64": {func(p *sharedProductKernelProbe) { p.arch = func() string { return "arm64" } }, "x86_64 required"},
		"no bpf LSM": {func(p *sharedProductKernelProbe) {
			p.lsm = func() (string, error) { return "lockdown,capability,landlock,yama,apparmor", nil }
		}, "BPF LSM not active"},
		"bpf substring": {func(p *sharedProductKernelProbe) {
			p.lsm = func() (string, error) { return "capability,bpfx,ebpf", nil }
		}, "BPF LSM not active"},
		"LSM unreadable":   {func(p *sharedProductKernelProbe) { p.lsm = func() (string, error) { return "", os.ErrNotExist } }, "LSM list"},
		"ftrace off":       {func(p *sharedProductKernelProbe) { p.ftrace = func() (string, error) { return "0\n", nil } }, "ftrace is not enabled"},
		"ftrace unread":    {func(p *sharedProductKernelProbe) { p.ftrace = func() (string, error) { return "", os.ErrPermission } }, "ftrace_enabled"},
		"livepatched":      {func(p *sharedProductKernelProbe) { p.tainted = func() (string, error) { return "32768\n", nil } }, "livepatched"},
		"taint unreadable": {func(p *sharedProductKernelProbe) { p.tainted = func() (string, error) { return "x", nil } }, "kernel taint"},
	} {
		p := stock()
		tc.mutate(&p)
		if err := verifySharedProbedKernel(p); !errors.Is(err, ErrSharedKernelProbe) || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: err %v, want a refusal with %q", name, err, tc.reason)
		}
	}
}

// TestSharedProbedKernelOverrideBuild: only a qualification build can turn
// the override on, and only with the explicit environment opt-in; a default
// build ignores the variable.
func TestSharedProbedKernelOverrideBuild(t *testing.T) {
	t.Setenv("IG_ENFORCE_EXEC_PROBED_KERNEL", "1")
	if got := sharedProbedKernelOverride(); got != sharedQualificationBuild {
		t.Fatalf("override %v with the opt-in set in a build with qualification=%v", got, sharedQualificationBuild)
	}
	t.Setenv("IG_ENFORCE_EXEC_PROBED_KERNEL", "")
	if sharedProbedKernelOverride() {
		t.Fatal("override on without the opt-in")
	}
	// The canary negative test's LSM-list bypass: qualification builds
	// only, and only together with the probed-kernel opt-in.
	t.Setenv("IG_ENFORCE_EXEC_SKIP_LSM_LIST_GATE", "1")
	if sharedSkipLSMListGate() {
		t.Fatal("LSM-list bypass on without the probed-kernel opt-in")
	}
	t.Setenv("IG_ENFORCE_EXEC_PROBED_KERNEL", "1")
	if got := sharedSkipLSMListGate(); got != sharedQualificationBuild {
		t.Fatalf("LSM-list bypass %v in a build with qualification=%v", got, sharedQualificationBuild)
	}
	t.Setenv("IG_ENFORCE_EXEC_PROBED_KERNEL", "true")
	if sharedProbedKernelOverride() {
		t.Fatal("override on with a value other than 1")
	}
}

// TestSharedProbedKernelLiveRefusal (D3 oracle, on the running kernel): a
// kernel that is not an exact pinned build is refused by the candidate gate
// without the test-only override, whatever its probes say; a pinned build is
// admitted. The product gate admits both, as qualified or probed.
// IG_SHARED_PROBED_LIVE=1 (VM).
func TestSharedProbedKernelLiveRefusal(t *testing.T) {
	if os.Getenv("IG_SHARED_PROBED_LIVE") != "1" {
		t.Skip("set IG_SHARED_PROBED_LIVE=1 on a VM")
	}
	old := sharedProbedKernelOverride
	t.Cleanup(func() { sharedProbedKernelOverride = old })
	sharedProbedKernelOverride = func() bool { return false }
	digest, err := kernelBTFDigest()
	if err != nil {
		t.Fatal(err)
	}
	_, pinned := sharedCandidateKernelBTF[digest]
	err = verifySharedCandidateKernel()
	if pinned != (err == nil) {
		t.Fatalf("pinned=%v, candidate gate without the override: %v", pinned, err)
	}
	// The product gate admits a pinned build as qualified; any other build
	// as probed, or refuses it (a VM without the bpf LSM, ftrace off).
	_, pin, perr := verifySharedProductKernel()
	switch {
	case pinned && (perr != nil || pin.Tier != KernelTierQualified):
		t.Fatalf("pinned build, product gate: tier %q %v", pin.Tier, perr)
	case !pinned && perr == nil && pin.Tier != KernelTierProbed:
		t.Fatalf("unpinned build admitted with tier %q", pin.Tier)
	case !pinned && perr != nil && !errors.Is(perr, ErrSharedNativeUnavailable):
		t.Fatalf("unpinned build refused untyped: %v", perr)
	}
	t.Logf("product gate: tier %q %v", pin.Tier, perr)
	t.Logf("pinned=%v candidate gate: %v", pinned, err)
}

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

// TestSharedFmodeBackingPinnedAndProbed: on a pinned kernel the pinned bit
// survives a probe that cannot run and is refused only by a probe that
// contradicts it; elsewhere the probe decides. A refusal is never cached.
func TestSharedFmodeBackingPinnedAndProbed(t *testing.T) {
	oldProbe, oldPinned := fmodeBackingProbe, fmodeBackingPinned
	reset := func() {
		sharedFmodeBackingMu.Lock()
		sharedFmodeBackingValue = 0
		sharedFmodeBackingMu.Unlock()
	}
	t.Cleanup(func() { fmodeBackingProbe, fmodeBackingPinned = oldProbe, oldPinned; reset() })
	boom := errors.New("fsconfig overlay create: invalid argument")
	calls := 0
	set := func(pinned uint32, probed uint32, err error) {
		reset()
		calls = 0
		fmodeBackingPinned = func() (uint32, bool) { return pinned, pinned != 0 }
		fmodeBackingProbe = func(uint32) (uint32, error) { calls++; return probed, err }
	}
	const layout = sharedImageOverlayLayoutRealFile

	set(sharedFmodeBacking24, 0, boom)
	for i := 1; i <= 2; i++ {
		if got, err := sharedFmodeBacking(layout); err != nil || got != sharedFmodeBacking24 {
			t.Fatalf("pinned, probe unavailable: %#x, %v", got, err)
		}
		if calls != i {
			t.Fatalf("pinned, probe unavailable: %d probes after %d calls (the cross-check must be retried)", calls, i)
		}
	}
	set(sharedFmodeBacking24, sharedFmodeBacking25, nil)
	for i := 1; i <= 2; i++ {
		if got, err := sharedFmodeBacking(layout); err == nil || got != 0 || !strings.Contains(err.Error(), "contradicts the pinned bit") {
			t.Fatalf("pinned, probe mismatch: %#x, %v", got, err)
		}
	}
	if calls != 2 {
		t.Fatalf("a mismatch was cached: %d probes", calls)
	}
	set(sharedFmodeBacking24, sharedFmodeBacking24, nil)
	for range 2 {
		if got, err := sharedFmodeBacking(layout); err != nil || got != sharedFmodeBacking24 {
			t.Fatalf("pinned, confirmed: %#x, %v", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("a confirmed bit was not cached: %d probes", calls)
	}
	set(0, 0, boom)
	if got, err := sharedFmodeBacking(layout); !errors.Is(err, boom) || got != 0 {
		t.Fatalf("unpinned, probe failed: %#x, %v", got, err)
	}
	fmodeBackingProbe = func(uint32) (uint32, error) { calls++; return sharedFmodeBacking25, nil }
	if got, err := sharedFmodeBacking(layout); err != nil || got != sharedFmodeBacking25 || calls != 2 {
		t.Fatalf("unpinned, retry after a failure: %#x, %v, %d probes", got, err, calls)
	}
	for digest, pin := range sharedProductPins {
		if pin.FmodeBacking != sharedFmodeBacking24 {
			t.Errorf("pin %s (%s): FMODE_BACKING %#x, want the source-verified bit 24", digest, pin.Release, pin.FmodeBacking)
		}
	}
}

// TestPinnedSharedFmodeBackingNeedsTheBuild: the pinned FMODE_BACKING bit
// is used only on the exact pinned build; a kernel that shares a pinned BTF
// with another release or build-id, or whose identity is unreadable, gets
// none (the live probe then decides, and a failed probe refuses).
func TestPinnedSharedFmodeBackingNeedsTheBuild(t *testing.T) {
	digest := sharedProductPinDigests()[0]
	useProductKernel(t, pinnedProductKernel(digest))
	if bit, ok := pinnedSharedFmodeBacking(); !ok || bit != sharedProductPins[digest].FmodeBacking {
		t.Fatalf("pinned build: %#x %v", bit, ok)
	}
	for name, mutate := range map[string]func(*fakeProductKernel){
		"other build-id":   func(k *fakeProductKernel) { k.buildID = strings.Repeat("0", 40) },
		"other release":    func(k *fakeProductKernel) { k.release = "6.12.114-139.210.amzn2023.x86_64" },
		"unpinned BTF":     func(k *fakeProductKernel) { k.digest = strings.Repeat("0", 64) },
		"unreadable BTF":   func(k *fakeProductKernel) { k.digestErr = os.ErrPermission },
		"unreadable build": func(k *fakeProductKernel) { k.buildIDErr = os.ErrPermission },
	} {
		k := pinnedProductKernel(digest)
		mutate(k)
		useProductKernel(t, k)
		if bit, ok := pinnedSharedFmodeBacking(); ok || bit != 0 {
			t.Errorf("%s: pinned bit %#x used", name, bit)
		}
	}
	// Through sharedFmodeBacking: no pinned bit and a failed probe refuse.
	k := pinnedProductKernel(digest)
	k.buildID = strings.Repeat("0", 40)
	useProductKernel(t, k)
	oldProbe, oldValue := fmodeBackingProbe, sharedFmodeBackingValue
	t.Cleanup(func() { fmodeBackingProbe, sharedFmodeBackingValue = oldProbe, oldValue })
	sharedFmodeBackingValue = 0
	fmodeBackingProbe = func(uint32) (uint32, error) { return 0, errors.New("no layer directory") }
	if bit, err := sharedFmodeBacking(sharedImageOverlayLayoutOvlFile); err == nil || bit != 0 {
		t.Fatalf("probed kernel with a failed probe: %#x %v", bit, err)
	}
}
