// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestSharedProductObjectsMatchTestdata (D3): sharedProductObjects equals
// testdata/shared_product_objects.tsv, one object per profile for every
// kernel (bpf/build-product.sh --check rebuilds them).
func TestSharedProductObjectsMatchTestdata(t *testing.T) {
	data, err := os.ReadFile("testdata/shared_product_objects.tsv")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 2 || !isLowerHex(fields[1], 64) {
			t.Fatalf("testdata line %q", line)
		}
		got[fields[0]] = fields[1]
	}
	if !maps.Equal(got, sharedProductObjects) || len(got) != 4 {
		t.Fatalf("testdata %v, sharedProductObjects %v", got, sharedProductObjects)
	}
	for _, sum := range got {
		if !sharedProductObject(sum) || sharedProductObject(strings.ToUpper(sum)) || sharedProductObject("") {
			t.Fatalf("sharedProductObject(%s)", sum)
		}
	}
}

// fakeProductKernel is a kernel identity as the probe reads it.
type fakeProductKernel struct {
	arch, digest, release, buildID, lsm, ftrace, tainted             string
	digestErr, releaseErr, buildIDErr, lsmErr, ftraceErr, taintedErr error
}

func (k *fakeProductKernel) probe() sharedProductKernelProbe {
	return sharedProductKernelProbe{
		arch:      func() string { return k.arch },
		btfDigest: func() (string, error) { return k.digest, k.digestErr },
		release:   func() (string, error) { return k.release, k.releaseErr },
		buildID:   func() (string, error) { return k.buildID, k.buildIDErr },
		lsm:       func() (string, error) { return k.lsm, k.lsmErr },
		ftrace:    func() (string, error) { return k.ftrace, k.ftraceErr },
		tainted:   func() (string, error) { return k.tainted, k.taintedErr },
	}
}

// useProductKernel installs k as the product kernel probe for the test.
func useProductKernel(t *testing.T, k *fakeProductKernel) {
	t.Helper()
	old := sharedProductKernelProbes
	sharedProductKernelProbes = k.probe()
	t.Cleanup(func() { sharedProductKernelProbes = old })
}

// arbitraryProductKernel is a healthy fake kernel build (an Ubuntu build).
func arbitraryProductKernel() *fakeProductKernel {
	return &fakeProductKernel{
		arch: "amd64", digest: strings.Repeat("e1", 32), release: "7.0.0-43-generic", buildID: strings.Repeat("5a", 20),
		lsm: "lockdown,capability,landlock,yama,apparmor,bpf\n", ftrace: "1\n", tainted: "0\n",
	}
}

// otherProductKernel is another healthy fake kernel build (a Debian build),
// with a different identity and LSM list.
func otherProductKernel() *fakeProductKernel {
	return &fakeProductKernel{
		arch: "amd64", digest: strings.Repeat("0d", 32), release: "6.12.48+deb13-amd64", buildID: strings.Repeat("1d", 20),
		lsm: "lockdown,capability,landlock,yama,safesetid,selinux,bpf,ima\n", ftrace: "1\n", tainted: "0\n",
	}
}

// productGateKernels are the kernels the gate tests run on: two healthy
// builds and one whose release carries a suffix.
func productGateKernels() map[string]*fakeProductKernel {
	suffix := otherProductKernel()
	suffix.release += "+"
	return map[string]*fakeProductKernel{"ubuntu build": arbitraryProductKernel(), "debian build": otherProductKernel(), "release suffix": suffix}
}

// TestSharedProductKernelGate: every kernel goes through the same checks.
// Each healthy kernel is admitted with its own identity; on each of them a
// wrong architecture, an unreadable or malformed identity and every failed
// control is refused with the same check, wrapping both the
// *KernelCheckError and ErrSharedNativeUnavailable.
func TestSharedProductKernelGate(t *testing.T) {
	cases := map[string]struct {
		mutate func(*fakeProductKernel)
		check  string
		reason string
	}{
		"uppercase digest":           {func(k *fakeProductKernel) { k.digest = strings.ToUpper(k.digest) }, KernelCheckBTF, "not lowercase hex"},
		"digest read error":          {func(k *fakeProductKernel) { k.digestErr = os.ErrPermission }, KernelCheckBTF, "kernel BTF"},
		"release read error":         {func(k *fakeProductKernel) { k.releaseErr = os.ErrPermission }, KernelCheckRelease, "kernel release"},
		"release empty":              {func(k *fakeProductKernel) { k.release = "\n" }, KernelCheckRelease, "empty kernel release"},
		"build-id read error":        {func(k *fakeProductKernel) { k.buildIDErr = os.ErrPermission }, KernelCheckBuildID, "build-id"},
		"build-id empty":             {func(k *fakeProductKernel) { k.buildID = "" }, KernelCheckBuildID, "build-id"},
		"build-id malformed":         {func(k *fakeProductKernel) { k.buildID = "xyz" }, KernelCheckBuildID, "not lowercase hex"},
		"livepatch taint":            {func(k *fakeProductKernel) { k.tainted = "32768\n" }, KernelCheckLivepatch, "livepatched"},
		"livepatch with other taint": {func(k *fakeProductKernel) { k.tainted = fmt.Sprint(1<<15 | 1<<12) }, KernelCheckLivepatch, "livepatched"},
		"malformed taint":            {func(k *fakeProductKernel) { k.tainted = "x" }, KernelCheckLivepatch, "kernel taint"},
		"no bpf LSM":                 {func(k *fakeProductKernel) { k.lsm = "lockdown,capability,selinux" }, KernelCheckBPFLSM, "BPF LSM not active"},
		"bpf LSM prefix only":        {func(k *fakeProductKernel) { k.lsm = "bpfx,selinux" }, KernelCheckBPFLSM, "BPF LSM not active"},
		"ftrace off":                 {func(k *fakeProductKernel) { k.ftrace = "0\n" }, KernelCheckFtrace, "ftrace is not enabled"},
		"ftrace read error":          {func(k *fakeProductKernel) { k.ftraceErr = os.ErrPermission }, KernelCheckFtrace, "ftrace_enabled"},
		"non-amd64":                  {func(k *fakeProductKernel) { k.arch = "arm64" }, KernelCheckArch, "requires amd64, running on arm64"},
	}
	for kname, healthy := range productGateKernels() {
		useProductKernel(t, healthy)
		want := KernelIdentity{Arch: "amd64", Release: healthy.release, BTF: healthy.digest, BuildID: healthy.buildID}
		if got, err := SharedProductKernel(); err != nil || got != want {
			t.Fatalf("%s: %+v %v, want %+v", kname, got, err, want)
		}
		if got, err := verifySharedProductKernel(); err != nil || got != want {
			t.Fatalf("%s: verifySharedProductKernel %+v %v", kname, got, err)
		}
		for name, tc := range cases {
			t.Run(kname+"/"+name, func(t *testing.T) {
				k := *healthy
				tc.mutate(&k)
				useProductKernel(t, &k)
				got, err := SharedProductKernel()
				var kerr *KernelCheckError
				if !errors.As(err, &kerr) || kerr.Check != tc.check || !errors.Is(err, ErrSharedNativeUnavailable) || got != (KernelIdentity{}) ||
					!strings.Contains(err.Error(), tc.reason) || !strings.Contains(err.Error(), "shared product node refused") {
					t.Fatalf("got %+v err %v, want check %q with %q and ErrSharedNativeUnavailable", got, err, tc.check, tc.reason)
				}
			})
		}
	}
	// A tainted bit other than TAINT_LIVEPATCH is not this gate's concern.
	k := arbitraryProductKernel()
	k.tainted = fmt.Sprint(1 << 12)
	useProductKernel(t, k)
	if _, err := verifySharedProductKernel(); err != nil {
		t.Fatalf("out-of-tree taint alone: %v", err)
	}
}

// TestSharedProductKernelBuildsIdentical: two different kernel builds go
// through the identical path. With the same controls they get the same
// outcome from SharedProductKernel, AdmitKernel, the FMODE_BACKING bit (the
// live probe on both, a failed probe refusing on both) and the product
// image admission (the same product objects on both, an unknown object
// refused on both); the kernel identity never enters the decision.
func TestSharedProductKernelBuildsIdentical(t *testing.T) {
	type outcome struct {
		gate, admit, fmodeOK, fmodeFail string
		images                          []string
	}
	errString := func(err error) string {
		var kerr *KernelCheckError
		switch {
		case err == nil:
			return "ok"
		case errors.As(err, &kerr):
			return "refused " + kerr.Check
		default:
			return "refused"
		}
	}
	oldProbe, oldValue := fmodeBackingProbe, sharedFmodeBackingValue
	t.Cleanup(func() { fmodeBackingProbe, sharedFmodeBackingValue = oldProbe, oldValue })
	run := func(k *fakeProductKernel) outcome {
		useProductKernel(t, k)
		var o outcome
		_, err := SharedProductKernel()
		o.gate = errString(err)
		_, err = AdmitKernel()
		o.admit = errString(err)
		sharedFmodeBackingValue = 0
		fmodeBackingProbe = func(uint32) (uint32, error) { return sharedFmodeBacking25, nil }
		bit, err := sharedFmodeBacking(sharedImageOverlayLayoutOvlFile)
		o.fmodeOK = fmt.Sprintf("%#x %v", bit, err)
		sharedFmodeBackingValue = 0
		fmodeBackingProbe = func(uint32) (uint32, error) { return 0, errors.New("no layer directory") }
		bit, err = sharedFmodeBacking(sharedImageOverlayLayoutOvlFile)
		o.fmodeFail = fmt.Sprintf("%#x %v", bit, err)
		sharedFmodeBackingValue = 0
		for _, object := range []string{sharedProductObjects["g19pkg64"], sharedProductObjects["g19pkg512"], strings.Repeat("cd", 32)} {
			err := admitSharedProductImage(sharedProductImageContext(object), sharedProductImageMetadata(), sharedProductResources())
			if err != nil && !errors.Is(err, ErrSharedNativeUnavailable) {
				t.Fatalf("untyped image refusal: %v", err)
			}
			o.images = append(o.images, errString(err))
		}
		return o
	}
	for name, mutate := range map[string]func(*fakeProductKernel){
		"healthy":    func(*fakeProductKernel) {},
		"no bpf LSM": func(k *fakeProductKernel) { k.lsm = "selinux" },
		"ftrace off": func(k *fakeProductKernel) { k.ftrace = "0" },
		"livepatch":  func(k *fakeProductKernel) { k.tainted = "32768" },
		"arm64":      func(k *fakeProductKernel) { k.arch = "arm64" },
	} {
		arbitrary := arbitraryProductKernel()
		mutate(arbitrary)
		want := run(arbitrary)
		other := otherProductKernel()
		mutate(other)
		if got := run(other); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %s %+v, %s %+v", name, other.release, got, arbitrary.release, want)
		}
		if name == "healthy" && (want.gate != "ok" || want.admit != "ok" || want.fmodeOK != "0x2000000 <nil>" || want.fmodeFail == "0x0 <nil>" ||
			!reflect.DeepEqual(want.images, []string{"ok", "ok", "refused"})) {
			t.Errorf("healthy kernels: %+v", want)
		}
	}
}

// TestKernelBTFDigestCachesOnlySuccess: a failed digest read is retried, a
// successful one is cached.
func TestKernelBTFDigestCachesOnlySuccess(t *testing.T) {
	kernelBTFDigestMu.Lock()
	oldValue, oldRead := kernelBTFDigestValue, kernelBTFRead
	kernelBTFDigestValue = ""
	kernelBTFDigestMu.Unlock()
	t.Cleanup(func() {
		kernelBTFDigestMu.Lock()
		kernelBTFDigestValue, kernelBTFRead = oldValue, oldRead
		kernelBTFDigestMu.Unlock()
	})
	reads := 0
	fail := os.ErrNotExist
	kernelBTFRead = func() ([]byte, error) { reads++; return []byte("btf"), fail }
	if _, err := kernelBTFDigest(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first read: %v", err)
	}
	fail = nil
	digest, err := kernelBTFDigest()
	sum := sha256.Sum256([]byte("btf"))
	if err != nil || digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("retry: %q %v", digest, err)
	}
	fail = os.ErrPermission
	if again, err := kernelBTFDigest(); err != nil || again != digest || reads != 2 {
		t.Fatalf("cached: %q %v reads %d", again, err, reads)
	}
}

// buildNote encodes one ELF note (native endian, 4-byte padding).
func buildNote(name string, typ uint32, desc []byte) []byte {
	n := []byte(name)
	out := binary.NativeEndian.AppendUint32(nil, uint32(len(n)))
	out = binary.NativeEndian.AppendUint32(out, uint32(len(desc)))
	out = binary.NativeEndian.AppendUint32(out, typ)
	out = append(out, n...)
	out = append(out, make([]byte, int(align4(uint64(len(n))))-len(n))...)
	out = append(out, desc...)
	return append(out, make([]byte, int(align4(uint64(len(desc))))-len(desc))...)
}

func TestParseGNUBuildID(t *testing.T) {
	id := []byte{0x1d, 0x13, 0x5d, 0x67, 0xe6, 0xd0, 0xea, 0x8f, 0x77, 0xd6, 0x0a, 0x29, 0x84, 0x91, 0x5e, 0xad, 0xd2, 0x8a, 0x5f, 0xcf}
	linux := buildNote("Linux\x00", 0x101, []byte{6, 0, 0, 0})
	version := buildNote("Linux\x00", 6, []byte("6.12.113\x00"))
	gnu := buildNote("GNU\x00", ntGNUBuildID, id)
	cases := []struct {
		name  string
		notes []byte
		want  string
	}{
		{"build-id after Linux notes (kernel layout)", slices.Concat(linux, version, gnu), "1d135d67e6d0ea8f77d60a2984915eadd28a5fcf"},
		{"build-id only", gnu, "1d135d67e6d0ea8f77d60a2984915eadd28a5fcf"},
		{"odd descriptor length", buildNote("GNU\x00", ntGNUBuildID, []byte{1, 2, 3}), "010203"},
		{"empty", nil, ""},
		{"no build-id", slices.Concat(linux, version), ""},
		{"GNU note of another type", buildNote("GNU\x00", 1, id), ""},
		{"build-id type under another name", buildNote("Linux\x00", ntGNUBuildID, id), ""},
		{"name without NUL", buildNote("GNU", ntGNUBuildID, id), ""},
		{"duplicate build-id", slices.Concat(gnu, gnu), ""},
		{"empty descriptor", buildNote("GNU\x00", ntGNUBuildID, nil), ""},
		{"truncated header", gnu[:11], ""},
		{"truncated descriptor", gnu[:len(gnu)-4], ""},
		{"trailing bytes", append(slices.Clone(gnu), 0, 0), ""},
		{"huge sizes", binary.NativeEndian.AppendUint32(binary.NativeEndian.AppendUint32(binary.NativeEndian.AppendUint32(nil, 0xffffffff), 0xffffffff), 3), ""},
	}
	for _, tc := range cases {
		got, err := parseGNUBuildID(tc.notes)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: accepted %q", tc.name, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: %q %v, want %q", tc.name, got, err, tc.want)
		}
	}
}

func FuzzParseGNUBuildID(f *testing.F) {
	f.Add(buildNote("GNU\x00", ntGNUBuildID, []byte{1, 2, 3, 4}))
	f.Add(slices.Concat(buildNote("Linux\x00", 6, []byte("x")), buildNote("GNU\x00", ntGNUBuildID, []byte{9})))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, notes []byte) {
		got, err := parseGNUBuildID(notes)
		if err == nil && (got == "" || len(got)%2 != 0 || len(got)/2 > len(notes)) {
			t.Fatalf("accepted %q from %d bytes", got, len(notes))
		}
	})
}

// TestReadProcSysRequiresProcfs (review L4): a kernel control is read only
// from procfs.
func TestReadProcSysRequiresProcfs(t *testing.T) {
	if v, err := readProcSys("/proc/sys/kernel/ostype"); err != nil || strings.TrimSpace(v) != "Linux" {
		t.Fatalf("procfs read: %q %v", v, err)
	}
	fake := t.TempDir() + "/ftrace_enabled"
	if err := os.WriteFile(fake, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := readProcSys(fake); err == nil || !strings.Contains(err.Error(), "not on procfs") {
		t.Fatalf("non-procfs read accepted: %q %v", v, err)
	}
	if _, err := readProcSys("/proc/sys/kernel/does-not-exist"); err == nil {
		t.Fatal("missing control accepted")
	}
	// Through the gate, a non-procfs ftrace control is a typed refusal.
	k := arbitraryProductKernel()
	useProductKernel(t, k)
	sharedProductKernelProbes.ftrace = func() (string, error) { return readProcSys(fake) }
	if _, err := verifySharedProductKernel(); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "not on procfs") {
		t.Fatalf("gate with a non-procfs control: %v", err)
	}
}
