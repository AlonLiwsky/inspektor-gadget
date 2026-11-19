// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestSharedProductPinsMatchTestdata: the compiled pins equal the step-0
// record in testdata/shared_product_pins.tsv, field by field.
func TestSharedProductPinsMatchTestdata(t *testing.T) {
	f, err := os.Open("testdata/shared_product_pins.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<16)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("testdata line %q: %d fields, want 4", line, len(fields))
		}
		release, digest, buildID := fields[0], fields[1], fields[2]
		pin, ok := sharedProductPins[digest]
		if !ok {
			t.Fatalf("testdata BTF %s (%s) is not pinned", digest, release)
		}
		seen[digest] = true
		if pin.Release != release || pin.BuildID != buildID {
			t.Errorf("pin %s = %+v, testdata %q", digest, pin, fields)
		}
		// The qualified objects, in profile order (the stage-1 objects).
		qualified := strings.Split(fields[3], ",")
		if len(qualified) != len(pin.ProductObjects) {
			t.Errorf("pin %s: testdata qualifies %d objects, ProductObjects %d", release, len(qualified), len(pin.ProductObjects))
		}
		for i, obj := range qualified {
			if _, ok := pin.ProductObjects[obj]; !ok || obj != sharedProductObjects[sharedProductProfiles[i].Name] {
				t.Errorf("pin %s: testdata object %d %s is not ProductObjects' %s object", release, i, obj, sharedProductProfiles[i].Name)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(sharedProductPins) {
		t.Fatalf("testdata covers %d of %d pins", len(seen), len(sharedProductPins))
	}
}

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

// fakeProductKernel is a pinned kernel's identity as the probe reads it.
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

// pinnedProductKernel is a healthy fake of the pinned build digest.
func pinnedProductKernel(digest string) *fakeProductKernel {
	pin := sharedProductPins[digest]
	return &fakeProductKernel{
		arch: "amd64", digest: digest, release: pin.Release, buildID: pin.BuildID,
		lsm: "lockdown,capability,landlock,yama,safesetid,selinux,bpf,ima\n", ftrace: "1\n", tainted: "0\n",
	}
}

// useProductKernel installs k as the product kernel probe for the test.
func useProductKernel(t *testing.T, k *fakeProductKernel) {
	t.Helper()
	old := sharedProductKernelProbes
	sharedProductKernelProbes = k.probe()
	t.Cleanup(func() { sharedProductKernelProbes = old })
}

func sharedProductPinDigests() []string {
	var out []string
	for digest := range sharedProductPins {
		out = append(out, digest)
	}
	slices.Sort(out)
	return out
}

// TestSharedProductKernelGate (plan 3.1, gate part): each pin passes; every
// other identity or control is refused with ErrSharedNativeUnavailable and
// a reason.
func TestSharedProductKernelGate(t *testing.T) {
	digests := sharedProductPinDigests()
	for _, digest := range digests {
		useProductKernel(t, pinnedProductKernel(digest))
		got, pin, err := verifySharedProductKernel()
		if err != nil || got != digest || pin.Release != sharedProductPins[digest].Release {
			t.Fatalf("pin %s: digest %q pin %+v err %v", digest, got, pin, err)
		}
	}
	other := digests[1]
	cases := map[string]struct {
		mutate func(*fakeProductKernel)
		reason string
	}{
		"unpinned digest":            {func(k *fakeProductKernel) { k.digest = strings.Repeat("0", 64) }, "not a qualified"},
		"persistent-owner BTF":       {func(k *fakeProductKernel) { k.digest = SupportedKernelBTF }, "not a qualified"},
		"persistent-owner k8s BTF":   {func(k *fakeProductKernel) { k.digest = SupportedKubernetesKernelBTF }, "not a qualified"},
		"uppercase digest":           {func(k *fakeProductKernel) { k.digest = strings.ToUpper(k.digest) }, "not a qualified"},
		"digest read error":          {func(k *fakeProductKernel) { k.digestErr = os.ErrPermission }, "kernel BTF"},
		"release mismatch":           {func(k *fakeProductKernel) { k.release = sharedProductPins[other].Release }, "kernel release"},
		"release suffix":             {func(k *fakeProductKernel) { k.release += "+" }, "kernel release"},
		"build-id mismatch":          {func(k *fakeProductKernel) { k.buildID = sharedProductPins[other].BuildID }, "build-id"},
		"build-id empty":             {func(k *fakeProductKernel) { k.buildID = "" }, "build-id"},
		"livepatch taint":            {func(k *fakeProductKernel) { k.tainted = "32768\n" }, "livepatched"},
		"livepatch with other taint": {func(k *fakeProductKernel) { k.tainted = fmt.Sprint(1<<15 | 1<<12) }, "livepatched"},
		"malformed taint":            {func(k *fakeProductKernel) { k.tainted = "x" }, "kernel taint"},
		"no bpf LSM":                 {func(k *fakeProductKernel) { k.lsm = "lockdown,capability,selinux" }, "BPF LSM not active"},
		"bpf LSM prefix only":        {func(k *fakeProductKernel) { k.lsm = "bpfx,selinux" }, "BPF LSM not active"},
		"ftrace off":                 {func(k *fakeProductKernel) { k.ftrace = "0\n" }, "ftrace is not enabled"},
		"non-amd64":                  {func(k *fakeProductKernel) { k.arch = "arm64" }, "require amd64, running on arm64"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			k := pinnedProductKernel(digests[0])
			tc.mutate(k)
			useProductKernel(t, k)
			digest, _, err := verifySharedProductKernel()
			if !errors.Is(err, ErrSharedNativeUnavailable) || digest != "" || !strings.Contains(err.Error(), tc.reason) || !strings.Contains(err.Error(), "shared product node refused") {
				t.Fatalf("err %v digest %q, want ErrSharedNativeUnavailable with %q", err, digest, tc.reason)
			}
		})
	}
	// A tainted bit other than TAINT_LIVEPATCH is not this gate's concern.
	k := pinnedProductKernel(digests[0])
	k.tainted = fmt.Sprint(1 << 12)
	useProductKernel(t, k)
	if _, _, err := verifySharedProductKernel(); err != nil {
		t.Fatalf("out-of-tree taint alone: %v", err)
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
	k := pinnedProductKernel(sharedProductPinDigests()[0])
	useProductKernel(t, k)
	sharedProductKernelProbes.ftrace = func() (string, error) { return readProcSys(fake) }
	if _, _, err := verifySharedProductKernel(); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "not on procfs") {
		t.Fatalf("gate with a non-procfs control: %v", err)
	}
}
