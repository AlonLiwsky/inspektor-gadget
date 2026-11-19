// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestSupportedKernelBTFExactMatrix(t *testing.T) {
	for _, digest := range []string{SupportedKernelBTF, SupportedKubernetesKernelBTF} {
		if !supportedKernelBTF(digest) {
			t.Fatalf("known exact artifact rejected: %s", digest)
		}
		for _, unknown := range []string{"", digest[:63], digest + "0", "0" + digest[1:], strings.ToUpper(digest), digest + "\n", " " + digest} {
			if supportedKernelBTF(unknown) {
				t.Fatalf("nonexact artifact accepted: %q", unknown)
			}
		}
	}
	if supportedKernelBTF(strings.Repeat("0", 64)) {
		t.Fatal("unknown digest accepted")
	}
}

func TestOwnerBuilderKernelMatrixMatchesRuntime(t *testing.T) {
	builder, err := os.ReadFile("../full/owner/build-archive.sh")
	if err != nil {
		t.Fatal(err)
	}
	for name, digest := range map[string]string{"expected_btf": SupportedKernelBTF, "kubernetes_btf": SupportedKubernetesKernelBTF} {
		if !strings.Contains(string(builder), "\n"+name+"="+digest+"\n") {
			t.Fatalf("builder %s differs from runtime matrix", name)
		}
	}
}

// TestSharedCandidateKernelMatrixIsSeparate: the shared product pins are
// exactly the two qualified AL2023 kernel builds (every field literal), the
// candidate matrix is derived from them, and neither shares anything with
// the persistent-owner matrix in either direction.
func TestSharedCandidateKernelMatrixIsSeparate(t *testing.T) {
	want := map[string]sharedProductPin{
		"0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82": {
			Release: "6.12.113-138.209.amzn2023.x86_64", BuildID: "1d135d67e6d0ea8f77d60a2984915eadd28a5fcf",
			FmodeBacking: 1 << 24, ProductObjects: map[string]struct{}{"da796db9846e32d64b475fb2b7dbd33178e297c5630e9303c3dc57c60d9f119f": {}, "8bc88d1505dac04fa744cf9d2f0af511b2337da8dd889efa5798c64977f51987": {}, "74b21461d18e98d6336cac320e7f830a5ee8e441198e3053dcf68b98ad093845": {}, "206decf3344b9f7c90dd285d36ec653dbf5f557ef081d986fa4e56c6cd726b35": {}},
		},
		"d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee": {
			Release: "6.18.56-125.164.amzn2023.x86_64", BuildID: "884ed4548406a1461ac5fb658c0dffdd87f1b3b2",
			FmodeBacking: 1 << 24, ProductObjects: map[string]struct{}{"da796db9846e32d64b475fb2b7dbd33178e297c5630e9303c3dc57c60d9f119f": {}, "8bc88d1505dac04fa744cf9d2f0af511b2337da8dd889efa5798c64977f51987": {}, "74b21461d18e98d6336cac320e7f830a5ee8e441198e3053dcf68b98ad093845": {}, "206decf3344b9f7c90dd285d36ec653dbf5f557ef081d986fa4e56c6cd726b35": {}},
		},
	}
	if !reflect.DeepEqual(sharedProductPins, want) {
		t.Fatalf("shared product pins %+v, want %+v", sharedProductPins, want)
	}
	if len(sharedCandidateKernelBTF) != len(want) {
		t.Fatalf("shared candidate matrix %v", sharedCandidateKernelBTF)
	}
	for digest, pin := range want {
		if sharedCandidateKernelBTF[digest] != pin.Release {
			t.Errorf("candidate matrix %s = %q, want %q", digest, sharedCandidateKernelBTF[digest], pin.Release)
		}
		if supportedKernelBTF(digest) {
			t.Errorf("shared candidate kernel %s admitted by the persistent-owner matrix", pin.Release)
		}
	}
	for _, digest := range []string{SupportedKernelBTF, SupportedKubernetesKernelBTF} {
		if _, ok := sharedCandidateKernelBTF[digest]; ok {
			t.Errorf("persistent-owner kernel %s in the shared candidate matrix", digest)
		}
		if _, ok := sharedProductPins[digest]; ok {
			t.Errorf("persistent-owner kernel %s in the shared product pins", digest)
		}
	}
}

// TestMain makes the node-level unit tests host-independent: the overlay
// layout read is faked (as on a matrix kernel with overlay loaded) unless a
// live VM test (IG_SHARED_OVL_BTF / IG_SHARED_OVL_AUTOLOAD) uses the real one,
// or the binary runs on an exact shared-candidate kernel: there every
// attached test loads real objects, whose classifier must get that kernel's
// own layout (a faked 6.18 OVL_FILE on 6.12 dereferenced the realfile as an
// ovl_file: every image fact READ_FAULT/UNKNOWN, G020 6.12 image failure).
func TestMain(m *testing.M) {
	// D3: under the test-only probed-kernel override the attached tests run
	// on a stock kernel and need its real layout and FMODE_BACKING probe too.
	if os.Getenv("IG_SHARED_OVL_BTF") != "1" && os.Getenv("IG_SHARED_OVL_AUTOLOAD") != "1" && !onSharedCandidateKernel() && !sharedProbedKernelOverride() {
		overlayLayoutReader = func() (uint32, error) { return sharedImageOverlayLayoutOvlFile, nil }
		overlayModuleLoader = func() error { return nil }
		fmodeBackingReader = func(uint32) (uint32, error) { return sharedFmodeBacking24, nil }
	}
	os.Exit(m.Run())
}

// onSharedCandidateKernel: the running kernel's BTF is one of the exact
// shared-candidate matrix kernels.
func onSharedCandidateKernel() bool {
	digest, err := kernelBTFDigest()
	if err != nil {
		return false
	}
	_, ok := sharedCandidateKernelBTF[digest]
	return ok
}

// sharedImageOverlayLayoutsPinned are the source-verified layouts of the two
// pinned builds (6.12 fs/overlayfs/file.c:170, 6.18 file.c:92-95,232). D3:
// production no longer has this table (the layout is derived from the
// overlay BTF shape); the tests keep it to assert that the derivation gives
// the source-verified value on the pinned builds.
var sharedImageOverlayLayoutsPinned = map[string]uint32{
	"6.12.113-138.209.amzn2023.x86_64": sharedImageOverlayLayoutRealFile,
	"6.18.56-125.164.amzn2023.x86_64":  sharedImageOverlayLayoutOvlFile,
}

// TestSharedImageOverlayLayoutExactMatrix: the shape derivation gives every
// pinned kernel its source-verified layout, and the values match the
// classifier header.
func TestSharedImageOverlayLayoutExactMatrix(t *testing.T) {
	if len(sharedImageOverlayLayoutsPinned) != len(sharedCandidateKernelBTF) {
		t.Fatalf("layout matrix %v differs from kernel matrix %v", sharedImageOverlayLayoutsPinned, sharedCandidateKernelBTF)
	}
	for _, release := range sharedCandidateKernelBTF {
		want := sharedImageOverlayLayoutsPinned[release]
		got, err := sharedImageOverlayLayout(overlaySpecForLayout(t, want))
		if err != nil || got != want || got == sharedImageOverlayLayoutUnset {
			t.Errorf("%s: layout %d err %v, want %d", release, got, err, want)
		}
	}
	header, err := os.ReadFile("../full/shared_image_classify.h")
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]uint32{
		"SE_IMAGE_OVL_LAYOUT_UNSET":    sharedImageOverlayLayoutUnset,
		"SE_IMAGE_OVL_LAYOUT_REALFILE": sharedImageOverlayLayoutRealFile,
		"SE_IMAGE_OVL_LAYOUT_OVL_FILE": sharedImageOverlayLayoutOvlFile,
	} {
		if !strings.Contains(string(header), fmt.Sprintf("#define %s %d", name, value)) {
			t.Errorf("header %s differs from Go value %d", name, value)
		}
	}
}

// overlaySpecForLayout builds a synthetic overlay module BTF: 6.18 shape
// (struct ovl_file {file *realfile; file *upperfile}) or, for the realfile
// layout, a spec without struct ovl_file.
func overlaySpecForLayout(t *testing.T, layout uint32) *btf.Spec {
	t.Helper()
	if layout == sharedImageOverlayLayoutRealFile {
		return ovlSpec(t, nil)
	}
	file := &btf.Struct{Name: "file", Size: 8}
	ptr := &btf.Pointer{Target: file}
	return ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 16, Members: []btf.Member{
		{Name: "realfile", Type: ptr, Offset: 0},
		{Name: "upperfile", Type: ptr, Offset: 64},
	}})
}

func ovlSpec(t *testing.T, ovl *btf.Struct) *btf.Spec {
	t.Helper()
	types := []btf.Type{&btf.Struct{Name: "unrelated", Size: 4}, &btf.Struct{Name: "ovl_inode", Size: 8}}
	if ovl != nil {
		types = append(types, ovl)
	}
	b, err := btf.NewBuilder(types, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := b.Spec()
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// TestSharedImageOverlayLayoutShape (review M6, D3): the layout comes from the
// overlay BTF shape alone. A missing BTF, a BTF without overlayfs's own types
// (the absence of struct ovl_file then proves nothing), a struct ovl_file
// without a struct file *realfile member and a duplicated struct ovl_file
// select UNSET. The realfile offset and the other members are not pinned:
// the object relocates the access (CO-RE).
func TestSharedImageOverlayLayoutShape(t *testing.T) {
	file := &btf.Struct{Name: "file", Size: 8}
	ptr := &btf.Pointer{Target: file}
	member := func(name string, off uint32) btf.Member {
		return btf.Member{Name: name, Type: ptr, Offset: btf.Bits(off)}
	}
	noWitness := func(ovl *btf.Struct) *btf.Spec {
		types := []btf.Type{&btf.Struct{Name: "unrelated", Size: 4}}
		if ovl != nil {
			types = append(types, ovl)
		}
		b, err := btf.NewBuilder(types, nil)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := b.Spec()
		if err != nil {
			t.Fatal(err)
		}
		return spec
	}
	refused := []struct {
		name string
		spec *btf.Spec
	}{
		{"overlay BTF missing", nil},
		{"no overlayfs types, ovl_file absent", noWitness(nil)},
		{"no overlayfs types, ovl_file present", noWitness(&btf.Struct{Name: "ovl_file", Size: 16, Members: []btf.Member{member("realfile", 0), member("upperfile", 64)}})},
		{"no realfile member", ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 16, Members: []btf.Member{member("upperfile", 0), member("x", 64)}})},
		{"realfile not a pointer", ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 16, Members: []btf.Member{{Name: "realfile", Type: &btf.Int{Name: "long", Size: 8}, Offset: 0}}})},
		{"realfile not a struct file pointer", ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 16, Members: []btf.Member{{Name: "realfile", Type: &btf.Pointer{Target: &btf.Struct{Name: "path", Size: 16}}, Offset: 0}}})},
	}
	for _, tc := range refused {
		if got, err := sharedImageOverlayLayout(tc.spec); err == nil || got != sharedImageOverlayLayoutUnset {
			t.Errorf("%s: layout %d err %v, want UNSET and error", tc.name, got, err)
		}
	}
	accepted := []struct {
		name string
		spec *btf.Spec
		want uint32
	}{
		{"ovl_file absent", ovlSpec(t, nil), sharedImageOverlayLayoutRealFile},
		{"6.18 shape", overlaySpecForLayout(t, sharedImageOverlayLayoutOvlFile), sharedImageOverlayLayoutOvlFile},
		{"realfile moved (relocated by CO-RE)", ovlSpec(t, &btf.Struct{Name: "ovl_file", Size: 24, Members: []btf.Member{member("upperfile", 0), member("realfile", 64), member("x", 128)}}), sharedImageOverlayLayoutOvlFile},
	}
	for _, tc := range accepted {
		if got, err := sharedImageOverlayLayout(tc.spec); err != nil || got != tc.want {
			t.Errorf("%s: layout %d err %v, want %d", tc.name, got, err, tc.want)
		}
	}
}

// TestResolveSharedImageOverlayLayoutAutoload: an absent overlay module BTF
// triggers one autoload then a re-read; a failed autoload or a non-ENOENT
// error does not; failures are recorded as the node's unavailable reason.
func TestResolveSharedImageOverlayLayoutAutoload(t *testing.T) {
	oldRead, oldLoad := overlayLayoutReader, overlayModuleLoader
	t.Cleanup(func() {
		overlayLayoutReader, overlayModuleLoader = oldRead, oldLoad
		sharedOverlayLayoutFailure.Store(nil)
	})
	loaded, loads := false, 0
	overlayLayoutReader = func() (uint32, error) {
		if !loaded {
			return 0, fmt.Errorf("overlay module BTF: %w", os.ErrNotExist)
		}
		return sharedImageOverlayLayoutOvlFile, nil
	}
	overlayModuleLoader = func() error { loads++; loaded = true; return nil }
	if got, err := resolveSharedImageOverlayLayout(); err != nil || got != sharedImageOverlayLayoutOvlFile || loads != 1 {
		t.Fatalf("autoload path: layout %d err %v loads %d", got, err, loads)
	}
	// Autoload fails: UNSET and a reason reaches the node.
	loaded, loads = false, 0
	overlayModuleLoader = func() error { loads++; return fmt.Errorf("EPERM") }
	if got, err := resolveSharedImageOverlayLayout(); err == nil || got != sharedImageOverlayLayoutUnset || loads != 1 {
		t.Fatalf("failed autoload: layout %d err %v loads %d", got, err, loads)
	}
	c, err := sharedImageOverlayConstants()
	if err != nil || c[sharedImageOverlayLayoutConstant] != sharedImageOverlayLayoutUnset {
		t.Fatalf("constants %v err %v", c, err)
	}
	if err := sharedImageOverlayUnavailable(); err == nil || !strings.Contains(err.Error(), "EPERM") {
		t.Fatalf("unavailable reason %v", err)
	}
	// Non-ENOENT errors (shape mismatch) never autoload.
	loads = 0
	overlayLayoutReader = func() (uint32, error) { return 0, fmt.Errorf("shape mismatch") }
	if _, err := resolveSharedImageOverlayLayout(); err == nil || loads != 0 {
		t.Fatalf("mismatch must not autoload: err %v loads %d", err, loads)
	}
	// Recovery clears the reason.
	overlayLayoutReader = func() (uint32, error) { return sharedImageOverlayLayoutRealFile, nil }
	if _, err := sharedImageOverlayConstants(); err != nil || sharedImageOverlayUnavailable() != nil {
		t.Fatalf("reason not cleared: %v", err)
	}
}

// TestSharedLiveHealthOverlayUnavailable: an unavailable overlay layout is
// Degraded, never a startup failure: the live health stays clean, the node's
// Ready reports it (FromImage refused), and the image build refuses.
func TestSharedLiveHealthOverlayUnavailable(t *testing.T) {
	boom := fmt.Errorf("overlay layout unavailable: boom")
	if e := (sharedLiveHealth{image: healthyImage{}}).check(); e != nil {
		t.Fatalf("startup health %v", e)
	}
	n := &NodeEnforcer{host: &sharedHostState{}}
	if e := n.overlayDegraded(); e != nil {
		t.Fatalf("Degraded without a reason: %v", e)
	}
	n.host.overlayFailure.Store(&boom)
	if e := n.overlayDegraded(); e == nil || !strings.Contains(e.Error(), "FromImage policies refused") || !errors.Is(e, boom) {
		t.Fatalf("Degraded %v", e)
	}
	x := &productImageIndex{resolver: noopImageResolver{}, overlayUnavailable: func() error { return boom }}
	_, _, e := x.build(t.Context(), 0, 0, SharedInitIdentity{ContainerID: "c"})
	if !errors.Is(e, ErrSharedImageIndexUnavailable) || !strings.Contains(e.Error(), "overlay layout unavailable") {
		t.Fatalf("build %v", e)
	}
}

type noopImageResolver struct{ sharedImageResolving }

type healthyImage struct{}

func (healthyImage) imageHealth() error { return nil }
