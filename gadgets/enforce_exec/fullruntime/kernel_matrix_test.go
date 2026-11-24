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

// TestMain makes the node-level unit tests host-independent: the overlay
// layout read and the FMODE_BACKING probe are faked unless the binary runs
// attached tests on a live kernel, where every loaded object's classifier
// must get that kernel's own layout (a faked OVL_FILE layout on a realfile
// kernel dereferences the realfile as an ovl_file: every image fact
// READ_FAULT/UNKNOWN). Live: IG_SHARED_OVL_BTF=1, IG_SHARED_OVL_AUTOLOAD=1,
// the product attached tests (IG_SHARED_PRODUCT_LAYOUT) or
// IG_SHARED_LIVE_KERNEL=1 (the qualification attached tests).
func TestMain(m *testing.M) {
	if !sharedLiveKernelTest() {
		overlayLayoutReader = func() (uint32, error) { return sharedImageOverlayLayoutOvlFile, nil }
		overlayModuleLoader = func() error { return nil }
		fmodeBackingReader = func(uint32) (uint32, error) { return sharedFmodeBacking24, nil }
	}
	os.Exit(m.Run())
}

// sharedLiveKernelTest reports whether this test binary runs attached tests
// on a live kernel (TestMain).
func sharedLiveKernelTest() bool {
	return os.Getenv("IG_SHARED_OVL_BTF") == "1" || os.Getenv("IG_SHARED_OVL_AUTOLOAD") == "1" ||
		os.Getenv("IG_SHARED_PRODUCT_LAYOUT") != "" || os.Getenv("IG_SHARED_LIVE_KERNEL") == "1"
}

// TestSharedImageOverlayLayoutValues: the shape derivation gives each
// layout's synthetic overlay BTF its layout, and the values match the
// classifier header.
func TestSharedImageOverlayLayoutValues(t *testing.T) {
	for _, want := range []uint32{sharedImageOverlayLayoutRealFile, sharedImageOverlayLayoutOvlFile} {
		got, err := sharedImageOverlayLayout(overlaySpecForLayout(t, want))
		if err != nil || got != want {
			t.Errorf("layout %d err %v, want %d", got, err, want)
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

// overlaySpecForLayout builds a synthetic overlay module BTF: the ovl_file shape
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
