// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification && enforce_exec_product_layout

package fullruntime

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

// The product OCI layout builder (G035 step 1; a build tool behind its own
// tag enforce_exec_product_layout, so it is in no test suite and never in a
// product binary). It writes the layout TestSharedProductNodeReadyAttached
// and TestSharedProductNodeNegativesAttached read from
// IG_SHARED_PRODUCT_LAYOUT: one image per pinned kernel and product profile
// (4 profiles x 2 kernels), tagged local/shared-product-<ktag>:pkg<N> (ktag
// 612 or 618). Stage 1: one CO-RE object per profile for every kernel, so
// both kernels' images of a profile carry the same object.
//
//   IG_ENFORCE_EXEC_PRODUCT_OBJECTS  the 4 objects build-product.sh writes,
//                                    g19pkg<N>.bpf.o, comma or white-space
//                                    separated
//   IG_SHARED_PRODUCT_NEG_OBJECTS    optional: objects that are NOT qualified
//                                    on any pin (a twin, another build of a
//                                    product object), each imaged as
//                                    local/shared-product-neg:<basename> for
//                                    the negatives test; the builder refuses a
//                                    qualified one
//   IG_SHARED_PRODUCT_LAYOUT_OUT     a new (or empty) directory; it receives
//                                    layout/ (the OCI layout), images.tsv
//                                    and layout.sha256sums
//
// The layout is built twice and must be byte-identical (reproducible), and
// every image's program layer must equal a qualified product ELF of its kernel.
// Without the env vars the test fails: it is only run on purpose.

var sharedProductObjectName = regexp.MustCompile(`^g19pkg(64|128|256|512)\.bpf\.o$`)

// sharedProductLayoutImage is one row of images.tsv.
type sharedProductLayoutImage struct {
	Kernel, Profile, Ref, Object, ObjectSHA256 string
	Index                                      string // the image index digest the ref resolves to
}

// sharedProductLayoutRef is the image reference of one kernel and profile.
func sharedProductLayoutRef(kernel, profile string) string {
	return "local/shared-product-" + strings.ReplaceAll(kernel, ".", "") + ":pkg" + profile
}

// sharedProductPinnedELF reads testdata/shared_product_pins.tsv (the
// record TestSharedProductPinsMatchTestdata ties to sharedProductPins): the
// qualified product ELF sha256 of each release, in sharedProductProfiles
// order.
func sharedProductPinnedELF(t *testing.T) map[string][]string {
	t.Helper()
	data, err := os.ReadFile("testdata/shared_product_pins.tsv")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("pins line %q: %d fields, want 4", line, len(fields))
		}
		elf := strings.Split(fields[3], ",")
		if len(elf) != len(sharedProductProfiles) {
			t.Fatalf("pins %s: %d product ELFs, want %d", fields[0], len(elf), len(sharedProductProfiles))
		}
		out[fields[0]] = elf
	}
	return out
}

// buildSharedProductLayout writes the layout of objects (path by kernel and
// profile) into dir and returns its images, sorted by kernel and profile.
func buildSharedProductLayout(t *testing.T, dir string, objects map[[2]string]string, negatives []string) []sharedProductLayoutImage {
	t.Helper()
	store, err := orasoci.New(dir)
	if err != nil {
		t.Fatalf("OCI layout %s: %v", dir, err)
	}
	pinned := sharedProductPinnedELF(t)
	var images []sharedProductLayoutImage
	for key, path := range objects {
		kernel, profile := key[0], key[1]
		elf, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(elf)
		digest := hex.EncodeToString(sum[:])
		var pin sharedProductPin
		for _, p := range sharedProductPins {
			if strings.HasPrefix(p.Release, kernel+".") {
				pin = p
			}
		}
		if pin.Release == "" {
			t.Fatalf("%s: no product pin for kernel %s", path, kernel)
		}
		p, i, ok := sharedProductProfileNamed(profile)
		if !ok {
			t.Fatalf("%s: unknown profile %s", path, profile)
		}
		// The object must be the pin of its own kernel AND profile, not
		// just any product ELF of the kernel.
		if want := pinned[pin.Release]; len(want) <= i || digest != want[i] {
			t.Fatalf("%s: sha256 %s is not the pinned product ELF of %s profile %s (%v)", path, digest, pin.Release, profile, want)
		}
		if !sharedProductObject(digest) {
			t.Fatalf("%s: sha256 %s is not a product ELF of this release", path, digest)
		}
		ref, err := BuildSharedCandidateImageRef(t.Context(), store, elf, KernelMatrixEntry{
			Release: pin.Release, Profile: p,
		}, sharedProductLayoutRef(kernel, profile))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		images = append(images, sharedProductLayoutImage{Kernel: kernel, Profile: profile, Ref: ref, Object: filepath.Base(path), ObjectSHA256: digest})
	}
	// Negative images: objects that are not product objects of this release,
	// packaged like a product image (profile 128 geometry) so the product
	// StartNode must refuse them on their digest.
	for _, path := range negatives {
		elf, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(elf)
		digest := hex.EncodeToString(sum[:])
		if sharedProductObject(digest) {
			t.Fatalf("negative %s: sha256 %s is a product object of this release", path, digest)
		}
		p, _, _ := sharedProductProfileNamed("128")
		var release string
		for _, d := range slices.Sorted(maps.Keys(sharedProductPins)) {
			release = sharedProductPins[d].Release
			break
		}
		name := strings.TrimSuffix(filepath.Base(path), ".bpf.o")
		ref, err := BuildSharedCandidateImageRef(t.Context(), store, elf, KernelMatrixEntry{Release: release, Profile: p}, "local/shared-product-neg:"+name)
		if err != nil {
			t.Fatalf("negative %s: %v", path, err)
		}
		images = append(images, sharedProductLayoutImage{Kernel: "neg", Profile: "128", Ref: ref, Object: filepath.Base(path), ObjectSHA256: digest})
	}
	// oras writes index.json from a map (random manifest order); rewrite it
	// in a canonical order so the layout bytes are reproducible.
	indexPath := filepath.Join(dir, ocispec.ImageIndexFile)
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(index.Manifests, func(a, b ocispec.Descriptor) int {
		return cmp.Or(cmp.Compare(a.Annotations[ocispec.AnnotationRefName], b.Annotations[ocispec.AnnotationRefName]), cmp.Compare(a.Digest, b.Digest))
	})
	if raw, err = json.Marshal(index); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(images, func(a, b sharedProductLayoutImage) int {
		return cmp.Or(cmp.Compare(a.Kernel, b.Kernel), cmp.Compare(len(a.Profile), len(b.Profile)), cmp.Compare(a.Profile, b.Profile))
	})
	return images
}

// sharedProductLayoutFiles is every regular file of dir: relative path to
// sha256 (hex).
func sharedProductLayoutFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// verifySharedProductLayout reopens the layout read-only (as the product
// test does) and requires each ref to resolve to an index of one manifest
// whose program layer is the image's object; it records the index digest.
func verifySharedProductLayout(t *testing.T, dir string, images []sharedProductLayoutImage) {
	t.Helper()
	store, err := orasoci.NewFromFS(t.Context(), os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(desc ocispec.Descriptor, into any) {
		t.Helper()
		data, err := content.FetchAll(t.Context(), store, desc)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatal(err)
		}
	}
	for i := range images {
		img := &images[i]
		domain, remainder := oci.SplitIGDomain(img.Ref)
		top, err := store.Resolve(t.Context(), domain+"/"+remainder)
		if err != nil {
			t.Fatalf("resolve %s: %v", img.Ref, err)
		}
		var index ocispec.Index
		fetch(top, &index)
		if len(index.Manifests) != 1 {
			t.Fatalf("%s: %d manifests, want 1", img.Ref, len(index.Manifests))
		}
		var manifest ocispec.Manifest
		fetch(index.Manifests[0], &manifest)
		if len(manifest.Layers) != 1 || manifest.Layers[0].MediaType != "application/vnd.gadget.ebpf.program.v1+binary" {
			t.Fatalf("%s: layers %+v, want one eBPF program layer", img.Ref, manifest.Layers)
		}
		layer, err := content.FetchAll(t.Context(), store, manifest.Layers[0])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(layer)
		if got := hex.EncodeToString(sum[:]); got != img.ObjectSHA256 {
			t.Fatalf("%s: program layer sha256 %s, want the object's %s", img.Ref, got, img.ObjectSHA256)
		}
		img.Index = top.Digest.String()
	}
}

func TestBuildSharedProductLayout(t *testing.T) {
	out := os.Getenv("IG_SHARED_PRODUCT_LAYOUT_OUT")
	list := strings.FieldsFunc(os.Getenv("IG_ENFORCE_EXEC_PRODUCT_OBJECTS"), func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if out == "" || len(list) == 0 {
		t.Fatal("set IG_SHARED_PRODUCT_LAYOUT_OUT and IG_ENFORCE_EXEC_PRODUCT_OBJECTS (the 4 build-product.sh objects); this builder never skips")
	}
	// Stage 1: one object per profile, imaged for every pinned kernel.
	objects := map[[2]string]string{}
	for _, path := range list {
		m := sharedProductObjectName.FindStringSubmatch(filepath.Base(path))
		if m == nil {
			t.Fatalf("%s: want g19pkg<64|128|256|512>.bpf.o", path)
		}
		for _, pin := range sharedProductPins {
			kernel := strings.Join(strings.SplitN(pin.Release, ".", 3)[:2], ".")
			key := [2]string{kernel, m[1]}
			if _, dup := objects[key]; dup {
				t.Fatalf("%s: a second object for profile %s", path, m[1])
			}
			objects[key] = path
		}
	}
	if len(objects) != len(sharedProductPins)*len(sharedProductProfiles) {
		t.Fatalf("%d images, want every profile on every pinned kernel (%d)", len(objects), len(sharedProductPins)*len(sharedProductProfiles))
	}
	// Never overwrite evidence: the output directory must be new or empty.
	if entries, err := os.ReadDir(out); err == nil && len(entries) != 0 {
		t.Fatalf("%s is not empty", out)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	layout := filepath.Join(out, "layout")
	negatives := strings.FieldsFunc(os.Getenv("IG_SHARED_PRODUCT_NEG_OBJECTS"), func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	images := buildSharedProductLayout(t, layout, objects, negatives)
	again := filepath.Join(t.TempDir(), "layout")
	buildSharedProductLayout(t, again, objects, negatives)
	files := sharedProductLayoutFiles(t, layout)
	if second := sharedProductLayoutFiles(t, again); !maps.Equal(files, second) {
		t.Fatalf("the layout is not reproducible: first build %v, second build %v", files, second)
	}
	verifySharedProductLayout(t, layout, images)

	var sums, rows bytes.Buffer
	for _, name := range slices.Sorted(maps.Keys(files)) {
		fmt.Fprintf(&sums, "%s  layout/%s\n", files[name], name)
	}
	fmt.Fprintf(&rows, "# kernel\tprofile\tref\tobject\tobject-sha256\tindex-digest\n")
	for _, img := range images {
		fmt.Fprintf(&rows, "%s\t%s\t%s\t%s\t%s\t%s\n", img.Kernel, img.Profile, img.Ref, img.Object, img.ObjectSHA256, img.Index)
	}
	for name, data := range map[string][]byte{"layout.sha256sums": sums.Bytes(), "images.tsv": rows.Bytes()} {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("layout %s: %d images, index.json sha256 %s, reproducible across two builds", layout, len(images), files[ocispec.ImageIndexFile])
}
