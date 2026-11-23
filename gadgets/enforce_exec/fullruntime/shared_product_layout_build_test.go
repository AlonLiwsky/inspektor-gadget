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

// The product OCI layout builder (a build tool behind its own tag
// enforce_exec_product_layout, so it is in no test suite and never in a
// product binary). It writes the layout TestSharedProductNodeReadyAttached
// and TestSharedProductNodeNegativesAttached read from
// IG_SHARED_PRODUCT_LAYOUT: one image per product profile, tagged
// local/shared-product:pkg<N> (one CO-RE object per profile for every
// kernel).
//
//   IG_ENFORCE_EXEC_PRODUCT_OBJECTS  the 4 objects build-product.sh writes,
//                                    g19pkg<N>.bpf.o, comma or white-space
//                                    separated
//   IG_SHARED_PRODUCT_NEG_OBJECTS    optional: objects that are NOT product
//                                    objects (a twin, another build of a
//                                    product object), each imaged as
//                                    local/shared-product-neg:<basename> for
//                                    the negatives test; the builder refuses a
//                                    product object
//   IG_SHARED_PRODUCT_LAYOUT_OUT     a new (or empty) directory; it receives
//                                    layout/ (the OCI layout), images.tsv
//                                    and layout.sha256sums
//
// The layout is built twice and must be byte-identical (reproducible), and
// every image's program layer must equal the product object of its profile.
// Without the env vars the test fails: it is only run on purpose.

var sharedProductObjectName = regexp.MustCompile(`^g19pkg(64|128|256|512)\.bpf\.o$`)

// sharedProductLayoutImage is one row of images.tsv.
type sharedProductLayoutImage struct {
	Profile, Ref, Object, ObjectSHA256 string
	Index                              string // the image index digest the ref resolves to
}

// sharedProductLayoutRef is the image reference of one profile.
func sharedProductLayoutRef(profile string) string {
	return "local/shared-product:pkg" + profile
}

// buildSharedProductLayout writes the layout of objects (path by profile)
// into dir and returns its images, sorted by profile.
func buildSharedProductLayout(t *testing.T, dir string, objects map[string]string, negatives []string) []sharedProductLayoutImage {
	t.Helper()
	store, err := orasoci.New(dir)
	if err != nil {
		t.Fatalf("OCI layout %s: %v", dir, err)
	}
	var images []sharedProductLayoutImage
	for profile, path := range objects {
		elf, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(elf)
		digest := hex.EncodeToString(sum[:])
		p, _, ok := sharedProductProfileNamed(profile)
		if !ok {
			t.Fatalf("%s: unknown profile %s", path, profile)
		}
		// The object must be the product object of its own profile, not
		// just any product object.
		if want := sharedProductObjects["g19pkg"+profile]; digest != want {
			t.Fatalf("%s: sha256 %s is not the product object of profile %s (%s)", path, digest, profile, want)
		}
		ref, err := BuildSharedCandidateImageRef(t.Context(), store, elf, KernelMatrixEntry{Profile: p}, sharedProductLayoutRef(profile))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		images = append(images, sharedProductLayoutImage{Profile: profile, Ref: ref, Object: filepath.Base(path), ObjectSHA256: digest})
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
		name := strings.TrimSuffix(filepath.Base(path), ".bpf.o")
		ref, err := BuildSharedCandidateImageRef(t.Context(), store, elf, KernelMatrixEntry{Profile: p}, "local/shared-product-neg:"+name)
		if err != nil {
			t.Fatalf("negative %s: %v", path, err)
		}
		images = append(images, sharedProductLayoutImage{Profile: "neg", Ref: ref, Object: filepath.Base(path), ObjectSHA256: digest})
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
		return cmp.Or(cmp.Compare(len(a.Profile), len(b.Profile)), cmp.Compare(a.Profile, b.Profile))
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
	// One object, and one image, per profile.
	objects := map[string]string{}
	for _, path := range list {
		m := sharedProductObjectName.FindStringSubmatch(filepath.Base(path))
		if m == nil {
			t.Fatalf("%s: want g19pkg<64|128|256|512>.bpf.o", path)
		}
		if _, dup := objects[m[1]]; dup {
			t.Fatalf("%s: a second object for profile %s", path, m[1])
		}
		objects[m[1]] = path
	}
	if len(objects) != len(sharedProductProfiles) {
		t.Fatalf("%d images, want every profile (%d)", len(objects), len(sharedProductProfiles))
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
	fmt.Fprintf(&rows, "# profile\tref\tobject\tobject-sha256\tindex-digest\n")
	for _, img := range images {
		fmt.Fprintf(&rows, "%s\t%s\t%s\t%s\t%s\n", img.Profile, img.Ref, img.Object, img.ObjectSHA256, img.Index)
	}
	for name, data := range map[string][]byte{"layout.sha256sums": sums.Bytes(), "images.tsv": rows.Bytes()} {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("layout %s: %d images, index.json sha256 %s, reproducible across two builds", layout, len(images), files[ocispec.ImageIndexFile])
}
