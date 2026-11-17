// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

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

// The product OCI layout builder (G035 step 1; tag-only, never in a product
// binary). It writes the layout TestSharedProductNodeReadyAttached and
// TestSharedProductNodeNegativesAttached read from IG_SHARED_PRODUCT_LAYOUT:
// one image per product object (4 profiles x 2 kernels), tagged
// local/shared-product-<ktag>:pkg<N> (ktag 612 or 618).
//
//   IG_ENFORCE_EXEC_PRODUCT_OBJECTS  the 8 objects build-product.sh writes,
//                                    g19pkg<N>-<6.12|6.18>.bpf.o, comma or
//                                    white-space separated
//   IG_SHARED_PRODUCT_LAYOUT_OUT     a new (or empty) directory; it receives
//                                    layout/ (the OCI layout), images.tsv
//                                    and layout.sha256sums
//
// The layout is built twice and must be byte-identical (reproducible), and
// every image's program layer must equal a pinned product ELF of its kernel.
// Without the env vars the test fails: it is only run on purpose.

var sharedProductObjectName = regexp.MustCompile(`^g19pkg(64|128|256|512)-(6\.12|6\.18)\.bpf\.o$`)

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
// product ELF sha256 of each release, in sharedProductProfiles order.
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
		if len(fields) != 6 {
			t.Fatalf("pins line %q: %d fields, want 6", line, len(fields))
		}
		elf := strings.Split(fields[5], ",")
		if len(elf) != len(sharedProductProfiles) {
			t.Fatalf("pins %s: %d product ELFs, want %d", fields[0], len(elf), len(sharedProductProfiles))
		}
		out[fields[0]] = elf
	}
	return out
}

// buildSharedProductLayout writes the layout of objects (path by kernel and
// profile) into dir and returns its images, sorted by kernel and profile.
func buildSharedProductLayout(t *testing.T, dir string, objects map[[2]string]string) []sharedProductLayoutImage {
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
		if _, ok := pin.ProductELF[digest]; !ok {
			t.Fatalf("%s: sha256 %s is not a pinned product ELF of %s", path, digest, pin.Release)
		}
		ref, err := BuildSharedCandidateImageRef(t.Context(), store, elf, KernelMatrixEntry{
			Release: pin.Release, OuterSymbol: pin.OuterSymbol, HandlerSymbol: pin.HandlerSymbol, Profile: p,
		}, sharedProductLayoutRef(kernel, profile))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		images = append(images, sharedProductLayoutImage{Kernel: kernel, Profile: profile, Ref: ref, Object: filepath.Base(path), ObjectSHA256: digest})
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
		t.Fatal("set IG_SHARED_PRODUCT_LAYOUT_OUT and IG_ENFORCE_EXEC_PRODUCT_OBJECTS (the 8 build-product.sh objects); this builder never skips")
	}
	objects := map[[2]string]string{}
	for _, path := range list {
		m := sharedProductObjectName.FindStringSubmatch(filepath.Base(path))
		if m == nil {
			t.Fatalf("%s: want g19pkg<64|128|256|512>-<6.12|6.18>.bpf.o", path)
		}
		key := [2]string{m[2], m[1]}
		if _, dup := objects[key]; dup {
			t.Fatalf("%s: a second object for kernel %s profile %s", path, m[2], m[1])
		}
		objects[key] = path
	}
	if len(objects) != 2*len(sharedProductProfiles) {
		t.Fatalf("%d objects, want every profile on both kernels (%d)", len(objects), 2*len(sharedProductProfiles))
	}
	// Never overwrite evidence: the output directory must be new or empty.
	if entries, err := os.ReadDir(out); err == nil && len(entries) != 0 {
		t.Fatalf("%s is not empty", out)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	layout := filepath.Join(out, "layout")
	images := buildSharedProductLayout(t, layout, objects)
	again := filepath.Join(t.TempDir(), "layout")
	buildSharedProductLayout(t, again, objects)
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
