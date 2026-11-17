// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

// sharedMinimalObject compiles a one-program, one-map BPF object (no
// interpreter continuation, not a product object).
func sharedMinimalObject(t *testing.T) []byte {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang required")
	}
	dir := t.TempDir()
	source, object := filepath.Join(dir, "minimal.bpf.c"), filepath.Join(dir, "minimal.bpf.o")
	const program = `#define SEC(n) __attribute__((section(n), used))
struct { int (*type)[2]; int (*max_entries)[1]; unsigned int *key; unsigned int *value; } minimal_map SEC(".maps");
SEC("socket") int minimal_prog(void *ctx) { return 0; }
char LICENSE[] SEC("license") = "GPL";
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(clang, "-target", "bpf", "-O2", "-g", "-c", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("clang: %v\n%s", err, out)
	}
	elf, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	return elf
}

// TestPushSharedImageDeterministic: fixed object and metadata bytes give
// fixed manifest and index digests (no timestamp, annotation or host input),
// in any store, and the index holds exactly that manifest for linux/amd64.
// The digests were reproduced independently from the OCI JSON encoding.
func TestPushSharedImageDeterministic(t *testing.T) {
	const (
		wantManifest = "sha256:dbbfa7c293f2f84f7cc9f278db176cf707164a67c9aac1fc0445231afef613c5"
		wantIndex    = "sha256:e8b0871df261757bddcd0398dbf25075fd4938274812da3c1b3a37bdad74165a"
	)
	elf, metadata := []byte("fixed object bytes"), []byte("name: fixed metadata\n")
	for range 2 {
		store := memory.New()
		manifest, index, err := pushSharedImage(t.Context(), store, elf, metadata, sharedProductImageArch)
		if err != nil {
			t.Fatal(err)
		}
		if manifest.Digest.String() != wantManifest || index.Digest.String() != wantIndex {
			t.Fatalf("manifest %s index %s, want %s %s", manifest.Digest, index.Digest, wantManifest, wantIndex)
		}
		data, err := content.FetchAll(t.Context(), store, index)
		if err != nil {
			t.Fatal(err)
		}
		var got ocispec.Index
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Manifests) != 1 || got.Manifests[0].Digest != manifest.Digest || got.Manifests[0].MediaType != ocispec.MediaTypeImageManifest ||
			got.Manifests[0].Platform == nil || got.Manifests[0].Platform.Architecture != "amd64" || got.Manifests[0].Platform.OS != "linux" ||
			got.Annotations != nil || got.Manifests[0].Annotations != nil {
			t.Fatalf("index %+v", got)
		}
	}
}

// TestSharedProductImagePinsMatchTestdata: SharedProductImagePins equals
// testdata/shared_product_images.tsv line by line, every image's object is
// a pinned product object of its kernel, every kernel has every profile
// once, and each compiled-in profile is valid.
func TestSharedProductImagePinsMatchTestdata(t *testing.T) {
	f, err := os.Open("testdata/shared_product_images.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pins := SharedProductImagePins()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(lines) != len(pins) || len(pins) != len(sharedProductPins)*len(sharedProductProfiles) {
		t.Fatalf("%d testdata lines, %d pins, want %d", len(lines), len(pins), len(sharedProductPins)*len(sharedProductProfiles))
	}
	seen := map[[2]string]bool{}
	for i, pin := range pins {
		want := strings.Join([]string{pin.Release, pin.Profile, pin.Image, pin.ObjectSHA256, pin.ManifestDigest, pin.IndexDigest}, "\t")
		if lines[i] != want {
			t.Errorf("testdata line %d %q, pin %q", i, lines[i], want)
		}
		kernel, ok := sharedProductPins[pin.BTF]
		if !ok || pin.Release != kernel.Release {
			t.Fatalf("pin %d: BTF %s not a product kernel", i, pin.BTF)
		}
		if _, ok := kernel.ProductELF[pin.ObjectSHA256]; !ok {
			t.Errorf("pin %d: object %s is not a pinned %s object", i, pin.ObjectSHA256, kernel.Release)
		}
		if want := sharedProductProfiles[i%len(sharedProductProfiles)].Name; pin.Profile != want {
			t.Errorf("pin %d: profile %s, want %s (pin order)", i, pin.Profile, want)
		}
		key := [2]string{pin.BTF, pin.Profile}
		if seen[key] {
			t.Errorf("pin %d: duplicate %v", i, key)
		}
		seen[key] = true
		if _, err := pin.SharedProfile.Validate(); err != nil {
			t.Errorf("pin %d: profile %+v: %v", i, pin.SharedProfile, err)
		}
		if !strings.HasPrefix(pin.ManifestDigest, "sha256:") || !strings.HasPrefix(pin.IndexDigest, "sha256:") {
			t.Errorf("pin %d: digests %s %s", i, pin.ManifestDigest, pin.IndexDigest)
		}
	}
	// Every pinned product object has an image.
	for btf, kernel := range sharedProductPins {
		for object := range kernel.ProductELF {
			found := false
			for _, pin := range pins {
				found = found || pin.BTF == btf && pin.ObjectSHA256 == object
			}
			if !found {
				t.Errorf("%s object %s has no image pin", kernel.Release, object)
			}
		}
	}
	// The result is a copy.
	pins[0].ManifestDigest = "changed"
	if SharedProductImagePins()[0].ManifestDigest == "changed" {
		t.Fatal("SharedProductImagePins returned the table itself")
	}
}

// TestSharedProductImageProfileMatchesQualification: the compiled-in
// profile of each product object is the geometry the AL2023 qualification
// ran with (sharedProductAttachedProfile).
func TestSharedProductImageProfileMatchesQualification(t *testing.T) {
	for _, q := range sharedProductProfiles {
		want := sharedProductProfileFor(q.Task, q.Work)
		want.ExitTombstones = sharedProductExitTombstones
		if got := sharedProductImageProfile(q.Task, q.Work); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v, want %+v", q.Name, got, want)
		}
	}
}

// TestSharedProductImageName: the local reference scheme, and the
// normalized name it is tagged with in a layout.
func TestSharedProductImageName(t *testing.T) {
	got := sharedProductImageName("g19pkg128", "6.12.113-138.209.amzn2023.x86_64")
	if got != "enforce-exec-shared:g19pkg128-al2023-6.12.113-138.209" {
		t.Fatalf("image name %q", got)
	}
	domain, remainder := oci.SplitIGDomain(got)
	if domain+"/"+remainder != "ghcr.io/inspektor-gadget/gadget/enforce-exec-shared:g19pkg128-al2023-6.12.113-138.209" {
		t.Fatalf("normalized %s/%s", domain, remainder)
	}
}

// TestBuildSharedProductImage: the same object builds the same digests in
// two stores, tagged with the normalized local reference; the exported
// builder refuses an object that is not the pinned one, an unknown profile
// or kernel.
func TestBuildSharedProductImage(t *testing.T) {
	elf := sharedMinimalObject(t)
	pin := SharedProductImagePins()[1]
	var first SharedProductImagePin
	for k := range 2 {
		store := memory.New()
		got, err := buildSharedProductImage(t.Context(), store, elf, pin.BTF, pin.Profile)
		if err != nil {
			t.Fatal(err)
		}
		if k == 0 {
			first = got
		} else if !reflect.DeepEqual(got, first) {
			t.Fatalf("rebuild %+v, first %+v", got, first)
		}
		if got.Image != pin.Image || !reflect.DeepEqual(got.SharedProfile, pin.SharedProfile) {
			t.Fatalf("built %+v", got)
		}
		domain, remainder := oci.SplitIGDomain(got.Image)
		desc, err := store.Resolve(t.Context(), domain+"/"+remainder)
		if err != nil || desc.Digest.String() != got.IndexDigest || desc.MediaType != ocispec.MediaTypeImageIndex {
			t.Fatalf("resolve %s: %+v %v", got.Image, desc, err)
		}
	}
	if _, err := BuildSharedProductImage(t.Context(), memory.New(), elf, pin.BTF, pin.Profile); err == nil || errors.Is(err, ErrSharedProductImageMismatch) {
		t.Fatalf("unpinned object: %v", err)
	}
	if _, err := buildSharedProductImage(t.Context(), memory.New(), elf, pin.BTF, "g19pkg1024"); err == nil {
		t.Fatal("unknown profile built")
	}
	if _, err := buildSharedProductImage(t.Context(), memory.New(), elf, "00", pin.Profile); err == nil {
		t.Fatal("unknown kernel built")
	}
}

// TestBuildSharedProductImageChecksDigests: the exported builder returns
// the image when its digests equal the pin, and an error wrapping
// ErrSharedProductImageMismatch (with the built digests) when the manifest
// or the index digest differs, so every caller fails on metadata or
// dependency drift.
func TestBuildSharedProductImageChecksDigests(t *testing.T) {
	elf := sharedMinimalObject(t)
	pinned := SharedProductImagePins()[1]
	built, err := buildSharedProductImage(t.Context(), memory.New(), elf, pinned.BTF, pinned.Profile)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(elf)
	object := hex.EncodeToString(sum[:])
	saved := sharedProductImagePins
	t.Cleanup(func() { sharedProductImagePins = saved })
	for name, tc := range map[string]struct {
		manifest, index string
		mismatch        bool
	}{
		"equal":          {built.ManifestDigest, built.IndexDigest, false},
		"manifest drift": {"sha256:" + strings.Repeat("0", 64), built.IndexDigest, true},
		"index drift":    {built.ManifestDigest, "sha256:" + strings.Repeat("0", 64), true},
	} {
		sharedProductImagePins = []sharedProductImagePin{{BTF: pinned.BTF, Profile: pinned.Profile, ObjectSHA256: object, ManifestDigest: tc.manifest, Index: tc.index}}
		got, err := BuildSharedProductImage(t.Context(), memory.New(), elf, pinned.BTF, pinned.Profile)
		if tc.mismatch != errors.Is(err, ErrSharedProductImageMismatch) || !tc.mismatch && err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.ManifestDigest != built.ManifestDigest || got.IndexDigest != built.IndexDigest {
			t.Fatalf("%s: returned %s %s, built %s %s", name, got.ManifestDigest, got.IndexDigest, built.ManifestDigest, built.IndexDigest)
		}
		if tc.mismatch && !strings.Contains(err.Error(), built.ManifestDigest) {
			t.Fatalf("%s: error without the built digests: %v", name, err)
		}
	}
}
