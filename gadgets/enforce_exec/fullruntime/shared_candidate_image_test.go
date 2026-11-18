// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"bytes"
	"encoding/json"
	"io"
	"runtime"
	"slices"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// TestBuildSharedCandidateImage: the image resolves under the normalized
// reference to an index of one manifest for this GOARCH whose layers are the
// packaged candidate metadata (geometry annotations) and the object; a rebuild
// reuses the blobs; an entry outside the matrix or with an invalid profile is
// refused.
func TestBuildSharedCandidateImage(t *testing.T) {
	elf := sharedMinimalObject(t)
	var release string
	for _, p := range sharedProductPins {
		release = p.Release
		break
	}
	kernel := KernelMatrixEntry{Release: release, Profile: sharedCandidateQualificationProfile()}
	store := memory.New()
	ref, err := BuildSharedCandidateImage(t.Context(), store, elf, kernel)
	if err != nil || ref != SharedCandidateImage {
		t.Fatalf("build: %q %v", ref, err)
	}
	if _, err := BuildSharedCandidateImage(t.Context(), store, elf, kernel); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	fetch := func(desc ocispec.Descriptor, into any) []byte {
		t.Helper()
		r, err := store.Fetch(t.Context(), desc)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if into != nil {
			if err := json.Unmarshal(data, into); err != nil {
				t.Fatal(err)
			}
		}
		return data
	}
	domain, remainder := oci.SplitIGDomain(ref)
	top, err := store.Resolve(t.Context(), domain+"/"+remainder)
	if err != nil || top.MediaType != ocispec.MediaTypeImageIndex {
		t.Fatalf("resolve %s: %+v %v", ref, top, err)
	}
	var index ocispec.Index
	fetch(top, &index)
	if len(index.Manifests) != 1 || index.Manifests[0].Platform == nil || index.Manifests[0].Platform.Architecture != runtime.GOARCH || index.Manifests[0].Platform.OS != "linux" {
		t.Fatalf("index %+v", index)
	}
	var manifest ocispec.Manifest
	fetch(index.Manifests[0], &manifest)
	if len(manifest.Layers) != 1 || manifest.Layers[0].MediaType != "application/vnd.gadget.ebpf.program.v1+binary" || manifest.Config.MediaType != "application/vnd.gadget.config.v1+yaml" {
		t.Fatalf("manifest %+v", manifest)
	}
	if !bytes.Equal(fetch(manifest.Layers[0], nil), elf) || manifest.Layers[0].Digest != content.NewDescriptorFromBytes("", elf).Digest {
		t.Fatal("program layer is not the object")
	}
	config := viper.New()
	config.SetConfigType("yaml")
	if err := config.ReadConfig(bytes.NewReader(fetch(manifest.Config, nil))); err != nil {
		t.Fatal(err)
	}
	for key, want := range sharedGeometryAnnotations(kernel.Profile) {
		if got := config.GetString(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	for _, check := range [][2]string{
		{"annotations.enforce-exec-owner-abi", "3"},
		{"annotations.enforce-exec-shared-profile", "1"},
	} {
		if got := config.GetString(check[0]); got != check[1] {
			t.Fatalf("%s = %q, want %q", check[0], got, check[1])
		}
	}
	// A pre-continuation non-product object: the packaging drops the
	// continuation tail-call slots (sharedPackagingForObject).
	var calls []operators.NativeTailCall
	if err := config.UnmarshalKey("tail_calls", &calls); err != nil {
		t.Fatal(err)
	}
	for _, c := range sharedInterpContinuationTailCalls {
		if slices.Contains(calls, c) {
			t.Fatalf("continuation slot %+v kept for an object without it", c)
		}
	}
	// The event ABI annotation follows the single switch: once the emitter
	// landed the builder must write it, otherwise it must be absent.
	if sharedVerdictEmitterLanded {
		if got := config.GetString("annotations." + SharedEventABIAnnotation); got != SharedEventABIVersion {
			t.Fatalf("event ABI annotation %q, want %q", got, SharedEventABIVersion)
		}
	} else if config.IsSet("annotations." + SharedEventABIAnnotation) {
		t.Fatal("event ABI annotated before the emitter landed")
	}
	if err := admitSharedEventABI(config); err != nil {
		t.Fatal(err)
	}

	for name, bad := range map[string]KernelMatrixEntry{
		"outside the matrix": {Release: "6.1.0-generic", Profile: kernel.Profile},
		"invalid profile":    {Release: release},
	} {
		if _, err := BuildSharedCandidateImage(t.Context(), memory.New(), elf, bad); err == nil {
			t.Fatalf("%s: built", name)
		}
	}
	// Every pinned release builds and supports diagnostic overlays.
	for _, own := range sharedProductPins {
		entry := KernelMatrixEntry{Release: own.Release, Profile: kernel.Profile}
		if _, err := BuildSharedCandidateImage(t.Context(), memory.New(), elf, entry); err != nil {
			t.Fatalf("%s: %v", own.Release, err)
		}
		entry.Diagnostic = true
		if err := entry.validate(); err != nil {
			t.Fatalf("diagnostic %s: %v", own.Release, err)
		}
	}
	if _, err := BuildSharedCandidateImage(t.Context(), memory.New(), []byte("not an ELF"), kernel); err == nil || !strings.Contains(err.Error(), "candidate object") {
		t.Fatalf("not an object: %v", err)
	}
	if _, err := BuildSharedCandidateImageRef(t.Context(), memory.New(), elf, kernel, ""); err == nil || !strings.Contains(err.Error(), "missing image reference") {
		t.Fatalf("empty reference: %v", err)
	}
	if ref, err := BuildSharedCandidateImageRef(t.Context(), memory.New(), elf, kernel, "local/other:tag"); err != nil || ref != "local/other:tag" {
		t.Fatalf("explicit reference: %q %v", ref, err)
	}
}
