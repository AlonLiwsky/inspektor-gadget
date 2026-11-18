// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	_ "embed"
	"fmt"
	"runtime"

	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

// The diagnostic overlays of the candidate image metadata (qualification
// builds only), merged after the product metadata of sharedImageMetadata.
var (
	//go:embed candidate/gadget.diagnostic.yaml
	sharedCandidateDiagnosticGadgetYAMLData []byte
	//go:embed bpf/opaque_real_owner_child_candidate.programs.diagnostic.yaml
	sharedCandidateDiagnosticPackagingData []byte
)

// SharedCandidateImage is the reference BuildSharedCandidateImage returns:
// the gadget context's image name, and SharedNodeConfig.Image.
const SharedCandidateImage = "local/shared-candidate:abi3-development"

// KernelMatrixEntry is what the candidate image is built for on one exact
// kernel of the shared candidate matrix (QUALIFICATION ONLY).
type KernelMatrixEntry struct {
	// Release is the kernel's release of the shared candidate matrix
	// (sharedCandidateKernelBTF, e.g. 6.12.113-138.209.amzn2023.x86_64).
	Release string
	// Profile is the object's compile-time geometry, written as the image's
	// geometry annotations (the node's SharedNodeConfig.Profile).
	Profile SharedProfile
	// Diagnostic merges the diagnostic overlays (a diagnostic twin).
	Diagnostic bool
}

func (k KernelMatrixEntry) validate() error {
	known := false
	for _, release := range sharedCandidateKernelBTF {
		known = known || release == k.Release
	}
	// D3: the test-only probed-kernel override admits a release outside
	// the matrix (verifySharedCandidateKernel still gates the load).
	if !known && !sharedProbedKernelOverride() {
		return fmt.Errorf("kernel %q outside the shared candidate matrix", k.Release)
	}
	_, err := k.Profile.Validate()
	return err
}

// sharedCandidateMetadata is the candidate image's gadget.yaml for elf on
// kernel: sharedImageMetadata with, for a diagnostic twin, both diagnostic
// overlays.
func sharedCandidateMetadata(elf []byte, kernel KernelMatrixEntry) ([]byte, error) {
	if err := kernel.validate(); err != nil {
		return nil, err
	}
	var overlays [][]byte
	if kernel.Diagnostic {
		overlays = [][]byte{sharedCandidateDiagnosticGadgetYAMLData, sharedCandidateDiagnosticPackagingData}
	}
	return sharedImageMetadata(elf, kernel.Profile, overlays...)
}

// BuildSharedCandidateImage pushes the shared candidate gadget image of elf
// (the compiled candidate object) for kernel into store and tags it
// (QUALIFICATION ONLY): a config layer with sharedCandidateMetadata, the
// object as the eBPF program layer, a manifest for this GOARCH and an index
// tagged with the normalized reference the OCI handler resolves. It returns
// SharedCandidateImage, the short reference a gadget context runs (with
// gadgetcontext.WithOrasReadonlyTarget(store)) and SharedNodeConfig.Image
// pins. Blobs already in store are reused.
func BuildSharedCandidateImage(ctx context.Context, store oras.Target, elf []byte, kernel KernelMatrixEntry) (string, error) {
	return BuildSharedCandidateImageRef(ctx, store, elf, kernel, SharedCandidateImage)
}

// BuildSharedCandidateImageRef is BuildSharedCandidateImage tagged with ref
// (a short reference, as SharedCandidateImage) instead of
// SharedCandidateImage, so one store can hold several images (the product
// layout of every kernel and profile). It returns ref.
func BuildSharedCandidateImageRef(ctx context.Context, store oras.Target, elf []byte, kernel KernelMatrixEntry, ref string) (string, error) {
	if store == nil {
		return "", fmt.Errorf("missing image store")
	}
	if ref == "" {
		return "", fmt.Errorf("missing image reference")
	}
	metadata, err := sharedCandidateMetadata(elf, kernel)
	if err != nil {
		return "", err
	}
	_, top, err := pushSharedImage(ctx, store, elf, metadata, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	// The oci handler resolves the normalized reference (default domain
	// ghcr.io); gadgetcontext keeps the short name that StartNode pins.
	domain, remainder := oci.SplitIGDomain(ref)
	if err := store.Tag(ctx, top, domain+"/"+remainder); err != nil {
		return "", fmt.Errorf("tag %s: %w", ref, err)
	}
	return ref, nil
}
