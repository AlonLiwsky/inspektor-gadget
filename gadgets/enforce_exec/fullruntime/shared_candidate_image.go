// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

// The candidate image metadata (qualification builds only): the product
// gadget.yaml, the packaged attach declaration and, for a diagnostic twin,
// both diagnostic overlays, merged in this order.
var (
	//go:embed candidate/gadget.yaml
	sharedCandidateGadgetYAMLData []byte
	//go:embed bpf/opaque_real_owner_child_candidate.programs.yaml
	sharedCandidatePackagingData []byte
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
	// OuterSymbol and HandlerSymbol are this kernel's text symbols the
	// failure-frame kprobes attach to (do_execveat_common[.isra.N];
	// search_binary_handler or exec_binprm), as the qualified loader
	// resolves them from /proc/kallsyms.
	OuterSymbol, HandlerSymbol string
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
	if !known {
		return fmt.Errorf("kernel %q outside the shared candidate matrix", k.Release)
	}
	if k.OuterSymbol == "" || k.HandlerSymbol == "" {
		return fmt.Errorf("kernel %s: failure-frame symbols required", k.Release)
	}
	// A product (non-diagnostic) image carries exactly the pinned build's
	// failure-frame symbols, which the product node also requires.
	if !k.Diagnostic {
		for _, pin := range sharedProductPins {
			if pin.Release == k.Release && (k.OuterSymbol != pin.OuterSymbol || k.HandlerSymbol != pin.HandlerSymbol) {
				return fmt.Errorf("kernel %s: failure-frame symbols %s/%s, the pin is %s/%s", k.Release, k.OuterSymbol, k.HandlerSymbol, pin.OuterSymbol, pin.HandlerSymbol)
			}
		}
	}
	_, err := k.Profile.Validate()
	return err
}

// sharedCandidateMetadata is the candidate image's gadget.yaml for elf on
// kernel: the merged metadata, its packaging for the object
// (sharedPackagingForObject), the geometry annotations and the failure-frame
// kprobe targets (and, once the verdict emitter landed, the event ABI).
func sharedCandidateMetadata(elf []byte, kernel KernelMatrixEntry) ([]byte, error) {
	if err := kernel.validate(); err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		return nil, fmt.Errorf("candidate object: %w", err)
	}
	files := [][]byte{sharedCandidateGadgetYAMLData, sharedCandidatePackagingData}
	if kernel.Diagnostic {
		files = append(files, sharedCandidateDiagnosticGadgetYAMLData, sharedCandidateDiagnosticPackagingData)
	}
	merged := viper.New()
	merged.SetConfigType("yaml")
	for k, data := range files {
		read := merged.MergeConfig
		if k == 0 {
			read = merged.ReadConfig
		}
		if err := read(bytes.NewReader(data)); err != nil {
			return nil, fmt.Errorf("candidate metadata %d: %w", k, err)
		}
	}
	merged, err = sharedPackagingForObject(merged, sharedObjectShapeOf(spec))
	if err != nil {
		return nil, err
	}
	for key, value := range sharedGeometryAnnotations(kernel.Profile) {
		merged.Set(key, value)
	}
	if sharedVerdictEmitterLanded {
		merged.Set("annotations."+SharedEventABIAnnotation, SharedEventABIVersion)
	}
	for name, symbol := range map[string]string{
		"opaque_real_owner_failure_outer_enter": kernel.OuterSymbol, "opaque_real_owner_failure_outer_exit": kernel.OuterSymbol,
		"opaque_real_owner_failure_handler_enter": kernel.HandlerSymbol, "opaque_real_owner_failure_handler_exit": kernel.HandlerSymbol,
	} {
		merged.Set("programs."+name+".attach_to", symbol)
	}
	return yaml.Marshal(merged.AllSettings())
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
	if store == nil {
		return "", fmt.Errorf("missing image store")
	}
	metadata, err := sharedCandidateMetadata(elf, kernel)
	if err != nil {
		return "", err
	}
	push := func(media string, data []byte) (ocispec.Descriptor, error) {
		desc := content.NewDescriptorFromBytes(media, data)
		if err := store.Push(ctx, desc, bytes.NewReader(data)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			return desc, fmt.Errorf("push %s: %w", media, err)
		}
		return desc, nil
	}
	config, err := push("application/vnd.gadget.config.v1+yaml", metadata)
	if err != nil {
		return "", err
	}
	layer, err := push("application/vnd.gadget.ebpf.program.v1+binary", elf)
	if err != nil {
		return "", err
	}
	manifest, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: config, Layers: []ocispec.Descriptor{layer}})
	if err != nil {
		return "", err
	}
	desc, err := push(ocispec.MediaTypeImageManifest, manifest)
	if err != nil {
		return "", err
	}
	desc.Platform = &ocispec.Platform{Architecture: runtime.GOARCH, OS: "linux"}
	index, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}})
	if err != nil {
		return "", err
	}
	top, err := push(ocispec.MediaTypeImageIndex, index)
	if err != nil {
		return "", err
	}
	// The oci handler resolves the normalized reference (default domain
	// ghcr.io); gadgetcontext keeps the short name that StartNode pins.
	domain, remainder := oci.SplitIGDomain(SharedCandidateImage)
	if err := store.Tag(ctx, top, domain+"/"+remainder); err != nil {
		return "", fmt.Errorf("tag %s: %w", SharedCandidateImage, err)
	}
	return SharedCandidateImage, nil
}
