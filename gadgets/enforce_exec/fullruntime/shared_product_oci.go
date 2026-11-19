// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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

// The shared image metadata: the product gadget.yaml and the packaged
// attach declaration, merged in this order.
var (
	//go:embed candidate/gadget.yaml
	sharedCandidateGadgetYAMLData []byte
	//go:embed bpf/opaque_real_owner_child_candidate.programs.yaml
	sharedCandidatePackagingData []byte
)

// Media types of a gadget image.
const (
	sharedImageConfigMediaType  = "application/vnd.gadget.config.v1+yaml"
	sharedImageProgramMediaType = "application/vnd.gadget.ebpf.program.v1+binary"
)

// sharedImageMetadata is a shared image's gadget.yaml for elf: the product
// metadata merged with overlays (the diagnostic twins' only), its packaging
// for the object (sharedPackagingForObject), the geometry annotations of
// profile and, once the verdict emitter landed, the event ABI. Stage 1 (D1):
// no failure-frame attach_to target, so the metadata is the same for every
// kernel. yaml.Marshal sorts the keys, so the bytes are a function of the
// inputs and this source.
func sharedImageMetadata(elf []byte, profile SharedProfile, overlays ...[]byte) ([]byte, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		return nil, fmt.Errorf("candidate object: %w", err)
	}
	files := append([][]byte{sharedCandidateGadgetYAMLData, sharedCandidatePackagingData}, overlays...)
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
	for key, value := range sharedGeometryAnnotations(profile) {
		merged.Set(key, value)
	}
	if sharedVerdictEmitterLanded {
		merged.Set("annotations."+SharedEventABIAnnotation, SharedEventABIVersion)
	}
	return yaml.Marshal(merged.AllSettings())
}

// pushSharedImage pushes the gadget image of elf with metadata into store:
// a config blob (metadata), the object as the eBPF program layer, a manifest
// and an index holding that one manifest for linux/arch. Nothing else is
// written (no annotations, no timestamps), so both digests are a pure
// function of (elf, metadata, arch). Blobs already in store are reused. It
// returns the manifest descriptor (with its platform) and the index's.
func pushSharedImage(ctx context.Context, store oras.Target, elf, metadata []byte, arch string) (ocispec.Descriptor, ocispec.Descriptor, error) {
	push := func(media string, data []byte) (ocispec.Descriptor, error) {
		desc := content.NewDescriptorFromBytes(media, data)
		if err := store.Push(ctx, desc, bytes.NewReader(data)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			return desc, fmt.Errorf("push %s: %w", media, err)
		}
		return desc, nil
	}
	var none ocispec.Descriptor
	config, err := push(sharedImageConfigMediaType, metadata)
	if err != nil {
		return none, none, err
	}
	layer, err := push(sharedImageProgramMediaType, elf)
	if err != nil {
		return none, none, err
	}
	manifest, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: config, Layers: []ocispec.Descriptor{layer}})
	if err != nil {
		return none, none, err
	}
	desc, err := push(ocispec.MediaTypeImageManifest, manifest)
	if err != nil {
		return none, none, err
	}
	desc.Platform = &ocispec.Platform{Architecture: arch, OS: "linux"}
	index, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}})
	if err != nil {
		return none, none, err
	}
	top, err := push(ocispec.MediaTypeImageIndex, index)
	if err != nil {
		return none, none, err
	}
	return desc, top, nil
}

// sharedProductImageArch is the platform of every product image: the pinned
// objects target x86 (-D__TARGET_ARCH_x86) and the pinned kernels are
// x86_64, whatever GOARCH builds the image.
const sharedProductImageArch = "amd64"

// sharedProductImageRepository is the local name of the product images in
// an image archive (the node-agent tracers.tar). It is never pushed to a
// registry; like any short gadget image name it resolves under the IG
// default domain (oci.SplitIGDomain).
const sharedProductImageRepository = "enforce-exec-shared"

// sharedProductProfiles are the product object geometries, in pin order
// (build-product.sh PROFILES): name, per-binding TASK and WORK quota.
var sharedProductProfiles = []struct {
	Name       string
	Task, Work uint64
}{{"g19pkg64", 64, 8}, {"g19pkg128", 128, 32}, {"g19pkg256", 256, 32}, {"g19pkg512", 512, 16}}

// sharedProductImageProfile is the SharedProfile of the product q(task,
// work) object. Its geometry is compiled into the object and annotated on
// the image (two bindings, the product policy objects 4/0/0/0, 8 accepted
// UIDs, 2/1 inode facts, 128 image roots per binding, 8192 exit tombstones),
// as the AL2023 qualification ran it. The budget fields (CompileBytes 8 MiB,
// CompileConcurrency 2, TelemetryBytes 4096, RolloutBytes 4096,
// CandidateBytes 1 MiB, PossibleCPUs 64) are host-side runtime limits, not in
// the object or the image digests: these values are the qualification
// sizes. PossibleCPUs 64 is also the hard limit (Validate): a host with more
// possible CPUs is refused (ErrSharedNativeUnavailable, fail closed).
func sharedProductImageProfile(task, work uint64) SharedProfile {
	return SharedProfile{
		Version: SharedProfileVersion, Bindings: 2, PolicySlots: [4]uint64{4, 0, 0, 0},
		Tasks: 2 * task, Scratch: 2 * work, InodeFacts: 2, AcceptedUIDs: 8, Images: 2 * sharedImageLayersMax,
		CompileBytes: 8 << 20, CompileConcurrency: 2, TelemetryBytes: 4096, RolloutBytes: 4096, CandidateBytes: 1 << 20,
		PossibleCPUs:   64,
		PerBinding:     SharedQuota{Tasks: task, Scratch: work, InodeFacts: 1, AcceptedUIDs: 4, Images: sharedImageLayersMax},
		ExitTombstones: 8192,
	}
}

// sharedProductImageName is the local image reference of profile on
// release: enforce-exec-shared:<profile>-al2023-<kernel version>.
func sharedProductImageName(profile, release string) string {
	return sharedProductImageRepository + ":" + profile + "-al2023-" + strings.TrimSuffix(release, ".amzn2023.x86_64")
}

// sharedProductImagePin is one row of testdata/shared_product_images.tsv.
type sharedProductImagePin struct {
	BTF, Profile                        string
	ObjectSHA256, ManifestDigest, Index string
}

// sharedProductImagePins are the product images built from the pinned
// objects (pinset p1, neutral build paths), one per kernel x profile, in
// pin order. TestSharedProductImagePinsMatchTestdata requires them to equal
// testdata/shared_product_images.tsv; the product-objects CI job rebuilds
// the objects and the images and requires these digests. Stage 1: one
// object per profile for both kernels, qualified on both (ProductObjects),
// so a profile's two images have the same digests.
var sharedProductImagePins = []sharedProductImagePin{
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg64", ObjectSHA256: "8c5acc1eff4da8246ad02f010825c648b9c032be7c25759baf875df396f38954",
		ManifestDigest: "sha256:2f161cc1edcbcd42fdfdce3c7ea746b260dfd071955d7fb25fab341ee32ee124", Index: "sha256:1397ee56fd71995e95fc6ae610c0c9b07d23d26e2a5110b1d6006bba308743fe",
	},
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg128", ObjectSHA256: "4d67259c637343f100b8f5583b1fed53c121d3c25c155dfca2b036ba729b3ed7",
		ManifestDigest: "sha256:036e99e41408b669b879f925a942af68689c1734c2d9b0d8033207387f25de6a", Index: "sha256:e67bd898e7e9cf9e53d4c298ab018009357174f4ae1c8e903540088829cb1114",
	},
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg256", ObjectSHA256: "92dc17d870ac543a8aef316a287e06538d503f8f34d293181436fb73caa1742e",
		ManifestDigest: "sha256:b65fc46b646442d746eb46cade87eda3a6d33144651e92e066adb9e7559e1bf0", Index: "sha256:f58271b21e84dc06d97b9345288020ad278874935e18e840b11d70e3ae8b761c",
	},
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg512", ObjectSHA256: "b8fd0637c744a7960b0e6d25f19d3f8b9c461276a43583925e85421d5230552a",
		ManifestDigest: "sha256:3b5bd67827694a55b8e7de90cedf12142d1d02b67ecce1bc92f893e3fb67c3ec", Index: "sha256:60609bd695295bf01fd1a4f6924953c65fcc17269d26ab572044a113d0c0639f",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg64", ObjectSHA256: "8c5acc1eff4da8246ad02f010825c648b9c032be7c25759baf875df396f38954",
		ManifestDigest: "sha256:2f161cc1edcbcd42fdfdce3c7ea746b260dfd071955d7fb25fab341ee32ee124", Index: "sha256:1397ee56fd71995e95fc6ae610c0c9b07d23d26e2a5110b1d6006bba308743fe",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg128", ObjectSHA256: "4d67259c637343f100b8f5583b1fed53c121d3c25c155dfca2b036ba729b3ed7",
		ManifestDigest: "sha256:036e99e41408b669b879f925a942af68689c1734c2d9b0d8033207387f25de6a", Index: "sha256:e67bd898e7e9cf9e53d4c298ab018009357174f4ae1c8e903540088829cb1114",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg256", ObjectSHA256: "92dc17d870ac543a8aef316a287e06538d503f8f34d293181436fb73caa1742e",
		ManifestDigest: "sha256:b65fc46b646442d746eb46cade87eda3a6d33144651e92e066adb9e7559e1bf0", Index: "sha256:f58271b21e84dc06d97b9345288020ad278874935e18e840b11d70e3ae8b761c",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg512", ObjectSHA256: "b8fd0637c744a7960b0e6d25f19d3f8b9c461276a43583925e85421d5230552a",
		ManifestDigest: "sha256:3b5bd67827694a55b8e7de90cedf12142d1d02b67ecce1bc92f893e3fb67c3ec", Index: "sha256:60609bd695295bf01fd1a4f6924953c65fcc17269d26ab572044a113d0c0639f",
	},
}

// SharedProductImagePin is one product gadget image: the image built by
// BuildSharedProductImage from the pinned object of Profile for the kernel
// with vmlinux BTF sha256 BTF.
type SharedProductImagePin struct {
	// BTF and Release identify the pinned kernel build.
	BTF, Release string
	// Profile names the object geometry (g19pkg64/128/256/512).
	Profile string
	// Image is the local image reference in an image archive (tracers.tar).
	Image string
	// ObjectSHA256 is the sha256 of the pinned product object.
	ObjectSHA256 string
	// ManifestDigest is the linux/amd64 manifest and IndexDigest the image
	// index. IG does not check either at run time (its runtime binding is
	// the (kernel, object) qualification and the geometry annotations); the
	// consumer (node-agent) pins the manifest digest.
	ManifestDigest, IndexDigest string
	// SharedProfile is the object's profile: the geometry compiled into the
	// object, and the qualification sizes of the host-side runtime budgets
	// (sharedProductImageProfile).
	SharedProfile SharedProfile
}

// SharedProductImagePins returns every pinned product image, in pin order
// (kernel, then profile). The slice is a copy.
func SharedProductImagePins() []SharedProductImagePin {
	out := make([]SharedProductImagePin, 0, len(sharedProductImagePins))
	for _, p := range sharedProductImagePins {
		kernel := sharedProductPins[p.BTF]
		pin := SharedProductImagePin{
			BTF: p.BTF, Release: kernel.Release, Profile: p.Profile, Image: sharedProductImageName(p.Profile, kernel.Release),
			ObjectSHA256: p.ObjectSHA256, ManifestDigest: p.ManifestDigest, IndexDigest: p.Index,
		}
		for _, q := range sharedProductProfiles {
			if q.Name == p.Profile {
				pin.SharedProfile = sharedProductImageProfile(q.Task, q.Work)
			}
		}
		out = append(out, pin)
	}
	return out
}

// buildSharedProductImage pushes the product image of elf for the pinned
// kernel btf and the product profile into store and tags it with its
// normalized local reference. It checks neither elf nor the digests against
// the pins (tests use it on non-product objects).
func buildSharedProductImage(ctx context.Context, store oras.Target, elf []byte, btf, profile string) (SharedProductImagePin, error) {
	var none SharedProductImagePin
	if store == nil {
		return none, fmt.Errorf("missing image store")
	}
	kernel, ok := sharedProductPins[btf]
	if !ok {
		return none, fmt.Errorf("no product pin for BTF %s", btf)
	}
	out := SharedProductImagePin{BTF: btf, Release: kernel.Release, Profile: profile, Image: sharedProductImageName(profile, kernel.Release)}
	found := false
	for _, q := range sharedProductProfiles {
		if q.Name == profile {
			out.SharedProfile, found = sharedProductImageProfile(q.Task, q.Work), true
		}
	}
	if !found {
		return none, fmt.Errorf("unknown product profile %q", profile)
	}
	metadata, err := sharedImageMetadata(elf, out.SharedProfile)
	if err != nil {
		return none, err
	}
	manifest, index, err := pushSharedImage(ctx, store, elf, metadata, sharedProductImageArch)
	if err != nil {
		return none, err
	}
	domain, remainder := oci.SplitIGDomain(out.Image)
	if err := store.Tag(ctx, index, domain+"/"+remainder); err != nil {
		return none, fmt.Errorf("tag %s: %w", out.Image, err)
	}
	sum := sha256.Sum256(elf)
	out.ObjectSHA256 = hex.EncodeToString(sum[:])
	out.ManifestDigest, out.IndexDigest = manifest.Digest.String(), index.Digest.String()
	return out, nil
}

// ErrSharedProductImageMismatch reports a built product image whose
// manifest or index digest differs from its pin: the metadata, packaging,
// emitter switch, profile or a dependency that encodes the metadata (viper,
// yaml.v3, oras, image-spec as resolved by the building module) changed.
var ErrSharedProductImageMismatch = errors.New("product image digest differs from its pin")

// BuildSharedProductImage builds the product image of elf, the pinned
// product object of profile for the kernel with vmlinux BTF sha256 btf,
// into store, tagged with its local reference (SharedProductImagePin.Image,
// normalized under the IG default domain), and checks it against
// SharedProductImagePins. It refuses an object whose sha256 is not that
// pin's. When the built manifest or index digest differs from the pin it
// returns the built image (with its digests) and an error wrapping
// ErrSharedProductImageMismatch; the image is still in store, so the caller
// must not ship it.
func BuildSharedProductImage(ctx context.Context, store oras.Target, elf []byte, btf, profile string) (SharedProductImagePin, error) {
	sum := sha256.Sum256(elf)
	object := hex.EncodeToString(sum[:])
	var pin *sharedProductImagePin
	for i, p := range sharedProductImagePins {
		if p.BTF == btf && p.Profile == profile && p.ObjectSHA256 == object {
			pin = &sharedProductImagePins[i]
		}
	}
	if pin == nil {
		return SharedProductImagePin{}, fmt.Errorf("object sha256 %s is not the pinned %s object for BTF %s", object, profile, btf)
	}
	built, err := buildSharedProductImage(ctx, store, elf, btf, profile)
	if err != nil {
		return SharedProductImagePin{}, err
	}
	if built.ManifestDigest != pin.ManifestDigest || built.IndexDigest != pin.Index {
		return built, fmt.Errorf("%s: built manifest %s index %s, pinned %s %s: %w", built.Image, built.ManifestDigest, built.IndexDigest, pin.ManifestDigest, pin.Index, ErrSharedProductImageMismatch)
	}
	return built, nil
}
