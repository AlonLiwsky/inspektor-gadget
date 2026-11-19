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
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg64", ObjectSHA256: "da796db9846e32d64b475fb2b7dbd33178e297c5630e9303c3dc57c60d9f119f",
		ManifestDigest: "sha256:394725f46a06fc712548eb8d06b077aef07362c47ccafddf63113ff63d6d744e", Index: "sha256:d479e1640f224cd290a60bd7d962047feae0ab138b6331764c21ac154c3ede11",
	},
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg128", ObjectSHA256: "8bc88d1505dac04fa744cf9d2f0af511b2337da8dd889efa5798c64977f51987",
		ManifestDigest: "sha256:91ddb1816a7330af366dc580c673480a82f331bf717e895853317d69838117b3", Index: "sha256:d787b9305048d3dac04401ba08c0ed94d16696aaa2d02996b68b342ae99b7c06",
	},
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg256", ObjectSHA256: "74b21461d18e98d6336cac320e7f830a5ee8e441198e3053dcf68b98ad093845",
		ManifestDigest: "sha256:b2980cc0976550dbea549bd91a683c305254acb38acf5405dc65ad0cae005909", Index: "sha256:792501332082798ce6f5c8306edf8806513449d665a542e88f4ff7e3292b2116",
	},
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg512", ObjectSHA256: "206decf3344b9f7c90dd285d36ec653dbf5f557ef081d986fa4e56c6cd726b35",
		ManifestDigest: "sha256:313883bc686923022d1e619aad725b8a2f86ea10400eb38d54c87894da639dbc", Index: "sha256:b442a32a3c4b85d6bac82d0dbaec30693af44a3007dcea4e539b0d3ff6e33f0a",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg64", ObjectSHA256: "da796db9846e32d64b475fb2b7dbd33178e297c5630e9303c3dc57c60d9f119f",
		ManifestDigest: "sha256:394725f46a06fc712548eb8d06b077aef07362c47ccafddf63113ff63d6d744e", Index: "sha256:d479e1640f224cd290a60bd7d962047feae0ab138b6331764c21ac154c3ede11",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg128", ObjectSHA256: "8bc88d1505dac04fa744cf9d2f0af511b2337da8dd889efa5798c64977f51987",
		ManifestDigest: "sha256:91ddb1816a7330af366dc580c673480a82f331bf717e895853317d69838117b3", Index: "sha256:d787b9305048d3dac04401ba08c0ed94d16696aaa2d02996b68b342ae99b7c06",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg256", ObjectSHA256: "74b21461d18e98d6336cac320e7f830a5ee8e441198e3053dcf68b98ad093845",
		ManifestDigest: "sha256:b2980cc0976550dbea549bd91a683c305254acb38acf5405dc65ad0cae005909", Index: "sha256:792501332082798ce6f5c8306edf8806513449d665a542e88f4ff7e3292b2116",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg512", ObjectSHA256: "206decf3344b9f7c90dd285d36ec653dbf5f557ef081d986fa4e56c6cd726b35",
		ManifestDigest: "sha256:313883bc686923022d1e619aad725b8a2f86ea10400eb38d54c87894da639dbc", Index: "sha256:b442a32a3c4b85d6bac82d0dbaec30693af44a3007dcea4e539b0d3ff6e33f0a",
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
