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
// profile, the failure-frame kprobe targets outer and handler and, once the
// verdict emitter landed, the event ABI. yaml.Marshal sorts the keys, so the
// bytes are a function of the inputs and this source.
func sharedImageMetadata(elf []byte, outer, handler string, profile SharedProfile, overlays ...[]byte) ([]byte, error) {
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
	for name, symbol := range map[string]string{
		"opaque_real_owner_failure_outer_enter": outer, "opaque_real_owner_failure_outer_exit": outer,
		"opaque_real_owner_failure_handler_enter": handler, "opaque_real_owner_failure_handler_exit": handler,
	} {
		merged.Set("programs."+name+".attach_to", symbol)
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
// the objects and the images and requires these digests. NOT YET
// REQUALIFIED on AL2023: the objects were rebuilt at neutral paths after the
// G011 qualification; requalification is pending (G035).
var sharedProductImagePins = []sharedProductImagePin{
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg64", ObjectSHA256: "0d5e4d9732689312a272d2dccc79618f0d0e7b7c3ac011c5d0bccc550e31aab4",
		ManifestDigest: "sha256:382485d6e53d414cd00e7ebf94d92c8556c7c18cb320cabc8e8d1fc66e829e3a", Index: "sha256:2421e2a74346c11d33b2c94624d6e9d9addcc08f4fd60a5d028763148817500d",
	},
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg128", ObjectSHA256: "507382feed5fd8d534b21d00be11f041b2f9f9068ead6e47666273a50dd6ad1c",
		ManifestDigest: "sha256:aeb6eaaa67ecb4b9e463c757dd9b6d4025d394b941852ffdba2ab4bd2f5112af", Index: "sha256:cf1eb6ebf6ddd700fae2ff11e894e2480e5705dd394be72448d0ed644d954230",
	},
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg256", ObjectSHA256: "528b686977d1920642a225680cafcf2ff0573c2b4bdf0565747fd1e672728f2c",
		ManifestDigest: "sha256:0f44808a63b3119e12c2a40b4c462bb96284bd3663e071d4f16a0fc0caedca18", Index: "sha256:cc6674c4968a10f54daa72763b72112b1acf6db6efbf6b0277f1e51e7543c495",
	},
	{
		BTF: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", Profile: "g19pkg512", ObjectSHA256: "1b504b838a6086e20a9968b848b09173e7c4273df040d53da2bd21323fb2dfa1",
		ManifestDigest: "sha256:dee10b290dc2b2346837001da9ad0063635b4a23a66e3bc46f4ecaf531fd2158", Index: "sha256:24125ffa6ca766bb5cb2e09633c247406977597bf48b4eca48e18e069d3090f4",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg64", ObjectSHA256: "a3a2f56fa0345904a3b8005001bb4e03929f3e94275382d56622330b0f4c9757",
		ManifestDigest: "sha256:f2c10f364a62874289c354885ad0e4f27631cdfd668261eed96fef502ff95245", Index: "sha256:3f19b0342a6a522ce25485465981ad7b8d9537ee4c98bf54608be680550a32b7",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg128", ObjectSHA256: "3fa3da0e7a7f8cb90317e2a648dfe48753df3ba954b2fb6b20575a3c43bc8fc8",
		ManifestDigest: "sha256:516b5669e73790bc1e59ec56f381a0b29ec06d164874aa66384a161c685b6e53", Index: "sha256:b4f0fa89a64caa1636382941378be664682a2500f51621f207d48e1ed5aab6d0",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg256", ObjectSHA256: "ca63241d3457d1037204c97971e46a1ee63b28f7e6439b19fe66658c16a42be7",
		ManifestDigest: "sha256:1f17c47573eeb9dc1391a9cb5017fefa30d99da2f3ad736c8f79990554c1cdf7", Index: "sha256:992e3d09a9d3be5ca26900db07e5ccfceca422498d058c05f977621ce1f94846",
	},
	{
		BTF: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", Profile: "g19pkg512", ObjectSHA256: "91b21068719070461138cdce68afa6494d10cc324ea1b75c362c862438ed2de1",
		ManifestDigest: "sha256:df89f93074d8ebfac1b18536319ebaca5da07f0010a8e5fd711ccc1e0ca8586a", Index: "sha256:2fe300f78856753d198f9f87e97bd6189db83f0a5e0ecd74c3b0e709e24375ef",
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
	// the object sha256, the failure-frame attach targets and the geometry
	// annotations); the consumer (node-agent) pins the manifest digest.
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
	metadata, err := sharedImageMetadata(elf, kernel.OuterSymbol, kernel.HandlerSymbol, out.SharedProfile)
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
