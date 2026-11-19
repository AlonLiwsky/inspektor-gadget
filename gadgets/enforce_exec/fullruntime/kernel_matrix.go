// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// SupportedKernelBTF identifies the original isolated proof artifact. This is NOT
// a general Linux or released-kernel support claim. Expanding the exact matrix
// requires isolated proof of overlay fields, task lifecycle and the mutex barrier.
const SupportedKernelBTF = "12f7d6270d8090e944941d3ff77c13339cebe1c394f4ef0d27be1bff0d09561b"

// SupportedKubernetesKernelBTF identifies the same pinned Linux source with the
// additional fanotify, networking and CPU bandwidth configuration needed by the
// isolated Kubernetes proof. It does not admit other builds of that source.
const SupportedKubernetesKernelBTF = "759807546ae2feaf616dc65c73167439867bb393dc468a4bd39c0ab1bc267d51"

func supportedKernelBTF(digest string) bool {
	switch digest {
	case SupportedKernelBTF, SupportedKubernetesKernelBTF:
		return true
	default:
		return false
	}
}

// sharedProductPin is one exact kernel build the shared product node is
// qualified on (G011 pass 1; checklist step 0 values, mirrored in
// testdata/shared_product_pins.tsv). The BTF digest alone does not identify a
// build: the release and the vmlinux GNU build-id must match too.
type sharedProductPin struct {
	Release string // uname -r
	BuildID string // vmlinux GNU build-id (hex) from /sys/kernel/notes
	// Stage 1 (D1): no failure-frame symbols. The exec frame is
	// lsm/bprm_creds_for_exec .. tp_btf/sys_exit on every kernel, so a pin
	// carries no per-kernel handler choice.
	//
	// FmodeBacking is the FMODE_BACKING bit of this build
	// (include/linux/fs.h; source-verified). The live probe only
	// cross-checks it (kernel_probe.go sharedFmodeBacking).
	FmodeBacking uint32
	// ProductObjects is the set of product object sha256 (a subset of
	// sharedProductObjects) QUALIFIED on this pinned build: the product
	// admits only a (kernel, object) pair that ran its oracle there (S1
	// review F1). Literal digests, never derived from sharedProductObjects:
	// a rebuilt object is NOT qualified until it runs the oracle on the pin.
	ProductObjects map[string]struct{}
}

// qualifiesProductObject reports whether digest is a product object of this
// release that is qualified on pin.
func (pin sharedProductPin) qualifiesProductObject(digest string) bool {
	if !sharedProductObject(digest) {
		return false
	}
	_, ok := pin.ProductObjects[digest]
	return ok
}

// sharedProductObjects is the sha256 set of the product objects of THIS
// release, by profile. D3: one CO-RE object per profile for every kernel
// (they were one set per kernel build: the per-kernel objects differed only
// in unrelocated CO-RE placeholders and in the BTF/DWARF copied from each
// kernel's vmlinux.h). The values are those of bpf/build-product.sh with the
// pinned toolchain at the neutral paths; testdata/shared_product_objects.tsv
// mirrors them.
var sharedProductObjects = map[string]string{
	"g19pkg64":  "8c5acc1eff4da8246ad02f010825c648b9c032be7c25759baf875df396f38954",
	"g19pkg128": "4d67259c637343f100b8f5583b1fed53c121d3c25c155dfca2b036ba729b3ed7",
	"g19pkg256": "92dc17d870ac543a8aef316a287e06538d503f8f34d293181436fb73caa1742e",
	"g19pkg512": "b8fd0637c744a7960b0e6d25f19d3f8b9c461276a43583925e85421d5230552a",
}

// sharedProductObject reports whether digest is a product object of this
// release.
func sharedProductObject(digest string) bool {
	for _, want := range sharedProductObjects {
		if digest != "" && digest == want {
			return true
		}
	}
	return false
}

// sharedProductPins maps a vmlinux BTF sha256 to its pinned build.
var sharedProductPins = map[string]sharedProductPin{
	"0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82": {
		Release:      "6.12.113-138.209.amzn2023.x86_64",
		BuildID:      "1d135d67e6d0ea8f77d60a2984915eadd28a5fcf",
		FmodeBacking: sharedFmodeBacking24,
		// Stage 1 qualification on this pinned build (stage-1 PR build):
		// the stage-1 oracle (D3 34 steps, D1 18), Strict + Audit, 0 FAIL 0 SKIP.
		ProductObjects: map[string]struct{}{
			"8c5acc1eff4da8246ad02f010825c648b9c032be7c25759baf875df396f38954": {}, // g19pkg64
			"4d67259c637343f100b8f5583b1fed53c121d3c25c155dfca2b036ba729b3ed7": {}, // g19pkg128
			"92dc17d870ac543a8aef316a287e06538d503f8f34d293181436fb73caa1742e": {}, // g19pkg256
			"b8fd0637c744a7960b0e6d25f19d3f8b9c461276a43583925e85421d5230552a": {}, // g19pkg512
		},
	},
	"d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee": {
		Release:      "6.18.56-125.164.amzn2023.x86_64",
		BuildID:      "884ed4548406a1461ac5fb658c0dffdd87f1b3b2",
		FmodeBacking: sharedFmodeBacking24,
		// Stage 1 qualification on this pinned build (stage-1 PR build):
		// the stage-1 oracle (D3 34 steps, D1 18), Strict + Audit, 0 FAIL 0 SKIP.
		ProductObjects: map[string]struct{}{
			"8c5acc1eff4da8246ad02f010825c648b9c032be7c25759baf875df396f38954": {}, // g19pkg64
			"4d67259c637343f100b8f5583b1fed53c121d3c25c155dfca2b036ba729b3ed7": {}, // g19pkg128
			"92dc17d870ac543a8aef316a287e06538d503f8f34d293181436fb73caa1742e": {}, // g19pkg256
			"b8fd0637c744a7960b0e6d25f19d3f8b9c461276a43583925e85421d5230552a": {}, // g19pkg512
		},
	},
}

// sharedCandidateKernelBTF is the exact kernel matrix of the shared-node
// candidate (G019 qualification builds): the BTF of the two AL2023 guest
// kernels the candidate objects are compiled against (compile.sh vmlinux.h)
// and qualified on, derived from sharedProductPins. It is not the
// persistent-owner matrix above and admits nothing to that path.
var sharedCandidateKernelBTF = func() map[string]string {
	out := make(map[string]string, len(sharedProductPins))
	for digest, pin := range sharedProductPins {
		out[digest] = pin.Release
	}
	return out
}()

// Overlay exec-file private_data layouts consumed by se_image_classify through
// the se_image_ovl_layout rodata constant (full/shared_image_classify.h
// SE_IMAGE_OVL_LAYOUT_*). struct ovl_file is overlay-private: its BTF is in
// the overlay module (or in vmlinux when overlayfs is built in).
//
// D3: there is no per-release layout table any more. The layout is derived
// from the overlay BTF the loader positively read, and the object relocates
// struct ovl_file itself (CO-RE against the module BTF); the classifier
// refuses when the two disagree.
const (
	sharedImageOverlayLayoutUnset    uint32 = 0
	sharedImageOverlayLayoutRealFile uint32 = 1 // < v6.13: private_data is the real file (fs/overlayfs/file.c)
	sharedImageOverlayLayoutOvlFile  uint32 = 2 // >= v6.13: private_data is a struct ovl_file
)

// sharedImageOverlayLayout derives the se_image_ovl_layout constant from the
// overlay types of the running kernel (a split spec over vmlinux for the
// module, or vmlinux itself when overlayfs is built in). A nil spec (overlay
// BTF absent) or a spec that does not carry overlayfs's private types is
// refused: the absence of struct ovl_file selects the realfile layout only
// when overlayfs's own types were positively seen (struct ovl_inode is the
// witness). A struct ovl_file must have a struct file *realfile member; its
// offset is relocated by CO-RE, so it is not pinned. Any failure is UNSET
// (the classifier then returns UNKNOWN).
func sharedImageOverlayLayout(overlay *btf.Spec) (uint32, error) {
	if overlay == nil {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("overlay BTF unavailable")
	}
	// A split spec may carry a type name more than once (a module's own copy
	// of a vmlinux type): look types up by name, never by a unique match.
	if n, err := btfStructs(overlay, "ovl_inode"); err != nil || len(n) == 0 {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("overlay BTF carries no overlayfs types (struct ovl_inode): %w", err)
	}
	files, err := btfStructs(overlay, "ovl_file")
	if err != nil {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("overlay BTF lookup: %w", err)
	}
	if len(files) == 0 {
		return sharedImageOverlayLayoutRealFile, nil
	}
	if len(files) != 1 {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("overlay BTF has %d struct ovl_file", len(files))
	}
	st := files[0]
	for _, m := range st.Members {
		if m.Name != "realfile" {
			continue
		}
		if m.BitfieldSize != 0 || m.Offset%8 != 0 || !isFilePointer(m.Type) {
			return sharedImageOverlayLayoutUnset, fmt.Errorf("struct ovl_file.realfile is not a struct file * member")
		}
		return sharedImageOverlayLayoutOvlFile, nil
	}
	return sharedImageOverlayLayoutUnset, fmt.Errorf("struct ovl_file has no realfile member")
}

// btfStructs returns every struct named name in spec (none is not an error).
func btfStructs(spec *btf.Spec, name string) ([]*btf.Struct, error) {
	types, err := spec.AnyTypesByName(name)
	if err != nil && !errors.Is(err, btf.ErrNotFound) {
		return nil, err
	}
	var out []*btf.Struct
	for _, t := range types {
		if st, ok := t.(*btf.Struct); ok {
			out = append(out, st)
		}
	}
	return out, nil
}

func isFilePointer(t btf.Type) bool {
	p, ok := btf.UnderlyingType(t).(*btf.Pointer)
	if !ok {
		return false
	}
	st, ok := btf.UnderlyingType(p.Target).(*btf.Struct)
	return ok && st.Name == "file"
}

// overlayTypesSpec is the BTF that carries overlayfs's private types on the
// running kernel: /sys/kernel/btf/overlay (sysfs-checked, bounded) as a split
// spec over the running vmlinux BTF, or the vmlinux BTF itself when overlayfs
// is built in (it then has struct ovl_inode). Neither: fs.ErrNotExist (the
// overlay module is not loaded).
func overlayTypesSpec() (*btf.Spec, error) {
	vmlinux, err := readSysfsBTF("/sys/kernel/btf/vmlinux")
	if err != nil {
		return nil, err
	}
	base, err := btf.LoadSpecFromReader(bytes.NewReader(vmlinux))
	if err != nil {
		return nil, fmt.Errorf("vmlinux BTF: %w", err)
	}
	module, err := readSysfsBTF("/sys/kernel/btf/overlay")
	if errors.Is(err, fs.ErrNotExist) {
		if n, _ := btfStructs(base, "ovl_inode"); len(n) != 0 {
			return base, nil // built in
		}
		return nil, fmt.Errorf("overlay module BTF: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("overlay module BTF: %w", err)
	}
	return btf.LoadSplitSpecFromReader(bytes.NewReader(module), base)
}

// Seams for tests: the live layout read and the overlay module autoload.
var (
	overlayLayoutReader = liveSharedImageOverlayLayout
	overlayModuleLoader = autoloadOverlayModule
)

// sharedOverlayLayoutFailure is why the last constants computation could not
// select an overlay layout (nil: it did). Kernel-global, so process-global.
var sharedOverlayLayoutFailure atomic.Pointer[error]

// sharedImageOverlayUnavailable is the node-visible "overlay layout
// unavailable" reason, nil when the layout is set. FromImage publishes are
// refused with it (productImageIndex.build) and node health is Degraded.
func sharedImageOverlayUnavailable() error {
	if p := sharedOverlayLayoutFailure.Load(); p != nil {
		return fmt.Errorf("overlay layout unavailable: %w", *p)
	}
	return nil
}

// resolveSharedImageOverlayLayout reads the live layout. If the overlay
// module BTF is absent (overlay.ko not loaded yet: the agent started before
// any container) it first asks the kernel to load the module, then re-reads.
func resolveSharedImageOverlayLayout() (uint32, error) {
	layout, err := overlayLayoutReader()
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return layout, err
	}
	if lerr := overlayModuleLoader(); lerr != nil {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("%w; module autoload: %w", err, lerr)
	}
	return overlayLayoutReader()
}

// autoloadOverlayModule triggers the kernel's filesystem-type autoload
// (request_module("fs-overlay")) with fsopen(2), which creates no mount. It
// needs CAP_SYS_ADMIN (fsopen) and the kernel's modprobe path; no
// CAP_SYS_MODULE is used by the agent itself.
func autoloadOverlayModule() error {
	fd, err := unix.Fsopen("overlay", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("fsopen overlay: %w", err)
	}
	return unix.Close(fd)
}

// liveSharedImageOverlayLayout is the layout of the running kernel, from its
// overlay BTF shape; any failure is UNSET with the error.
func liveSharedImageOverlayLayout() (uint32, error) {
	overlay, err := overlayTypesSpec()
	if err != nil {
		return sharedImageOverlayLayoutUnset, err
	}
	return sharedImageOverlayLayout(overlay)
}

func verifySupportedKernel() error {
	return verifyKernelBTF(supportedKernelBTF, "persistent-owner")
}

// verifySharedCandidateKernel admits only sharedCandidateKernelBTF. D3: with
// the test-only probed-kernel override (qualification builds, explicit
// opt-in) a kernel outside that matrix is admitted on its probes instead
// (verifySharedProbedKernel: still x86_64, bpf LSM,
// ftrace on, no livepatch).
func verifySharedCandidateKernel() error {
	err := verifyKernelBTF(func(digest string) bool {
		_, ok := sharedCandidateKernelBTF[digest]
		return ok
	}, "shared candidate")
	if err == nil || !sharedProbedKernelOverride() {
		return err
	}
	if perr := verifySharedProbedKernel(sharedProductKernelProbes); perr != nil {
		return fmt.Errorf("%w; %w", err, perr)
	}
	return nil
}

func verifyKernelBTF(supported func(string) bool, matrix string) error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("%s matrix requires a proved x86_64 kernel", matrix)
	}
	digest, err := kernelBTFDigest()
	if err != nil {
		return err
	}
	if !supported(digest) {
		return fmt.Errorf("kernel BTF is outside proved %s matrix (sha256 %s)", matrix, digest)
	}
	return checkKernelControls()
}

// sharedProductKernelProbe reads the running kernel's identity and controls
// for verifySharedProductKernel. Tests replace sharedProductKernelProbes.
type sharedProductKernelProbe struct {
	arch      func() string
	btfDigest func() (string, error)
	release   func() (string, error)
	buildID   func() (string, error)
	lsm       func() (string, error)
	ftrace    func() (string, error)
	tainted   func() (string, error)
}

var sharedProductKernelProbes = sharedProductKernelProbe{
	arch:      func() string { return runtime.GOARCH },
	btfDigest: kernelBTFDigest,
	release:   kernelRelease,
	buildID:   kernelBuildID,
	lsm:       func() (string, error) { return readKernelLSM(kernelLSMRoots()) },
	ftrace:    func() (string, error) { return readProcSys("/proc/sys/kernel/ftrace_enabled") },
	tainted:   func() (string, error) { return readProcSys("/proc/sys/kernel/tainted") },
}

// sharedProductKernelCheck is the product kernel gate; tests replace it.
var sharedProductKernelCheck = verifySharedProductKernel

// verifySharedProductKernel admits only an exact sharedProductPins build:
// x86_64, a pinned vmlinux BTF digest, its release and GNU build-id, the bpf
// LSM active, ftrace enabled and no livepatch (verifyKernelIdentity, the
// check exported as VerifyKernel). It returns the BTF digest and its pin.
// Every refusal wraps ErrSharedNativeUnavailable with the reason.
func verifySharedProductKernel() (string, sharedProductPin, error) {
	id, err := verifyKernelIdentity(sharedProductKernelProbes, sharedProductIdentities)
	if err != nil {
		return "", sharedProductPin{}, fmt.Errorf("shared product node refused: %w: %w", err, ErrSharedNativeUnavailable)
	}
	pin, ok := sharedProductPins[id.BTF]
	if !ok {
		return "", sharedProductPin{}, fmt.Errorf("shared product node refused: no product pin for BTF %s: %w", id.BTF, ErrSharedNativeUnavailable)
	}
	return id.BTF, pin, nil
}

// taintLivepatch is TAINT_LIVEPATCH (bit 15, include/linux/panic.h).
const taintLivepatch = 1 << 15

// checkSharedProductKernelRuntime re-reads the two controls that can change
// while the agent runs: ftrace_enabled (with ftrace off the fentry/fexit
// trampolines stop) and the livepatch taint (a livepatch changes exec-path
// text without changing the BTF or the build-id). Never cached.
func checkSharedProductKernelRuntime(p sharedProductKernelProbe) error {
	ftrace, err := p.ftrace()
	if err != nil {
		return kernelCheckFailed(KernelCheckFtrace, fmt.Errorf("ftrace_enabled: %w", err))
	}
	if strings.TrimSpace(ftrace) != "1" {
		return kernelCheckFailed(KernelCheckFtrace, fmt.Errorf("ftrace is not enabled (kernel.ftrace_enabled=%s)", strings.TrimSpace(ftrace)))
	}
	tainted, err := p.tainted()
	if err != nil {
		return kernelCheckFailed(KernelCheckLivepatch, fmt.Errorf("kernel taint: %w", err))
	}
	mask, err := strconv.ParseUint(strings.TrimSpace(tainted), 10, 64)
	if err != nil {
		return kernelCheckFailed(KernelCheckLivepatch, fmt.Errorf("kernel taint %q: %w", strings.TrimSpace(tainted), err))
	}
	if mask&taintLivepatch != 0 {
		return kernelCheckFailed(KernelCheckLivepatch, fmt.Errorf("kernel is livepatched (taint %d has TAINT_LIVEPATCH)", mask))
	}
	return nil
}

// readProcSys reads a small /proc/sys value, refusing anything not on
// procfs (a bind-mounted or replaced file cannot fake a kernel control).
func readProcSys(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return "", err
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return "", fmt.Errorf("%s is not on procfs", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", err
	}
	if len(data) > 4096 {
		return "", fmt.Errorf("%s exceeds 4096 bytes", path)
	}
	return string(data), nil
}

// kernelRelease is uname -r.
func kernelRelease() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(u.Release[:]), nil
}

// kernelBuildID is the running vmlinux GNU build-id from /sys/kernel/notes
// (sysfs-checked, at most 64 KiB).
func kernelBuildID() (string, error) {
	notes, err := readSysfsFile("/sys/kernel/notes", 64<<10, "kernel notes")
	if err != nil {
		return "", err
	}
	return parseGNUBuildID(notes)
}

// ntGNUBuildID is NT_GNU_BUILD_ID (elf.h).
const ntGNUBuildID = 3

// parseGNUBuildID returns the hex descriptor of the one "GNU" NT_GNU_BUILD_ID
// note in an ELF note section (Elf64_Nhdr: namesz, descsz, type, each a
// native-endian 32-bit word; name and descriptor padded to 4 bytes). A
// truncated note, no build-id or more than one is an error.
func parseGNUBuildID(notes []byte) (string, error) {
	var found string
	for len(notes) > 0 {
		if len(notes) < 12 {
			return "", fmt.Errorf("truncated note header")
		}
		namesz, descsz, typ := binary.NativeEndian.Uint32(notes), binary.NativeEndian.Uint32(notes[4:]), binary.NativeEndian.Uint32(notes[8:])
		notes = notes[12:]
		nameLen, descLen := align4(uint64(namesz)), align4(uint64(descsz))
		if nameLen+descLen > uint64(len(notes)) {
			return "", fmt.Errorf("truncated note (name %d, descriptor %d bytes)", namesz, descsz)
		}
		name, desc := notes[:namesz], notes[nameLen:nameLen+uint64(descsz)]
		notes = notes[nameLen+descLen:]
		if typ != ntGNUBuildID || string(name) != "GNU\x00" {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("more than one GNU build-id note")
		}
		if len(desc) == 0 {
			return "", fmt.Errorf("empty GNU build-id note")
		}
		found = hex.EncodeToString(desc)
	}
	if found == "" {
		return "", fmt.Errorf("no GNU build-id note")
	}
	return found, nil
}

func align4(n uint64) uint64 { return (n + 3) &^ 3 }

var (
	kernelBTFDigestMu    sync.Mutex
	kernelBTFDigestValue string
	// kernelBTFRead reads the running vmlinux BTF; tests replace it.
	kernelBTFRead = func() ([]byte, error) { return readSysfsBTF("/sys/kernel/btf/vmlinux") }
)

// kernelBTFDigest is the sha256 of the running kernel's sysfs vmlinux BTF.
// Only a successful digest is cached (the running kernel's BTF cannot
// change); a failed read is retried on the next call.
func kernelBTFDigest() (string, error) {
	kernelBTFDigestMu.Lock()
	defer kernelBTFDigestMu.Unlock()
	if kernelBTFDigestValue != "" {
		return kernelBTFDigestValue, nil
	}
	data, err := kernelBTFRead()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	kernelBTFDigestValue = hex.EncodeToString(sum[:])
	return kernelBTFDigestValue, nil
}

// readSysfsBTF reads a kernel BTF file, refusing anything not on sysfs or
// larger than 128 MiB.
func readSysfsBTF(path string) ([]byte, error) {
	return readSysfsFile(path, 128<<20, "kernel BTF")
}

// readSysfsFile reads a sysfs file of at most limit bytes, refusing anything
// not on sysfs; what names it in errors.
func readSysfsFile(path string, limit int64, what string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.SYSFS_MAGIC {
		return nil, fmt.Errorf("%s is not on sysfs", what)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", what, limit)
	}
	return data, nil
}

// sharedImageOverlayConstants are the native constants (operators.
// NativeConstantsKey) of one shared candidate collection load on the running
// kernel: the se_image_ovl_layout of the exact matrix kernel (off the matrix
// UNSET: the classifier then refuses every overlay file as UNKNOWN (AUTH),
// never from-image), and the load's random nonzero se_verdict_load_epoch
// (review M7: task_cookie restarts per load, so verdict events are keyed by
// (load_epoch, task_cookie, exec_id)).
func sharedImageOverlayConstants() (map[string]any, error) {
	layout, err := resolveSharedImageOverlayLayout()
	if err != nil {
		layout = sharedImageOverlayLayoutUnset
		reason := err
		sharedOverlayLayoutFailure.Store(&reason)
	} else {
		sharedOverlayLayoutFailure.Store(nil)
	}
	epoch, err := sharedVerdictLoadEpoch()
	if err != nil {
		return nil, err
	}
	// FMODE_BACKING: the pinned bit on a pinned kernel (cross-checked by the
	// live probe), the probed bit elsewhere (kernel_probe.go). Unset (0)
	// with a layout is refused by the classifier like an unset layout, with
	// the reason; a failure is not cached, the next load computes it again.
	backing := uint32(0)
	if layout != sharedImageOverlayLayoutUnset {
		if backing, err = fmodeBackingReader(layout); err != nil {
			backing = 0
			reason := err
			sharedOverlayLayoutFailure.Store(&reason)
		}
	}
	return map[string]any{sharedImageOverlayLayoutConstant: layout, sharedImageFmodeBackingConstant: backing, sharedVerdictLoadEpochConstant: epoch}, nil
}

// Native constant names (full/shared_image_classify.h,
// full/shared_verdict_event.h).
const (
	sharedImageOverlayLayoutConstant = "se_image_ovl_layout"
	sharedImageFmodeBackingConstant  = "se_image_fmode_backing"
	sharedVerdictLoadEpochConstant   = "se_verdict_load_epoch"
)

// sharedVerdictLoadEpoch is a random nonzero 64-bit load epoch.
func sharedVerdictLoadEpoch() (uint64, error) {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("verdict load epoch: %w", err)
		}
		if epoch := binary.LittleEndian.Uint64(b[:]); epoch != 0 {
			return epoch, nil
		}
	}
}

// kernelLSMRoots are the roots under which sys/kernel/security/lsm is read,
// in order: the host root (HOST_ROOT), then this process's own view. An
// unprivileged agent pod's /sys has no securityfs mounted, while the host's
// boot-time securityfs is visible under its host root mount. Falling back to
// the own view is equally correct: securityfs is one kernel-wide superblock
// (not namespaced), so every mount of it shows the same list, and the
// SECURITYFS_MAGIC check refuses anything that is not that filesystem.
var kernelLSMRoots = func() []string { return []string{host.HostRoot, "/"} }

// readKernelLSM returns the active LSM list from the first root whose
// sys/kernel/security/lsm is on securityfs; every failure is reported.
func readKernelLSM(roots []string) (string, error) {
	var errs []error
	seen := map[string]bool{}
	for _, root := range roots {
		path := filepath.Join(root, "sys/kernel/security/lsm")
		if seen[path] {
			continue
		}
		seen[path] = true
		data, err := readSecurityFSFile(root, "sys/kernel/security/lsm")
		if err == nil {
			return data, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return "", fmt.Errorf("no LSM list root")
	}
	return "", errors.Join(errs...)
}

// readSecurityFSFile opens name with root as its filesystem root
// (RESOLVE_IN_ROOT): a symlink inside the host tree cannot redirect the read
// outside it, e.g. onto a file in the agent's own filesystem.
func readSecurityFSFile(root, name string) (string, error) {
	path := filepath.Join(root, name)
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("%s: %w", root, err)
	}
	fd, err := unix.Openat2(rootFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
	closeErr := unix.Close(rootFD)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if closeErr != nil {
		return "", closeErr
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return "", err
	}
	if fs.Type != unix.SECURITYFS_MAGIC {
		return "", fmt.Errorf("%s is not on securityfs", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", err
	}
	if len(data) > 4096 {
		return "", fmt.Errorf("%s exceeds 4096 bytes", path)
	}
	return string(data), nil
}

// requireBPFLSM refuses an LSM list without the exact "bpf" entry.
func requireBPFLSM(lsm string) error {
	for _, name := range strings.Split(strings.TrimSpace(lsm), ",") {
		if name == "bpf" {
			return nil
		}
	}
	return fmt.Errorf("BPF LSM not active")
}

func checkKernelControls() error {
	lsm, err := readKernelLSM(kernelLSMRoots())
	if err != nil {
		return err
	}
	if err = requireBPFLSM(lsm); err != nil {
		return err
	}
	ftrace, err := os.ReadFile("/proc/sys/kernel/ftrace_enabled")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(ftrace)) != "1" {
		return fmt.Errorf("ftrace is not enabled")
	}
	return nil
}
