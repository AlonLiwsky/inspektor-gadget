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
	// OuterSymbol and HandlerSymbol are the failure_outer_* and
	// failure_handler_* kprobe targets the qualified loader resolved.
	OuterSymbol, HandlerSymbol string
	// ProductELF is the sha256 set of the qualified product objects for this
	// kernel (g19pkg64/128/256/512).
	ProductELF map[string]struct{}
}

// sharedProductPins maps a vmlinux BTF sha256 to its pinned build.
var sharedProductPins = map[string]sharedProductPin{
	"0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82": {
		Release:       "6.12.113-138.209.amzn2023.x86_64",
		BuildID:       "1d135d67e6d0ea8f77d60a2984915eadd28a5fcf",
		OuterSymbol:   "do_execveat_common.isra.0",
		HandlerSymbol: "search_binary_handler",
		ProductELF: map[string]struct{}{
			"2e2b033bde0ece73ac9f95fd7455fcf36be7aa32250f52e527aff4bd86546be9": {}, // g19pkg64
			"b7245ddfbb7bac323921d0583b67295789e9f3f22cd7460e36f9f37b65b10c31": {}, // g19pkg128
			"86f04ecc2f919c91992487c85b7be038feee39cec9dfd99187dcd64bc863e5b3": {}, // g19pkg256
			"16dfb0eaa510d3d5ae9c744d3c8f9023047724f6a2ad253da33629d6a74c3404": {}, // g19pkg512
		},
	},
	"d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee": {
		Release:       "6.18.56-125.164.amzn2023.x86_64",
		BuildID:       "884ed4548406a1461ac5fb658c0dffdd87f1b3b2",
		OuterSymbol:   "do_execveat_common.isra.0",
		HandlerSymbol: "exec_binprm",
		ProductELF: map[string]struct{}{
			"1ab606ec132732984cd682438dd2ca6be0e98f6bfa567c263d1263326ee351ce": {}, // g19pkg64
			"142ae885221167eaf258678f508999eb0528447b53355eb5d776ae009b6115ae": {}, // g19pkg128
			"074ce03442631ab34462de5802addb67c3e783109c6de8b9ec55f05091b2d38a": {}, // g19pkg256
			"370f971574941b15fcee31dbeb6d6d2467db189a1618a877d8c4636d5afc940c": {}, // g19pkg512
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
// SE_IMAGE_OVL_LAYOUT_*). struct ovl_file is overlay-module private and absent
// from vmlinux BTF, so the layout is pinned per exact kernel, never CO-RE.
const (
	sharedImageOverlayLayoutUnset    uint32 = 0
	sharedImageOverlayLayoutRealFile uint32 = 1 // 6.12 fs/overlayfs/file.c:170
	sharedImageOverlayLayoutOvlFile  uint32 = 2 // 6.18 fs/overlayfs/file.c:92-95,232
)

// sharedImageOverlayLayouts maps every sharedCandidateKernelBTF release to its
// source-verified overlay layout.
var sharedImageOverlayLayouts = map[string]uint32{
	"6.12.113-138.209.amzn2023.x86_64": sharedImageOverlayLayoutRealFile,
	"6.18.56-125.164.amzn2023.x86_64":  sharedImageOverlayLayoutOvlFile,
}

// sharedImageOverlayLayout selects the se_image_ovl_layout constant for an
// exact shared-candidate vmlinux BTF digest AND the overlay module BTF split
// spec (review M6: struct ovl_file lives in the overlay module, not vmlinux,
// so the vmlinux digest alone does not pin it). The digest picks the expected
// layout; the module BTF must then confirm its exact type shape. A nil spec
// (overlay module BTF absent), any other kernel or any shape mismatch is
// refused (UNSET: the classifier then returns UNKNOWN).
func sharedImageOverlayLayout(btfDigest string, overlay *btf.Spec) (uint32, error) {
	release, ok := sharedCandidateKernelBTF[btfDigest]
	if !ok {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("kernel BTF %q outside the shared candidate matrix", btfDigest)
	}
	layout, ok := sharedImageOverlayLayouts[release]
	if !ok {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("no proved overlay layout for %s", release)
	}
	if overlay == nil {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("overlay module BTF unavailable for %s", release)
	}
	if err := checkOverlayLayoutShape(overlay, layout); err != nil {
		return sharedImageOverlayLayoutUnset, fmt.Errorf("%s: %w", release, err)
	}
	return layout, nil
}

// checkOverlayLayoutShape verifies the overlay module BTF against the layout:
// 6.18 (OvlFile) requires struct ovl_file {struct file *realfile @0; struct
// file *upperfile @8} size 16 (fs/overlayfs/file.c:92-95); 6.12 (RealFile)
// requires struct ovl_file ABSENT (private_data is the realfile itself).
func checkOverlayLayoutShape(overlay *btf.Spec, layout uint32) error {
	var st *btf.Struct
	err := overlay.TypeByName("ovl_file", &st)
	switch layout {
	case sharedImageOverlayLayoutRealFile:
		if err == nil {
			return fmt.Errorf("struct ovl_file present in overlay BTF, expected absent for the realfile layout")
		}
		if !errors.Is(err, btf.ErrNotFound) {
			return fmt.Errorf("overlay BTF lookup: %w", err)
		}
		return nil
	case sharedImageOverlayLayoutOvlFile:
		if err != nil {
			return fmt.Errorf("struct ovl_file in overlay BTF: %w", err)
		}
		if st.Size != 16 || len(st.Members) != 2 {
			return fmt.Errorf("struct ovl_file size %d members %d, want 16 and 2", st.Size, len(st.Members))
		}
		for i, name := range []string{"realfile", "upperfile"} {
			m := st.Members[i]
			if m.Name != name || m.Offset != btf.Bits(i*64) || m.BitfieldSize != 0 || !isFilePointer(m.Type) {
				return fmt.Errorf("struct ovl_file member %d is %q @%d bits, want struct file *%s @%d bits", i, m.Name, m.Offset, name, i*64)
			}
		}
		return nil
	default:
		return fmt.Errorf("no overlay shape for layout %d", layout)
	}
}

func isFilePointer(t btf.Type) bool {
	p, ok := t.(*btf.Pointer)
	if !ok {
		return false
	}
	st, ok := p.Target.(*btf.Struct)
	return ok && st.Name == "file"
}

// overlayModuleSpec loads /sys/kernel/btf/overlay (sysfs-checked, bounded) as
// a split spec over the running vmlinux BTF. A missing file means the overlay
// module is not loaded (or is built in): refused.
func overlayModuleSpec() (*btf.Spec, error) {
	vmlinux, err := readSysfsBTF("/sys/kernel/btf/vmlinux")
	if err != nil {
		return nil, err
	}
	base, err := btf.LoadSpecFromReader(bytes.NewReader(vmlinux))
	if err != nil {
		return nil, fmt.Errorf("vmlinux BTF: %w", err)
	}
	module, err := readSysfsBTF("/sys/kernel/btf/overlay")
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

// liveSharedImageOverlayLayout is the layout of the running kernel: vmlinux
// digest plus overlay module BTF shape; any failure is UNSET with the error.
func liveSharedImageOverlayLayout() (uint32, error) {
	digest, err := kernelBTFDigest()
	if err != nil {
		return sharedImageOverlayLayoutUnset, err
	}
	overlay, err := overlayModuleSpec()
	if err != nil {
		return sharedImageOverlayLayoutUnset, err
	}
	return sharedImageOverlayLayout(digest, overlay)
}

func verifySupportedKernel() error {
	return verifyKernelBTF(supportedKernelBTF, "persistent-owner")
}

// verifySharedCandidateKernel admits only sharedCandidateKernelBTF.
func verifySharedCandidateKernel() error {
	return verifyKernelBTF(func(digest string) bool {
		_, ok := sharedCandidateKernelBTF[digest]
		return ok
	}, "shared candidate")
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
// LSM active, ftrace enabled and no livepatch. It returns the BTF digest and
// its pin. Every refusal wraps ErrSharedNativeUnavailable with the reason.
func verifySharedProductKernel() (string, sharedProductPin, error) {
	refuse := func(cause error) (string, sharedProductPin, error) {
		return "", sharedProductPin{}, fmt.Errorf("shared product node refused: %w: %w", cause, ErrSharedNativeUnavailable)
	}
	p := sharedProductKernelProbes
	if arch := p.arch(); arch != "amd64" {
		return refuse(fmt.Errorf("shared product node requires x86_64, running on %s", arch))
	}
	digest, err := p.btfDigest()
	if err != nil {
		return refuse(fmt.Errorf("kernel BTF: %w", err))
	}
	pin, ok := sharedProductPins[digest]
	if !ok {
		return refuse(fmt.Errorf("kernel BTF sha256 %s is not a qualified shared product kernel build", digest))
	}
	release, err := p.release()
	if err != nil {
		return refuse(fmt.Errorf("kernel release: %w", err))
	}
	if release != pin.Release {
		return refuse(fmt.Errorf("kernel release %q, the pinned BTF %s is %q", release, digest, pin.Release))
	}
	buildID, err := p.buildID()
	if err != nil {
		return refuse(fmt.Errorf("kernel build-id: %w", err))
	}
	if buildID != pin.BuildID {
		return refuse(fmt.Errorf("kernel build-id %s, %s is pinned to %s", buildID, pin.Release, pin.BuildID))
	}
	lsm, err := p.lsm()
	if err != nil {
		return refuse(fmt.Errorf("LSM list: %w", err))
	}
	if err := requireBPFLSM(lsm); err != nil {
		return refuse(err)
	}
	if err := checkSharedProductKernelRuntime(p); err != nil {
		return refuse(err)
	}
	return digest, pin, nil
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
		return fmt.Errorf("ftrace_enabled: %w", err)
	}
	if strings.TrimSpace(ftrace) != "1" {
		return fmt.Errorf("ftrace is not enabled (kernel.ftrace_enabled=%s)", strings.TrimSpace(ftrace))
	}
	tainted, err := p.tainted()
	if err != nil {
		return fmt.Errorf("kernel taint: %w", err)
	}
	mask, err := strconv.ParseUint(strings.TrimSpace(tainted), 10, 64)
	if err != nil {
		return fmt.Errorf("kernel taint %q: %w", strings.TrimSpace(tainted), err)
	}
	if mask&taintLivepatch != 0 {
		return fmt.Errorf("kernel is livepatched (taint %d has TAINT_LIVEPATCH)", mask)
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
	return map[string]any{sharedImageOverlayLayoutConstant: layout, sharedVerdictLoadEpochConstant: epoch}, nil
}

// Native constant names (full/shared_image_classify.h,
// full/shared_verdict_event.h).
const (
	sharedImageOverlayLayoutConstant = "se_image_ovl_layout"
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
