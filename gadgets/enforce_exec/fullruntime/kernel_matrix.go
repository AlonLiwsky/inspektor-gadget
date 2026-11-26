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

// sharedProductObjects is the sha256 set of the product objects of THIS
// release, by profile. D3: one CO-RE object per profile for every kernel
// (they were one set per kernel build: the per-kernel objects differed only
// in unrelocated CO-RE placeholders and in the BTF/DWARF copied from each
// kernel's vmlinux.h). The values are those of bpf/build-product.sh with the
// pinned toolchain at the neutral paths; testdata/shared_product_objects.tsv
// mirrors them.
var sharedProductObjects = map[string]string{
	"g19pkg64":  "77cca2db878a3dbd32ab9180c52522bcf023075f000591ea42756d8968373042",
	"g19pkg128": "c0d64c970473d27216300e78482e429af7b0fdf2eb49d2af8c72b46827ffea5b",
	"g19pkg256": "f67aaf9bb71d4b3c6902fea7f5aa00f6cb565904b01019fb8a33f8907986dd10",
	"g19pkg512": "8621ad3ce16dfbc3f966dd3ce4c78306da328e59edcda41f13a72de027f5879c",
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

// verifySharedCandidateKernel admits the qualified candidate's kernel
// (qualification builds only) on the product gate's checks
// (admitKernelIdentity). The canary negative test may skip the LSM-list
// check (sharedSkipLSMListGate) to show that the startup canary alone
// refuses a kernel whose BPF LSM programs never run.
func verifySharedCandidateKernel() error {
	p := sharedProductKernelProbes
	if sharedSkipLSMListGate() {
		p.lsm = func() (string, error) { return "bpf", nil }
	}
	_, err := admitKernelIdentity(p)
	return err
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

// verifySharedProductKernel is the product kernel gate (admitKernelIdentity,
// the check exported as AdmitKernel): amd64, a readable lowercase-hex vmlinux
// BTF sha256, a non-empty release, a lowercase-hex GNU build-id, bpf LSM
// active, ftrace enabled and no livepatch. Every kernel is admitted the same
// way, on these checks; no build list is consulted. It returns the running
// kernel's identity. Every refusal wraps both the *KernelCheckError and
// ErrSharedNativeUnavailable.
func verifySharedProductKernel() (KernelIdentity, error) {
	id, err := admitKernelIdentity(sharedProductKernelProbes)
	if err != nil {
		return KernelIdentity{}, fmt.Errorf("shared product node refused: %w: %w", err, ErrSharedNativeUnavailable)
	}
	return id, nil
}

// SharedProductKernel is the product kernel gate on the running kernel
// (amd64, a readable BTF digest, release and build-id, bpf LSM active,
// ftrace enabled, no livepatch) and returns its identity for status
// reporting. StartNode's product path and the product image admission run
// the same gate. A refusal wraps both a *KernelCheckError (errors.As) and
// ErrSharedNativeUnavailable.
func SharedProductKernel() (KernelIdentity, error) {
	return sharedProductKernelCheck()
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
// kernel: the se_image_ovl_layout probed from the overlay BTF (UNSET when
// it cannot be resolved: the classifier then refuses every overlay file as
// UNKNOWN (AUTH), never from-image), and the load's random nonzero se_verdict_load_epoch
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
	// FMODE_BACKING: the live probe's bit on every kernel (kernel_probe.go;
	// a failed probe refuses). Unset (0)
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
