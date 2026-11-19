// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// D3 (universal-kernel spike): runtime feature probing for the single CO-RE
// product object. Nothing here admits a kernel by itself in a default build:
// the product path still requires an exact pinned build (kernel_matrix.go).
// A qualification build may admit a probed kernel with an explicit test-only
// override (kernel_probe_override_tag.go).
//
// What the probes cover, and what they cannot:
//   - every kernel type, field, kfunc and BTF attach target the object needs
//     is checked by the object's own load (CO-RE relocation and the verifier),
//     so it is not duplicated here;
//   - stage 1 (D1): there are no failure-frame kprobe, kretprobe, fentry or
//     fexit targets; the exec outcome comes from BPF LSM and tracepoints
//     only, all BTF attach targets checked by the load;
//   - FMODE_BACKING is a preprocessor constant (not in BTF): probed live;
//   - hook ordering and semantics are NOT probed. They stay a per-family
//     qualification question (or D4's behavioural self-test).

// FMODE_BACKING candidates (include/linux/fs.h). The bit is a preprocessor
// constant: 1<<25 from v6.5 to v6.13 and in early 6.12.y, 1<<24 from v6.14
// and in later 6.12.y stable (measured: v6.12 has 25, 6.12.113 has 24, and
// the 6.12.113 BTF carries no type of the series that moved it). Neither the
// release nor BTF predicts it, so it is read from a live backing file.
const (
	sharedFmodeBacking24 uint32 = 1 << 24
	sharedFmodeBacking25 uint32 = 1 << 25
)

var (
	// Only a successful result is cached (the bit of the running kernel
	// cannot change); a failure is retried by the next constants computation.
	sharedFmodeBackingMu    sync.Mutex
	sharedFmodeBackingValue uint32
	// sharedFmodeBackingNote is how the last result was obtained (diagnostic).
	sharedFmodeBackingNote atomic.Pointer[string]
	// fmodeBackingReader is the bit the loader installs; tests replace it.
	fmodeBackingReader = sharedFmodeBacking
	// Seams of sharedFmodeBacking: the live probe and the pinned bit.
	fmodeBackingProbe  = probeSharedFmodeBacking
	fmodeBackingPinned = pinnedSharedFmodeBacking
)

// pinnedSharedFmodeBacking is the source-verified FMODE_BACKING bit of the
// running kernel when it is one of the exact pinned builds.
func pinnedSharedFmodeBacking() (uint32, bool) {
	digest, err := kernelBTFDigest()
	if err != nil {
		return 0, false
	}
	pin, ok := sharedProductPins[digest]
	return pin.FmodeBacking, ok && pin.FmodeBacking != 0
}

// sharedFmodeBacking is the FMODE_BACKING bit for the running kernel.
//
// On a pinned kernel the pinned bit is authoritative and the live probe only
// cross-checks it: a probe that cannot run (no usable layer directory, a
// transient error) changes nothing, a probe that contradicts the pin refuses.
// On any other kernel (qualification builds only) the bit is the probe's, and
// a failed probe refuses. A refusal is never cached.
func sharedFmodeBacking(layout uint32) (uint32, error) {
	sharedFmodeBackingMu.Lock()
	defer sharedFmodeBackingMu.Unlock()
	if sharedFmodeBackingValue != 0 {
		return sharedFmodeBackingValue, nil
	}
	note := func(format string, args ...any) {
		s := fmt.Sprintf(format, args...)
		sharedFmodeBackingNote.Store(&s)
	}
	pinned, isPinned := fmodeBackingPinned()
	probed, err := fmodeBackingProbe(layout)
	switch {
	case isPinned && err != nil:
		// Not cached: the next computation cross-checks again.
		note("pinned %#x; cross-check unavailable: %v", pinned, err)
		return pinned, nil
	case isPinned && probed != pinned:
		err = fmt.Errorf("FMODE_BACKING: the live probe (%#x) contradicts the pinned bit (%#x)", probed, pinned)
		note("refused: %v", err)
		return 0, err
	case err != nil:
		note("refused: %v", err)
		return 0, err
	case isPinned:
		note("pinned %#x; confirmed by the live probe", pinned)
	default:
		note("probed %#x", probed)
	}
	sharedFmodeBackingValue = probed
	return probed, nil
}

// probeSharedFmodeBacking finds the FMODE_BACKING bit of the running kernel.
// It builds a detached overlay mount (new mount API: nothing enters a mount
// namespace or a visible path) over a detached tmpfs, opens one lower file
// through the overlay and the same file directly, and reads both struct
// file.f_mode values with a task_file iterator (this process's fds): the
// overlay's real file is a backing file (alloc_empty_backing_file), the
// direct one is not. The bit is the candidate set only in the backing file's
// mode; any other outcome is refused (0).
//
// layout is the probed overlay private_data layout: the real file is
// private_data itself (REALFILE) or *(struct file **)(private_data +
// offsetof(struct ovl_file, realfile)) (OVL_FILE).
func probeSharedFmodeBacking(layout uint32) (uint32, error) {
	if layout != sharedImageOverlayLayoutRealFile && layout != sharedImageOverlayLayoutOvlFile {
		return 0, fmt.Errorf("FMODE_BACKING probe: no overlay layout")
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return 0, fmt.Errorf("FMODE_BACKING probe: kernel BTF: %w", err)
	}
	modeOff, err := btfMemberOffset(kernel, "file", "f_mode")
	if err != nil {
		return 0, err
	}
	privOff, err := btfMemberOffset(kernel, "file", "private_data")
	if err != nil {
		return 0, err
	}
	pidOff, err := btfMemberOffset(kernel, "task_struct", "tgid")
	if err != nil {
		return 0, err
	}
	realOff := uint32(0)
	if layout == sharedImageOverlayLayoutOvlFile {
		overlay, err := overlayTypesSpec()
		if err != nil {
			return 0, err
		}
		if realOff, err = btfMemberOffset(overlay, "ovl_file", "realfile"); err != nil {
			return 0, err
		}
	}

	type result struct {
		mode uint32
		err  error
	}
	var out [2]result
	ovl, plain, cleanup, err := openOverlayProbeFiles()
	if err != nil {
		return 0, fmt.Errorf("FMODE_BACKING probe: %w", err)
	}
	defer cleanup()
	out[0].mode, out[0].err = readFileMode(ovl, pidOff, modeOff, privOff, realOff, layout, true)
	out[1].mode, out[1].err = readFileMode(plain, pidOff, modeOff, privOff, realOff, layout, false)
	if out[0].err != nil {
		return 0, fmt.Errorf("FMODE_BACKING probe: backing file: %w", out[0].err)
	}
	if out[1].err != nil {
		return 0, fmt.Errorf("FMODE_BACKING probe: plain file: %w", out[1].err)
	}
	only := out[0].mode &^ out[1].mode
	has24, has25 := only&sharedFmodeBacking24 != 0, only&sharedFmodeBacking25 != 0
	switch {
	case has24:
		// New numbering: 24 backing (25 is FMODE_NONOTIFY, which overlayfs
		// may also set on its real files).
		return sharedFmodeBacking24, nil
	case has25:
		// Old numbering: 25 backing, 24 unused (26 is FMODE_NONOTIFY).
		return sharedFmodeBacking25, nil
	default:
		return 0, fmt.Errorf("FMODE_BACKING probe: backing f_mode %#x, plain f_mode %#x: neither candidate bit distinguishes them", out[0].mode, out[1].mode)
	}
}

func btfMemberOffset(spec *btf.Spec, structName, member string) (uint32, error) {
	structs, err := btfStructs(spec, structName)
	if err != nil {
		return 0, fmt.Errorf("BTF struct %s: %w", structName, err)
	}
	if len(structs) != 1 {
		return 0, fmt.Errorf("BTF has %d struct %s, want 1", len(structs), structName)
	}
	for _, m := range structs[0].Members {
		if m.Name == member {
			if m.BitfieldSize != 0 || m.Offset%8 != 0 {
				return 0, fmt.Errorf("BTF %s.%s is a bitfield", structName, member)
			}
			return m.Offset.Bytes(), nil
		}
	}
	return 0, fmt.Errorf("BTF %s.%s: no such member", structName, member)
}

// overlayProbeTmpfsDirs are tried, in order, for the probe's layer
// directories when the detached tmpfs is refused: in a container /dev/shm
// and /run are tmpfs mounts of the container's own mount namespace, while
// $TMPDIR is usually the container's overlay root, which overlayfs refuses
// as an upper directory.
var overlayProbeTmpfsDirs = []string{"/dev/shm", "/run", "/tmp"}

// openOverlayProbeFiles returns one file opened through a detached overlay
// (fsmount: it enters no mount namespace and no visible path) and the same
// lower file opened directly. The layer directories are first tried on a
// detached tmpfs; kernels whose clone_private_mount requires the layer mount
// to be in the caller's mount namespace (measured: 6.12 and older refuse the
// detached tmpfs with EINVAL) get a private temporary directory instead,
// removed before returning: on a tmpfs of this mount namespace first
// (overlayProbeTmpfsDirs), on os.TempDir() last.
func openOverlayProbeFiles() (ovl, plain *os.File, cleanup func(), err error) {
	ovl, plain, cleanup, err = openOverlayProbeFilesOn(true, "")
	if err == nil {
		return ovl, plain, cleanup, nil
	}
	errs := []error{fmt.Errorf("detached tmpfs: %w", err)}
	dirs := make([]string, 0, len(overlayProbeTmpfsDirs)+1)
	for _, dir := range overlayProbeTmpfsDirs {
		var st unix.Statfs_t
		if unix.Statfs(dir, &st) == nil && st.Type == unix.TMPFS_MAGIC {
			dirs = append(dirs, dir)
		}
	}
	dirs = append(dirs, os.TempDir())
	for _, dir := range dirs {
		if ovl, plain, cleanup, err = openOverlayProbeFilesOn(false, dir); err == nil {
			return ovl, plain, cleanup, nil
		}
		errs = append(errs, fmt.Errorf("on %s: %w", dir, err))
	}
	return nil, nil, nil, errors.Join(errs...)
}

func openOverlayProbeFilesOn(detachedTmpfs bool, parent string) (ovl, plain *os.File, cleanup func(), err error) {
	var fds []int
	tmpdir := ""
	closeAll := func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		if tmpdir != "" {
			_ = os.RemoveAll(tmpdir)
		}
	}
	fail := func(what string, err error) (*os.File, *os.File, func(), error) {
		closeAll()
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	var tmp int
	if detachedTmpfs {
		fsfd, err := unix.Fsopen("tmpfs", unix.FSOPEN_CLOEXEC)
		if err != nil {
			return fail("fsopen tmpfs", err)
		}
		fds = append(fds, fsfd)
		if err = unix.FsconfigCreate(fsfd); err != nil {
			return fail("fsconfig tmpfs create", err)
		}
		if tmp, err = unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, 0); err != nil {
			return fail("fsmount tmpfs", err)
		}
	} else {
		if tmpdir, err = os.MkdirTemp(parent, "ig-enforce-exec-fmode-"); err != nil {
			return fail("temporary directory", err)
		}
		if tmp, err = unix.Open(tmpdir, unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
			return fail("open temporary directory", err)
		}
	}
	fds = append(fds, tmp)
	for _, dir := range []string{"lower", "upper", "work"} {
		if err = unix.Mkdirat(tmp, dir, 0o700); err != nil {
			return fail("mkdir "+dir, err)
		}
	}
	lower, err := unix.Openat(tmp, "lower/probe", unix.O_CREAT|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fail("create lower file", err)
	}
	_ = unix.Close(lower)
	ofd, err := unix.Fsopen("overlay", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return fail("fsopen overlay", err)
	}
	fds = append(fds, ofd)
	base := fmt.Sprintf("/proc/self/fd/%d/", tmp)
	for _, kv := range [][2]string{{"lowerdir", "lower"}, {"upperdir", "upper"}, {"workdir", "work"}} {
		if err = unix.FsconfigSetString(ofd, kv[0], base+kv[1]); err != nil {
			return fail("fsconfig overlay "+kv[0], err)
		}
	}
	if err = unix.FsconfigCreate(ofd); err != nil {
		return fail("fsconfig overlay create", err)
	}
	mnt, err := unix.Fsmount(ofd, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		return fail("fsmount overlay", err)
	}
	fds = append(fds, mnt)
	o, err := unix.Openat(mnt, "probe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail("open overlay file", err)
	}
	p, err := unix.Openat(tmp, "lower/probe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(o)
		return fail("open lower file", err)
	}
	ovl, plain = os.NewFile(uintptr(o), "overlay-probe"), os.NewFile(uintptr(p), "lower-probe")
	return ovl, plain, func() {
		_ = ovl.Close()
		_ = plain.Close()
		closeAll()
	}, nil
}

// readFileMode returns f_mode of the struct file behind f (the calling
// thread's fd), or, with real set, of the overlay real file it points to. It
// runs a task_file iterator and matches this process (task->tgid) and fd. The program is built
// from offsets read from the running kernel's BTF (loader-side relocation):
// nothing is attached to an exec path.
func readFileMode(f *os.File, pidOff, modeOff, privOff, realOff, layout uint32, real bool) (uint32, error) {
	out, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return 0, fmt.Errorf("probe map: %w", err)
	}
	defer out.Close()
	// The iterator visits each files table once, through its thread-group
	// leader (threads sharing it are skipped): match the tgid.
	tgid := os.Getpid()
	// struct bpf_iter__task_file { meta @0; task @8; u32 fd @16; file @24 }.
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R7, asm.R6, 24, asm.DWord), // file (NULL at the end)
		asm.JEq.Imm(asm.R7, 0, "out"),
		asm.LoadMem(asm.R1, asm.R6, 16, asm.Word), // fd
		asm.JNE.Imm(asm.R1, int32(f.Fd()), "out"),
		asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord), // task
		asm.JEq.Imm(asm.R8, 0, "out"),
		asm.LoadMem(asm.R1, asm.R8, int16(pidOff), asm.Word), // task->tgid
		asm.JNE.Imm(asm.R1, int32(tgid), "out"),
	}
	if real {
		// r7 = file->private_data (a scalar for the verifier).
		insns = append(insns, asm.LoadMem(asm.R7, asm.R7, int16(privOff), asm.DWord))
		if layout == sharedImageOverlayLayoutOvlFile {
			insns = append(insns,
				// probe-read *(private + realOff) into the stack.
				asm.Mov.Reg(asm.R3, asm.R7), asm.Add.Imm(asm.R3, int32(realOff)),
				asm.StoreImm(asm.RFP, -16, 0, asm.DWord),
				asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -16),
				asm.Mov.Imm(asm.R2, 8),
				asm.FnProbeReadKernel.Call(),
				asm.JNE.Imm(asm.R0, 0, "out"),
				asm.LoadMem(asm.R7, asm.RFP, -16, asm.DWord),
			)
		}
		insns = append(insns, asm.JEq.Imm(asm.R7, 0, "out"))
	}
	insns = append(insns,
		// value = (1 << 32) | f_mode, probe-read (r7 may be a scalar).
		asm.StoreImm(asm.RFP, -8, 0, asm.DWord),
		asm.Mov.Reg(asm.R3, asm.R7), asm.Add.Imm(asm.R3, int32(modeOff)),
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -8),
		asm.Mov.Imm(asm.R2, 4),
		asm.FnProbeReadKernel.Call(),
		asm.JNE.Imm(asm.R0, 0, "out"),
		asm.StoreImm(asm.RFP, -4, 1, asm.Word),
		asm.StoreImm(asm.RFP, -20, 0, asm.Word), // key 0
		asm.LoadMapPtr(asm.R1, out.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -20),
		asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceIter, AttachTo: "task_file",
		License: "GPL", Instructions: insns,
	})
	if err != nil {
		return 0, fmt.Errorf("probe program: %w", err)
	}
	defer prog.Close()
	iter, err := link.AttachIter(link.IterOptions{Program: prog})
	if err != nil {
		return 0, fmt.Errorf("probe iterator: %w", err)
	}
	defer iter.Close()
	reader, err := iter.Open()
	if err != nil {
		return 0, fmt.Errorf("probe iterator open: %w", err)
	}
	_, err = io.Copy(io.Discard, reader)
	_ = reader.Close()
	if err != nil {
		return 0, fmt.Errorf("probe iterator read: %w", err)
	}
	var value uint64
	if err = out.Lookup(uint32(0), &value); err != nil {
		return 0, fmt.Errorf("probe result: %w", err)
	}
	if value>>32 != 1 {
		return 0, fmt.Errorf("probe did not see fd %d of process %d", f.Fd(), tgid)
	}
	return uint32(value), nil
}

// sharedProbedKernelOverride reports whether a kernel outside the pinned
// matrix may be admitted on its probes. It is false in every default build;
// only a qualification build can set it (kernel_probe_override_tag.go), and
// only with an explicit environment opt-in. TEST ONLY.
var sharedProbedKernelOverride = func() bool { return false }

// sharedSkipLSMListGate skips the probed admission's LSM-list check, so a
// test can show that the startup canary alone refuses a kernel whose BPF LSM
// programs never run. TEST ONLY: set only in qualification builds
// (kernel_probe_override_tag.go); the product gate never consults it.
var sharedSkipLSMListGate = func() bool { return false }

// ErrSharedKernelProbe marks a refusal of the probed-kernel admission.
var ErrSharedKernelProbe = errors.New("shared kernel probe refused")

// verifySharedProbedKernel is the admission of a kernel that is not an exact
// pinned build (TEST ONLY, behind sharedProbedKernelOverride). It still
// refuses, in this order: a non-x86_64 kernel, no bpf LSM, ftrace off and a
// livepatched kernel. Everything
// typed (fields, kfuncs, BTF attach targets) is then checked by the object's
// own load. It does NOT prove hook ordering or semantics.
func verifySharedProbedKernel(p sharedProductKernelProbe) error {
	refuse := func(err error) error {
		return fmt.Errorf("%w: %w", ErrSharedKernelProbe, err)
	}
	if !sharedProbedKernelOverride() {
		return refuse(fmt.Errorf("probed-kernel admission is not enabled (test-only override)"))
	}
	if arch := p.arch(); arch != "amd64" {
		return refuse(fmt.Errorf("x86_64 required, running on %s", arch))
	}
	lsm, err := p.lsm()
	if err != nil {
		return refuse(fmt.Errorf("LSM list: %w", err))
	}
	// The canary negative test (qualification builds only) bypasses this
	// userspace check to prove that the startup canary refuses on its own.
	if !sharedSkipLSMListGate() {
		if err = requireBPFLSM(lsm); err != nil {
			return refuse(err)
		}
	}
	if err = checkSharedProductKernelRuntime(p); err != nil {
		return refuse(err)
	}
	return nil
}

// SharedKernelProbeReport is the read-only result of every runtime probe on
// the running kernel (diagnostics and the D3 evidence tables). It admits
// nothing.
type SharedKernelProbeReport struct {
	Arch, Release, BTFDigest, BuildID string
	LSM                               string
	BPFLSM                            bool
	Ftrace, Tainted                   string
	// Pinned is the release of the exact pinned build this kernel is, or "".
	Pinned            string
	OverlayLayout     uint32
	OverlayError      string
	FmodeBacking      uint32
	FmodeBackingError string
	// FmodeBackingNote: pinned or probed, and the cross-check's outcome.
	FmodeBackingNote string
}

// ProbeSharedKernel runs every probe and reports each result or its error.
// The overlay module is autoloaded first, as the loader does.
func ProbeSharedKernel() SharedKernelProbeReport {
	p := sharedProductKernelProbes
	str := func(f func() (string, error)) string {
		v, err := f()
		if err != nil {
			return "error: " + err.Error()
		}
		return strings.TrimSpace(v)
	}
	r := SharedKernelProbeReport{Arch: p.arch(), Release: str(p.release), BTFDigest: str(p.btfDigest), BuildID: str(p.buildID), LSM: str(p.lsm), Ftrace: str(p.ftrace), Tainted: str(p.tainted)}
	r.BPFLSM = requireBPFLSM(r.LSM) == nil
	if pin, ok := sharedProductPins[r.BTFDigest]; ok && pin.Release == r.Release && pin.BuildID == r.BuildID {
		r.Pinned = pin.Release
	}
	layout, err := resolveSharedImageOverlayLayout()
	if err != nil {
		r.OverlayError = err.Error()
		return r
	}
	r.OverlayLayout = layout
	if r.FmodeBacking, err = fmodeBackingReader(layout); err != nil {
		r.FmodeBackingError = err.Error()
	}
	if note := sharedFmodeBackingNote.Load(); note != nil {
		r.FmodeBackingNote = *note
	}
	return r
}
