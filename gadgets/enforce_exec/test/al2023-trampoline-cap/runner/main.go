// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Command trampoline-cap-runner measures, on an isolated exact AL2023 kernel,
// how many BPF trampoline links each G009 attach target accepts. Without
// -run-isolated it only inspects the filler object. The fillers are no-ops
// and never deny.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

const (
	programLSM    = "filler_lsm"
	programFEntry = "filler_fentry"
	programFExit  = "filler_fexit"
	// BPF_MAX_TRAMP_LINKS on x86_64 (include/linux/bpf.h), shared by the
	// fentry, fexit and fmod_ret/LSM lists of one trampoline.
	maxTrampLinks = 38
	// BPF_LINK_GET_NEXT_ID.
	bpfLinkGetNextID = 31
)

var expectedPrograms = map[string]struct {
	typ    ebpf.ProgramType
	attach ebpf.AttachType
}{
	programLSM:    {ebpf.LSM, ebpf.AttachLSMMac},
	programFEntry: {ebpf.Tracing, ebpf.AttachTraceFEntry},
	programFExit:  {ebpf.Tracing, ebpf.AttachTraceFExit},
}

// filler is one program of a probe rotation, attached to attachTo.
type filler struct {
	program, attachTo string
}

// probe attaches its fillers in rotation until an attach fails. trampoline
// is the kernel function whose trampoline all of them share.
type probe struct {
	target, kind, trampoline string
	fillers                  []filler
}

func probes() []probe {
	var out []probe
	for _, hook := range []string{"bprm_check_security", "task_alloc", "task_free", "file_open", "socket_connect", "inode_init_security_anon"} {
		out = append(out, probe{hook, "lsm", "bpf_lsm_" + hook, []filler{{programLSM, hook}}})
	}
	for _, fn := range []string{"bprm_execve", "cgroup_migrate", "copy_process"} {
		out = append(out,
			probe{fn, "fentry", fn, []filler{{programFEntry, fn}}},
			probe{fn, "fexit", fn, []filler{{programFExit, fn}}})
	}
	return append(out,
		probe{"bprm_execve", "mixed", "bprm_execve", []filler{{programFEntry, "bprm_execve"}, {programFExit, "bprm_execve"}}},
		probe{"bprm_check_security", "mixed", "bpf_lsm_bprm_check_security", []filler{
			{programLSM, "bprm_check_security"},
			{programFEntry, "bpf_lsm_bprm_check_security"},
			{programFExit, "bpf_lsm_bprm_check_security"},
		}})
}

func inspect(s *ebpf.CollectionSpec) error {
	if s.ByteOrder != binary.LittleEndian || len(s.Programs) != len(expectedPrograms) || len(s.Maps) != 0 {
		return fmt.Errorf("unexpected collection shape: %d programs %d maps", len(s.Programs), len(s.Maps))
	}
	for name, want := range expectedPrograms {
		p := s.Programs[name]
		if p == nil || p.Type != want.typ || p.AttachType != want.attach || p.Flags != 0 {
			return fmt.Errorf("unexpected program %s", name)
		}
		// A no-op filler is "r0 = 0; exit".
		if len(p.Instructions) != 2 {
			return fmt.Errorf("program %s is not a two-instruction no-op: %d instructions", name, len(p.Instructions))
		}
	}
	return nil
}

func kernelCheck() (string, error) {
	if runtime.GOARCH != "amd64" {
		return "", fmt.Errorf("amd64 only")
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	release := unix.ByteSliceToString(u.Release[:])
	hashes := map[string]string{
		"6.12.113-138.209.amzn2023.x86_64": "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82",
		"6.18.56-125.164.amzn2023.x86_64":  "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee",
	}
	want, ok := hashes[release]
	if !ok {
		return "", fmt.Errorf("unreviewed kernel %s", release)
	}
	data, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		return "", err
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		return "", fmt.Errorf("kernel BTF hash mismatch: %s", got)
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return "", err
	}
	if !strings.Contains(","+strings.TrimSpace(string(lsm))+",", ",bpf,") {
		return "", fmt.Errorf("BPF LSM inactive: %s", lsm)
	}
	return release, nil
}

// linkIDs walks every bpf link ID with BPF_LINK_GET_NEXT_ID.
func linkIDs() ([]uint32, error) {
	var ids []uint32
	attr := struct{ start, next, flags uint32 }{}
	for {
		_, _, errno := unix.Syscall(unix.SYS_BPF, bpfLinkGetNextID, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		if errno == unix.ENOENT {
			return ids, nil
		}
		if errno != 0 {
			return nil, fmt.Errorf("BPF_LINK_GET_NEXT_ID: %w", errno)
		}
		ids = append(ids, attr.next)
		attr.start = attr.next
	}
}

// onTrampoline counts the given links that are tracing/LSM links on the
// kernel function with BTF ID btfID. Links that vanish meanwhile are skipped.
func onTrampoline(ids []uint32, btfID btf.TypeID) (int, error) {
	n := 0
	for _, id := range ids {
		l, err := link.NewFromID(link.ID(id))
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("link %d: %w", id, err)
		}
		info, err := l.Info()
		l.Close()
		if err != nil {
			return 0, fmt.Errorf("link %d info: %w", id, err)
		}
		if t := info.Tracing(); t != nil && btf.TypeID(t.TargetBtfId) == btfID {
			n++
		}
	}
	return n, nil
}

type result struct {
	cap, preexisting int
	errno, phase     string
	restored         bool
	ours             []uint32
}

func errnoName(err error) string {
	var e unix.Errno
	if errors.As(err, &e) {
		if name := unix.ErrnoName(e); name != "" {
			return name
		}
		return fmt.Sprintf("errno%d", int(e))
	}
	return "unknown"
}

func run1(spec *ebpf.CollectionSpec, kernel *btf.Spec, p probe, limit int) (r result, retErr error) {
	var fn *btf.Func
	if err := kernel.TypeByName(p.trampoline, &fn); err != nil {
		return r, fmt.Errorf("%s: %w", p.trampoline, err)
	}
	btfID, err := kernel.TypeID(fn)
	if err != nil {
		return r, err
	}
	baseline, err := linkIDs()
	if err != nil {
		return r, err
	}
	if r.preexisting, err = onTrampoline(baseline, btfID); err != nil {
		return r, err
	}
	var links []link.Link
	var progs []*ebpf.Program
	defer func() {
		for _, l := range links {
			retErr = errors.Join(retErr, l.Close())
		}
		for _, prog := range progs {
			retErr = errors.Join(retErr, prog.Close())
		}
		if retErr != nil {
			return
		}
		// Link IDs are released asynchronously after the last FD closes.
		deadline := time.Now().Add(10 * time.Second)
		for {
			after, err := linkIDs()
			if err != nil {
				retErr = err
				return
			}
			leftover := slices.ContainsFunc(r.ours, func(id uint32) bool { return slices.Contains(after, id) })
			r.restored = !leftover && len(after) == len(baseline)
			if r.restored || time.Now().After(deadline) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	r.errno, r.phase = "none", "none"
	for i := 0; i < limit; i++ {
		f := p.fillers[i%len(p.fillers)]
		ps := spec.Programs[f.program].Copy()
		ps.AttachTo = f.attachTo
		prog, err := ebpf.NewProgramWithOptions(ps, ebpf.ProgramOptions{KernelTypes: kernel})
		if err != nil {
			r.errno, r.phase = errnoName(err), "load"
			fmt.Printf("  %s/%s: load %d (%s->%s) failed: %v\n", p.target, p.kind, i+1, f.program, f.attachTo, err)
			break
		}
		progs = append(progs, prog)
		var l link.Link
		if f.program == programLSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: prog})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: prog})
		}
		if err != nil {
			r.errno, r.phase = errnoName(err), "attach"
			fmt.Printf("  %s/%s: attach %d (%s->%s) failed: %v\n", p.target, p.kind, i+1, f.program, f.attachTo, err)
			break
		}
		links = append(links, l)
		info, err := l.Info()
		if err != nil {
			return r, err
		}
		r.ours = append(r.ours, uint32(info.ID))
		r.cap++
	}
	return r, nil
}

func live(spec *ebpf.CollectionSpec, limit int) error {
	release, err := kernelCheck()
	if err != nil {
		return err
	}
	fmt.Printf("kernel %s exact BTF and active BPF LSM\n", release)
	if err = rlimit.RemoveMemlock(); err != nil {
		return err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return err
	}
	start, err := linkIDs()
	if err != nil {
		return err
	}
	fmt.Printf("baseline: %d bpf links\n", len(start))
	failed := 0
	for _, p := range probes() {
		r, err := run1(spec, kernel, p, limit)
		if err != nil {
			failed++
			fmt.Printf("FAIL %s/%s: %v\n", p.target, p.kind, err)
			continue
		}
		// E2BIG with preexisting+cap == BPF_MAX_TRAMP_LINKS is the link-count
		// limit; any other E2BIG (for example the one-page trampoline image)
		// or errno is reported as "other".
		limitKind := "other"
		switch {
		case r.errno == "none":
			limitKind = "not_reached"
		case r.phase == "attach" && r.errno == "E2BIG" && r.preexisting+r.cap == maxTrampLinks:
			limitKind = "tramp_links"
		}
		fmt.Printf("CAP kernel=%s target=%s kind=%s cap=%d errno=%s baseline_restored=%t preexisting=%d phase=%s limit=%s\n",
			release, p.target, p.kind, r.cap, r.errno, r.restored, r.preexisting, r.phase, limitKind)
		if !r.restored {
			failed++
		}
	}
	end, err := linkIDs()
	if err != nil {
		return err
	}
	fmt.Printf("final: %d bpf links (baseline %d)\n", len(end), len(start))
	if failed != 0 {
		return fmt.Errorf("%d probe(s) failed or left links behind", failed)
	}
	fmt.Println("PASS: trampoline cap probe; no-op fillers, NOT product enforcement")
	return nil
}

func run() error {
	object := flag.String("object", "", "explicit filler object path")
	limit := flag.Int("max", 128, "stop a probe after this many links")
	enabled := flag.Bool("run-isolated", false, "load/attach on an isolated exact AL2023 kernel; default is inspect only")
	mode := flag.String("mode", "cap", "cap: trampoline cap probe; txn: transactional attach of -candidate against fillers; ready: readiness after an external removal; "+
		"retry: automatic retry until fillers are freed; coex: coexistence matrix; hold: hold boundary fillers on every candidate hook until SIGTERM")
	candidate := flag.String("candidate", "", "exec candidate object (g25final128) for -mode txn|ready|retry|coex|hold")
	target := flag.String("target", "bprm_execve", "trampoline to pre-fill in -mode txn|retry")
	reserve := flag.Int("reserve", nativeattach.DefaultReservePerHook, "reserve R per hook")
	freeAfter := flag.Duration("free-after", 3*time.Second, "-mode retry: free the fillers after this delay")
	holdTimeout := flag.Duration("hold-timeout", 30*time.Minute, "-mode hold: release the fillers after this delay at the latest")
	flag.Parse()
	switch *mode {
	case "cap":
	case "txn", "ready", "retry", "coex", "hold":
		if *candidate == "" {
			return fmt.Errorf("-candidate required for -mode %s", *mode)
		}
	default:
		return fmt.Errorf("unknown -mode %s", *mode)
	}
	if *object == "" {
		return fmt.Errorf("-object required")
	}
	if *limit < 1 {
		return fmt.Errorf("-max must be positive")
	}
	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	if err = inspect(spec); err != nil {
		return err
	}
	fmt.Println("PASS: trampoline filler object shape")
	for _, p := range probes() {
		var rotation []string
		for _, f := range p.fillers {
			rotation = append(rotation, f.program+"->"+f.attachTo)
		}
		fmt.Printf("plan target=%s kind=%s trampoline=%s rotation=%s\n", p.target, p.kind, p.trampoline, strings.Join(rotation, ","))
	}
	if !*enabled {
		return nil
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return err
	}
	switch *mode {
	case "txn", "ready":
		return liveTxn(spec, *candidate, *target, *reserve, *mode == "ready")
	case "retry":
		if *freeAfter <= 0 {
			return fmt.Errorf("-free-after must be positive")
		}
		return liveRetry(spec, *candidate, *target, *reserve, *freeAfter)
	case "coex":
		return liveCoex(spec, *candidate, *reserve)
	case "hold":
		return liveHold(spec, *candidate, *reserve, *holdTimeout)
	}
	return live(spec, *limit)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
