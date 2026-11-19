// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package enterprise_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Test-only limits, never an enforcement decision. Well-formed metadata does
// not authenticate direct origin or completeness.
const (
	a0Flag                = "IG_ENTERPRISE_A0_REPORT_ONLY_TEST"
	a0Target              = "4.18.0-553.el8_10.x86_64"
	maxTasks              = 4
	maxAttempts           = 16
	maxDepth              = 8
	maxRecords            = 4096
	maxCPUs               = 64
	maxDuration           = 30 * time.Second
	maxReturnInstances    = 128
	copyCandidateUnknown  = uint64(2 | 32 | 64)
	returnSnapshotUnknown = copyCandidateUnknown | 128
)

type a0Bounds struct {
	Tasks, Attempts, Depth, Records, CPUs, PayloadBytes int
	Duration                                            time.Duration
}

func (b a0Bounds) validate() error {
	if b.Tasks < 1 || b.Tasks > maxTasks || b.Attempts < 1 || b.Attempts > maxAttempts ||
		b.Depth < 1 || b.Depth > maxDepth || b.Records < 1 || b.Records > maxRecords ||
		b.CPUs < 1 || b.CPUs > maxCPUs || b.PayloadBytes != 0 || b.Duration <= 0 || b.Duration > maxDuration {
		return errors.New("A0 resource bounds violated")
	}
	return nil
}

// This guard must precede every compiler, subprocess, map, program, probe,
// or collection operation, including all opt-in tests.
func a0Enabled(value string) bool { return value == "1" }

type a0Report struct {
	Discovery, KernelProbe, Completeness                                string
	CopyEntry, CopyReturn, ReturnArguments, Pairing, ReturnInstanceLoss string
	RetprobeMaxActive                                                   int
}

func offlineReport(valid bool) a0Report {
	report := a0Report{
		Discovery: "METADATA_INVALID", KernelProbe: "NOT_RUN", Completeness: "NOT_READY",
		CopyEntry: "canonical_kprobe", CopyReturn: "canonical_kretprobe",
		ReturnArguments: "entry_snapshot", Pairing: "LIFO_candidate",
		ReturnInstanceLoss: "UNKNOWN", RetprobeMaxActive: maxReturnInstances,
	}
	if valid {
		report.Discovery = "METADATA_STRUCTURALLY_VALID"
	}
	return report
}

func TestA0KernelReportOnly(t *testing.T) {
	if !a0Enabled(os.Getenv(a0Flag)) {
		t.Skip("A0 disabled before all compiler/subprocess/kernel operations")
	}
	// The loader also requires separate execution review and exact target checks.
	runA0(t)
}

// Native fixture below is deliberately gated separately from offline unit tests.
// It is a hypothesis producer, not qualified attachment or lifetime evidence.
const targetELFSHA = "742ecbff5b4cc8b13f7d3ca064a641af11cf67aaec3dcf1d3e4a6d9675c60d53"

type (
	nativeCounters struct{ Records, Attempts, Calls, Faults uint64 }
	nativeRecord   struct {
		Kind, PIDTGID, NamespacePIDTGID, Task, Attempt, Call, Depth, To, N, Remaining uint64
		Bprm, MM, P, Argc, StackBytes, Unknown                                        uint64
		Stack                                                                         [16]uint64
	}
)

func unsignedLong(typ btf.Type) bool {
	v, ok := btf.UnderlyingType(typ).(*btf.Int)
	return ok && v.Size == 8 && v.Encoding == btf.Unsigned
}

func signedInt(typ btf.Type) bool {
	v, ok := btf.UnderlyingType(typ).(*btf.Int)
	return ok && v.Size == 4 && v.Encoding == btf.Signed
}

func pointerTo(typ btf.Type, name string) bool {
	p, ok := btf.UnderlyingType(typ).(*btf.Pointer)
	if !ok {
		return false
	}
	if name == "void" {
		_, ok := btf.UnderlyingType(p.Target).(*btf.Void)
		return ok
	}
	s, ok := btf.UnderlyingType(p.Target).(*btf.Struct)
	return ok && s.Name == name
}

func validateTargetBTF(spec *btf.Spec) error {
	for _, name := range []string{"security_bprm_creds_for_exec", "security_bprm_check", "free_bprm", "_copy_from_user"} {
		var fn *btf.Func
		if err := spec.TypeByName(name, &fn); err != nil {
			return fmt.Errorf("typed boundary %s: %w", name, err)
		}
		proto, ok := fn.Type.(*btf.FuncProto)
		if !ok {
			return fmt.Errorf("%s lacks function prototype", name)
		}
		if name == "_copy_from_user" {
			if len(proto.Params) != 3 || !pointerTo(proto.Params[0].Type, "void") || !pointerTo(proto.Params[1].Type, "void") || !unsignedLong(proto.Params[2].Type) || !unsignedLong(proto.Return) {
				return errors.New("copy prototype mismatch")
			}
		} else {
			if len(proto.Params) != 1 || !pointerTo(proto.Params[0].Type, "linux_binprm") {
				return fmt.Errorf("%s bprm argument mismatch", name)
			}
			if name == "free_bprm" {
				if _, ok := btf.UnderlyingType(proto.Return).(*btf.Void); !ok {
					return errors.New("free_bprm return mismatch")
				}
			} else if !signedInt(proto.Return) {
				return fmt.Errorf("%s return mismatch", name)
			}
		}
	}
	var bprm *btf.Struct
	if err := spec.TypeByName("linux_binprm", &bprm); err != nil {
		return err
	}
	checks := map[string]func(btf.Type) bool{"mm": func(t btf.Type) bool { return pointerTo(t, "mm_struct") }, "p": unsignedLong, "argc": signedInt}
	for _, member := range bprm.Members {
		if check, ok := checks[member.Name]; ok {
			if member.BitfieldSize != 0 || !check(member.Type) {
				return fmt.Errorf("bprm field %s mismatch", member.Name)
			}
			delete(checks, member.Name)
		}
	}
	if len(checks) != 0 {
		return errors.New("missing bprm fields")
	}
	var regs *btf.Struct
	if err := spec.TypeByName("pt_regs", &regs); err != nil {
		return fmt.Errorf("amd64 pt_regs: %w", err)
	}
	return validateA0RegisterLayout(regs)
}

// Authenticated vendor pt_regs uses di/si/dx/ax; included amd64 UAPI uses
// rdi/rsi/rdx/rax. C static assertions bind that UAPI layout to these BTF facts.
func validateA0RegisterLayout(regs *btf.Struct) error {
	if regs == nil || regs.Size != 168 {
		return errors.New("amd64 pt_regs size mismatch")
	}
	expected := map[string]btf.Bits{"di": 112 * 8, "si": 104 * 8, "dx": 96 * 8, "ax": 80 * 8}
	for _, m := range regs.Members {
		if offset, ok := expected[m.Name]; ok {
			if m.Offset != offset || m.BitfieldSize != 0 || !unsignedLong(m.Type) {
				return fmt.Errorf("amd64 register %s mismatch", m.Name)
			}
			delete(expected, m.Name)
		}
	}
	if len(expected) != 0 {
		return errors.New("missing amd64 register layout")
	}
	return nil
}

func boundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds bound")
	}
	return data, nil
}

func targetBTF(path string) ([]byte, error) {
	data, err := boundedFile(path, 128<<20)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != targetELFSHA {
		return nil, errors.New("reference ELF identity mismatch")
	}
	elfFile, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer elfFile.Close()
	if elfFile.Class != elf.ELFCLASS64 || elfFile.Data != elf.ELFDATA2LSB || elfFile.Machine != elf.EM_X86_64 {
		return nil, errors.New("reference is not little-endian amd64 ELF64")
	}
	sec := elfFile.Section(".BTF")
	if sec == nil || sec.Size > 16<<20 {
		return nil, errors.New("missing or oversized reference BTF")
	}
	raw, err := sec.Data()
	if err != nil {
		return nil, err
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return raw, validateTargetBTF(spec)
}

func compileA0(t *testing.T) (string, string) {
	t.Helper()
	if !a0Enabled(os.Getenv(a0Flag)) {
		t.Fatal("compile requested without explicit opt-in")
	}
	// No kernel operations: validate the exact archived ELF's BTF offline first.
	if _, err := targetBTF(os.Getenv("IG_ENTERPRISE_A0_REFERENCE_ELF")); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	object := filepath.Join(dir, "copy_metadata.bpf.o")
	helper := filepath.Join(dir, "exec_target")
	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()
	// Absolute, operator-selected local toolchain; no shell, package install or downloads.
	clang := os.Getenv("IG_ENTERPRISE_A0_CLANG")
	if !filepath.IsAbs(clang) {
		t.Fatal("absolute trusted IG_ENTERPRISE_A0_CLANG required")
	}
	for _, args := range [][]string{
		{"-target", "bpf", "-D__TARGET_ARCH_x86", "-I/usr/include/x86_64-linux-gnu", "-O2", "-g", "-Wall", "-Werror", "-c", "testdata/copy_metadata.bpf.c", "-o", object},
		{"-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "testdata/exec_target.c", "-o", helper},
	} {
		out, err := exec.CommandContext(ctx, clang, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("compile-only: %v: %s", err, out)
		}
	}
	return object, helper
}

func TestA0CompileOnly(t *testing.T) {
	if !a0Enabled(os.Getenv(a0Flag)) {
		t.Skip("A0 compile-only disabled")
	}
	object, helper := compileA0(t)
	for _, path := range []string{object, helper} {
		data, err := boundedFile(path, 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("compile-only artifact %s SHA256=%x", filepath.Base(path), sha256.Sum256(data))
	}
}

func runA0(t *testing.T) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Fatal("NOT_READY: canonical register adapter requires amd64")
	}
	_, hasDeadline := t.Deadline()
	if err := validateA0NativeDeadline(hasDeadline); err != nil {
		t.Fatal(err)
	}
	// Review acknowledgement is not inferred from flag, compilation or source/BTF.
	if os.Getenv("IG_ENTERPRISE_A0_EXECUTION_REVIEW") != "approved-owned-isolated-metadata-only" {
		t.Skip("NOT_READY: separate execution review and owned isolated authority required")
	}
	if os.Getenv("IG_ENTERPRISE_A0_BOOT_ELF_SHA256") != targetELFSHA {
		t.Fatal("NOT_READY: authenticated running image attestation missing")
	}
	release, err := boundedFile("/proc/sys/kernel/osrelease", 256)
	if err != nil || strings.TrimSpace(string(release)) != a0Target {
		t.Fatal("NOT_READY: wrong running kernel")
	}
	reference, err := targetBTF(os.Getenv("IG_ENTERPRISE_A0_REFERENCE_ELF"))
	if err != nil {
		t.Fatal(err)
	}
	running, err := boundedFile("/sys/kernel/btf/vmlinux", 16<<20)
	if err != nil || !bytes.Equal(reference, running) {
		t.Fatal("NOT_READY: running BTF does not match authenticated reference")
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(running))
	if err != nil {
		t.Fatal(err)
	}
	if err = validateTargetBTF(spec); err != nil {
		t.Fatal(err)
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil || cpus < 1 || cpus > maxCPUs {
		t.Fatal("NOT_READY: possible CPU bound")
	}
	if err = (a0Bounds{Tasks: 1, Attempts: 16, Depth: 8, Records: 4096, CPUs: cpus, Duration: maxDuration}).validate(); err != nil {
		t.Fatal(err)
	}
	object, helper := compileA0(t)
	// Deadline covers all native resources. No memlock/sysctl/security-policy changes.
	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	anchor, err := openA0NamespaceAnchor()
	if err != nil {
		t.Fatalf("NOT_READY: native namespace anchor: %v", err)
	}
	// This FD remains pinned until all probes are positively stopped.
	defer anchor.file.Close()
	cs, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(cs, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: spec}})
	if err != nil {
		t.Fatalf("NOT_READY: native load eligibility: %v", err)
	}
	owner := &a0NativeOwner{collection: collection, namespace: anchor}
	defer owner.cleanup(t)
	if err := attachA0Plan(owner, func(spec a0AttachSpec) (io.Closer, error) {
		p := collection.Programs[spec.Name]
		if p == nil || p.Type() != spec.ProgramType {
			return nil, fmt.Errorf("missing/wrong program %s", spec.Name)
		}
		if spec.ProgramType == ebpf.Tracing {
			return link.AttachTracing(link.TracingOptions{Program: p})
		}
		if spec.Return {
			return link.Kretprobe(spec.Symbol, p, &spec.Options)
		}
		return link.Kprobe(spec.Symbol, p, &spec.Options)
	}); err != nil {
		t.Fatalf("NOT_READY: mixed attachment: %v", err)
	}

	var now unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatal(err)
	}
	until, _ := ctx.Deadline()
	remaining := time.Until(until)
	if remaining <= 0 {
		t.Fatal("native setup deadline")
	}
	deadline := uint64(now.Nano()) + uint64(remaining)
	zero := uint32(0)
	if err = collection.Maps["config"].Put(zero, struct{ Deadline, Dev, Ino uint64 }{deadline, anchor.dev, anchor.ino}); err != nil {
		t.Fatal(err)
	}
	if err = collection.Maps["config"].Freeze(); err != nil {
		t.Fatalf("NOT_READY: immutable namespace/deadline config: %v", err)
	}
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	owner.files = append(owner.files, gateRead, gateWrite)
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	owner.files = append(owner.files, readyRead, readyWrite)
	child := ownedA0Command(helper, gateRead, readyWrite)
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	owner.child = child
	// Deadline may kill the exact child, but must NOT reap/release its identity.
	owner.timer = time.AfterFunc(time.Until(until), func() { _ = child.Process.Kill() })

	_ = gateRead.Close()
	_ = readyWrite.Close()
	tgid := uint32(child.Process.Pid)
	if err = readyRead.SetReadDeadline(until); err != nil {
		t.Fatal(err)
	}
	var identity [8]byte
	if _, err = io.ReadFull(readyRead, identity[:]); err != nil {
		t.Fatal("helper initial identity handshake missing")
	}
	if err = validateA0ChildIdentity(binary.LittleEndian.Uint32(identity[:4]), binary.LittleEndian.Uint32(identity[4:]), tgid, uint32(os.Getpid())); err != nil {
		t.Fatal(err)
	}
	if err = collection.Maps["owned"].Put(tgid, zero); err != nil {
		t.Fatal(err)
	}
	owner.registered = tgid

	if _, err = gateWrite.Write([]byte{'G'}); err != nil {
		t.Fatal(err)
	}
	if err = readyRead.SetReadDeadline(until); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err = io.ReadFull(readyRead, ready[:]); err != nil || ready[0] != 'R' {
		t.Fatal("synthetic exec did not reach owned completion rendezvous")
	}
	// No asynchronous event reader: the bounded array is read synchronously after
	// detaching every producer while the child remains held alive.
	if err = owner.detach(); err != nil {
		t.Fatalf("UNCERTAIN: detach producers: %v", err)
	}

	var counts nativeCounters
	if err = collection.Maps["counters"].Lookup(zero, &counts); err != nil {
		t.Fatal(err)
	}
	t.Logf("METADATA_COLLECTED kernel_probe=OBSERVED completeness=NOT_READY counters=%+v", counts)
	if counts.Records == 0 || counts.Records > maxRecords || counts.Attempts == 0 || counts.Attempts > maxAttempts || counts.Faults != 0 {
		t.Error("metadata incomplete: empty/overflow/fault counters")
	}
	limit := min(counts.Records, uint64(maxRecords))
	records := make([]nativeRecord, 0, limit)
	for i := uint32(0); uint64(i) < limit; i++ {
		if ctx.Err() != nil {
			t.Fatal("native read deadline")
		}
		var r nativeRecord
		if err = collection.Maps["records"].Lookup(i, &r); err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
		t.Logf("OWNER_ONLY_METADATA record=%+v", r)
	}
	report := offlineReport(validateNativeRecords(records, tgid) == nil)
	report.KernelProbe = "METADATA_COLLECTED"
	t.Logf("A0 observation limits: %+v", report)
	if err = validateNativeRecords(records, tgid); err != nil {
		t.Errorf("metadata structure: %v", err)
	}
	// Unknown direct provenance is deliberately not converted into A0 PASS.
	t.Log("A0 NOT_READY: direct-caller authentication, all-path coverage and callback lifetime require independent review; no payload captured")
}

func validateNativeRecords(records []nativeRecord, tgid uint32) error {
	if len(records) == 0 || len(records) > maxRecords {
		return errors.New("invalid native record count")
	}
	var stack []nativeRecord
	var attempt, task, bprm, hostPIDTGID uint64
	started, checked, retired := false, false, false
	calls := map[uint64]bool{}
	for _, r := range records {
		if r.NamespacePIDTGID != uint64(tgid)<<32|uint64(tgid) || r.PIDTGID == 0 || r.Task == 0 || r.Attempt == 0 || r.Attempt > maxAttempts {
			return errors.New("unowned or unidentified native record")
		}
		if r.Kind == 3 {
			if started {
				return errors.New("unexpected second synthetic attempt")
			}
			started = true
			attempt = r.Attempt
			task = r.Task
			bprm = r.Bprm
			hostPIDTGID = r.PIDTGID
		}
		if !started || retired || r.Attempt != attempt || r.Task != task || r.Bprm != bprm || r.PIDTGID != hostPIDTGID {
			return errors.New("native attempt/lifetime mismatch")
		}
		switch r.Kind {
		case 3:
			if r.Unknown != 0 || r.Bprm == 0 || r.MM == 0 {
				return errors.New("uncertain typed start")
			}
		case 1:
			if r.Unknown != copyCandidateUnknown || r.To == 0 || r.N == 0 || r.Call == 0 || calls[r.Call] || r.Depth != uint64(len(stack)+1) || len(stack) >= maxDepth || r.StackBytes == 0 || r.StackBytes >= 128 || r.StackBytes%8 != 0 {
				return errors.New("uncertain copy entry")
			}
			calls[r.Call] = true
			stack = append(stack, r)
		case 2:
			if len(stack) == 0 {
				return errors.New("missing copy entry")
			}
			e := stack[len(stack)-1]
			if r.Unknown != returnSnapshotUnknown || r.Call != e.Call || r.Depth != e.Depth || r.To != e.To || r.N != e.N || r.Remaining != 0 {
				return errors.New("copy pair mismatch")
			}
			stack = stack[:len(stack)-1]
		case 4:
			if r.Unknown != 0 || len(stack) != 0 {
				return errors.New("uncertain typed check")
			}
			checked = true
		case 5:
			if r.Unknown != 0 || len(stack) != 0 {
				return errors.New("uncertain retirement")
			}
			retired = true
		default:
			return errors.New("unknown native record kind")
		}
	}
	if !started || !checked || !retired || len(stack) != 0 || len(calls) == 0 {
		return errors.New("missing lifecycle or copy observation")
	}
	return nil
}

// Cleanup ordering is a scope boundary, not best-effort housekeeping. A failed
// detach must never be followed by releasing the child's PID for possible reuse.
type a0CleanupSteps struct {
	detach, unregister, release func() error
	quarantine                  func(error)
}

func orderedA0Cleanup(steps a0CleanupSteps) (retained bool, err error) {
	if err := steps.detach(); err != nil {
		uncertain := fmt.Errorf("UNCERTAIN: producers not positively stopped: %w", err)
		if steps.quarantine != nil {
			steps.quarantine(uncertain)
		}
		return true, uncertain
	}
	// Once producers are positively stopped, a failed map delete cannot capture
	// a reused PID. Continue closing resources, but preserve the cleanup failure.
	return false, errors.Join(steps.unregister(), steps.release())
}

func ownedA0Command(helper string, gate, ready *os.File) *exec.Cmd {
	child := exec.Command(helper)
	// A nil Env inherits the harness environment, including LD_PRELOAD/LD_AUDIT.
	child.Env = []string{}
	child.ExtraFiles = []*os.File{gate, ready}
	return child
}

// PROC_ROOT_INO=1 is from authenticated vendor include/linux/proc_ns.h:42.
// The root/self implementation is preserved in the external review evidence.
// This identifies genuine procfs roots, not the initial PID namespace.
func validateA0NamespaceFacts(procType int64, rootIno uint64, nsType int64, cloneType int, linkedIno, openedIno, dev uint64) error {
	if procType != unix.PROC_SUPER_MAGIC || rootIno != 1 || nsType != unix.NSFS_MAGIC || cloneType != unix.CLONE_NEWPID || linkedIno == 0 || linkedIno != openedIno || dev == 0 {
		return errors.New("ambiguous or substituted PID namespace anchor")
	}
	return nil
}

func parsePIDNamespaceLink(value string) (uint64, error) {
	if !strings.HasPrefix(value, "pid:[") || !strings.HasSuffix(value, "]") {
		return 0, errors.New("not a PID namespace symlink")
	}
	number := strings.TrimSuffix(strings.TrimPrefix(value, "pid:["), "]")
	inode, err := strconv.ParseUint(number, 10, 64)
	if err != nil || inode == 0 || strconv.FormatUint(inode, 10) != number {
		return 0, errors.New("invalid namespace inode")
	}
	return inode, nil
}

type a0Namespace struct {
	file     *os.File
	dev, ino uint64
}

func openA0NamespaceAnchor() (*a0Namespace, error) {
	// thread-self is a genuine kernel-generated procfs ordinary symlink, not an
	// operator-supplied PID. NO_XDEV rejects bind mounts anywhere below proc root.
	root, err := unix.Open("/proc", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	var rootStat unix.Stat_t
	var rootFS unix.Statfs_t
	if err = unix.Fstat(root, &rootStat); err != nil {
		return nil, err
	}
	if err = unix.Fstatfs(root, &rootFS); err != nil {
		return nil, err
	}
	if rootFS.Type != unix.PROC_SUPER_MAGIC || rootStat.Ino != 1 {
		return nil, errors.New("not a genuine procfs root")
	}
	resolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_MAGICLINKS)
	nsdir, err := unix.Openat2(root, "thread-self/ns", &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: resolve})
	if err != nil {
		return nil, fmt.Errorf("pinned native thread namespace path: %w", err)
	}
	defer unix.Close(nsdir)
	openNamespace := func(name string) (*a0Namespace, error) {
		// Pin the actual proc symlink itself before following the nsfs magic link.
		// Its empty-path readlink is bound to the held inode, not a second pathname
		// resolution. A substituted nsfs file/bind mount fails these checks.
		symlink, err := unix.Openat2(nsdir, name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: resolve})
		if err != nil {
			return nil, err
		}
		defer unix.Close(symlink)
		var linkStat unix.Stat_t
		var linkFS unix.Statfs_t
		if err = unix.Fstat(symlink, &linkStat); err != nil {
			return nil, err
		}
		if err = unix.Fstatfs(symlink, &linkFS); err != nil {
			return nil, err
		}
		if linkFS.Type != unix.PROC_SUPER_MAGIC || linkStat.Mode&unix.S_IFMT != unix.S_IFLNK {
			return nil, errors.New("namespace anchor is not a real procfs symlink")
		}
		var text [64]byte
		n, err := unix.Readlinkat(symlink, "", text[:])
		if err != nil || n == len(text) {
			return nil, errors.New("namespace symlink unreadable/truncated")
		}
		inode, err := parsePIDNamespaceLink(string(text[:n]))
		if err != nil {
			return nil, err
		}
		fd, err := unix.Openat(nsdir, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fd), "pinned-own-"+name)
		fail := func(err error) (*a0Namespace, error) { _ = file.Close(); return nil, err }
		var stat unix.Stat_t
		var fs unix.Statfs_t
		if err = unix.Fstat(fd, &stat); err != nil {
			return fail(err)
		}
		if err = unix.Fstatfs(fd, &fs); err != nil {
			return fail(err)
		}
		typ, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if err != nil {
			return fail(err)
		}
		if err = validateA0NamespaceFacts(rootFS.Type, rootStat.Ino, fs.Type, typ, inode, stat.Ino, stat.Dev); err != nil {
			return fail(err)
		}
		return &a0Namespace{file: file, dev: stat.Dev, ino: stat.Ino}, nil
	}
	active, err := openNamespace("pid")
	if err != nil {
		return nil, err
	}
	children, err := openNamespace("pid_for_children")
	if err != nil {
		_ = active.file.Close()
		return nil, err
	}
	defer children.file.Close()
	if active.dev != children.dev || active.ino != children.ino {
		_ = active.file.Close()
		return nil, errors.New("native thread active and children PID namespaces differ")
	}
	return active, nil
}

func validateA0ChildIdentity(childPID, childParent, ownedPID, ownPID uint32) error {
	if childPID == 0 || childParent == 0 || childPID != ownedPID || childParent != ownPID {
		return errors.New("helper native PID namespace handshake mismatch")
	}
	return nil
}

type a0AttachSpec struct {
	Name        string
	ProgramType ebpf.ProgramType
	Symbol      string
	Return      bool
	Options     link.KprobeOptions
}

func a0AttachmentPlan() [5]a0AttachSpec {
	return [5]a0AttachSpec{
		{Name: "start", ProgramType: ebpf.Tracing},
		{Name: "copy_enter", ProgramType: ebpf.Kprobe, Symbol: "_copy_from_user", Options: link.KprobeOptions{ExactSymbol: true, Offset: 0}},
		{Name: "copy_exit", ProgramType: ebpf.Kprobe, Symbol: "_copy_from_user", Return: true, Options: link.KprobeOptions{ExactSymbol: true, Offset: 0, RetprobeMaxActive: maxReturnInstances}},
		{Name: "check", ProgramType: ebpf.Tracing},
		{Name: "finish", ProgramType: ebpf.Tracing},
	}
}

// No retries or continuation after any error, including nil-link anomalies.
// Error plus returned handle still transfers that handle into retained ownership.
func attachA0Plan(owner *a0NativeOwner, attach func(a0AttachSpec) (io.Closer, error)) error {
	for _, spec := range a0AttachmentPlan() {
		l, err := attach(spec)
		present := l != nil
		if present {
			v := reflect.ValueOf(l)
			if v.Kind() == reflect.Pointer && v.IsNil() {
				present = false
			}
		}
		if present {
			owner.links = append(owner.links, l)
		}
		if err != nil || !present {
			if err == nil {
				err = errors.New("attachment returned nil link")
			}
			owner.attachErr = errors.Join(owner.attachErr, fmt.Errorf("%s attachment/hidden rollback uncertain: %w", spec.Name, err))
			return owner.attachErr
		}
	}
	return nil
}

type a0NativeOwner struct {
	collection      *ebpf.Collection
	namespace       *a0Namespace
	attachErr       error
	detachAttempted bool
	links           []io.Closer
	detachErr       error
	child           *exec.Cmd
	registered      uint32
	files           []*os.File
	timer           *time.Timer
}

// A failed FD Close may disown its raw FD before returning an error. Retrying
// Close can then return nil without any syscall; that is NOT stop evidence.
func (o *a0NativeOwner) detach() error {
	if o.detachAttempted {
		return o.detachErr
	}
	o.detachAttempted = true
	// Separate attach uncertainty: it must not suppress the reverse close pass.
	errs := []error{o.attachErr}
	for i := len(o.links) - 1; i >= 0; i-- {
		if err := o.links[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	o.detachErr = errors.Join(errs...)
	if o.detachErr == nil {
		o.links = nil
	}
	// On uncertainty keep every link reference and the first failure permanently.
	// No independent stop proof or recovery mechanism is implemented in-process.
	return o.detachErr
}

func validateA0NativeDeadline(hasDeadline bool) error {
	if hasDeadline {
		return errors.New("NOT_READY: native A0 requires go test -timeout=0 and independently reviewed whole-VM supervision; a Go test deadline can destroy quarantine")
	}
	return nil
}

func (o *a0NativeOwner) cleanup(t *testing.T) {
	t.Helper()
	_, err := orderedA0Cleanup(a0CleanupSteps{
		detach: o.detach,
		quarantine: func(err error) {
			t.Errorf("A0 cleanup: %v", err)
			t.Log("UNCERTAIN: retaining native resources and unreaped child; isolated whole-VM supervisor must retire this VM; hidden unreturned handles are not accounted for")
			// Returning would allow process exit to release ownership. This timed loop
			// keeps the owner/namespace FD strongly reachable without deadlock auto-exit.
			for {
				time.Sleep(time.Hour)
				runtime.KeepAlive(o)
			}
		},
		unregister: func() error {
			if o.registered != 0 {
				return o.collection.Maps["owned"].Delete(o.registered)
			}
			return nil
		},
		release: func() error {
			if o.timer != nil {
				o.timer.Stop()
			}
			var errs []error
			if o.child != nil {
				// Probe detachment has succeeded, so releasing/reaping this PID is safe even
				// when deleting its inactive map entry failed. Preserve other cleanup errors.
				if err := o.child.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					errs = append(errs, err)
				}
				if err := o.child.Wait(); err != nil {
					var exit *exec.ExitError
					if !errors.As(err, &exit) {
						errs = append(errs, err)
					}
				}
			}
			for _, f := range o.files {
				if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
					errs = append(errs, err)
				}
			}
			o.collection.Close()
			return errors.Join(errs...)
		},
	})
	if err != nil {
		t.Errorf("A0 cleanup: %v", err)
	}
}
