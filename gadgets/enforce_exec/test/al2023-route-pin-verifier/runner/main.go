// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Hard-coded review boundary: any source-layout evolution requires re-review.
var fields = []struct {
	name         string
	offset, size uint32
}{
	{"lock", 0, 4},
	{"incarnation", 4, 4},
	{"cgroup_identity", 8, 8},
	{"scope", 16, 8},
	{"payload_generation", 24, 8},
	{"active_serial", 32, 8},
	{"admission_serial", 40, 8},
	{"payload_slot", 48, 4},
	{"active_record", 52, 4},
	{"execution_class", 56, 4},
	{"phase", 60, 4},
	{"early_claims", 64, 4},
	{"reserved", 68, 4},
	{"tasks_used", 72, 4},
	{"scratch_used", 76, 4},
	{"inode_refs", 80, 4},
	{"inode_reserved", 84, 4},
	{"next_source_pin", 88, 8},
	{"source_pins", 96, 4},
	{"unresolved_sources", 100, 4},
}

func checkLayout(t btf.Type) error {
	s, ok := t.(*btf.Struct)
	if !ok || s.Name != "se_route_anchor" || s.Size != 104 || len(s.Members) != len(fields) {
		return fmt.Errorf("unsupported route BTF: %v", t)
	}
	for i, f := range fields {
		m := s.Members[i]
		size, err := btf.Sizeof(m.Type)
		if err != nil || m.Name != f.name || uint32(m.Offset) != f.offset*8 || m.BitfieldSize != 0 || size != int(f.size) {
			return fmt.Errorf("route member %d mismatch: %v", i, m)
		}
		if i == 0 {
			lock, ok := m.Type.(*btf.Struct)
			if !ok || lock.Name != "bpf_spin_lock" || lock.Size != 4 || len(lock.Members) != 1 || lock.Members[0].Name != "val" || lock.Members[0].Offset != 0 {
				return fmt.Errorf("invalid spinlock BTF")
			}
		} else if n, ok := m.Type.(*btf.Typedef); !ok || (n.Name != "__u32" && n.Name != "__u64") {
			return fmt.Errorf("unexpected field type %v", m.Type)
		}
	}
	return nil
}

func inspect(s *ebpf.CollectionSpec) error {
	if s.ByteOrder != binary.LittleEndian || len(s.Programs) != 2 || len(s.Maps) != 3 {
		return fmt.Errorf("unexpected collection shape")
	}
	for name, at := range map[string]ebpf.AttachType{"probe_entry": ebpf.AttachTraceFEntry, "probe_exit": ebpf.AttachTraceFExit} {
		p := s.Programs[name]
		if p == nil || p.Type != ebpf.Tracing || p.AttachType != at || p.AttachTo != targets(s)[name] || p.Flags != 0 {
			return fmt.Errorf("unexpected program %s", name)
		}
	}
	for name, shape := range map[string][2]uint32{"routes": {104, 1}, "target": {8, 1}, "outcomes": {32, 2}} {
		m := s.Maps[name]
		if m == nil || m.Type != ebpf.Array || m.KeySize != 4 || m.ValueSize != shape[0] || m.MaxEntries != shape[1] || m.Pinning != ebpf.PinNone || m.Flags != 0 {
			return fmt.Errorf("unexpected map %s", name)
		}
	}
	return checkLayout(s.Maps["routes"].Value)
}

// The default control is not the exec-hook verifier gate.
func targets(s *ebpf.CollectionSpec) map[string]string {
	if p := s.Programs["probe_entry"]; p != nil {
		switch p.AttachTo {
		case "security_bprm_creds_for_exec":
			return map[string]string{"probe_entry": "security_bprm_creds_for_exec", "probe_exit": "bprm_execve"}
		case "cgroup_kn_lock_live":
			return map[string]string{"probe_entry": "cgroup_kn_lock_live", "probe_exit": "cgroup_kn_lock_live"}
		}
	}
	return map[string]string{"probe_entry": "__x64_sys_getpgid", "probe_exit": "__x64_sys_getpgid"}
}

func checkPrototype(f *btf.Func, exec bool) error {
	p, ok := f.Type.(*btf.FuncProto)
	if !ok || len(p.Params) != 1 {
		return fmt.Errorf("unexpected prototype %s", f.Name)
	}
	r, ok := p.Return.(*btf.Int)
	size := uint32(8)
	name := "pt_regs"
	if exec {
		size = 4
		name = "linux_binprm"
	}
	if !ok || r.Size != size || r.Encoding != btf.Signed {
		return fmt.Errorf("unexpected return %s", f.Name)
	}
	ptr, ok := p.Params[0].Type.(*btf.Pointer)
	if !ok {
		return fmt.Errorf("unexpected argument %s", f.Name)
	}
	arg := btf.UnderlyingType(ptr.Target)
	st, ok := arg.(*btf.Struct)
	if !ok || st.Name != name {
		return fmt.Errorf("unexpected pointee %s", f.Name)
	}
	return nil
}

func checkPublicationPrototype(f *btf.Func) error {
	p, ok := f.Type.(*btf.FuncProto)
	if !ok || len(p.Params) != 2 {
		return fmt.Errorf("unexpected publication prototype %s", f.Name)
	}
	for _, want := range []struct {
		typ  btf.Type
		name string
	}{{p.Params[0].Type, "kernfs_node"}, {p.Return, "cgroup"}} {
		ptr, ok := btf.UnderlyingType(want.typ).(*btf.Pointer)
		if !ok {
			return fmt.Errorf("publication hook requires pointer to %s", want.name)
		}
		st, ok := btf.UnderlyingType(ptr.Target).(*btf.Struct)
		if !ok || st.Name != want.name {
			return fmt.Errorf("publication hook requires pointee %s", want.name)
		}
	}
	drain, ok := btf.UnderlyingType(p.Params[1].Type).(*btf.Int)
	if !ok || drain.Size != 1 || drain.Encoding != btf.Bool {
		return fmt.Errorf("publication hook requires one-byte bool drain_offline")
	}
	return nil
}

func kernelPrototypes(s *ebpf.CollectionSpec) error {
	k, err := btf.LoadKernelSpec()
	if err != nil {
		return err
	}
	for _, name := range targets(s) {
		var f *btf.Func
		if err = k.TypeByName(name, &f); err != nil {
			return err
		}
		if name == "cgroup_kn_lock_live" {
			err = checkPublicationPrototype(f)
		} else {
			err = checkPrototype(f, name != "__x64_sys_getpgid")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func kernelCheck() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("amd64 only")
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return err
	}
	release := unix.ByteSliceToString(u.Release[:])
	hashes := map[string]string{
		"6.12.113-138.209.amzn2023.x86_64": "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82",
		"6.18.56-125.164.amzn2023.x86_64":  "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee",
	}
	want, ok := hashes[release]
	if !ok {
		return fmt.Errorf("unreviewed kernel %s", release)
	}
	data, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != want {
		return fmt.Errorf("kernel BTF hash mismatch")
	}
	return nil
}

// A fresh, empty child is used only for a no-mask-change newline write. Never
// move a task, enable a controller, or kill a cgroup as part of this fixture.
type publicationTrigger struct {
	dir     string
	control *os.File
	before  string
}

func openPublicationTrigger(root string) (_ *publicationTrigger, retErr error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, fmt.Errorf("publication trigger requires cgroup v2")
	}
	dir, err := os.MkdirTemp(root, "route-pin-publication-")
	if err != nil {
		return nil, err
	}
	p := &publicationTrigger{dir: dir}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, p.close())
		}
	}()
	before, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(before)) != "" {
		return nil, fmt.Errorf("new publication cgroup has enabled subtree controllers")
	}
	p.before = string(before)
	if err = p.check(); err != nil {
		return nil, err
	}
	p.control, err = os.OpenFile(filepath.Join(dir, "cgroup.subtree_control"), os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *publicationTrigger) check() error {
	control, err := os.ReadFile(filepath.Join(p.dir, "cgroup.subtree_control"))
	if err != nil {
		return err
	}
	if string(control) != p.before {
		return fmt.Errorf("publication trigger changed subtree control mask")
	}
	for _, name := range []string{"cgroup.procs", "cgroup.threads"} {
		data, err := os.ReadFile(filepath.Join(p.dir, name))
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(data)) != "" {
			return fmt.Errorf("publication cgroup unexpectedly populated: %s", name)
		}
	}
	return nil
}

func (p *publicationTrigger) close() error {
	var err error
	if p.control != nil {
		err = p.control.Close()
	}
	return errors.Join(err, os.Remove(p.dir))
}

func live(s *ebpf.CollectionSpec) (retErr error) {
	if err := kernelCheck(); err != nil {
		return err
	}
	if err := kernelPrototypes(s); err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	c, err := ebpf.NewCollection(s)
	if err != nil {
		return err
	}
	defer c.Close()
	// Isolated ARRAY, never pinned. Zero target keeps both programs inert.
	raw := make([]byte, 104)
	binary.LittleEndian.PutUint32(raw[4:], 1)
	for off, v := range map[int]uint64{8: 7, 16: 10, 24: 13, 32: 1} {
		binary.LittleEndian.PutUint64(raw[off:], v)
	}
	binary.LittleEndian.PutUint32(raw[56:], 1) // Synthetic Audit class, not policy authority.
	binary.LittleEndian.PutUint32(raw[60:], 2) // ACTIVE
	if err = c.Maps["routes"].Update(uint32(0), raw, ebpf.UpdateAny); err != nil {
		return err
	}
	for _, name := range []string{"probe_entry", "probe_exit"} {
		l, e := link.AttachTracing(link.TracingOptions{Program: c.Programs[name]})
		if e != nil {
			return e
		}
		defer l.Close()
	}
	// A deliberately invalid executable reaches bprm without replacing this process.
	var invalid string
	var publication *publicationTrigger
	if targets(s)["probe_exit"] == "bprm_execve" {
		f, e := os.CreateTemp("", "route-pin-invalid-*")
		if e != nil {
			return e
		}
		invalid = f.Name()
		defer os.Remove(invalid)
		_, e = f.Write([]byte("not an executable format\n"))
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		if e = os.Chmod(invalid, 0o700); e != nil {
			return e
		}
	} else if targets(s)["probe_exit"] == "cgroup_kn_lock_live" {
		publication, err = openPublicationTrigger("/sys/fs/cgroup")
		if err != nil {
			return err
		}
		defer func() { retErr = errors.Join(retErr, publication.close()) }()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	target := uint64(os.Getpid())<<32 | uint64(unix.Gettid())
	if err = c.Maps["target"].Update(uint32(0), target, ebpf.UpdateAny); err != nil {
		return err
	}
	var triggerErr error
	if invalid != "" {
		triggerErr = unix.Exec(invalid, []string{invalid}, []string{})
		if errors.Is(triggerErr, unix.ENOEXEC) {
			triggerErr = nil
		} else {
			triggerErr = fmt.Errorf("expected ENOEXEC: %w", triggerErr)
		}
	} else if publication != nil {
		var n int
		n, triggerErr = publication.control.Write([]byte("\n"))
		if triggerErr == nil && n != 1 {
			triggerErr = fmt.Errorf("publication trigger short write: %d", n)
		}
	} else {
		_, _, errno := unix.Syscall(unix.SYS_GETPGID, 0, 0, 0)
		if errno != 0 {
			triggerErr = errno
		}
	}
	if err = c.Maps["target"].Update(uint32(0), uint64(0), ebpf.UpdateAny); err != nil {
		return err
	}
	if triggerErr != nil {
		return triggerErr
	}
	if publication != nil {
		if err = publication.check(); err != nil {
			return err
		}
	}
	for i := uint32(0); i < 2; i++ {
		var out [4]uint64
		if err = c.Maps["outcomes"].Lookup(i, &out); err != nil {
			return err
		}
		if out != [4]uint64{1, 1, 1, 0} {
			return fmt.Errorf("hook %d outcome %v", i, out)
		}
	}
	if err = c.Maps["routes"].Lookup(uint32(0), raw); err != nil {
		return err
	}
	if binary.LittleEndian.Uint64(raw[88:]) != 2 || binary.LittleEndian.Uint32(raw[64:]) != 0 || binary.LittleEndian.Uint32(raw[96:]) != 0 || binary.LittleEndian.Uint32(raw[100:]) != 0 {
		return fmt.Errorf("route not balanced: %x", raw)
	}
	fmt.Println("PASS: two synchronous synthetic acquire/release pairs; NOT physical-exec/product proof")
	return nil
}

func run() error {
	object := flag.String("object", "", "explicit object path")
	enabled := flag.Bool("run-isolated", false, "load/attach on reviewed isolated exact AL2023 kernel; default is inspect only")
	flag.Parse()
	if *object == "" {
		return fmt.Errorf("-object required")
	}
	s, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	if err = inspect(s); err != nil {
		return err
	}
	fmt.Println("PASS: current source-pin route BTF and non-sleepable tracing spec")
	if !*enabled {
		return nil
	}
	return live(s)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
