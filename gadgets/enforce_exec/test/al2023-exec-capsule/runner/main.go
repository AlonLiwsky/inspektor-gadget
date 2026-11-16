// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Command exec-capsule-runner drives the default-off exec-capsule fixture on
// an isolated exact AL2023 kernel. Without -run-isolated it only inspects the
// object. It never denies an exec: the LSM program is pass-through.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Mirrors SE_CAP_STAT_* in full/shared_exec_capsule.h.
const (
	statBegin = iota
	statUncoveredBegin
	statStaleRetired
	statFrozen
	statFrozenUncovered
	statPinned
	statPinFailed
	statOriginalClaim
	statTerminal
	statForeignTerminal
	statSuccess
	statCheckOnly
	statReleaseFault
	statFault
	statCount
)

var statNames = [statCount]string{
	"begin", "uncovered_begin", "stale_retired",
	"frozen", "frozen_uncovered", "pinned", "pin_failed", "original_claim",
	"terminal", "foreign_terminal", "success", "check_only",
	"release_fault", "fault",
}

const (
	routeOwned      = 1
	routeAuditFault = 2
	atExecveCheck   = 0x10000
	programTerminal = "capsule_terminal"
	programEntry    = "capsule_entry"
	programBegin    = "capsule_begin"
	programAdmit    = "capsule_admit"
)

// Attach order is part of the coverage proof: terminal before entry.
var attachOrder = []string{programTerminal, programEntry, programBegin, programAdmit}

type admission struct {
	Cgroup, Sequence     uint64
	Result               int32
	Frozen, Current, Pid uint32
}

type observation struct {
	Count, Reserved uint32
	Admissions      [8]admission
}

type stats [statCount]uint64

func (s stats) delta(before stats) stats {
	var d stats
	for i := range s {
		d[i] = s[i] - before[i]
	}
	return d
}

func (s stats) String() string {
	var b strings.Builder
	for i, v := range s {
		if v != 0 {
			fmt.Fprintf(&b, "%s=%d ", statNames[i], v)
		}
	}
	return strings.TrimSpace(b.String())
}

var expectedPrograms = map[string]struct {
	typ    ebpf.ProgramType
	attach ebpf.AttachType
	target string
}{
	programTerminal: {ebpf.Tracing, ebpf.AttachTraceFExit, "bprm_execve"},
	programEntry:    {ebpf.Tracing, ebpf.AttachTraceFEntry, "bprm_execve"},
	programBegin:    {ebpf.Tracing, ebpf.AttachTraceFEntry, "security_bprm_creds_for_exec"},
	programAdmit:    {ebpf.LSM, ebpf.AttachLSMMac, "bprm_check_security"},
}

var expectedMaps = map[string]struct {
	typ        ebpf.MapType
	key, value uint32
}{
	"routes": {ebpf.Array, 4, 104}, "locators": {ebpf.Hash, 8, 8},
	"capsules": {ebpf.Array, 4, 104}, "markers": {ebpf.Array, 4, 16},
	"sequence": {ebpf.Array, 4, 8}, "stats": {ebpf.Array, 4, 8 * statCount},
	"observations": {ebpf.Hash, 4, 264},
}

func inspect(s *ebpf.CollectionSpec) error {
	if s.ByteOrder != binary.LittleEndian || len(s.Programs) != len(expectedPrograms) ||
		len(s.Maps) != len(expectedMaps) {
		return fmt.Errorf("unexpected collection shape: %d programs %d maps",
			len(s.Programs), len(s.Maps))
	}
	for name, want := range expectedPrograms {
		p := s.Programs[name]
		if p == nil || p.Type != want.typ || p.AttachType != want.attach ||
			p.AttachTo != want.target || p.Flags != 0 {
			return fmt.Errorf("unexpected program %s", name)
		}
	}
	for name, want := range expectedMaps {
		m := s.Maps[name]
		if m == nil || m.Type != want.typ || m.KeySize != want.key ||
			m.ValueSize != want.value || m.Pinning != ebpf.PinNone || m.Flags != 0 {
			return fmt.Errorf("unexpected map %s", name)
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

type fixture struct {
	coll       *ebpf.Collection
	links      []link.Link
	cgroups    [2]string
	cgroupIDs  [2]uint64
	cgroupFDs  [2]int
	work       string
	script     string
	interp     string
	waiter     string
	invalid    string
	fanotifyFD int
}

func cgroupID(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

func newFixture(waiter string) (_ *fixture, retErr error) {
	f := &fixture{fanotifyFD: -1, cgroupFDs: [2]int{-1, -1}}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, f.close())
		}
	}()
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, fmt.Errorf("cgroup v2 required")
	}
	for i := range f.cgroups {
		dir, err := os.MkdirTemp("/sys/fs/cgroup", fmt.Sprintf("exec-capsule-%d-", i))
		if err != nil {
			return nil, err
		}
		f.cgroups[i] = dir
		if f.cgroupIDs[i], err = cgroupID(dir); err != nil {
			return nil, err
		}
		if f.cgroupFDs[i], err = unix.Open(dir, unix.O_DIRECTORY|unix.O_PATH|unix.O_CLOEXEC, 0); err != nil {
			return nil, err
		}
	}
	work, err := os.MkdirTemp("/root", "exec-capsule-")
	if err != nil {
		return nil, err
	}
	f.work = work
	f.interp = filepath.Join(work, "interp")
	bash, err := os.ReadFile("/bin/bash")
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(f.interp, bash, 0o700); err != nil {
		return nil, err
	}
	f.script = filepath.Join(work, "script")
	if err = os.WriteFile(f.script, []byte("#!"+f.interp+"\nexec /bin/true\n"), 0o700); err != nil {
		return nil, err
	}
	f.invalid = filepath.Join(work, "invalid")
	if err = os.WriteFile(f.invalid, []byte("not an executable format\n"), 0o700); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(waiter)
	if err != nil {
		return nil, err
	}
	f.waiter = filepath.Join(work, "waiter")
	if err = os.WriteFile(f.waiter, data, 0o700); err != nil {
		return nil, err
	}
	f.fanotifyFD, err = unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	if err = unix.FanotifyMark(f.fanotifyFD, unix.FAN_MARK_ADD,
		unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, f.interp); err != nil {
		return nil, fmt.Errorf("fanotify_mark: %w", err)
	}
	return f, nil
}

func (f *fixture) detach() error {
	var err error
	// Reverse of attach order: admission first, terminal last.
	for i := len(f.links) - 1; i >= 0; i-- {
		err = errors.Join(err, f.links[i].Close())
	}
	f.links = nil
	if f.coll != nil {
		f.coll.Close()
		f.coll = nil
	}
	return err
}

func (f *fixture) close() error {
	err := f.detach()
	if f.fanotifyFD >= 0 {
		err = errors.Join(err, unix.Close(f.fanotifyFD))
	}
	for i := range f.cgroups {
		if f.cgroupFDs[i] >= 0 {
			err = errors.Join(err, unix.Close(f.cgroupFDs[i]))
		}
		if f.cgroups[i] != "" {
			err = errors.Join(err, os.Remove(f.cgroups[i]))
		}
	}
	if f.work != "" {
		err = errors.Join(err, os.RemoveAll(f.work))
	}
	return err
}

func (f *fixture) load(spec *ebpf.CollectionSpec, pidMax uint32) error {
	spec = spec.Copy()
	spec.Maps["capsules"].MaxEntries = pidMax
	spec.Maps["markers"].MaxEntries = pidMax
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load: %+w", ve)
		}
		return fmt.Errorf("load: %w", err)
	}
	f.coll = coll
	for slot, id := range f.cgroupIDs {
		locator := uint64(1)<<32 | uint64(slot)
		if err = coll.Maps["locators"].Update(id, locator, ebpf.UpdateNoExist); err != nil {
			return err
		}
	}
	return nil
}

// setRoutes installs slot 0 (cgroup 0) with class0 and slot 1 with the other
// class. Only valid while no route is claimed or pinned.
func (f *fixture) setRoutes(class0 uint32) error {
	for slot := uint32(0); slot < 2; slot++ {
		raw := make([]byte, 104)
		if err := f.coll.Maps["routes"].Lookup(slot, raw); err != nil {
			return err
		}
		if early, pins, unresolved := binary.LittleEndian.Uint32(raw[64:]),
			binary.LittleEndian.Uint32(raw[96:]), binary.LittleEndian.Uint32(raw[100:]); early|pins|unresolved != 0 {
			return fmt.Errorf("route %d busy before reconfiguration", slot)
		}
		class := class0
		if slot == 1 {
			class = 3 - class0
		}
		binary.LittleEndian.PutUint32(raw[4:], 1) // incarnation
		binary.LittleEndian.PutUint64(raw[8:], f.cgroupIDs[slot])
		binary.LittleEndian.PutUint64(raw[16:], uint64(10+slot)) // scope
		binary.LittleEndian.PutUint64(raw[24:], 13)              // payload generation
		binary.LittleEndian.PutUint64(raw[32:], 1)               // active serial
		binary.LittleEndian.PutUint32(raw[48:], slot)            // payload slot
		binary.LittleEndian.PutUint32(raw[56:], class)           // synthetic class
		binary.LittleEndian.PutUint32(raw[60:], 2)               // ACTIVE
		if err := f.coll.Maps["routes"].Update(slot, raw, ebpf.UpdateExist); err != nil {
			return err
		}
	}
	return nil
}

func (f *fixture) attach(names []string) error {
	for _, name := range names {
		p := f.coll.Programs[name]
		var l link.Link
		var err error
		if name == programAdmit {
			l, err = link.AttachLSM(link.LSMOptions{Program: p})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: p})
		}
		if err != nil {
			return fmt.Errorf("attach %s: %w", name, err)
		}
		f.links = append(f.links, l)
	}
	return nil
}

func (f *fixture) stats() (stats, error) {
	var s stats
	raw := make([]byte, 8*statCount)
	if err := f.coll.Maps["stats"].Lookup(uint32(0), raw); err != nil {
		return s, err
	}
	for i := range s {
		s[i] = binary.LittleEndian.Uint64(raw[8*i:])
	}
	return s, nil
}

func (f *fixture) observation(tgid int) (observation, error) {
	var o observation
	raw := make([]byte, 264)
	if err := f.coll.Maps["observations"].Lookup(uint32(tgid), raw); err != nil {
		return o, fmt.Errorf("no observation for tgid %d: %w", tgid, err)
	}
	err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &o)
	return o, err
}

// quiescent checks balanced routes, no faults, and FREE capsules for tgids.
func (f *fixture) quiescent(tgids ...int) error {
	for slot := uint32(0); slot < 2; slot++ {
		raw := make([]byte, 104)
		if err := f.coll.Maps["routes"].Lookup(slot, raw); err != nil {
			return err
		}
		early, pins, unresolved := binary.LittleEndian.Uint32(raw[64:]),
			binary.LittleEndian.Uint32(raw[96:]), binary.LittleEndian.Uint32(raw[100:])
		if early != 0 || pins != 0 || unresolved != 0 {
			return fmt.Errorf("route %d unbalanced: early=%d pins=%d unresolved=%d",
				slot, early, pins, unresolved)
		}
	}
	s, err := f.stats()
	if err != nil {
		return err
	}
	if s[statFault] != 0 || s[statReleaseFault] != 0 || s[statPinFailed] != 0 {
		return fmt.Errorf("capsule faults: %s", s)
	}
	for _, tgid := range tgids {
		raw := make([]byte, 104)
		if err = f.coll.Maps["capsules"].Lookup(uint32(tgid), raw); err != nil {
			return err
		}
		if phase := binary.LittleEndian.Uint32(raw[4:]); phase != 0 {
			return fmt.Errorf("capsule %d not FREE: phase %d", tgid, phase)
		}
		// owner.owned lives at offset 96 (owner at 40, token 56 bytes).
		if owned := binary.LittleEndian.Uint32(raw[96:]); owned != 0 {
			return fmt.Errorf("capsule %d still owns a route pin", tgid)
		}
	}
	return nil
}

// permission handles exactly one FAN_OPEN_EXEC_PERM event: it runs onBlocked
// with the opener's TGID while the interpreter open is held, then allows.
func (f *fixture) permission(onBlocked func(pid int) error) <-chan error {
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		n, err := unix.Read(f.fanotifyFD, buf)
		if err != nil {
			done <- err
			return
		}
		var meta unix.FanotifyEventMetadata
		if n < int(unsafeSizeofMeta) {
			done <- fmt.Errorf("short fanotify read %d", n)
			return
		}
		_ = binary.Read(bytes.NewReader(buf[:unsafeSizeofMeta]), binary.LittleEndian, &meta)
		var hookErr error
		if meta.Mask&unix.FAN_OPEN_EXEC_PERM == 0 {
			hookErr = fmt.Errorf("unexpected fanotify mask %#x", meta.Mask)
		} else {
			hookErr = onBlocked(int(meta.Pid))
		}
		resp := make([]byte, 8)
		binary.LittleEndian.PutUint32(resp[0:], uint32(meta.Fd))
		binary.LittleEndian.PutUint32(resp[4:], unix.FAN_ALLOW)
		_, werr := unix.Write(f.fanotifyFD, resp)
		cerr := unix.Close(int(meta.Fd))
		done <- errors.Join(hookErr, werr, cerr)
	}()
	return done
}

const unsafeSizeofMeta = 24

func (f *fixture) move(pid, cgroup int) error {
	return os.WriteFile(filepath.Join(f.cgroups[cgroup], "cgroup.procs"),
		[]byte(strconv.Itoa(pid)), 0)
}

func (f *fixture) command(cgroup int, newPID bool, path string, args ...string) *exec.Cmd {
	cmd := exec.Command(path, args...)
	cmd.Env = []string{}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: f.cgroupFDs[cgroup]}
	if newPID {
		cmd.SysProcAttr.Cloneflags = unix.CLONE_NEWPID
	}
	return cmd
}

func waitFor(timeout time.Duration, cond func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	for {
		ok, err := cond()
		if err != nil || ok {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// threadsInExecve counts tasks of tgid currently inside execve (nr 59).
func threadsInExecve(tgid int) (inExec int, leaderInExec bool, err error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", tgid))
	if err != nil {
		return 0, false, err
	}
	for _, e := range entries {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/syscall", tgid, e.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(string(data), "59 ") {
			inExec++
			if e.Name() == strconv.Itoa(tgid) {
				leaderInExec = true
			}
		}
	}
	return inExec, leaderInExec, nil
}

func expectAdmission(a admission, idx int, frozen, current uint32, cgroup uint64) error {
	if a.Frozen != frozen || a.Current != current || a.Cgroup != cgroup ||
		(a.Result != routeOwned) {
		return fmt.Errorf("admission %d: got frozen=%d current=%d cgroup=%d result=%d; want frozen=%d current=%d cgroup=%d owned",
			idx, a.Frozen, a.Current, a.Cgroup, a.Result, frozen, current, cgroup)
	}
	return nil
}

// exactly checks selected stats deltas; other counters are unconstrained.
func exactly(d stats, want map[int]uint64) error {
	for i, v := range want {
		if d[i] != v {
			return fmt.Errorf("stat %s: got %d want %d (delta %s)", statNames[i], d[i], v, d)
		}
	}
	return nil
}

type scenario struct {
	name string
	run  func(f *fixture, original uint32) error
}

// Audit<->Strict migration between the script admission and the
// interpreter admission of ONE physical exec; then a fresh exec.
func migrate(newPID bool) func(*fixture, uint32) error {
	return func(f *fixture, original uint32) error {
		before, err := f.stats()
		if err != nil {
			return err
		}
		cmd := f.command(0, newPID, f.waiter, "exec", f.script)
		done := f.permission(func(pid int) error { return f.move(pid, 1) })
		startErr := cmd.Start()
		if err = <-done; err != nil {
			return errors.Join(err, startErr)
		}
		if startErr != nil {
			return startErr
		}
		if err = cmd.Wait(); err != nil {
			return fmt.Errorf("script exit: %w", err)
		}
		o, err := f.observation(cmd.Process.Pid)
		if err != nil {
			return err
		}
		other := 3 - original
		// launcher, script, interpreter (migrated), fresh /bin/true.
		if o.Count != 4 {
			return fmt.Errorf("want 4 admissions, got %d: %+v", o.Count, o.Admissions[:min(o.Count, 8)])
		}
		if err = errors.Join(
			expectAdmission(o.Admissions[0], 0, original, original, f.cgroupIDs[0]),
			expectAdmission(o.Admissions[1], 1, original, original, f.cgroupIDs[0]),
			expectAdmission(o.Admissions[2], 2, original, other, f.cgroupIDs[1]),
			expectAdmission(o.Admissions[3], 3, other, other, f.cgroupIDs[1])); err != nil {
			return err
		}
		if o.Admissions[0].Sequence == o.Admissions[1].Sequence ||
			o.Admissions[1].Sequence != o.Admissions[2].Sequence ||
			o.Admissions[2].Sequence == o.Admissions[3].Sequence {
			return fmt.Errorf("physical-exec sequences wrong: %+v", o.Admissions[:4])
		}
		d, err := f.stats()
		if err != nil {
			return err
		}
		d = d.delta(before)
		// launcher, script(+interpreter), fresh /bin/true.
		if err = exactly(d, map[int]uint64{
			statBegin: 3, statTerminal: 3,
			statSuccess: 3, statForeignTerminal: 0, statFrozen: 3,
			statPinned: 3, statOriginalClaim: 1, statStaleRetired: 0,
		}); err != nil {
			return err
		}
		return f.quiescent(cmd.Process.Pid)
	}
}

// Nonleader exec plus a same-TGID losing waiter killed by de_thread.
func waiterScenario(f *fixture, original uint32) error {
	before, err := f.stats()
	if err != nil {
		return err
	}
	cmd := f.command(0, false, f.waiter, f.script)
	done := f.permission(func(pid int) error {
		var leader bool
		if err := waitFor(10*time.Second, func() (bool, error) {
			n, l, err := threadsInExecve(pid)
			leader = l
			return n >= 2, err
		}); err != nil {
			return fmt.Errorf("losing waiter never entered execve: %w", err)
		}
		if leader {
			return fmt.Errorf("leader unexpectedly in execve")
		}
		return f.move(pid, 1)
	})
	if err = cmd.Start(); err != nil {
		return err
	}
	if err = <-done; err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	if err = cmd.Wait(); err != nil {
		return fmt.Errorf("waiter exit: %w", err)
	}
	o, err := f.observation(cmd.Process.Pid)
	if err != nil {
		return err
	}
	other := 3 - original
	if o.Count != 4 {
		return fmt.Errorf("want 4 admissions, got %d: %+v", o.Count, o.Admissions[:min(o.Count, 8)])
	}
	if err = errors.Join(
		expectAdmission(o.Admissions[0], 0, original, original, f.cgroupIDs[0]),
		expectAdmission(o.Admissions[1], 1, original, original, f.cgroupIDs[0]),
		expectAdmission(o.Admissions[2], 2, original, other, f.cgroupIDs[1]),
		expectAdmission(o.Admissions[3], 3, other, other, f.cgroupIDs[1])); err != nil {
		return err
	}
	if o.Admissions[1].Pid == uint32(cmd.Process.Pid) {
		return fmt.Errorf("script exec ran on the leader, not a nonleader")
	}
	if o.Admissions[1].Sequence != o.Admissions[2].Sequence {
		return fmt.Errorf("interpreter lost its physical exec: %+v", o.Admissions[:4])
	}
	if o.Admissions[3].Pid != uint32(cmd.Process.Pid) {
		return fmt.Errorf("post-de_thread exec did not take the leader PID")
	}
	d, err := f.stats()
	if err != nil {
		return err
	}
	d = d.delta(before)
	// waiter, winner script(+interpreter), fresh /bin/true; the loser never
	// begins and its terminal is the only FOREIGN one.
	if err = exactly(d, map[int]uint64{
		statBegin: 3, statTerminal: 3,
		statSuccess: 3, statForeignTerminal: 1, statFrozen: 3,
		statPinned: 3, statOriginalClaim: 1, statStaleRetired: 0,
	}); err != nil {
		return err
	}
	return f.quiescent(cmd.Process.Pid)
}

// Failed exec (ENOEXEC) after admission: terminal, no success, no leak.
func failureScenario(f *fixture, original uint32) error {
	before, err := f.stats()
	if err != nil {
		return err
	}
	cmd := f.command(0, false, f.waiter, "exec", f.invalid)
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 104 {
		return fmt.Errorf("want launcher exit 104 after ENOEXEC, got %w", err)
	}
	o, err := f.observation(cmd.Process.Pid)
	if err != nil {
		return err
	}
	if o.Count != 2 {
		return fmt.Errorf("want 2 admissions, got %d", o.Count)
	}
	if err = errors.Join(
		expectAdmission(o.Admissions[0], 0, original, original, f.cgroupIDs[0]),
		expectAdmission(o.Admissions[1], 1, original, original, f.cgroupIDs[0])); err != nil {
		return err
	}
	d, err := f.stats()
	if err != nil {
		return err
	}
	d = d.delta(before)
	if err = exactly(d, map[int]uint64{
		statBegin: 2, statTerminal: 2,
		statSuccess: 1, statFrozen: 2, statPinned: 2, statOriginalClaim: 0,
	}); err != nil {
		return err
	}
	return f.quiescent(cmd.Process.Pid)
}

// AT_EXECVE_CHECK: 6.18 returns 0 after begin without admission or success;
// 6.12 rejects the flag before any begin.
func checkScenario(f *fixture, release string) error {
	before, err := f.stats()
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd, err := unix.Open("/bin/true", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	argv, _ := syscall.SlicePtrFromStrings([]string{"/bin/true"})
	envp, _ := syscall.SlicePtrFromStrings([]string{})
	empty, _ := syscall.BytePtrFromString("")
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd),
		uintptr(unsafe.Pointer(empty)), uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envp[0])), unix.AT_EMPTY_PATH|atExecveCheck, 0)
	d, err := f.stats()
	if err != nil {
		return err
	}
	d = d.delta(before)
	if strings.HasPrefix(release, "6.18.") {
		if errno != 0 {
			return fmt.Errorf("6.18 AT_EXECVE_CHECK failed: %w", errno)
		}
		if err = exactly(d, map[int]uint64{
			statBegin: 1, statTerminal: 1,
			statCheckOnly: 1, statSuccess: 0, statFrozen: 0,
		}); err != nil {
			return err
		}
	} else {
		// Rejected inside alloc_bprm, before any bprm or hook.
		if errno != unix.EINVAL {
			return fmt.Errorf("6.12 AT_EXECVE_CHECK: want EINVAL, got %w", errno)
		}
		if err = exactly(d, map[int]uint64{
			statBegin: 0, statTerminal: 0,
			statCheckOnly: 0,
		}); err != nil {
			return err
		}
	}
	return f.quiescent(os.Getpid())
}

// lateAttach blocks an exec before the programs are attached, attaches, and
// releases it. The interpreter admission is uncovered: it must freeze the
// original class WITHOUT a pin, and the next exec must retire it.
func lateAttach(spec *ebpf.CollectionSpec, pidMax uint32, f *fixture, original uint32) error {
	attached := make(chan error, 1)
	cmd := f.command(0, false, f.waiter, "exec", f.script)
	done := f.permission(func(int) error {
		err := f.load(spec, pidMax)
		if err == nil {
			err = f.setRoutes(original)
		}
		if err == nil {
			err = f.attach(attachOrder)
		}
		attached <- err
		return err
	})
	startErr := cmd.Start()
	if err := <-done; err != nil {
		return errors.Join(err, startErr)
	}
	if err := <-attached; err != nil {
		return err
	}
	if startErr != nil {
		return startErr
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("script exit: %w", err)
	}
	o, err := f.observation(cmd.Process.Pid)
	if err != nil {
		return err
	}
	if o.Count != 2 {
		return fmt.Errorf("want 2 admissions, got %d: %+v", o.Count, o.Admissions[:min(o.Count, 8)])
	}
	if err = errors.Join(
		expectAdmission(o.Admissions[0], 0, original, original, f.cgroupIDs[0]),
		expectAdmission(o.Admissions[1], 1, original, original, f.cgroupIDs[0])); err != nil {
		return err
	}
	if o.Admissions[0].Sequence == o.Admissions[1].Sequence {
		return fmt.Errorf("uncovered and covered execs share a sequence")
	}
	s, err := f.stats()
	if err != nil {
		return err
	}
	// The in-flight script exec has no begin and no terminal; only the
	// fresh /bin/true is covered and retires the uncovered capsule.
	if err = exactly(s, map[int]uint64{
		statBegin: 1, statTerminal: 1,
		statSuccess: 1, statFrozen: 2, statFrozenUncovered: 1,
		statPinned: 1, statStaleRetired: 1, statUncoveredBegin: 0,
	}); err != nil {
		return err
	}
	return f.quiescent(cmd.Process.Pid)
}

// leftoverMarkers counts nonzero entry markers (exec calls in flight or
// leaked). Iterates the whole pid_max-sized ARRAY.
func (f *fixture) leftoverMarkers() (int, error) {
	var key uint32
	value := make([]byte, 16)
	n := 0
	it := f.coll.Maps["markers"].Iterate()
	for it.Next(&key, &value) {
		if binary.LittleEndian.Uint64(value[0:]) != 0 || binary.LittleEndian.Uint64(value[8:]) != 0 {
			n++
		}
	}
	return n, it.Err()
}

// recursionMisses sums programs skipped by the per-CPU recursion guard.
func (f *fixture) recursionMisses() (map[string]uint64, error) {
	out := map[string]uint64{}
	for _, name := range attachOrder {
		info, err := f.coll.Programs[name].Stats()
		if err != nil {
			return nil, err
		}
		out[name] = info.RecursionMisses
	}
	return out, nil
}

// preemptMode records the dynamic preemption mode; the coverage premise
// requires no involuntary preemption inside fentry/fexit programs.
func preemptMode() string {
	data, err := os.ReadFile("/sys/kernel/debug/sched/preempt")
	if err != nil {
		cmdline, _ := os.ReadFile("/proc/cmdline")
		return fmt.Sprintf("unknown (%v); cmdline: %s", err, strings.TrimSpace(string(cmdline)))
	}
	return strings.TrimSpace(string(data))
}

func live(spec *ebpf.CollectionSpec, waiter string) (retErr error) {
	release, err := kernelCheck()
	if err != nil {
		return err
	}
	fmt.Printf("kernel %s exact BTF and active BPF LSM\n", release)
	mode := preemptMode()
	fmt.Printf("preemption: %s\n", mode)
	// Only modes without involuntary preemption satisfy the premise; an
	// unknown mode is refused rather than assumed.
	if !strings.Contains(mode, "(none)") && !strings.Contains(mode, "(voluntary)") {
		return fmt.Errorf("preemption mode %q violates the capsule coverage premise", mode)
	}
	raw, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return err
	}
	pidMax, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return err
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return err
	}
	failed := 0
	report := func(name string, err error) {
		if err != nil {
			failed++
			fmt.Printf("FAIL %s: %v\n", name, err)
		} else {
			fmt.Printf("PASS %s\n", name)
		}
	}
	// Late attach first, each class, on its own collection.
	for _, original := range []uint32{1, 2} {
		f, err := newFixture(waiter)
		if err != nil {
			return err
		}
		report(fmt.Sprintf("late-attach/class%d", original), lateAttach(spec, uint32(pidMax), f, original))
		if err = f.close(); err != nil {
			return err
		}
	}
	f, err := newFixture(waiter)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, f.close()) }()
	if err = f.load(spec, uint32(pidMax)); err != nil {
		return err
	}
	if err = f.setRoutes(1); err != nil {
		return err
	}
	if err = f.attach(attachOrder); err != nil {
		return err
	}
	scenarios := []scenario{
		{"migrate", migrate(false)},
		{"migrate-pidns", migrate(true)},
		{"nonleader-losing-waiter", waiterScenario},
		{"failed-exec", failureScenario},
	}
	for _, original := range []uint32{1, 2} {
		if err = f.setRoutes(original); err != nil {
			return err
		}
		for _, s := range scenarios {
			report(fmt.Sprintf("%s/class%d", s.name, original), s.run(f, original))
		}
	}
	report("execve-check", checkScenario(f, release))
	var markers int
	if err = waitFor(5*time.Second, func() (bool, error) {
		n, err := f.leftoverMarkers()
		markers = n
		return n == 0, err
	}); err != nil {
		report("markers-drained", fmt.Errorf("%d nonzero markers: %w", markers, err))
	} else {
		report("markers-drained", nil)
	}
	misses, err := f.recursionMisses()
	if err != nil {
		return err
	}
	var missErr error
	for name, n := range misses {
		if n != 0 {
			missErr = errors.Join(missErr, fmt.Errorf("%s recursion misses %d", name, n))
		}
	}
	report("no-recursion-misses", missErr)
	s, err := f.stats()
	if err != nil {
		return err
	}
	fmt.Printf("final stats (pid_max=%d): %s\n", pidMax, s)
	if failed != 0 {
		return fmt.Errorf("%d scenario(s) failed", failed)
	}
	fmt.Println("PASS: exec capsule original-class authority on exact kernel; pass-through fixture, NOT product enforcement")
	return nil
}

func run() error {
	object := flag.String("object", "", "explicit object path")
	waiter := flag.String("waiter", "", "static waiter helper path")
	enabled := flag.Bool("run-isolated", false, "load/attach on an isolated exact AL2023 kernel; default is inspect only")
	flag.Parse()
	if *object == "" {
		return fmt.Errorf("-object required")
	}
	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	if err = inspect(spec); err != nil {
		return err
	}
	fmt.Println("PASS: exec-capsule object shape")
	if !*enabled {
		return nil
	}
	if *waiter == "" {
		return fmt.Errorf("-waiter required with -run-isolated")
	}
	return live(spec, *waiter)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
