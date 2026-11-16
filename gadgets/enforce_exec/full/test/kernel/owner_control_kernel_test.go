// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
)

type ocConfig struct {
	Cookie, Cgroup                uint64
	InitPID, Limit, GateSlot, ABI uint32
}
type ocCommand struct {
	Nonce, Generation, RootCookie uint64
	Operation, NewMask            uint32
}
type ocHealth struct {
	TaskCredits, WorkCredits, Authority, AComplete, Ready  uint64
	Active, MovementSequence, MovementArmed, MovementFault uint64
	Faults, PendingBirths, GateDenials, RootCookie         uint64
	Count, Result, Retired, Busy, RootMatch, Padding       uint32
}
type ocRow struct {
	Cookie                       uint64
	TID, TGID, Flags, ValidRoles uint32
}

// Actual production command and movement programs, with production role helpers.
// No role lifecycle hooks or exec LSM are attached: this is not an enforcement,
// late-fork coverage, aggregate-memory-budget or complete OwnerProfile proof.
func TestOwnerControlKernel(t *testing.T) {
	if os.Getenv("IG_OWNER_CONTROL_KERNEL_TEST") != "1" {
		t.Skip("disposable kernel opt-in required")
	}
	require.Zero(t, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tmp := t.TempDir()
	header, e := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "vmlinux.h"), header, 0o600))
	source := os.Getenv("IG_OWNER_CONTROL_BPF_SOURCE")
	if source == "" {
		source = "bpf/owner_control_compile.bpf.c"
	}
	object := filepath.Join(tmp, "owner.bpf.o")
	output, e := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object).CombinedOutput()
	require.NoError(t, e, string(output))
	spec, e := ebpf.LoadCollectionSpec(object)
	require.NoError(t, e)
	hooks := []string{"eo_migrate_enter", "eo_migrate_exit", "eo_reconfigure_enter", "eo_reconfigure_exit", "eo_movement_arm"}
	selected := map[string]bool{"eo_command": true}
	for _, hook := range hooks {
		selected[hook] = true
	}
	for name := range spec.Programs {
		if !selected[name] {
			delete(spec.Programs, name)
		}
	}
	collection, e := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 16 * 1024 * 1024}})
	if e != nil {
		t.Fatalf("production owner verifier: %+v", e)
	}
	var attached []link.Link
	var gates *fullruntime.GateMap
	var owner *fullruntime.ProgramSlot
	defer func() {
		for _, l := range attached {
			l.Close()
		}
		if owner != nil {
			owner.CloseAfterDetach()
		}
		if gates != nil {
			gates.Close()
		}
		collection.Close()
	}()
	for _, hook := range hooks {
		l, e := link.AttachTracing(link.TracingOptions{Program: collection.Programs[hook]})
		require.NoError(t, e, hook)
		attached = append(attached, l)
	}
	nonce := uint64(0x43c18b652)
	pidfd, e := unix.PidfdOpen(unix.Gettid(), 0x80)
	require.NoError(t, e)
	defer unix.Close(pidfd)
	require.NoError(t, collection.Maps["eo_admin"].Put(uint32(pidfd), nonce))
	for _, name := range []string{"eo_admin", "eo_task_ids", "eo_zero_task", "eo_work", "eo_anchor", "eo_birth_groups"} {
		require.NoError(t, collection.Maps[name].Freeze(), name)
	}
	require.ErrorIs(t, collection.Maps["eo_admin"].Put(uint32(pidfd), nonce+1), syscall.EPERM)
	var anchor [16]byte
	require.ErrorIs(t, collection.Maps["eo_anchor"].Lookup(uint32(0), &anchor), syscall.EPERM)
	gates, e = fullruntime.NewGateMap(collection.Maps["eo_gates"])
	require.NoError(t, e)
	slot, gate, e := gates.Allocate()
	require.NoError(t, e)
	path := fmt.Sprintf("/sys/fs/cgroup/ig-owner-control-%d", os.Getpid())
	require.NoError(t, os.Mkdir(path, 0o755))
	t.Cleanup(func() { os.Remove(path) })
	cg, e := os.Open(path)
	require.NoError(t, e)
	defer cg.Close()
	var stat syscall.Stat_t
	require.NoError(t, syscall.Fstat(int(cg.Fd()), &stat))
	helper := filepath.Join(tmp, "helper")
	require.NoError(t, os.WriteFile(helper+".c", []byte(inventoryHelper), 0o600))
	output, e = exec.Command("cc", "-pthread", "-O2", helper+".c", "-o", helper).CombinedOutput()
	require.NoError(t, e, string(output))
	process, input, lines := startInventoryHelper(t, helper, "normal", cg)
	proc, e := os.Open(fmt.Sprintf("/proc/%d", process.Process.Pid))
	require.NoError(t, e)
	defer proc.Close()
	start := rootProcStart(t, proc)
	require.NoError(t, collection.Maps["eo_configuration"].Put(uint32(0), ocConfig{nonce, stat.Ino, uint32(process.Process.Pid), 4096, slot, fullruntime.OwnerABI}))
	require.NoError(t, collection.Maps["eo_configuration"].Freeze())
	require.NoError(t, collection.Maps["eo_commands"].Put(uint32(0), ocCommand{Nonce: nonce, Operation: 1}))
	barrier := filepath.Join(path, "barrier")
	require.NoError(t, os.Mkdir(barrier, 0o755))
	t.Cleanup(func() { os.Remove(barrier) })
	health := func() ocHealth {
		var h ocHealth
		require.NoError(t, collection.Maps["eo_health"].Lookup(uint32(0), &h))
		return h
	}
	require.Equal(t, uint64(1), health().MovementArmed)
	command := func(operation uint32, generation, cookie uint64, mask uint32) ocHealth {
		require.NoError(t, collection.Maps["eo_commands"].Put(uint32(0), ocCommand{nonce, generation, cookie, operation, mask}))
		result, e := collection.Programs["eo_command"].Run(&ebpf.RunOptions{})
		require.NoError(t, e)
		h := health()
		require.Equal(t, result, h.Result)
		return h
	}
	inventory := command(1, 0, 0, 0)
	require.Zero(t, inventory.Result)
	require.Equal(t, uint32(4), inventory.Count)
	cookies := map[uint32]uint64{}
	for index := uint32(0); index < inventory.Count; index++ {
		var row ocRow
		require.NoError(t, collection.Maps["eo_rows"].Lookup(index, &row))
		cookies[row.TID] = row.Cookie
	}
	rootCookie := cookies[uint32(process.Process.Pid)]
	require.NotZero(t, rootCookie)
	lease, e := gate.BeginUpdate(context.Background())
	require.NoError(t, e)
	require.NotZero(t, command(2, 0, 0, 0).Result, "zero cookie must not authorize")
	require.Zero(t, command(2, 0, rootCookie, 0).Result)
	require.Equal(t, start, rootProcStart(t, proc))
	require.NoError(t, lease.Reopen())
	before := health()
	check := command(3, 0, 0, 0)
	require.Zero(t, check.Result)
	require.Equal(t, uint32(1), check.RootMatch)
	require.Equal(t, before.TaskCredits, check.TaskCredits)
	// Unauthorized callers cannot even overwrite the owner's status receipt.
	saved := health()
	require.NoError(t, collection.Maps["eo_commands"].Put(uint32(0), ocCommand{Nonce: nonce + 1, Operation: 11}))
	retval, e := collection.Programs["eo_command"].Run(&ebpf.RunOptions{})
	require.NoError(t, e)
	require.Equal(t, uint32(10), retval)
	require.Equal(t, saved, health())
	require.NoError(t, collection.Maps["eo_commands"].Put(uint32(0), ocCommand{Nonce: nonce, Operation: 11}))
	other := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		_, e := collection.Programs["eo_command"].Run(&ebpf.RunOptions{})
		other <- e
	}()
	require.NoError(t, <-other)
	require.Equal(t, saved, health())
	owner, e = fullruntime.NewProgramSlot(gate, collection.Maps["eo_programs"], collection.Maps["eo_epochs"])
	require.NoError(t, e)
	compile := func(generation uint64) *fullpolicy.KernelProgram {
		p, e := fullpolicy.CompileKernelWithRoleEpochs([]fullpolicy.Policy{{ID: "uid-root", Revision: "revision", Mode: fullpolicy.Enforce, RootRole: "root"}}, generation, "app", owner.Epochs())
		require.NoError(t, e)
		return p
	}
	candidate := compile(1)
	originalHeader := candidate.Entries[0]
	update, e := owner.Begin(context.Background(), candidate)
	require.NoError(t, e)
	image, e := update.Map()
	require.NoError(t, e)
	require.ErrorIs(t, image.Put(uint32(0), originalHeader), syscall.EPERM, "published candidate must be frozen")
	candidate.Entries[0][0] ^= 0xff
	var storedHeader fullpolicy.Blob
	require.NoError(t, image.Lookup(uint32(0), &storedHeader))
	require.Equal(t, originalHeader, storedHeader, "caller mutation must not change candidate snapshot")
	require.NotZero(t, command(5, 1, 0, 1).Result, "B without A")
	require.NotZero(t, command(10, 1, 0, 1).Result, "phase clear before commit")
	a := command(4, 1, 0, 1)
	require.Zero(t, a.Result)
	require.Equal(t, uint64(1), a.AComplete)
	b := command(5, 1, 0, 1)
	require.Zero(t, b.Result)
	require.Equal(t, uint64(1), b.Ready)
	for index := uint32(0); index < b.Count; index++ {
		var row ocRow
		require.NoError(t, collection.Maps["eo_rows"].Lookup(index, &row))
		require.Equal(t, uint32(1), row.ValidRoles)
	}
	require.Zero(t, command(7, 1, 0, 1).Result)
	committed, e := update.Commit()
	require.NoError(t, e)
	require.True(t, committed.Committed)
	require.NotZero(t, command(9, 1, 0, 1).Result, "cannot abort active slot after commit")
	require.Zero(t, command(8, 1, 0, 1).Result)
	require.Zero(t, command(6, 1, 0, 0).Result, "committed validation is active-only, no new root mask")
	require.Zero(t, command(10, 1, 0, 1).Result)
	require.NoError(t, update.Finish())
	require.NotZero(t, command(fullruntime.OwnerReattest, 1, 0, 0).Result, "read-only re-attestation requires drained admission")
	attestation, e := gate.BeginUpdate(context.Background())
	require.NoError(t, e)
	require.Zero(t, command(fullruntime.OwnerReattest, 1, 0, 0).Result, "active-only same-generation validation")
	require.NotZero(t, command(fullruntime.OwnerReattest, 2, 0, 0).Result, "cannot attest another generation")
	require.NoError(t, attestation.Reopen())
	require.Equal(t, uint64(1), owner.Generation())
	// Nonleader exec changes the selected physical cookie, not the pinned group.
	_, e = io.WriteString(input, "e")
	require.NoError(t, e)
	readInventoryLine(t, lines, "EXEC ")
	readInventoryLine(t, lines, "AFTER ")
	before = health()
	check = command(3, 0, 0, 0)
	require.Zero(t, check.Result)
	require.Equal(t, uint32(1), check.RootMatch)
	require.Equal(t, before.TaskCredits, check.TaskCredits)
	require.NotZero(t, command(3, 0, rootCookie, 0).Result, "old physical cookie must not silently reauthorize")
	require.Equal(t, start, rootProcStart(t, proc))
	// An unrelated pre-existing process in the same cgroup has no birth provenance.
	foreign, foreignInput, _ := startInventoryHelper(t, helper, "normal", cg)
	next, e := owner.Begin(context.Background(), compile(2))
	require.NoError(t, e)
	refused := command(4, 2, 0, 0)
	require.Equal(t, uint32(7), refused.Result)
	require.Zero(t, command(9, 2, 0, 0).Result)
	require.NoError(t, next.Abort())
	require.Equal(t, uint64(1), owner.Generation())
	_, e = io.WriteString(foreignInput, "q")
	require.NoError(t, e)
	require.NoError(t, foreign.Wait())
	_, e = io.WriteString(input, "q")
	require.NoError(t, e)
	require.NoError(t, process.Wait())
	retire, e := gate.BeginUpdate(context.Background())
	require.NoError(t, e)
	require.Zero(t, command(11, 0, 0, 0).Result)
	require.NoError(t, retire.Retire())
	require.NoError(t, proc.Close())
	require.Zero(t, health().RootCookie)
	require.Equal(t, uint32(1), health().Retired)
	t.Log("production command/root/group/phase proof only; exec and birth hooks were not attached")
}
