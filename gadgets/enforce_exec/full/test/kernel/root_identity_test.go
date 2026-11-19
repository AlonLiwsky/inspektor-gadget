// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type rootCommand struct {
	Nonce, Cookie, Cgroup uint64
	Operation, HostPID    uint32
}
type rootResult struct {
	Cookie        uint64
	Status, Match uint32
}

func TestRootIdentityKernel(t *testing.T) {
	if os.Getenv("IG_ROOT_IDENTITY_KERNEL_TEST") != "1" {
		t.Skip("disposable kernel opt-in required")
	}
	require.Zero(t, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tmp := t.TempDir()
	source := os.Getenv("IG_ROOT_IDENTITY_BPF_SOURCE")
	if source == "" {
		source = "bpf/root_identity.bpf.c"
	}
	header, e := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "vmlinux.h"), header, 0o600))
	object := filepath.Join(tmp, "root.bpf.o")
	out, e := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object).CombinedOutput()
	require.NoError(t, e, string(out))
	spec, e := ebpf.LoadCollectionSpec(object)
	require.NoError(t, e)
	collection, e := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 8 * 1024 * 1024}})
	if e != nil {
		t.Fatalf("root identity verifier: %+v", e)
	}
	defer collection.Close()
	var random [8]byte
	_, e = rand.Read(random[:])
	require.NoError(t, e)
	nonce := binary.LittleEndian.Uint64(random[:])
	require.NotZero(t, nonce)
	// PIDFD_THREAD is in the caller's namespace, not a host PID qualification.
	adminFD, e := unix.PidfdOpen(unix.Gettid(), 0x80)
	require.NoError(t, e)
	defer unix.Close(adminFD)
	require.NoError(t, collection.Maps["admin"].Put(uint32(adminFD), nonce))
	for _, name := range []string{"admin", "identities", "anchor"} {
		require.NoError(t, collection.Maps[name].Freeze())
	}
	require.ErrorIs(t, collection.Maps["admin"].Put(uint32(adminFD), nonce+1), syscall.EPERM)
	var opaque [16]byte
	require.ErrorIs(t, collection.Maps["anchor"].Lookup(uint32(0), &opaque), syscall.EPERM)
	path := fmt.Sprintf("/sys/fs/cgroup/ig-root-identity-%d", os.Getpid())
	require.NoError(t, os.Mkdir(path, 0o755))
	t.Cleanup(func() { os.Remove(path) })
	cg, e := os.Open(path)
	require.NoError(t, e)
	defer cg.Close()
	var st syscall.Stat_t
	require.NoError(t, syscall.Fstat(int(cg.Fd()), &st))
	invoke := func(op, pid uint32, cookie uint64) rootResult {
		require.NoError(t, collection.Maps["commands"].Put(uint32(0), rootCommand{nonce, cookie, st.Ino, op, pid}))
		_, e := collection.Programs["root_identity"].Run(&ebpf.RunOptions{})
		require.NoError(t, e)
		var r rootResult
		require.NoError(t, collection.Maps["results"].Lookup(uint32(0), &r))
		return r
	}
	helper := filepath.Join(tmp, "root-helper")
	require.NoError(t, os.WriteFile(helper+".c", []byte(rootIdentityHelper), 0o600))
	out, e = exec.Command("cc", "-pthread", "-O2", helper+".c", "-o", helper).CombinedOutput()
	require.NoError(t, e, string(out))
	process, input, lines := startInventoryHelper(t, helper, "normal", cg)
	pid := process.Process.Pid
	proc, e := os.Open(fmt.Sprintf("/proc/%d", pid))
	require.NoError(t, e)
	defer proc.Close()
	// The pinned inode retains this PID object; bookends never reopen by numeric PID.
	start := rootProcStart(t, proc)
	threads, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	require.NoError(t, e)
	require.NoError(t, collection.Maps["credit_limit"].Put(uint32(0), uint32(1)))
	firstIdentity := invoke(1, uint32(pid), 0)
	require.Zero(t, firstIdentity.Status)
	require.Equal(t, uint64(1), firstIdentity.Cookie)
	for _, entry := range threads {
		tid, e := strconv.Atoi(entry.Name())
		require.NoError(t, e)
		if tid != pid {
			require.Equal(t, uint32(7), invoke(1, uint32(tid), 0).Status)
			break
		}
	}
	require.Equal(t, firstIdentity.Cookie, invoke(1, uint32(pid), 0).Cookie, "exhaustion cannot replace an existing identity")
	require.NoError(t, collection.Maps["credit_limit"].Put(uint32(0), uint32(4096)))
	cookies := map[uint32]uint64{}
	for _, entry := range threads {
		tid, e := strconv.Atoi(entry.Name())
		require.NoError(t, e)
		r := invoke(1, uint32(tid), 0)
		require.Zero(t, r.Status)
		cookies[uint32(tid)] = r.Cookie
	}
	anchor := invoke(2, uint32(pid), cookies[uint32(pid)])
	require.Zero(t, anchor.Status)
	require.Equal(t, uint32(1), anchor.Match)
	require.Equal(t, start, rootProcStart(t, proc))
	for tid, cookie := range cookies {
		r := invoke(3, tid, cookie)
		require.Zero(t, r.Status)
		require.Equal(t, uint32(1), r.Match)
	}
	foreign, foreignInput, _ := startInventoryHelper(t, helper, "normal", cg)
	foreignCookie := invoke(1, uint32(foreign.Process.Pid), 0)
	require.Zero(t, foreignCookie.Status)
	require.Zero(t, invoke(3, uint32(foreign.Process.Pid), foreignCookie.Cookie).Match)
	require.NotZero(t, invoke(2, uint32(foreign.Process.Pid), foreignCookie.Cookie).Status)
	require.NotZero(t, invoke(2, uint32(pid), cookies[uint32(pid)]+999).Status)
	// A different thread lacks the frozen administrative nonce.
	require.NoError(t, collection.Maps["commands"].Put(uint32(0), rootCommand{nonce, 0, st.Ino, 4, 0}))
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		_, e := collection.Programs["root_identity"].Run(&ebpf.RunOptions{})
		done <- e
	}()
	require.NoError(t, <-done)
	var rejected rootResult
	require.NoError(t, collection.Maps["results"].Lookup(uint32(0), &rejected))
	require.Equal(t, uint32(1), rejected.Status)
	require.NoError(t, collection.Maps["commands"].Put(uint32(0), rootCommand{nonce + 1, 0, st.Ino, 4, 0}))
	_, e = collection.Programs["root_identity"].Run(&ebpf.RunOptions{})
	require.NoError(t, e)
	require.NoError(t, collection.Maps["results"].Lookup(uint32(0), &rejected))
	require.Equal(t, uint32(1), rejected.Status)
	_, e = io.WriteString(input, "e")
	require.NoError(t, e)
	line := readInventoryLine(t, lines, "EXEC ")
	tid, e := strconv.Atoi(strings.TrimPrefix(line, "EXEC "))
	require.NoError(t, e)
	readInventoryLine(t, lines, "AFTER ")
	survivor := invoke(1, uint32(pid), 0)
	require.Zero(t, survivor.Status)
	require.Equal(t, cookies[uint32(tid)], survivor.Cookie)
	require.NotEqual(t, cookies[uint32(pid)], survivor.Cookie)
	require.NotZero(t, invoke(3, uint32(pid), cookies[uint32(pid)]).Status)
	require.Equal(t, uint32(1), invoke(3, uint32(pid), survivor.Cookie).Match)
	require.Equal(t, start, rootProcStart(t, proc))
	_, e = io.WriteString(input, "q")
	require.NoError(t, e)
	require.NoError(t, process.Wait())
	require.Zero(t, invoke(4, 0, 0).Status)
	require.NoError(t, proc.Close()) // invalidate BEFORE dropping object pin
	require.Zero(t, invoke(3, uint32(foreign.Process.Pid), foreignCookie.Cookie).Match)
	_, e = io.WriteString(foreignInput, "q")
	require.NoError(t, e)
	require.NoError(t, foreign.Wait())
	// Anchor before leader exit, then check known physical members without relying
	// on /proc/PID/task enumeration after its original leader has died.
	leader, leaderInput, leaderLines := startInventoryHelper(t, helper, "normal", cg)
	leaderProc, e := os.Open(fmt.Sprintf("/proc/%d", leader.Process.Pid))
	require.NoError(t, e)
	defer leaderProc.Close()
	members, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", leader.Process.Pid))
	require.NoError(t, e)
	memberCookies := map[uint32]uint64{}
	for _, entry := range members {
		tid, e := strconv.Atoi(entry.Name())
		require.NoError(t, e)
		r := invoke(1, uint32(tid), 0)
		require.Zero(t, r.Status)
		memberCookies[uint32(tid)] = r.Cookie
	}
	require.Zero(t, invoke(2, uint32(leader.Process.Pid), memberCookies[uint32(leader.Process.Pid)]).Status)
	_, e = io.WriteString(leaderInput, "l")
	require.NoError(t, e)
	readInventoryLine(t, leaderLines, "LEADER_EXIT")
	require.Eventually(t, func() bool {
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", leader.Process.Pid))
		if e != nil {
			return false
		}
		end := strings.LastIndexByte(string(b), ')')
		return end >= 0 && strings.HasPrefix(string(b[end+1:]), " Z")
	}, time.Second, time.Millisecond)
	for tid, cookie := range memberCookies {
		if tid != uint32(leader.Process.Pid) {
			r := invoke(3, tid, cookie)
			require.Zero(t, r.Status)
			require.Equal(t, uint32(1), r.Match)
		}
	}
	require.Zero(t, invoke(4, 0, 0).Status)
	require.NoError(t, leaderProc.Close())
	_, e = io.WriteString(leaderInput, "q")
	require.NoError(t, e)
	require.NoError(t, leader.Wait())
	child := exec.Command(os.Args[0], "-test.run=^TestRootIdentityNamespaceAdmin$", "-test.v", "-test.timeout=15s")
	child.Env = append(os.Environ(), "IG_ROOT_IDENTITY_NAMESPACE_CHILD="+object)
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWPID}
	output, e := child.CombinedOutput()
	require.NoError(t, e, string(output))
	t.Log(string(output))
}

func rootProcStart(t *testing.T, proc *os.File) string {
	t.Helper()
	fd, e := unix.Openat(int(proc.Fd()), "stat", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	require.NoError(t, e)
	f := os.NewFile(uintptr(fd), "pinned-stat")
	defer f.Close()
	b, e := io.ReadAll(f)
	require.NoError(t, e)
	end := strings.LastIndexByte(string(b), ')')
	require.Greater(t, end, 0)
	fields := strings.Fields(string(b[end+1:]))
	require.Greater(t, len(fields), 19)
	return fields[19]
}

var rootIdentityHelper = strings.NewReplacer(
	"static atomic_int ready;", "static atomic_int ready; static atomic_int leader_exit;",
	"if(c=='e')", "if(c=='l'){atomic_store(&leader_exit,1);continue;}if(c=='e')",
	"for(;;)pause();\n}", "while(!atomic_load(&leader_exit)){usleep(1000);}puts(\"LEADER_EXIT\");pthread_exit(NULL);\n}",
).Replace(inventoryHelper)

// This subprocess creates only a private PID namespace, never writes ns_last_pid.
func TestRootIdentityNamespaceAdmin(t *testing.T) {
	object := os.Getenv("IG_ROOT_IDENTITY_NAMESPACE_CHILD")
	if object == "" {
		t.Skip("internal namespace fixture")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	require.Equal(t, 1, os.Getpid())
	status, e := os.ReadFile("/proc/self/status")
	require.NoError(t, e)
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			require.GreaterOrEqual(t, len(strings.Fields(line)), 3)
			found = true
		}
	}
	require.True(t, found)
	spec, e := ebpf.LoadCollectionSpec(object)
	require.NoError(t, e)
	collection, e := ebpf.NewCollection(spec)
	require.NoError(t, e)
	defer collection.Close()
	pidfd, e := unix.PidfdOpen(unix.Gettid(), 0x80)
	require.NoError(t, e)
	defer unix.Close(pidfd)
	nonce := uint64(0x19ab37841)
	require.NoError(t, collection.Maps["admin"].Put(uint32(pidfd), nonce))
	for _, name := range []string{"admin", "identities", "anchor"} {
		require.NoError(t, collection.Maps[name].Freeze())
	}
	for _, value := range []uint64{nonce, nonce + 1} {
		require.NoError(t, collection.Maps["commands"].Put(uint32(0), rootCommand{Nonce: value, Operation: 4}))
		_, e := collection.Programs["root_identity"].Run(&ebpf.RunOptions{})
		require.NoError(t, e)
		var result rootResult
		require.NoError(t, collection.Maps["results"].Lookup(uint32(0), &result))
		if value == nonce {
			require.Zero(t, result.Status)
		} else {
			require.Equal(t, uint32(1), result.Status)
		}
	}
}
