// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bufio"
	"errors"
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
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type inventoryConfig struct {
	Cgroup, Epoch   uint64
	OwnerPID, Limit uint32
}
type inventoryResult struct {
	Credits, Epoch uint64
	Count, Status  uint32
	Busy           uint64
}
type (
	movementControl struct{ OwnerTID, Arm, Hold, Release uint32 }
	movementState   struct{ Sequence, Armed, Fault, Reached uint64 }
)

type inventoryRow struct {
	Cookie    uint64
	TID, TGID uint32
}

func TestInventoryKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_INVENTORY_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel opt-in required")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	tmp := t.TempDir()
	source := os.Getenv("IG_EXEC_INVENTORY_BPF_SOURCE")
	if source == "" {
		source = "bpf/inventory.bpf.c"
	}
	header, err := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "vmlinux.h"), header, 0o600))
	object := filepath.Join(tmp, "inventory.bpf.o")
	out, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object).CombinedOutput()
	require.NoError(t, err, string(out))
	base, err := ebpf.LoadCollectionSpec(object)
	require.NoError(t, err)
	var collection *ebpf.Collection
	var attached link.Link
	selected := ""
	for _, name := range []string{"inventory_syscall", "inventory_trace"} {
		spec := base.Copy()
		for other := range spec.Programs {
			if other != name && strings.HasPrefix(other, "inventory_") {
				delete(spec.Programs, other)
			}
		}
		candidate, e := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 8 * 1024 * 1024}})
		if e != nil {
			var verifier *ebpf.VerifierError
			if errors.As(e, &verifier) {
				t.Logf("%s verifier: %+v", name, verifier)
			}
			t.Logf("%s unavailable: %v", name, e)
			continue
		}
		// Local-storage creation rejects BPF_F_RDONLY. Seal UAPI mutation before
		// any attachment or test_run; kernel helper writes must still work.
		if e = candidate.Maps["identities"].Freeze(); e != nil {
			candidate.Close()
			t.Fatalf("freeze kernel-owned task identities: %v", e)
		}
		if name == "inventory_trace" {
			attached, e = link.AttachTracing(link.TracingOptions{Program: candidate.Programs[name]})
			if e != nil {
				candidate.Close()
				t.Logf("tracing attach unavailable: %v", e)
				continue
			}
		}
		collection = candidate
		selected = name
		break
	}
	require.NotNil(t, collection, "neither explicit syscall nor narrowly-triggered tracing inventory ABI loaded")
	defer collection.Close()
	if attached != nil {
		defer attached.Close()
	}
	t.Logf("selected ABI %s", selected)
	cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-inventory-%d", os.Getpid())
	require.NoError(t, os.Mkdir(cgpath, 0o755))
	t.Cleanup(func() { os.Remove(cgpath) })
	cg, err := os.Open(cgpath)
	require.NoError(t, err)
	defer cg.Close()
	var st syscall.Stat_t
	helper := filepath.Join(tmp, "inventory-helper")
	require.NoError(t, os.WriteFile(helper+".c", []byte(inventoryHelper), 0o600))
	out, err = exec.Command("cc", "-O2", "-pthread", helper+".c", "-o", helper).CombinedOutput()
	require.NoError(t, err, string(out))
	oldSource, oldDestination, barrier := filepath.Join(cgpath, "old-source"), filepath.Join(cgpath, "old-destination"), filepath.Join(cgpath, "barrier")
	for _, path := range []string{oldSource, oldDestination} {
		require.NoError(t, os.Mkdir(path, 0o755))
		t.Cleanup(func() { os.Remove(path) })
	}
	availableCPUs, e := os.ReadFile(filepath.Join(cgpath, "cgroup.controllers"))
	require.NoError(t, e)
	require.Contains(t, strings.Fields(string(availableCPUs)), "cpuset", "initial drain requires delegated cpuset; no root controller writes")
	require.NoError(t, os.WriteFile(filepath.Join(cgpath, "cgroup.subtree_control"), []byte("+cpuset"), 0o600))
	allowedCPUs, e := os.ReadFile(filepath.Join(cgpath, "cpuset.cpus.effective"))
	require.NoError(t, e)
	firstCPU := strings.Split(strings.Split(strings.TrimSpace(string(allowedCPUs)), ",")[0], "-")[0]
	require.NotEqual(t, firstCPU, strings.TrimSpace(string(allowedCPUs)), "distinct CPU masks require at least two effective CPUs")
	require.NoError(t, os.WriteFile(filepath.Join(oldDestination, "cpuset.cpus"), []byte(firstCPU), 0o600))
	oldFD, err := os.Open(oldSource)
	require.NoError(t, err)
	defer oldFD.Close()
	oldProcess, oldInput, _ := startInventoryHelper(t, helper, "normal", oldFD)
	holdLink, e := link.AttachLSM(link.LSMOptions{Program: collection.Programs["drain_hold"]})
	require.NoError(t, e)
	defer holdLink.Close()
	type drainControl struct{ WriterTID, Release, TargetTGID, Padding uint32 }
	type drainState struct{ Reached, Expired, BarrierAttempt uint64 }
	readDrain := func() drainState {
		var state drainState
		require.NoError(t, collection.Maps["drain_state"].Lookup(uint32(0), &state))
		return state
	}

	writerDone := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		e := collection.Maps["drain_control"].Put(uint32(0), drainControl{WriterTID: uint32(unix.Gettid()), TargetTGID: uint32(oldProcess.Process.Pid)})
		if e == nil {
			e = os.WriteFile(filepath.Join(oldDestination, "cgroup.procs"), []byte(strconv.Itoa(oldProcess.Process.Pid)), 0o600)
		}
		writerDone <- e
	}()
	require.Eventually(t, func() bool { return readDrain().Reached == 1 }, time.Second, time.Millisecond)
	// The outer migration entered before these links existed. Hold target differs
	// from every updated trampoline; no attachment waits for its own held program.
	for _, hook := range []string{"migrate_enter", "migrate_exit", "reconfigure_enter", "reconfigure_exit", "movement_arm", "drain_barrier_entry"} {
		l, e := link.AttachTracing(link.TracingOptions{Program: collection.Programs[hook]})
		require.NoError(t, e, hook)
		defer l.Close()
	}
	barrierDone := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		e := collection.Maps["movement_control"].Put(uint32(0), movementControl{OwnerTID: uint32(unix.Gettid()), Arm: 1})
		if e == nil {
			e = os.Mkdir(barrier, 0o755)
		}
		barrierDone <- e
	}()
	t.Cleanup(func() { os.Remove(barrier) })
	require.Eventually(t, func() bool { return readDrain().BarrierAttempt == 1 }, time.Second, time.Millisecond)
	var armed movementState
	require.NoError(t, collection.Maps["movement_state"].Lookup(uint32(0), &armed))
	require.Zero(t, armed.Armed, "barrier must wait behind old migration mutex")
	require.Zero(t, readDrain().Expired, "bounded old-migration hold expired before barrier proof")
	require.NoError(t, collection.Maps["drain_control"].Put(uint32(0), drainControl{Release: 1}))
	require.NoError(t, <-writerDone)
	require.NoError(t, <-barrierDone)
	require.Zero(t, readDrain().Expired)
	require.NoError(t, collection.Maps["movement_state"].Lookup(uint32(0), &armed))
	require.Equal(t, uint64(1), armed.Armed)
	require.Zero(t, armed.Fault)
	require.Zero(t, armed.Sequence)
	require.NoError(t, syscall.Stat(oldDestination, &st))
	denyLink, e := link.AttachLSM(link.LSMOptions{Program: collection.Programs["deny_fixture_attach"]})
	require.NoError(t, e)
	defer denyLink.Close()
	epoch := uint64(0)
	run := func(limit uint32) (inventoryResult, map[uint32]uint64) {
		t.Helper()
		epoch++
		require.NoError(t, collection.Maps["configuration"].Put(uint32(0), inventoryConfig{st.Ino, epoch, uint32(os.Getpid()), limit}))
		if selected == "inventory_syscall" {
			_, e := collection.Programs[selected].Run(&ebpf.RunOptions{})
			require.NoError(t, e)
		} else {
			_, _, e := unix.Syscall(unix.SYS_GETPGID, 0, 0, 0)
			require.Equal(t, unix.Errno(0), e)
		}
		var result inventoryResult
		require.NoError(t, collection.Maps["results"].Lookup(uint32(0), &result))
		require.Equal(t, epoch, result.Epoch)
		require.Zero(t, result.Busy)
		require.LessOrEqual(t, result.Count, uint32(4096))
		identities := map[uint32]uint64{}
		cookies := map[uint64]bool{}
		for i := uint32(0); i < result.Count; i++ {
			var row inventoryRow
			require.NoError(t, collection.Maps["rows"].Lookup(i, &row))
			require.NotZero(t, row.Cookie)
			require.False(t, cookies[row.Cookie], "duplicate physical-task cookie")
			cookies[row.Cookie] = true
			identities[row.TID] = row.Cookie
		}
		return result, identities
	}
	initial, oldIDs := run(4096)
	require.Zero(t, initial.Status)
	require.Len(t, oldIDs, 4, "old migration completed into destination before barrier armed")
	_, err = io.WriteString(oldInput, "q")
	require.NoError(t, err)
	require.NoError(t, oldProcess.Wait())
	require.NoError(t, syscall.Fstat(int(cg.Fd()), &st))
	require.NoError(t, os.WriteFile(filepath.Join(cgpath, "cgroup.subtree_control"), []byte("-cpuset"), 0o600))
	t.Log("forced pre-attachment migration mutex drain passed")
	t.Run("migration-and-controller-change", func(t *testing.T) {
		left, right := filepath.Join(cgpath, "left"), filepath.Join(cgpath, "right")
		require.NoError(t, os.Mkdir(left, 0o755))
		t.Cleanup(func() { os.Remove(left) })
		require.NoError(t, os.Mkdir(right, 0o755))
		t.Cleanup(func() { os.Remove(right) })
		lf, e := os.Open(left)
		require.NoError(t, e)
		defer lf.Close()
		process, input, _ := startInventoryHelper(t, helper, "normal", lf)
		move := func(path string) {
			require.NoError(t, os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(process.Process.Pid)), 0o600))
		}
		state := func() movementState {
			var v movementState
			require.NoError(t, collection.Maps["movement_state"].Lookup(uint32(0), &v))
			require.Zero(t, v.Fault)
			return v
		}
		before := state()
		move(right)
		after := state()
		require.Greater(t, after.Sequence, before.Sequence)
		require.Zero(t, after.Sequence&1)
		// Enable only a controller already delegated to this owned subtree.
		available, e := os.ReadFile(filepath.Join(cgpath, "cgroup.controllers"))
		require.NoError(t, e)
		controller := ""
		for _, v := range strings.Fields(string(available)) {
			if v == "pids" || v == "memory" {
				controller = v
				break
			}
		}
		require.NotEmpty(t, controller, "fixture needs pids or memory delegated to its parent; never changes host-root controllers")
		var old syscall.Stat_t
		require.NoError(t, syscall.Stat(right, &old))
		before = state()
		require.NoError(t, os.WriteFile(filepath.Join(cgpath, "cgroup.subtree_control"), []byte("+"+controller), 0o600))
		after = state()
		require.Greater(t, after.Sequence, before.Sequence)
		var current syscall.Stat_t
		require.NoError(t, syscall.Stat(right, &current))
		require.Equal(t, old.Ino, current.Ino)
		// Hold an iterator after its first physical task, then migrate that cgroup.
		require.NoError(t, syscall.Fstat(int(lf.Fd()), &st))
		move(left)
		require.NoError(t, collection.Maps["movement_control"].Put(uint32(0), movementControl{Hold: 1}))
		epoch++
		require.NoError(t, collection.Maps["configuration"].Put(uint32(0), inventoryConfig{st.Ino, epoch, uint32(os.Getpid()), 4096}))
		done := make(chan error, 1)
		go func() {
			if selected == "inventory_syscall" {
				_, e := collection.Programs[selected].Run(&ebpf.RunOptions{})
				done <- e
			} else {
				_, _, e := unix.Syscall(unix.SYS_GETPGID, 0, 0, 0)
				if e != 0 {
					done <- e
				} else {
					done <- nil
				}
			}
		}()
		require.Eventually(t, func() bool { return state().Reached == 1 }, time.Second, time.Millisecond)
		move(right)
		require.NoError(t, collection.Maps["movement_control"].Put(uint32(0), movementControl{Release: 1}))
		require.NoError(t, <-done)
		var unstable inventoryResult
		require.NoError(t, collection.Maps["results"].Lookup(uint32(0), &unstable))
		require.Equal(t, uint32(6), unstable.Status)
		move(left)
		stable, _ := run(4096)
		require.Zero(t, stable.Status)
		_, e = io.WriteString(input, "q")
		require.NoError(t, e)
		require.NoError(t, process.Wait())
		require.NoError(t, os.WriteFile(filepath.Join(cgpath, "cgroup.subtree_control"), []byte("-"+controller), 0o600))
		require.NoError(t, syscall.Fstat(int(cg.Fd()), &st))
	})
	t.Run("failed-staged-migration", func(t *testing.T) {
		available, e := os.ReadFile(filepath.Join(cgpath, "cgroup.controllers"))
		require.NoError(t, e)
		require.Contains(t, strings.Fields(string(available)), "cpuset", "cpuset must already be delegated; no host-root writes")
		require.NoError(t, os.WriteFile(filepath.Join(cgpath, "cgroup.subtree_control"), []byte("+cpuset"), 0o600))
		t.Cleanup(func() { os.WriteFile(filepath.Join(cgpath, "cgroup.subtree_control"), []byte("-cpuset"), 0o600) })
		allowed, e := os.ReadFile(filepath.Join(cgpath, "cpuset.cpus.effective"))
		require.NoError(t, e)
		first := strings.Split(strings.Split(strings.TrimSpace(string(allowed)), ",")[0], "-")[0]
		require.NotEqual(t, first, strings.TrimSpace(string(allowed)), "two or more effective CPUs required for distinct safe masks")
		src, dst := filepath.Join(cgpath, "failed-source"), filepath.Join(cgpath, "failed-destination")
		require.NoError(t, os.Mkdir(src, 0o755))
		t.Cleanup(func() { os.Remove(src) })
		require.NoError(t, os.Mkdir(dst, 0o755))
		t.Cleanup(func() { os.Remove(dst) })
		require.NoError(t, os.WriteFile(filepath.Join(dst, "cpuset.cpus"), []byte(first), 0o600))
		source, e := os.Open(src)
		require.NoError(t, e)
		defer source.Close()
		process, input, _ := startInventoryHelper(t, helper, "normal", source)
		require.NoError(t, syscall.Fstat(int(source.Fd()), &st))
		before, ids := run(4096)
		require.Zero(t, before.Status)
		leaderCookie := ids[uint32(process.Process.Pid)]
		require.NotZero(t, leaderCookie)
		var old movementState
		require.NoError(t, collection.Maps["movement_state"].Lookup(uint32(0), &old))
		runtime.LockOSThread()
		control := struct {
			OwnerTID, TargetTGID uint32
			Cookie               uint64
		}{uint32(unix.Gettid()), uint32(process.Process.Pid), leaderCookie}
		require.NoError(t, collection.Maps["deny_config"].Put(uint32(0), control))
		e = os.WriteFile(filepath.Join(dst, "cgroup.procs"), []byte(strconv.Itoa(process.Process.Pid)), 0o600)
		runtime.UnlockOSThread()
		require.ErrorIs(t, e, syscall.EPERM)
		control.Cookie = 0
		require.NoError(t, collection.Maps["deny_config"].Put(uint32(0), control))
		var denied uint64
		require.NoError(t, collection.Maps["denied"].Lookup(uint32(0), &denied))
		require.Equal(t, uint64(1), denied)
		var after movementState
		require.NoError(t, collection.Maps["movement_state"].Lookup(uint32(0), &after))
		require.Zero(t, after.Fault)
		require.Zero(t, after.Sequence&1)
		require.Greater(t, after.Sequence, old.Sequence)
		stable, remaining := run(4096)
		require.Zero(t, stable.Status)
		require.Equal(t, ids, remaining, "failed can_attach cleanup preserves all physical identities in source")
		require.NoError(t, os.WriteFile(filepath.Join(dst, "cgroup.procs"), []byte(strconv.Itoa(process.Process.Pid)), 0o600))
		_, e = io.WriteString(input, "q")
		require.NoError(t, e)
		require.NoError(t, process.Wait())
		require.NoError(t, syscall.Fstat(int(cg.Fd()), &st))
	})
	t.Run("all-threads-and-exec-identity", func(t *testing.T) {
		process, input, lines := startInventoryHelper(t, helper, "normal", cg)
		first, ids := run(4096)
		require.Zero(t, first.Status)
		require.Len(t, ids, 4)
		again, repeated := run(4096)
		require.Zero(t, again.Status)
		require.Equal(t, first.Credits, again.Credits)
		require.Equal(t, ids, repeated)
		// TASK_STORAGE identity is kernel-owned, not a userspace root grant.
		pidfd, e := unix.PidfdOpen(process.Process.Pid, 0x80) // PIDFD_THREAD, Linux UAPI
		require.NoError(t, e)
		require.ErrorIs(t, collection.Maps["identities"].Put(uint32(pidfd), uint64(99)), syscall.EPERM)
		require.ErrorIs(t, collection.Maps["identities"].Delete(uint32(pidfd)), syscall.EPERM)
		require.NoError(t, unix.Close(pidfd))
		_, e = io.WriteString(input, "e")
		require.NoError(t, e)
		before := readInventoryLine(t, lines, "EXEC ")
		tid, e := strconv.Atoi(strings.TrimPrefix(before, "EXEC "))
		require.NoError(t, e)
		cookie := ids[uint32(tid)]
		require.NotZero(t, cookie)
		readInventoryLine(t, lines, "AFTER ")
		after, execIDs := run(4096)
		require.Zero(t, after.Status)
		require.Len(t, execIDs, 1)
		require.Equal(t, cookie, execIDs[uint32(process.Process.Pid)], "surviving physical task keeps cookie across de_thread PID exchange")
		require.Equal(t, first.Credits, after.Credits)
		_, e = io.WriteString(input, "q")
		require.NoError(t, e)
		require.NoError(t, process.Wait())
	})
	t.Run("leader-death-and-lifetime-budget", func(t *testing.T) {
		process, input, lines := startInventoryHelper(t, helper, "leaderdeath", cg)
		readInventoryLine(t, lines, "LEADER_EXIT")
		// Wait for leader to become a zombie, not merely for its announcement.
		require.Eventually(t, func() bool {
			b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", process.Process.Pid))
			if e != nil {
				return false
			}
			end := strings.LastIndexByte(string(b), ')')
			return end >= 0 && strings.HasPrefix(string(b[end+1:]), " Z")
		}, 3*time.Second, 10*time.Millisecond)
		result, ids := run(4096)
		require.Zero(t, result.Status)
		require.Len(t, ids, 3, "live threads remain visible without their leader")
		require.Greater(t, result.Credits, uint64(4), "exited tasks never return lifetime identity credits")
		_, e := io.WriteString(input, "q")
		require.NoError(t, e)
		require.NoError(t, process.Wait())
		next, nextInput, _ := startInventoryHelper(t, helper, "normal", cg)
		limited, _ := run(uint32(result.Credits))
		require.Equal(t, uint32(4), limited.Status, "new identity beyond lifetime budget must report incomplete")
		require.Equal(t, result.Credits, limited.Credits)
		_, e = io.WriteString(nextInput, "q")
		require.NoError(t, e)
		require.NoError(t, next.Wait())
	})
}

func startInventoryHelper(t *testing.T, path, mode string, cgroup *os.File) (*exec.Cmd, io.WriteCloser, <-chan string) {
	t.Helper()
	command := exec.Command(path, mode)
	command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	input, err := command.StdinPipe()
	require.NoError(t, err)
	output, err := command.StdoutPipe()
	require.NoError(t, err)
	command.Stderr = os.Stderr
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		input.Close()
		if command.ProcessState == nil {
			command.Process.Kill()
			command.Wait()
		}
	})
	lines := make(chan string, 16)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	readInventoryLine(t, lines, "READY")
	return command, input, lines
}

func readInventoryLine(t *testing.T, lines <-chan string, prefix string) string {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-lines:
			require.True(t, ok, "helper closed output")
			if strings.HasPrefix(line, prefix) {
				return line
			}
		case <-timer.C:
			t.Fatalf("helper timeout waiting for %q", prefix)
		}
	}
}

const inventoryHelper = `
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
static atomic_int ready;
static char *self;
static void *worker(void *index) {
 atomic_fetch_add(&ready,1);
 if((long)index)for(;;)pause();
 for(;;){int c=getchar();if(c=='q'||c==EOF)_exit(0);if(c=='e'){printf("EXEC %ld\n",syscall(SYS_gettid));execl(self,self,"after",NULL);_exit(99);}}
}
int main(int argc,char **argv){
 self=argv[0];setvbuf(stdout,NULL,_IOLBF,0);
 if(argc>1&&!strcmp(argv[1],"after")){printf("AFTER %ld\n",syscall(SYS_gettid));for(;;)if(getchar()=='q')return 0;}
 pthread_t threads[3];for(long i=0;i<3;i++)if(pthread_create(&threads[i],NULL,worker,(void*)i))return 98;
 while(atomic_load(&ready)!=3)usleep(1000);
 puts("READY");
 if(argc>1&&!strcmp(argv[1],"leaderdeath")){puts("LEADER_EXIT");pthread_exit(NULL);}
 for(;;)pause();
}
`
