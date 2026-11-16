// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
)

const ownerExecHelper = `
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static int run(const char *path,const char *arg){
 pid_t pid=fork();if(pid<0)return 90;
 if(!pid){execl(path,path,arg,(char*)0);_exit(errno==EPERM?77:78);}
 int status;if(waitpid(pid,&status,0)!=pid)return 91;
 return WIFEXITED(status)?WEXITSTATUS(status):92;
}
int main(int argc,char**argv){
 setbuf(stdout,0);
 if(argc>1&&!strcmp(argv[1],"stage"))return run(OWNER_WORKER_TARGET,0);
 puts("READY");char cmd;
 while(read(0,&cmd,1)==1){
  if(cmd=='q')return 0;
  int result=cmd=='s'?run(argv[0],"stage"):run(cmd=='t'?OWNER_WORKER_TARGET:"/usr/bin/false",0);
  printf("RESULT %d\n",result);
 }
 return 0;
}
`

// This attaches the actual assembled owner profile, uses the qualified native
// worker and Publisher, and exercises root/child/exec roles across reload. It is
// NOT the OCI operator lifecycle, containerd/CRI lease or aggregate budget proof.
func TestFullOwnerImageKernel(t *testing.T) {
	if os.Getenv("IG_FULL_OWNER_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel opt-in required")
	}
	require.Zero(t, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tmp := t.TempDir()
	source := os.Getenv("IG_FULL_OWNER_BPF_SOURCE")
	require.NotEmpty(t, source)
	root := os.Getenv("IG_FULL_OWNER_REPO")
	require.NotEmpty(t, root)
	header, e := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "vmlinux.h"), header, 0o600))
	obj := filepath.Join(tmp, "owner.o")
	out, e := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-DENFORCE_EXEC_PERSISTENT_OWNER", "-Wno-missing-declarations", "-I"+tmp, "-I"+filepath.Join(root, "include"), "-I"+filepath.Join(root, "gadgets/enforce_exec/fullpolicy/bpf"), "-c", source, "-o", obj).CombinedOutput()
	require.NoError(t, e, string(out))
	spec, e := ebpf.LoadCollectionSpec(obj)
	require.NoError(t, e)
	verifyOnly := os.Getenv("IG_FULL_OWNER_VERIFY_ONLY")
	if verifyOnly != "" {
		require.NotNil(t, spec.Programs[verifyOnly])
		for name := range spec.Programs {
			if name != verifyOnly {
				delete(spec.Programs, name)
			}
		}
	}
	options := ebpf.ProgramOptions{LogSizeStart: 16 * 1024 * 1024}
	if verifyOnly != "" {
		options.LogSizeStart = 64 * 1024 * 1024
		options.LogLevel = ebpf.LogLevelInstruction | ebpf.LogLevelStats
	}
	collection, e := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: options})
	if e != nil {
		var verifier *ebpf.VerifierError
		if errors.As(e, &verifier) {
			if path := os.Getenv("IG_FULL_OWNER_VERIFIER_LOG"); path != "" {
				require.NoError(t, os.WriteFile(path, []byte(strings.Join(verifier.Log, "\n")), 0o600))
			}
			t.Fatalf("assembled owner verifier: %v\n%-80v", e, verifier)
		}
		t.Fatalf("assembled owner verifier: %+v", e)
	}
	if verifyOnly != "" {
		collection.Close()
		t.Logf("diagnostic verifier-only %s; NO assembled lifecycle proof", verifyOnly)
		return
	}
	var links []link.Link
	var gates *fullruntime.GateMap
	var slot *fullruntime.ProgramSlot
	var control *fullruntime.OwnerControl
	var publisher *fullruntime.Publisher
	var proc, cg *os.File
	var process *exec.Cmd
	var cgpath string
	// Test-only emergency cleanup first detaches every hook, joins commands, then
	// releases maps/pins. Production must use the successful pre-Stop drain path.
	defer func() {
		for _, l := range links {
			require.NoError(t, l.Close())
		}
		if control != nil {
			require.NoError(t, control.Close())
		}
		if slot != nil {
			require.NoError(t, slot.CloseAfterDetach())
		}
		if gates != nil {
			require.NoError(t, gates.Close())
		}
		collection.Close()
		if process != nil && process.Process != nil {
			process.Process.Kill()
			process.Wait()
		}
		if proc != nil {
			proc.Close()
		}
		if cg != nil {
			cg.Close()
		}
		if cgpath != "" {
			os.Remove(cgpath)
		}
	}()
	for name, program := range collection.Programs {
		if program.Type() == ebpf.Syscall {
			continue
		}
		var l link.Link
		if program.Type() == ebpf.LSM {
			l, e = link.AttachLSM(link.LSMOptions{Program: program})
		} else {
			l, e = link.AttachTracing(link.TracingOptions{Program: program})
		}
		require.NoError(t, e, name)
		links = append(links, l)
	}
	require.NoError(t, collection.Maps["image_origins"].Freeze())
	require.NoError(t, collection.Maps["image_ready"].Freeze())
	require.NoError(t, collection.Maps["zero_observation"].Freeze())
	gates, e = fullruntime.NewGateMap(collection.Maps["eo_gates"])
	require.NoError(t, e)
	index, gate, e := gates.Allocate()
	require.NoError(t, e)
	slot, e = fullruntime.NewProgramSlot(gate, collection.Maps["eo_programs"], collection.Maps["eo_epochs"])
	require.NoError(t, e)
	cgpath = fmt.Sprintf("/sys/fs/cgroup/ig-full-owner-%d", os.Getpid())
	require.NoError(t, os.Mkdir(cgpath, 0o755))
	cg, e = os.Open(cgpath)
	require.NoError(t, e)
	var cgstat syscall.Stat_t
	require.NoError(t, syscall.Fstat(int(cg.Fd()), &cgstat))
	helper := filepath.Join(tmp, "owner-helper")
	workerTarget := filepath.Join(tmp, "worker-target")
	require.NoError(t, os.WriteFile(workerTarget+".c", []byte("int main(void){return 0;}"), 0o600))
	out, e = exec.Command("cc", "-O2", workerTarget+".c", "-o", workerTarget).CombinedOutput()
	require.NoError(t, e, string(out))
	require.NoError(t, os.WriteFile(helper+".c", []byte("#define OWNER_WORKER_TARGET "+strconv.Quote(workerTarget)+"\n"+ownerExecHelper), 0o600))
	out, e = exec.Command("cc", "-O2", helper+".c", "-o", helper).CombinedOutput()
	require.NoError(t, e, string(out))
	process = exec.CommandContext(ctx, helper)
	process.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	input, e := process.StdinPipe()
	require.NoError(t, e)
	output, e := process.StdoutPipe()
	require.NoError(t, e)
	require.NoError(t, process.Start())
	scanner := bufio.NewScanner(output)
	require.True(t, scanner.Scan())
	require.Equal(t, "READY", scanner.Text())
	proc, e = os.Open(fmt.Sprintf("/proc/%d", process.Process.Pid))
	require.NoError(t, e)
	start := rootProcStart(t, proc)
	var failAfterGeneration uint64
	verify := func(context.Context) error {
		if failAfterGeneration != 0 && slot.Generation() == failAfterGeneration {
			return fmt.Errorf("injected temporary native lease-verification failure")
		}
		if rootProcStart(t, proc) != start {
			return fmt.Errorf("trusted init changed")
		}
		return nil
	}
	compileUID := func(gen uint64, rootRole, uid string) *fullpolicy.KernelProgram {
		paths := []string{helper}
		for i := 0; i < 12; i++ {
			paths = append(paths, fmt.Sprintf("/unmatched/path/%d", i))
		}
		program, e := fullpolicy.CompileKernelWithRoleEpochs([]fullpolicy.Policy{{ID: uid, Revision: fmt.Sprint(gen), Mode: fullpolicy.Enforce, RootRole: rootRole, Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{
			{Name: "stage", Action: fullpolicy.Allow, Actor: fullpolicy.Actor{Role: []string{"agent"}}, Target: fullpolicy.Target{Path: paths, SetRole: "worker"}},
			{Name: "worker", Action: fullpolicy.Allow, Actor: fullpolicy.Actor{Role: []string{"worker"}}, Target: fullpolicy.Target{Path: []string{workerTarget}}},
		}}}, gen, "app", slot.Epochs())
		require.NoError(t, e)
		return program
	}
	compile := func(gen uint64, rootRole string) *fullpolicy.KernelProgram { return compileUID(gen, rootRole, "uid") }
	prepared, e := slot.Begin(ctx, compile(1, "agent"))
	require.NoError(t, e)
	control, e = fullruntime.NewOwnerControl(ctx, fullruntime.ControlConfig{Cookie: 0x91352abc, Cgroup: cgstat.Ino, InitHostPID: uint32(process.Process.Pid), TaskLimit: 4096, GateSlot: index, ABI: fullruntime.OwnerABI}, fullruntime.ControlResources{
		TaskIDs: collection.Maps["eo_task_ids"], ZeroTask: collection.Maps["eo_zero_task"], Configuration: collection.Maps["eo_configuration"], Commands: collection.Maps["eo_commands"], Health: collection.Maps["eo_health"], Phase: collection.Maps["eo_phase"], Rows: collection.Maps["eo_rows"], Admin: collection.Maps["eo_admin"], Tasks: collection.Maps["eo_tasks"], Work: collection.Maps["eo_work"], Anchor: collection.Maps["eo_anchor"], Births: collection.Maps["eo_birth_groups"], GenerationFaults: collection.Maps["eo_generation_faults"], Program: collection.Programs["eo_command"],
	}, gate)
	require.NoError(t, e)
	require.NoError(t, control.ArmMovement(ctx, cgpath), "actual nonmutating negative-PID mutex barrier")
	inventory, e := control.Call(ctx, fullruntime.ControlCommand{Operation: fullruntime.OwnerInventory})
	require.NoError(t, e)
	rows, e := control.Rows(inventory.Count)
	require.NoError(t, e)
	var cookie uint64
	for _, row := range rows {
		if row.TID == uint32(process.Process.Pid) {
			cookie = row.Cookie
		}
	}
	require.NotZero(t, cookie)
	// Prove both identity publication and spin-locked state are UAPI sealed. A
	// missing/faulted accepted state must not be repaired by native row seeding.
	pidfd, err := unix.PidfdOpen(process.Process.Pid, 0)
	require.NoError(t, err)
	require.ErrorIs(t, collection.Maps["eo_task_ids"].Put(uint32(pidfd), cookie+1), syscall.EPERM)
	require.ErrorIs(t, collection.Maps["eo_task_ids"].Delete(uint32(pidfd)), syscall.EPERM)
	require.NoError(t, unix.Close(pidfd))
	var zeroTask [680]byte
	require.ErrorIs(t, collection.Maps["eo_tasks"].Put(cookie, zeroTask), syscall.EPERM)
	require.ErrorIs(t, collection.Maps["eo_tasks"].Delete(cookie), syscall.EPERM)
	require.ErrorIs(t, collection.Maps["eo_zero_task"].Put(uint32(0), zeroTask), syscall.EPERM)
	require.NoError(t, verify(ctx))
	_, e = control.Call(ctx, fullruntime.ControlCommand{Operation: fullruntime.OwnerRootAuthorize, RootCookie: cookie})
	require.NoError(t, e)
	require.NoError(t, verify(ctx))
	publisher, e = fullruntime.NewPublisher(slot, control, verify, prepared)
	require.NoError(t, e)
	result, e := publisher.Resume(ctx)
	require.NoError(t, e)
	require.True(t, result.Committed)
	require.True(t, result.Admitting)
	run := func(command string, want int) {
		_, e := io.WriteString(input, command)
		require.NoError(t, e)
		require.True(t, scanner.Scan())
		require.Equal(t, fmt.Sprintf("RESULT %d", want), scanner.Text())
		h, e := control.Health()
		require.NoError(t, e)
		require.Zero(t, h.Faults)
		fault, e := control.GenerationFault(slot.Generation())
		require.NoError(t, e)
		require.Zero(t, fault)
	}
	run("t", 77) // Root cannot use the worker-only executable.
	run("s", 0)  // Successful exec commits worker role, inherited by the next fork.
	run("f", 77)
	result, e = publisher.Publish(ctx, compile(2, "changed-root"))
	require.NoError(t, e)
	require.True(t, result.Committed)
	require.True(t, result.Admitting)
	run("s", 0) // Same successful UID epoch: RootRole edits do NOT reroot tasks.
	require.Equal(t, uint64(1), slot.Epochs()["uid"])
	// Fill all sixteen retained task-role slots using real successful revisions.
	// A seventeenth UID must refuse before map commit, preserving healthy last-good.
	for uid := 2; uid <= 16; uid++ {
		result, e = publisher.Publish(ctx, compileUID(uint64(uid+1), "agent", fmt.Sprintf("uid-%d", uid)))
		require.NoError(t, e)
		require.True(t, result.Committed)
		require.True(t, result.Admitting)
	}
	result, e = publisher.Publish(ctx, compileUID(18, "agent", "uid-17"))
	require.Error(t, e)
	require.False(t, result.Committed)
	require.True(t, result.Admitting)
	require.Equal(t, uint64(17), result.Generation)
	require.Len(t, slot.Epochs(), 16)
	require.NotContains(t, slot.Epochs(), "uid-17")
	run("s", 0) // Real last-good rules/roles still enforce after rejected bootstrap.
	result, e = publisher.Publish(ctx, compileUID(19, "edited-root", "uid-16"))
	require.NoError(t, e)
	require.True(t, result.Committed)
	require.True(t, result.Admitting)
	run("s", 0)
	// Fail the native verification callback AFTER the irreversible swap. Admission
	// must stay closed until the SAME committed generation is re-attested/resumed.
	failAfterGeneration = 20
	result, e = publisher.Publish(ctx, compileUID(20, "edited-root-again", "uid-16"))
	require.Error(t, e)
	require.True(t, result.Committed)
	require.False(t, result.Admitting)
	require.Equal(t, uint64(20), result.Generation)
	require.Error(t, publisher.Abort(ctx), "never roll back a committed epoch")
	failAfterGeneration = 0
	result, e = publisher.Resume(ctx)
	require.NoError(t, e)
	require.True(t, result.Committed)
	require.True(t, result.Admitting)
	require.Equal(t, uint64(20), result.Generation)
	require.Equal(t, uint64(17), slot.Epochs()["uid-16"])
	run("s", 0)
	require.NoError(t, publisher.Retire(ctx))
	h, e := control.Health()
	require.NoError(t, e)
	require.Equal(t, uint32(1), h.Retired)
	require.Zero(t, h.RootCookie)
	_, e = io.WriteString(input, "q")
	require.NoError(t, e)
	require.NoError(t, process.Wait())
	t.Log("actual assembled profile + UAPI seals + qualified native control + successful-only publication + fork/exec roles + reload + >8 paths + seventeenth-UID refusal/last-good + postcommit resume; OCI operator/containerd proof remains separate")
}
