// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// heartbeatIterations stays below the owner lifetime task budget (see rounds).
const heartbeatIterations = 700

// heartbeatChurnHelper runs ITERATIONS fork+exec rounds of an Audit would-deny
// target per command and reports fork EAGAIN, exec EPERM and other failures.
const heartbeatChurnHelper = `
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void){
 setbuf(stdout,0);puts("READY");char cmd;
 while(read(0,&cmd,1)==1){
  if(cmd=='q')return 0;
  int eagain=0,eperm=0,other=0;
  for(int i=0;i<ITERATIONS;i++){
   pid_t pid=fork();
   if(pid<0){if(errno==EAGAIN)eagain++;else other++;continue;}
   if(!pid){execl(TARGET,TARGET,(char*)0);_exit(errno==EPERM?77:78);}
   int status;if(waitpid(pid,&status,0)!=pid){other++;continue;}
   if(!WIFEXITED(status))other++;else if(WEXITSTATUS(status)==77)eperm++;else if(WEXITSTATUS(status))other++;
  }
  printf("RESULT %d %d %d\n",eagain,eperm,other);
 }
 return 0;
}
`

// The per-binding heartbeat (Owner.Check) must stay read-only under node-wide
// cgroup churn. A same-plan refresh that closed the admission gate would deny
// not-yet-owned execs and fail forks with EAGAIN in the bound cgroup even for an
// Audit-only binding. Uses the same owner object as TestFullOwnerOCIRuntime.
func TestFullOwnerHeartbeatAuditChurnKernel(t *testing.T) {
	if os.Getenv("IG_FULL_OWNER_HEARTBEAT_TEST") != "1" {
		t.Skip("explicit disposable kernel opt-in required")
	}
	require.Zero(t, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	object, metadata := os.Getenv("IG_FULL_OWNER_OCI_OBJECT"), os.Getenv("IG_FULL_OWNER_OCI_METADATA")
	require.NotEmpty(t, object)
	require.NotEmpty(t, metadata)
	t.Setenv("IG_FULL_EXEC_BPF_OBJECT", object)
	t.Setenv("IG_FULL_EXEC_METADATA", metadata)
	store, image := trustedFullImage(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	rt := local.New()
	require.NoError(t, rt.Init(nil))
	defer rt.Close()
	manager, e := instancemanager.New(rt)
	require.NoError(t, e)

	cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-owner-heartbeat-%d", os.Getpid())
	require.NoError(t, os.Mkdir(cgpath, 0o755))
	defer os.Remove(cgpath)
	cg, e := os.Open(cgpath)
	require.NoError(t, e)
	defer cg.Close()
	var cgstat syscall.Stat_t
	require.NoError(t, syscall.Fstat(int(cg.Fd()), &cgstat))

	tmp := t.TempDir()
	helper, target := filepath.Join(tmp, "heartbeat-helper"), filepath.Join(tmp, "audit-target")
	require.NoError(t, os.WriteFile(target+".c", []byte("int main(void){return 0;}"), 0o600))
	out, e := exec.Command("cc", "-O2", target+".c", "-o", target).CombinedOutput()
	require.NoError(t, e, string(out))
	require.NoError(t, os.WriteFile(helper+".c", []byte("#define ITERATIONS "+strconv.Itoa(heartbeatIterations)+"\n#define TARGET "+strconv.Quote(target)+"\n"+heartbeatChurnHelper), 0o600))
	out, e = exec.Command("cc", "-O2", helper+".c", "-o", helper).CombinedOutput()
	require.NoError(t, e, string(out))
	process := exec.CommandContext(ctx, helper)
	process.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd()), Cloneflags: syscall.CLONE_NEWNS}
	input, e := process.StdinPipe()
	require.NoError(t, e)
	output, e := process.StdoutPipe()
	require.NoError(t, e)
	require.NoError(t, process.Start())
	defer func() { process.Process.Kill(); process.Wait() }()
	scanner := bufio.NewScanner(output)
	require.True(t, scanner.Scan())
	require.Equal(t, "READY", scanner.Text())

	budget, e := fullruntime.NewBudget(fullruntime.BudgetLimits{Owners: 1, MapPayloadBytes: fullruntime.OwnerMapPayloadLimit, ProgramInstructions: fullruntime.OwnerInstructionLimit, HistoryEntries: fullruntime.OwnerHistoryLimit})
	require.NoError(t, e)
	acquire := func(context.Context) (fullruntime.BindingLease, error) {
		l := new(ociOwnerLease)
		for path, dst := range map[string]**os.File{
			fmt.Sprintf("/proc/%d", process.Process.Pid): &l.proc, cgpath: &l.cgroup,
			fmt.Sprintf("/proc/%d/ns/mnt", process.Process.Pid): &l.mount, "/proc/1/ns/mnt": &l.host,
		} {
			file, err := os.Open(path)
			if err != nil {
				return l, err
			}
			*dst = file
		}
		return l, nil
	}
	// Audit-only: the root role may not exec the target, so every exec below is
	// an Audit would-deny that must still run.
	program, e := fullpolicy.CompileKernelWithRoleEpochs([]fullpolicy.Policy{{ID: "uid", Revision: "1", Mode: fullpolicy.Audit, RootRole: "agent", Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{
		{Name: "worker", Action: fullpolicy.Allow, Actor: fullpolicy.Actor{Role: []string{"worker"}}, Target: fullpolicy.Target{Path: []string{target}}},
	}}}, 1, "app", nil)
	require.NoError(t, e)
	owner, e := fullruntime.NewOwner(fullruntime.OwnerConfig{Program: program, CgroupID: cgstat.Ino, InitHostPID: uint32(process.Process.Pid), ControlRoot: cgpath, Acquire: acquire}, budget)
	require.NoError(t, e)
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	require.NoError(t, params.Set("allow-enforcement", "true"))
	require.NoError(t, params.Set("verify-image", "false"))
	require.NoError(t, handler.Init(params))
	defer func() {
		if manager.LookupInstance("owner-heartbeat") != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := owner.BeforeStop(cleanup); err == nil {
				manager.StopGadget(cleanup, "owner-heartbeat")
			} else {
				t.Errorf("native cleanup retained pins after failed drain: %v", err)
			}
		}
		if manager.LookupInstance("owner-heartbeat") == nil {
			owner.ReleaseAfterDetach()
		}
	}()
	require.NoError(t, manager.StartGadget(ctx, &api.GadgetInstance{Id: "owner-heartbeat", GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: image}},
		gadgetcontext.WithOrasReadonlyTarget(store), gadgetcontext.WithAdditionalDataOperators(handler, fullruntime.New()), fullruntime.WithOwner(owner)))
	result, e := owner.Activate(ctx)
	require.NoError(t, e)
	require.True(t, result.Committed)
	require.True(t, result.Admitting)
	require.NoError(t, owner.Check(ctx))
	before, e := owner.Diagnostics()
	require.NoError(t, e)

	// Node-wide churn: move an unrelated process between two unrelated cgroups.
	// Every cgroup_migrate advances the owner's movement sequence and leaves the
	// validated movement receipt stale.
	churnA, churnB := cgpath+"-churn-a", cgpath+"-churn-b"
	for _, path := range []string{churnA, churnB} {
		require.NoError(t, os.Mkdir(path, 0o755))
		defer os.Remove(path)
	}
	churnA0, e := os.Open(churnA)
	require.NoError(t, e)
	defer churnA0.Close()
	sleeper := exec.CommandContext(ctx, "sleep", "600")
	sleeper.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(churnA0.Fd())}
	require.NoError(t, sleeper.Start())
	defer func() { sleeper.Process.Kill(); sleeper.Wait() }()
	pid := []byte(strconv.Itoa(sleeper.Process.Pid))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var moves, checks, checkErrors atomic.Uint64
	var churnErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			dst := churnA
			if i%2 == 0 {
				dst = churnB
			}
			if err := os.WriteFile(filepath.Join(dst, "cgroup.procs"), pid, 0o600); err != nil {
				churnErr = err
				return
			}
			moves.Add(1)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// A Check that lands inside a migration (odd sequence) may report
			// NotReady. It must never refuse an exec or fork.
			if err := owner.Check(ctx); err != nil {
				checkErrors.Add(1)
			}
			checks.Add(1)
		}
	}()
	// Every child consumes one never-recycled owner task credit (OWNER-ABI.md:
	// 4096 lifetime task allocations, including the helper). Stay below it, or
	// the CAPACITY fault fails closed and is misread as a heartbeat regression.
	rounds := 5
	require.Less(t, 1+rounds*heartbeatIterations, fullruntime.OwnerTaskLimit)
	for i := 0; i < rounds; i++ {
		_, e = io.WriteString(input, "r")
		require.NoError(t, e)
		require.True(t, scanner.Scan())
		require.Equal(t, "RESULT 0 0 0", scanner.Text(), "round %d: fork EAGAIN, exec EPERM, other", i)
	}
	close(stop)
	wg.Wait()
	require.NoError(t, churnErr)
	require.NotZero(t, moves.Load())
	require.NotZero(t, checks.Load())
	require.Less(t, checkErrors.Load(), checks.Load(), "heartbeat never confirmed protection under churn")

	after, e := owner.Diagnostics()
	require.NoError(t, e)
	require.Greater(t, after.Health.MovementSequence, before.Health.MovementSequence, "churn never reached the movement observer")
	require.Equal(t, before.Health.GateDenials, after.Health.GateDenials, "heartbeat closed admission")
	require.Zero(t, after.Health.Faults)
	require.False(t, after.GateClosed)
	require.Equal(t, uint64(1), owner.Generation())
	require.NoError(t, owner.Check(ctx), "stale movement receipt is not drift")

	require.NoError(t, owner.BeforeStop(ctx))
	require.NoError(t, manager.StopGadget(ctx, "owner-heartbeat"))
	require.NoError(t, owner.ReleaseAfterDetach())
	_, e = io.WriteString(input, "q")
	require.NoError(t, e)
	require.NoError(t, process.Wait())
	t.Logf("read-only heartbeat under churn: %d rounds x %d Audit fork+exec, %d migrations, %d checks (%d NotReady mid-migration), gate denials unchanged", rounds, heartbeatIterations, moves.Load(), checks.Load(), checkErrors.Load())
}
