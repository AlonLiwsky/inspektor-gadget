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

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// Synthetic TEST owner: the fixture itself creates and pins this exact helper.
// This is NOT a containerd/CRI authenticator or production root/mount attestation.
type ociOwnerLease struct {
	proc, cgroup, mount, host *os.File
	closed                    bool
}

func (l *ociOwnerLease) Check(ctx context.Context) error {
	if l.closed {
		return fmt.Errorf("test lease closed")
	}
	return ctx.Err()
}
func (l *ociOwnerLease) InitProc() *os.File           { return l.proc }
func (l *ociOwnerLease) Cgroup() *os.File             { return l.cgroup }
func (l *ociOwnerLease) MountNamespace() *os.File     { return l.mount }
func (l *ociOwnerLease) HostMountNamespace() *os.File { return l.host }
func (l *ociOwnerLease) Close() error {
	if l.closed {
		return nil
	}
	l.closed = true
	var errs []error
	for _, file := range []*os.File{l.proc, l.cgroup, l.mount, l.host} {
		if file != nil {
			errs = append(errs, file.Close())
		}
	}
	return errors.Join(errs...)
}

// Exact native path: in-memory trusted OCI -> actual eBPF operator -> qualified
// command handle/attachment receipts -> closed preparation -> explicit activation
// -> same-map role reload -> read-only heartbeat and publication re-attestation
// -> drain/confirmed teardown.
func TestFullOwnerOCIRuntime(t *testing.T) {
	if os.Getenv("IG_FULL_OWNER_OCI_TEST") != "1" {
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rt := local.New()
	require.NoError(t, rt.Init(nil))
	defer rt.Close()
	manager, e := instancemanager.New(rt)
	require.NoError(t, e)
	cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-owner-oci-%d", os.Getpid())
	require.NoError(t, os.Mkdir(cgpath, 0o755))
	defer os.Remove(cgpath)
	cg, e := os.Open(cgpath)
	require.NoError(t, e)
	defer cg.Close()
	var cgstat syscall.Stat_t
	require.NoError(t, syscall.Fstat(int(cg.Fd()), &cgstat))
	tmp := t.TempDir()
	helper, target := filepath.Join(tmp, "owner-helper"), filepath.Join(tmp, "worker-target")
	require.NoError(t, os.WriteFile(target+".c", []byte("int main(void){return 0;}"), 0o600))
	out, e := exec.Command("cc", "-O2", target+".c", "-o", target).CombinedOutput()
	require.NoError(t, e, string(out))
	require.NoError(t, os.WriteFile(helper+".c", []byte("#define OWNER_WORKER_TARGET "+strconv.Quote(target)+"\n"+ownerExecHelper), 0o600))
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
	budget, e := fullruntime.NewBudget(fullruntime.BudgetLimits{Owners: 2, MapPayloadBytes: 2 * fullruntime.OwnerMapPayloadLimit, ProgramInstructions: 2 * fullruntime.OwnerInstructionLimit, HistoryEntries: 2 * fullruntime.OwnerHistoryLimit})
	require.NoError(t, e)
	var leases []*ociOwnerLease
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

		leases = append(leases, l)
		return l, nil
	}
	compile := func(generation uint64, rootRole string, epochs map[string]uint64) *fullpolicy.KernelProgram {
		paths := []string{helper}
		for i := 0; i < 12; i++ {
			paths = append(paths, fmt.Sprintf("/unused/%d", i))
		}
		p, e := fullpolicy.CompileKernelWithRoleEpochs([]fullpolicy.Policy{{ID: "uid", Revision: fmt.Sprint(generation), Mode: fullpolicy.Enforce, RootRole: rootRole, Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{
			{Name: "stage", Action: fullpolicy.Allow, Actor: fullpolicy.Actor{Role: []string{"agent"}}, Target: fullpolicy.Target{Path: paths, SetRole: "worker"}},
			{Name: "worker", Action: fullpolicy.Allow, Actor: fullpolicy.Actor{Role: []string{"worker"}}, Target: fullpolicy.Target{Path: []string{target}}},
		}}}, generation, "app", epochs)
		require.NoError(t, e)
		return p
	}
	config := fullruntime.OwnerConfig{Program: compile(1, "agent", nil), CgroupID: cgstat.Ino, InitHostPID: uint32(process.Process.Pid), ControlRoot: cgpath, Acquire: acquire}
	events := make(chan uint64, 64)
	eventErrors := make(chan error, 64)
	options := func(owner *fullruntime.Owner, fail bool) []gadgetcontext.Option {
		handler := ocihandler.New()
		params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
		require.NoError(t, params.Set("allow-enforcement", "true"))
		require.NoError(t, params.Set("verify-image", "false"))
		require.NoError(t, handler.Init(params))
		capture := simple.New("owner-native-events", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
			ds := gc.GetDataSources()["verdict"]
			if ds == nil {
				return fmt.Errorf("missing verdict datasource")
			}
			for _, name := range []string{"generation", "cgroup", "matched_rules", "error"} {
				if ds.GetField(name) == nil {
					return fmt.Errorf("missing full event field %s", name)
				}
			}
			return ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				gen, e1 := ds.GetField("generation").Uint64(data)
				cg, e2 := ds.GetField("cgroup").Uint64(data)
				bits, e3 := ds.GetField("matched_rules").Uint64Array(data)
				fault, e4 := ds.GetField("error").Uint32(data)
				if err := errors.Join(e1, e2, e3, e4); err != nil {
					select {
					case eventErrors <- err:
					default:
					}
					return nil
				}
				if cg != cgstat.Ino || len(bits) != 4 || fault != 0 {
					select {
					case eventErrors <- fmt.Errorf("bad owner verdict cg=%d bitmap=%v fault=%d", cg, bits, fault):
					default:
					}
					return nil
				}
				if bits[0] != 0 {
					select {
					case events <- gen:
					default:
					}
				}
				return nil
			}, 100)
		}), simple.OnStart(func(operators.GadgetContext) error {
			if fail {
				return errors.New("injected late operator start failure")
			}
			return nil
		}))
		return []gadgetcontext.Option{gadgetcontext.WithOrasReadonlyTarget(store), gadgetcontext.WithAdditionalDataOperators(handler, fullruntime.New(), capture), fullruntime.WithOwner(owner)}
	}
	desired := func(id string) *api.GadgetInstance {
		return &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: image}}
	}
	bad, e := fullruntime.NewOwner(config, budget)
	require.NoError(t, e)
	require.ErrorContains(t, manager.StartGadget(ctx, desired("owner-bad"), options(bad, true)...), "injected late operator start failure")
	require.Error(t, bad.Check(ctx))
	require.Equal(t, uint64(0), bad.Generation())
	require.Equal(t, uint64(1), budget.Usage().Owners, "automatic operator close must not release native pins/reservation")
	require.NoError(t, bad.ReleaseAfterDetach())
	require.Len(t, leases, 1)
	require.True(t, leases[0].closed)
	require.Zero(t, budget.Usage().Owners)
	owner, e := fullruntime.NewOwner(config, budget)
	require.NoError(t, e)
	defer func() {
		// Normal shutdown must retire BEFORE manager cancellation. On a test failure,
		// retain pins rather than pretending an unsuccessful drain was safe.
		if manager.LookupInstance("owner-good") != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := owner.BeforeStop(cleanup); err == nil {
				manager.StopGadget(cleanup, "owner-good")
			} else {
				t.Errorf("native cleanup retained pins after failed drain: %v", err)
			}
		}
		if manager.LookupInstance("owner-good") == nil {
			owner.ReleaseAfterDetach()
		}
	}()
	require.NoError(t, manager.StartGadget(ctx, desired("owner-good"), options(owner, false)...))
	require.Equal(t, uint64(0), owner.Generation())
	require.Error(t, owner.Check(ctx), "IG startup acknowledgement is not policy activation")
	result, e := owner.Activate(ctx)
	require.NoError(t, e)
	require.True(t, result.Committed)
	require.True(t, result.Admitting)
	require.NoError(t, owner.Check(ctx))
	if duplicate, e := fullruntime.NewOwner(config, budget); e == nil {
		duplicate.ReleaseAfterDetach()
		t.Fatal("parallel owner for exact cgroup accepted")
	}
	run := func(command string, want int) {
		_, e := io.WriteString(input, command)
		require.NoError(t, e)
		require.True(t, scanner.Scan())
		require.Equal(t, fmt.Sprintf("RESULT %d", want), scanner.Text())
	}
	run("t", 77)
	run("s", 0)
	result, e = owner.Update(ctx, compile(2, "edited-root", owner.Epochs()))
	require.NoError(t, e)
	require.True(t, result.Committed)
	require.True(t, result.Admitting)
	require.Equal(t, uint64(1), owner.Epochs()["uid"])
	run("s", 0)
	require.NoError(t, owner.Check(ctx))
	// Existing foreign ingress has no observed creator lineage. The heartbeat is
	// read-only (it never closes admission), so it does not inventory a dormant
	// task; the next publication re-attests under a drained gate and refuses it
	// without executing it. Recovery needs no publication after it leaves.
	sidecar := exec.CommandContext(ctx, "sleep", "60")
	require.NoError(t, sidecar.Start())
	defer func() { sidecar.Process.Kill(); sidecar.Wait() }()
	procCG, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", sidecar.Process.Pid))
	require.NoError(t, e)
	var original string
	for _, line := range strings.Split(string(procCG), "\n") {
		if strings.HasPrefix(line, "0::") {
			original = strings.TrimPrefix(line, "0::")
		}
	}
	require.NotEmpty(t, original)
	move := func(path string) {
		require.NoError(t, os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(sidecar.Process.Pid)), 0o600))
	}
	move(cgpath)
	require.NoError(t, owner.Check(ctx), "dormant foreign ingress stays Ready: the heartbeat is read-only and does not inventory cgroup membership")
	result, e = owner.Update(ctx, compile(3, "edited-root", owner.Epochs()))
	require.Error(t, e, "publication must refuse foreign ingress")
	// EO_LINEAGE (7) is surfaced by fullruntime/control.go as "status 7" or "result 7".
	require.Regexp(t, `(status|result) 7\b`, e.Error(), "refusal must be the lineage refusal")
	require.False(t, result.Committed)
	require.True(t, result.Admitting)
	require.Equal(t, uint64(2), owner.Generation())
	move(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(original, "/")))
	require.NoError(t, owner.Check(ctx))
	require.Equal(t, uint64(2), owner.Generation())
	// Accepted state re-attests once the foreign ingress has left.
	result, e = owner.Update(ctx, compile(4, "edited-root", owner.Epochs()))
	require.NoError(t, e)
	require.True(t, result.Committed)
	require.True(t, result.Admitting)
	require.Equal(t, uint64(4), owner.Generation())
	require.NoError(t, owner.Check(ctx))
	run("s", 0)
	seen := map[uint64]bool{}
	require.Eventually(t, func() bool {
		for {
			select {
			case gen := <-events:
				seen[gen] = true
			default:
				return seen[1] && seen[2]
			}
		}
	}, time.Second, 10*time.Millisecond)
	select {
	case err := <-eventErrors:
		t.Fatal(err)
	default:
	}
	require.NoError(t, owner.BeforeStop(ctx))
	require.Error(t, owner.ReleaseAfterDetach(), "cannot release before actual runtime teardown")
	require.NoError(t, manager.StopGadget(ctx, "owner-good"))
	require.NoError(t, owner.ReleaseAfterDetach())
	require.True(t, leases[1].closed)
	require.Zero(t, budget.Usage().Owners)
	_, e = io.WriteString(input, "q")
	require.NoError(t, e)
	require.NoError(t, process.Wait())
	t.Log("native OCI lifecycle/command/attachment/event/reload/closed activation/read-only heartbeat/publication re-attestation/late failure/confirmed teardown proof; synthetic lease, NOT containerd/CRI validation")
}
