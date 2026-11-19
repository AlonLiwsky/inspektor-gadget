// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	jsonformatter "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// These test owners create containers with fixed restricted runtime credentials
// and issue only ordinary execs. Init credentials are checked as corroboration;
// the owner contract comes from controlling creation AND subsequent execs.
type execContainer struct {
	identity execruntime.ContainerIdentity
	pid      string
	exec     func(...string) (string, error)
}

func restrictedDescriptors(c execContainer) (execruntime.RestrictedWorkload, error) {
	w := execruntime.RestrictedWorkload{
		Credentials:   execruntime.WorkloadCredentials{NoNewPrivileges: true, Effective: 1 << unix.CAP_SYS_CHROOT, Permitted: 1 << unix.CAP_SYS_CHROOT, Bounding: 1 << unix.CAP_SYS_CHROOT},
		OwnerContract: execruntime.RestrictedWorkloadContract{AllWorkloadEntriesRestricted: true, NoHostDelegation: true},
	}
	var err error
	w.HostMountNamespace, err = os.Open("/proc/1/ns/mnt")
	if err != nil {
		return w, err
	}
	w.MountNamespace, err = os.Open("/proc/" + c.pid + "/ns/mnt")
	if err != nil {
		w.HostMountNamespace.Close()
		return w, err
	}
	w.UserNamespace, err = os.Open("/proc/" + c.pid + "/ns/user")
	if err != nil {
		w.HostMountNamespace.Close()
		w.MountNamespace.Close()
		return w, err
	}
	return w, nil
}

func checkRestrictedInit(t *testing.T, c execContainer) {
	t.Helper()
	status, err := os.ReadFile("/proc/" + c.pid + "/status")
	require.NoError(t, err)
	checkRestrictedStatus(t, string(status))
}

func checkRestrictedStatus(t *testing.T, status string) {
	t.Helper()
	seen := map[string]bool{}
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "CapEff:", "CapPrm:", "CapInh:", "CapAmb:", "CapBnd:":
			mask, err := strconv.ParseUint(fields[1], 16, 64)
			require.NoError(t, err)
			require.Zero(t, mask&uint64(1<<unix.CAP_SYS_ADMIN|1<<unix.CAP_SYS_PTRACE), line)
			seen[fields[0]] = true
		case "NoNewPrivs:":
			require.Equal(t, "1", fields[1])
			seen[fields[0]] = true
		}
	}
	require.Len(t, seen, 6, "all five capability sets and no_new_privs must be present")
}

func namespaceReferences(name string) int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err == nil && target == name {
			count++
		}
	}
	return count
}

func closeDescriptors(w execruntime.RestrictedWorkload) {
	w.HostMountNamespace.Close()
	w.MountNamespace.Close()
	w.UserNamespace.Close()
}

func TestExecRestrictedDocker(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" || os.Getenv("IG_EXEC_DOCKER_TEST") != "1" {
		t.Skip("requires disposable BPF LSM Docker host and explicit opt-in")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	command := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("docker", args...).CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.TrimSpace(string(out))
	}
	command("pull", "alpine:3.21")
	create := func() execContainer {
		id := command("run", "-d", "--cap-drop=ALL", "--cap-add=SYS_CHROOT", "--security-opt=no-new-privileges:true", "--security-opt=seccomp=unconfined", "--security-opt=apparmor=unconfined", "alpine:3.21", "sleep", "600")
		t.Cleanup(func() { command("rm", "-f", id) })
		command("exec", id, "mkdir", "-p", "/tmp/approved")
		for _, p := range []string{"/tmp/busybox", "/tmp/approved/busybox", "/runc"} {
			command("exec", id, "cp", "/bin/busybox", p)
		}
		pid := command("inspect", "--format", "{{.State.Pid}}", id)
		c := containerIdentity(t, "docker", id, pid)
		return execContainer{identity: c, pid: pid, exec: func(args ...string) (string, error) {
			out, err := exec.Command("docker", append([]string{"exec", id}, args...)...).CombinedOutput()
			return string(out), err
		}}
	}
	exerciseRestrictedRuntime(t, create(), create(), os.Getenv("IG_EXEC_EXPECT_RUNC_HELPER") == "1")
}

func containerIdentity(t *testing.T, runtime, id, pid string) execruntime.ContainerIdentity {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + pid + "/cgroup")
	require.NoError(t, err)
	p := strings.TrimPrefix(strings.TrimSpace(string(raw)), "0::")
	var st unix.Stat_t
	require.NoError(t, unix.Stat(filepath.Join("/sys/fs/cgroup", p), &st))
	return execruntime.ContainerIdentity{Runtime: runtime, ID: id, CgroupID: st.Ino, CgroupPath: p}
}

func exerciseRestrictedRuntime(t *testing.T, target, control execContainer, expectHelper bool) {
	t.Helper()
	checkRestrictedInit(t, target)
	checkRestrictedInit(t, control)
	for _, c := range []execContainer{target, control} {
		status, err := c.exec("cat", "/proc/self/status")
		require.NoError(t, err, status)
		checkRestrictedStatus(t, status)
	}
	namespaceName, err := os.Readlink("/proc/" + target.pid + "/ns/mnt")
	require.NoError(t, err)
	baselineNamespaceReferences := namespaceReferences(namespaceName)
	require.NotEqual(t, -1, baselineNamespaceReferences)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	store, image := executionImage(t)
	runtime := local.New()
	require.NoError(t, runtime.Init(nil))
	defer runtime.Close()
	manager, err := instancemanager.New(runtime)
	require.NoError(t, err)
	desired := func(id string) *api.GadgetInstance {
		return &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: image}}
	}
	var lock sync.Mutex
	contexts := map[string]operators.GadgetContext{}
	verdicts := map[string][]map[string]interface{}{}
	config := func(revision uint64, allowNew bool) execruntime.Config {
		extra := ""
		if allowNew {
			extra = ", \"/tmp/approved/busybox\""
		}
		document, err := execpolicy.Parse(strings.NewReader(fmt.Sprintf("version: 1\nbinding:\n  container:\n    runtime: %s\n    id: %s\npolicy:\n  mode: enforce\n  exec:\n    default: deny\n    rules:\n      - name: allowed\n        target:\n          path: [\"/bin/**\", \"/usr/bin/**\"%s]\n        action: allow\n", target.identity.Runtime, target.identity.ID, extra)), execpolicy.DefaultLimits())
		require.NoError(t, err)
		entries, err := execpolicy.CompileKernel(document, revision)
		require.NoError(t, err)
		return execruntime.Config{Entries: entries}
	}
	options := func(id string, restricted, invalid bool, gate, entered chan struct{}) []gadgetcontext.Option {
		handler := ocihandler.New()
		p := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
		require.NoError(t, p.Set("verify-image", "false"))
		require.NoError(t, p.Set("allow-enforcement", "true"))
		require.NoError(t, handler.Init(p))
		owner := simple.New("restricted-owner", simple.WithPriority(2), simple.OnStart(func(gc operators.GadgetContext) error {
			lock.Lock()
			contexts[id] = gc
			lock.Unlock()
			b, err := execruntime.GetBindings(gc)
			if err != nil {
				return err
			}
			if restricted {
				w, err := restrictedDescriptors(target)
				if err != nil {
					return err
				}
				defer closeDescriptors(w)
				if invalid {
					w.OwnerContract.AllWorkloadEntriesRestricted = false
				}
				if err := b.BindRestricted(target.identity, w); err != nil {
					return err
				}
			} else if err := b.Bind(target.identity); err != nil {
				return err
			}
			if entered != nil {
				close(entered)
			}
			if gate != nil {
				select {
				case <-gate:
				case <-gc.Context().Done():
					return gc.Context().Err()
				}
			}
			return nil
		}))
		output := simple.New("test-verdicts", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
			ds := gc.GetDataSources()["verdict"]
			if ds == nil {
				return fmt.Errorf("missing verdict datasource")
			}
			formatter, err := jsonformatter.New(ds)
			if err != nil {
				return err
			}
			return ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
				var row map[string]interface{}
				if err := json.Unmarshal(formatter.Marshal(data), &row); err != nil {
					return err
				}
				lock.Lock()
				verdicts[id] = append(verdicts[id], row)
				lock.Unlock()
				return nil
			}, 1000001)
		}))
		revision := uint64(81)
		if restricted {
			revision = 82
		}
		return []gadgetcontext.Option{gadgetcontext.WithOrasReadonlyTarget(store), gadgetcontext.WithAdditionalDataOperators(handler, execruntime.New(), owner, output), execruntime.WithConfig(config(revision, restricted))}
	}
	check := func(c execContainer, path string, allowed bool) {
		t.Helper()
		args := []string{path}
		if strings.HasPrefix(path, "/tmp/") || path == "/runc" {
			args = append(args, "echo", "ran")
		}
		out, err := c.exec(args...)
		if allowed {
			require.NoError(t, err, out)
		} else {
			require.Error(t, err, out)
		}
	}
	defer func() {
		for _, id := range []string{"strict", "restricted", "invalid"} {
			if manager.LookupInstance(id) != nil {
				require.NoError(t, manager.StopGadget(context.Background(), id))
			}
		}
	}()
	require.NoError(t, manager.StartGadget(ctx, desired("strict"), options("strict", false, false, nil, nil)...))
	check(target, "/bin/true", true)
	check(target, "/tmp/busybox", false)
	check(control, "/tmp/busybox", true)
	if expectHelper {
		require.Eventually(t, func() bool {
			lock.Lock()
			defer lock.Unlock()
			for _, e := range verdicts["strict"] {
				if e["path"] == "/runc" && e["deny"] == float64(1) {
					return true
				}
			}
			return false
		}, 3*time.Second, 20*time.Millisecond, "strict baseline must reproduce a helper denial")
	}
	require.ErrorIs(t, manager.ReplaceGadget(ctx, "strict", desired("invalid"), options("invalid", true, true, nil, nil)...), execruntime.ErrRestrictedWorkload)
	require.NotNil(t, manager.LookupInstance("strict"))
	check(target, "/tmp/busybox", false)
	gate, entered := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
	}()
	replacement := make(chan error, 1)
	opts := options("restricted", true, false, gate, entered)
	go func() { replacement <- manager.ReplaceGadget(ctx, "strict", desired("restricted"), opts...) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	lock.Lock()
	gc := contexts["restricted"]
	lock.Unlock()
	b, err := execruntime.GetBindings(gc)
	require.NoError(t, err)
	require.Equal(t, 1, b.Status().RestrictedBindings)
	require.False(t, b.Status().Ready)
	check(target, "/tmp/approved/busybox", false)
	check(target, "/tmp/busybox", false)
	close(gate)
	require.NoError(t, <-replacement)
	require.Nil(t, manager.LookupInstance("strict"))
	// Caller descriptors were closed when the owner startup operator returned.
	require.True(t, b.Status().Ready)
	require.Equal(t, baselineNamespaceReferences+1, namespaceReferences(namespaceName), "controller must retain its namespace reference after caller FDs close")
	require.Equal(t, 1, b.Status().RestrictedBindings)
	lock.Lock()
	start := len(verdicts["restricted"])
	lock.Unlock()
	check(target, "/bin/true", true)
	require.Eventually(t, func() bool {
		lock.Lock()
		defer lock.Unlock()
		for _, e := range verdicts["restricted"][start:] {
			if e["deny"] == float64(0) && e["generation"] == float64(82) {
				return true
			}
		}
		return false
	}, 3*time.Second, 20*time.Millisecond)
	lock.Lock()
	batch := append([]map[string]interface{}(nil), verdicts["restricted"][start:]...)
	lock.Unlock()
	for _, e := range batch {
		require.False(t, e["path"] == "/runc" && e["deny"] == float64(1), "helper must be exempted after handoff")
	}
	check(target, "/tmp/approved/busybox", true)
	check(target, "/tmp/busybox", false)
	check(target, "/runc", false)
	require.Eventually(t, func() bool {
		lock.Lock()
		defer lock.Unlock()
		for _, e := range verdicts["restricted"] {
			if e["path"] == "/runc" && e["deny"] == float64(1) && e["generation"] == float64(82) {
				return true
			}
		}
		return false
	}, 3*time.Second, 20*time.Millisecond, "workload-owned runtime path must be denied by BPF")
	// Child namespaces must remain enforced by the actual gadget, not only
	// the earlier diagnostic program. Read the child identity before its exec.
	lock.Lock()
	childStart := len(verdicts["restricted"])
	lock.Unlock()
	childOutput, childErr := target.exec("unshare", "-Um", "/bin/sh", "-c", "readlink /proc/self/ns/mnt > /tmp/child-namespace; exec /tmp/busybox echo child-ran")
	require.Error(t, childErr, childOutput)
	// crictl exec --sync may omit workload stdout when exit status is nonzero.
	// Read the namespace record through a separate successful exec instead.
	namespaceRecord, err := target.exec("cat", "/tmp/child-namespace")
	require.NoError(t, err, namespaceRecord)
	childNamespace := strings.TrimSpace(namespaceRecord)
	require.NotEmpty(t, childNamespace, "unshare must reach the child namespace before the denial")
	require.NotEqual(t, namespaceName, childNamespace)
	hostNamespace, err := os.Readlink("/proc/1/ns/mnt")
	require.NoError(t, err)
	require.NotEqual(t, hostNamespace, childNamespace)
	require.NotContains(t, childOutput, "child-ran\n")
	require.Eventually(t, func() bool {
		lock.Lock()
		defer lock.Unlock()
		for _, e := range verdicts["restricted"][childStart:] {
			if e["path"] == "/tmp/busybox" && e["deny"] == float64(1) && e["generation"] == float64(82) {
				return true
			}
		}
		return false
	}, 3*time.Second, 20*time.Millisecond, "child namespace exec must be denied by the actual policy")
	require.Error(t, b.Bind(target.identity), "strict replay must not silently change scope")
	w, err := restrictedDescriptors(control)
	require.NoError(t, err)
	require.NoError(t, b.BindRestricted(control.identity, w))
	closeDescriptors(w)
	check(control, "/tmp/busybox", false)
	require.Equal(t, 2, b.Status().RestrictedBindings)
	require.NoError(t, b.Unbind(control.identity))
	check(control, "/tmp/busybox", true)
	childControl, err := control.exec("unshare", "-Um", "/tmp/busybox", "echo", "child-control")
	require.NoError(t, err, childControl)
	require.Contains(t, childControl, "child-control")
	check(target, "/tmp/busybox", false)
	require.NoError(t, manager.StopGadget(ctx, "restricted"))
	require.Equal(t, baselineNamespaceReferences, namespaceReferences(namespaceName), "namespace reference must be released after cleanup")
	check(target, "/tmp/busybox", true)
}
