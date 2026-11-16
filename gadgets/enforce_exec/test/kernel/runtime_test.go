// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// TestExecRuntime exercises the production OCI/BPF image through native control
// and the actual instance manager. Cache replay is synthetic; enforcement isn't.
func TestExecRuntime(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" {
		t.Skip("requires disposable BPF LSM host and IG_EXEC_KERNEL_TEST=1")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, image := executionImage(t)
	runtime := local.New()
	require.NoError(t, runtime.Init(nil))
	defer runtime.Close()
	manager, err := instancemanager.New(runtime)
	require.NoError(t, err)
	cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-exec-native-%d", os.Getpid())
	require.NoError(t, os.Mkdir(cgpath, 0o755))
	defer os.Remove(cgpath)
	cg, err := os.Open(cgpath)
	require.NoError(t, err)
	defer cg.Close()
	var stat syscall.Stat_t
	require.NoError(t, syscall.Fstat(int(cg.Fd()), &stat))
	identity := execruntime.ContainerIdentity{Runtime: "containerd", ID: "native-runtime-test", CgroupID: stat.Ino, CgroupPath: "/" + filepath.Base(cgpath)}
	tmp := t.TempDir()
	first, second, never := filepath.Join(tmp, "first"), filepath.Join(tmp, "second"), filepath.Join(tmp, "never")
	binary, err := os.ReadFile("/usr/bin/true")
	require.NoError(t, err)
	for _, p := range []string{first, second, never} {
		require.NoError(t, os.WriteFile(p, binary, 0o755))
	}
	execute := func(p string) error {
		cmd := exec.Command(p)
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
		return cmd.Run()
	}
	policy := func(allowed string, revision uint64) execruntime.Config {
		d, e := execpolicy.Parse(strings.NewReader(fmt.Sprintf("version: 1\nbinding:\n  container:\n    runtime: containerd\n    id: native-runtime-test\npolicy:\n  mode: enforce\n  exec:\n    default: deny\n    rules:\n      - name: allowed\n        target:\n          path: [%q]\n        action: allow\n", allowed)), execpolicy.DefaultLimits())
		require.NoError(t, e)
		entries, e := execpolicy.CompileKernel(d, revision)
		require.NoError(t, e)
		return execruntime.Config{Entries: entries, Targets: d.Binding.Targets()}
	}
	var lock sync.Mutex
	contexts := map[string]operators.GadgetContext{}
	gateEntered := map[string]chan struct{}{}
	desired := func(id string) *api.GadgetInstance {
		return &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: image}}
	}
	options := func(id string, config execruntime.Config, invalidBinding bool, gate <-chan struct{}) []gadgetcontext.Option {
		handler := ocihandler.New()
		p := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
		require.NoError(t, p.Set("verify-image", "false"))
		require.NoError(t, p.Set("allow-enforcement", "true"))
		require.NoError(t, handler.Init(p))
		var containers datasource.DataSource
		publisher := simple.New("cache", simple.WithPriority(-1), simple.OnInit(func(gc operators.GadgetContext) error {
			var e error
			containers, e = gc.RegisterDataSource(datasource.TypeSingle, "containers")
			if e != nil {
				return e
			}
			for _, name := range []string{"event_type", "runtime", "container_id", "cgroup_v2_path"} {
				if _, e = containers.AddField(name, api.Kind_String); e != nil {
					return e
				}
			}
			if _, e = containers.AddField("cgroup_id", api.Kind_Uint64); e != nil {
				return e
			}
			lock.Lock()
			contexts[id] = gc
			lock.Unlock()
			return nil
		}), simple.OnStart(func(operators.GadgetContext) error {
			packet, e := containers.NewPacketSingle()
			if e != nil {
				return e
			}
			for key, value := range map[string]string{"event_type": "CREATED", "runtime": identity.Runtime, "container_id": identity.ID, "cgroup_v2_path": identity.CgroupPath} {
				if e = containers.GetField(key).PutString(packet, value); e != nil {
					return e
				}
			}
			cgroupID := identity.CgroupID
			if invalidBinding {
				cgroupID = 0
			}
			if e = containers.GetField("cgroup_id").PutUint64(packet, cgroupID); e != nil {
				return e
			}
			return containers.EmitAndRelease(packet)
		}))
		entered := make(chan struct{})
		gateEntered[id] = entered
		barrier := simple.New("test-ready-barrier", simple.WithPriority(2), simple.OnStart(func(gc operators.GadgetContext) error {
			if gate != nil {
				close(entered)
				select {
				case <-gate:
				case <-gc.Context().Done():
					return gc.Context().Err()
				}
			}
			return nil
		}))
		return []gadgetcontext.Option{gadgetcontext.WithOrasReadonlyTarget(store), gadgetcontext.WithAdditionalDataOperators(handler, publisher, execruntime.New(), barrier), execruntime.WithConfig(config)}
	}
	require.NoError(t, manager.StartGadget(ctx, desired("old"), options("old", policy(first, 41), false, nil)...))
	defer func() {
		for _, id := range []string{"old", "new"} {
			if manager.LookupInstance(id) != nil {
				require.NoError(t, manager.StopGadget(context.Background(), id))
			}
		}
	}()
	require.NoError(t, execute(first))
	require.Error(t, execute(second))
	require.Error(t, execute(never))
	gc := contexts["old"]
	value, _ := gc.GetVar(operators.MapPrefix + "policy")
	policyMap := value.(*ebpf.Map)
	require.ErrorIs(t, policyMap.Put(uint32(0), execpolicy.KernelEntry{}), syscall.EPERM, "policy must be frozen")
	bindings, err := execruntime.GetBindings(gc)
	require.NoError(t, err)
	require.NoError(t, bindings.Unbind(identity))
	require.NoError(t, execute(never))
	require.NoError(t, bindings.Bind(identity))
	require.Error(t, execute(never))
	require.Equal(t, uint64(41), bindings.Status().Revision)
	// A failed initial binding must never retire the working instance.
	require.Error(t, manager.ReplaceGadget(ctx, "old", desired("invalid"), options("invalid", policy(second, 42), true, nil)...))
	require.NotNil(t, manager.LookupInstance("old"))
	require.Nil(t, manager.LookupInstance("invalid"))
	require.NoError(t, execute(first))
	require.Error(t, execute(never))
	// A late startup-window error must remain fatal even if an unrelated
	// successful bind subsequently clears the latest-operation error.
	lateGate := make(chan struct{})
	lateResult := make(chan error, 1)
	lateOptions := options("late", policy(second, 42), false, lateGate)
	go func() { lateResult <- manager.ReplaceGadget(ctx, "old", desired("late"), lateOptions...) }()
	select {
	case <-gateEntered["late"]:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	lock.Lock()
	lateGC := contexts["late"]
	lock.Unlock()
	lateBindings, err := execruntime.GetBindings(lateGC)
	require.NoError(t, err)
	require.False(t, lateBindings.Status().Ready)
	ds := lateGC.GetDataSources()["containers"]
	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)
	for key, value := range map[string]string{"event_type": "CREATED", "runtime": identity.Runtime, "container_id": identity.ID, "cgroup_v2_path": identity.CgroupPath} {
		require.NoError(t, ds.GetField(key).PutString(packet, value))
	}
	require.NoError(t, ds.GetField("cgroup_id").PutUint64(packet, identity.CgroupID+1))
	require.Error(t, ds.EmitAndRelease(packet))
	require.NoError(t, lateBindings.Bind(identity))
	close(lateGate)
	require.Error(t, <-lateResult)
	require.NotNil(t, manager.LookupInstance("old"))
	require.Nil(t, manager.LookupInstance("late"))
	require.NoError(t, execute(first))
	require.Error(t, execute(never))

	gate := make(chan struct{})
	replacement := make(chan error, 1)
	newOptions := options("new", policy(second, 43), false, gate)
	go func() {
		replacement <- manager.ReplaceGadget(ctx, "old", desired("new"), newOptions...)
	}()
	// Wait for the explicit startup barrier; querying vars while operators are
	// still instantiating would race the framework's initialization-only map.
	select {
	case <-gateEntered["new"]:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	lock.Lock()
	candidateGC := contexts["new"]
	lock.Unlock()
	candidateBindings, err := execruntime.GetBindings(candidateGC)
	require.NoError(t, err)
	require.Equal(t, 1, candidateBindings.Status().Bound)
	require.False(t, candidateBindings.Status().Ready)
	require.NotNil(t, manager.LookupInstance("old"))
	require.Error(t, execute(first), "new denies while old allows")
	require.Error(t, execute(second), "old denies while new allows")
	require.Error(t, execute(never))
	close(gate)
	require.NoError(t, <-replacement)
	require.Nil(t, manager.LookupInstance("old"))
	require.NoError(t, execute(second))
	require.Error(t, execute(first))
	require.Error(t, execute(never))
	b, err := execruntime.GetBindings(contexts["new"])
	require.NoError(t, err)
	require.Equal(t, uint64(43), b.Status().Revision)
	require.NoError(t, manager.StopGadget(ctx, "new"))
	require.NoError(t, execute(never))
}

func executionImage(t *testing.T) (*memory.Store, string) {
	t.Helper()
	ctx := context.Background()
	read := func(name string) []byte {
		t.Helper()
		p := os.Getenv(name)
		require.NotEmpty(t, p)
		b, e := os.ReadFile(p)
		require.NoError(t, e)
		return b
	}
	store := memory.New()
	push := func(media string, b []byte) ocispec.Descriptor {
		d := content.NewDescriptorFromBytes(media, b)
		require.NoError(t, store.Push(ctx, d, bytes.NewReader(b)))
		return d
	}
	cfg := push("application/vnd.gadget.config.v1+yaml", read("IG_EXEC_METADATA"))
	layers := []ocispec.Descriptor{push("application/vnd.gadget.ebpf.program.v1+binary", read("IG_EXEC_BPF_OBJECT"))}
	raw, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: cfg, Layers: layers})
	require.NoError(t, err)
	desc := push(ocispec.MediaTypeImageManifest, raw)
	desc.Platform = &ocispec.Platform{Architecture: goruntime.GOARCH, OS: "linux"}
	raw, err = json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}})
	require.NoError(t, err)
	desc = push(ocispec.MediaTypeImageIndex, raw)
	const image = "ghcr.io/inspektor-gadget/gadget/enforce_exec:native-runtime-test"
	require.NoError(t, store.Tag(ctx, desc, image))

	return store, image
}
