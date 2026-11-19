// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
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

// Only explicitly supplied, locally built object/metadata bytes enter this
// in-memory OCI store. Disabling registry signature lookup here is not a general
// image-input policy and does not change production image verification.
func trustedFullImage(t *testing.T, imageCapability bool) (*memory.Store, string) {
	t.Helper()
	ctx := context.Background()
	store := memory.New()
	read := func(env string) []byte {
		p := os.Getenv(env)
		require.NotEmpty(t, p)
		b, e := os.ReadFile(p)
		require.NoError(t, e)
		return b
	}
	push := func(media string, b []byte) ocispec.Descriptor {
		d := content.NewDescriptorFromBytes(media, b)
		require.NoError(t, store.Push(ctx, d, bytes.NewReader(b)))
		return d
	}
	metadata := read("IG_FULL_EXEC_METADATA")
	if imageCapability {
		// Explicit local test attestation only; do not alter arbitrary image inputs.
		var document map[string]interface{}
		require.NoError(t, yaml.Unmarshal(metadata, &document))
		annotations, ok := document["annotations"].(map[string]interface{})
		require.True(t, ok)
		features, ok := annotations["enforce-exec-full-features"].(string)
		require.True(t, ok)
		annotations["enforce-exec-full-features"] = features + ",image"
		var err error
		metadata, err = yaml.Marshal(document)
		require.NoError(t, err)
	}
	cfg := push("application/vnd.gadget.config.v1+yaml", metadata)
	layer := push("application/vnd.gadget.ebpf.program.v1+binary", read("IG_FULL_EXEC_BPF_OBJECT"))
	raw, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: cfg, Layers: []ocispec.Descriptor{layer}})
	require.NoError(t, err)
	manifest := push(ocispec.MediaTypeImageManifest, raw)
	manifest.Platform = &ocispec.Platform{Architecture: goruntime.GOARCH, OS: "linux"}
	raw, err = json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{manifest}})
	require.NoError(t, err)
	desc := push(ocispec.MediaTypeImageIndex, raw)
	const image = "localhost/enforce-exec-full:trusted-disposable-test"
	require.NoError(t, store.Tag(ctx, desc, image))
	return store, image
}

func TestFullExecRuntime(t *testing.T)      { testFullExecRuntime(t, false) }
func TestFullExecRuntimeImage(t *testing.T) { testFullExecRuntime(t, true) }
func testFullExecRuntime(t *testing.T, imageCapability bool) {
	if os.Getenv("IG_FULL_EXEC_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel opt-in required")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, image := trustedFullImage(t, imageCapability)
	rt := local.New()
	require.NoError(t, rt.Init(nil))
	defer rt.Close()
	manager, err := instancemanager.New(rt)
	require.NoError(t, err)
	cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-full-native-%d", os.Getpid())
	require.NoError(t, os.Mkdir(cgpath, 0o755))
	defer os.Remove(cgpath)
	cg, err := os.Open(cgpath)
	require.NoError(t, err)
	defer cg.Close()
	var stat syscall.Stat_t
	require.NoError(t, syscall.Fstat(int(cg.Fd()), &stat))
	identity := execruntime.ContainerIdentity{Runtime: "containerd", ID: "full-native-test", CgroupID: stat.Ino, CgroupPath: "/" + filepath.Base(cgpath)}
	temp := t.TempDir()
	first, second := filepath.Join(temp, "first"), filepath.Join(temp, "second")
	binary, err := os.ReadFile("/usr/bin/true")
	require.NoError(t, err)
	for _, p := range []string{first, second} {
		require.NoError(t, os.WriteFile(p, binary, 0o755))
	}
	run := func(path string, args ...string) error {
		cmd := exec.Command(path, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
		return cmd.Run()
	}
	config := func(path string, generation uint64) execruntime.Config {
		target := fullpolicy.Target{Path: []string{path}, Argv: &fullpolicy.Argv{Contains: []string{"safe"}}}
		if imageCapability {
			value := true
			target.FromImage = &value
		}
		program, e := fullpolicy.CompileKernel([]fullpolicy.Policy{{ID: "p", Revision: fmt.Sprint(generation), Mode: fullpolicy.Enforce, Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{{Name: "allowed", Action: fullpolicy.Allow, Target: target}}}}, generation, "worker")
		require.NoError(t, e)
		result := execruntime.Config{Full: program, Entries: [execpolicy.KernelMaxRules + 1]execpolicy.KernelEntry{{Generation: generation, Mode: 2}}, InitialBindings: []execruntime.ContainerIdentity{identity}}
		if imageCapability {
			// Synthetic controlled backing membership proves native plumbing,
			// not the production owner's complete lower-root construction.
			var backing syscall.Stat_t
			require.NoError(t, syscall.Stat(path, &backing))
			result.ImageOrigins = &execruntime.ImageOriginSnapshot{Complete: true, Keys: []execruntime.ImageOriginKey{{Inode: backing.Ino, Major: unix.Major(uint64(backing.Dev)), Minor: unix.Minor(uint64(backing.Dev))}}}
		}
		return result
	}
	contexts := map[string]operators.GadgetContext{}
	options := func(id string, c execruntime.Config, fail bool) []gadgetcontext.Option {
		handler := ocihandler.New()
		p := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
		require.NoError(t, p.Set("verify-image", "false"))
		require.NoError(t, p.Set("allow-enforcement", "true"))
		require.NoError(t, handler.Init(p))
		capture := simple.New("capture", simple.WithPriority(100), simple.OnStart(func(gc operators.GadgetContext) error {
			contexts[id] = gc
			if fail {
				return errors.New("injected late candidate failure")
			}
			return nil
		}))
		return []gadgetcontext.Option{gadgetcontext.WithOrasReadonlyTarget(store), gadgetcontext.WithAdditionalDataOperators(handler, execruntime.New(), capture), execruntime.WithConfig(c)}
	}
	desired := func(id string) *api.GadgetInstance {
		return &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: image}}
	}
	defer func() {
		for _, id := range []string{"old", "bad", "late", "new", "missing-index", "incomplete-index"} {
			if manager.LookupInstance(id) != nil {
				require.NoError(t, manager.StopGadget(context.Background(), id))
			}
		}
	}()
	require.NoError(t, manager.StartGadget(ctx, desired("old"), options("old", config(first, 101), false)...))
	old, err := execruntime.GetBindings(contexts["old"])
	require.NoError(t, err)
	require.True(t, old.Status().Ready)
	require.Equal(t, 1, old.Status().Bound)
	require.NoError(t, run(first, "safe"))
	require.ErrorIs(t, run(second, "safe"), syscall.EPERM)
	value, _ := contexts["old"].GetVar(operators.MapPrefix + "full_program")
	require.ErrorIs(t, value.(*ebpf.Map).Put(uint32(0), fullpolicy.Blob{}), syscall.EPERM)
	if imageCapability {
		for _, name := range []string{"missing-index", "incomplete-index"} {
			candidate := config(second, 102)
			if name == "missing-index" {
				candidate.ImageOrigins = nil
			} else {
				candidate.ImageOrigins.Complete = false
			}
			require.Error(t, manager.ReplaceGadget(ctx, "old", desired(name), options(name, candidate, false)...))
			require.NotNil(t, manager.LookupInstance("old"))
			require.Nil(t, manager.LookupInstance(name))
			require.True(t, old.Status().Ready)
			require.NoError(t, run(first, "safe"))
			require.ErrorIs(t, run(second, "safe"), syscall.EPERM)
		}
		index, _ := contexts["old"].GetVar(operators.MapPrefix + "image_origins")
		require.ErrorIs(t, index.(*ebpf.Map).Put(execruntime.ImageOriginKey{Inode: 1}, uint8(1)), syscall.EPERM)
		ready, _ := contexts["old"].GetVar(operators.MapPrefix + "image_ready")
		require.ErrorIs(t, ready.(*ebpf.Map).Put(uint32(0), uint32(0)), syscall.EPERM)
	}
	invalid := config(second, 102)
	invalid.InitialBindings[0].CgroupID = 0
	require.Error(t, manager.ReplaceGadget(ctx, "old", desired("bad"), options("bad", invalid, false)...))
	require.NotNil(t, manager.LookupInstance("old"))
	require.Nil(t, manager.LookupInstance("bad"))
	require.NoError(t, run(first, "safe"))
	require.Error(t, manager.ReplaceGadget(ctx, "old", desired("late"), options("late", config(second, 102), true)...))
	require.NotNil(t, manager.LookupInstance("old"))
	require.Nil(t, manager.LookupInstance("late"))
	require.NoError(t, run(first, "safe"))
	require.ErrorIs(t, run(second, "safe"), syscall.EPERM)
	require.NoError(t, manager.ReplaceGadget(ctx, "old", desired("new"), options("new", config(second, 103), false)...))
	require.Nil(t, manager.LookupInstance("old"))
	current, err := execruntime.GetBindings(contexts["new"])
	require.NoError(t, err)
	require.True(t, current.Status().Ready)
	require.Equal(t, uint64(103), current.Status().Revision)
	require.NoError(t, run(second, "safe"))
	require.ErrorIs(t, run(first, "safe"), syscall.EPERM)
	require.NoError(t, current.Unbind(identity))
	require.NoError(t, run(first))
	require.Equal(t, 0, current.Status().Bound)
	require.NoError(t, current.Bind(identity))
	require.ErrorIs(t, run(first, "safe"), syscall.EPERM)
	// Unsupported runtime observation must become NotReady without removing protection.
	args := make([]string, 65)
	for i := range args {
		args[i] = "safe"
	}
	require.ErrorIs(t, run(second, args...), syscall.EPERM)
	status := current.Status()
	require.False(t, status.Ready)
	require.Error(t, status.Error)
	require.Equal(t, 1, status.Bound)
	require.NoError(t, current.Unbind(identity))
	require.NoError(t, manager.StopGadget(ctx, "new"))
	require.NoError(t, run(first))
}
