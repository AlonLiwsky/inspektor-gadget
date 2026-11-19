// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

type fakeMap struct {
	values map[uint64]uint64
	err    error
}

func (m *fakeMap) Put(k, v interface{}) error {
	if m.err != nil {
		return m.err
	}
	m.values[k.(uint64)] = v.(uint64)
	return nil
}

func (m *fakeMap) Delete(k interface{}) error {
	if m.err != nil {
		return m.err
	}
	delete(m.values, k.(uint64))
	return nil
}

func controller() (*Bindings, *fakeMap) {
	m := &fakeMap{values: map[uint64]uint64{}}
	return &Bindings{config: Config{Entries: [execpolicy.KernelMaxRules + 1]execpolicy.KernelEntry{{Generation: 7}}}, ready: true, hostNamespaceSupported: true, members: m, active: map[uint64]ContainerIdentity{}, desired: map[execpolicy.Container]ContainerIdentity{}}, m
}

func identity(id uint64) ContainerIdentity {
	return ContainerIdentity{Runtime: "containerd", ID: fmt.Sprint(id), CgroupID: id, CgroupPath: fmt.Sprintf("/test/%d", id)}
}

func TestMembershipIdentityAndFailure(t *testing.T) {
	b, m := controller()
	c := identity(1)
	require.NoError(t, b.Bind(c))
	require.NoError(t, b.Bind(c))
	require.Len(t, m.values, 1)
	stale := c
	stale.ID = "old"
	require.NoError(t, b.Unbind(stale))
	require.Len(t, m.values, 1)
	require.Error(t, b.Bind(stale))
	moved := c
	moved.CgroupID = 2
	require.Error(t, b.Bind(moved))
	m.err = errors.New("map failure")
	require.Error(t, b.Unbind(c))
	require.Equal(t, 1, b.Status().Bound)
	require.Error(t, b.Bind(identity(3)))
	require.Equal(t, 1, b.Status().Bound)
	require.Error(t, b.Status().Error)
	m.err = nil
	require.NoError(t, b.Unbind(c))
	require.Zero(t, b.Status().Bound)
	for _, invalid := range []ContainerIdentity{{}, {Runtime: "r", ID: "i", CgroupID: 1, CgroupPath: "/"}, {Runtime: "r", ID: "i", CgroupID: 1, CgroupPath: "/a/../b"}} {
		require.Error(t, b.Bind(invalid))
	}
	require.NoError(t, b.Stop(nil))
	require.Error(t, b.Bind(c))
	require.Error(t, b.Unbind(c))
	require.False(t, b.Status().Ready)
}

func TestMembershipCapacityAndConcurrentChurn(t *testing.T) {
	b, _ := controller()
	for i := uint64(1); i <= execpolicy.KernelMaxBindings; i++ {
		require.NoError(t, b.Bind(identity(i)))
	}
	require.Error(t, b.Bind(identity(execpolicy.KernelMaxBindings+1)))
	require.NoError(t, b.Unbind(identity(1)))
	require.NoError(t, b.Bind(identity(execpolicy.KernelMaxBindings+1)))
	var wg sync.WaitGroup
	for i := uint64(2); i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if err := b.Unbind(identity(i)); err != nil {
					t.Error(err)
				}
				if err := b.Bind(identity(i)); err != nil {
					t.Error(err)
				}
				b.Status()
			}
		}()
	}
	wg.Wait()
	require.Equal(t, execpolicy.KernelMaxBindings, b.Status().Bound)
}

func TestStartupSnapshotCoalescing(t *testing.T) {
	b, _ := controller()
	b.ready = false
	c := identity(1)
	b.config.Targets = []execpolicy.Container{c.selector()}
	require.NoError(t, b.container("CREATED", identity(2)))
	require.Empty(t, b.desired)
	require.NoError(t, b.container("CREATED", c))
	require.Len(t, b.desired, 1)
	stale := c
	stale.CgroupID = 8
	require.NoError(t, b.container("DELETED", stale))
	require.Len(t, b.desired, 1)
	require.NoError(t, b.container("DELETED", c))
	require.Empty(t, b.desired)
	require.NoError(t, b.container("CREATED", c))
	require.Equal(t, c, b.desired[c.selector()])
	require.Error(t, b.Bind(c), "startup cannot be bypassed")
	invalid := c
	invalid.CgroupPath = "/"
	require.Error(t, b.container("CREATED", invalid))
	require.Error(t, b.lastError)
	require.Error(t, b.Start(nil), "bad replay must fail startup before accessing maps")
}

func TestNativeConfigurationGuard(t *testing.T) {
	gc := gadgetcontext.New(context.Background(), "test")
	instance, err := New().InstantiateDataOperator(gc, nil)
	require.NoError(t, err)
	require.Nil(t, instance)
	require.NoError(t, gc.SetMetadata([]byte("annotations:\n  enforce-exec: true\n")))
	_, err = New().InstantiateDataOperator(gc, nil)
	require.ErrorContains(t, err, "native policy configuration")
	config := Config{Entries: [execpolicy.KernelMaxRules + 1]execpolicy.KernelEntry{{Generation: 1, Mode: 2, DefaultDeny: 1}}, InitialBindings: []ContainerIdentity{identity(1)}}
	option := WithConfig(config)
	config.InitialBindings[0].ID = "mutated"
	option(gc)
	instance, err = New().InstantiateDataOperator(gc, nil)
	require.NoError(t, err)
	b := instance.(*Bindings)
	require.Equal(t, identity(1), b.desired[identity(1).selector()])
	require.Error(t, b.Start(gc), "missing kernel maps cannot claim readiness")
	require.False(t, b.Status().Ready)
	config.Targets = []execpolicy.Container{{Runtime: "r", ID: "id"}}
	WithConfig(config)(gc)
	_, err = New().InstantiateDataOperator(gc, nil)
	require.ErrorContains(t, err, "containers datasource")
}

func TestFinalReadinessRetainsLateBindingFailures(t *testing.T) {
	for _, source := range []string{"discovery", "native-bind", "native-unbind"} {
		t.Run(source, func(t *testing.T) {
			b, m := controller() // map installation completed; later operators may still start
			first, second := identity(1), identity(2)
			b.config.Targets = []execpolicy.Container{first.selector(), second.selector()}
			require.NoError(t, b.Bind(first))
			require.False(t, b.Status().Ready, "map availability alone is not instance readiness")
			fault := errors.New("binding map exhausted")
			m.err = fault
			switch source {
			case "discovery":
				require.ErrorIs(t, b.container("CREATED", second), fault)
			case "native-bind":
				require.ErrorIs(t, b.Bind(second), fault)
			case "native-unbind":
				require.ErrorIs(t, b.Unbind(first), fault)
			}
			m.err = nil
			require.NoError(t, b.Bind(identity(3)), "unrelated success must not erase failed coverage")
			require.ErrorIs(t, b.Ready(nil), fault)
			require.False(t, b.Status().Ready)
		})
	}
}

func TestReadinessSeparatesStartupFromRuntimeErrors(t *testing.T) {
	b, m := controller()
	require.NoError(t, b.Bind(identity(1)))
	require.NoError(t, b.Ready(nil))
	require.True(t, b.Status().Ready)
	m.err = errors.New("live write failure")
	require.Error(t, b.Bind(identity(2)))
	require.Error(t, b.Status().Error)
	require.Nil(t, b.startupError, "post-readiness failures are reported to the active owner")
	require.NoError(t, b.Stop(nil))
	require.Error(t, b.Ready(nil))
}

func fullConfig(t *testing.T) Config {
	t.Helper()
	program, err := fullpolicy.CompileKernel([]fullpolicy.Policy{{ID: "policy", Revision: "revision", Mode: fullpolicy.Enforce, Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{{
		Name: "allow-tool", Action: fullpolicy.Allow,
		Actor:  fullpolicy.Actor{Path: []string{"/usr/**"}, Ancestor: &fullpolicy.Ancestor{Path: []string{"/sbin/init"}, Depth: 3}, UID: []int64{0}, Container: []string{"worker"}},
		Target: fullpolicy.Target{Path: []string{"/bin/tool"}, Argv: &fullpolicy.Argv{Contains: []string{"--safe"}, Prefix: []string{"tool"}}},
	}}}}, 7, "worker")
	require.NoError(t, err)
	return Config{Full: program, Entries: [execpolicy.KernelMaxRules + 1]execpolicy.KernelEntry{{Generation: 7, Mode: 2}}, InitialBindings: []ContainerIdentity{identity(1)}}
}

func newFullBindings(t *testing.T, config Config) *Bindings {
	t.Helper()
	gc := gadgetcontext.New(context.Background(), "test-full")
	require.NoError(t, gc.SetMetadata([]byte("annotations:\n  enforce-exec: true\n  enforce-exec-full: true\n  enforce-exec-full-features: path,uid,argv,actor-path,ancestor,fs\n  enforce-exec-host-namespace: true\n")))
	WithConfig(config)(gc)
	instance, err := New().InstantiateDataOperator(gc, nil)
	require.NoError(t, err)
	return instance.(*Bindings)
}

func TestFullConfigurationImageGuards(t *testing.T) {
	for _, tc := range []struct {
		name, metadata string
		full           bool
		valid          bool
	}{
		{"full-matching", "enforce-exec: true\n  enforce-exec-full: true\n  enforce-exec-full-features: path,uid,argv,actor-path,ancestor", true, true},
		{"full-on-legacy", "enforce-exec: true", true, false},
		{"nil-on-full", "enforce-exec: true\n  enforce-exec-full: true", false, false},
		{"full-annotation-alone", "enforce-exec-full: true", true, false},
		{"full-config-unmarked", "unrelated: true", true, false},
		{"legacy-unchanged", "enforce-exec: true", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gc := gadgetcontext.New(context.Background(), "test")
			require.NoError(t, gc.SetMetadata([]byte("annotations:\n  "+tc.metadata+"\n")))
			config := fullConfig(t)
			if !tc.full {
				config.Full = nil
			}
			WithConfig(config)(gc)
			instance, err := New().InstantiateDataOperator(gc, nil)
			if tc.valid {
				require.NoError(t, err)
				require.NotNil(t, instance)
			} else {
				require.Error(t, err)
				require.Nil(t, instance)
			}
		})
	}
	gc := gadgetcontext.New(context.Background(), "missing-native-config")
	require.NoError(t, gc.SetMetadata([]byte("annotations:\n  enforce-exec-full: true\n")))
	_, err := New().InstantiateDataOperator(gc, nil)
	require.Error(t, err, "full image cannot silently bypass native enforcement")
}

func TestFullConfigurationSnapshot(t *testing.T) {
	config := fullConfig(t)
	option := WithConfig(config)
	expectedBlob := config.Full.Entries[0]
	expectedRule := config.Full.Rules[0]
	var expectedID uint64
	var expectedName string
	for id, name := range config.Full.Identities {
		expectedID, expectedName = id, name
		break
	}
	config.Full.Entries[0] = fullpolicy.Blob{}
	config.Full.Rules[0].Name = "mutated"
	config.Full.Identities[expectedID] = "mutated"
	gc := gadgetcontext.New(context.Background(), "snapshot")
	option(gc)
	raw, _ := gc.GetVar(configKey)
	snapshot := raw.(Config)
	require.Equal(t, expectedBlob, snapshot.Full.Entries[0])
	require.Equal(t, expectedRule, snapshot.Full.Rules[0])
	require.Equal(t, expectedName, snapshot.Full.Identities[expectedID])
	require.NoError(t, fullpolicy.ValidateKernelProgram(snapshot.Full))
}

func TestFullCapabilityAndHeaderRefusals(t *testing.T) {
	for _, feature := range []string{"actor-role", "set-role", "actor-image", "target-image"} {
		t.Run(feature, func(t *testing.T) {
			rule := fullpolicy.Rule{Name: "rule", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{"/bin/tool"}}}
			no := false
			switch feature {
			case "actor-role":
				rule.Actor.Role = []string{"agent"}
			case "set-role":
				rule.Target.SetRole = "worker"
			case "actor-image":
				rule.Actor.FromImage = &no
			case "target-image":
				rule.Target.FromImage = &no
			}
			program, err := fullpolicy.CompileKernel([]fullpolicy.Policy{{ID: "p", Revision: "r", Mode: fullpolicy.Enforce, Rules: []fullpolicy.Rule{rule}}}, 7, "worker")
			require.NoError(t, err)
			config := fullConfig(t)
			config.Full = program
			require.Error(t, validatePolicyConfig(config, true))
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"generation", func(c *Config) { c.Entries[0].Generation++ }},
		{"mode", func(c *Config) { c.Entries[0].Mode = 1 }},
		{"default", func(c *Config) { c.Entries[0].DefaultDeny = 1 }},
		{"legacy-rules", func(c *Config) {
			c.Entries[0].Count = 1
			c.Entries[1] = execpolicy.KernelEntry{Length: 1, Path: [256]byte{'/'}}
		}},
		{"forged-full", func(c *Config) { c.Full.Entries[0] = fullpolicy.Blob{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := fullConfig(t)
			tc.mutate(&config)
			require.Error(t, validatePolicyConfig(config, true))
		})
	}
	b := newFullBindings(t, fullConfig(t))
	require.False(t, b.hostNamespaceSupported, "full images never infer restricted helper exemptions")
}

type fakeImmutableMap struct {
	kind                                ebpf.MapType
	keySize, valueSize, capacity, flags uint32
	name                                string
	events                              *[]string
	values                              map[interface{}]interface{}
	putFailAt                           int
	puts                                int
	frozen                              bool
	putErr, freezeErr                   error
}

func (m *fakeImmutableMap) Type() ebpf.MapType { return m.kind }
func (m *fakeImmutableMap) KeySize() uint32    { return m.keySize }
func (m *fakeImmutableMap) ValueSize() uint32  { return m.valueSize }
func (m *fakeImmutableMap) MaxEntries() uint32 { return m.capacity }
func (m *fakeImmutableMap) Flags() uint32      { return m.flags }
func (m *fakeImmutableMap) Put(key, value interface{}) error {
	*m.events = append(*m.events, m.name+":put")
	m.puts++
	if m.putErr != nil && (m.putFailAt == 0 || m.puts == m.putFailAt) {
		return m.putErr
	}
	if m.frozen {
		return errors.New("frozen")
	}
	m.values[key] = value
	return nil
}
func (m *fakeImmutableMap) Delete(key interface{}) error { delete(m.values, key); return nil }
func (m *fakeImmutableMap) Freeze() error {
	*m.events = append(*m.events, m.name+":freeze")
	if m.freezeErr != nil {
		return m.freezeErr
	}
	m.frozen = true
	return nil
}

func fullMaps() (*fakeImmutableMap, *fakeImmutableMap, *fakeImmutableMap, *[]string) {
	events := []string{}
	makeMap := func(name string, kind ebpf.MapType, key, value, capacity, flags uint32) *fakeImmutableMap {
		return &fakeImmutableMap{name: name, kind: kind, keySize: key, valueSize: value, capacity: capacity, flags: flags, events: &events, values: map[interface{}]interface{}{}}
	}
	return makeMap("policy", ebpf.Array, 4, 288, execpolicy.KernelMaxRules+1, unix.BPF_F_RDONLY_PROG), makeMap("bindings", ebpf.Hash, 8, 8, execpolicy.KernelMaxBindings, 0), makeMap("full", ebpf.Hash, 4, fullpolicy.KernelBlobSize, fullpolicy.MaxKernelEntries, unix.BPF_F_RDONLY_PROG), &events
}

func TestFullMapsFreezeBeforeStrictBinding(t *testing.T) {
	config := fullConfig(t)
	b := newFullBindings(t, config)
	policy, members, full, events := fullMaps()
	require.NoError(t, b.startMaps(policy, members, full, fullFaultMap(), fakeImageMaps()))
	require.True(t, policy.frozen)
	require.True(t, full.frozen)
	require.Equal(t, len(config.Full.Entries), full.puts)
	require.Equal(t, []string{"full:freeze", "bindings:put"}, (*events)[len(*events)-2:])
	require.Equal(t, uint64(0), members.values[identity(1).CgroupID], "strict membership value")
	require.False(t, b.Status().Ready, "native final readiness barrier still required")
	require.NoError(t, b.Ready(nil))
	require.True(t, b.Status().Ready)
	writes := full.puts
	require.ErrorContains(t, b.startMaps(policy, members, full, fullFaultMap(), fakeImageMaps()), "already started")
	require.Equal(t, writes, full.puts, "no full-map updates in place")
}

func TestFullMapFailuresNeverPublishBindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fakeImmutableMap, *fakeImmutableMap, *fakeImmutableMap)
	}{
		{"full-type", func(_, _, f *fakeImmutableMap) { f.kind = ebpf.Array }},
		{"full-key", func(_, _, f *fakeImmutableMap) { f.keySize = 8 }},
		{"full-value", func(_, _, f *fakeImmutableMap) { f.valueSize = 280 }},
		{"full-capacity", func(_, _, f *fakeImmutableMap) { f.capacity-- }},
		{"full-not-readonly", func(_, _, f *fakeImmutableMap) { f.flags = 0 }},
		{"full-write", func(_, _, f *fakeImmutableMap) { f.putErr = errors.New("write failure") }},
		{"full-partial-write", func(_, _, f *fakeImmutableMap) { f.putErr = errors.New("late write failure"); f.putFailAt = 3 }},
		{"full-freeze", func(_, _, f *fakeImmutableMap) { f.freezeErr = errors.New("freeze failure") }},
		{"policy-write", func(p, _, _ *fakeImmutableMap) { p.putErr = errors.New("write failure") }},
		{"policy-freeze", func(p, _, _ *fakeImmutableMap) { p.freezeErr = errors.New("freeze failure") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newFullBindings(t, fullConfig(t))
			p, m, f, _ := fullMaps()
			tc.mutate(p, m, f)
			require.Error(t, b.startMaps(p, m, f, fullFaultMap(), fakeImageMaps()))
			require.Zero(t, m.puts)
			require.Zero(t, b.Status().Bound)
			require.False(t, b.ready)
		})
	}
	b := newFullBindings(t, fullConfig(t))
	p, m, _, _ := fullMaps()
	require.Error(t, b.startMaps(p, m, nil, fullFaultMap(), fakeImageMaps()))
	require.Zero(t, p.puts)
	require.Zero(t, m.puts)
	// A public native caller cannot forge data after admission and before writes.
	b.config.Full.Entries[0] = fullpolicy.Blob{}
	p, m, f, _ := fullMaps()
	require.Error(t, b.startMaps(p, m, f, fullFaultMap(), fakeImageMaps()))
	require.Zero(t, p.puts)
	require.Zero(t, f.puts)
	require.Zero(t, m.puts)
}

func TestFullFeatureAdmission(t *testing.T) {
	config := fullConfig(t)
	for _, omitted := range []string{"path", "uid", "argv", "actor-path", "ancestor"} {
		t.Run(omitted, func(t *testing.T) {
			var features []string
			for _, f := range []string{"path", "uid", "argv", "actor-path", "ancestor"} {
				if f != omitted {
					features = append(features, f)
				}
			}
			require.ErrorContains(t, validateFullFeatures(config, strings.Join(features, ",")), omitted)
		})
	}
	require.NoError(t, validateFullFeatures(config, "path,uid,argv,actor-path,ancestor"))
	for _, stdin := range []bool{false, true} {
		rule := fullpolicy.Rule{Name: "unsupported", Action: fullpolicy.Deny, Target: fullpolicy.Target{FSType: []string{"overlay"}}}
		if stdin {
			value := true
			rule.Target.FSType = nil
			rule.Target.Argv = &fullpolicy.Argv{StdinIsPipe: &value}
		}
		program, err := fullpolicy.CompileKernel([]fullpolicy.Policy{{ID: "p", Revision: "r", Mode: fullpolicy.Enforce, Rules: []fullpolicy.Rule{rule}}}, 7, "worker")
		require.NoError(t, err)
		config.Full = program
		if stdin {
			require.ErrorContains(t, validateFullFeatures(config, "path,uid,argv,actor-path,ancestor"), "stdin")
			require.NoError(t, validateFullFeatures(config, "path,uid,argv,actor-path,ancestor,stdin"))
		} else {
			require.ErrorContains(t, validateFullFeatures(config, "path,uid,argv,actor-path,ancestor,stdin"), "fs")
			require.NoError(t, validateFullFeatures(config, "path,uid,argv,actor-path,ancestor,fs,stdin"))
		}
	}
}

func fullFaultMap() *fakeImmutableMap {
	return &fakeImmutableMap{kind: ebpf.Array, keySize: 4, valueSize: 8, capacity: 1, flags: unix.BPF_F_RDONLY, values: map[interface{}]interface{}{}}
}

func (m *fakeImmutableMap) Lookup(key, out interface{}) error {
	if m.putErr != nil {
		return m.putErr
	}
	value, _ := m.values[key].(uint64)
	*out.(*uint64) = value
	return nil
}

func TestFullOperationalFaultRetainsEnforcement(t *testing.T) {
	b := newFullBindings(t, fullConfig(t))
	p, m, f, _ := fullMaps()
	faults := fullFaultMap()
	require.NoError(t, b.startMaps(p, m, f, faults, fakeImageMaps()))
	require.NoError(t, b.Ready(nil))
	require.True(t, b.Status().Ready)
	faults.values[uint32(0)] = uint64(1)
	status := b.Status()
	require.False(t, status.Ready)
	require.Error(t, status.Error)
	require.Equal(t, 1, status.Bound)
	require.Len(t, m.values, 1)
	faults.values[uint32(0)] = uint64(0)
	require.False(t, b.Status().Ready, "fault is sticky")
	require.Error(t, b.Ready(nil))
	require.NoError(t, b.Stop(nil))
	faults.putErr = errors.New("closed handle")
	require.NotContains(t, b.Status().Error.Error(), "closed handle")
}

func TestFullFaultMapRequiredBeforeBindings(t *testing.T) {
	for _, mutate := range []func(*fakeImmutableMap){func(m *fakeImmutableMap) { m.kind = ebpf.Hash }, func(m *fakeImmutableMap) { m.keySize = 8 }, func(m *fakeImmutableMap) { m.valueSize = 4 }, func(m *fakeImmutableMap) { m.capacity = 2 }, func(m *fakeImmutableMap) { m.flags = 0 }, func(m *fakeImmutableMap) { m.putErr = errors.New("lookup failed") }} {
		b := newFullBindings(t, fullConfig(t))
		p, m, f, _ := fullMaps()
		faults := fullFaultMap()
		mutate(faults)
		require.Error(t, b.startMaps(p, m, f, faults, fakeImageMaps()))
		require.Empty(t, m.values)
	}
	b := newFullBindings(t, fullConfig(t))
	p, m, f, _ := fullMaps()
	require.Error(t, b.startMaps(p, m, f, nil, fakeImageMaps()))
	require.Empty(t, m.values)
}

func fakeImageMaps() imageMaps {
	events := []string{}
	return imageMaps{origins: &fakeImmutableMap{kind: ebpf.Hash, keySize: 16, valueSize: 1, capacity: MaxImageOrigins, flags: unix.BPF_F_NO_PREALLOC | unix.BPF_F_RDONLY_PROG, events: &events, values: map[interface{}]interface{}{}}, ready: &fakeImmutableMap{kind: ebpf.Array, keySize: 4, valueSize: 4, capacity: 1, flags: unix.BPF_F_RDONLY_PROG, events: &events, values: map[interface{}]interface{}{}}}
}

func TestImageOriginSnapshotValidation(t *testing.T) {
	valid := ImageOriginKey{Inode: 42, Major: 8, Minor: 1}
	for _, snapshot := range []*ImageOriginSnapshot{
		{Complete: false},
		{Complete: true, Keys: []ImageOriginKey{{}}},
		{Complete: true, Keys: []ImageOriginKey{{Inode: 1, Major: 1 << 12}}},
		{Complete: true, Keys: []ImageOriginKey{{Inode: 1, Minor: 1 << 20}}},
		{Complete: true, Keys: []ImageOriginKey{valid, valid}},
		{Complete: true, Keys: make([]ImageOriginKey, MaxImageOrigins+1)},
	} {
		require.Error(t, validateImageOrigins(snapshot))
	}
	require.NoError(t, validateImageOrigins(nil))
	require.NoError(t, validateImageOrigins(&ImageOriginSnapshot{Complete: true}))
	require.NoError(t, validateImageOrigins(&ImageOriginSnapshot{Complete: true, Keys: []ImageOriginKey{valid}}))
	config := fullConfig(t)
	config.ImageOrigins = &ImageOriginSnapshot{Complete: true, Keys: []ImageOriginKey{valid}}
	option := WithConfig(config)
	config.ImageOrigins.Complete = false
	config.ImageOrigins.Keys[0].Inode = 99
	gc := gadgetcontext.New(context.Background(), "image-copy")
	option(gc)
	value, _ := gc.GetVar(configKey)
	copied := value.(Config)
	require.True(t, copied.ImageOrigins.Complete)
	require.Equal(t, uint64(42), copied.ImageOrigins.Keys[0].Inode)
	for _, actor := range []bool{false, true} {
		yes := true
		rule := fullpolicy.Rule{Name: "image", Action: fullpolicy.Deny}
		if actor {
			rule.Actor.FromImage = &yes
		} else {
			rule.Target.FromImage = &yes
		}
		program, err := fullpolicy.CompileKernel([]fullpolicy.Policy{{ID: "p", Revision: "r", Mode: fullpolicy.Enforce, Rules: []fullpolicy.Rule{rule}}}, 7, "worker")
		require.NoError(t, err)
		c := fullConfig(t)
		c.Full = program
		require.Error(t, validatePolicyConfig(c, true))
		c.ImageOrigins = &ImageOriginSnapshot{Complete: true}
		require.NoError(t, validatePolicyConfig(c, true))
		require.ErrorContains(t, validateFullFeatures(c, "path"), "image")
		require.NoError(t, validateFullFeatures(c, "path,image"))
	}
}

func TestImageMapsAreFrozenBeforeBindings(t *testing.T) {
	c := fullConfig(t)
	key := ImageOriginKey{Inode: 1, Major: 8, Minor: 1}
	c.ImageOrigins = &ImageOriginSnapshot{Complete: true, Keys: []ImageOriginKey{key}}
	b := newFullBindings(t, c)
	p, m, f, events := fullMaps()
	images := fakeImageMaps()
	origins := images.origins.(*fakeImmutableMap)
	ready := images.ready.(*fakeImmutableMap)
	origins.events = events
	origins.name = "origins"
	ready.events = events
	ready.name = "origin-ready"
	require.NoError(t, b.startMaps(p, m, f, fullFaultMap(), images))
	require.True(t, origins.frozen)
	require.True(t, ready.frozen)
	require.Equal(t, uint8(1), origins.values[key])
	require.Equal(t, uint32(1), ready.values[uint32(0)])
	require.Equal(t, []string{"origins:put", "origins:freeze", "origin-ready:put", "origin-ready:freeze", "bindings:put"}, (*events)[len(*events)-5:])
}

func TestImageMapFailuresPreventBindings(t *testing.T) {
	for _, mutate := range []func(imageMaps){
		func(m imageMaps) { m.origins.(*fakeImmutableMap).keySize = 8 }, func(m imageMaps) { m.origins.(*fakeImmutableMap).valueSize = 8 }, func(m imageMaps) { m.origins.(*fakeImmutableMap).capacity-- }, func(m imageMaps) { m.origins.(*fakeImmutableMap).flags = 0 },
		func(m imageMaps) { m.origins.(*fakeImmutableMap).putErr = errors.New("put") }, func(m imageMaps) { m.origins.(*fakeImmutableMap).freezeErr = errors.New("freeze") },
		func(m imageMaps) { m.ready.(*fakeImmutableMap).valueSize = 8 }, func(m imageMaps) { m.ready.(*fakeImmutableMap).kind = ebpf.Hash }, func(m imageMaps) { m.ready.(*fakeImmutableMap).flags = 0 },
		func(m imageMaps) { m.ready.(*fakeImmutableMap).putErr = errors.New("put") }, func(m imageMaps) { m.ready.(*fakeImmutableMap).freezeErr = errors.New("freeze") },
	} {
		c := fullConfig(t)
		c.ImageOrigins = &ImageOriginSnapshot{Complete: true, Keys: []ImageOriginKey{{Inode: 1}}}
		b := newFullBindings(t, c)
		p, m, f, _ := fullMaps()
		images := fakeImageMaps()
		mutate(images)
		require.Error(t, b.startMaps(p, m, f, fullFaultMap(), images))
		require.Empty(t, m.values)
	}
	c := fullConfig(t)
	b := newFullBindings(t, c)
	p, m, f, _ := fullMaps()
	require.Error(t, b.startMaps(p, m, f, fullFaultMap(), imageMaps{}))
	require.Empty(t, m.values)
}
