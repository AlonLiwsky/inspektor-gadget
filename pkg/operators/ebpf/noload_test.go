// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"
)

func TestDropUnloadedPrograms(t *testing.T) {
	t.Parallel()
	gc := newResolverGadgetCtx(t, nil)
	config := viper.New()
	config.Set("programs.lsm_off.load", false)
	config.Set("programs.kprobe_off.load", "false")
	config.Set("programs.kprobe_on.load", true)
	config.Set("programs.lsm_disabled.attach_to", disabledProgram)
	i := &ebpfInstance{config: config, logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"lsm_off":      {Name: "lsm_off", Type: ebpf.LSM, AttachTo: "socket_connect"},
		"cgroup_on":    {Name: "cgroup_on", Type: ebpf.CGroupSockAddr},
		"kprobe_on":    {Name: "kprobe_on", Type: ebpf.Kprobe, AttachTo: "x"},
		"kprobe_off":   {Name: "kprobe_off", Type: ebpf.Kprobe, AttachTo: "x"},
		"lsm_disabled": {Name: "lsm_disabled", Type: ebpf.LSM, AttachTo: "socket_connect"},
		"spec_off":     {Name: "spec_off", Type: ebpf.Kprobe, AttachTo: disabledProgram},
	}}}
	if err := i.dropUnloadedPrograms(); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(i.collectionSpec.Programs))
	for name := range i.collectionSpec.Programs {
		got = append(got, name)
	}
	slices.Sort(got)
	// A disabled program is loaded; only load: false drops one.
	if want := []string{"cgroup_on", "kprobe_on", "lsm_disabled", "spec_off"}; !slices.Equal(got, want) {
		t.Fatalf("loaded programs %v, want %v", got, want)
	}
}

// A load value that is not a boolean is refused, so a typo does not drop a
// program silently.
func TestDropUnloadedInvalidValue(t *testing.T) {
	t.Parallel()
	gc := newResolverGadgetCtx(t, nil)
	for _, value := range []any{"no", "flase", 0} {
		config := viper.New()
		config.Set("programs.p.load", value)
		i := &ebpfInstance{config: config, logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
			"p": {Name: "p", Type: ebpf.Kprobe, AttachTo: "x"},
		}}}
		if err := i.dropUnloadedPrograms(); err == nil || !strings.Contains(err.Error(), "programs.p.load") {
			t.Errorf("load %v: got %v, want an error naming programs.p.load", value, err)
		}
	}
}

// A tail call target that is not loaded is refused before the load, with an
// error that names it. A disabled tail call target is loaded and accepted.
func TestDropUnloadedTailCallTarget(t *testing.T) {
	t.Parallel()
	gc := newResolverGadgetCtx(t, nil)
	newInstance := func(config *viper.Viper) *ebpfInstance {
		return &ebpfInstance{config: config, logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				"entry": {Name: "entry", Type: ebpf.Kprobe, AttachTo: "x"},
				"tail":  {Name: "tail", Type: ebpf.Kprobe, AttachTo: disabledProgram},
			},
			Maps: map[string]*ebpf.MapSpec{
				"tails": {Name: "tails", Type: ebpf.ProgramArray, Contents: []ebpf.MapKV{{Key: uint32(0), Value: "tail"}}},
			},
		}}
	}
	if err := newInstance(viper.New()).dropUnloadedPrograms(); err != nil {
		t.Fatalf("disabled tail call target: %v", err)
	}
	config := viper.New()
	config.Set("programs.tail.load", false)
	err := newInstance(config).dropUnloadedPrograms()
	if err == nil || !strings.Contains(err.Error(), `"tail"`) || !strings.Contains(err.Error(), `"tails"`) {
		t.Fatalf("got %v, want an error naming program tail and map tails", err)
	}
}

func TestProgramAttachTarget(t *testing.T) {
	t.Parallel()
	spec := &ebpf.ProgramSpec{Name: "p", AttachTo: "spec_target"}
	config := viper.New()
	if got := (&ebpfInstance{config: config}).programAttachTarget(spec); got != "spec_target" {
		t.Errorf("no override: got %q", got)
	}
	if got := (&ebpfInstance{}).programAttachTarget(spec); got != "spec_target" {
		t.Errorf("nil config: got %q", got)
	}
	config.Set("programs.p.attach_to", "override")
	if got := (&ebpfInstance{config: config}).programAttachTarget(spec); got != "override" {
		t.Errorf("override: got %q", got)
	}
}
