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

func TestDropDisabledPrograms(t *testing.T) {
	t.Parallel()
	gc := newResolverGadgetCtx(t, nil)
	config := viper.New()
	config.Set("programs.lsm_off.attach_to", disabledProgram)
	config.Set("programs.kprobe_moved.attach_to", "do_sys_openat2")
	i := &ebpfInstance{config: config, logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"lsm_off":      {Name: "lsm_off", Type: ebpf.LSM, AttachTo: "socket_connect"},
		"cgroup_on":    {Name: "cgroup_on", Type: ebpf.CGroupSockAddr},
		"kprobe_on":    {Name: "kprobe_on", Type: ebpf.Kprobe, AttachTo: "x"},
		"kprobe_moved": {Name: "kprobe_moved", Type: ebpf.Kprobe, AttachTo: disabledProgram},
		"spec_off":     {Name: "spec_off", Type: ebpf.Kprobe, AttachTo: disabledProgram},
	}}}
	if err := i.dropDisabledPrograms(); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(i.collectionSpec.Programs))
	for name := range i.collectionSpec.Programs {
		got = append(got, name)
	}
	slices.Sort(got)
	if want := []string{"cgroup_on", "kprobe_moved", "kprobe_on"}; !slices.Equal(got, want) {
		t.Fatalf("loaded programs %v, want %v", got, want)
	}
}

// A disabled tail call target is refused before the load, with an error that
// names it.
func TestDropDisabledTailCallTarget(t *testing.T) {
	t.Parallel()
	gc := newResolverGadgetCtx(t, nil)
	i := &ebpfInstance{config: viper.New(), logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"entry": {Name: "entry", Type: ebpf.Kprobe, AttachTo: "x"},
			"tail":  {Name: "tail", Type: ebpf.Kprobe, AttachTo: disabledProgram},
		},
		Maps: map[string]*ebpf.MapSpec{
			"tails": {Name: "tails", Type: ebpf.ProgramArray, Contents: []ebpf.MapKV{{Key: uint32(0), Value: "tail"}}},
		},
	}}
	err := i.dropDisabledPrograms()
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
