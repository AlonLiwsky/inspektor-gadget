// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"
)

func TestDropDisabledPrograms(t *testing.T) {
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
	i.dropDisabledPrograms()
	got := make([]string, 0, len(i.collectionSpec.Programs))
	for name := range i.collectionSpec.Programs {
		got = append(got, name)
	}
	slices.Sort(got)
	if want := []string{"cgroup_on", "kprobe_moved", "kprobe_on"}; !slices.Equal(got, want) {
		t.Fatalf("loaded programs %v, want %v", got, want)
	}
}
