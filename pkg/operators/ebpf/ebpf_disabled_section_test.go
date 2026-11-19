// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/tchandler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/uprobetracer"
)

func TestInitProgramTracersSkipsDisabledSections(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	newInstance := func(disabled bool, specs ...*ebpf.ProgramSpec) *ebpfInstance {
		config := viper.New()
		programs := map[string]*ebpf.ProgramSpec{}
		for _, spec := range specs {
			if disabled {
				config.Set("programs."+spec.Name+".attach_to", disabledProgram)
			}
			programs[spec.Name] = spec
		}
		return &ebpfInstance{
			config: config, logger: gc.Logger(),
			collectionSpec: &ebpf.CollectionSpec{Programs: programs},
			networkTracers: map[string]*networktracer.Tracer[api.GadgetData]{},
			tcHandlers:     map[string]*tchandler.Handler{},
			uprobeTracers:  map[string]*uprobetracer.Tracer[api.GadgetData]{},
		}
	}
	prog := func(name string, typ ebpf.ProgramType, section string) *ebpf.ProgramSpec {
		return &ebpf.ProgramSpec{Name: name, Type: typ, SectionName: section, Instructions: asm.Instructions{asm.Return()}}
	}

	// Disabled programs of any kind select no tracer and their section is not parsed.
	i := newInstance(true,
		prog("seed", ebpf.SchedCLS, "tc"),
		prog("bad", ebpf.SchedCLS, "classifier/sideways/x"),
		prog("sock", ebpf.SocketFilter, "socket"),
		prog("up", ebpf.Kprobe, "uprobe/bin:sym"))
	if err := i.initProgramTracers(gc); err != nil {
		t.Fatalf("disabled programs: %v", err)
	}
	if len(i.tcHandlers)+len(i.networkTracers)+len(i.uprobeTracers) != 0 {
		t.Fatal("disabled programs created tracers or handlers")
	}

	// Ordinary gadgets are unchanged: enabled malformed sections still fail.
	for _, spec := range []*ebpf.ProgramSpec{
		prog("seed", ebpf.SchedCLS, "tc"),
		prog("bad", ebpf.SchedCLS, "classifier/sideways/x"),
		prog("nclass", ebpf.SchedCLS, "other/ingress/x"),
	} {
		if err := newInstance(false, spec).initProgramTracers(gc); err == nil || !strings.Contains(err.Error(), "invalid section name") && !strings.Contains(err.Error(), "unsupported hook type") {
			t.Fatalf("enabled %q: got %v", spec.SectionName, err)
		}
	}

	// Recovery refusals still run first: a disabled pool reaper is refused
	// without recovery TEST_RUN selection.
	if err := newInstance(true, prog("se_pool_reaper_entry", ebpf.SchedCLS, "tc")).initProgramTracers(gc); err == nil {
		t.Fatal("disabled pool reaper admitted without recovery selection")
	}
}
