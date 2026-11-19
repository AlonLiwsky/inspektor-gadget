// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func poolReaperTestInstance(gc operators.GadgetContext) *ebpfInstance {
	config := viper.New()
	config.Set("annotations.enforce-exec-shared-recovery", "1")
	return &ebpfInstance{
		config: config, logger: gc.Logger(),
		collectionSpec: &ebpf.CollectionSpec{
			Maps: map[string]*ebpf.MapSpec{
				"se_pool_reap_stage": {Type: ebpf.Array, KeySize: 4, ValueSize: 144, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
				"se_pool_reap_chain": {Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 1},
			},
			Programs: map[string]*ebpf.ProgramSpec{
				"se_pool_reaper_entry": {Name: "se_pool_reaper_entry", Type: ebpf.SchedCLS, SectionName: "tc"},
				"se_pool_reaper_chunk": {Name: "se_pool_reaper_chunk", Type: ebpf.SchedCLS, SectionName: "tc"},
			},
		},
		collection: &ebpf.Collection{
			Maps:     map[string]*ebpf.Map{},
			Programs: map[string]*ebpf.Program{},
		},
	}
}

func TestPoolReaperChainRequiresCompleteTrustedCollection(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	i := &ebpfInstance{collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}}}
	if err := i.installNativePoolReaperChain(gc); err != nil {
		t.Fatalf("ordinary collection changed: %v", err)
	}
	i = poolReaperTestInstance(gc)
	delete(i.collectionSpec.Programs, "se_pool_reaper_chunk")
	if err := i.installNativePoolReaperChain(gc); err == nil {
		t.Fatal("partial reaper inventory accepted")
	}
	i = poolReaperTestInstance(gc)
	delete(i.collectionSpec.Maps, "se_pool_reap_chain")
	if err := i.installNativePoolReaperChain(gc); err == nil {
		t.Fatal("missing program array accepted")
	}
	i = poolReaperTestInstance(gc)
	if err := i.installNativePoolReaperChain(gc); err == nil {
		t.Fatal("unselected reaper accepted")
	}
	gc.SetVar(operators.NativeRecoveryTestRunKey, true)
	gc.SetVar(operators.NativeOwnerRequiredKey, true)
	gc.SetVar(operators.NativeResourceValidatorKey, func(*operators.NativeResources) error { return nil })
	i = poolReaperTestInstance(gc)
	if err := i.installNativePoolReaperChain(gc); err == nil {
		t.Fatal("reaper accepted without final admission")
	}
	i.recoveryTestRunAdmitted = true
	i.collectionSpec.Maps["se_pool_reap_stage"].Flags = 0
	if err := i.installNativePoolReaperChain(gc); err == nil {
		t.Fatal("userspace-writable reaper stage accepted")
	}
	i = poolReaperTestInstance(gc)
	i.recoveryTestRunAdmitted = true
	if err := i.installNativePoolReaperChain(gc); err == nil {
		t.Fatal("missing loaded map/program handles accepted")
	}
}

// Opt-in local-kernel installer proof. This is not a selected policy, kernel
// matrix, or real reaper visitor test; it exercises exact slot readback.
func TestPoolReaperChainKernelInstallation(t *testing.T) {
	if os.Getenv("IG_NATIVE_POOL_REAPER_INSTALL_TEST") != "1" {
		t.Skip("set IG_NATIVE_POOL_REAPER_INSTALL_TEST=1 on an isolated BPF-capable host")
	}
	gc := newResolverGadgetCtx(t, nil)
	gc.SetVar(operators.NativeRecoveryTestRunKey, true)
	gc.SetVar(operators.NativeOwnerRequiredKey, true)
	gc.SetVar(operators.NativeResourceValidatorKey, func(*operators.NativeResources) error { return nil })
	i := poolReaperTestInstance(gc)
	i.recoveryTestRunAdmitted = true
	stage, err := ebpf.NewMap(i.collectionSpec.Maps["se_pool_reap_stage"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stage.Close() })
	chain, err := ebpf.NewMap(i.collectionSpec.Maps["se_pool_reap_chain"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { chain.Close() })
	program := &ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}}
	entry, err := ebpf.NewProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { entry.Close() })
	chunk, err := ebpf.NewProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { chunk.Close() })
	i.collection.Maps["se_pool_reap_stage"] = stage
	i.collection.Maps["se_pool_reap_chain"] = chain
	i.collection.Programs["se_pool_reaper_entry"] = entry
	i.collection.Programs["se_pool_reaper_chunk"] = chunk
	if err := i.installNativePoolReaperChain(gc); err != nil {
		t.Fatal(err)
	}
	if err := i.installNativePoolReaperChain(gc); err == nil {
		t.Fatal("prepopulated program array accepted on a second installation")
	}
}
