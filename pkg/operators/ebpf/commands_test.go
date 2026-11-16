// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func TestSyscallCommandsAreBorrowedNotAutomaticallyAttached(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	command, observer := new(ebpf.Program), new(ebpf.Program) // never used as real FDs
	i := &ebpfInstance{config: viper.New(), logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"control": {Name: "control", Type: ebpf.Syscall, SectionName: "syscall"}, "observer": {Name: "observer", Type: ebpf.Tracing},
	}}, collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{"control": command, "observer": observer}}}
	if err := i.publishCommandPrograms(gc); err != nil {
		t.Fatal(err)
	}
	if value, ok := gc.GetVar(operators.ProgramPrefix + "control"); !ok || value != command {
		t.Fatal("native command not connected")
	}
	if _, ok := gc.GetVar(operators.ProgramPrefix + "observer"); ok {
		t.Fatal("unrequested observer FD exposed")
	}
	if value, _ := gc.GetVar(operators.NativeLoadedProgramPrefix + "control"); value != nil {
		t.Fatal("ordinary command acquired recovery loaded-program view")
	}
	if link, err := i.attachProgram(gc, i.collectionSpec.Programs["control"], nil); err != nil || link != nil {
		t.Fatal("syscall command attempted automatic attachment", link, err)
	}
	i.collectionSpec = nil // normal Start releases the large BTF/spec before Close
	i.unpublishCommandPrograms(gc)
	if value, _ := gc.GetVar(operators.ProgramPrefix + "control"); value != nil {
		t.Fatal("command remains visible during close")
	}
}

func TestRecoveryTCProgramsAreBorrowedAndNeverAttached(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	gc.SetVar(operators.NativeOwnerRequiredKey, true)
	gc.SetVar(operators.NativeRecoveryTestRunKey, true)
	gc.SetVar(operators.NativeResourceValidatorKey, func(*operators.NativeResources) error { return nil })
	config := viper.New()
	config.Set("annotations.enforce-exec-shared-recovery", "1")
	guardian, administrator, taskHook := new(ebpf.Program), new(ebpf.Program), new(ebpf.Program)
	specs := map[string]*ebpf.ProgramSpec{
		"se_rm_guardian":      {Name: "se_rm_guardian", Type: ebpf.SchedCLS, SectionName: "tc"},
		"se_rm_administrator": {Name: "se_rm_administrator", Type: ebpf.SchedCLS, SectionName: "tc"},
		"se_task_alloc":       {Name: "se_task_alloc", Type: ebpf.LSM, SectionName: "lsm/task_alloc", AttachTo: "task_alloc"},
	}
	i := &ebpfInstance{config: config, logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: specs}, collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{
		"se_rm_guardian": guardian, "se_rm_administrator": administrator, "se_task_alloc": taskHook,
	}}}
	if err := i.publishCommandPrograms(gc); err == nil {
		t.Fatal("recovery programs published before final admission")
	}
	if value, _ := gc.GetVar(operators.NativeLoadedProgramPrefix + "se_task_alloc"); value != nil {
		t.Fatal("recovery loaded program published before final admission")
	}
	if l, err := i.attachProgram(gc, specs["se_rm_guardian"], guardian); err == nil || l != nil {
		t.Fatalf("unadmitted recovery program attached: link=%v err=%v", l, err)
	}
	if err := i.validateNativeResources(gc); err != nil {
		t.Fatal(err)
	}
	if err := i.publishCommandPrograms(gc); err != nil {
		t.Fatal(err)
	}
	for name, want := range i.collection.Programs {
		if got, _ := gc.GetVar(operators.NativeLoadedProgramPrefix + name); got != want {
			t.Fatalf("%s missing from admitted recovery loaded-program view", name)
		}
		if name == "se_task_alloc" {
			if got, _ := gc.GetVar(operators.ProgramPrefix + name); got != nil {
				t.Fatal("LSM hook exposed as invokable command")
			}
			continue
		}
		if got, _ := gc.GetVar(operators.ProgramPrefix + name); got != want {
			t.Fatalf("%s not published as a borrowed TEST_RUN program", name)
		}
		if l, err := i.attachProgram(gc, specs[name], want); err != nil || l != nil {
			t.Fatalf("%s attempted TC attachment: link=%v err=%v", name, l, err)
		}
	}
	i.unpublishCommandPrograms(gc)
	for name := range specs {
		if got, _ := gc.GetVar(operators.ProgramPrefix + name); got != nil {
			t.Fatalf("%s remains published after owner close", name)
		}
		if got, _ := gc.GetVar(operators.NativeLoadedProgramPrefix + name); got != nil {
			t.Fatalf("%s loaded-program view remains after owner close", name)
		}
	}
}

func TestRecoveryTCProgramsRequireExactTrustedSelection(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	config := viper.New()
	config.Set("annotations.enforce-exec-shared-recovery", "1")
	newInstance := func() *ebpfInstance { return &ebpfInstance{config: config, logger: gc.Logger()} }
	i := newInstance()
	valid := &ebpf.ProgramSpec{Name: "se_rm_guardian", Type: ebpf.SchedCLS, SectionName: "tc"}
	if selected, err := i.nativeRecoveryTestRunProgram(gc, valid); err != nil || selected {
		t.Fatalf("unselected recovery TC accepted: selected=%v err=%v", selected, err)
	}
	gc.SetVar(operators.NativeRecoveryTestRunKey, true)
	if _, err := i.nativeRecoveryTestRunProgram(gc, valid); err == nil {
		t.Fatal("changed selection accepted after snapshot")
	}
	i = newInstance()
	if _, err := i.nativeRecoveryTestRunProgram(gc, valid); err == nil {
		t.Fatal("recovery TC accepted without native owner")
	}
	gc.SetVar(operators.NativeOwnerRequiredKey, true)
	i = newInstance()
	if _, err := i.nativeRecoveryTestRunProgram(gc, valid); err == nil {
		t.Fatal("recovery TC accepted without resource validator")
	}
	gc.SetVar(operators.NativeResourceValidatorKey, func(*operators.NativeResources) error { return nil })
	i = &ebpfInstance{config: viper.New(), logger: gc.Logger()}
	if _, err := i.nativeRecoveryTestRunProgram(gc, valid); err == nil {
		t.Fatal("recovery TC accepted without recovered-image annotation")
	}
	for _, bad := range []*ebpf.ProgramSpec{
		{Name: "se_rm_guardian", Type: ebpf.SchedCLS, SectionName: "classifier/ingress/eth0"},
		{Name: "se_rm_guardian", Type: ebpf.SchedCLS, SectionName: "tc", AttachTo: "eth0"},
		{Name: "se_rm_guardian", Type: ebpf.Syscall, SectionName: "syscall"},
	} {
		i = newInstance()
		if _, err := i.nativeRecoveryTestRunProgram(gc, bad); err == nil {
			t.Fatalf("invalid recovery program accepted: %+v", bad)
		}
		if l, err := i.attachProgram(gc, bad, nil); err == nil || l != nil {
			t.Fatalf("invalid recovery program attached: link=%v err=%v", l, err)
		}
	}
	i = newInstance()
	i.config.Set("programs.se_rm_guardian.attach_to", "override")
	if _, err := i.nativeRecoveryTestRunProgram(gc, valid); err == nil {
		t.Fatal("overridden recovery target accepted")
	}
	i.config.Set("programs.se_rm_guardian.attach_to", "")
	if _, err := i.nativeRecoveryTestRunProgram(gc, valid); err == nil {
		t.Fatal("recovery target fault resumed after override removal")
	}
	i = newInstance()
	if selected, err := i.nativeRecoveryTestRunProgram(gc, &ebpf.ProgramSpec{Name: "other", Type: ebpf.SchedCLS, SectionName: "tc"}); err != nil || selected {
		t.Fatalf("unlisted TC program selected: selected=%v err=%v", selected, err)
	}
	if selected, err := i.nativeRecoveryTestRunProgram(gc, valid); err != nil || !selected {
		t.Fatalf("valid recovery program rejected: selected=%v err=%v", selected, err)
	}
	gc.SetVar(operators.NativeRecoveryTestRunKey, false)
	if l, err := i.attachProgram(gc, valid, nil); err == nil || l != nil {
		t.Fatalf("changed selection attached: link=%v err=%v", l, err)
	}
	gc.SetVar(operators.NativeRecoveryTestRunKey, true)
	if _, err := i.nativeRecoveryTestRunProgram(gc, valid); err == nil {
		t.Fatal("selection fault resumed after restoration")
	}
	i = &ebpfInstance{config: config, logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"command":        {Name: "command", Type: ebpf.Syscall, SectionName: "syscall"},
		"se_rm_guardian": {Name: "se_rm_guardian", Type: ebpf.SchedCLS, SectionName: "classifier/ingress/eth0"},
	}}, collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{
		"command": new(ebpf.Program), "se_rm_guardian": new(ebpf.Program),
	}}}
	if err := i.publishCommandPrograms(gc); err == nil {
		t.Fatal("invalid recovery image published programs")
	}
	if value, exists := gc.GetVar(operators.ProgramPrefix + "command"); exists && value != nil {
		t.Fatal("partially published command before recovery validation")
	}
}

func TestPoolReaperTCProgramsRequireExactTrustedSelection(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	config := viper.New()
	config.Set("annotations.enforce-exec-shared-recovery", "1")
	newInstance := func() *ebpfInstance { return &ebpfInstance{config: config, logger: gc.Logger()} }
	for _, name := range []string{"se_pool_reaper_entry", "se_pool_reaper_chunk"} {
		spec := &ebpf.ProgramSpec{Name: name, Type: ebpf.SchedCLS, SectionName: "tc"}
		i := newInstance()
		if selected, err := i.nativeRecoveryTestRunProgram(gc, spec); err == nil || selected {
			t.Fatalf("unselected %s could take ordinary TC attach path: selected=%v err=%v", name, selected, err)
		}
		if link, err := newInstance().attachProgram(gc, spec, nil); err == nil || link != nil {
			t.Fatalf("unselected %s attached: link=%v err=%v", name, link, err)
		}
		gc.SetVar(operators.NativeRecoveryTestRunKey, true)
		gc.SetVar(operators.NativeOwnerRequiredKey, true)
		gc.SetVar(operators.NativeResourceValidatorKey, func(*operators.NativeResources) error { return nil })
		i = newInstance()
		if selected, err := i.nativeRecoveryTestRunProgram(gc, spec); err != nil || !selected {
			t.Fatalf("trusted %s did not select unattached TEST_RUN: selected=%v err=%v", name, selected, err)
		}
		if link, err := i.attachProgram(gc, spec, nil); err == nil || link != nil {
			t.Fatalf("unadmitted %s attached: link=%v err=%v", name, link, err)
		}
		i.recoveryTestRunAdmitted = true // final manifest admission is covered separately
		if link, err := i.attachProgram(gc, spec, nil); err != nil || link != nil {
			t.Fatalf("admitted %s took TC attach path: link=%v err=%v", name, link, err)
		}
		if _, err := i.nativeRecoveryTestRunProgram(gc, &ebpf.ProgramSpec{Name: name, Type: ebpf.SchedCLS, SectionName: "classifier/ingress/eth0"}); err == nil {
			t.Fatalf("%s accepted an attachable TC section", name)
		}
		gc.SetVar(operators.NativeRecoveryTestRunKey, false)
		gc.SetVar(operators.NativeOwnerRequiredKey, false)
		gc.SetVar(operators.NativeResourceValidatorKey, nil)
	}
}

func TestRecoveryTCAdmissionFailureExposesNothing(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	gc.SetVar(operators.NativeOwnerRequiredKey, true)
	gc.SetVar(operators.NativeRecoveryTestRunKey, true)
	rejected := errors.New("exact image rejected")
	gc.SetVar(operators.NativeResourceValidatorKey, func(*operators.NativeResources) error { return rejected })
	config := viper.New()
	config.Set("annotations.enforce-exec-shared-recovery", "1")
	spec := &ebpf.ProgramSpec{Name: "se_rm_guardian", Type: ebpf.SchedCLS, SectionName: "tc"}
	i := &ebpfInstance{config: config, logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{spec.Name: spec}}, collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{spec.Name: new(ebpf.Program)}}}
	if selected, err := i.nativeRecoveryTestRunProgram(gc, spec); err != nil || !selected {
		t.Fatalf("setup did not provisionally select recovery TC: selected=%v err=%v", selected, err)
	}
	if err := i.validateNativeResources(gc); !errors.Is(err, rejected) || i.recoveryTestRunAdmitted {
		t.Fatalf("rejected final image admitted: err=%v admitted=%v", err, i.recoveryTestRunAdmitted)
	}
	if err := i.publishCommandPrograms(gc); err == nil {
		t.Fatal("rejected image published recovery program")
	}
	if program, exists := gc.GetVar(operators.ProgramPrefix + spec.Name); exists && program != nil {
		t.Fatal("rejected image exposed recovery program")
	}
	if program, exists := gc.GetVar(operators.NativeLoadedProgramPrefix + spec.Name); exists && program != nil {
		t.Fatal("rejected image exposed loaded-program handle")
	}
}

func TestRecoverySelectionWithoutTCOrAdmissionPublishesNothing(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	gc.SetVar(operators.NativeOwnerRequiredKey, true)
	gc.SetVar(operators.NativeRecoveryTestRunKey, true)
	gc.SetVar(operators.NativeResourceValidatorKey, func(*operators.NativeResources) error { return nil })
	config := viper.New()
	config.Set("annotations.enforce-exec-shared-recovery", "1")
	spec := &ebpf.ProgramSpec{Name: "se_task_alloc", Type: ebpf.LSM, SectionName: "lsm/task_alloc", AttachTo: "task_alloc"}
	i := &ebpfInstance{config: config, logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{spec.Name: spec}}, collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{spec.Name: new(ebpf.Program)}}}
	if err := i.publishCommandPrograms(gc); err == nil {
		t.Fatal("unadmitted recovery selection without TC published handles")
	}
	if got, _ := gc.GetVar(operators.NativeLoadedProgramPrefix + spec.Name); got != nil {
		t.Fatal("unadmitted loaded-program view exposed")
	}
}

func TestCommandUnpublishDoesNotClearAnotherOwnersValue(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	mine, other := new(ebpf.Program), new(ebpf.Program)
	i := &ebpfInstance{collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{"control": mine}}}
	gc.SetVar(operators.ProgramPrefix+"control", other)
	i.unpublishCommandPrograms(gc)
	if value, _ := gc.GetVar(operators.ProgramPrefix + "control"); value != other {
		t.Fatal("unrelated context value cleared")
	}
}

func TestDisabledCommandCannotBeInvokedThroughContext(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(map[bool]string{false: "spec", true: "override"}[override], func(t *testing.T) {
			gc := newResolverGadgetCtx(t, nil)
			spec := &ebpf.ProgramSpec{Name: "control", Type: ebpf.Syscall, SectionName: "syscall"}
			config := viper.New()
			if override {
				config.Set("programs.control.attach_to", disabledProgram)
			} else {
				spec.AttachTo = disabledProgram
			}
			i := &ebpfInstance{config: config, logger: gc.Logger(), collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"control": spec}}, collection: &ebpf.Collection{Programs: map[string]*ebpf.Program{"control": new(ebpf.Program)}}}
			if err := i.publishCommandPrograms(gc); err != nil {
				t.Fatal(err)
			}
			if _, ok := gc.GetVar(operators.ProgramPrefix + "control"); ok {
				t.Fatal("disabled command exposed")
			}
			if link, err := i.attachProgram(gc, spec, nil); err != nil || link != nil {
				t.Fatal(link, err)
			}
		})
	}
}

func TestProgramAttachTarget(t *testing.T) {
	for _, typ := range []ebpf.ProgramType{ebpf.LSM, ebpf.Tracing, ebpf.Kprobe, ebpf.TracePoint, ebpf.RawTracepoint, ebpf.Syscall} {
		t.Run(typ.String(), func(t *testing.T) {
			spec := &ebpf.ProgramSpec{Name: "hook", Type: typ, AttachTo: "actual"}
			i := &ebpfInstance{}
			if got := i.programAttachTarget(spec); got != "actual" {
				t.Fatalf("without config: got %q", got)
			}
			i.config = viper.New()
			for _, override := range []string{"", "override", disabledProgram} {
				i.config.Set("programs.hook.attach_to", override)
				want := override
				if override == "" || (override != disabledProgram && (typ == ebpf.LSM || typ == ebpf.Tracing)) {
					want = "actual"
				}
				if got := i.programAttachTarget(spec); got != want {
					t.Errorf("override %q: got %q, want %q", override, got, want)
				}
			}
		})
	}
}
