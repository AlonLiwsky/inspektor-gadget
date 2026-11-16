// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func sharedRecoveryFixture(t *testing.T) (SharedProfile, *operators.NativeResources) {
	t.Helper()
	p, _ := sharedImageFixture(t)
	m, programs, err := sharedRecoveryGeometry(p)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range programs {
		value.Instructions = 17
		programs[name] = value
	}
	return p, &operators.NativeResources{Maps: m, Programs: programs}
}

func TestSharedRecoveryLoadedProgramViewIsExact(t *testing.T) {
	profile, manifest := sharedRecoveryFixture(t)
	gc := &sharedHostContext{vars: map[string]any{}}
	gc.SetVar(operators.NativeResourcesKey, manifest)
	gc.SetVar(operators.NativeRecoveryTestRunKey, true)
	for name := range manifest.Maps {
		gc.SetVar(operators.MapPrefix+name, new(ebpf.Map))
	}
	for name := range manifest.Programs {
		gc.SetVar(operators.NativeLoadedProgramPrefix+name, new(ebpf.Program))
	}
	r, err := sharedControlResourcesFromContext(gc)
	if err != nil || len(r.programs) != 11 || r.program != r.programs["se_command"] {
		t.Fatalf("recovered loaded-program view incomplete: programs=%d err=%v", len(r.programs), err)
	}
	// These fake pointers test collection routing only. A valid-ebpf-FD
	// success path requires the later isolated kernel test.
	badManifest := &operators.NativeResources{Maps: maps.Clone(manifest.Maps), Programs: maps.Clone(manifest.Programs)}
	delete(badManifest.Maps, "se_rm_control")
	r.manifest = badManifest
	if err := r.validate(profile); err == nil || !strings.Contains(err.Error(), "recovered image inventory mismatch") {
		t.Fatalf("malformed recovered geometry reached loaded-ID path: %v", err)
	}
	r.manifest = manifest
	if _, err := newSharedControl(t.Context(), profile, r); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("recovered image entered Go control-thread constructor: %v", err)
	}
	// A stale invocation-view handle cannot stand in for a missing loaded
	// program. The recovery ledger needs the entire admitted collection.
	gc.SetVar(operators.NativeLoadedProgramPrefix+"se_task_free", nil)
	gc.SetVar(operators.ProgramPrefix+"se_task_free", new(ebpf.Program))
	if _, err := sharedControlResourcesFromContext(gc); err == nil {
		t.Fatal("recovered LSM program silently borrowed from command view")
	}
	gc.SetVar(operators.NativeLoadedProgramPrefix+"se_task_free", new(ebpf.Program))
	gc.SetVar(operators.NativeRecoveryTestRunKey, false)
	if _, err := sharedControlResourcesFromContext(gc); err == nil {
		t.Fatal("unselected recovered program handles accepted")
	}
}

func TestSharedRecoveryImageExactInventory(t *testing.T) {
	p, resources := sharedRecoveryFixture(t)
	// G020: 30 maps (the legacy image_origins/image_ready maps are gone).
	if len(resources.Maps) != 30 || len(resources.Programs) != 11 {
		t.Fatalf("recovery inventory drift: maps=%d programs=%d", len(resources.Maps), len(resources.Programs))
	}
	// Independent fixed names, not derived from sharedRecoveryGeometry.
	for _, name := range []string{
		"se_configuration", "se_commands", "se_receipts", "se_objects",
		"se_bindings", "se_routes", "se_route_index", "se_arena",
		"se_tasks", "se_zero_tasks", "se_invocations", "se_zero_invocations",
		"se_accepted_epochs", "se_task_sequences", "se_inode_facts", "se_inode_accounts",
		"events", "counters", ".bss",
		"se_arm_requests", "se_arm_receipts", "se_epoch_bank", "se_epoch_index", "se_arm_frame",
		"se_rm_configuration", "se_rm_guardian_request", "se_rm_admin_request",
		"se_rm_control", "se_rm_guardian_receipt", "se_rm_admin_receipt",
	} {
		if _, ok := resources.Maps[name]; !ok {
			t.Fatalf("expected recovered map %s missing", name)
		}
	}
	// G020: the shared node never declares the legacy image-origin maps.
	for _, name := range []string{"image_origins", "image_ready"} {
		if _, ok := resources.Maps[name]; ok {
			t.Fatalf("recovered image declares the legacy map %s", name)
		}
	}
	for _, name := range []string{
		"se_command", "se_publication_arm", "se_sched_exec", "se_bprm_exit",
		"se_task_alloc", "se_task_free", "se_inode_free", "enforce_exec_full",
		"enforce_exec_track_memfd", "se_rm_guardian", "se_rm_administrator",
	} {
		if _, ok := resources.Programs[name]; !ok {
			t.Fatalf("expected recovered program %s missing", name)
		}
	}
	if _, hasAdmin := resources.Maps["se_admin"]; hasAdmin {
		t.Fatal("recovered image retained task-storage admin")
	}
	for name, size := range map[string]uint32{
		"se_rm_configuration": 32, "se_rm_guardian_request": 64,
		"se_rm_admin_request": 40, "se_rm_control": 192,
		"se_rm_guardian_receipt": 96, "se_rm_admin_receipt": 96,
	} {
		got := resources.Maps[name]
		if got.Type != uint32(ebpf.Array) || got.KeySize != 4 || got.ValueSize != size || got.MaxEntries != 1 {
			t.Fatalf("recovery ABI map %s drifted: %+v", name, got)
		}
		flags := uint32(unix.BPF_F_RDONLY)
		if name == "se_rm_configuration" || name == "se_rm_guardian_request" || name == "se_rm_admin_request" {
			flags = unix.BPF_F_RDONLY_PROG
		}
		if got.Flags != flags {
			t.Fatalf("recovery map %s flags=%d want=%d", name, got.Flags, flags)
		}
	}
	if err := validateSharedRecoveryImageGeometry(p, resources); err != nil {
		t.Fatal(err)
	}
	for name := range resources.Maps {
		t.Run("missing-map/"+name, func(t *testing.T) {
			mutated := &operators.NativeResources{Maps: maps.Clone(resources.Maps), Programs: maps.Clone(resources.Programs)}
			delete(mutated.Maps, name)
			if err := validateSharedRecoveryImageGeometry(p, mutated); err == nil {
				t.Fatal("missing map accepted")
			}
		})
	}
	for name := range resources.Programs {
		t.Run("wrong-program/"+name, func(t *testing.T) {
			mutated := &operators.NativeResources{Maps: maps.Clone(resources.Maps), Programs: maps.Clone(resources.Programs)}
			value := mutated.Programs[name]
			value.Target = "foreign"
			mutated.Programs[name] = value
			if err := validateSharedRecoveryImageGeometry(p, mutated); err == nil {
				t.Fatal("foreign program target accepted")
			}
		})
	}
	extra := &operators.NativeResources{Maps: maps.Clone(resources.Maps), Programs: maps.Clone(resources.Programs)}
	extra.Maps[".rodata"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: 1}
	if err := validateSharedRecoveryImageGeometry(p, extra); err == nil {
		t.Fatal("extra map accepted")
	}
	legacy := &operators.NativeResources{Maps: maps.Clone(resources.Maps), Programs: maps.Clone(resources.Programs)}
	legacy.Maps["se_admin"] = operators.NativeMapResource{Type: uint32(ebpf.TaskStorage)}
	if err := validateSharedRecoveryImageGeometry(p, legacy); err == nil {
		t.Fatal("legacy admin accepted")
	}
}

func TestSharedRecoverySelectionStaysUnavailable(t *testing.T) {
	p, resources := sharedRecoveryFixture(t)
	base := SharedNodeConfig{Profile: p, ABI3Development: true, Image: "local/shared:abi3-development"}
	if _, err := NewNodeEnforcer(SharedNodeConfig{Profile: p, ABI3Development: true, RecoveryDevelopment: true, Image: base.Image}); err == nil {
		t.Fatal("recovery opt-in accepted ordinary image")
	}
	if _, err := NewNodeEnforcer(SharedNodeConfig{Profile: p, ABI3Development: true, Image: "local/shared:abi3-recovery-development"}); err == nil {
		t.Fatal("recovery image accepted without trusted opt-in")
	}
	recovery := base
	recovery.RecoveryDevelopment = true
	recovery.Image = "local/shared:abi3-recovery-development"
	node, err := NewNodeEnforcer(recovery)
	if err != nil {
		t.Fatal(err)
	}
	gc := gadgetcontext.New(t.Context(), recovery.Image, WithNodeEnforcer(node))
	if selected, _ := gc.GetVar(operators.NativeRecoveryTestRunKey); selected != true {
		t.Fatal("trusted recovered owner did not select TC TEST_RUN path")
	}
	if err := node.admitSharedResources(resources); !errors.Is(err, ErrSharedNativeUnavailable) || node.host.admitted != nil {
		t.Fatalf("incomplete recovery runtime admitted: err=%v retained=%v", err, node.host.admitted)
	}
	mutated := &operators.NativeResources{Maps: maps.Clone(resources.Maps), Programs: maps.Clone(resources.Programs)}
	delete(mutated.Maps, "se_rm_control")
	if err := node.admitSharedResources(mutated); err == nil || errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("malformed recovery image not rejected by exact manifest: %v", err)
	}
	ordinary, err := NewNodeEnforcer(base)
	if err != nil {
		t.Fatal(err)
	}
	ordinaryContext := gadgetcontext.New(t.Context(), base.Image, WithNodeEnforcer(ordinary))
	if selected, exists := ordinaryContext.GetVar(operators.NativeRecoveryTestRunKey); exists || selected != nil {
		t.Fatal("ordinary shared owner selected recovery TC path")
	}
}

func TestSharedRecoveryMetadataIsNotInferred(t *testing.T) {
	p, _ := sharedRecoveryFixture(t)
	config := SharedNodeConfig{Profile: p, ABI3Development: true, RecoveryDevelopment: true, Image: "local/shared:abi3-recovery-development"}
	node, err := NewNodeEnforcer(config)
	if err != nil {
		t.Fatal(err)
	}
	gc := &sharedHostContext{vars: map[string]any{}, image: config.Image}
	metadata := viper.New()
	metadata.Set("annotations.enforce-exec-owner-abi", "3")
	metadata.Set("annotations.enforce-exec-owner-development", true)
	metadata.Set("annotations.enforce-exec-shared-profile", "1")
	if _, err := instantiateSharedNode(gc, metadata, node); err == nil || !strings.Contains(err.Error(), "capability mismatch") {
		t.Fatalf("missing recovery annotation did not fail capability check: %v", err)
	}
	metadata.Set("annotations.enforce-exec-shared-recovery", "1")
	if _, err := instantiateSharedNode(gc, metadata, node); err == nil || strings.Contains(err.Error(), "capability mismatch") {
		t.Fatalf("matching recovery annotation did not reach geometry check: %v", err)
	}
	ordinary := config
	ordinary.RecoveryDevelopment = false
	ordinary.Image = "local/shared:abi3-development"
	ordinaryNode, err := NewNodeEnforcer(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	gc.image = ordinary.Image
	if _, err := instantiateSharedNode(gc, metadata, ordinaryNode); err == nil || !strings.Contains(err.Error(), "capability mismatch") {
		t.Fatalf("ordinary owner accepted recovery annotation: %v", err)
	}
}

// IG_SHARED_RECOVERY_OBJECT selects a compile-only object for the explicit
// B2/T128/W32 development profile. Parsing never loads a map or program.
func TestSharedRecoveryCompiledInventory(t *testing.T) {
	path := os.Getenv("IG_SHARED_RECOVERY_OBJECT")
	if path == "" {
		t.Skip("set IG_SHARED_RECOVERY_OBJECT to an exact compiled candidate")
	}
	p := sharedTestProfile()
	p.PolicySlots = [4]uint64{2, 0, 0, 0}
	p.Tasks, p.Scratch, p.AcceptedUIDs = 128, 32, 32
	p.PerBinding.Tasks, p.PerBinding.Scratch, p.PerBinding.AcceptedUIDs = 64, 16, 16
	p.Images, p.PerBinding.Images, p.TelemetryBytes = 65536, 32768, 262144
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	resources := &operators.NativeResources{Maps: map[string]operators.NativeMapResource{}, Programs: map[string]operators.NativeProgramResource{}}
	for name, m := range spec.Maps {
		if m.InnerMap != nil {
			t.Fatalf("unexpected nested map %s", name)
		}
		resources.Maps[name] = operators.NativeMapResource{Type: uint32(m.Type), KeySize: m.KeySize, ValueSize: m.ValueSize, MaxEntries: m.MaxEntries, Flags: m.Flags}
	}
	for name, program := range spec.Programs {
		resources.Programs[name] = operators.NativeProgramResource{Type: uint32(program.Type), Target: program.AttachTo, Instructions: uint64(len(program.Instructions)) * 2}
	}
	if err := validateSharedRecoveryImageGeometry(p, resources); err != nil {
		t.Fatalf("emitted recovery inventory: %v", err)
	}
	for _, name := range []string{"se_rm_guardian", "se_rm_administrator"} {
		program := spec.Programs[name]
		if program.SectionName != "tc" || program.AttachTo != "" {
			t.Fatalf("recovery endpoint %s is not unattached tc: section=%q target=%q", name, program.SectionName, program.AttachTo)
		}
	}
	// Clang 21 must reject false-drain cgroup operations before the recovery
	// publication hook can read a staged request. This only checks emitted
	// instructions; it does not prove an attached kernel trampoline.
	arm := spec.Programs["se_publication_arm"]
	if arm == nil || len(arm.Instructions) < 2 {
		t.Fatal("recovery publication arm missing")
	}
	load, branch := arm.Instructions[0], arm.Instructions[1]
	if load.OpCode != asm.LoadMem(asm.R2, asm.R1, 8, asm.DWord).OpCode ||
		load.Dst != asm.R2 || load.Src != asm.R1 || load.Offset != 8 ||
		branch.OpCode.JumpOp() != asm.JEq || branch.Dst != asm.R2 ||
		branch.Constant != 0 || branch.Offset <= 0 {
		t.Fatalf("recovery publication arm lacks early false-drain guard: %v; %v", load, branch)
	}
	target := asm.RawInstructionOffset(2 + int(branch.Offset))
	iter := arm.Instructions.Iterate()
	foundReturn := false
	for iter.Next() {
		if iter.Offset != target {
			continue
		}
		zero := *iter.Ins
		if zero.OpCode != asm.Mov.Imm32(asm.R0, 0).OpCode ||
			zero.Dst != asm.R0 || zero.Constant != 0 || !iter.Next() ||
			iter.Ins.OpCode != asm.Return().OpCode {
			t.Fatalf("false-drain branch does not return zero at raw offset %d", target)
		}
		foundReturn = true
		break
	}
	if !foundReturn {
		t.Fatalf("false-drain branch target %d missing", target)
	}
}
