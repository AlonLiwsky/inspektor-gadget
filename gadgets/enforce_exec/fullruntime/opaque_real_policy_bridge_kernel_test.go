// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// This opt-in test loads only the disarmed bprm diagnostic. It never attaches
// an enforcement link or grants authority to the candidate image.
func TestOpaqueRealPolicyBridgeKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_POLICY_BRIDGE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_REAL_POLICY_BRIDGE_OBJECT to the opt-in bridge object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	const source = "opaque_real_owner_reader_begin_probe"
	const target = "opaque_real_owner_policy_target_candidate"
	const stageTarget = "opaque_real_owner_policy_stage_target_candidate"
	const ruleTarget = "opaque_real_owner_rule_target_candidate"
	const seed = "opaque_real_owner_policy_seed_diagnostic"
	for _, name := range []string{source, target} {
		program := spec.Programs[name]
		if program == nil || program.Type != ebpf.LSM || program.AttachTo != "bprm_check_security" {
			t.Fatalf("bridge bprm program %s missing or incompatible: %+v", name, program)
		}
	}
	for _, name := range []string{"se_objects", "se_bindings", "se_arena", "se_opaque_work_payload"} {
		if spec.Maps[name] == nil {
			t.Fatalf("bridge missing real source/WORK map %s", name)
		}
	}
	if program := spec.Programs[seed]; program == nil || program.Type != ebpf.SchedCLS {
		t.Fatalf("bridge real-map seed diagnostic missing or incompatible: %+v", program)
	}
	stageMap := spec.Maps["opaque_real_owner_policy_stage_targets"]
	stageProgram := spec.Programs[stageTarget]
	ruleMap := spec.Maps["opaque_real_owner_rule_targets"]
	ruleProgram := spec.Programs[ruleTarget]
	if stageMap != nil {
		if stageProgram == nil || stageProgram.Type != ebpf.LSM || stageProgram.AttachTo != "bprm_check_security" {
			t.Fatalf("bridge stage target missing or incompatible: %+v", stageProgram)
		}
	}
	if ruleMap != nil {
		if stageMap == nil || ruleProgram == nil || ruleProgram.Type != ebpf.LSM ||
			ruleProgram.AttachTo != "bprm_check_security" {
			t.Fatalf("bridge rule target missing or incompatible: %+v", ruleProgram)
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for disarmed verifier load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{
		source: spec.Programs[source], target: spec.Programs[target],
		seed: spec.Programs[seed],
	}
	if stageMap != nil {
		spec.Programs[stageTarget] = stageProgram
	}
	if ruleMap != nil {
		spec.Programs[ruleTarget] = ruleProgram
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("real-source policy bridge verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	if err := collection.Maps["opaque_real_owner_policy_targets"].Update(
		uint32(0), collection.Programs[target], ebpf.UpdateAny); err != nil {
		t.Fatalf("install exact unattached policy target: %v", err)
	}
	if stageMap != nil {
		if err := collection.Maps["opaque_real_owner_policy_stage_targets"].Update(
			uint32(0), collection.Programs[stageTarget], ebpf.UpdateAny); err != nil {
			t.Fatalf("install exact unattached stage target: %v", err)
		}
	}
	if ruleMap != nil {
		if err := collection.Maps["opaque_real_owner_rule_targets"].Update(
			uint32(0), collection.Programs[ruleTarget], ebpf.UpdateAny); err != nil {
			t.Fatalf("install exact unattached rule target: %v", err)
		}
	}
	var gate uint32
	if err := collection.Maps["opaque_real_owner_child_gate"].Lookup(uint32(0), &gate); err != nil || gate != 0 {
		t.Fatalf("diagnostic bridge unexpectedly armed: gate=%d err=%v", gate, err)
	}
}

// A separate load-only probe isolates the typed map-backed alternative
// request ABI from the rule target's unrelated aggregate stack limit.
func TestOpaqueRealAltRequestKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_ALT_REQUEST_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_REAL_ALT_REQUEST_OBJECT to the opt-in rule object")
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for verifier load")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	const probe = "opaque_real_owner_alt_request_probe"
	program := spec.Programs[probe]
	if program == nil || program.Type != ebpf.SchedCLS {
		t.Fatalf("typed alternative probe missing or incompatible: %+v", program)
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{probe: program}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("typed alternative request verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	collection.Close()
}
