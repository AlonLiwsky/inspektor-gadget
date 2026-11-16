// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"context"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type sharedHostContext struct {
	operators.GadgetContext
	vars  map[string]any
	image string
}

func (c *sharedHostContext) GetVar(k string) (any, bool) { v, ok := c.vars[k]; return v, ok }
func (c *sharedHostContext) SetVar(k string, v any)      { c.vars[k] = v }
func (c *sharedHostContext) Context() context.Context    { return context.Background() }
func (c *sharedHostContext) ImageName() string           { return c.image }
func TestSharedHostTwoPhaseAdmission(t *testing.T) {
	cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
	bad := cfg
	bad.ABI3Development = false
	if _, err := NewNodeEnforcer(bad); err == nil {
		t.Fatal("default enabled shared host")
	}
	n, err := NewNodeEnforcer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	acquired := false
	if _, err = n.Bind(t.Context(), SharedBindingConfig{CgroupID: 1, Acquire: func(context.Context) (BindingLease, error) { acquired = true; return &sharedTestLease{}, nil }}); err == nil || acquired {
		t.Fatal("binding without trusted init identity")
	}
	gc := &sharedHostContext{vars: map[string]any{sharedNodeKey: n}, image: cfg.Image}
	gc.vars["config"] = viper.New()
	if _, err = New().InstantiateDataOperator(gc, nil); err == nil {
		t.Fatal("unmarked image admitted through real operator")
	}
	metadata := viper.New()
	metadata.Set("annotations.enforce-exec-owner-abi", "3")
	metadata.Set("annotations.enforce-exec-owner-development", true)
	metadata.Set("annotations.enforce-exec-shared-profile", "1")
	gc.vars["config"] = metadata
	if _, err = New().InstantiateDataOperator(gc, nil); err == nil {
		t.Fatal("missing image geometry/maps admitted")
	}
	if err = n.Ready(gc); err == nil {
		t.Fatal("protocol foundation advertised protection")
	}
	if err = n.ReleaseAfterDetach(); err != nil {
		t.Fatal("never-claimed native handle release", err)
	}
}

func TestSharedHostStopDoesNotPretendManagerDetached(t *testing.T) {
	cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
	n, err := NewNodeEnforcer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.host.claimed = true // simulate host ownership without allocating BPF
	if err = n.StopNode(t.Context()); err == nil {
		t.Fatal("host manager detach falsely inferred")
	}
	if n.host.released {
		t.Fatal("released while operator remains claimed")
	}
	if err = n.Start(nil); err == nil {
		t.Fatal("nil context")
	}
	if err = n.Stop(nil); err == nil {
		t.Fatal("nil stop context")
	}
	if err = n.Close(nil); err == nil {
		t.Fatal("nil close context")
	}
}

func TestSharedHostJoinedPanicCleanup(t *testing.T) {
	cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
	n, err := NewNodeEnforcer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gc := &sharedHostContext{vars: map[string]any{}, image: cfg.Image}
	n.host.claimed = true
	n.host.context = gc
	thread, err := startControlThread(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	n.host.control = &sharedControl{thread: thread}
	if err = thread.do(t.Context(), func() error { panic("command panic") }); err == nil {
		t.Fatal("panic diagnostic lost")
	}
	if err = n.Close(gc); err == nil {
		t.Fatal("sticky panic diagnostic lost")
	}
	select {
	case <-thread.done:
	default:
		t.Fatal("command thread not joined")
	}
	// No BPF resources are allocated in this unit fixture. Manager teardown has
	// no borrowed FDs to close; joined diagnostics must not retain the handle.
	if !n.host.operatorClosed {
		t.Fatal("joined cleanup reported permanently incomplete")
	}
	if err = n.ReleaseAfterDetach(); err != nil {
		t.Fatal("joined failed command prevented release", err)
	}
}

func TestSharedHostBindingRefusalIsNotJoinedCleanup(t *testing.T) {
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "development"})
	if err != nil {
		t.Fatal(err)
	}
	gc := &sharedHostContext{vars: map[string]any{}, image: "development"}
	n.host.context = gc
	n.host.claimed = true
	n.bindings[1] = &BindingSession{node: n, prepared: 1, cgroup: 1}
	if err = n.Close(gc); err == nil || n.host.operatorClosed {
		t.Fatal("active binding drain refusal marked closed")
	}
	if err = n.ReleaseAfterDetach(); err == nil {
		t.Fatal("unjoined cleanup released")
	}
}

func TestSharedHostRejectsImageKeyGeometry(t *testing.T) {
	for _, key := range []string{"images", "image-quota"} {
		for _, value := range []string{"", "0", "3", "4294967296"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "local/shared:abi3-development"}
				n, err := NewNodeEnforcer(cfg)
				if err != nil {
					t.Fatal(err)
				}
				gc := &sharedHostContext{vars: map[string]any{}, image: cfg.Image}
				metadata := viper.New()
				metadata.Set("annotations.enforce-exec-owner-abi", "3")
				metadata.Set("annotations.enforce-exec-owner-development", true)
				metadata.Set("annotations.enforce-exec-shared-profile", "1")
				p := cfg.Profile
				for name, count := range map[string]uint64{"inode-facts": p.InodeFacts, "inode-quota": p.PerBinding.InodeFacts, "tasks": p.Tasks, "scratch": p.Scratch, "accepted-uids": p.AcceptedUIDs, "task-quota": p.PerBinding.Tasks, "scratch-quota": p.PerBinding.Scratch, "bindings": p.Bindings, "exit-tombstones": p.exitTombstones(), "slots-256": p.PolicySlots[0], "slots-1024": p.PolicySlots[1], "slots-4096": p.PolicySlots[2], "slots-16384": p.PolicySlots[3], "images": p.Images, "image-quota": p.PerBinding.Images, "verdict-ring": p.verdictRing()} {
					metadata.Set("annotations.enforce-exec-shared-"+name, strconv.FormatUint(count, 10))
				}
				metadata.Set("annotations."+SharedEventABIAnnotation, SharedEventABIVersion)
				metadata.Set("annotations.enforce-exec-shared-"+key, value)
				_, err = instantiateSharedNode(gc, metadata, n)
				if err == nil || !strings.Contains(err.Error(), "shared image geometry mismatch: "+key) {
					t.Fatalf("wrong geometry admission: %v", err)
				}
				if n.host.claimed || n.host.admitted != nil || n.host.ready {
					t.Fatal("invalid image geometry acquired host authority")
				}
			})
		}
	}
}

// The verdict candidate's compile-time guards are part of its fail-closed
// boundary (G025 step 10): the same-bprm continuation has no proved
// pre-dispatch class recovery, the verdict needs staged evaluation and the
// exact reader catalogue, and the source capsule and test-only injectors
// need the guarded verdict and disposable bootstrap. Removing or weakening
// one of these #error blocks must fail CI.
func TestOpaqueRealVerdictCandidateCompileGuards(t *testing.T) {
	raw, err := os.ReadFile("bpf/opaque_real_owner_child_candidate.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, guard := range []string{
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) && \\\n" +
			"    defined(ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC)\n" +
			"#error \"verdict candidate has no proved pre-dispatch interpreter class recovery\"\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC) && \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE)\n" +
			"#error \"same-bprm continuation requires the exact policy bridge\"\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) && \\\n" +
			"    (!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC) || \\\n" +
			"     !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC) || \\\n" +
			"     !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE))\n" +
			"#error \"real-policy verdict requires staged evaluation and exact reader catalogue\"\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE\n" +
			"#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE\n" +
			"#error \"source capsule admission requires the real-policy verdict candidate\"\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_POLICY_TASK_CLOSE_FAULT_DIAGNOSTIC) && \\\n" +
			"    (!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) || \\\n" +
			"     !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC))\n" +
			"#error \"policy close injection requires guarded verdict and disposable bootstrap\"\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC) || \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)\n" +
			"#error \"abort injection requires successful-birth disposable bootstrap\"\n#endif\n",
		"#ifdef SE_TEST_DEFERRED_STORAGE_ENTRIES\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC) || \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)\n" +
			"#error \"shrunken deferred storage requires its witness and disposable bootstrap\"\n#endif\n",
		"#if SE_TEST_DEFERRED_STORAGE_ENTRIES < 1 || \\\n" +
			"    SE_TEST_DEFERRED_STORAGE_ENTRIES > SE_PROFILE_TASKS\n" +
			"#error \"deferred storage override must be 1..SE_PROFILE_TASKS\"\n#endif\n",
		// G025 batch C: per-map storage overrides, route migration and
		// the generation advance stay test-only.
		"#if defined(SE_TEST_TERMINAL_RECEIPT_ENTRIES) || \\\n" +
			"    defined(SE_TEST_BIRTH_RECEIPT_ENTRIES) || \\\n" +
			"    defined(SE_TEST_FAILURE_FRAME_ENTRIES)\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC) || \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)\n" +
			"#error \"per-map deferred storage overrides require the witness and disposable bootstrap\"\n#endif\n#endif\n",
		"#if SE_TEST_TERMINAL_RECEIPT_ENTRIES < 1 || \\\n" +
			"    SE_TEST_TERMINAL_RECEIPT_ENTRIES > SE_PROFILE_TASKS\n" +
			"#error \"terminal receipt override must be 1..SE_PROFILE_TASKS\"\n#endif\n",
		"#if SE_TEST_BIRTH_RECEIPT_ENTRIES < 1 || \\\n" +
			"    SE_TEST_BIRTH_RECEIPT_ENTRIES > SE_PROFILE_TASKS\n" +
			"#error \"birth receipt override must be 1..SE_PROFILE_TASKS\"\n#endif\n",
		"#if SE_TEST_FAILURE_FRAME_ENTRIES < 1 || \\\n" +
			"    SE_TEST_FAILURE_FRAME_ENTRIES > SE_PROFILE_TASKS\n" +
			"#error \"failure frame override must be 1..SE_PROFILE_TASKS\"\n#endif\n",
		// G019 M4 review L3 and lead decision (b): the uncovered-capsule
		// diagnostic, the WORK fault-site witness and a product object
		// without the synchronous WORK return are refused.
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_CAPSULE_UNCOVERED_DIAGNOSTIC\n#ifdef SE_PRODUCT_NO_TEST_RUN\n" +
			"#error \"the uncovered-capsule diagnostic is test only\"\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_FAULT_SITE_DIAGNOSTIC\n#ifdef SE_PRODUCT_NO_TEST_RUN\n" +
			"#error \"the WORK fault-site witness is diagnostic only\"\n#endif\n",
		"#if defined(SE_PRODUCT_NO_TEST_RUN) && \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE)\n" +
			"#error \"the product object requires the synchronous WORK return\"\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_ROUTE_MIGRATION_DIAGNOSTIC\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) || \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC) || \\\n" +
			"    SE_PROFILE_BINDINGS < 2\n" +
			"#error \"route migration requires the source capsule, disposable bootstrap and two bindings\"\n#endif\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_RELOAD_DIAGNOSTIC\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) || \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)\n" +
			"#error \"generation advance requires the source capsule and disposable bootstrap\"\n#endif\n#endif\n",
		// G019 gap 4 (review H1): the interpreter continuation needs the
		// verdict, the capsule's frozen class and the final failure frames,
		// replaces the same-bprm diagnostic (whose #error above stays), and
		// is part of every product object.
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE) && \\\n" +
			"    (!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) || \\\n" +
			"     !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) || \\\n" +
			"     !defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE) || \\\n" +
			"     !defined(ENFORCE_EXEC_POOL_OPAQUE_READER_BEGIN_PROBE))\n" +
			"#error \"interpreter continuation requires the real-policy verdict, the source capsule and the final failed-exec frames\"\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE) && \\\n" +
			"    defined(ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC)\n" +
			"#error \"interpreter continuation replaces the same-bprm continuation diagnostic\"\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) && \\\n" +
			"    !defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE)\n" +
			"#error \"the product publisher requires the interpreter continuation\"\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_STALE_RESUME_DIAGNOSTIC) && \\\n" +
			"    ((defined(SE_PRODUCT_NO_TEST_RUN) && \\\n" +
			"      !defined(SE_PRODUCT_DIAGNOSTIC_TWIN)) || \\\n" +
			"     !defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE))\n" +
			"#error \"the stale-resume injector is test only and needs the interpreter continuation\"\n#endif\n",
		// G025 batch D: the fail-closed rate witness rides only the
		// guarded verdict, and the quota profile stays an exact per-binding
		// partition within the measured stack range.
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE\n" +
			"#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE\n" +
			"#error \"fail-closed rate witness requires the real-policy verdict candidate\"\n#endif\n",
		"_Static_assert((__u64)SE_PROFILE_BINDINGS * SE_PROFILE_TASK_QUOTA ==\n" +
			"\t\t       SE_PROFILE_TASKS &&\n" +
			"\t       (__u64)SE_PROFILE_BINDINGS * SE_PROFILE_SCRATCH_QUOTA ==\n" +
			"\t\t       SE_PROFILE_SCRATCH,\n",
		// U1: TASK quota 1..256, or exactly 512 (the thread-sized profile,
		// measured with the looped bitmap count below).
		"_Static_assert(((SE_PROFILE_TASK_QUOTA >= 1 && SE_PROFILE_TASK_QUOTA <= 256) ||\n" +
			"\t\tSE_PROFILE_TASK_QUOTA == 512) &&\n" +
			"\t\tSE_PROFILE_SCRATCH_QUOTA >= 1 && SE_PROFILE_SCRATCH_QUOTA <= 32,\n",
		// A non-power-of-two WORK quota puts the fork source at 528 bytes.
		"_Static_assert((SE_PROFILE_SCRATCH_QUOTA & (SE_PROFILE_SCRATCH_QUOTA - 1)) == 0,\n" +
			"\t       \"verdict WORK quota must be a power of two (1..32)\");\n",
		"_Static_assert(SE_PROFILE_WORK_RETRIES >= 1 &&\n" +
			"\t       SE_PROFILE_WORK_RETRIES <= SE_PROFILE_SCRATCH_QUOTA &&\n" +
			"\t       SE_PROFILE_WORK_RETRIES <= 16,\n",
		// G025 final: the physical-reuse directory withdrawal is a
		// correctness fix of every build of the final-free program, never
		// gated by the rate witness or any other option.
		"#ifndef SE_OF_WITHDRAW_DIRECTORY\n" +
			"#error \"real-map final-free requires the physical-reuse directory withdrawal\"\n#endif\n",
		"#ifndef SE_OP_INSERT_RETRY\n" +
			"#error \"real-map birth requires the physical-reuse single insert retry\"\n#endif\n",
		"\t\t(void)se_of_complete_native_unheld(&lease, physical);\n" +
			"\t\t/* Withdraw the directory entry before this address can be reused\n" +
			"\t\t * (full/shared_pool_opaque_final_free_candidate.h). Any refusal\n" +
			"\t\t * leaves the reaper's ordinary withdrawal as the fallback. */\n" +
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE\n" +
			"\t\t/* Mirror se_or_task_terminal_guard: a receipt left at this key\n" +
			"\t\t * keeps the key for its consumer; only the reaper retires it. */\n" +
			"\t\tif (!bpf_map_lookup_elem(&se_exec_terminal_receipts,\n" +
			"\t\t\t\t\t &receipt_key))\n" +
			"#endif\n" +
			"\t\t\t(void)se_of_withdraw_directory(&lease, physical);\n" +
			"\t\t(void)se_of_release(&lease, physical);\n",
		// G019 M0: first-exec qualification is built with the verdict
		// candidate, not only under the successful-birth diagnostic, and
		// both first-use callers still propagate a qualification fault.
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) || \\\n" +
			"    defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC)\n" +
			"#define SE_REAL_OWNER_BIRTH_QUALIFY 1\n#endif\n#ifdef SE_REAL_OWNER_BIRTH_QUALIFY\n",
		"#ifdef SE_REAL_OWNER_BIRTH_QUALIFY\n\tbirth_fault =\n\t\treal_owner_birth_qualify(\n" +
			"\t\t\t(struct task_struct *)bpf_get_current_task_btf()) < 0;\n#endif\n",
		"#ifdef SE_REAL_OWNER_BIRTH_QUALIFY\n\tif (real_owner_image_configured() &&\n" +
			"\t    SE_FC_QUALIFY_FAULT(real_owner_birth_qualify(\n\t\t    (struct task_struct *)bpf_get_current_task_btf())))\n" +
			"\t\tterminal_fault = 2;\n#endif\n",
		// G019 fail-closed injectors: test-only, and compiled to the
		// product expressions (no fault, qualify < 0) without the flag.
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC\n" +
			"#if (!defined(ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC) && \\\n" +
			"\t!defined(SE_PRODUCT_DIAGNOSTIC_TWIN)) || \\\n",
		"!defined(SE_REAL_OWNER_BIRTH_QUALIFY)\n" +
			"#error \"fail-closed injectors require the abort injector or the product diagnostic twin, rate witness, success completion and birth qualification\"\n#endif\n",
		"#else\n#define SE_FC_PENDING_SKIP(physical) 0\n#define SE_FC_OPEN_PARENT_FAULT() 0\n" +
			"#define SE_FC_QUALIFY_FAULT(qualified) ((qualified) < 0)\n#endif\n",
		"if (SE_FC_OPEN_PARENT_FAULT() ||\n\t    real_owner_child_open_parent(&parent) != SE_OL_OK) {\n" +
			"\t\tSE_EXEC_EXCLUSION_WITNESS(2);\n",
		"if (receipt && !SE_FC_PENDING_SKIP(key) &&\n\t    real_owner_terminal_transition(\n",
		// The extended injectors (exec open parent, exec and birth
		// admission) are test-only, need the selector injectors and the
		// product publisher, and compile to no fault without the flag.
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_EXT_DIAGNOSTIC\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC) || \\\n" +
			"\t!defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) || \\\n" +
			"\t!defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE)\n" +
			"#error \"the extended fail-closed injector requires the fail-closed injectors and the product publisher\"\n#endif\n",
		"#else\n#define SE_FC_EXEC_OPEN_PARENT_FAULT(key) 0\n#define SE_FC_EXEC_ADMISSION_FAULT(later) 0\n" +
			"#define SE_FC_BIRTH_ADMISSION_FAULT() 0\n#define SE_FC_TARGET_ADMISSION_FAULT() 0\n" +
			"#define SE_FC_READER_BEGIN_FAULT() 0\n#endif\n",
		"good = !SE_FC_EXEC_OPEN_PARENT_FAULT(key) &&\n\t\t       real_owner_child_open_parent(&owner) == SE_OL_OK;\n",
		// G020 carryover: the target re-admission and reader-not-begun
		// injectors (every[3], every[4]) take the product's own paths.
		"if (admission == SE_ROUTE_OWNED && SE_FC_TARGET_ADMISSION_FAULT()) {\n" +
			"\t\t(void)real_owner_child_release_claim(&claim);\n",
		"int opened = !SE_FC_READER_BEGIN_FAULT() &&\n\t\t\t     real_owner_reader_open_exact(&owner, &claim, bprm,\n",
		"(frozen_class != claim.execution_class ||\n\t     SE_FC_EXEC_ADMISSION_FAULT(later))) {\n",
		"if (admission == SE_ROUTE_OWNED && SE_FC_BIRTH_ADMISSION_FAULT()) {\n" +
			"\t\t(void)real_owner_child_release_claim(&claim);\n",
		// G019 section 8: the product object (SE_PRODUCT_NO_TEST_RUN) has
		// no TC program, recovery authority, disposable bootstrap or
		// injector, and needs the product reaper.
		"#ifdef SE_PRODUCT_NO_TEST_RUN\n" +
			"#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) || \\\n" +
			"\tdefined(ENFORCE_EXEC_POOL_OPAQUE_PRCTL_ARM_CANDIDATE) || \\\n" +
			"\tdefined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC) || \\\n" +
			"\tdefined(ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC) || \\\n" +
			"\tdefined(ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC) || \\\n" +
			"\tdefined(ENFORCE_EXEC_POOL_OPAQUE_PENDING_RECEIPT_DIAGNOSTIC) || \\\n" +
			"\t(defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC) && \\\n" +
			"\t!defined(SE_PRODUCT_DIAGNOSTIC_TWIN)) || \\\n" +
			"\t(defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_EXT_DIAGNOSTIC) && \\\n" +
			"\t!defined(SE_PRODUCT_DIAGNOSTIC_TWIN)) || \\\n" +
			"\t!defined(ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE)\n" +
			"#error \"product object has no TEST_RUN classifier programs and needs the product reaper\"\n#endif\n#endif\n",
		// The exact WORK high-water witness is test-only, never product.
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_HIGH_WATER_DIAGNOSTIC\n#ifdef SE_PRODUCT_NO_TEST_RUN\n" +
			"#error \"the WORK high-water witness is diagnostic only\"\n#endif\n",
		// Reap events stand without recovery only in the product object.
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) && \\\n" +
			"\t!defined(SE_PRODUCT_NO_TEST_RUN)\n" +
			"#error \"reap events require the recovered reaper or the product object\"\n#endif\n",
		// Review S1: the product reap command has the held-lease witness
		// (credit at exit); OFF profiles are qualification-only.
		"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) && \\\n" +
			"\t!defined(ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE)\n" +
			"#error \"product reap events require credit at exit (the held-lease witness)\"\n#endif\n",
		// Only the reaper visit helpers (and the credit-at-exit pre-visit)
		// are hoisted out of recovery: wire and control stay recovery-only,
		// and the pool reaper maps, chunk and transport also stay out of
		// SE_PRODUCT_NO_POOL_REAPER.
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) || \\\n" +
			"\tdefined(ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE)\n" +
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE\n" +
			"#define ENFORCE_EXEC_POOL_REAPER_CANDIDATE 1\n" +
			"#include \"shared_pool_reaper_wire_candidate.h\"\n" +
			"#define SE_POOL_T SE_OL_TASKS\n#define SE_POOL_W SE_OWK_WORKS\n" +
			"#include \"shared_pool_reaper_control_candidate.h\"\n#endif\n" +
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE\n",
		"#include \"shared_pool_opaque_reaper_visit_candidate.h\"\n" +
			"/* Product/qualification profile: omit the recovery-only pool reaper\n" +
			" * (se_pool_reaper_* programs, se_pool_reap_* maps); the visit helpers above\n" +
			" * stay for the product reap command opaque_real_reap. */\n" +
			"#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) && \\\n" +
			"\t!defined(SE_PRODUCT_NO_POOL_REAPER)\n" +
			"/* Reaper transport is not selected by the product.",
		// The TEST_RUN-only (TC) entrypoints and their selector maps are
		// compiled out of the product object; the completion helpers stay
		// for the real terminal producers.
		"#ifndef SE_PRODUCT_NO_TEST_RUN\nstruct {\n\t__uint(type, BPF_MAP_TYPE_ARRAY);\n\t__uint(max_entries, 1);\n" +
			"\t__uint(map_flags, BPF_F_RDONLY_PROG);\n\t__type(key, __u32);\n\t__type(value, __u32);\n" +
			"} opaque_real_owner_work_completion_gate SEC(\".maps\");\n",
		"} opaque_real_owner_work_completion_selector SEC(\".maps\");\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC) && \\\n" +
			"\t!defined(SE_PRODUCT_NO_TEST_RUN)\nSEC(\"tc\")\nint opaque_real_owner_terminal_race_complete(",
		"#ifndef SE_PRODUCT_NO_TEST_RUN\nSEC(\"tc\")\nint opaque_real_owner_work_completion_probe(",
		// The terminal-race rendezvous (witness map, bounded bpf_ktime
		// spin on every WORK completion) never reaches the product object;
		// only the retain tail-call target stays under TERMINAL_RACE.
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC) && \\\n" +
			"\t!defined(SE_PRODUCT_NO_TEST_RUN)\n#define SE_TERMINAL_RACE_RENDEZVOUS 1\n#endif\n",
		"#ifdef SE_TERMINAL_RACE_RENDEZVOUS\nstruct opaque_real_terminal_race_witness {",
		"#ifdef SE_TERMINAL_RACE_RENDEZVOUS\n\treal_owner_terminal_auth_enter();\n#endif\n" +
			"\tresult = real_owner_work_complete_active(&owner, key);\n" +
			"#ifdef SE_TERMINAL_RACE_RENDEZVOUS\n\treal_owner_terminal_auth_exit();\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC\n" +
			"/* Leave the exact source-issued reader/receipt to the real terminal producer.",
		"#ifndef SE_PRODUCT_NO_TEST_RUN\nSEC(\"tc\")\nint opaque_real_owner_work_retry_probe(",
		// Security review L-2: the product diagnostic twin marker is exactly
		// 1 and admits only the product publisher object plus the
		// publication fault injector.
		"#if defined(SE_PRODUCT_DIAGNOSTIC_TWIN) && SE_PRODUCT_DIAGNOSTIC_TWIN != 1\n" +
			"#error \"SE_PRODUCT_DIAGNOSTIC_TWIN must be exactly 1\"\n#endif\n",
		"#if defined(SE_PRODUCT_DIAGNOSTIC_TWIN) && \\\n" +
			"\t(!defined(SE_PRODUCT_NO_TEST_RUN) || \\\n" +
			"\t !defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) || \\\n" +
			"\t !defined(ENFORCE_EXEC_POOL_OPAQUE_PUBLISH_FAULT_DIAGNOSTIC))\n" +
			"#error \"the product diagnostic twin is the product publisher object plus the publication fault injector and test-only fault injectors\"\n#endif\n",
	} {
		if strings.Count(squashSpace(source), squashSpace(guard)) != 1 {
			t.Errorf("verdict candidate compile guard missing or changed:\n%s", guard)
		}
	}
	// Every TC (TEST_RUN classifier) entrypoint of the candidate source is
	// pinned with the option that keeps it out of the product object
	// (build-g19pkg.sh checks the built product object has none): a new
	// one fails here until it is classified.
	tcEntrypoints := map[string]string{
		"opaque_real_pending_receipt_cleanup":      "PENDING_RECEIPT_DIAGNOSTIC",
		"opaque_real_owner_policy_seed_diagnostic": "REAL_LIVE_BOOTSTRAP_DIAGNOSTIC",
		"opaque_real_owner_second_policy_seed":     "REAL_LIVE_BOOTSTRAP_DIAGNOSTIC",
		"opaque_real_reuse_hold":                   "ABORT_INJECTOR_DIAGNOSTIC",
		"opaque_real_owner_alt_request_probe":      "!REAL_POLICY_VERDICT_CANDIDATE",
		"opaque_real_owner_terminal_race_complete": "SE_PRODUCT_NO_TEST_RUN",
		"opaque_real_owner_work_completion_probe":  "SE_PRODUCT_NO_TEST_RUN",
		"opaque_real_owner_work_retry_probe":       "SE_PRODUCT_NO_TEST_RUN",
	}
	found := map[string]string{}
	for _, m := range regexp.MustCompile(`SEC\("tc"\)\s*int (\w+)\(`).FindAllStringSubmatch(source, -1) {
		found[m[1]] = tcEntrypoints[m[1]]
	}
	if fmt.Sprint(found) != fmt.Sprint(tcEntrypoints) {
		t.Errorf("TC entrypoints %v, pinned %v", slices.Sorted(maps.Keys(found)), slices.Sorted(maps.Keys(tcEntrypoints)))
	}
	// TERMINAL_RACE itself gates only the retain target (and, with the
	// product excluded, the TC contender and the rendezvous define): any
	// new code under the raw flag would reach the product object.
	if n := strings.Count(source, "#ifdef ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC\n"); n != 1 {
		t.Errorf("%d #ifdef ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC blocks, want 1 (the retain target); gate diagnostics on SE_TERMINAL_RACE_RENDEZVOUS", n)
	}
	if n := strings.Count(source, "defined(ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC)"); n != 2 {
		t.Errorf("%d defined(...TERMINAL_RACE_DIAGNOSTIC) conditions, want 2 (rendezvous define, TC contender), both excluding the product", n)
	}
	// The WORK charge diagnostic hooks are empty unless a test build
	// defines them, and the locked copy sits inside the account lock right
	// after the charge (the high-water is exact, not a racy re-read).
	raw, err = os.ReadFile("../full/shared_pool_opaque_work_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	for _, pin := range []string{
		"#ifndef SE_OWK_CHARGED\n#define SE_OWK_CHARGED_DECL\n#define SE_OWK_CHARGED_LOCKED(used) ((void)0)\n#define SE_OWK_CHARGED(slot) ((void)0)\n#endif\n",
		"\tSE_OWK_CHARGED_DECL;\n\tbpf_spin_lock(&account->lock);\n",
		"\t\taccount->bits |= bit;\n\t\taccount->used++;\n\t\tSE_OWK_CHARGED_LOCKED(account->used);\n",
		"\t\t\treturn SE_OL_CORRUPT;\n\t\treturn result;\n\t}\n\tSE_OWK_CHARGED(slot);\n",
	} {
		if strings.Count(squashSpace(string(raw)), squashSpace(pin)) != 1 {
			t.Errorf("WORK charge diagnostic hook missing or changed:\n%s", pin)
		}
	}
	// The reaper visit header is built by the recovered candidate and by
	// the product reap command (reap events), never by anything else.
	raw, err = os.ReadFile("../full/shared_pool_opaque_reaper_visit_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	if pin := "#if !defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE) || \\\n" +
		"\t(!defined(ENFORCE_EXEC_SHARED_RECOVERY) && \\\n" +
		"\t !defined(ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE))\n" +
		"#error \"opaque reaper visitors require the recovered or reap-events candidate\"\n#endif\n"; strings.Count(squashSpace(string(raw)), squashSpace(pin)) != 1 {
		t.Errorf("reaper visit header guard missing or changed:\n%s", pin)
	}
	// The withdrawal and its marker are defined unconditionally in the
	// final-free header (only its LOCATOR_CANDIDATE file guard applies).
	raw, err = os.ReadFile("../full/shared_pool_opaque_final_free_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	header := string(raw)
	marker := "#include \"shared_pool_opaque_writer_candidate.h\"\n/* Physical-reuse fix (G025 batch F)."
	withdraw := "#define SE_OF_WITHDRAW_DIRECTORY 1\nstatic inline int se_of_withdraw_directory(struct se_of_lease *lease,\n"
	if strings.Count(squashSpace(header), squashSpace(marker)) != 1 || strings.Count(squashSpace(header), squashSpace(withdraw)) != 1 {
		t.Error("final-free header lost the unconditional physical-reuse directory withdrawal")
	}
	// The single insert retry (and its non-aborting STALE return) is
	// unconditional in the birth header.
	raw, err = os.ReadFile("../full/shared_pool_opaque_birth_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	birth := string(raw)
	for _, pin := range []string{
		"#define SE_OP_INSERT_RETRY 1\nstatic __attribute__((noinline)) int se_op_replace_charged_child(",
		"\t\tif (status == SE_OL_STALE)\n\t\t\treturn -1;\n",
		"\tif (status == SE_OL_CONTENDED) {\n\t\tstatus = se_op_replace_charged_child(reservation, opaque_key,\n\t\t\tarchive);\n\t\tif (status != -1)\n\t\t\treturn status;\n\t\tstatus = se_ow_insert_zero(reservation->meta,\n",
	} {
		if strings.Count(squashSpace(birth), squashSpace(pin)) != 1 {
			t.Errorf("birth header lost the unconditional physical-reuse insert retry:\n%s", pin)
		}
	}
	if strings.Contains(birth, "FAIL_CLOSED_RATE_CANDIDATE") {
		t.Error("birth header gates behaviour on the fail-closed rate witness again")
	}
	var conditionals []string
	for _, line := range strings.Split(header, "\n") {
		if strings.HasPrefix(line, "#if") {
			conditionals = append(conditionals, line)
		}
	}
	if want := []string{
		"#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_FINAL_FREE_CANDIDATE_H",
		"#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE",
	}; !slices.Equal(conditionals, want) {
		t.Errorf("final-free header conditionals %q, want only %q: the withdrawal must not depend on any option", conditionals, want)
	}
	// SE_OC_WORD (se_oc_word) clamps the word index to the last bitmap
	// word for the verifier only; a caller still owes local < SE_OC_QUOTA,
	// so the documented precondition must stay next to the macro.
	raw, err = os.ReadFile("../full/shared_pool_opaque_charge_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	precondition := "/* Bitmap word of a slot-local TASK index.\n * Precondition: local < SE_OC_QUOTA."
	if strings.Count(squashSpace(string(raw)), squashSpace(precondition)) != 1 {
		t.Error("charge header lost the SE_OC_WORD precondition (local < SE_OC_QUOTA)")
	}
	// U1: above 4 words (TASK quota 512) the bitmap count stays a loop, or
	// the fork source and the task_alloc target exceed 512 bytes.
	if pin := "#if SE_OC_WORDS > 4\n#pragma clang loop unroll(disable)\n#endif\n\tfor (__u32 i = 0; i < SE_OC_WORDS; i++) {"; strings.Count(squashSpace(string(raw)), squashSpace(pin)) != 1 {
		t.Error("charge header lost the looped bitmap count above 4 words (TASK quota 512 stack)")
	}
}

// squashSpace removes all whitespace, so the compile guard pins survive
// clang-format re-wrapping and re-indentation while still failing when a
// guard, call or condition is removed or changed.
func squashSpace(s string) string {
	return strings.Join(strings.Fields(s), "")
}
