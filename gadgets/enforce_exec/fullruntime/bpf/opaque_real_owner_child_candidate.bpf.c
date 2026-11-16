// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Default-inert real-map composition candidate. No product image selects this
 * object: final-free settles only the exec/reader owner; native completion,
 * WORK/TASK reaping and the complete Ready proof are still absent. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#error "source capsule admission requires the real-policy verdict candidate"
#endif
/* 104-byte route with source pins (full/shared_route.h). Must precede the
 * first include of shared_route.h. */
#define ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE 1
#endif
/* G019 M4 product publisher: authenticated stage/publish/withdraw/recycle
 * and root-task adoption commands (opaque_real_owner_product_publisher.h).
 * Only on the product object and its product-source twins: it extends the
 * route anchor (104 -> 112 B), so every IDENT baseline stays without it. */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) &&      \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) ||   \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE) ||      \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE))
#error "the product publisher requires the product composition (fail-closed rate, source capsule, reap events, credit at exit)"
#endif
/* G019 gap 4 (review H1): every product object carries the same-bprm
 * script-interpreter continuation; without it a #! exec is refused. */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE)
#error "the product publisher requires the interpreter continuation"
#endif
/* G020: every product object collects the per-pass exec facts (path, fs
 * class, stdin, ancestors) on each evaluated pass, first and interpreter
 * (full/shared_pass_facts.h). Test objects opt in with the same flag. */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE)
#define ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE 1
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE) &&                \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE))
#error "the per-pass exec facts require the real-policy verdict candidate and the interpreter continuation"
#endif
/* G020 verdict events: every product-publisher object emits one
 * legacy-compatible verdict event per evaluated pass and per fail-closed
 * fault (full/shared_verdict_event.h, se_verdict_emit). Objects without the
 * publisher stay byte-identical. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
#define SE_VERDICT_EVENTS 1
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_WITNESS) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE)
#error "the per-pass fact witness requires the per-pass exec facts"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_WITNESS) && \
	defined(SE_PRODUCT_NO_TEST_RUN) &&                  \
	!defined(SE_PRODUCT_DIAGNOSTIC_TWIN)
#error "the per-pass fact witness is test-only: a product object never carries it"
#endif
#if defined(SE_PRODUCT_DIAGNOSTIC_TWIN) && SE_PRODUCT_DIAGNOSTIC_TWIN != 1
#error "SE_PRODUCT_DIAGNOSTIC_TWIN must be exactly 1"
#endif
#if defined(SE_PRODUCT_DIAGNOSTIC_TWIN) &&                                 \
	(!defined(SE_PRODUCT_NO_TEST_RUN) ||                               \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_PUBLISH_FAULT_DIAGNOSTIC))
#error "the product diagnostic twin is the product publisher object plus the publication fault injector and test-only fault injectors"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#define SE_EXEC_ROLE_FILL_BPF_LOOP 1
#endif
#define ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_FAULT_INLINE_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_OPEN_INLINE_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_SNAPSHOT_BRANCHLESS_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_OWNED_INLINE_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_CHOOSE_INLINE_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_SNAPSHOT_MATCH_NOINLINE_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_PARENT_PROJECT_SPLIT_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_PARENT_PROJECT_INLINE_DIAGNOSTIC 1
#define ENFORCE_EXEC_POOL_OPAQUE_CANCEL_OBSERVATION_INLINE_DIAGNOSTIC 1
/* The constructor's inline boundaries are verifier-budget diagnostics until
 * this complete real-map path has passed admitted-kernel qualification. */
#define ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC 1
/* G019 section 8 product object: no TC (TEST_RUN classifier) program, no
 * recovery authority, no disposable bootstrap or injector, and the product
 * reaper's reap command and wakeups. The TEST_RUN-only entrypoints of the
 * WORK completion probe and the terminal race are compiled out below. The
 * fail-closed injectors (selector and extended) are admitted only in the
 * product diagnostic twin (SE_PRODUCT_DIAGNOSTIC_TWIN), never in a product
 * object. */
#ifdef SE_PRODUCT_NO_TEST_RUN
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) ||                  \
	defined(ENFORCE_EXEC_POOL_OPAQUE_PRCTL_ARM_CANDIDATE) ||                  \
	defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC) ||       \
	defined(ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC) ||            \
	defined(ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC) ||  \
	defined(ENFORCE_EXEC_POOL_OPAQUE_PENDING_RECEIPT_DIAGNOSTIC) ||           \
	(defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC) &&     \
	 !defined(SE_PRODUCT_DIAGNOSTIC_TWIN)) ||                                 \
	(defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_EXT_DIAGNOSTIC) && \
	 !defined(SE_PRODUCT_DIAGNOSTIC_TWIN)) ||                                 \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE)
#error "product object has no TEST_RUN classifier programs and needs the product reaper"
#endif
#endif
/* G019 M4 revision headroom: the product publisher revises make-before-break
 * (it stages the new policy into a FREE object before the old one is
 * released), so with every binding published one policy object must still be
 * free. The product control refuses the same profile (PolicyObjects <=
 * Bindings) before any allocation. */
#if defined(SE_PRODUCT_NO_TEST_RUN)
_Static_assert(0ULL + SE_PROFILE_SLOTS_256 + SE_PROFILE_SLOTS_1024 +
			       SE_PROFILE_SLOTS_4096 + SE_PROFILE_SLOTS_16384 >
		       0ULL + SE_PROFILE_BINDINGS,
	       "product object needs a spare policy object for revision");
#endif
/* G019 option C: synchronous WORK return at settle. The settling program
 * returns the exact WORK it just moved to DONE at its own top level
 * (real_owner_work_sync_return), so a WORK credit no longer waits for the
 * userspace reaper; the reaper stays the fallback for every WORK the
 * synchronous return did not complete. Settle encoding: a settling call
 * returns its result in the low 32 bits and the settled WORK slot + 1 in
 * the high 32 bits of a 64-bit R0 (no stack); without the flag the same
 * calls return int and the macros are the identity. */
/* G019 lead decision (b): without the synchronous return a WORK credit waits
 * for the reaper, so no static capacity holds under reap latency (chain15/
 * fs6x20: 4 of 160 zero-gate runs refused at (W-3)/2 on both kernels). The
 * product requires the synchronous return; a non-sync capacity is a
 * measured, test-only figure. */
#if defined(SE_PRODUCT_NO_TEST_RUN) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE)
#error "the product object requires the synchronous WORK return"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE)
#error "synchronous WORK return requires the reap events and credit at exit"
#endif
#define SE_OWK_INIT_PAYLOAD_ZERO(slot) 0
#define SE_SETTLE_T __s64
#define SE_SETTLE_PACK(result, slot1) \
	((__s64)(((__u64)(slot1) << 32) | (__u32)(result)))
#define SE_SETTLE_RESULT(value) ((int)(value))
#define SE_SETTLE_SLOT(value) ((__u32)((__u64)(value) >> 32))
#define SE_DEATH_T __u32
#else
#define SE_SETTLE_T int
#define SE_SETTLE_PACK(result, slot1) (result)
#define SE_SETTLE_RESULT(value) (value)
#define SE_SETTLE_SLOT(value) (value)
#define SE_DEATH_T void
#define SE_OWK_REAP_CLAIMED(slot, cookie) se_owk_reap_step((slot), (cookie))
/* Without the flag the settling call still runs; only its slot is unused. */
#define SE_WORK_SYNC_RETURN(settled, site) ((void)(settled))
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_DECISION_WITNESS_DIAGNOSTIC) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE)
#error "the WORK decision witness requires the synchronous WORK return"
#endif
/* The terminal-race rendezvous (its witness map and the bounded bpf_ktime
 * spin it adds to every WORK completion) is diagnostic only. The product
 * object keeps only the TERMINAL_RACE tail-call target
 * opaque_real_owner_terminal_retain_target (never attached, no spin). */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC) && \
	!defined(SE_PRODUCT_NO_TEST_RUN)
#define SE_TERMINAL_RACE_RENDEZVOUS 1
#endif
#if (defined(ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_CLOSE_FAULT_DIAGNOSTIC) ||       \
     defined(ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_TASK_CLOSE_FAULT_DIAGNOSTIC)) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "post-publication close fault injection requires disposable bootstrap"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_CLOSE_FAULT_DIAGNOSTIC) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_TASK_CLOSE_FAULT_DIAGNOSTIC)
#error "inject only one post-publication close fault"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_NATIVE_CONFIG_GATE_CANDIDATE) &&        \
	((!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) &&      \
	  !defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE)) || \
	 defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC))
#error "native-config gate requires recovered control or the product publisher, and no synthetic bootstrap"
#endif
/* G019 M4 arming (fail-open fix): a product object arms its hooks only from
 * the authenticated node configuration the product control installs and
 * freezes (se_profile_matches(se_configuration)); the test gate map that
 * only the bootstrap publisher writes must not exist in it. */
#if defined(SE_PRODUCT_NO_TEST_RUN) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_NATIVE_CONFIG_GATE_CANDIDATE)
#error "the product object arms only from the authenticated node configuration (NATIVE_CONFIG_GATE)"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_READER_BEGIN_PROBE)
#error "reader lifecycle probe requires the begin probe"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE) && \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE))
#error "staged policy bridge requires exact reader and failure-terminal probes"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC) && \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_COMPLETION_PROBE) ||          \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE))
#error "success-source completion requires WORK completion and terminal producer"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_SOURCE_COMPLETION_DIAGNOSTIC) && \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_COMPLETION_PROBE) ||          \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE))
#error "failure-source completion requires WORK completion and exact failure frames"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_SOURCE_COMPLETION_DIAGNOSTIC)
static __attribute__((noinline)) SE_SETTLE_T
real_owner_work_completion_shape(__u64 key);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_TERMINAL_DRAIN_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_COMPLETION_PROBE) ||      \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_READER_BEGIN_PROBE)
#error "source terminal drain requires WORK completion and reader lifecycle"
#endif
static __attribute__((noinline)) int real_owner_source_terminal_drain(void);
static __attribute__((noinline)) int
real_owner_reader_quarantine_pending(__u64 physical);
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE)
#error "same-bprm continuation requires the exact policy bridge"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) &&     \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE))
#error "real-policy verdict requires staged evaluation and exact reader catalogue"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC)
#error "verdict candidate has no proved pre-dispatch interpreter class recovery"
#endif
/* G019 gap 4 (review H1): the same-bprm script-interpreter continuation.
 * Its pre-dispatch class is the exec capsule's frozen ORIGINAL class (the
 * capsule admission re-claims the original route and reports the later
 * admission, SE_CAP_LATER), and its receipt authentication needs the final
 * failed-exec frames. It replaces the disposable same-bprm diagnostic. */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE) &&       \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) ||      \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE) ||    \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_READER_BEGIN_PROBE))
#error "interpreter continuation requires the real-policy verdict, the source capsule and the final failed-exec frames"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC)
#error "interpreter continuation replaces the same-bprm continuation diagnostic"
#endif
/* Test-only (G019 gap 4 attached test): forces the continuation's WORK
 * resume to a mismatched stage class, i.e. a STALE resume refusal. Never
 * in a product object; admitted in the product diagnostic twin (the GAP
 * class of the live-node fail-closed injection test). */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_STALE_RESUME_DIAGNOSTIC) && \
	((defined(SE_PRODUCT_NO_TEST_RUN) &&                            \
	  !defined(SE_PRODUCT_DIAGNOSTIC_TWIN)) ||                      \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE))
#error "the stale-resume injector is test only and needs the interpreter continuation"
#endif
/* Test-only (G020 H2 attached test): the finish program's WORK suspension
 * of a clean proposal behaves as failed, so its staged decision event is
 * superseded by the pass's fault event. Never in a product object; admitted
 * in the product diagnostic twin only. */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_VERDICT_SUSPEND_FAULT_DIAGNOSTIC) && \
	((defined(SE_PRODUCT_NO_TEST_RUN) &&                              \
	  !defined(SE_PRODUCT_DIAGNOSTIC_TWIN)) ||                        \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE))
#error "the verdict suspend-fault injector is test only and needs the product publisher"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_POLICY_TASK_CLOSE_FAULT_DIAGNOSTIC) &&  \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC))
#error "policy close injection requires guarded verdict and disposable bootstrap"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
#error "real stage begin requires the exact real-policy WORK bridge"
#endif
/* This diagnostic selects the same bounded evaluator wire as the staged
 * fixture, but resolves its header through the real retained WORK and policy
 * cohort. It does not observe facts, evaluate rules or emit a verdict. */
#define ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE 1
#define ENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE 1
#define ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC 1
#define ENFORCE_EXEC_STAGE2_SOURCE_OBJECT 1
#define FE_BOUNDED_LOOP_CANDIDATE 1
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
#define FE_STAGE_RULES 1U
#define FE_STAGE_RELOOKUP_HEADER_CANDIDATE 1
#define FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC 1
#define FE_RULE_STEP_INLINE_DIAGNOSTIC 1
#define SE_OBJECT_RANGE_INLINE_DIAGNOSTIC 1
#define FM_WORK_RUN_STATE_DIAGNOSTIC 1
/* The successor already owns its lexical output ticket. Reuse it during
 * resume instead of reserving a second 64-byte ticket in the callee. */
#define ENFORCE_EXEC_POOL_OPAQUE_RESUME_OUTPUT_TICKET_DIAGNOSTIC 1
#endif
#define FM_STAGE_INLINE_INSTRUCTION_WINDOW 1
#define SE_POLICY_EVALUATOR_HEADER "evaluator_stage_candidate.h"
struct fm_blob;
struct fm_global_token;
struct se_policy_view;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
#define REAL_OWNER_STAGE_VIEW_INLINE __attribute__((always_inline))
#define REAL_OWNER_STAGE_BLOB_INLINE __attribute__((always_inline))
#else
#define REAL_OWNER_STAGE_VIEW_INLINE
#define REAL_OWNER_STAGE_BLOB_INLINE
#endif
static REAL_OWNER_STAGE_VIEW_INLINE inline struct se_policy_view *
real_owner_stage_view(const struct fm_global_token *);
static REAL_OWNER_STAGE_BLOB_INLINE inline const struct fm_blob *
real_owner_stage_blob(unsigned int, unsigned long long, unsigned int);
#define SE_POLICY_VIEW(ctx) \
	real_owner_stage_view((const struct fm_global_token *)(ctx))
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	real_owner_stage_blob((slot), (cookie), (key))
#endif
#define SE_CATALOGUE_FROM_BANK 1
/* WORK continuation stage that the stage/rule/propose programs consume. The
 * verdict build inserts a separate prepare program (stage 1 -> 2) because
 * history/catalogue/role preparation inside the policy program exceeded 1M
 * processed instructions and 512 stack bytes on exact AL2023 6.18. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#define REAL_OWNER_EVAL_STAGE 2
/* A proposed evaluation WORK stays suspended for the exec terminal, which
 * completes into it instead of charging a third credit (monotone next). */
#define REAL_OWNER_TERMINAL_STAGE (REAL_OWNER_EVAL_STAGE + 1)
#else
#define REAL_OWNER_EVAL_STAGE 1
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
/* G019 gap 4: pass p (0..SE_OWK_EXEC_PASSES - 1) of one exec runs prepare at
 * 3p+1, evaluation at 3p+2 and keeps its proposed WORK at the terminal stage
 * 3p+3 (pass 0: today's 1, 2, 3). Every successor resumes the stage CLASS
 * (residue, pass bound) and suspends to exactly the resumed stage + 1, so
 * the WORK is still single-owner and monotone; the highest stage is 18 of
 * SE_OWK_CONTINUATION_MAX 32. No pass charges a new WORK credit. */
#define SE_OWK_STAGE_CLASSES 1
#define REAL_OWNER_PREPARE_RESUME SE_OWK_STAGE_CLASS(1, SE_OWK_EXEC_PASSES - 1)
#define REAL_OWNER_EVAL_RESUME SE_OWK_STAGE_CLASS(2, SE_OWK_EXEC_PASSES - 1)
#define REAL_OWNER_TERMINAL_RESUME SE_OWK_STAGE_CLASS(0, SE_OWK_EXEC_PASSES - 1)
#define REAL_OWNER_NEXT_STAGE(ticket, fixed) ((ticket).continuation_stage + 1U)
#define SE_OWK_EVAL_VIEW_STAGE REAL_OWNER_EVAL_RESUME
#else
#define REAL_OWNER_PREPARE_RESUME 1
#define REAL_OWNER_EVAL_RESUME REAL_OWNER_EVAL_STAGE
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#define REAL_OWNER_TERMINAL_RESUME REAL_OWNER_TERMINAL_STAGE
#endif
#define REAL_OWNER_NEXT_STAGE(ticket, fixed) (fixed)
#define SE_OWK_EVAL_VIEW_STAGE REAL_OWNER_EVAL_STAGE
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_ADVANCE_DIAGNOSTIC
/* Disposable observation of the exact post-death locator CAS. */
struct se_ow_advance_observation {
	__u64 locator, observed, previous;
	__u32 stage, exact, attempts, reserved;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_ow_advance_observation);
} se_ow_advance_observation SEC(".maps");
static __always_inline void se_ow_advance_observe(__u32 stage, __u64 locator,
						  __u64 observed,
						  __u64 previous, __u32 exact)
{
	__u32 zero = 0;
	struct se_ow_advance_observation *o =
		bpf_map_lookup_elem(&se_ow_advance_observation, &zero);
	if (o) {
		o->locator = locator;
		o->observed = observed;
		o->previous = previous;
		o->stage = stage;
		o->exact = exact;
		o->attempts++;
	}
}
#define SE_OW_ADVANCE_DIAG(stage, locator, observed, previous, exact) \
	se_ow_advance_observe(stage, locator, observed, previous, exact)
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "abort injection requires successful-birth disposable bootstrap"
#endif
/* Test-only fault edge: every Nth published-zero child constructor takes the
 * exact semantic abort (phase ABORTED, charge still OWNED), the same path as
 * a naturally lost replacement. [0] of the selector is N; 0 disables it. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_abort_every SEC(".maps");
/* [0] constructors reaching the fault edge while enabled, [1] injected
 * aborts, [2] exact semantic aborts to ABORTED (injected or natural). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_abort_counts SEC(".maps");
static __always_inline void real_owner_abort_count(__u32 index)
{
	__u64 *count = bpf_map_lookup_elem(&opaque_real_abort_counts, &index);
	if (count)
		__sync_fetch_and_add(count, 1);
}
static __always_inline int real_owner_abort_inject(void)
{
	__u32 zero = 0;
	const __u32 *every =
		bpf_map_lookup_elem(&opaque_real_abort_every, &zero);
	__u64 *seen = bpf_map_lookup_elem(&opaque_real_abort_counts, &zero);
	__u32 n = every ? *every : 0;
	if (!n || !seen || __sync_add_and_fetch(seen, 1) % n)
		return 0;
	real_owner_abort_count(1);
	return 1;
}
#define SE_OP_ABORT_AFTER_PUBLISH_ZERO() real_owner_abort_inject()
#define SE_OP_ABORTED_WITNESS() real_owner_abort_count(2)
/* Test-only physical-reuse witness: replacement failures of a constructor
 * whose task address still had a directory entry (se_op_replace_charged_child):
 * [0] key gone before observation, [1] zero/withdrawn value, [2] predecessor
 * not holdable (claimed or not DEAD), [3] replacement claim lost. Leaf frame
 * only: the target chain is at the 512-byte combined stack. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_replace_failures SEC(".maps");
static __attribute__((noinline)) void real_owner_replace_failure(__u32 site)
{
	__u32 key = site < 4 ? site : 3;
	__u64 *count = bpf_map_lookup_elem(&opaque_real_replace_failures, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#define SE_OP_REPLACE_FAILURE(site) real_owner_replace_failure(site)
#endif
/* G025 step 7: a second disposable route of the opposite class on a second
 * cgroup, for migration. Admission must go through the source capsule. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_ROUTE_MIGRATION_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) ||           \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC) || \
	SE_PROFILE_BINDINGS < 2
#error "route migration requires the source capsule, disposable bootstrap and two bindings"
#endif
#endif
/* G025 step 8: test-only generation advance through the product route and
 * binding commit primitives, during churn. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_RELOAD_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "generation advance requires the source capsule and disposable bootstrap"
#endif
#endif
/* Deferred plain storage: the terminal receipt and failure-frame HASHes (and
 * the test-only birth receipts) are sized to the TASK pool. A test-only
 * override shrinks only these maps so every insert refusal is exercised. */
#ifdef SE_TEST_DEFERRED_STORAGE_ENTRIES
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "shrunken deferred storage requires its witness and disposable bootstrap"
#endif
#if SE_TEST_DEFERRED_STORAGE_ENTRIES < 1 || \
	SE_TEST_DEFERRED_STORAGE_ENTRIES > SE_PROFILE_TASKS
#error "deferred storage override must be 1..SE_PROFILE_TASKS"
#endif
#define SE_DEFERRED_STORAGE_ENTRIES SE_TEST_DEFERRED_STORAGE_ENTRIES
#else
#define SE_DEFERRED_STORAGE_ENTRIES SE_PROFILE_TASKS
#endif
/* Independent test-only per-map overrides (G025 step 4b): shrinking only the
 * terminal receipts while birth receipts stay full size makes the terminal
 * receipt insert refusal reachable. Each defaults to the shared size. */
#if defined(SE_TEST_TERMINAL_RECEIPT_ENTRIES) ||  \
	defined(SE_TEST_BIRTH_RECEIPT_ENTRIES) || \
	defined(SE_TEST_FAILURE_FRAME_ENTRIES)
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "per-map deferred storage overrides require the witness and disposable bootstrap"
#endif
#endif
#ifdef SE_TEST_TERMINAL_RECEIPT_ENTRIES
#if SE_TEST_TERMINAL_RECEIPT_ENTRIES < 1 || \
	SE_TEST_TERMINAL_RECEIPT_ENTRIES > SE_PROFILE_TASKS
#error "terminal receipt override must be 1..SE_PROFILE_TASKS"
#endif
#define SE_TERMINAL_RECEIPT_ENTRIES SE_TEST_TERMINAL_RECEIPT_ENTRIES
#else
#define SE_TERMINAL_RECEIPT_ENTRIES SE_DEFERRED_STORAGE_ENTRIES
#endif
#ifdef SE_TEST_BIRTH_RECEIPT_ENTRIES
#if SE_TEST_BIRTH_RECEIPT_ENTRIES < 1 || \
	SE_TEST_BIRTH_RECEIPT_ENTRIES > SE_PROFILE_TASKS
#error "birth receipt override must be 1..SE_PROFILE_TASKS"
#endif
#define SE_BIRTH_RECEIPT_ENTRIES SE_TEST_BIRTH_RECEIPT_ENTRIES
#else
#define SE_BIRTH_RECEIPT_ENTRIES SE_DEFERRED_STORAGE_ENTRIES
#endif
#ifdef SE_TEST_FAILURE_FRAME_ENTRIES
#if SE_TEST_FAILURE_FRAME_ENTRIES < 1 || \
	SE_TEST_FAILURE_FRAME_ENTRIES > SE_PROFILE_TASKS
#error "failure frame override must be 1..SE_PROFILE_TASKS"
#endif
#define SE_FAILURE_FRAME_ENTRIES SE_TEST_FAILURE_FRAME_ENTRIES
#else
#define SE_FAILURE_FRAME_ENTRIES SE_DEFERRED_STORAGE_ENTRIES
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) ||   \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE) ||  \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "deferred storage witness requires the verdict, birth and failure-frame disposable build"
#endif
/* Test-only insert-refusal witness, read by the attached verdict test.
 * [0] terminal receipt insert refused (verdict reader quarantined); [1] outer
 * failure frame insert refused; [2] handler failure frame insert refused;
 * [3] birth receipt insert refused (source finishes the birth WORK without a
 * target); [4] verdict reader quarantined because its frames were not ready. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 5);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_deferred_storage_refusals SEC(".maps");
static __always_inline void real_owner_storage_refused(__u32 index)
{
	__u64 *count = bpf_map_lookup_elem(
		&opaque_real_deferred_storage_refusals, &index);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#define SE_DEFERRED_STORAGE_REFUSED(index) real_owner_storage_refused(index)
#else
#define SE_DEFERRED_STORAGE_REFUSED(index) \
	do {                               \
	} while (0)
#endif
/* G025 decision 3: fail-closed rate witness. Default-off candidate, not a
 * test diagnostic: a future product loader reads these counters and must
 * report NotReady/degraded when their deltas are nonzero (or above its
 * threshold); see fullruntime.FailClosedRateVerdict. Each counts a managed
 * birth or exec that was refused (Strict) or left unevaluated (Audit):
 * [0] constructor TASK quota LIMIT; [1] source refused the birth before the
 * target (start_work refusal, parent/terminal fault); [2] birth WORK
 * finished without a constructor (missing target, target resume/open
 * failure; with the product publisher also an exec verdict-graph tail call
 * that returned: SE_GRAPH_MISS); [3] evaluation WORK refused (reader quarantined); [4] deferred
 * storage quarantine (terminal receipt refused, failure frames not ready);
 * [5] other constructor failure (STALE, CONTENDED, CORRUPT, not attempted).
 * G019 M0 exec-path classes, disjoint from [0..5] (a refused exec never
 * opens a reader, so it reaches no evaluation or storage class):
 * [6] first-exec qualification fault (real_owner_birth_qualify < 0 at
 * bprm_check on an owned route; at task_alloc it is already [1]); [7]
 * pending-receipt quarantine (owned exec refused while a prior terminal
 * receipt is pending or its drain faulted); [8] birth target could not open
 * the parent TASK (real_owner_child_open_parent in real_owner_child_finish);
 * [9] GAP: only the interpreter continuation (G019 gap 4, review H1;
 * ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE) refusing a later
 * pass of one exec (its receipt or failure frames, reader classification or
 * recovery, the exact suspended terminal WORK, the depth bound, the WORK
 * rebind, or a missing continue/prepare graph entry; reason in
 * opaque_real_interp_stats). A later pass with a terminal fault is refused
 * before any continuation as QUALIFY [6] or PENDING [7]; the migration
 * relabel (gap 5) is a status, never counted. Each counts against that
 * pass's exec attempt [1]. The G019
 * gaps 1-3 refusals land in CONSTRUCT [5], QUALIFY [6] and OPEN_PARENT
 * [8], never in GAP.
 * [10] is a subset, not a class: start_work exhausted SE_PROFILE_WORK_RETRIES
 * lost races; that refusal is also counted as [1], [3] or a refused
 * terminal fallback. Leaf frame only, at the existing witness call sites.
 * G019 M4 (product publisher only, U2): [11] ENTRY, reported apart and
 * outside Total like [10]: an exec on an OWNED route by a task with no TASK
 * at all (no se_opaque_keys entry: a runtime exec entry or a migration in).
 * With the product publisher [8] also counts the reader's own open or
 * reserve refusal (a TASK present but unusable, e.g. QUARANTINED in Strict),
 * and opaque_real_attempts counts every OWNED birth [0] and exec [1] claim:
 * the denominator of Total and of ENTRY.
 * [12] ADMISSION (product publisher only), outside Total like ENTRY: an exec
 * admission fault before any reader opens (SE_ROUTE_STRICT/AUDIT/INVARIANT
 * _FAULT from se_cap_admit or se_route_admit: capsule miss, busy, stale
 * retire, unpinned frozen capsule, freeze error, adopting/reserved/saturated
 * route, invariant; or an owned claim whose class differs from the frozen
 * one). Each also counts an exec attempt [1]; Strict denies, Audit allows,
 * neither silently. The fork source's admission faults (task_alloc:
 * adopting, reserved, saturated or invariant route) count a birth attempt
 * [0] plus ADMISSION the same way; the target's re-admission fault
 * (design 13.20) counts ADMISSION too, against the birth attempt the source
 * already counted (one class per attempt: never also CONSTRUCT); a target
 * re-admission that is not a fault (UNSELECTED) stays CONSTRUCT [5].
 * Another LSM's earlier deny is not ours to count. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#error "fail-closed rate witness requires the real-policy verdict candidate"
#endif
#define REAL_OWNER_RATE_LIMIT 0
#define REAL_OWNER_RATE_SOURCE 1
#define REAL_OWNER_RATE_MISSING_TARGET 2
#define REAL_OWNER_RATE_EVAL_WORK 3
#define REAL_OWNER_RATE_STORAGE 4
#define REAL_OWNER_RATE_CONSTRUCT 5
#define REAL_OWNER_RATE_QUALIFY 6
#define REAL_OWNER_RATE_PENDING 7
#define REAL_OWNER_RATE_OPEN_PARENT 8
#define REAL_OWNER_RATE_GAP 9
#define REAL_OWNER_RATE_WORK_RETRY 10
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
#define REAL_OWNER_RATE_ENTRY 11
#define REAL_OWNER_RATE_ADMISSION 12
#define REAL_OWNER_RATE_CLASSES 13
#else
#define REAL_OWNER_RATE_CLASSES 11
#endif
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, REAL_OWNER_RATE_CLASSES);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_fail_closed_rates SEC(".maps");
static __attribute__((noinline)) void real_owner_fail_closed_rate(__u32 index)
{
	__u32 key = index < REAL_OWNER_RATE_CLASSES ? index :
						      REAL_OWNER_RATE_CONSTRUCT;
	__u64 *count =
		bpf_map_lookup_elem(&opaque_real_fail_closed_rates, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#define SE_FAIL_CLOSED_RATE(index) real_owner_fail_closed_rate(index)
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_attempts SEC(".maps");
/* In the caller's existing frame (no new BPF-to-BPF frame). */
#define SE_RATE_ATTEMPT(index)                                          \
	do {                                                            \
		__u32 se_rate_attempt_key = (index);                    \
		__u64 *se_rate_attempt_count = bpf_map_lookup_elem(     \
			&opaque_real_attempts, &se_rate_attempt_key);   \
		if (se_rate_attempt_count)                              \
			__sync_fetch_and_add(se_rate_attempt_count, 1); \
	} while (0)
#endif
#else
#define SE_FAIL_CLOSED_RATE(index) \
	do {                       \
	} while (0)
#endif
/* G019 M4 (product publisher): a verdict-graph tail call that returns (an
 * empty PROG_ARRAY slot, or an exhausted tail-call budget) is a missing
 * target: counted in [2] like the task_alloc constructor's, and the site
 * then takes its static class verdict (Strict denies, Audit allows,
 * uncounted otherwise). Only the code after a bpf_tail_call reaches it. */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE)
#define SE_GRAPH_MISS() SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_MISSING_TARGET)
#else
#define SE_GRAPH_MISS() \
	do {            \
	} while (0)
#endif
/* G019 M1 product reaper wakeups. A compact (cookie, slot, kind) record
 * says that one exact charge became terminal: TASK DEAD (lsm/task_free after
 * the directory withdrawal and lease release), WORK DONE (death finish),
 * WORK ABORTED (constructor abort) or TASK ABORTED (exact semantic abort).
 * It is a hint, never authority: the reaper re-reads the exact phase and
 * cookie and the reap programs refuse anything not yet terminal. A refused
 * reserve changes no enforcement or accounting; it loses one wakeup, which
 * the reaper's fallback sweep covers, and is counted in
 * opaque_real_reap_event_drops. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) && \
	!defined(SE_PRODUCT_NO_TEST_RUN)
#error "reap events require the recovered reaper or the product object"
#endif
/* A held death lease on a DEAD charge is a PENDING visit; only credit at
 * exit witnesses one that stays held (SE_OR_TASK_HELD, HELD_STUCK). Without
 * it a leaked lease would be PENDING forever with no counter, so the
 * product reaper (reap events without recovery) requires credit at exit.
 * Reap-event profiles without it (the OFF objects) are recovery builds for
 * qualification only, never a product. */
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE)
#error "product reap events require credit at exit (the held-lease witness)"
#endif
#define REAL_OWNER_REAP_TASK_DEAD 1
#define REAL_OWNER_REAP_WORK_DONE 2
#define REAL_OWNER_REAP_WORK_ABORTED 3
#define REAL_OWNER_REAP_TASK_ABORTED 4
struct opaque_real_reap_event {
	__u64 cookie;
	__u32 slot, kind;
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} opaque_real_reap_events SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_reap_event_drops SEC(".maps");
static __always_inline void real_owner_reap_event(__u32 kind, __u32 slot,
						  __u64 cookie)
{
	struct opaque_real_reap_event *event = bpf_ringbuf_reserve(
		&opaque_real_reap_events, sizeof(*event), 0);
	if (!event) {
		__u32 zero = 0;
		__u64 *drops = bpf_map_lookup_elem(
			&opaque_real_reap_event_drops, &zero);
		if (drops)
			__sync_fetch_and_add(drops, 1);
		return;
	}
	event->cookie = cookie;
	event->slot = slot;
	event->kind = kind;
	bpf_ringbuf_submit(event, 0);
}
#define SE_REAP_EVENT(kind, slot, cookie) \
	real_owner_reap_event(REAL_OWNER_REAP_##kind, (slot), (cookie))
#endif
/* G019 credit at exit. The exact death settlement of a charged TASK
 * (DEAD, exec/reader, WORK death, native, directory withdrawal, release,
 * TASK_DEAD wakeup) runs in tp_btf/sched_process_exit instead of
 * lsm/task_free, so a TASK credit returns at exit, not after the
 * RCU-deferred free (~160 ms later). The exiting task never returns to
 * userspace: no later bprm_check, exec terminal, sched_process_exec or
 * task_alloc (as parent) can run with current == this task, and the
 * address stays allocated (zombie or RCU-pending), so no successor can be
 * born at it before task_free.
 *
 * se_exit_tombstones carries the exact identity (cookie, locator, slot) from
 * exit to free, keyed by the physical task key bytes. An address is reused
 * only after the slab free, so a tombstone its own free never consumed (a
 * failed delete, a missed task_free) can be met by a later lifetime at the
 * same address and is never trusted:
 *   - at exit, every tombstone already at the key is an earlier lifetime's
 *     (sched_process_exit fires once per task, before its free);
 *   - at free, the tombstone is this lifetime's only if its start equals
 *     task_struct.start_time (read through BTF at exit and at free) and the
 *     directory does not name another charge at the key (a value other than
 *     0 and the tombstone's locator: this task's own charge, still
 *     published because its exit settled nothing). start_time alone is not
 *     unique per lifetime: a non-leader exec (de_thread) takes the leader's
 *     start_time, start_boottime and pid, so a thread born at the reused
 *     address of a leader that exec'd that way can carry the earlier
 *     lifetime's start_time again (start_boottime is copied alike and adds
 *     nothing); the directory check is what separates such a charged
 *     successor whose exit inserted nothing. An uncharged successor that
 *     still matches finishes the earlier tombstone as if it were its own,
 *     which settles nothing of its own (it has no charge).
 *   RESERVED     inserted before se_of_record_death; the exact identity is
 *                written as soon as se_of_record_death took the lease;
 *   SETTLED      key DELETED and lease released at exit; free retires the
 *                exact terminal receipt and the tombstone (TASK_FREED);
 *   DIR_PENDING  the withdrawal was refused at exit (a receipt at the key,
 *                CONTENDED or a failed stage): the death lease stays held,
 *                so the reaper stays excluded (single deleter); free
 *                rebuilds the exact lease, resumes the withdrawal and
 *                releases it (TASK_DEAD, TASK_FREED);
 *   FREE_PENDING the free-time resume was refused too: free released the
 *                lease, the reaper's ordinary withdrawal retries as before
 *                this change, and the reaper's next visit of the exact
 *                charge retires the tombstone once no lease is held
 *                (active_leases == 0). A free that cannot rebuild the exact
 *                lease (identity, DEAD, active_leases == 1) or release it
 *                counts LEASE_FAULT and leaves it held: the reaper never
 *                retires that tombstone nor withdraws the key, so the slot
 *                stays charged (fail-closed, a permanent loss of that one
 *                slot, counted and reported Degraded);
 *   RETIRING     a reaper won the FREE_PENDING -> RETIRING CAS and alone
 *                deletes it (concurrent reapers lose the CAS);
 *   FREED        consumed by its own free (TASK_FREED counted) just before
 *                the delete; left only when that delete failed.
 * A stale tombstone (an earlier lifetime's, above) found at exit or at free
 * is counted STALE and finished as its own free would have: RESERVED and
 * FREED are deleted, SETTLED is counted FREED and deleted, DIR_PENDING
 * releases its held lease without resuming the withdrawal (FREE_PENDING, the
 * reaper withdraws); the task at hand then takes its normal path. A FREED
 * or RESERVED tombstone whose delete failed (TOMB_FAULT, Degraded) at an
 * address no later lifetime reuses is not swept: it keeps one entry of its
 * binding's share and of LIVE, bounded by the counted delete faults, and no
 * credit (its charge settled or was never touched); a sweep would need a
 * reaper-driven program over the map.
 * Reaper exclusion: a reaper visit of a DEAD charge whose death lease is
 * still held (an exit or free between withdrawal stages, a DIR_PENDING exit
 * awaiting its free, a LEASE_FAULT) is PENDING (real_owner_exit_tomb_reap),
 * never a fault: every reaper directory stage requires !active_leases.
 * Overflow is fail-closed by ordering: the tombstone is inserted
 * (BPF_NOEXIST) before se_of_record_death. A refused insert (the binding's
 * share or the map full, a busy bucket, or an earlier lifetime's tombstone
 * the reaper still owns) leaves the TASK untouched and the task_free
 * fallback settles it exactly as before: slow, never early. Each such
 * refusal is counted and reported Degraded (fullruntime/exit_credit.go).
 *
 * Accounting. A zombie holds no TASK credit: the quota bounds live tasks,
 * the tombstones bound exited-but-unfreed ones. Each binding (TASK account,
 * slot / SE_PROFILE_TASK_QUOTA) may hold at most SE_EXIT_TOMBSTONE_ACCOUNT
 * tombstones (opaque_real_exit_accounts), so one workload that keeps its
 * children as zombies overflows only its own share to the slow path; the
 * shares sum to the map size, so the map itself cannot fill while the
 * per-binding gauges are exact. Link order: attach the exit program before
 * lsm/task_free and detach it before lsm/task_free, or a task settled at
 * exit may miss its free-time consumption (then counted STALE at the
 * address's next lifetime). */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE
#error "credit at exit requires the product reap events"
#endif
/* Witness only: counted and skipped by the node Reaper. */
#define REAL_OWNER_REAP_TASK_FREED 5
#ifdef SE_TEST_EXIT_TOMBSTONE_ENTRIES
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC
#error "shrunken exit tombstones require the disposable bootstrap"
#endif
#if SE_TEST_EXIT_TOMBSTONE_ENTRIES < 1 || \
	SE_TEST_EXIT_TOMBSTONE_ENTRIES > 32 * SE_PROFILE_TASKS
#error "exit tombstone override must be 1..32*SE_PROFILE_TASKS"
#endif
#define SE_EXIT_TOMBSTONE_ENTRIES SE_TEST_EXIT_TOMBSTONE_ENTRIES
#else
/* U1 sizing: the tombstone table is a profile parameter of its own,
 * SE_PROFILE_EXIT_TOMBSTONES (node-wide, an exact multiple of the bindings),
 * sized for the exit burst, not for the TASK pool: it bounds tasks that
 * exited and await their RCU-deferred free (exit rate x exit-to-free
 * latency). Measured G019 chains 6-9 (1,000-birth back-to-back bursts,
 * steady 400/s, churn): live tombstones peaked at 824 node-wide (an older
 * build without exit-time birth-receipt retirement held ~4.3k). Without an
 * explicit value it stays 32 x SE_PROFILE_TASKS (4,096 / 8,192 / 16,384 at
 * 64/8, 128/16, 256/32: unchanged objects, >= 5x the measured peak). A
 * thread-sized TASK quota must set it explicitly (512/16: 8,192). */
#ifndef SE_PROFILE_EXIT_TOMBSTONES
#define SE_PROFILE_EXIT_TOMBSTONES (32 * SE_PROFILE_TASKS)
#endif
_Static_assert(
	SE_PROFILE_EXIT_TOMBSTONES >= SE_PROFILE_BINDINGS &&
		SE_PROFILE_EXIT_TOMBSTONES % SE_PROFILE_BINDINGS == 0 &&
		SE_PROFILE_EXIT_TOMBSTONES <= (1U << 20),
	"exit tombstones must be a multiple of the bindings, at most 2^20");
#define SE_EXIT_TOMBSTONE_ENTRIES SE_PROFILE_EXIT_TOMBSTONES
#endif
/* Per-binding share of the tombstones (S4: overflow stays in its account). */
#define SE_EXIT_TOMBSTONE_ACCOUNT \
	(SE_EXIT_TOMBSTONE_ENTRIES / SE_PROFILE_BINDINGS)
_Static_assert(SE_EXIT_TOMBSTONE_ACCOUNT >= 1,
	       "every binding needs at least one exit tombstone");
#define REAL_OWNER_EXIT_RESERVED 1
#define REAL_OWNER_EXIT_SETTLED 2
#define REAL_OWNER_EXIT_DIR_PENDING 3
#define REAL_OWNER_EXIT_FREE_PENDING 4
#define REAL_OWNER_EXIT_RETIRING 5
#define REAL_OWNER_EXIT_FREED_STAGE 6
/* flags: a receipt that is not this lifetime's stayed at the key. */
#define REAL_OWNER_EXIT_FOREIGN_RECEIPT 1
struct real_owner_exit_tombstone {
	__u64 cookie, locator, start;
	__u32 slot, stage, flags, account;
};
_Static_assert(sizeof(struct real_owner_exit_tombstone) == 40,
	       "exit tombstone wire");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_EXIT_TOMBSTONE_ENTRIES);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct real_owner_exit_tombstone);
} se_exit_tombstones SEC(".maps");
/* Witness (fullruntime/exit_credit.go). Exact when quiescent:
 * INSERTED == SETTLED + DIR_PENDING + UNSETTLED + UNSETTLED_FAULT, FREED ==
 * SETTLED + DIR_PENDING, DIR_PENDING == DIR_RESUMED + DIR_FAULTED,
 * REAPER_RETIRED == DIR_FAULTED, LIVE == 0; every DEAD TASK reap is SETTLED,
 * DIR_PENDING or FALLBACK_FREE. HIGH_WATER is the largest LIVE (a lower
 * bound: see real_owner_exit_tomb_insert). Refused inserts: OVERFLOW (map
 * full), ACCOUNT_OVERFLOW (the binding's share full), BUSY (-EBUSY bucket),
 * BLOCKED (an earlier lifetime's FREE_PENDING/RETIRING tombstone). UNSETTLED
 * is se_of_record_death CONTENDED (this task never owned the charge: benign);
 * UNSETTLED_FAULT is LIMIT, CORRUPT or STALE. RETIRE_LOST counts reaper
 * visits that lost the FREE_PENDING -> RETIRING CAS (benign). LEASE_FAULT
 * counts held exit leases a free could not rebuild exactly or release
 * (real_owner_exit_finish_pending): the slot stays charged. HELD_STUCK
 * counts DEAD charges whose death lease a reaper visit still found held
 * REAL_OWNER_EXIT_HELD_STUCK_NS after it first found it so, with no
 * accounted holder (real_owner_exit_held_watch): once per charge.
 * HIGH_CROSSED counts the inserts that raised LIVE to REAL_OWNER_EXIT_HIGH_MARK
 * (each upward crossing of the mark exactly once: the atomic increment
 * returns that value to one insert per crossing), so a repeat peak below
 * the lifetime HIGH_WATER is still seen in its window. */
#define REAL_OWNER_EXIT_INSERTED 0
#define REAL_OWNER_EXIT_LIVE 1
#define REAL_OWNER_EXIT_HIGH_WATER 2
#define REAL_OWNER_EXIT_OVERFLOW 3
#define REAL_OWNER_EXIT_STALE 4
#define REAL_OWNER_EXIT_SETTLED_COUNT 5
#define REAL_OWNER_EXIT_DIR_PENDING_COUNT 6
#define REAL_OWNER_EXIT_DIR_RESUMED 7
#define REAL_OWNER_EXIT_DIR_FAULTED 8
#define REAL_OWNER_EXIT_FALLBACK_FREE 9
#define REAL_OWNER_EXIT_FREED 10
#define REAL_OWNER_EXIT_REAPER_RETIRED 11
#define REAL_OWNER_EXIT_UNSETTLED 12
#define REAL_OWNER_EXIT_TOMB_FAULT 13
#define REAL_OWNER_EXIT_UNSETTLED_FAULT 14
#define REAL_OWNER_EXIT_BUSY 15
#define REAL_OWNER_EXIT_BLOCKED 16
#define REAL_OWNER_EXIT_ACCOUNT_OVERFLOW 17
#define REAL_OWNER_EXIT_RETIRE_LOST 18
#define REAL_OWNER_EXIT_LEASE_FAULT 19
#define REAL_OWNER_EXIT_HELD_STUCK 20
#define REAL_OWNER_EXIT_HIGH_CROSSED 21
#define REAL_OWNER_EXIT_COUNTERS 22
/* The high-water mark: the least LIVE with LIVE * 100 >= 75% of the map
 * (fullruntime/exit_credit.go ExitCreditHighWaterPercent). */
#define REAL_OWNER_EXIT_HIGH_MARK \
	((SE_EXIT_TOMBSTONE_ENTRIES * 75ULL + 99) / 100)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, REAL_OWNER_EXIT_COUNTERS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_exit_credit SEC(".maps");
/* Tombstones held per binding (gauges, SE_EXIT_TOMBSTONE_ACCOUNT each). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_BINDINGS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_exit_accounts SEC(".maps");
/* Per TASK slot: the charge (cookie) a reaper visit found DEAD with its
 * death lease held and no accounted holder, first seen at since (ktime);
 * counted once HELD_STUCK (real_owner_exit_held_watch). */
struct real_owner_exit_held {
	__u64 cookie, since;
	__u32 counted, reserved;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_TASKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct real_owner_exit_held);
} se_exit_held_watch SEC(".maps");
static __attribute__((noinline)) void real_owner_exit_count(__u32 index)
{
	__u64 *counter = bpf_map_lookup_elem(&opaque_real_exit_credit, &index);
	if (counter)
		__sync_fetch_and_add(counter, 1);
}
/* Every tombstone delete goes through here, so LIVE and the binding's gauge
 * stay exact. account is the tombstone's own (set at insert, never
 * rewritten). */
static __attribute__((noinline)) int real_owner_exit_tomb_delete(__u64 key,
								 __u32 account)
{
	if (bpf_map_delete_elem(&se_exit_tombstones, &key)) {
		real_owner_exit_count(REAL_OWNER_EXIT_TOMB_FAULT);
		return -1;
	}
	__u32 index = REAL_OWNER_EXIT_LIVE;
	__u64 *live = bpf_map_lookup_elem(&opaque_real_exit_credit, &index);
	if (live)
		__sync_fetch_and_add(live, -1);
	__u64 *held = bpf_map_lookup_elem(&opaque_real_exit_accounts, &account);
	if (held)
		__sync_fetch_and_add(held, -1);
	else
		real_owner_exit_count(REAL_OWNER_EXIT_TOMB_FAULT);
	return 0;
}
#endif
/* WORK start retries per lost bit race (each loss is a sibling's charge).
 * Default: one per WORK credit up to 16 (min(WORK quota, 16)), so
 * contention alone never refuses at 64/8 and 128/16. The
 * rolled retry loop is re-walked per attempt; 32 attempts exceeded the 8192
 * pending-jump limit in the completion probes on AL2023 6.12 (g25d), 16
 * loaded. A smaller bound refuses fail-closed, witnessed by rate [10]
 * (WORK_RETRY, a subset of [1]/[3]). */
#ifndef SE_PROFILE_WORK_RETRIES
#define SE_PROFILE_WORK_RETRIES \
	(SE_PROFILE_SCRATCH_QUOTA < 16 ? SE_PROFILE_SCRATCH_QUOTA : 16)
#endif
_Static_assert(
	SE_PROFILE_WORK_RETRIES >= 1 &&
		SE_PROFILE_WORK_RETRIES <= SE_PROFILE_SCRATCH_QUOTA &&
		SE_PROFILE_WORK_RETRIES <= 16,
	"WORK start retries must be 1..min(WORK quota, 16): the verifier's pending-jump bound");
/* G025 decision 2: the TASK and WORK quotas are the build-profile parameters
 * SE_PROFILE_TASK_QUOTA and SE_PROFILE_SCRATCH_QUOTA (WORK). The opaque
 * owner partitions each pool exactly per binding; the WORK account is one
 * 64-bit bitmap and the evaluation start_work retries at most once per WORK
 * credit. Only 64/8, 128/16 and 256/32 (two bindings) have been measured
 * against the 512-byte combined stack: requalify before widening. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
_Static_assert(
	(__u64)SE_PROFILE_BINDINGS *SE_PROFILE_TASK_QUOTA == SE_PROFILE_TASKS &&
		(__u64)SE_PROFILE_BINDINGS * SE_PROFILE_SCRATCH_QUOTA ==
			SE_PROFILE_SCRATCH,
	"verdict TASK/WORK pools must be partitioned exactly per binding");
/* U1: TASK quota 512 per binding (the thread-sized profile) is measured at
 * 512/16 and 512/32 on 6.12 and 6.18: every root <= 512 bytes once the TASK
 * bitmap count is a loop instead of one unrolled register set per word
 * (se_oc_bitmap_count, SE_OC_WORDS > 4; full/shared_pool_opaque_charge_candidate.h);
 * the fork source and the task_alloc target then sit at exactly 512. A quota
 * above 256 and below 512 adds words the same way and is not qualified. */
_Static_assert(
	((SE_PROFILE_TASK_QUOTA >= 1 && SE_PROFILE_TASK_QUOTA <= 256) ||
	 SE_PROFILE_TASK_QUOTA == 512) &&
		SE_PROFILE_SCRATCH_QUOTA >= 1 && SE_PROFILE_SCRATCH_QUOTA <= 32,
	"verdict quota profile outside the measured TASK 1..256 or 512 / WORK 1..32 range");
/* A WORK quota that is not a power of two grows se_owk_begin's frame (112 ->
 * 128 bytes: the slot arithmetic is no longer a mask), which puts the fork
 * source at 528 > 512 bytes combined stack: unloadable. Refuse it here, at
 * compile time (measured: 2, 4, 8 and 16 at 512; 3 at 528). */
_Static_assert((SE_PROFILE_SCRATCH_QUOTA & (SE_PROFILE_SCRATCH_QUOTA - 1)) == 0,
	       "verdict WORK quota must be a power of two (1..32)");
#endif
/* Test-only exact WORK high-water witness (G019 burst capacity): per WORK
 * account, the largest used count any accepted charge produced, copied
 * inside the account lock (shared_pool_opaque_work_candidate.h hooks) and
 * raised with a bounded CAS after the unlock. lost counts a raise that lost
 * 8 CAS rounds (the high-water is then a lower bound; tests require 0). It
 * observes only; nothing reads it in BPF. Never in a product object. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_HIGH_WATER_DIAGNOSTIC
#ifdef SE_PRODUCT_NO_TEST_RUN
#error "the WORK high-water witness is diagnostic only"
#endif
struct opaque_real_work_high_water {
	__u64 high;
	__u64 lost;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_BINDINGS);
	__type(key, __u32);
	__type(value, struct opaque_real_work_high_water);
} opaque_real_work_high_water SEC(".maps");
static __always_inline void real_owner_work_high_water(__u32 slot, __u32 used)
{
	struct opaque_real_work_high_water *high =
		bpf_map_lookup_elem(&opaque_real_work_high_water, &slot);
	if (!high)
		return;
	for (int i = 0; i < 8; i++) {
		__u64 seen = *(volatile __u64 *)&high->high;
		if (used <= seen || __sync_val_compare_and_swap(
					    &high->high, seen, used) == seen)
			return;
	}
	__sync_fetch_and_add(&high->lost, 1);
}
#define SE_OWK_CHARGED_DECL __u32 se_owk_charged_used = 0
#define SE_OWK_CHARGED_LOCKED(used) (se_owk_charged_used = (used))
#define SE_OWK_CHARGED(slot) \
	real_owner_work_high_water((slot), se_owk_charged_used)
#endif
/* Test-only WORK account fault-site witness (chain15 burst-nosync-s6): each
 * site that sets a WORK account's fault (full/shared_pool_opaque_work_
 * candidate.h sites 1-8, _work_reap_candidate.h site 9) also ORs its own
 * bit into the same fault word, under the account lock it already holds:
 * fault stays nonzero exactly as before (bit 0), and bits 1-9 name every
 * site that fired. No local, helper or map: the fork chain's se_owk_begin
 * sits at the 512-byte limit. The harness prints the word. Never in a
 * product object. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_FAULT_SITE_DIAGNOSTIC
#ifdef SE_PRODUCT_NO_TEST_RUN
#error "the WORK fault-site witness is diagnostic only"
#endif
#define SE_OWK_FAULT_SITE(site) (account->fault |= 1U << (site))
#define SE_OWK_FAULT_SITE_CLEAN(site) (account->fault = 1U | 1U << (site))
#endif
/* Test-only recovered-control composition. The physical admin registry
 * replaces TASK_STORAGE, but its guardian/admin protocol and native owner
 * must be qualified separately before any selected image may use it. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
#define ENFORCE_EXEC_SHARED_RECOVERY 1
#include "shared_recovery_kernel.h"
#endif
/* Generic role helpers have no lexical scope parameter in this candidate.
 * Only the explicit scoped WORK catalogue path below is used for projection;
 * unrelated generic lookups fail closed rather than infer current cgroup. */
#define ER_ACCEPTED_EPOCH(uid) (~0ULL)
#include "epoch_roles.h"
#include "shared_pool_opaque_real_control_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* The loader must install the matching static-class wrapper in each graph
 * and freeze every map before linking the source. No mutable map data or
 * receipt lookup is allowed to choose a failure verdict after dispatch. */
#define REAL_OWNER_CLASS_GRAPH(name)                   \
	struct {                                       \
		__uint(type, BPF_MAP_TYPE_PROG_ARRAY); \
		__uint(max_entries, 1);                \
		__type(key, __u32);                    \
		__type(value, __u32);                  \
	} name SEC(".maps")
REAL_OWNER_CLASS_GRAPH(opaque_real_policy_audit);
REAL_OWNER_CLASS_GRAPH(opaque_real_policy_strict);
REAL_OWNER_CLASS_GRAPH(opaque_real_prepare_audit);
REAL_OWNER_CLASS_GRAPH(opaque_real_prepare_strict);
REAL_OWNER_CLASS_GRAPH(opaque_real_stage_audit);
REAL_OWNER_CLASS_GRAPH(opaque_real_stage_strict);
REAL_OWNER_CLASS_GRAPH(opaque_real_rule_audit);
REAL_OWNER_CLASS_GRAPH(opaque_real_rule_strict);
REAL_OWNER_CLASS_GRAPH(opaque_real_finish_audit);
/* Test-only witness: rule-program re-entries (windows after the first). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_owner_rule_windows SEC(".maps");
REAL_OWNER_CLASS_GRAPH(opaque_real_finish_strict);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
/* G019 gap 4: the static-class interpreter continuation entry. */
REAL_OWNER_CLASS_GRAPH(opaque_real_continue_audit);
REAL_OWNER_CLASS_GRAPH(opaque_real_continue_strict);
#endif
#undef REAL_OWNER_CLASS_GRAPH
#else
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_policy_targets SEC(".maps");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_policy_stage_targets SEC(".maps");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_rule_targets SEC(".maps");
#endif
#endif
#endif /* static-class graphs versus original Audit diagnostics */
/* Test-only observation, never a policy or cleanup authority. Only an
 * unattached target reached through the source tail call may write it. */
struct opaque_real_owner_policy_witness {
	__u64 prepared, physical, cookie, invocation;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_real_owner_policy_witness);
} opaque_real_owner_policy_witness SEC(".maps");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
struct opaque_real_owner_rule_progress {
	int stage_begin, rule_eval, matched, observed_uid;
	__u64 rule_eval_count, matched_count;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_real_owner_rule_progress);
} opaque_real_owner_rule_progress SEC(".maps");
/* Test-only expected UID, set before the BPF seed. It is not a policy source
 * or admission authority; the rule target observes the actual current eUID. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_rule_uid_expect SEC(".maps");
static __attribute__((noinline)) void real_owner_rule_progress(__u32 stage,
							       int result)
{
	__u32 zero = 0;
	struct opaque_real_owner_rule_progress *progress =
		bpf_map_lookup_elem(&opaque_real_owner_rule_progress, &zero);
	if (!progress)
		return;
	if (stage == 0)
		progress->stage_begin = result;
	else if (stage == 1) {
		progress->rule_eval = result;
		if (result == 1)
			__sync_fetch_and_add(&progress->rule_eval_count, 1);
	} else if (stage == 2) {
		progress->matched = result;
		if (result == 1)
			__sync_fetch_and_add(&progress->matched_count, 1);
	} else if (stage == 3)
		progress->observed_uid = result;
}
#endif
/* The real route/snapshot/object cohort, not the lifecycle fixture's
 * synthetic policy maps, supplies the held WORK view. This remains an
 * opt-in diagnostic until source, terminal and native owner gates pass. */
#include "shared_policy_prepare.h"
#include "shared_pool_opaque_work_eval_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
#define SE_OWK_CURRENT_TASK() bpf_get_current_task_btf()
#include "shared_pool_opaque_work_suspended_read_candidate.h"
static REAL_OWNER_STAGE_VIEW_INLINE inline struct se_policy_view *
real_owner_stage_view(const struct fm_global_token *token)
{
	return token && !token->reserved ?
		       se_owk_suspended_view_from_token(token->slot,
							token->cookie) :
		       0;
}
static REAL_OWNER_STAGE_BLOB_INLINE inline const struct fm_blob *
real_owner_stage_blob(unsigned int slot, unsigned long long cookie,
		      unsigned int key)
{
	struct fm_global_token token = { .slot = slot, .cookie = cookie };
	return se_policy_data(real_owner_stage_view(&token), key);
}
#endif
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
static struct se_binding_snapshots *real_owner_work_binding_lookup(__u32 slot)
{
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &slot);
	return binding ? &binding->state : 0;
}
#define SE_OWK_BINDING_LOOKUP(slot) real_owner_work_binding_lookup(slot)
#endif
#define SE_OWK_CATALOGUE_EPOCH(scope, uid) se_catalogue_epoch((scope), (uid))
#define SE_POOL_CATALOGUE_ROW_NOINLINE 1
/* G019 M0: first-exec qualification is part of the verdict candidate, not a
 * diagnostic. The birth receipts, their issue/stamp/observe/retire path and
 * real_owner_birth_qualify are built whenever the verdict candidate is;
 * SUCCESSFUL_BIRTH_DIAGNOSTIC only adds the pure witness counters below. */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC)
#define SE_REAL_OWNER_BIRTH_QUALIFY 1
#endif
#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
/* A map row is never a successful-fork signal. task_alloc invalidates old
 * pointer state; only the charged, published child may stamp this receipt.
 * The post-success kernel tracepoint must still validate it before any
 * eligibility transition. User space cannot populate this diagnostic map. */
struct opaque_birth_receipt {
	__u64 child, child_cookie, child_locator;
	__u64 parent, parent_cookie, scope, generation, serial;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	/* G019 gap 2: the birth claim's execution class (1 Audit, 2 Strict). */
	__u32 slot, incarnation, record, state, observation, execution_class;
#else
	__u32 slot, incarnation, record, state, observation, reserved;
#endif
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_BIRTH_RECEIPT_ENTRIES);
	/* Stock Rocky 4.18 tracing programs cannot access runtime-allocated HASH
	 * values, so this map is preallocated. It is NOT bounded by the TASK
	 * pool: a receipt lives until the child's RCU-deferred free, including
	 * unconstructed children, so a full map makes the source finish the birth
	 * WORK without the target (fail closed in Strict). */
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct opaque_birth_receipt);
} opaque_birth_receipts SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_birth_receipt);
} opaque_birth_receipt_zero SEC(".maps");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
/* Test-only failed-birth witness: retired receipts that were issued and
 * stamped but never observed by sched_process_fork, i.e. copy_process failed
 * after security_task_alloc. [0] task_free retired it, [1] free_task did. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_birth_failed_retired SEC(".maps");
#endif
static __always_inline void real_owner_birth_retire(__u64 key, __u32 path)
{
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	const struct opaque_birth_receipt *receipt =
		bpf_map_lookup_elem(&opaque_birth_receipts, &key);
	if (receipt && receipt->state == 1 && receipt->child_cookie &&
	    !receipt->observation) {
		__u64 *count = bpf_map_lookup_elem(&opaque_birth_failed_retired,
						   &path);
		if (count)
			__sync_fetch_and_add(count, 1);
	}
#else
	(void)path;
#endif
	(void)bpf_map_delete_elem(&opaque_birth_receipts, &key);
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
/* Test-only birth accounting witness. [0] source birth start_work refused
 * before any WORK was charged; [1..5] target constructor status + 1 (OK,
 * STALE, CONTENDED, LIMIT, CORRUPT/other); [6] constructor not attempted
 * (route/binding/snapshot); [7] birth WORK finished without a constructor
 * (target resume/open failure or source missing target). Leaf frame only:
 * the source and target chains are at the 512-byte combined stack. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_birth_outcomes SEC(".maps");
static __attribute__((noinline)) void real_owner_birth_outcome(__u32 index)
{
	__u32 key = index < 8 ? index : 5;
	__u64 *count = bpf_map_lookup_elem(&opaque_birth_outcomes, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}
/* Test-only exact witness of the G019 M0 rate classes, counted where the
 * outcome is decided (the rate witness counts it from the returned result):
 * [0] owned exec refused on a first-exec qualification fault; [1] owned exec
 * refused on a pending terminal receipt or drain fault; [2] birth target
 * could not open the parent TASK. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_exec_exclusions SEC(".maps");
static __attribute__((noinline)) void real_owner_exec_exclusion(__u32 index)
{
	__u32 key = index < 3 ? index : 1;
	__u64 *count = bpf_map_lookup_elem(&opaque_real_exec_exclusions, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#define SE_EXEC_EXCLUSION_WITNESS(index) real_owner_exec_exclusion(index)
#endif
#endif
#ifndef SE_EXEC_EXCLUSION_WITNESS
#define SE_EXEC_EXCLUSION_WITNESS(index) \
	do {                             \
	} while (0)
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC
#if (!defined(ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC) &&              \
     !defined(SE_PRODUCT_DIAGNOSTIC_TWIN)) ||                                     \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE) ||          \
	!defined(                                                                 \
		ENFORCE_EXEC_POOL_OPAQUE_SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC) || \
	!defined(SE_REAL_OWNER_BIRTH_QUALIFY)
#error "fail-closed injectors require the abort injector or the product diagnostic twin, rate witness, success completion and birth qualification"
#endif
/* Test-only G019 fail-closed injectors, one selector each; 0 disables it:
 * every[0] pending receipt: only the first exact success terminal of each
 * task lifetime (task pointer and start_time, so a reused task_struct is a
 * new task) is an edge, so a later exec of the same task always follows
 * (the FORKR helper's "reexec"); the Nth edge is skipped, so its REGISTERED
 * receipt stays pending and that next owned exec is refused (rate [7]). A
 * later terminal of a marked task has no next exec and is never an edge.
 * every[1] open parent: the Nth birth target behaves as if
 * real_owner_child_open_parent failed (rate [8]); births whose parent is
 * skip_parent are no edge. every[2] qualification: the Nth successful
 * first-exec qualification at bprm_check is reported as a fault (rate [6]).
 * Each fault then takes the product's own fail-closed path. */
struct opaque_real_fc_inject_selector {
	__u32 every[3];
	__u32 reserved;
	__u64 skip_parent;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_fc_inject_selector);
} opaque_real_fc_inject_selector SEC(".maps");
/* [0..2] edges seen while enabled, [3..5] injected, per selector. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 6);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_fc_inject_counts SEC(".maps");
/* One task lifetime: a pending edge is its first success terminal only. */
struct opaque_real_fc_task {
	__u64 physical, start_time;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, struct opaque_real_fc_task);
	__type(value, __u32);
} opaque_real_fc_pending_marked SEC(".maps");
static __attribute__((noinline)) int real_owner_fc_inject(__u32 kind)
{
	__u32 zero = 0, edge = kind < 3 ? kind : 0;
	const struct opaque_real_fc_inject_selector *selector =
		bpf_map_lookup_elem(&opaque_real_fc_inject_selector, &zero);
	if (!selector)
		return 0;
	__u32 n = edge == 0 ? selector->every[0] :
		  edge == 1 ? selector->every[1] :
			      selector->every[2];
	if (!n || (edge == 1 &&
		   selector->skip_parent == (__u64)bpf_get_current_task_btf()))
		return 0;
	__u64 *seen = bpf_map_lookup_elem(&opaque_real_fc_inject_counts, &edge);
	if (!seen || __sync_add_and_fetch(seen, 1) % n)
		return 0;
	__u32 hit = edge + 3;
	__u64 *injected =
		bpf_map_lookup_elem(&opaque_real_fc_inject_counts, &hit);
	if (injected)
		__sync_fetch_and_add(injected, 1);
	return 1;
}
static __attribute__((noinline)) int real_owner_fc_pending_skip(__u64 physical)
{
	__u32 zero = 0, marked = 1;
	const struct opaque_real_fc_inject_selector *selector =
		bpf_map_lookup_elem(&opaque_real_fc_inject_selector, &zero);
	if (!selector || !selector->every[0])
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct opaque_real_fc_task id = { .physical = physical,
					  .start_time = task->start_time };
	if (bpf_map_lookup_elem(&opaque_real_fc_pending_marked, &id) ||
	    bpf_map_update_elem(&opaque_real_fc_pending_marked, &id, &marked,
				BPF_NOEXIST))
		return 0;
	return real_owner_fc_inject(0);
}
static __attribute__((noinline)) int real_owner_fc_qualify_fault(int qualified)
{
	return qualified < 0 || (qualified > 0 && real_owner_fc_inject(2));
}
#define SE_FC_PENDING_SKIP(physical) real_owner_fc_pending_skip(physical)
#define SE_FC_OPEN_PARENT_FAULT() real_owner_fc_inject(1)
#define SE_FC_QUALIFY_FAULT(qualified) real_owner_fc_qualify_fault(qualified)
#else
#define SE_FC_PENDING_SKIP(physical) 0
#define SE_FC_OPEN_PARENT_FAULT() 0
#define SE_FC_QUALIFY_FAULT(qualified) ((qualified) < 0)
#endif
/* The exit injector (below, with credit at exit) stays out of the product
 * diagnostic twin: the twin's fail-closed injectors are exactly the selector,
 * its counts and marker, and the extended injector. */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC) && \
	!defined(SE_PRODUCT_DIAGNOSTIC_TWIN)
#define SE_FC_EXIT_INJECTOR 1
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_EXT_DIAGNOSTIC
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE)
#error "the extended fail-closed injector requires the fail-closed injectors and the product publisher"
#endif
/* Test-only G019 extended fail-closed injectors (separate from the selector
 * above so that its objects keep their bytes), one period each; 0 disables:
 * every[0] exec open parent: the Nth owned exec (product branch of
 * real_owner_reader_begin_core) whose task has a TASK (se_opaque_keys hit)
 * behaves as if real_owner_child_open_parent failed: OPEN_PARENT [8], never
 * ENTRY; every[1] exec admission: the Nth owned first-pass exec admission
 * takes the frozen-class mismatch path (claim released, exec attempt [1],
 * ADMISSION [12]; Strict denies, Audit allows); every[2] birth admission:
 * the Nth owned fork admission (real_owner_child_prepare_claimed) releases
 * its claim before anything is parked and takes the source admission-fault
 * path (birth attempt [0], ADMISSION [12]; Strict refuses the fork, Audit
 * allows it unmanaged); every[3] target admission: the Nth fork target
 * (real_owner_child_claimed_construct) whose parked claim it took releases
 * it and takes the target re-admission fault path (ADMISSION [12] against
 * the source's birth attempt, never CONSTRUCT; Strict refuses the fork,
 * Audit allows it unmanaged); every[4] reader not begun: the Nth owned exec
 * whose TASK opened skips its reader begin (real_owner_reader_open_exact)
 * as if it failed: OPEN_PARENT [8], the TASK closed, no reader, no verdict
 * (Strict denies, Audit allows). Each fault then takes the product's own
 * path. */
struct opaque_real_fc_inject_ext {
	__u32 every[5];
	__u32 reserved;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_fc_inject_ext);
} opaque_real_fc_inject_ext SEC(".maps");
/* [0..4] edges seen while enabled, [5..9] injected, per period. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_fc_inject_ext_counts SEC(".maps");
static __attribute__((noinline)) int real_owner_fc_inject_ext(__u32 kind)
{
	__u32 zero = 0, edge = kind < 5 ? kind : 0;
	const struct opaque_real_fc_inject_ext *ext =
		bpf_map_lookup_elem(&opaque_real_fc_inject_ext, &zero);
	if (!ext)
		return 0;
	__u32 n = edge == 0 ? ext->every[0] :
		  edge == 1 ? ext->every[1] :
		  edge == 2 ? ext->every[2] :
		  edge == 3 ? ext->every[3] :
			      ext->every[4];
	if (!n)
		return 0;
	__u64 *seen =
		bpf_map_lookup_elem(&opaque_real_fc_inject_ext_counts, &edge);
	if (!seen || __sync_add_and_fetch(seen, 1) % n)
		return 0;
	__u32 hit = edge + 5;
	__u64 *injected =
		bpf_map_lookup_elem(&opaque_real_fc_inject_ext_counts, &hit);
	if (injected)
		__sync_fetch_and_add(injected, 1);
	return 1;
}
/* An edge only for a task with a TASK, so the refusal is [8], never ENTRY. */
static __attribute__((noinline)) int
real_owner_fc_exec_open_parent_fault(__u64 key)
{
	if (!bpf_map_lookup_elem(&se_opaque_keys, &key))
		return 0;
	return real_owner_fc_inject_ext(0);
}
#define SE_FC_EXEC_OPEN_PARENT_FAULT(key) \
	real_owner_fc_exec_open_parent_fault(key)
#define SE_FC_EXEC_ADMISSION_FAULT(later) \
	(!(later) && real_owner_fc_inject_ext(1))
#define SE_FC_BIRTH_ADMISSION_FAULT() real_owner_fc_inject_ext(2)
#define SE_FC_TARGET_ADMISSION_FAULT() real_owner_fc_inject_ext(3)
#define SE_FC_READER_BEGIN_FAULT() real_owner_fc_inject_ext(4)
#else
#define SE_FC_EXEC_OPEN_PARENT_FAULT(key) 0
#define SE_FC_EXEC_ADMISSION_FAULT(later) 0
#define SE_FC_BIRTH_ADMISSION_FAULT() 0
#define SE_FC_TARGET_ADMISSION_FAULT() 0
#define SE_FC_READER_BEGIN_FAULT() 0
#endif
#include "shared_pool_opaque_inherit_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
#include "shared_pool_opaque_exec_work_completion_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#include "shared_pool_opaque_exec_prepare_candidate.h"
#include "shared_pool_opaque_exec_propose_candidate.h"
#endif
#endif
#include "shared_pool_opaque_final_semantic_candidate.h"

#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
/* Plain, bounded diagnostic mailbox. The tracing callback cannot access a
 * map whose values contain spinlocks on stock Rocky 4.18. This receipt is
 * evidence only: a future authenticated TC consumer must validate the exact
 * live owner and release its reader; this map alone never grants cleanup. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_TERMINAL_RECEIPT_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct se_exec_terminal_receipt);
} se_exec_terminal_receipts SEC(".maps");
/* Both actual terminal producers use this exact, one-way transition. A
 * failed exec's outer frame supplies independent identity; the success
 * tracepoint supplies the live receipt's identity and bprm. Only the first
 * REGISTERED -> terminal CAS can win. This does not grant cleanup authority. */
static __always_inline int
real_owner_terminal_transition(struct se_exec_terminal_receipt *receipt,
			       __u64 physical, __u64 bprm, __u64 cookie,
			       __u64 locator, __u64 invocation, __u64 scope,
			       __u64 generation, __u32 terminal)
{
	if (!receipt || !physical || !bprm || !cookie || !locator ||
	    !invocation || !scope || !generation || receipt->reserved ||
	    (terminal != SE_EXEC_TERMINAL_SUCCESS &&
	     terminal != SE_EXEC_TERMINAL_FAILURE) ||
	    receipt->physical != physical || receipt->bprm != bprm ||
	    receipt->cookie != cookie || receipt->locator != locator ||
	    receipt->invocation != invocation || receipt->scope != scope ||
	    receipt->generation != generation)
		return 0;
	return __sync_val_compare_and_swap(&receipt->phase,
					   SE_EXEC_TERMINAL_REGISTERED,
					   terminal) ==
	       SE_EXEC_TERMINAL_REGISTERED;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PENDING_RECEIPT_DIAGNOSTIC
/* Test-only injection of a mismatched receipt before the real bprm source.
 * Only the exact isolated physical task chosen by the controller is touched.
 * The separate cleanup entrypoint refuses to delete any other receipt. */
struct opaque_real_pending_selector {
	__u64 physical;
	__u64 stale_cookie;
	__u64 stale_locator;
	__u64 cgroup;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_pending_selector);
} opaque_real_pending_selector SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
	__type(key, __u64);
	__type(value, struct opaque_real_pending_selector);
} opaque_real_pending_history SEC(".maps");
static __attribute__((noinline)) int real_pending_receipt_inject(void)
{
	__u32 zero = 0;
	const struct opaque_real_pending_selector *selected =
		bpf_map_lookup_elem(&opaque_real_pending_selector, &zero);
	__u64 physical = (__u64)bpf_get_current_task_btf();
	if (!selected || selected->physical != physical)
		selected = bpf_map_lookup_elem(&opaque_real_pending_history,
					       &physical);
	if (!selected || !physical || selected->physical != physical ||
	    !selected->cgroup ||
	    selected->cgroup != bpf_get_current_cgroup_id() ||
	    !selected->stale_cookie || !selected->stale_locator)
		return 0;
	struct se_exec_terminal_receipt receipt = {
		.physical = physical,
		.bprm = 1,
		.cookie = selected->stale_cookie,
		.locator = selected->stale_locator,
		.invocation = 1,
		.scope = 10,
		.generation = 1,
		.phase = SE_EXEC_TERMINAL_REGISTERED,
	};
	(void)bpf_map_update_elem(&se_exec_terminal_receipts, &physical,
				  &receipt, BPF_NOEXIST);
	return 0;
}
SEC("tc")
int opaque_real_pending_receipt_cleanup(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const struct opaque_real_pending_selector *selected =
		bpf_map_lookup_elem(&opaque_real_pending_selector, &zero);
	if (!selected || !selected->physical || !selected->stale_cookie ||
	    !selected->stale_locator)
		return 1;
	const struct se_exec_terminal_receipt *receipt = bpf_map_lookup_elem(
		&se_exec_terminal_receipts, &selected->physical);
	if (!receipt || receipt->physical != selected->physical ||
	    receipt->cookie != selected->stale_cookie ||
	    receipt->locator != selected->stale_locator ||
	    receipt->phase != SE_EXEC_TERMINAL_REGISTERED)
		return 2;
	return bpf_map_delete_elem(&se_exec_terminal_receipts,
				   &selected->physical) ?
		       3 :
		       0;
}
#endif
#endif

/* The reaper visit helpers (and the credit-at-exit pre-visit) serve both the
 * recovery pool reaper and the product reap command opaque_real_reap; the
 * reaper wire, control, chunk and transport are recovery-only. */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE)
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
#define ENFORCE_EXEC_POOL_REAPER_CANDIDATE 1
#include "shared_pool_reaper_wire_candidate.h"
#define SE_POOL_T SE_OL_TASKS
#define SE_POOL_W SE_OWK_WORKS
#include "shared_pool_reaper_control_candidate.h"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE
/* A held death lease is accounted while this charge's own tombstone shows
 * its holder: DIR_PENDING (the exit kept it until its free, or the free is
 * resuming it) or FREE_PENDING (the free set it before its release, or
 * counted LEASE_FAULT). Anything else holding the lease is a program in
 * flight (an exit before it wrote its identity, the task_free fallback
 * between its stages: microseconds) or a lease nobody will release: more
 * than one lease, a DIR_PENDING whose free never came after its tombstone
 * was lost, a release that failed after the tombstone was deleted (also
 * LEASE_FAULT). Such a visit is PENDING, never a fault; this watch counts
 * HELD_STUCK (Degraded) once the same charge is still found so
 * REAL_OWNER_EXIT_HELD_STUCK_NS after a visit first found it, so a held
 * lease can never hide a lost holder forever. An accounted visit or a
 * lease-free visit of the charge clears the watch. */
#define REAL_OWNER_EXIT_HELD_STUCK_NS 1000000000ULL
static __attribute__((noinline)) void real_owner_exit_held_clear(__u32 slot,
								 __u64 cookie)
{
	struct real_owner_exit_held *watch =
		bpf_map_lookup_elem(&se_exit_held_watch, &slot);
	if (watch && watch->cookie == cookie)
		watch->cookie = 0;
}
static __attribute__((noinline)) void real_owner_exit_held_watch(__u32 slot,
								 __u64 cookie,
								 __u64 locator,
								 __u32 leases)
{
	const __u64 *original = archive_lookup(slot);
	if (leases == 1 && original && *original) {
		__u64 key = *original;
		struct real_owner_exit_tombstone *tomb =
			bpf_map_lookup_elem(&se_exit_tombstones, &key);
		if (tomb && tomb->cookie == cookie &&
		    tomb->locator == locator && tomb->slot == slot &&
		    (tomb->stage == REAL_OWNER_EXIT_DIR_PENDING ||
		     tomb->stage == REAL_OWNER_EXIT_FREE_PENDING)) {
			real_owner_exit_held_clear(slot, cookie);
			return;
		}
	}
	struct real_owner_exit_held *watch =
		bpf_map_lookup_elem(&se_exit_held_watch, &slot);
	if (!watch)
		return;
	__u64 now = bpf_ktime_get_ns();
	if (watch->cookie != cookie) {
		watch->counted = 0;
		watch->since = now;
		watch->cookie = cookie;
		return;
	}
	if (watch->counted ||
	    now - watch->since < REAL_OWNER_EXIT_HELD_STUCK_NS)
		return;
	if (__sync_val_compare_and_swap(&watch->counted, 0, 1) == 0)
		real_owner_exit_count(REAL_OWNER_EXIT_HELD_STUCK);
}
#define SE_OR_TASK_HELD(slot, cookie, locator, leases) \
	real_owner_exit_held_watch((slot), (cookie), (locator), (leases))
/* Reaper visit pre-step of the exact charge (SE_OR_TASK_PRE_VISIT). A DEAD
 * charge whose death lease is still held never reaches it: se_or_task_visit
 * reads active_leases in the same lock section as its stage snapshot and is
 * PENDING then (the exit or free holding it is between withdrawal stages, a
 * DIR_PENDING exit awaits its free, or a free counted LEASE_FAULT), which
 * also keeps a FREE_PENDING tombstone from being retired before its lease is
 * released; real_owner_exit_held_watch witnesses a lease that stays held.
 * This step retires a FREE_PENDING tombstone of this exact charge. Its task was
 * freed, its lease released, and the archive still holds its key bytes
 * (only the reaper zeroes it, after this visit step). Exit and
 * free never delete FREE_PENDING or RETIRING, and no successor can insert at
 * this key while the tombstone exists (BPF_NOEXIST). Concurrent reapers are
 * safe by CAS: only the visit that moves stage FREE_PENDING -> RETIRING
 * deletes, after re-checking the exact identity, which nobody else writes
 * while RETIRING. A visit that lost the CAS returns PENDING (the winner may
 * not have deleted yet), and a later lifetime's tombstone at the same key
 * (RESERVED .. FREED, or FREE_PENDING with another cookie) is never
 * deleted here: a stale reaper that read FREE_PENDING before a reuse fails
 * the CAS or the identity re-check. Returns nonzero (visit PENDING) when
 * the delete failed or the CAS was lost, so the reaper retries before it can
 * zero the archive. */
static __attribute__((noinline)) int
real_owner_exit_tomb_reap(__u32 slot, __u64 cookie, __u64 locator)
{
	real_owner_exit_held_clear(slot, cookie);
	const __u64 *original = archive_lookup(slot);
	if (!original || !*original)
		return 0;
	__u64 key = *original;
	struct real_owner_exit_tombstone *tomb =
		bpf_map_lookup_elem(&se_exit_tombstones, &key);
	if (!tomb || tomb->stage != REAL_OWNER_EXIT_FREE_PENDING ||
	    tomb->cookie != cookie || tomb->locator != locator ||
	    tomb->slot != slot)
		return 0;
	if (__sync_val_compare_and_swap(
		    &tomb->stage, REAL_OWNER_EXIT_FREE_PENDING,
		    REAL_OWNER_EXIT_RETIRING) != REAL_OWNER_EXIT_FREE_PENDING) {
		real_owner_exit_count(REAL_OWNER_EXIT_RETIRE_LOST);
		return 1;
	}
	if (tomb->cookie != cookie || tomb->locator != locator ||
	    tomb->slot != slot) {
		/* The element was reused by a later lifetime between the checks:
		 * not this charge's tombstone. Hand it back untouched. */
		tomb->stage = REAL_OWNER_EXIT_FREE_PENDING;
		real_owner_exit_count(REAL_OWNER_EXIT_RETIRE_LOST);
		return 0;
	}
	if (real_owner_exit_tomb_delete(key, tomb->account)) {
		tomb->stage = REAL_OWNER_EXIT_FREE_PENDING;
		return 1;
	}
	real_owner_exit_count(REAL_OWNER_EXIT_REAPER_RETIRED);
	return 0;
}
#define SE_OR_TASK_PRE_VISIT(slot, cookie, locator)               \
	(real_owner_exit_tomb_reap((slot), (cookie), (locator)) ? \
		 SE_OR_PENDING :                                  \
		 SE_OR_EMPTY)
#endif
#include "shared_pool_opaque_reaper_visit_candidate.h"
/* Product/qualification profile: omit the recovery-only pool reaper
 * (se_pool_reaper_* programs, se_pool_reap_* maps); the visit helpers above
 * stay for the product reap command opaque_real_reap. */
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) && \
	!defined(SE_PRODUCT_NO_POOL_REAPER)
/* Reaper transport is not selected by the product. Its request is writable
 * only by the controller; control and receipt are writable only by BPF. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct se_pool_request);
} se_pool_reap_request SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_pool_control);
} se_pool_reap_control SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_pool_receipt);
} se_pool_reap_receipt SEC(".maps");
#include "shared_pool_opaque_reaper_chunk_candidate.h"
#include "shared_pool_reaper_transport_candidate.h"
#endif
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE
/* G019 M1 product reap command: one exact reap step of one charge, run with
 * BPF_PROG_TEST_RUN from the node reaper (a syscall program is never
 * attached). The argument is the caller's own context, so concurrent callers
 * share no request map. It grants nothing: TASK requires the exact charge
 * cookie, and both steps refuse (PENDING/STALE/EMPTY) anything not yet
 * terminal. Codes: WORK = se_owk_reap_step, TASK = se_or_task_visit, 255 =
 * malformed command; a TASK cookie the charge no longer carries is PENDING. */
struct opaque_real_reap_command {
	__u64 cookie;
	__u32 slot, kind;
};
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE
/* Per-WORK visit claim (option C). A visitor of one WORK charge (the
 * synchronous return for its whole sequence, the reap command for one step)
 * CASes the slot's claim from 0 to the charge cookie and releases it on
 * every path; any other visitor meanwhile gets SE_OWK_CLAIM_HELD and touches
 * nothing. The claim is never taken while a spin lock is held. TASK charges
 * keep the single-reaper rule (no claim). The reap command watches a claim
 * it keeps finding held: still the same claim REAL_OWNER_WORK_CLAIM_STUCK_NS
 * after it first saw it counts WORK_SYNC_STUCK once (Degraded), so a lost
 * release can never hold a credit silently (the held-lease rule). */
#define SE_OWK_CLAIM_HELD 6
#define REAL_OWNER_WORK_CLAIM_STUCK_NS 1000000000ULL
struct se_owk_visit_claim {
	__u64 claim, seen, since;
	__u32 counted, reserved;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OWK_WORKS);
	__type(key, __u32);
	__type(value, struct se_owk_visit_claim);
} se_owk_visit_claims SEC(".maps");
/* Synchronous WORK return witness. Its presence is also the "has the
 * synchronous return" signal (capacity (W-1)/2). Settled counts the WORKs a
 * settling program handed to the synchronous return, per site; each ends as
 * exactly one of returned, claim-lost (the reaper held the claim and
 * finishes the WORK), stale (the charge no longer named a just-settled
 * WORK), pending or fault (a stage refused: the WORK waits for the reaper;
 * Degraded). stuck is counted by the reap command (above). */
#define REAL_OWNER_WORK_SYNC_SETTLED_BIRTH 0
#define REAL_OWNER_WORK_SYNC_SETTLED_EXEC 1
#define REAL_OWNER_WORK_SYNC_SETTLED_DEATH 2
#define REAL_OWNER_WORK_SYNC_RETURNED 3
#define REAL_OWNER_WORK_SYNC_CLAIM_LOST 4
#define REAL_OWNER_WORK_SYNC_STALE 5
#define REAL_OWNER_WORK_SYNC_PENDING 6
#define REAL_OWNER_WORK_SYNC_FAULT 7
#define REAL_OWNER_WORK_SYNC_STUCK 8
#define REAL_OWNER_WORK_SYNC_COUNTERS 9
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, REAL_OWNER_WORK_SYNC_COUNTERS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_work_sync SEC(".maps");
static __attribute__((noinline)) void real_owner_work_sync_count(__u32 index)
{
	__u64 *count = bpf_map_lookup_elem(&opaque_real_work_sync, &index);
	if (count)
		__sync_fetch_and_add(count, 1);
}
/* Test-only decision witness (never in a product object). The synchronous
 * return zeroes the evaluation WORK's payload before a test harness could
 * read its decision; this snapshots the decision fields the harness checks
 * (se_invocation observation.evaluator.decision deny/mode, as its payload
 * read before a reap does) right before the return, under the visit claim,
 * for every WORK carrying a decision. Last snapshot wins, as the harness's
 * own payload read; count is the number of snapshots. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_DECISION_WITNESS_DIAGNOSTIC
#ifdef SE_PRODUCT_NO_TEST_RUN
#error "the WORK decision witness is diagnostic only"
#endif
struct opaque_real_work_decision {
	__u64 count, cookie;
	__u32 deny, mode;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct opaque_real_work_decision);
} opaque_real_work_decision SEC(".maps");
static __attribute__((noinline)) void
real_owner_work_decision_snapshot(__u32 slot, __u64 cookie)
{
	__u32 zero = 0;
	struct se_owk_payload *payload = SE_OWK_PAYLOAD_LOOKUP(slot);
	struct opaque_real_work_decision *witness =
		bpf_map_lookup_elem(&opaque_real_work_decision, &zero);
	if (!payload || !witness)
		return;
	const struct fe_decision *decision =
		&payload->semantic.observation.evaluator.decision;
	__u32 mode = decision->mode;
	if (!mode)
		return;
	witness->deny = decision->deny;
	witness->mode = mode;
	witness->cookie = cookie;
	__sync_fetch_and_add(&witness->count, 1);
}
#define SE_WORK_DECISION_SNAPSHOT(slot, cookie) \
	real_owner_work_decision_snapshot((slot), (cookie))
#else
#define SE_WORK_DECISION_SNAPSHOT(slot, cookie) ((void)0)
#endif
/* One reap-command step under the visit claim. */
static __attribute__((noinline)) int real_owner_work_reap_claimed(__u32 slot,
								  __u64 cookie)
{
	struct se_owk_visit_claim *claim =
		bpf_map_lookup_elem(&se_owk_visit_claims, &slot);
	if (!claim)
		return SE_OWK_CORRUPT;
	__u64 held = __sync_val_compare_and_swap(&claim->claim, 0, cookie);
	if (held) {
		__u64 now = bpf_ktime_get_ns();
		if (claim->seen != held) {
			claim->seen = held;
			claim->since = now;
			claim->counted = 0;
		} else if (!claim->counted &&
			   now - claim->since >=
				   REAL_OWNER_WORK_CLAIM_STUCK_NS &&
			   __sync_val_compare_and_swap(&claim->counted, 0, 1) ==
				   0) {
			real_owner_work_sync_count(REAL_OWNER_WORK_SYNC_STUCK);
		}
		return SE_OWK_CLAIM_HELD;
	}
	claim->seen = 0;
	int result = se_owk_reap_step(slot, cookie);
	(void)__sync_val_compare_and_swap(&claim->claim, cookie, 0);
	return result;
}
struct real_owner_work_sync_ctx {
	__u64 cookie;
	__u32 slot;
	int result;
};
#ifndef SE_OWK_SYNC_STRAIGHT_LINE
static long real_owner_work_sync_step(__u64 index, void *raw)
{
	struct real_owner_work_sync_ctx *ctx = raw;
	(void)index;
	ctx->result = se_owk_reap_step(ctx->slot, ctx->cookie);
	return ctx->result != SE_OWK_PROGRESS;
}
#endif
/* The synchronous return of the WORK a settling program just moved to DONE
 * (settled = its slot + 1; 0: nothing settled). Called only at a settling
 * program's top level: the bpf_loop ctx lives in this frame, never in a
 * root frame. The cookie is read from the charge; only a charge whose meta
 * is still DONE or ABORTED under that same cookie is visited, so a stale or
 * reused slot is counted stale and left alone. The claim is tried once: a
 * reaper step holding it finishes the WORK itself (claim-lost). The seven
 * reaper stages run unchanged, one per iteration, and stop at the first
 * result that is not PROGRESS. Every exit other than returned or claim-lost
 * emits WORK_DONE again, so the reaper always has a recovery wakeup. */
static __attribute__((noinline)) void real_owner_work_sync_return(__u32 settled,
								  __u32 site)
{
	if (!settled || settled > SE_OWK_WORKS)
		return;
	real_owner_work_sync_count(site);
	__u32 slot = settled - 1;
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(slot);
	struct se_owk_meta *meta = SE_OWK_META_LOOKUP(slot);
	struct se_owk_visit_claim *claim =
		bpf_map_lookup_elem(&se_owk_visit_claims, &slot);
	if (!charge || !meta || !claim) {
		real_owner_work_sync_count(REAL_OWNER_WORK_SYNC_FAULT);
		return;
	}
	__u64 cookie = *(volatile __u64 *)&charge->cookie;
	bpf_spin_lock(&meta->lock);
	int settled_exact =
		cookie && meta->cookie == cookie &&
		(meta->phase == SE_OWK_DONE || meta->phase == SE_OWK_ABORTED);
	bpf_spin_unlock(&meta->lock);
	if (!settled_exact) {
		real_owner_work_sync_count(REAL_OWNER_WORK_SYNC_STALE);
		if (cookie)
			SE_REAP_EVENT(WORK_DONE, slot, cookie);
		return;
	}
	if (__sync_val_compare_and_swap(&claim->claim, 0, cookie)) {
		real_owner_work_sync_count(REAL_OWNER_WORK_SYNC_CLAIM_LOST);
		return;
	}
	/* Before stage 3 zeroes the payload (test-only witness). */
	SE_WORK_DECISION_SNAPSHOT(slot, cookie);
	struct real_owner_work_sync_ctx ctx = {
		.cookie = cookie,
		.slot = slot,
		.result = SE_OWK_PENDING,
	};
#ifdef SE_OWK_SYNC_STRAIGHT_LINE
	/* Fallback if bpf_loop with spin locks in its callback is refused
	 * (run-g19sync-spike.sh): the same seven stages as direct calls. */
	ctx.result = se_owk_reap_step(slot, cookie);
	if (ctx.result == SE_OWK_PROGRESS)
		ctx.result = se_owk_reap_step(slot, cookie);
	if (ctx.result == SE_OWK_PROGRESS)
		ctx.result = se_owk_reap_step(slot, cookie);
	if (ctx.result == SE_OWK_PROGRESS)
		ctx.result = se_owk_reap_step(slot, cookie);
	if (ctx.result == SE_OWK_PROGRESS)
		ctx.result = se_owk_reap_step(slot, cookie);
	if (ctx.result == SE_OWK_PROGRESS)
		ctx.result = se_owk_reap_step(slot, cookie);
	if (ctx.result == SE_OWK_PROGRESS)
		ctx.result = se_owk_reap_step(slot, cookie);
#else
	if (bpf_loop(7, real_owner_work_sync_step, &ctx, 0) < 0)
		ctx.result = SE_OWK_PENDING;
#endif
	(void)__sync_val_compare_and_swap(&claim->claim, cookie, 0);
	if (ctx.result == SE_OWK_RETURNED) {
		real_owner_work_sync_count(REAL_OWNER_WORK_SYNC_RETURNED);
		return;
	}
	real_owner_work_sync_count(
		ctx.result == SE_OWK_CORRUPT ? REAL_OWNER_WORK_SYNC_FAULT :
		ctx.result == SE_OWK_STALE ||
				ctx.result == SE_OWK_ALREADY_RETURNED ?
					       REAL_OWNER_WORK_SYNC_STALE :
					       REAL_OWNER_WORK_SYNC_PENDING);
	SE_REAP_EVENT(WORK_DONE, slot, cookie);
}
#define SE_OWK_REAP_CLAIMED(slot, cookie) \
	real_owner_work_reap_claimed((slot), (cookie))
#define SE_WORK_SYNC_RETURN(settled, site) \
	real_owner_work_sync_return((settled), (site))
#endif
SEC("syscall")
int opaque_real_reap(struct opaque_real_reap_command *args)
{
	__u64 cookie = args->cookie;
	__u32 slot = args->slot, kind = args->kind;
	if (!cookie)
		return 255;
	if (kind == 1)
		return slot < SE_OWK_WORKS ? SE_OWK_REAP_CLAIMED(slot, cookie) :
					     255;
	if (kind != 2 || slot >= SE_OL_TASKS)
		return 255;
	struct se_oc_charge *charge = charge_lookup(slot);
	if (!charge)
		return SE_OR_FAULT;
	/* The charge no longer carries this cookie: returned (or reused) after
	 * the caller read it. Nothing of that charge is left to reap. */
	if (charge->cookie != cookie)
		return SE_OR_PENDING;
	return se_or_task_visit(slot);
}
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC
/* Disposable test authority only: it creates one synthetic parent in the
 * actual opaque maps so the real callbacks can be exercised while linked.
 * The selected image must never define this macro or expose these programs. */
#include "opaque_real_owner_live_bootstrap_diagnostic.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
/* Disposable BPF-only seed into the REAL fixed object/arena/binding maps.
 * Run once after bootstrap control and before any hook link is attached.
 * It bypasses native admission solely to exercise the source/reader/WORK
 * chain; the host manifest rejects this image as a product. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* Test-only fallback for the one seeded policy: 0 none, 1 allow, 2 deny.
 * Frozen by the controller before the seed runs; never product config. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_policy_verdict_fallback SEC(".maps");
/* Test-only rule count (1..256; 0 means 1). Rules 0..N-2 match only the
 * absent uid 4242; rule N-1 matches the expected uid, so an allow under a
 * deny fallback proves every window up to the last one was evaluated. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_policy_verdict_rules SEC(".maps");
/* Test-only role the matching rule proposes (0: none). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_policy_verdict_set_role SEC(".maps");
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
struct real_owner_seed_rules {
	__u32 rules, mode, match_cell, miss_cell, written, base, set_role;
	int error;
};
/* One test-only rule cell per iteration (an open-coded 256-cell loop was
 * too complex for the TC verifier on exact 6.18). */
static int real_owner_seed_rule(__u32 i, void *raw)
{
	struct real_owner_seed_rules *ctx = raw;
	if (i >= ctx->rules || i >= 256)
		return 1;
	__u32 cell = ctx->base + 9 + i;
	struct se_arena_cell *slot = bpf_map_lookup_elem(&se_arena, &cell);
	if (!slot) {
		ctx->error = 1;
		return 1;
	}
	struct fe_rule *r = (void *)slot;
	r->policy = 0;
	r->mode = ctx->mode;
	r->deny = 0;
	r->actor_image = -1;
	r->target_image = -1;
	r->stdin_pipe = -1;
	r->uid.base = i + 1 == ctx->rules ? ctx->match_cell : ctx->miss_cell;
	r->set_role = i + 1 == ctx->rules ? ctx->set_role : 0;
	r->uid.count = 1;
	ctx->written++;
	return 0;
}
#endif
SEC("tc")
int opaque_real_owner_policy_seed_diagnostic(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0, one = 1;
	const struct opaque_real_live_bootstrap_gate *gate =
		bpf_map_lookup_elem(&opaque_real_live_bootstrap_gate, &zero);
	const struct se_node_config *config =
		bpf_map_lookup_elem(&se_configuration, &zero);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* Layout: header 0, policy 1, rules 9..9+N-1, uid data after. More than
	 * 245 rules exceed a 256-cell slot; use the first 1024-cell object. */
	const __u32 *rules_value =
		bpf_map_lookup_elem(&opaque_real_policy_verdict_rules, &zero);
	__u32 seed_rules = rules_value && *rules_value ? *rules_value : 1;
	__u32 seed_object = 0, seed_class_size = 0, seed_base = 0;
	if (seed_rules > 256 || !config)
		return -1;
	if (seed_rules > 1 && 11 + seed_rules > 256)
		seed_object = config->slots[0];
	if (se_object_range(config, seed_object, &seed_class_size,
			    &seed_base) ||
	    se_object_capacity(seed_class_size) < 11 + seed_rules ||
	    seed_base > 0xffffU)
		return -1;
	__u32 base_zero = seed_base, base_one = seed_base + 1;
	__u32 base_nine = seed_base + 9, base_ten = seed_base + 10;
#else
	__u32 seed_rules = 1, seed_object = 0, seed_class_size = 0,
	      seed_base = 0;
	__u32 base_zero = 0, base_one = 1, base_nine = 9, base_ten = 10;
#endif
	struct se_shared_object *object =
		bpf_map_lookup_elem(&se_objects, &seed_object);
	struct se_arena_cell *header_cell =
		bpf_map_lookup_elem(&se_arena, &base_zero);
	struct se_arena_cell *policy_cell =
		bpf_map_lookup_elem(&se_arena, &base_one);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	struct se_arena_cell *rule_cell =
		bpf_map_lookup_elem(&se_arena, &base_nine);
	struct se_arena_cell *uid_cell =
		bpf_map_lookup_elem(&se_arena, &base_ten);
	const __u32 *expected_uid =
		bpf_map_lookup_elem(&opaque_real_owner_rule_uid_expect, &zero);
#endif
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &zero);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* Route, snapshot, object, policy and rule classes stay equal; the
	 * bootstrap control seeded the route/snapshot from the same gate. */
	const __u32 *fallback_value = bpf_map_lookup_elem(
		&opaque_real_policy_verdict_fallback, &zero);
	__u32 seed_class = gate ? gate->execution_class : 0;
	__u32 seed_fallback = fallback_value ? *fallback_value : ~0U;
	/* Explicit class only: the route/snapshot were seeded from this gate. */
	if (!gate || seed_class < 1 || seed_class > 2 || seed_fallback > 2)
		return -1;
#else
	__u32 seed_class = 1, seed_fallback = 0;
	if (gate && gate->execution_class != 0)
		return -1;
#endif
	if (!gate || gate->enabled != 1 || gate->scope != 10 ||
	    !se_profile_matches(config) || !object || !header_cell ||
	    !policy_cell || !binding ||
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	    !rule_cell || !uid_cell || !expected_uid ||
#endif
	    object->state.phase != SE_OBJECT_FREE ||
	    binding->state.scope != gate->scope ||
	    binding->state.records[0].phase != SE_SNAPSHOT_ACTIVE ||
	    binding->state.records[0].tickets[0].phase != SE_TICKET_EMPTY)
		return -1;
	struct fe_header *header = (void *)header_cell;
	struct fe_policy *policy = (void *)policy_cell;
	header->policies = 1;
	header->rule_base = 9;
	policy->uid = 1;
	policy->root_role = 1;
	policy->mode = seed_class;
	policy->fallback = seed_fallback;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	struct fe_rule *rule = (void *)rule_cell;
	header->rules = seed_rules;
	rule->policy = 0;
	rule->mode = seed_class;
	rule->actor_image = -1;
	rule->target_image = -1;
	rule->stdin_pipe = -1;
	rule->uid.base = 10;
	rule->uid.count = 1;
	((struct fm_blob *)uid_cell)->words[0] = *expected_uid;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	const __u32 *set_role_value = bpf_map_lookup_elem(
		&opaque_real_policy_verdict_set_role, &zero);
	__u32 seed_set_role = set_role_value ? *set_role_value : 0;
	if (seed_rules == 1)
		rule->set_role = seed_set_role;
	if (seed_rules > 1) {
		/* Cells: rules 9..9+N-1, matching uid 9+N, absent uid 9+N+1. */
		/* Rule uid lists hold object-relative cell indices. */
		__u32 match_cell = 9 + seed_rules, miss_cell = 10 + seed_rules;
		__u32 match_abs = seed_base + match_cell;
		__u32 miss_abs = seed_base + miss_cell;
		struct se_arena_cell *match =
			bpf_map_lookup_elem(&se_arena, &match_abs);
		struct se_arena_cell *miss =
			bpf_map_lookup_elem(&se_arena, &miss_abs);
		if (!match || !miss)
			return -1;
		((struct fm_blob *)match)->words[0] = *expected_uid;
		((struct fm_blob *)miss)->words[0] = 4242;
		struct real_owner_seed_rules ctx = { .rules = seed_rules,
						     .base = seed_base,
						     .set_role = seed_set_role,
						     .mode = seed_class,
						     .match_cell = match_cell,
						     .miss_cell = miss_cell };
		bpf_loop(256, real_owner_seed_rule, &ctx, 0);
		if (ctx.error || ctx.written != seed_rules)
			return -1;
	}
#endif
#endif
	object->state.generation = 1;
	object->state.slot = seed_object;
	object->state.size_class = seed_class_size;
	object->state.phase = SE_OBJECT_READY;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	/* Physical preparation reserves one post-rule data cell even for a rule
	 * with no data predicates: entries >= 10 + rules. */
	object->state.length = seed_rules > 1 ? 11 + seed_rules : 11;
	object->state.completed = object->state.length;
#else
	object->state.length = 10;
	object->state.completed = 10;
#endif
	object->state.pins = 1;
	object->state.execution_class = seed_class;
	struct se_pin_ticket *ticket = &binding->state.records[0].tickets[0];
	ticket->scope = gate->scope;
	ticket->snapshot_serial = 1;
	ticket->object_generation = 1;
	ticket->position = 0;
	ticket->object_slot = seed_object;
	ticket->phase = SE_TICKET_HELD;
	return 0;
}
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) &&   \
	(defined(ENFORCE_EXEC_POOL_OPAQUE_ROUTE_MIGRATION_DIAGNOSTIC) || \
	 defined(ENFORCE_EXEC_POOL_OPAQUE_RELOAD_DIAGNOSTIC))
/* G025 steps 7/8, test-only second policy in fixed 256-cell object 1, with
 * one rule for the expected uid. binding 1 tickets it into the second
 * route's ACTIVE snapshot (migration); binding 0 leaves it READY and
 * unpinned for the generation advance (reload: same class, the frozen
 * fallback may differ). Run once after the first seed, before any link. */
struct opaque_real_second_policy {
	__u32 execution_class, fallback, binding, enabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_second_policy);
} opaque_real_second_policy SEC(".maps");
SEC("tc")
int opaque_real_owner_second_policy_seed(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0, one = 1, class_size = 0, base = 0;
	const struct opaque_real_second_policy *want =
		bpf_map_lookup_elem(&opaque_real_second_policy, &zero);
	const struct se_node_config *config =
		bpf_map_lookup_elem(&se_configuration, &zero);
	const __u32 *expected_uid =
		bpf_map_lookup_elem(&opaque_real_owner_rule_uid_expect, &zero);
	const __u32 *set_role_value = bpf_map_lookup_elem(
		&opaque_real_policy_verdict_set_role, &zero);
	if (!want || want->enabled != 1 || want->execution_class < 1 ||
	    want->execution_class > 2 || want->fallback > 2 ||
	    want->binding > 1 || !config || !expected_uid ||
	    !se_profile_matches(config) ||
	    se_object_range(config, 1, &class_size, &base) ||
	    se_object_capacity(class_size) < 11 || base > 0xffffU)
		return -1;
	__u32 header_index = base, policy_index = base + 1;
	__u32 rule_index = base + 9, uid_index = base + 10;
	struct se_shared_object *object =
		bpf_map_lookup_elem(&se_objects, &one);
	struct se_arena_cell *header_cell =
		bpf_map_lookup_elem(&se_arena, &header_index);
	struct se_arena_cell *policy_cell =
		bpf_map_lookup_elem(&se_arena, &policy_index);
	struct se_arena_cell *rule_cell =
		bpf_map_lookup_elem(&se_arena, &rule_index);
	struct se_arena_cell *uid_cell =
		bpf_map_lookup_elem(&se_arena, &uid_index);
	struct se_shared_binding *binding =
		want->binding ? bpf_map_lookup_elem(&se_bindings, &one) : 0;
	if (!object || !header_cell || !policy_cell || !rule_cell ||
	    !uid_cell || object->state.phase != SE_OBJECT_FREE)
		return -1;
	if (want->binding &&
	    (!binding || binding->state.scope != 11 ||
	     binding->state.records[0].phase != SE_SNAPSHOT_ACTIVE ||
	     binding->state.records[0].execution_class !=
		     want->execution_class ||
	     binding->state.records[0].tickets[0].phase != SE_TICKET_EMPTY))
		return -1;
	struct fe_header *header = (void *)header_cell;
	struct fe_policy *policy = (void *)policy_cell;
	struct fe_rule *rule = (void *)rule_cell;
	header->policies = 1;
	header->rule_base = 9;
	header->rules = 1;
	policy->uid = 1;
	policy->root_role = 1;
	policy->mode = want->execution_class;
	policy->fallback = want->fallback;
	rule->policy = 0;
	rule->mode = want->execution_class;
	rule->actor_image = -1;
	rule->target_image = -1;
	rule->stdin_pipe = -1;
	rule->uid.base = 10;
	rule->uid.count = 1;
	rule->set_role = set_role_value ? *set_role_value : 0;
	((struct fm_blob *)uid_cell)->words[0] = *expected_uid;
	object->state.generation = 1;
	object->state.slot = 1;
	object->state.size_class = class_size;
	object->state.phase = SE_OBJECT_READY;
	object->state.length = 11;
	object->state.completed = 11;
	object->state.pins = want->binding ? 1 : 0;
	object->state.execution_class = want->execution_class;
	if (binding) {
		struct se_pin_ticket *ticket =
			&binding->state.records[0].tickets[0];
		ticket->scope = 11;
		ticket->snapshot_serial = 1;
		ticket->object_generation = 1;
		ticket->position = 0;
		ticket->object_slot = 1;
		ticket->phase = SE_TICKET_HELD;
	}
	return 0;
}
#endif
#endif
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
/* Keep recovered-admin capture's lock frame out of the charged source
 * constructor's older-kernel call chain. The callee relooks the original
 * recovery maps; no map-value pointer crosses this boundary. */
static __attribute__((noinline)) int
real_owner_child_recovery_capture(struct task_struct *child,
				  unsigned long clone_flags, int prior)
{
	return se_rm_capture(child, clone_flags, prior);
}
static __attribute__((noinline)) void
real_owner_child_recovery_close(struct task_struct *physical)
{
	se_rm_close(physical);
}
#endif

/* The native-config opt-in is a source-shape prerequisite, NOT an activation
 * switch: no product host admits this incomplete image. Configuration must
 * be installed and frozen before hooks attach. Ordinary diagnostics retain
 * their separate test-only gate. */
#ifndef ENFORCE_EXEC_POOL_OPAQUE_NATIVE_CONFIG_GATE_CANDIDATE
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_child_gate SEC(".maps");
#endif
static __always_inline int real_owner_image_configured(void)
{
	__u32 zero = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_NATIVE_CONFIG_GATE_CANDIDATE
	const struct se_node_config *config =
		bpf_map_lookup_elem(&se_configuration, &zero);
	return se_profile_matches(config);
#else
	const __u32 *armed =
		bpf_map_lookup_elem(&opaque_real_owner_child_gate, &zero);
	return armed && *armed == 1;
#endif
}
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_child_targets SEC(".maps");

#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
#error "final failed-exec probe requires the source-owned reader receipt"
#endif
/* Exact-build Rocky 4.18 diagnostic, not a portable product attachment.
 * Both frames are BPF-only. A missed or nested entry is an uncertain terminal,
 * never permission to finalize a receipt or preserve a trusted audit role. */
struct se_failure_outer_frame {
	__u64 physical, bprm, cookie, locator, invocation, scope, generation;
	__u32 depth, uncertain;
};
struct se_failure_handler_frame {
	__u64 bprm;
	__u32 depth, uncertain;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_FAILURE_FRAME_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct se_failure_outer_frame);
} se_failure_outer_frames SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_FAILURE_FRAME_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct se_failure_handler_frame);
} se_failure_handler_frames SEC(".maps");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
#include "shared_exec_interp_continuation.h"
#endif

static __always_inline int real_owner_failure_scope(void)
{
	__u64 cgroup = bpf_get_current_cgroup_id();
	return real_owner_image_configured() && cgroup &&
	       se_opaque_real_route_index(&cgroup) != 0;
}
static __always_inline int real_owner_failure_frame_ready(__u64 key, __u64 bprm)
{
	struct se_failure_outer_frame *outer =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	struct se_failure_handler_frame *handler =
		bpf_map_lookup_elem(&se_failure_handler_frames, &key);
	return outer && handler && key && bprm && outer->physical == key &&
	       outer->depth == 1 && !outer->uncertain && !outer->bprm &&
	       handler->bprm == bprm && handler->depth == 1 &&
	       !handler->uncertain;
}
static __always_inline int
real_owner_failure_bind_receipt(const struct se_exec_terminal_receipt *receipt)
{
	if (!receipt ||
	    !real_owner_failure_frame_ready(receipt->physical, receipt->bprm))
		return -1;
	struct se_failure_outer_frame *outer = bpf_map_lookup_elem(
		&se_failure_outer_frames, &receipt->physical);
	if (!outer || !receipt->cookie || !receipt->locator ||
	    !receipt->invocation || !receipt->scope || !receipt->generation)
		return -1;
	outer->bprm = receipt->bprm;
	outer->cookie = receipt->cookie;
	outer->locator = receipt->locator;
	outer->invocation = receipt->invocation;
	outer->scope = receipt->scope;
	outer->generation = receipt->generation;
	return 0;
}

SEC("kprobe/do_execveat_common.isra.38")
int BPF_KPROBE(opaque_real_owner_failure_outer_enter)
{
	if (!real_owner_failure_scope())
		return 0;
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_failure_outer_frame *old =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	if (old) {
		old->uncertain = 1;
		if (old->depth < 255)
			old->depth++;
		return 0;
	}
	struct se_failure_outer_frame frame = { .physical = key, .depth = 1 };
	if (key && bpf_map_update_elem(&se_failure_outer_frames, &key, &frame,
				       BPF_NOEXIST))
		SE_DEFERRED_STORAGE_REFUSED(1);
	return 0;
}
SEC("kprobe/search_binary_handler")
int BPF_KPROBE(opaque_real_owner_failure_handler_enter,
	       struct linux_binprm *bprm)
{
	if (!real_owner_failure_scope())
		return 0;
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_failure_outer_frame *outer =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	if (!outer || outer->uncertain || outer->depth != 1 ||
	    outer->physical != key || !bprm)
		return 0;
	struct se_failure_handler_frame *old =
		bpf_map_lookup_elem(&se_failure_handler_frames, &key);
	if (old) {
		old->uncertain = outer->uncertain = 1;
		if (old->depth < 255)
			old->depth++;
		return 0;
	}
	struct se_failure_handler_frame frame = {
		.bprm = (__u64)bprm,
		.depth = 1,
	};
	if (bpf_map_update_elem(&se_failure_handler_frames, &key, &frame,
				BPF_NOEXIST))
		SE_DEFERRED_STORAGE_REFUSED(2);
	return 0;
}
SEC("kretprobe/search_binary_handler")
int BPF_KRETPROBE(opaque_real_owner_failure_handler_exit, int ret)
{
	(void)ret;
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_failure_handler_frame *frame =
		bpf_map_lookup_elem(&se_failure_handler_frames, &key);
	if (frame) {
		if (frame->depth > 1)
			frame->depth--;
		else
			(void)bpf_map_delete_elem(&se_failure_handler_frames,
						  &key);
	}
	return 0;
}
SEC("kretprobe/do_execveat_common.isra.38")
int BPF_KRETPROBE(opaque_real_owner_failure_outer_exit, int ret)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_failure_outer_frame *frame =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	if (!frame)
		return 0;
	if (frame->depth > 1) {
		frame->depth--;
		return 0;
	}
	/* Only a failed outer exec may publish FAILURE here. A successful
	 * exec's terminal comes from the actual sched_process_exec event; a
	 * zero return is not independent proof that its tracepoint ran. */
	if (ret < 0 && frame->depth == 1 && !frame->uncertain &&
	    frame->physical == key && frame->bprm && frame->cookie &&
	    frame->locator && frame->invocation && frame->scope &&
	    frame->generation) {
		struct se_exec_terminal_receipt *receipt =
			bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
		(void)real_owner_terminal_transition(
			receipt, key, frame->bprm, frame->cookie,
			frame->locator, frame->invocation, frame->scope,
			frame->generation, SE_EXEC_TERMINAL_FAILURE);
	}
	(void)bpf_map_delete_elem(&se_failure_handler_frames, &key);
	(void)bpf_map_delete_elem(&se_failure_outer_frames, &key);
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAILURE_SOURCE_COMPLETION_DIAGNOSTIC
/* End this producer's lexical frame before entering lock-bearing completion.
 * The independent outer tuple authenticates the receipt; the inner handler
 * frame has already returned and cannot be required here. */
static __attribute__((noinline)) int
real_owner_failure_fexit_publish(__u64 key, __u64 bprm)
{
	const struct se_failure_outer_frame *frame =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	if (!key || !bprm || !frame || frame->depth != 1 || frame->uncertain ||
	    frame->physical != key || frame->bprm != bprm || !frame->cookie ||
	    !frame->locator || !frame->invocation || !frame->scope ||
	    !frame->generation)
		return 0;
	struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	return real_owner_terminal_transition(receipt, key, bprm, frame->cookie,
					      frame->locator, frame->invocation,
					      frame->scope, frame->generation,
					      SE_EXEC_TERMINAL_FAILURE);
}

/* Exact-AL2023 diagnostic, not a selected product source. The enclosing
 * user-exec frame remains live while bprm_execve returns; no ordering between
 * fexit and a kretprobe on the same function is assumed. kernel_execve lacks
 * that outer frame and is deliberately not certified by this variant. */
SEC("fexit/bprm_execve")
int BPF_PROG(opaque_real_owner_failure_fexit_probe, struct linux_binprm *bprm)
{
	__u64 raw = 0;
	if (bpf_get_func_ret(ctx, &raw) || (__s32)raw >= 0)
		return 0;
	__u64 key = (__u64)bpf_get_current_task_btf();
	if (real_owner_failure_fexit_publish(key, (__u64)bprm))
		SE_WORK_SYNC_RETURN(
			SE_SETTLE_SLOT(real_owner_work_completion_shape(key)),
			REAL_OWNER_WORK_SYNC_SETTLED_EXEC);
	/* Outer kretprobe still cleans its frames. If completion retired the
	 * receipt, its later terminal CAS is a no-op, not a second completion. */
	return 0;
}
#endif
#endif

static __attribute__((noinline)) int
real_owner_child_release_claim(struct se_route_claim *claim)
{
	struct se_route_anchor *route = route_lookup(claim->slot);
	if (!route)
		return -1;
	bpf_spin_lock(&route->lock);
	int released = se_route_release_locked(route, claim);
	bpf_spin_unlock(&route->lock);
	return released;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_INITIAL_TASK_DIAGNOSTIC
#include "opaque_real_owner_initial_task_diagnostic.h"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_RECOVERED_INITIAL_TASK_DIAGNOSTIC
#include "opaque_real_owner_recovered_initial_task_diagnostic.h"
#endif

/* Isolate the short-lived observation/lease frame while keeping TASK open's
 * internal lexical checks inline in this one BPF function. */
static __attribute__((noinline)) int
real_owner_child_open_parent(struct se_ol_payload_handle *parent)
{
	__u64 parent_key = (__u64)bpf_get_current_task_btf();
	return se_ol_task_open(&parent_key, parent);
}

/* Source frame: prepare a canonical parent projection under the real route
 * claim, then suspend the exact WORK. No pointer, claim or stack address
 * crosses the tail call. The WORK retains its TASK owner reference. */
static __attribute__((noinline)) int
real_owner_child_start_work(struct se_ol_payload_handle *parent,
			    struct se_owk_ticket *ticket)
{
	if (se_owk_bind_owner(parent) != SE_OL_OK)
		return -1;
	/* begin's CONTENDED: a sibling charged the chosen bit (its credit, not
	 * ours) and our pin was rolled back. Each lost attempt still consumes a
	 * sequence cookie and task->next_work_sequence (SE_OWK_COOKIE_LIMIT). */
	int began = SE_OL_CONTENDED;
#pragma clang loop unroll(disable)
	for (__u32 attempt = 0; attempt < SE_PROFILE_WORK_RETRIES; attempt++) {
		__u32 work_slot = 0;
		if (se_owk_choose(parent, &work_slot) != SE_OL_OK)
			return -1;
		began = se_owk_begin(parent, work_slot, ticket);
		if (began != SE_OL_CONTENDED)
			break;
	}
	if (began != SE_OL_OK) {
		/* Bound exhausted: recoverable contention, refused uncharged. */
		if (began == SE_OL_CONTENDED)
			SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_WORK_RETRY);
		return -1;
	}
	if (se_owk_attach_owner(parent, ticket) != SE_OL_OK ||
	    se_owk_initialize_payload(parent, ticket) != SE_OL_OK ||
	    se_owk_commit(parent, ticket) != SE_OL_OK)
		return -1;
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
static __attribute__((noinline)) int
real_owner_policy_prepare(struct se_invocation *work, __u64 scope,
			  __u64 generation, const struct se_snapshot *snapshot)
{
	return se_prepare_policy_view(&work->view, scope, snapshot, generation);
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
/* The source has already consumed its lexical TASK/WORK handles. The current
 * physical TASK and suspended WORK must be reauthenticated by this target
 * before calling here; the scalar token is not an entry capability. */
static __attribute__((noinline)) int
real_owner_policy_stage_begin(struct se_owk_payload *payload)
{
	struct se_invocation *work = &payload->semantic;
	struct fm_global_token *token =
		&work->observation.stage_workspace.token;
	if (token->reserved || token->slot != work->slot ||
	    token->cookie != work->cookie ||
	    real_owner_stage_view(token) != &work->view)
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
		return -1;
#else
		return 0;
#endif
	int began = fe_stage_begin((void *)token, &work->observation.facts,
				   &work->observation.evaluator,
				   &work->observation.stage_cursor);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	if (began)
		return -2;
	return work->observation.stage_cursor.state >= FE_STAGE_ACTIVE ? 1 : -3;
#else
	return began == 0 &&
	       work->observation.stage_cursor.state >= FE_STAGE_ACTIVE;
#endif
}
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE)
/* Rule advances per rule-program invocation. While the cursor stays ACTIVE
 * the rule program re-enters itself through its class graph, so 256 rules
 * need at most 16 windows, within the tail-call budget after the
 * begin -> policy -> prepare -> stage hops. Alternatives measured on the
 * exact AL2023 kernels (g005b-verdict-load-20261109): an open-coded 256-step
 * loop and a bpf_for iterator exceeded the 8192 pending-jump limit (6.18);
 * a bpf_loop callback frame exceeded the 8-frame call depth (6.12). */
#define REAL_OWNER_RULE_WINDOW_STEPS 16
/* begin -> policy -> prepare -> stage -> rule x windows -> finish. */
_Static_assert(256 / REAL_OWNER_RULE_WINDOW_STEPS + 4 <= 33,
	       "rule windows must fit the tail-call budget");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
/* An interpreter pass: begin -> continue -> prepare -> stage -> rule x
 * windows -> finish. Each bprm_check pass has its own tail-call budget. */
_Static_assert(256 / REAL_OWNER_RULE_WINDOW_STEPS + 5 <= 33,
	       "an interpreter pass must fit the tail-call budget");
#endif
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
static __attribute__((always_inline)) inline int
real_owner_policy_rule_window(struct se_owk_payload *payload)
{
	struct se_invocation *work = &payload->semantic;
	struct fm_global_token *token =
		&work->observation.stage_workspace.token;
	if (token->reserved || token->slot != work->slot ||
	    token->cookie != work->cookie ||
	    real_owner_stage_view(token) != &work->view)
		return -1;
	/* Current-task credentials are stable in this non-sleepable callback.
	 * The UID helper reports real UID, not the effective UID policy fact.
	 * Failed CO-RE reads leave the fact UNKNOWN, never inferred as root. */
	struct task_struct *task = bpf_get_current_task_btf();
	const struct cred *cred = 0;
	__u32 effective_uid = 0;
	work->observation.facts.effective_uid = 0;
	work->observation.facts.uid_known = 0;
	if (task && !BPF_CORE_READ_INTO(&cred, task, cred) && cred &&
	    !BPF_CORE_READ_INTO(&effective_uid, cred, euid.val)) {
		work->observation.facts.effective_uid = effective_uid;
		work->observation.facts.uid_known = 1;
	}
	real_owner_rule_progress(3, work->observation.facts.effective_uid);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#pragma clang loop unroll(disable)
	for (__u32 step = 0; step < REAL_OWNER_RULE_WINDOW_STEPS; step++) {
		if (work->observation.stage_cursor.state != FE_STAGE_ACTIVE)
			break;
		if (fe_stage_advance(
			    (void *)token, &work->observation.facts,
			    &work->observation.evaluator,
			    &work->observation.stage_cursor,
			    &work->observation.stage_workspace.alt_request) !=
		    0)
			return -2;
	}
	if (work->observation.stage_cursor.state == FE_STAGE_ACTIVE)
		return 2; /* more rules: re-enter through the class graph */
#else
	if (work->observation.stage_cursor.state == FE_STAGE_ACTIVE &&
	    fe_stage_advance((void *)token, &work->observation.facts,
			     &work->observation.evaluator,
			     &work->observation.stage_cursor,
			     &work->observation.stage_workspace.alt_request) !=
		    0)
		return -2;
#endif
	if (work->observation.stage_cursor.state != FE_STAGE_READY)
		return -3;
	if (fe_stage_finish((void *)token, &work->observation.evaluator,
			    &work->observation.stage_cursor) != 0)
		return -4;
	if (work->observation.stage_cursor.state != FE_STAGE_FINISHED)
		return -5;
	if (work->observation.evaluator.decision.error != FE_OK
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	    && work->observation.evaluator.decision.error != FE_AUDIT_UNKNOWN
#endif
	)
		return -6;
	real_owner_rule_progress(
		2, work->observation.evaluator.decision.matched_rules[0] & 1);
	return 1;
}
static __attribute__((always_inline)) inline int
real_owner_policy_rule_claimed_eval(__u64 scope)
{
	struct se_owk_payload *payload =
		se_owk_suspended_current(scope, REAL_OWNER_EVAL_RESUME, 3);
	return payload ? real_owner_policy_rule_window(payload) : -7;
}
#endif
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* Separate frame: inlined into the bridge, history snapshot + catalogue +
 * role classification pushed the policy program past 1M processed
 * instructions on exact AL2023 6.18 (g005b-verdict-load-20261109). */
static __attribute__((noinline)) int
real_owner_prepare_reader_frame(struct se_owk_semantic_handle *semantic,
				const struct se_exec_terminal_receipt *receipt,
				__u64 physical)
{
	return se_owk_exec_prepare_reader(semantic, receipt, physical);
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#error "evaluation WORK witness requires the real-policy verdict candidate"
#endif
/* Test-only evaluation WORK witness, read by the attached verdict test.
 * [0] policy bridge entered; [1] evaluation start_work refused before any
 * WORK was charged; [2] start_work failed after a charge; [3] the reader was
 * quarantined exactly and its receipt retired (abort handoff); [4] an exact
 * receipt was found but the abort handoff failed. Leaf frame only. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 5);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_eval_work_outcomes SEC(".maps");
static __attribute__((noinline)) void real_owner_eval_work_outcome(__u32 index)
{
	__u32 key = index < 5 ? index : 4;
	__u64 *count =
		bpf_map_lookup_elem(&opaque_real_eval_work_outcomes, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#endif
/* The caller first authenticates the retained reader against the original
 * binding. Its TASK lease brackets every policy read. WORK is DONE before
 * return; this test cut never emits a verdict or role. */
static __attribute__((noinline)) int
real_owner_policy_bridge(struct se_ol_payload_handle *owner, __u64 scope,
			 __u64 generation, const struct se_snapshot *snapshot)
{
	if (!owner || !scope || !generation || !snapshot ||
	    snapshot->scope != scope || snapshot->generation != generation ||
	    !snapshot->serial || !snapshot->claims)
		return -1;
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC
	real_owner_eval_work_outcome(0);
#endif
	if (real_owner_child_start_work(owner, &ticket)) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC
		real_owner_eval_work_outcome(ticket.held ? 2 : 1);
#endif
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_EVAL_WORK);
		goto failed;
	}
	if (se_owk_semantic_open(owner, &ticket, &semantic, &work) != SE_OL_OK)
		goto failed;
	int valid = real_owner_policy_prepare(work, scope, generation,
					      snapshot) == 0;
	/* Issue the token straight into this WORK's workspace: a stack copy put
	 * the verdict policy chain 16 bytes over the 512-byte combined stack on
	 * exact AL2023 6.18 (g005b-verdict-load-20261109). */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
	struct fm_global_token *token =
		&work->observation.stage_workspace.token;
#else
	struct fm_global_token token_storage = {};
	struct fm_global_token *token = &token_storage;
#endif
	if (valid)
		valid = se_owk_evaluator_token(&semantic, token) == SE_OL_OK &&
			se_owk_view_from_identity(token->slot, token->cookie) ==
				&work->view;
/* Verdict build: history/catalogue/role preparation runs in the separate
 * prepare program after this suspension (real_owner_prepare_frame). */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
	if (valid) {
		/* Source facts and the complete verdict path remain separate
		 * gates. A prepared history alone grants no policy decision. */
		__builtin_memset(&work->observation.stage_cursor, 0,
				 sizeof(work->observation.stage_cursor));
		if (se_owk_semantic_suspend(&semantic, &work, 1) == SE_OL_OK)
			return 1;
		valid = 0;
	}
#endif
	int closed = semantic.held && work &&
		     se_owk_semantic_done(&semantic, &work) == SE_OL_OK;
	return valid && closed ? 0 : -1;
failed:
	if (semantic.held && work)
		(void)se_owk_semantic_done(&semantic, &work);
	if (ticket.held) {
		if (ticket.stage == 0)
			(void)se_owk_abort_building(owner, &ticket);
		else if (ticket.stage == 1 || ticket.stage == 2)
			(void)se_owk_abort(owner, &ticket);
		else if (ticket.stage == 3)
			(void)se_owk_done(owner, &ticket);
	}
	return -1;
}
#endif
static __attribute__((noinline)) int
real_owner_child_prepare(const struct se_route_claim *claim,
			 __u64 *parent_cookie_out)
{
	if (!parent_cookie_out)
		return -1;
	*parent_cookie_out = 0;
	struct se_ol_payload_handle parent = {};
	if (real_owner_child_open_parent(&parent) != SE_OL_OK)
		return -1;
	struct se_owk_ticket ticket = {};
	if (real_owner_child_start_work(&parent, &ticket)) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
		if (!ticket.held)
			real_owner_birth_outcome(0);
#endif
		goto work_failure;
	}
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	if (se_owk_semantic_open(&parent, &ticket, &semantic, &work) !=
	    SE_OL_OK)
		goto work_failure;
	int valid =
		se_op_parent_snapshot_held(&parent, &semantic, work, claim) ==
			SE_OL_OK &&
		se_op_parent_project_held(&semantic, work, claim) == SE_OL_OK;
	if (!valid) {
		se_owk_fault_ticket(&ticket);
		(void)se_owk_semantic_done(&semantic, &work);
		goto close_parent;
	}
	__u64 parent_cookie = parent.lease.cookie;
	if (se_owk_semantic_suspend(&semantic, &work, 1) != SE_OL_OK)
		goto work_failure;
	if (se_ol_payload_close(&parent) != SE_OL_OK)
		return -2;
	*parent_cookie_out = parent_cookie;
	return 0;
work_failure:
	if (ticket.held) {
		if (ticket.stage == 0)
			(void)se_owk_abort_building(&parent, &ticket);
		else if (ticket.stage == 1 || ticket.stage == 2)
			(void)se_owk_abort(&parent, &ticket);
		else if (ticket.stage == 3)
			(void)se_owk_done(&parent, &ticket);
	}
close_parent:
	(void)se_ol_payload_close(&parent);
	return -1;
}

static __attribute__((noinline)) void real_owner_child_missing_target(void)
{
	__u64 parent_key = (__u64)bpf_get_current_task_btf();
	struct se_ol_payload_handle parent = {};
	struct se_owk_ticket ticket = {};
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	real_owner_birth_outcome(7);
#endif
	SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_MISSING_TARGET);
	if (se_ol_task_open(&parent_key, &parent) == SE_OL_OK) {
		if (se_owk_resume(&parent, 1, &ticket) == SE_OL_OK)
			(void)se_owk_done(&parent, &ticket);
		(void)se_ol_payload_close(&parent);
	}
}

#if (defined(ENFORCE_EXEC_POOL_OPAQUE_BIRTH_CLOSE_FAULT_DIAGNOSTIC) ||     \
     defined(ENFORCE_EXEC_POOL_OPAQUE_BIRTH_RELEASE_FAULT_DIAGNOSTIC)) &&  \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC))
#error "birth fault injection requires successful-birth disposable bootstrap"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE
#error "the birth park's task_free release rides the exec capsule death retire"
#endif
/* G019 gaps 1 and 2: the birth park and the cross-generation first-exec
 * qualification (full/shared_birth_receipt.h). The park is per-task storage
 * on the forking task. */
struct se_birth_park;
static __always_inline struct se_birth_park *real_owner_birth_park(__u64 flags);
static __attribute__((noinline)) void real_owner_birth_park_count(__u32 index);
#define SE_BIRTH_PARK_LOOKUP(create) \
	real_owner_birth_park((create) ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0)
#define SE_BIRTH_PARK_COUNT(index) real_owner_birth_park_count(index)
#define SE_BIRTH_CLAIM_RELEASE(claim) real_owner_child_release_claim(claim)
#define SE_BIRTH_ROUTE_LOOKUP(slot) route_lookup(slot)
#include "shared_birth_receipt.h"
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct se_birth_park);
} se_birth_parks SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_BIRTH_PARK_CELLS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_birth_park SEC(".maps");
static __always_inline struct se_birth_park *real_owner_birth_park(__u64 flags)
{
	return bpf_task_storage_get(&se_birth_parks, bpf_get_current_task_btf(),
				    0, flags);
}
static __attribute__((noinline)) void real_owner_birth_park_count(__u32 index)
{
	__u64 *count = bpf_map_lookup_elem(&opaque_real_birth_park, &index);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_BIRTH_PARK_SPIN_DIAGNOSTIC
/* Never in a product object. Like the publication fault injector, its one
 * product-composition carrier is the explicit test twin
 * (SE_PRODUCT_DIAGNOSTIC_TWIN: se_admin authority, so the product publisher
 * binds and publishes on it; product admission refuses that twin by its
 * injector map). */
#if defined(SE_PRODUCT_NO_TEST_RUN) && !defined(SE_PRODUCT_DIAGNOSTIC_TWIN)
#error "the birth-park spin widens a diagnostic twin's straddle window only"
#endif
/* Test only (diagnostic twins): busy-wait between the source's park and
 * the target's take, so a revision every few milliseconds overlaps parked
 * births (the parked early claim holds its record, ACTIVE -> RETIRING, and
 * blocks only the withdrawal and reuse of that record). */
static long real_owner_birth_park_spin_step(__u64 index, void *ctx)
{
	(void)index;
	(void)ctx;
	return 0;
}
static __attribute__((noinline)) void real_owner_birth_park_spin(void)
{
	(void)bpf_loop(1 << 16, real_owner_birth_park_spin_step, 0, 0);
}
#endif
#endif
#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
/* This issue is not proof of a successful fork. A zero row is allocated
 * while the original claim is held; raw sched_process_fork must later see
 * the same physical parent/child and exact charged child before eligibility. */
static __attribute__((noinline)) int
real_owner_child_birth_issue(struct task_struct *child,
			     const struct se_route_claim *claim,
			     __u64 parent_cookie)
{
	if (!child || !claim || !claim->owned || claim->reserved ||
	    !claim->scope || !claim->generation || !claim->serial ||
	    !parent_cookie)
		return -1;
	__u32 zero = 0;
	const struct opaque_birth_receipt *template =
		bpf_map_lookup_elem(&opaque_birth_receipt_zero, &zero);
	__u64 key = (__u64)child;
	if (!template)
		return -1;
	if (bpf_map_update_elem(&opaque_birth_receipts, &key, template,
				BPF_NOEXIST)) {
		SE_DEFERRED_STORAGE_REFUSED(3);
		return -1;
	}
	struct opaque_birth_receipt *receipt =
		bpf_map_lookup_elem(&opaque_birth_receipts, &key);
	if (!receipt || receipt->state || receipt->child)
		return -1;
	receipt->child = key;
	receipt->parent = (__u64)bpf_get_current_task_btf();
	receipt->parent_cookie = parent_cookie;
	receipt->scope = claim->scope;
	receipt->generation = claim->generation;
	receipt->serial = claim->serial;
	receipt->slot = claim->slot;
	receipt->incarnation = claim->incarnation;
	receipt->record = claim->record;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	receipt->execution_class = claim->execution_class;
#endif
	receipt->state = 1;
	return receipt->parent ? 0 : -1;
}

/* A failed post-transition close must not leave a usable qualified TASK.
 * Only the exact charged generation is poisoned; a reused pointer is not
 * sufficient authority. The receipt also remains faulted if reopening fails.
 * The product publisher's adoption quarantine (B5) needs to know whether the
 * TASK was actually marked: there it returns 0 marked, 1 not marked (no
 * such TASK, another generation, or a failed open). Without the flag the
 * function is unchanged (void). */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
#define SE_BIRTH_QUARANTINE_T int
#define SE_BIRTH_QUARANTINE_RETURN(marked) return (marked) ? 0 : 1
#else
#define SE_BIRTH_QUARANTINE_T void
#define SE_BIRTH_QUARANTINE_RETURN(marked) return
#endif
static __attribute__((noinline)) SE_BIRTH_QUARANTINE_T
real_owner_birth_quarantine(__u64 key, __u64 cookie, __u64 locator)
{
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&key, &owner) != SE_OL_OK)
		SE_BIRTH_QUARANTINE_RETURN(0);
	struct se_task_state *task = 0;
	int marked = 0;
	if (se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		if (owner.lease.cookie == cookie &&
		    owner.lease.locator == locator &&
		    task->physical_cookie == cookie) {
			if (!(task->flags & SE_TASK_QUARANTINED)) {
				task->flags |= SE_TASK_QUARANTINED;
				if (task->eligibility_version < ~0ULL - 1)
					task->eligibility_version++;
			}
			if (task->exec.owned)
				se_exec_fault_locked(&task->exec);
			marked = 1;
		}
		se_op_task_semantic_end(&owner, &task);
	}
	(void)se_ol_payload_close(&owner);
	(void)marked;
	SE_BIRTH_QUARANTINE_RETURN(marked);
}

/* 1: qualified; 0: no eligible receipt; -1: uncertain transition. State 4
 * is a sticky in-flight/fault marker, installed before touching TASK flags.
 * First-use LSM callers must propagate -1 through their Audit/Strict gate. */
static __attribute__((noinline)) int
real_owner_birth_qualify(struct task_struct *target)
{
	__u64 key = (__u64)target;
	struct opaque_birth_receipt *receipt =
		bpf_map_lookup_elem(&opaque_birth_receipts, &key);
	if (receipt && receipt->state == 4)
		return -1;
	if (!receipt || receipt->state != 2 || receipt->child != key ||
	    !receipt->parent || !receipt->parent_cookie ||
	    !receipt->child_cookie || !receipt->child_locator ||
	    !receipt->scope || !receipt->generation || !receipt->serial ||
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	    receipt->slot >= SE_PROFILE_BINDINGS ||
	    receipt->execution_class < 1 || receipt->execution_class > 2)
#else
	    receipt->slot >= SE_PROFILE_BINDINGS || receipt->reserved)
#endif
		return 0;
	__u64 cgroup = 0;
	if (BPF_CORE_READ_INTO(&cgroup, target, cgroups, dfl_cgrp, kn, id) ||
	    !cgroup)
		return 0;
	struct se_route_claim claim = {};
	if (se_route_admit(cgroup, &claim) != SE_ROUTE_OWNED)
		return 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	/* G019 gap 2: a child born under an older generation of the same route
	 * qualifies under the current one (2); a receipt newer than the route
	 * is an invariant fault (-1, QUALIFY), its claim released below. */
	int admits = se_birth_receipt_admits(
		receipt->scope, receipt->generation, receipt->serial,
		receipt->slot, receipt->incarnation, receipt->record,
		receipt->execution_class, claim.scope, claim.generation,
		claim.serial, claim.slot, claim.incarnation, claim.record,
		claim.execution_class);
	int same_claim = admits > 0;
#else
	int same_claim = claim.scope == receipt->scope &&
			 claim.generation == receipt->generation &&
			 claim.serial == receipt->serial &&
			 claim.slot == receipt->slot &&
			 claim.incarnation == receipt->incarnation &&
			 claim.record == receipt->record;
#endif
	__u64 cookie = receipt->child_cookie, locator = receipt->child_locator;
	__u64 parent = receipt->parent, parent_cookie = receipt->parent_cookie;
	int qualified = 0, transitioned = 0;
	if (same_claim) {
		/* The current task cannot race its own fork/exec first use. The
		 * fault marker also prevents a later use from trusting a partial
		 * transition when lexical ownership cleanup fails. */
		receipt->state = 4;
		struct se_ol_payload_handle owner = {};
		if (se_ol_task_open(&key, &owner) == SE_OL_OK) {
			struct se_task_state *task = 0;
			if (se_op_task_semantic_begin(&owner, &task) ==
			    SE_OL_OK) {
				if (!owner.lease.meta->cleanup_error &&
				    owner.lease.cookie == cookie &&
				    owner.lease.locator == locator &&
				    task->physical_cookie == cookie &&
				    task->flags == SE_TASK_LIVE &&
				    task->scope_cookie == claim.scope &&
				    task->scope_slot == claim.slot &&
				    task->committed.version &&
				    !task->exec.owned && !task->reader.owned &&
				    !task->next_invocation) {
					task->flags = SE_TASK_QUALIFIED;
					qualified = transitioned = 1;
				}
				se_op_task_semantic_end(&owner, &task);
			}
			if (se_ol_payload_close(&owner) != SE_OL_OK)
				qualified = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_BIRTH_CLOSE_FAULT_DIAGNOSTIC
			/* Exercise uncertain-close remediation after the real close;
			 * this does not model a leaked lexical lease. */
			qualified = 0;
#endif
		}
	}
	/* release may clear claim ownership; retain original identity scalars
	 * in claim itself, as required by se_route_release_locked. */
	int released = real_owner_child_release_claim(&claim);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_BIRTH_RELEASE_FAULT_DIAGNOSTIC
	/* Likewise, inject the result without deliberately leaking a claim. */
	if (transitioned)
		released = -1;
#endif
	receipt = bpf_map_lookup_elem(&opaque_birth_receipts, &key);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	if (qualified && !released && receipt && receipt->state == 4 &&
	    receipt->child == key && receipt->child_cookie == cookie &&
	    receipt->child_locator == locator && receipt->parent == parent &&
	    receipt->parent_cookie == parent_cookie &&
	    se_birth_receipt_admits(
		    receipt->scope, receipt->generation, receipt->serial,
		    receipt->slot, receipt->incarnation, receipt->record,
		    receipt->execution_class, claim.scope, claim.generation,
		    claim.serial, claim.slot, claim.incarnation, claim.record,
		    claim.execution_class) == admits) {
		receipt->state = 3;
		if (admits == 2)
			real_owner_birth_park_count(
				SE_BIRTH_PARK_CROSS_GENERATION);
		return 1;
	}
	if (transitioned)
		real_owner_birth_quarantine(key, cookie, locator);
	return same_claim || released || admits < 0 ? -1 : 0;
#else
	if (qualified && !released && receipt && receipt->state == 4 &&
	    receipt->child == key && receipt->child_cookie == cookie &&
	    receipt->child_locator == locator && receipt->parent == parent &&
	    receipt->parent_cookie == parent_cookie &&
	    receipt->scope == claim.scope &&
	    receipt->generation == claim.generation &&
	    receipt->serial == claim.serial && receipt->slot == claim.slot &&
	    receipt->incarnation == claim.incarnation &&
	    receipt->record == claim.record && !receipt->reserved) {
		receipt->state = 3;
		return 1;
	}
	if (transitioned)
		real_owner_birth_quarantine(key, cookie, locator);
	return same_claim || released ? -1 : 0;
#endif
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
SEC("lsm/task_kill")
long BPF_PROG(opaque_real_owner_birth_signal0_diagnostic,
	      struct task_struct *target, struct kernel_siginfo *info,
	      int signal, const struct cred *cred, int prior)
{
	(void)info;
	(void)cred;
	if (prior || signal || !target || !real_owner_image_configured())
		return prior;
	(void)real_owner_birth_qualify(target);
	return 0;
}
#endif
#endif

/* Keep the route claim's stack quantum out of the LSM wrapper. A source
 * return of -2 means a suspended WORK may remain and needs exact fallback. */
static __attribute__((noinline)) int
real_owner_child_prepare_claimed(struct task_struct *child,
				 unsigned long clone_flags, __u32 *mode_out,
				 int terminal_fault)
{
	struct se_route_claim claim = {};
	int admission = se_route_admit(bpf_get_current_cgroup_id(), &claim);
	/* Test-only birth admission fault: the claim is released here, before
	 * anything is parked, and the fork takes the admission-fault path. */
	if (admission == SE_ROUTE_OWNED && SE_FC_BIRTH_ADMISSION_FAULT()) {
		(void)real_owner_child_release_claim(&claim);
		admission = claim.execution_class == 2 ? SE_ROUTE_STRICT_FAULT :
							 SE_ROUTE_AUDIT_FAULT;
	}
	if (admission != SE_ROUTE_OWNED) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		/* G019 M4: a fork admission fault (adopting, reserved,
		 * saturated or invariant route) is a counted attempt and a
		 * counted ADMISSION, Audit too; outside Total. */
		if (admission == SE_ROUTE_STRICT_FAULT ||
		    admission == SE_ROUTE_AUDIT_FAULT ||
		    admission == SE_ROUTE_INVARIANT_FAULT) {
			SE_RATE_ATTEMPT(0);
			SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_ADMISSION);
		}
#endif
		*mode_out = admission == SE_ROUTE_STRICT_FAULT ||
					    admission ==
						    SE_ROUTE_INVARIANT_FAULT ?
				    2 :
				    1;
		return -1;
	}
	*mode_out = claim.execution_class;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	SE_RATE_ATTEMPT(0);
#endif
	if (terminal_fault) {
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_SOURCE);
		(void)real_owner_child_release_claim(&claim);
		return -1;
	}
	__u64 parent_cookie = 0;
	int result = clone_flags & (1ULL << 33) ?
			     -1 :
			     real_owner_child_prepare(&claim, &parent_cookie);
#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
	if (!result &&
	    real_owner_child_birth_issue(child, &claim, parent_cookie))
		result =
			-2; /* finish the suspended WORK, never construct a child */
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	/* G019 gap 1: the claim goes to the target through the birth park. A
	 * failed put releases it here and finishes the suspended WORK through
	 * the missing-target path (-2, counted there: one class). */
	if (!result &&
	    !se_birth_park_put(&claim, (__u64)child, parent_cookie)) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_BIRTH_PARK_SPIN_DIAGNOSTIC
		real_owner_birth_park_spin();
#endif
		return 0;
	}
	if (!result)
		result = -2;
#endif
	int released = real_owner_child_release_claim(&claim);
	if (released && result == 0)
		return -2;
	if (result == -1)
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_SOURCE);
	return result;
}

SEC("lsm/task_alloc")
long BPF_PROG(opaque_real_owner_child_source_candidate,
	      struct task_struct *child, unsigned long clone_flags, int prior)
{
	(void)child;
	/* Preserve the verifier's signed LSM retval range. The BPF_PROG int
	 * argument cast can lose that range on newer kernels. */
	__s64 prior_ret = (__s64)ctx[2];
	if (prior_ret)
		return prior_ret;
#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
	/* A reused task_struct address must never inherit a prior receipt. If
	 * deletion fails, NOEXIST at publication leaves it unqualified. */
	__u64 birth_key = (__u64)child;
	(void)bpf_map_delete_elem(&opaque_birth_receipts, &birth_key);
#endif
	if (!real_owner_image_configured())
		return 0;
	int birth_fault = 0;
#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
	birth_fault =
		real_owner_birth_qualify(
			(struct task_struct *)bpf_get_current_task_btf()) < 0;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
	int recovery_ret =
		real_owner_child_recovery_capture(child, clone_flags, prior);
	if (recovery_ret)
		return -1; /* prior was zero; recovery may only refuse this fork */
#endif
	int terminal_fault = birth_fault;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_TERMINAL_DRAIN_DIAGNOSTIC
	/* Finish the terminal outside the route-claim/parent-projection frame.
	 * An uncertain Audit fork remains nonblocking, without trusted roles. */
	terminal_fault |= real_owner_source_terminal_drain();
	if (terminal_fault)
		(void)real_owner_reader_quarantine_pending(
			(__u64)bpf_get_current_task_btf());
#endif
	__u32 mode = 1;
	int prepared = real_owner_child_prepare_claimed(child, clone_flags,
							&mode, terminal_fault);
	if (prepared) {
		if (prepared == -2)
			real_owner_child_missing_target();
		if (mode == 2)
			return -1;
		return 0;
	}
	bpf_tail_call(ctx, &opaque_real_owner_child_targets, 0);
	/* Missing target is not a successful child constructor. An audit route
	 * remains nonblocking; strict enforcement denies. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	se_birth_park_abandon(&mode);
#endif
	real_owner_child_missing_target();
	if (mode == 2)
		return -1;
	return 0;
}

/* Target frame: reopen original physical TASK, resume exact WORK, take a new
 * real route claim, and use its fixed original-binding snapshot. WORK and
 * claim cleanup happen even if publication or re-admission fails. */
static __attribute__((noinline)) int
real_owner_child_claimed_construct(struct se_owk_semantic_handle *semantic,
				   struct task_struct *child, __u32 *mode_out)
{
	struct se_route_claim claim = {};
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	int admission = se_birth_park_take((__u64)child, &claim, mode_out);
#else
	int admission = se_route_admit(bpf_get_current_cgroup_id(), &claim);
#endif
	/* Test-only target re-admission fault: the taken claim is released
	 * here and the target takes its re-admission fault path. */
	if (admission == SE_ROUTE_OWNED && SE_FC_TARGET_ADMISSION_FAULT()) {
		(void)real_owner_child_release_claim(&claim);
		admission = claim.execution_class == 2 ? SE_ROUTE_STRICT_FAULT :
							 SE_ROUTE_AUDIT_FAULT;
	}
	int committed = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE
	int attempted = 0;
#endif
	if (admission == SE_ROUTE_OWNED) {
		*mode_out = claim.execution_class;
		if (claim.record < 2) {
			struct se_shared_binding *binding =
				bpf_map_lookup_elem(&se_bindings, &claim.slot);
			if (binding) {
				__u32 record = claim.record;
				asm volatile("" : "+r"(record));
				record &= 1;
				const struct se_snapshot *snapshot =
					&binding->state.records[record];
				struct task_struct *child_key = child;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
				/* G019 gap 3: the claim's own record, ACTIVE or
				 * RETIRING (a revision committed after the
				 * source parked its claim). */
				if ((snapshot->phase == SE_SNAPSHOT_ACTIVE ||
				     snapshot->phase == SE_SNAPSHOT_RETIRING) &&
				    snapshot->serial == claim.serial &&
				    snapshot->generation == claim.generation) {
#else
				if (snapshot->phase == SE_SNAPSHOT_ACTIVE) {
#endif
					int status =
						se_op_construct_child_from_parent_work(
							semantic, &claim,
							snapshot, &child_key);
					committed = status == SE_OL_OK;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE
					attempted = 1;
					if (!committed)
						real_owner_fail_closed_rate(
							status == SE_OL_LIMIT ?
								REAL_OWNER_RATE_LIMIT :
								REAL_OWNER_RATE_CONSTRUCT);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
					real_owner_birth_outcome(
						status >= 0 ?
							(__u32)status + 1 :
							5);
					goto counted;
#endif
				}
			}
		}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE
		if (!attempted)
			real_owner_fail_closed_rate(REAL_OWNER_RATE_CONSTRUCT);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
		real_owner_birth_outcome(6);
counted:
#endif
		if (real_owner_child_release_claim(&claim) && !committed)
			*mode_out = 2; /* published child must not be denied */
	} else {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		/* G019 13.20: a target admission fault is ADMISSION (its birth
		 * attempt was counted by the source), anything else CONSTRUCT:
		 * exactly one class per attempt. */
		SE_FAIL_CLOSED_RATE(
			admission == SE_ROUTE_STRICT_FAULT ||
					admission == SE_ROUTE_AUDIT_FAULT ||
					admission == SE_ROUTE_INVARIANT_FAULT ?
				REAL_OWNER_RATE_ADMISSION :
				REAL_OWNER_RATE_CONSTRUCT);
#else
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_CONSTRUCT);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
		real_owner_birth_outcome(6);
#endif
		if (admission == SE_ROUTE_STRICT_FAULT ||
		    admission == SE_ROUTE_INVARIANT_FAULT)
			*mode_out = 2;
	}
	return committed ? 0 : -1;
}
/* A child may already be published when a later WORK/TASK close fails. A
 * post-publication fault cannot be converted into an LSM denial: keep the
 * exact parent charge unreapable instead. Never write a recycled slot whose
 * locator/cookie no longer matches this callback's held lease. */
static __attribute__((noinline)) void
real_owner_child_fault_open_parent(const struct se_ol_payload_handle *parent)
{
	if (!parent || parent->lease.held != 1 || !parent->lease.meta)
		return;
	struct se_ol_meta *meta = parent->lease.meta;
	bpf_spin_lock(&meta->lock);
	if (meta->locator == parent->lease.locator &&
	    meta->cookie == parent->lease.cookie)
		meta->cleanup_error = 1;
	bpf_spin_unlock(&meta->lock);
}
static __attribute__((noinline)) SE_SETTLE_T
real_owner_child_finish(struct task_struct *child, __u32 *mode_out)
{
	struct se_ol_payload_handle parent = {};
	if (SE_FC_OPEN_PARENT_FAULT() ||
	    real_owner_child_open_parent(&parent) != SE_OL_OK) {
		SE_EXEC_EXCLUSION_WITNESS(2);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		se_birth_park_abandon(mode_out);
#endif
		return -3; /* fail-closed rate [8], counted by the caller */
	}
	struct se_owk_ticket ticket = {};
	if (se_owk_resume(&parent, 1, &ticket) != SE_OL_OK)
		goto close_parent;
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	if (se_owk_semantic_open(&parent, &ticket, &semantic, &work) !=
	    SE_OL_OK) {
		(void)se_owk_done(&parent, &ticket);
		goto close_parent;
	}
	SE_SETTLE_T result =
		real_owner_child_claimed_construct(&semantic, child, mode_out);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_CLOSE_FAULT_DIAGNOSTIC
	/* Test only: the child is already published, but the semantic handle
	 * cannot complete. The strict LSM return must not deny that child. */
	if (!SE_SETTLE_RESULT(result))
		semantic.held = 0;
#endif
	if (se_owk_semantic_done(&semantic, &work) != SE_OL_OK) {
		se_owk_fault_ticket(&ticket);
		real_owner_child_fault_open_parent(&parent);
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE
	/* The birth WORK is exactly DONE: hand its slot to the top level in the
	 * high half of R0 (no stack in this 512-byte chain). */
	else
		result = SE_SETTLE_PACK(result, ticket.work_slot + 1);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_POST_PUBLISH_TASK_CLOSE_FAULT_DIAGNOSTIC
	/* Test only: logical close precondition fails after successful WORK DONE.
	 * The exact TASK lease remains held, so reaping must remain impossible. */
	if (!SE_SETTLE_RESULT(result))
		parent.locked = 1;
#endif
	if (se_ol_payload_close(&parent) != SE_OL_OK)
		real_owner_child_fault_open_parent(&parent);
	/* result == 0 means the child has escaped publication. A failed close is
	 * now a retained structural fault, never a reason to deny that child. */
	return result;
close_parent:
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	se_birth_park_abandon(mode_out);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESSFUL_BIRTH_DIAGNOSTIC
	real_owner_birth_outcome(7);
#endif
	SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_MISSING_TARGET);
	if (se_ol_payload_close(&parent) != SE_OL_OK)
		real_owner_child_fault_open_parent(&parent);
	return -1;
}

#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
/* Separate lexical frame: putting a receipt value in the constructor's
 * nested WORK/publication call exceeds Rocky 4.18's 512-byte BPF stack. */
static __attribute__((noinline)) void
real_owner_child_birth_stamp(struct task_struct *child)
{
	__u64 child_key = (__u64)child;
	struct opaque_birth_receipt *receipt =
		bpf_map_lookup_elem(&opaque_birth_receipts, &child_key);
	__u64 parent_key = (__u64)bpf_get_current_task_btf();
	if (!receipt || receipt->state != 1 || receipt->child != child_key ||
	    receipt->parent != parent_key || !receipt->parent_cookie ||
	    !receipt->scope || receipt->slot >= SE_PROFILE_BINDINGS)
		return;
	struct se_ol_payload_handle parent = {};
	if (se_ol_task_open(&parent_key, &parent) != SE_OL_OK)
		return;
	struct se_task_state *task = 0;
	int parent_exact = 0;
	if (se_op_task_semantic_begin(&parent, &task) == SE_OL_OK) {
		parent_exact = !parent.lease.meta->cleanup_error &&
			       parent.lease.cookie == receipt->parent_cookie &&
			       task->flags == SE_TASK_QUALIFIED &&
			       task->scope_cookie == receipt->scope &&
			       task->scope_slot == receipt->slot &&
			       task->committed.version != 0;
		se_op_task_semantic_end(&parent, &task);
	}
	if (se_ol_payload_close(&parent) != SE_OL_OK || !parent_exact)
		return;
	struct se_ol_payload_handle born = {};
	if (se_ol_task_open(&child_key, &born) != SE_OL_OK)
		return;
	int child_exact = 0;
	__u64 child_cookie = born.lease.cookie;
	__u64 child_locator = born.lease.locator;
	if (se_op_task_semantic_begin(&born, &task) == SE_OL_OK) {
		child_exact = !born.lease.meta->cleanup_error &&
			      task->flags == SE_TASK_LIVE &&
			      task->scope_cookie == receipt->scope &&
			      task->scope_slot == receipt->slot &&
			      task->committed.version != 0 &&
			      !task->exec.owned && !task->reader.owned;
		se_op_task_semantic_end(&born, &task);
	}
	if (se_ol_payload_close(&born) != SE_OL_OK || !child_exact)
		return;
	receipt = bpf_map_lookup_elem(&opaque_birth_receipts, &child_key);
	if (!receipt || receipt->state != 1 || receipt->child != child_key ||
	    receipt->parent != parent_key || !receipt->parent_cookie ||
	    receipt->child_cookie || receipt->child_locator)
		return;
	receipt->child_cookie = child_cookie;
	receipt->child_locator = child_locator;
}
#endif

SEC("lsm/task_alloc")
long BPF_PROG(opaque_real_owner_child_target_candidate,
	      struct task_struct *child, unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	(void)prior;
	__s64 prior_ret = (__s64)ctx[2];
	if (prior_ret)
		return prior_ret;
	if (!real_owner_image_configured())
		return 0;
	__u32 mode = 1;
	SE_SETTLE_T result = real_owner_child_finish(child, &mode);
	if (SE_SETTLE_RESULT(result) == -3)
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_OPEN_PARENT);
#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
	if (!SE_SETTLE_RESULT(result))
		real_owner_child_birth_stamp(child);
#endif
	SE_WORK_SYNC_RETURN(SE_SETTLE_SLOT(result),
			    REAL_OWNER_WORK_SYNC_SETTLED_BIRTH);
	if (SE_SETTLE_RESULT(result) && mode == 2) {
		/* Keep the strict deny as a signed 64-bit LSM return. Newer
		 * verifiers reject Clang's folded 32-bit boolean negation. */
		asm volatile("" ::: "memory");
		return -1;
	}
	return 0;
}

#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
/* Rocky 4.18 tracing programs cannot use the spinlocked TASK/route maps.
 * This hook only records independent success for the exact source-issued
 * parent/child pair. A separate LSM consumer must authenticate the charged
 * child, original route and parent before granting eligibility. */
SEC("raw_tp/sched_process_fork")
int opaque_real_owner_successful_birth_candidate(
	struct bpf_raw_tracepoint_args *ctx)
{
	__u64 parent = ctx->args[0], child = ctx->args[1];
	if (!parent || !child || parent == child ||
	    parent != (__u64)bpf_get_current_task_btf())
		return 0;
	struct opaque_birth_receipt *receipt =
		bpf_map_lookup_elem(&opaque_birth_receipts, &child);
	if (!receipt)
		return 0;
	receipt->observation = 1;
	if (receipt->state != 1 || receipt->child != child ||
	    receipt->parent != parent || !receipt->scope ||
	    !receipt->generation || !receipt->serial ||
	    !receipt->parent_cookie || !receipt->child_cookie ||
	    !receipt->child_locator || receipt->slot >= SE_PROFILE_BINDINGS)
		return 0;
	receipt->observation = 2;
	__u64 child_cgroup = 0;
	if (BPF_CORE_READ_INTO(&child_cgroup, (struct task_struct *)child,
			       cgroups, dfl_cgrp, kn, id) ||
	    child_cgroup != bpf_get_current_cgroup_id())
		return 0;
	receipt->observation = 3;
	receipt->state = 2;
	receipt->observation = 4;
	return 0;
}

/* security_task_free is skipped when security_task_alloc itself rejects a
 * fork. free_task is reached by that failure path after an RCU grace period;
 * it also covers later successful exits. Pointer reuse cannot inherit an
 * issued receipt while this source-owned cleanup link remains attached. */
SEC("kprobe/free_task")
int BPF_KPROBE(opaque_real_owner_birth_free_task_candidate,
	       struct task_struct *task)
{
	real_owner_birth_retire((__u64)task, 1);
	return 0;
}
#endif

/* A final-free lease pins the exact physical TASK while the two independent
 * locks settle their respective owners. Never hold the TASK metadata lock
 * across the route/binding lookup or the route lock. A failed reader release
 * retains the charge; it cannot be translated into an empty-owner receipt. */
static __attribute__((noinline)) int
real_owner_child_exec_death(struct se_of_lease *lease,
			    struct task_struct *physical)
{
	struct se_of_semantic_handle semantic = {};
	struct se_pool_task_wire *payload = 0;
	if (se_of_semantic_begin(lease, physical, &semantic, &payload) !=
	    SE_OL_OK)
		return SE_OL_CORRUPT;
	struct se_task_state *task = &payload->semantic;
	__u32 slot = task->scope_slot;
	__u64 invocation = task->reader_invocation;
	int abort_ok =
		!task->exec.owned ||
		(task->exec.bprm && task->exec.sequence &&
		 !se_exec_abort_locked(task, lease->cookie, task->exec.bprm,
				       task->exec.sequence));
	if (!abort_ok)
		lease->meta->cleanup_error = 1;
	/* begin's successful branch holds this exact metadata lock. The generic
	 * conditional end has verifier-visible error exits while locked here;
	 * close this proven lexical branch without another fallible check. */
	lease->locked = 0;
	payload = 0;
	bpf_spin_unlock(&lease->meta->lock);
	if (!abort_ok)
		return SE_OL_CORRUPT;

	/* The route lock owns reader state. The death lease excludes a successor
	 * TASK slot; actual task_free excludes a new exec on this physical task. */
	struct se_route_anchor *route = route_lookup(slot);
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &slot);
	if (!route || !binding)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&route->lock);
	int reader_ok = !task->reader.owned && !task->reader_invocation;
	if (!reader_ok && invocation)
		reader_ok = !se_exec_reader_release_locked(
			&binding->state, task, lease->cookie, invocation);
	bpf_spin_unlock(&route->lock);
	/* The callback-local death lease remains held; recheck the exact TASK
	 * identity before issuing a receipt. Reader state was observed under its
	 * owning route lock and cannot acquire a new owner after task_free. */
	struct se_ol_meta *meta = lease->meta;
	bpf_spin_lock(&meta->lock);
	int done = reader_ok && lease->held == 1 && meta->phase == SE_OL_DEAD &&
		   meta->cookie == lease->cookie &&
		   meta->locator == lease->locator && meta->active_leases &&
		   !meta->cleanup_error && !task->exec.owned &&
		   task->physical_cookie == lease->cookie &&
		   task->scope_slot == slot;
	if (done)
		meta->cleanup_done |= SE_OL_EXEC_DONE;
	else
		meta->cleanup_error = 1;
	bpf_spin_unlock(&meta->lock);
	return done ? SE_OL_OK : SE_OL_CORRUPT;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE
/* The dying TASK's current WORK slot + 1 (0: none), read before
 * se_owk_finish_suspended_death clears the tuple. Only an SE_OL_OK finish
 * hands it to the synchronous return, which re-checks DONE and the cookie. */
static __attribute__((noinline)) __u32
real_owner_work_death_slot(struct se_of_lease *lease)
{
	struct se_ol_meta *meta = lease->meta;
	if (!meta)
		return 0;
	bpf_spin_lock(&meta->lock);
	__u32 slot = meta->current_work_slot;
	int owned = meta->current_work_owned == 1 && slot < SE_OWK_WORKS;
	bpf_spin_unlock(&meta->lock);
	return owned ? slot + 1 : 0;
}
#endif
static __attribute__((noinline)) SE_DEATH_T
real_owner_child_work_death(struct se_of_lease *lease)
{
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE
	__u32 settled = real_owner_work_death_slot(lease);
	int death = se_owk_finish_suspended_death(lease);
	if (death == SE_OL_OK)
		return settled;
	if (death != SE_OL_CORRUPT)
		return 0;
	struct se_ol_meta *meta = lease->meta;
	if (!meta)
		return 0;
	bpf_spin_lock(&meta->lock);
	if (lease->held == 1 && meta->locator == lease->locator &&
	    meta->cookie == lease->cookie && meta->phase == SE_OL_DEAD)
		meta->cleanup_error = 1;
	bpf_spin_unlock(&meta->lock);
	return 0;
#else
	/* STALE means no suspended WORK; CONTENDED means a live WORK callback
	 * still owns completion. Neither is a fabricated WORK_DONE receipt. */
	if (se_owk_finish_suspended_death(lease) != SE_OL_CORRUPT)
		return;
	struct se_ol_meta *meta = lease->meta;
	if (!meta)
		return;
	bpf_spin_lock(&meta->lock);
	if (lease->held == 1 && meta->locator == lease->locator &&
	    meta->cookie == lease->cookie && meta->phase == SE_OL_DEAD)
		meta->cleanup_error = 1;
	bpf_spin_unlock(&meta->lock);
#endif
}

/* G025: the physical-reuse directory withdrawal is a correctness fix of
 * every build of this final-free program, never a witness option. */
#ifndef SE_OF_WITHDRAW_DIRECTORY
#error "real-map final-free requires the physical-reuse directory withdrawal"
#endif
#ifndef SE_OP_INSERT_RETRY
#error "real-map birth requires the physical-reuse single insert retry"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE
#ifdef SE_FC_EXIT_INJECTOR
/* Test-only exit injector. opaque_real_exit_inject_every[0] = N arms it (0
 * disables), [1] selects the fault (REAL_OWNER_EXIT_INJECT_*; 0 means
 * BEFORE_CLAIM):
 *   BEFORE_CLAIM, AFTER_CLAIM, AFTER_ADVANCE  every Nth exit that reaches
 *       its withdrawal stops before stage 1 (the key stays PUBLISHED),
 *       after stage 1 (WITHDRAW_CLAIM) or after stage 2 (WITHDRAWN_ZERO), as
 *       if the next stage refused: DIR_PENDING, resumed at free from there;
 *   UNSETTLED, UNSETTLED_FAULT  every Nth exit reports se_of_record_death
 *       CONTENDED or CORRUPT without calling it: the TASK is untouched and
 *       the task_free fallback settles it;
 *   SKIP_DELETE, SKIP_FREE  a cumulative budget instead of a period: while
 *       [1] injected < N, the next free of a SETTLED tombstone skips its
 *       delete (FREED left, as a failed delete) or its whole consumption
 *       (SETTLED left, as a missed task_free); the address's next lifetime
 *       finds it STALE;
 *   PENDING_SKIP_FREE  the same cumulative budget at the exit's withdrawal:
 *       the next exit refuses it before stage 1 (DIR_PENDING, lease held)
 *       and marks its tombstone (REAL_OWNER_EXIT_INJECT_SKIP_FREE_FLAG) so
 *       that its free skips the whole consumption (as a missed task_free;
 *       the free sets REAL_OWNER_EXIT_INJECT_FREE_SKIPPED as its witness):
 *       the address's next lifetime finds a stale DIR_PENDING.
 * Counts: [0] edges seen while enabled, [1] injected. */
#define REAL_OWNER_EXIT_INJECT_BEFORE_CLAIM 1
#define REAL_OWNER_EXIT_INJECT_AFTER_CLAIM 2
#define REAL_OWNER_EXIT_INJECT_AFTER_ADVANCE 3
#define REAL_OWNER_EXIT_INJECT_UNSETTLED 4
#define REAL_OWNER_EXIT_INJECT_UNSETTLED_FAULT 5
#define REAL_OWNER_EXIT_INJECT_SKIP_DELETE 6
#define REAL_OWNER_EXIT_INJECT_SKIP_FREE 7
#define REAL_OWNER_EXIT_INJECT_PENDING_SKIP_FREE 8
/* Test-only tombstone flags (injector objects only). */
#define REAL_OWNER_EXIT_INJECT_SKIP_FREE_FLAG 2
#define REAL_OWNER_EXIT_INJECT_FREE_SKIPPED 4
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_exit_inject_every SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_exit_inject_counts SEC(".maps");
/* Returns 1 when this edge of a fault in [lo, hi] is injected. */
static __attribute__((noinline)) int real_owner_exit_inject(__u32 lo, __u32 hi)
{
	__u32 zero = 0, one = 1;
	const __u32 *every =
		bpf_map_lookup_elem(&opaque_real_exit_inject_every, &zero);
	const __u32 *mode =
		bpf_map_lookup_elem(&opaque_real_exit_inject_every, &one);
	if (!every || !*every || !mode)
		return 0;
	__u32 fault = *mode ? *mode : REAL_OWNER_EXIT_INJECT_BEFORE_CLAIM;
	if (fault < lo || fault > hi)
		return 0;
	__u64 n = *every;
	__u64 *seen =
		bpf_map_lookup_elem(&opaque_real_exit_inject_counts, &zero);
	__u64 *injected =
		bpf_map_lookup_elem(&opaque_real_exit_inject_counts, &one);
	if (!seen || !injected)
		return 0;
	if (fault >= REAL_OWNER_EXIT_INJECT_SKIP_DELETE) {
		__sync_fetch_and_add(seen, 1);
		__u64 used = *injected;
		return used < n && __sync_val_compare_and_swap(
					   injected, used, used + 1) == used ?
			       fault :
			       0;
	}
	if (__sync_add_and_fetch(seen, 1) % n)
		return 0;
	__sync_fetch_and_add(injected, 1);
	return fault;
}
/* The exit's withdrawal under the injector: se_of_withdraw_directory, or
 * its own stages (full/shared_pool_opaque_final_free_candidate.h) stopped
 * before stage 1, 2 or 3. */
static __attribute__((noinline)) int
real_owner_exit_withdraw(struct se_of_lease *lease,
			 struct task_struct *physical)
{
	int fault =
		real_owner_exit_inject(REAL_OWNER_EXIT_INJECT_BEFORE_CLAIM,
				       REAL_OWNER_EXIT_INJECT_AFTER_ADVANCE);
	if (!fault &&
	    real_owner_exit_inject(REAL_OWNER_EXIT_INJECT_PENDING_SKIP_FREE,
				   REAL_OWNER_EXIT_INJECT_PENDING_SKIP_FREE)) {
		__u64 key = (__u64)physical;
		struct real_owner_exit_tombstone *tomb =
			bpf_map_lookup_elem(&se_exit_tombstones, &key);
		if (tomb)
			tomb->flags |= REAL_OWNER_EXIT_INJECT_SKIP_FREE_FLAG;
		return SE_OL_CONTENDED;
	}
	if (!fault)
		return se_of_withdraw_directory(lease, physical);
	if (fault == REAL_OWNER_EXIT_INJECT_BEFORE_CLAIM)
		return SE_OL_CONTENDED;
	if (!lease || lease->held != 1 || lease->locked || !lease->meta ||
	    !physical || lease->physical != physical || !lease->cookie)
		return SE_OL_CORRUPT;
	__u32 slot = 0;
	if (se_ol_decode(lease->locator, &slot) != SE_OL_OK ||
	    slot != lease->slot)
		return SE_OL_CORRUPT;
	const __u64 *archive = SE_OW_ARCHIVE_LOOKUP(slot);
	if (!archive || *archive != (__u64)(unsigned long)physical)
		return SE_OL_CONTENDED;
	struct se_ol_meta *meta = lease->meta;
	if (se_of_withdraw_claim(meta, lease->cookie, lease->locator) !=
		    SE_OL_OK ||
	    fault == REAL_OWNER_EXIT_INJECT_AFTER_CLAIM)
		return SE_OL_CONTENDED;
	(void)se_of_withdraw_advance(meta, archive, lease->cookie,
				     lease->locator);
	return SE_OL_CONTENDED;
}
static __always_inline int
real_owner_exit_record_death(struct task_struct *physical,
			     struct se_of_lease *lease)
{
	int fault =
		real_owner_exit_inject(REAL_OWNER_EXIT_INJECT_UNSETTLED,
				       REAL_OWNER_EXIT_INJECT_UNSETTLED_FAULT);
	if (fault)
		return fault == REAL_OWNER_EXIT_INJECT_UNSETTLED ?
			       SE_OL_CONTENDED :
			       SE_OL_CORRUPT;
	return se_of_record_death(physical, lease);
}
#define SE_FC_EXIT_WITHDRAW(lease, physical) \
	real_owner_exit_withdraw((lease), (physical))
#define SE_FC_EXIT_RECORD_DEATH(physical, lease) \
	real_owner_exit_record_death((physical), (lease))
#define SE_FC_EXIT_FREE_FAULT()                                    \
	real_owner_exit_inject(REAL_OWNER_EXIT_INJECT_SKIP_DELETE, \
			       REAL_OWNER_EXIT_INJECT_SKIP_FREE)
#else
#define SE_FC_EXIT_WITHDRAW(lease, physical) \
	se_of_withdraw_directory((lease), (physical))
#define SE_FC_EXIT_RECORD_DEATH(physical, lease) \
	se_of_record_death((physical), (lease))
#endif

/* RESERVED tombstone, inserted before se_of_record_death, charged to the
 * TASK binding of the charge the directory names (account). Returns 0 when
 * inserted; nonzero leaves the TASK to the task_free fallback (slow, never
 * early). On -EEXIST the tombstone at this key is an earlier lifetime's
 * (the exit fires once per task, before its free): one that is not the
 * reaper's is finished as stale (real_owner_exit_tomb_stale) and the insert
 * retried once; one that vanished between the insert and the lookup (its
 * free, stale finish or reaper retirement completed meanwhile) is retried
 * once too. */
static __attribute__((noinline)) int
real_owner_exit_tomb_stale(__u64 key, struct real_owner_exit_tombstone *tomb,
			   struct task_struct *physical);
static __attribute__((noinline)) int
real_owner_exit_tomb_insert(__u64 key, __u64 start, __u32 account,
			    struct task_struct *physical)
{
	__u64 *held = account < SE_PROFILE_BINDINGS ?
			      bpf_map_lookup_elem(&opaque_real_exit_accounts,
						  &account) :
			      0;
	if (!held) {
		real_owner_exit_count(REAL_OWNER_EXIT_TOMB_FAULT);
		return -1;
	}
	if (__sync_add_and_fetch(held, 1) > SE_EXIT_TOMBSTONE_ACCOUNT) {
		__sync_fetch_and_add(held, -1);
		real_owner_exit_count(REAL_OWNER_EXIT_ACCOUNT_OVERFLOW);
		return -1;
	}
	struct real_owner_exit_tombstone reserved = {
		.start = start,
		.stage = REAL_OWNER_EXIT_RESERVED,
		.account = account,
	};
	long err = bpf_map_update_elem(&se_exit_tombstones, &key, &reserved,
				       BPF_NOEXIST);
	if (err == -17 /* EEXIST */) {
		struct real_owner_exit_tombstone *old =
			bpf_map_lookup_elem(&se_exit_tombstones, &key);
		if (!old || !real_owner_exit_tomb_stale(key, old, physical))
			err = bpf_map_update_elem(&se_exit_tombstones, &key,
						  &reserved, BPF_NOEXIST);
	}
	if (err) {
		__sync_fetch_and_add(held, -1);
		/* -EEXIST: an earlier lifetime's tombstone the reaper still
		 * owns (FREE_PENDING/RETIRING); -EBUSY: a busy bucket lock;
		 * otherwise (-E2BIG/-ENOMEM) the map is full. */
		real_owner_exit_count(err == -17 ? REAL_OWNER_EXIT_BLOCKED :
				      err == -16 ? REAL_OWNER_EXIT_BUSY :
						   REAL_OWNER_EXIT_OVERFLOW);
		return -1;
	}
	real_owner_exit_count(REAL_OWNER_EXIT_INSERTED);
	__u32 index = REAL_OWNER_EXIT_LIVE;
	__u64 *live = bpf_map_lookup_elem(&opaque_real_exit_credit, &index);
	if (!live)
		return 0;
	__u64 n = __sync_add_and_fetch(live, 1);
	if (n == REAL_OWNER_EXIT_HIGH_MARK)
		real_owner_exit_count(REAL_OWNER_EXIT_HIGH_CROSSED);
	index = REAL_OWNER_EXIT_HIGH_WATER;
	__u64 *high = bpf_map_lookup_elem(&opaque_real_exit_credit, &index);
	/* Raise HIGH_WATER to n. Each lost CAS means another insert raised it
	 * meanwhile, so after 16 losses the gauge may stay below n by at most
	 * the inserts still racing: HIGH_WATER is a lower bound of the peak,
	 * exact without 16 concurrent raises. */
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (!high)
			break;
		__u64 seen = *high;
		if (seen >= n ||
		    __sync_val_compare_and_swap(high, seen, n) == seen)
			break;
	}
	return 0;
}

/* Retire this lifetime's exact terminal receipt at the key, if any. */
static __always_inline void
real_owner_exit_retire_receipt(__u64 key, __u64 cookie, __u64 locator)
{
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	if (receipt && receipt->physical == key && receipt->cookie == cookie &&
	    receipt->locator == locator)
		(void)bpf_map_delete_elem(&se_exec_terminal_receipts, &key);
#endif
}

/* The exact death settlement, moved unchanged from task_free (G019 credit
 * at exit). The typed tracepoint argument is current: it is used, as in
 * task_free, only as eight opaque key bytes, as the lease's physical and
 * for its start_time (the tombstone's stale-lifetime check; the directory
 * check separates a successor that carries the same start_time).
 * se_of_record_death's precondition (no later exec, terminal or birth on
 * this task, no successor at this address) holds from do_exit on, so the
 * exit is a second exact-death source next to task_free; only one of them
 * settles a lifetime (the tombstone decides). */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(opaque_real_owner_child_exit_candidate,
	     struct task_struct *physical)
{
	if (!real_owner_image_configured())
		return 0;
	__u64 key = (__u64)physical;
	if (!key || key != (__u64)bpf_get_current_task_btf())
		return 0;
#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
	/* Retire this task's birth receipt at exit, charged or not: an exited
	 * task never execs again (no first-exec qualification can read it) and
	 * its address cannot be reused before the free, so the receipt map is
	 * bounded by live tasks instead of tasks awaiting the RCU-deferred free.
	 * Not counted as a failed birth: a task that reached do_exit was born.
	 * task_free and free_task keep retiring as the fallback (failed births,
	 * exits before this link was attached). */
	(void)bpf_map_delete_elem(&opaque_birth_receipts, &key);
#endif
	/* An uncharged task carries nothing: one directory lookup. */
	const __u64 *published = SE_OL_LOOKUP(&key);
	if (!published)
		return 0;
	/* A zero value names no charge: an unpublished or aborted
	 * constructor's key, or an earlier lifetime's withdrawal stopped
	 * between stages 2 and 3 (WITHDRAWN_ZERO; a birth meeting it is
	 * refused, so this task holds no charge here). Nothing to settle and
	 * no fault. */
	__u64 value = se_ol_load_scalar(published);
	if (!value)
		return 0;
	/* The binding the charge belongs to (pools are partitioned exactly
	 * per binding). An undecodable entry is left to task_free. */
	__u32 charged = 0;
	if (se_ol_decode(value, &charged) != SE_OL_OK ||
	    charged >= SE_OL_TASKS) {
		real_owner_exit_count(REAL_OWNER_EXIT_TOMB_FAULT);
		return 0;
	}
	/* Overflow, busy, blocked: the TASK is untouched; task_free settles it. */
	if (real_owner_exit_tomb_insert(key, physical->start_time,
					charged / SE_OC_QUOTA, physical))
		return 0;
	struct real_owner_exit_tombstone *tomb =
		bpf_map_lookup_elem(&se_exit_tombstones, &key);
	if (!tomb) {
		real_owner_exit_count(REAL_OWNER_EXIT_TOMB_FAULT);
		return 0;
	}
	struct se_of_lease lease = {};
	int death = SE_FC_EXIT_RECORD_DEATH(physical, &lease);
	if (death != SE_OL_OK) {
		/* Nothing settled; task_free's fallback retries as before.
		 * CONTENDED: this task never owned the charge (benign). */
		real_owner_exit_count(death == SE_OL_CONTENDED ?
					      REAL_OWNER_EXIT_UNSETTLED :
					      REAL_OWNER_EXIT_UNSETTLED_FAULT);
		(void)real_owner_exit_tomb_delete(key, tomb->account);
		return 0;
	}
	/* The exact identity, before anything else can see the held lease
	 * (a reaper visit, a stale finish at a later lifetime). */
	tomb->cookie = lease.cookie;
	tomb->locator = lease.locator;
	tomb->slot = lease.slot;
	(void)real_owner_child_exec_death(&lease, physical);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE
	SE_WORK_SYNC_RETURN(real_owner_child_work_death(&lease),
			    REAL_OWNER_WORK_SYNC_SETTLED_DEATH);
#else
	real_owner_child_work_death(&lease);
#endif
	__u32 flags = 0;
	/* Receipt retirement moved here from task_free: both terminal producers
	 * run in this task's own syscall before do_exit, so none can follow.
	 * Retire only this exact lease's receipt; any other receipt at the key
	 * keeps it for its consumer (DIR_PENDING, as se_or_task_terminal_guard
	 * would); a failed delete is retried at free. */
	real_owner_exit_retire_receipt(key, lease.cookie, lease.locator);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
	if (bpf_map_lookup_elem(&se_exec_terminal_receipts, &key))
		flags = REAL_OWNER_EXIT_FOREIGN_RECEIPT;
#endif
	(void)se_of_complete_native_unheld(&lease, physical);
	tomb->flags = flags;
	/* Withdraw the directory entry under the exact death lease (batch F,
	 * full/shared_pool_opaque_final_free_candidate.h), then release. Any
	 * refusal keeps the lease: the reaper stays excluded and task_free
	 * resumes the withdrawal. */
	int settled = !flags &&
		      SE_FC_EXIT_WITHDRAW(&lease, physical) == SE_OL_OK &&
		      se_of_release(&lease, physical) == SE_OL_OK;
	tomb->stage = settled ? REAL_OWNER_EXIT_SETTLED :
				REAL_OWNER_EXIT_DIR_PENDING;
	real_owner_exit_count(settled ? REAL_OWNER_EXIT_SETTLED_COUNT :
					REAL_OWNER_EXIT_DIR_PENDING_COUNT);
	if (settled)
		SE_REAP_EVENT(TASK_DEAD, lease.slot, lease.cookie);
	return 0;
}

/* Free-time resume of a DIR_PENDING withdrawal under the exit's lease,
 * rebuilt by the caller. It enters se_of_withdraw_directory's own stages
 * (full/shared_pool_opaque_final_free_candidate.h) from the state the exit
 * left: PUBLISHED (stage 1 refused or skipped), WITHDRAW_CLAIM (stage 2
 * refused) or WITHDRAWN_ZERO (stage 3 refused). Single deleter: the lease
 * (active_leases == 1) still excludes the reaper's claim, advance and
 * delete, and only this lease's holder owns exclusive_owner == locator; no
 * successor exists before the slab free. */
static __attribute__((noinline)) int
real_owner_exit_withdraw_resume(struct se_of_lease *lease,
				struct task_struct *physical)
{
	if (!lease || lease->held != 1 || lease->locked || !lease->meta ||
	    !physical || lease->physical != physical || !lease->cookie)
		return SE_OL_CORRUPT;
	__u32 slot = 0;
	if (se_ol_decode(lease->locator, &slot) != SE_OL_OK ||
	    slot != lease->slot)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = lease->meta;
	__u64 locator = lease->locator, cookie = lease->cookie;
	bpf_spin_lock(&meta->lock);
	__u32 directory = meta->directory_state;
	int owned = meta->phase == SE_OL_DEAD && meta->cookie == cookie &&
		    meta->locator == locator && meta->active_leases == 1 &&
		    !meta->reserved && meta->exclusive == 1 &&
		    meta->exclusive_owner == locator;
	bpf_spin_unlock(&meta->lock);
	if (directory == SE_OL_PUBLISHED)
		return se_of_withdraw_directory(lease, physical);
	if (!owned || (directory != SE_OL_WITHDRAW_CLAIM &&
		       directory != SE_OL_WITHDRAWN_ZERO))
		return SE_OL_CONTENDED;
	const __u64 *archive = SE_OW_ARCHIVE_LOOKUP(slot);
	if (!archive || *archive != (__u64)(unsigned long)physical)
		return SE_OL_CONTENDED;
	if (directory == SE_OL_WITHDRAW_CLAIM) {
		int advanced =
			se_of_withdraw_advance(meta, archive, cookie, locator);
		if (advanced != SE_OL_OK)
			return advanced;
	}
	return se_of_withdraw_delete(meta, archive, cookie);
}

/* Finish a DIR_PENDING tombstone's still-held exit lease. resume: this is
 * the free of the tombstone's own lifetime, so the withdrawal is resumed;
 * otherwise (a stale tombstone found at a later lifetime) it is not, since
 * a successor now exists at this address. Rebuilds the lease from the exact
 * identity, then releases it (TASK_DEAD). A withdrawal not completed here is
 * the reaper's: stage FREE_PENDING, set before the release; the reaper
 * retires it only once no lease is held (real_owner_exit_tomb_reap), so it
 * can never zero the archive first. A lease that cannot be rebuilt exactly
 * (identity, DEAD, active_leases == 1) or released is a LEASE_FAULT: it
 * stays held, so the reaper never retires the tombstone nor withdraws the
 * key and the slot stays charged (fail-closed). Returns 1 when the
 * tombstone stays (FREE_PENDING), 0 when the withdrawal completed. */
static __attribute__((noinline)) int
real_owner_exit_finish_pending(__u64 key,
			       struct real_owner_exit_tombstone *tomb,
			       struct task_struct *physical, int resume)
{
	__u64 cookie = tomb->cookie, locator = tomb->locator;
	__u32 slot = tomb->slot;
	struct se_ol_meta *meta = slot < SE_OL_TASKS ? SE_OL_META_LOOKUP(slot) :
						       0;
	int exact = 0;
	if (meta) {
		bpf_spin_lock(&meta->lock);
		exact = meta->cookie == cookie && meta->locator == locator &&
			meta->phase == SE_OL_DEAD && meta->active_leases == 1 &&
			!meta->reserved;
		bpf_spin_unlock(&meta->lock);
	}
	int result = SE_OL_CORRUPT;
	struct se_of_lease lease = {
		.meta = meta,
		.physical = physical,
		.locator = locator,
		.cookie = cookie,
		.slot = slot,
		.held = 1,
	};
	if (exact) {
		result = SE_OL_CONTENDED;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
		if (resume &&
		    !bpf_map_lookup_elem(&se_exec_terminal_receipts, &key))
#else
		if (resume)
#endif
			result = real_owner_exit_withdraw_resume(&lease,
								 physical);
	}
	if (result != SE_OL_OK)
		tomb->stage = REAL_OWNER_EXIT_FREE_PENDING;
	real_owner_exit_count(result == SE_OL_OK ? REAL_OWNER_EXIT_DIR_RESUMED :
						   REAL_OWNER_EXIT_DIR_FAULTED);
	if (!exact || se_of_release(&lease, physical) != SE_OL_OK)
		real_owner_exit_count(REAL_OWNER_EXIT_LEASE_FAULT);
	else
		SE_REAP_EVENT(TASK_DEAD, slot, cookie);
	return result != SE_OL_OK;
}

/* A tombstone of an earlier lifetime at this address (see
 * se_exit_tombstones), found at exit or at free: finish it as its own free
 * would have, counted STALE. RESERVED and FREED (already counted) are
 * deleted; SETTLED is counted FREED (its receipt retired) and deleted;
 * DIR_PENDING releases its lease without resuming (FREE_PENDING, counted
 * FREED) and stays for the reaper. FREE_PENDING and RETIRING are the
 * reaper's and are left alone. Returns 0 when the key is free again. */
static __attribute__((noinline)) int
real_owner_exit_tomb_stale(__u64 key, struct real_owner_exit_tombstone *tomb,
			   struct task_struct *physical)
{
	__u32 stage = tomb->stage;
	if (stage == REAL_OWNER_EXIT_FREE_PENDING ||
	    stage == REAL_OWNER_EXIT_RETIRING)
		return 1;
	real_owner_exit_count(REAL_OWNER_EXIT_STALE);
	if (stage == REAL_OWNER_EXIT_DIR_PENDING) {
		/* Locals: once its lease is released a FREE_PENDING tombstone
		 * is the reaper's, which may retire (delete) it at any time. */
		__u64 cookie = tomb->cookie;
		__u32 slot = tomb->slot, account = tomb->account;
		int stays =
			real_owner_exit_finish_pending(key, tomb, physical, 0);
		real_owner_exit_count(REAL_OWNER_EXIT_FREED);
		SE_REAP_EVENT(TASK_FREED, slot, cookie);
		if (stays)
			return 1;
		return real_owner_exit_tomb_delete(key, account) ? 1 : 0;
	}
	if (stage == REAL_OWNER_EXIT_SETTLED) {
		real_owner_exit_retire_receipt(key, tomb->cookie,
					       tomb->locator);
		real_owner_exit_count(REAL_OWNER_EXIT_FREED);
		SE_REAP_EVENT(TASK_FREED, tomb->slot, tomb->cookie);
		tomb->stage = REAL_OWNER_EXIT_FREED_STAGE;
	} else if (stage != REAL_OWNER_EXIT_RESERVED &&
		   stage != REAL_OWNER_EXIT_FREED_STAGE) {
		real_owner_exit_count(REAL_OWNER_EXIT_TOMB_FAULT);
		return 1;
	}
	return real_owner_exit_tomb_delete(key, tomb->account) ? 1 : 0;
}

/* task_free side, run whether or not the image gate is armed (a gate
 * disarmed between exit and free must not leak the tombstone; everything
 * here is exact-identity and fail-closed). Returns 1 when this lifetime was
 * settled at exit (SETTLED or DIR_PENDING with this task's start_time and
 * no other charge published at the key): the fallback below must not run.
 * No tombstone (no exit settlement: overflow,
 * a late copy_process failure, or the exit link not attached), RESERVED (an
 * exit that settled nothing), a stale tombstone of an earlier lifetime
 * (finished, counted STALE) and FREE_PENDING/RETIRING (an earlier lifetime
 * the reaper owns) return 0: the fallback settles this task exactly as
 * before. */
static __attribute__((noinline)) int
real_owner_exit_free(struct task_struct *physical)
{
	__u64 key = (__u64)physical;
	struct real_owner_exit_tombstone *tomb =
		bpf_map_lookup_elem(&se_exit_tombstones, &key);
	if (!tomb)
		return 0;
	__u32 stage = tomb->stage;
	if (stage == REAL_OWNER_EXIT_FREE_PENDING ||
	    stage == REAL_OWNER_EXIT_RETIRING)
		return 0;
	int foreign = tomb->start != physical->start_time;
	if (!foreign && (stage == REAL_OWNER_EXIT_SETTLED ||
			 stage == REAL_OWNER_EXIT_DIR_PENDING)) {
		/* Its own SETTLED exit deleted the key and its own DIR_PENDING
		 * keeps its locator or zero there; any other value is this
		 * task's own charge, untouched at exit (see se_exit_tombstones:
		 * start_time can repeat across lifetimes). */
		const __u64 *published = SE_OL_LOOKUP(&key);
		__u64 value = published ? se_ol_load_scalar(published) : 0;
		foreign = value && value != tomb->locator;
	}
	if (foreign) {
		(void)real_owner_exit_tomb_stale(key, tomb, physical);
		return 0;
	}
	if (stage == REAL_OWNER_EXIT_RESERVED) {
		(void)real_owner_exit_tomb_delete(key, tomb->account);
		return 0;
	}
	if (stage != REAL_OWNER_EXIT_SETTLED &&
	    stage != REAL_OWNER_EXIT_DIR_PENDING) {
		/* FREED of this very lifetime: a free cannot run twice. */
		real_owner_exit_count(REAL_OWNER_EXIT_TOMB_FAULT);
		return 1;
	}
#ifdef SE_FC_EXIT_INJECTOR
	if (stage == REAL_OWNER_EXIT_DIR_PENDING &&
	    (tomb->flags & REAL_OWNER_EXIT_INJECT_SKIP_FREE_FLAG)) {
		tomb->flags |= REAL_OWNER_EXIT_INJECT_FREE_SKIPPED;
		return 1;
	}
	int fault = stage == REAL_OWNER_EXIT_SETTLED ? SE_FC_EXIT_FREE_FAULT() :
						       0;
	if (fault == REAL_OWNER_EXIT_INJECT_SKIP_FREE)
		return 1;
#endif
	__u64 cookie = tomb->cookie, locator = tomb->locator;
	__u32 slot = tomb->slot;
	/* Normally retired at exit; retire a receipt whose exit-time delete
	 * failed. Exact match only. */
	real_owner_exit_retire_receipt(key, cookie, locator);
	int stays = stage == REAL_OWNER_EXIT_DIR_PENDING &&
		    real_owner_exit_finish_pending(key, tomb, physical, 1);
	/* Emit before the delete: a drained LIVE implies every wakeup. */
	real_owner_exit_count(REAL_OWNER_EXIT_FREED);
	SE_REAP_EVENT(TASK_FREED, slot, cookie);
	if (stays)
		return 1;
	tomb->stage = REAL_OWNER_EXIT_FREED_STAGE;
#ifdef SE_FC_EXIT_INJECTOR
	if (fault == REAL_OWNER_EXIT_INJECT_SKIP_DELETE)
		return 1;
#endif
	(void)real_owner_exit_tomb_delete(key, tomb->account);
	return 1;
}
#endif
/* Exact physical death is the only source of the DEAD transition. This
 * callback settles exec/reader and certifies an empty native owner account.
 * Nonempty native refs remain pending for a future source-owned closer; this
 * callback never refunds a TASK or WORK credit. */
SEC("lsm/task_free")
int BPF_PROG(opaque_real_owner_child_final_free_candidate,
	     struct task_struct *physical)
{
	if (!real_owner_image_configured()) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE
		/* Consume a tombstone the armed exit left: a gate disarmed
		 * between exit and free must not strand it. No fallback runs,
		 * as before credit at exit. */
		(void)real_owner_exit_free(physical);
#endif
		return 0;
	}
#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
	real_owner_birth_retire((__u64)physical, 0);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_RECOVERED_INITIAL_TASK_DIAGNOSTIC
	opaque_recovered_initial_retire_physical(physical);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
	real_owner_child_recovery_close(physical);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE
	__u64 failure_key = (__u64)physical;
	(void)bpf_map_delete_elem(&se_failure_handler_frames, &failure_key);
	(void)bpf_map_delete_elem(&se_failure_outer_frames, &failure_key);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE
	if (real_owner_exit_free(physical))
		return 0;
#endif
	struct se_of_lease lease = {};
	/* On failure the receipt survives and a reused address is quarantined:
	 * fail-closed, an accepted availability cost. */
	if (se_of_record_death(physical, &lease) == SE_OL_OK) {
		(void)real_owner_child_exec_death(&lease, physical);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE
		SE_WORK_SYNC_RETURN(real_owner_child_work_death(&lease),
				    REAL_OWNER_WORK_SYNC_SETTLED_DEATH);
#else
		real_owner_child_work_death(&lease);
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
		/* No terminal retry can run after final free. Retire only this
		 * exact lease's receipt so a reused task address never inherits
		 * it as pending; any other receipt is left for quarantine. */
		__u64 receipt_key = (__u64)physical;
		const struct se_exec_terminal_receipt *receipt =
			bpf_map_lookup_elem(&se_exec_terminal_receipts,
					    &receipt_key);
		if (receipt && receipt->physical == receipt_key &&
		    receipt->cookie == lease.cookie &&
		    receipt->locator == lease.locator)
			(void)bpf_map_delete_elem(&se_exec_terminal_receipts,
						  &receipt_key);
#endif
		(void)se_of_complete_native_unheld(&lease, physical);
		/* Withdraw the directory entry before this address can be reused
		 * (full/shared_pool_opaque_final_free_candidate.h). Any refusal
		 * leaves the reaper's ordinary withdrawal as the fallback. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
		/* Mirror se_or_task_terminal_guard: a receipt left at this key
		 * keeps the key for its consumer; only the reaper retires it. */
		if (!bpf_map_lookup_elem(&se_exec_terminal_receipts,
					 &receipt_key))
#endif
			(void)se_of_withdraw_directory(&lease, physical);
		(void)se_of_release(&lease, physical);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE
		real_owner_exit_count(REAL_OWNER_EXIT_FALLBACK_FREE);
#endif
#ifdef SE_REAP_EVENT
		SE_REAP_EVENT(TASK_DEAD, lease.slot, lease.cookie);
#endif
	}
	return 0;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC
/* Test-only reader-hold injector for the physical-reuse fallback. Take: the
 * product speculative hold (se_ol_hold_observation) on a LIVE, PUBLISHED TASK
 * by its physical key, deliberately never converted or cancelled, so the
 * final-free withdrawal must refuse and leave the reaper path. Release: drop
 * exactly that one hold on the exact slot and cookie. It grants nothing. */
struct opaque_real_reuse_hold_request {
	__u64 physical, cookie;
	__u32 slot, release;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_reuse_hold_request);
} opaque_real_reuse_hold_request SEC(".maps");
SEC("tc")
int opaque_real_reuse_hold(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const struct opaque_real_live_bootstrap_gate *gate =
		opaque_real_live_gate();
	const struct opaque_real_reuse_hold_request *request =
		bpf_map_lookup_elem(&opaque_real_reuse_hold_request, &zero);
	if (!gate || gate->enabled != 1 || !request || !request->physical)
		return 1;
	if (!request->release) {
		__u64 key = request->physical;
		struct se_ol_observation observation = {};
		if (se_ol_observe(&key, &observation) != SE_OL_OK ||
		    se_ol_read_observation(&observation) != SE_OL_OK ||
		    se_ol_hold_observation(&observation) != SE_OL_OK)
			return 2;
		return 0;
	}
	if (request->slot >= SE_OL_TASKS || !request->cookie)
		return 1;
	struct se_ol_meta *meta = meta_lookup(request->slot);
	if (!meta)
		return 1;
	bpf_spin_lock(&meta->lock);
	int exact = meta->cookie == request->cookie && meta->reader_holds;
	if (exact)
		meta->reader_holds--;
	bpf_spin_unlock(&meta->lock);
	return exact ? 0 : 3;
}
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_BEGIN_PROBE
/* A pending receipt blocks a new reader so its exact original invocation
 * cannot be overwritten. Audit still runs, but neither prior trusted roles
 * nor an owned transaction may survive an unobserved successor exec. This
 * helper never consumes or retires the earlier receipt. */
static __attribute__((noinline)) int
real_owner_reader_quarantine_pending(__u64 physical)
{
	struct se_ol_payload_handle owner = {};
	if (!physical || se_ol_task_open(&physical, &owner) != SE_OL_OK)
		return -1;
	struct se_task_state *task = 0;
	int exact = 0;
	if (se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		exact = task->physical_cookie == owner.lease.cookie;
		if (exact) {
			if (!(task->flags & SE_TASK_QUARANTINED)) {
				task->flags |= SE_TASK_QUARANTINED;
				if (task->eligibility_version < ~0ULL - 1)
					task->eligibility_version++;
			}
			if (task->exec.owned)
				se_exec_fault_locked(&task->exec);
		}
		se_op_task_semantic_end(&owner, &task);
	}
	int closed = se_ol_payload_close(&owner) == SE_OL_OK;
	return exact && closed ? 0 : -1;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
/* The source has released its lexical TASK lease and early claim before a
 * tail call. A missing target must reopen and quarantine the exact reader;
 * a copied receipt alone can never authorize another physical generation. */
static __attribute__((noinline)) int
real_owner_policy_abort_handoff(__u64 physical, __u64 bprm)
{
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (!receipt || receipt->physical != physical ||
	    receipt->bprm != bprm || !receipt->cookie || !receipt->locator ||
	    !receipt->invocation || !receipt->scope || !receipt->generation ||
	    receipt->phase != SE_EXEC_TERMINAL_REGISTERED || receipt->reserved)
		return -1;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&physical, &owner) != SE_OL_OK) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC
		real_owner_eval_work_outcome(4);
#endif
		return -1;
	}
	int exact = owner.lease.cookie == receipt->cookie &&
		    owner.lease.locator == receipt->locator;
	__u32 slot = SE_OC_ACCOUNTS;
	struct se_task_state *task = 0;
	if (exact && se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		exact = task->physical_cookie == receipt->cookie &&
			task->scope_cookie == receipt->scope &&
			task->exec.bprm == bprm &&
			task->exec.sequence == receipt->invocation &&
			task->exec.generation == receipt->generation;
		slot = task->scope_slot;
		se_op_task_semantic_end(&owner, &task);
	} else {
		exact = 0;
	}
	struct se_shared_binding *binding =
		exact && slot < SE_OC_ACCOUNTS ?
			bpf_map_lookup_elem(&se_bindings, &slot) :
			0;
	int aborted = binding && se_op_exec_reader_abort_quarantined(
					 &owner, &binding->state, bprm,
					 receipt->invocation) == SE_OL_OK;
	int closed = se_ol_payload_close(&owner) == SE_OL_OK;
	if (aborted && closed)
		(void)bpf_map_delete_elem(&se_exec_terminal_receipts,
					  &physical);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC
	real_owner_eval_work_outcome(aborted && closed ? 3 : 4);
#endif
	return aborted && closed ? 0 : -1;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC
/* Disposable witness only: never consulted for admission or ownership. */
struct opaque_real_continue_witness {
	__u64 physical, bprm, cookie, locator, invocation, scope, generation;
	__u64 first_inode, second_inode, continuations;
	__u64 first_record, first_serial, continued_record, continued_serial;
	__u64 first_dev, second_dev;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_real_continue_witness);
} opaque_real_owner_continue_witness SEC(".maps");
static __attribute__((noinline)) void
real_owner_continue_observe(const struct se_exec_terminal_receipt *receipt,
			    __u64 bprm, int continued, __u64 record,
			    __u64 serial)
{
	__u32 zero = 0;
	struct opaque_real_continue_witness *w =
		bpf_map_lookup_elem(&opaque_real_owner_continue_witness, &zero);
	if (!w || !receipt)
		return;
	__u64 inode = BPF_CORE_READ((struct linux_binprm *)bprm, file, f_inode,
				    i_ino);
	__u64 dev = BPF_CORE_READ((struct linux_binprm *)bprm, file, f_inode,
				  i_sb, s_dev);
	if (continued) {
		w->second_inode = inode;
		w->second_dev = dev;
		w->continued_record = record;
		w->continued_serial = serial;
		w->continuations++;
	} else {
		w->physical = receipt->physical;
		w->bprm = receipt->bprm;
		w->cookie = receipt->cookie;
		w->locator = receipt->locator;
		w->invocation = receipt->invocation;
		w->scope = receipt->scope;
		w->generation = receipt->generation;
		w->first_inode = inode;
		w->first_dev = dev;
		w->second_dev = 0;
		w->first_record = record;
		w->first_serial = serial;
		w->continued_record = w->continued_serial = 0;
		w->second_inode = w->continuations = 0;
	}
}
#endif

/* Build the plain exact receipt in its own lexical frame. The source's
 * TASK-open frame must not retain this 64-byte temporary on the older
 * kernel's deepest payload-open path. */
static __attribute__((noinline)) int
real_owner_policy_register_receipt(const struct se_ol_payload_handle *owner,
				   const struct se_route_claim *claim,
				   __u64 bprm, __u64 invocation)
{
	__u64 physical = (__u64)bpf_get_current_task_btf();
	struct se_exec_terminal_receipt receipt = {
		.physical = physical,
		.bprm = bprm,
		.cookie = owner->lease.cookie,
		.locator = owner->lease.locator,
		.invocation = invocation,
		.scope = claim->scope,
		.generation = claim->generation,
		.phase = SE_EXEC_TERMINAL_REGISTERED,
	};
	if (bpf_map_update_elem(&se_exec_terminal_receipts, &physical, &receipt,
				BPF_NOEXIST)) {
		SE_DEFERRED_STORAGE_REFUSED(0);
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_STORAGE);
		return 0;
	}
	if (real_owner_failure_bind_receipt(&receipt)) {
		(void)bpf_map_delete_elem(&se_exec_terminal_receipts,
					  &physical);
		return 0;
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC
	real_owner_continue_observe(&receipt, bprm, 0, claim->record,
				    claim->serial);
#endif
	return 1;
}

struct real_owner_policy_auth {
	__u64 serial;
	__u32 slot;
	__u32 record;
};

static __attribute__((noinline)) void
real_owner_policy_note_prepared(__u64 physical, __u64 cookie, __u64 invocation)
{
	__u32 zero = 0;
	struct opaque_real_owner_policy_witness *witness =
		bpf_map_lookup_elem(&opaque_real_owner_policy_witness, &zero);
	if (!witness)
		return;
	witness->physical = physical;
	witness->cookie = cookie;
	witness->invocation = invocation;
	__sync_fetch_and_add(&witness->prepared, 1);
}

/* The only source of the original record selector is an exact live TASK
 * semantic borrow. No map-value or semantic pointer escapes this function. */
static __attribute__((noinline)) int
real_owner_policy_authenticate(struct se_ol_payload_handle *owner,
			       const struct se_exec_terminal_receipt *receipt,
			       __u64 bprm, struct real_owner_policy_auth *auth)
{
	if (owner->lease.cookie != receipt->cookie ||
	    owner->lease.locator != receipt->locator)
		return 0;
	struct se_task_state *task = 0;
	if (se_op_task_semantic_begin(owner, &task) != SE_OL_OK)
		return 0;
	int exact = task->physical_cookie == receipt->cookie &&
		    task->scope_cookie == receipt->scope && task->exec.owned &&
		    task->exec.bprm == bprm &&
		    task->exec.sequence == receipt->invocation &&
		    task->exec.generation == receipt->generation &&
		    task->reader.owned &&
		    task->reader_invocation == receipt->invocation &&
		    task->reader.token.task_cookie == receipt->cookie &&
		    task->reader.token.scope == receipt->scope;
	if (exact) {
		auth->slot = task->scope_slot;
		auth->record = task->reader.token.record;
		auth->serial = task->reader.token.serial;
	}
	se_op_task_semantic_end(owner, &task);
	return exact;
}

/* Keep the reopened TASK/policy frame out of the terminal-abort call chain.
 * Only the source-issued receipt and retained reader authorize preparation. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* Failed TASK close after a possible suspension. A separate frame keeps the
 * cleanup ticket off the target -> bridge -> WORK stack chain, which was 528
 * bytes (limit 512) on exact AL2023 6.18 with the ticket in this frame. */
static __attribute__((noinline)) void
real_owner_policy_close_fault(struct se_ol_payload_handle *owner, __u64 bprm,
			      int suspended)
{
	(void)se_op_task_owned_fault(owner, bprm);
	if (suspended) {
		struct se_owk_ticket ticket = {};
		if (se_owk_resume(owner, REAL_OWNER_PREPARE_RESUME, &ticket) ==
		    SE_OL_OK)
			(void)se_owk_done(owner, &ticket);
	}
	/* Best effort under the still-owned handle. The caller also attempts
	 * exact receipt-based cleanup, never a replacement policy proposal. */
	(void)se_ol_payload_close(owner);
}
#endif
static __attribute__((noinline)) int
real_owner_policy_target_core(struct linux_binprm *bprm)
{
	int suspended = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	int closed;
#endif
	__u64 physical = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (!receipt || receipt->physical != physical ||
	    receipt->bprm != (__u64)bprm || !receipt->cookie ||
	    !receipt->locator || !receipt->invocation || !receipt->scope ||
	    !receipt->generation || receipt->reserved ||
	    receipt->phase != SE_EXEC_TERMINAL_REGISTERED)
		return 0;
	struct se_ol_payload_handle owner = {};
	if (real_owner_child_open_parent(&owner) != SE_OL_OK)
		return 0;
	struct real_owner_policy_auth auth = {};
	int exact = real_owner_policy_authenticate(&owner, receipt, (__u64)bprm,
						   &auth);
	/* The original-record index must be scalar-bounded before pointer
	 * arithmetic; a conditional lookup alone does not carry that bound
	 * through old verifier state joins. */
	if (!exact || auth.slot >= SE_OC_ACCOUNTS || auth.record >= 2 ||
	    !auth.serial)
		goto close_owner;
	/* Keep an explicit 0/1 data bound in the emitted BPF after the reject
	 * branch. Rocky 4.18 otherwise loses the relation at the state join. */
	volatile __u64 bounded_record = auth.record;
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &auth.slot);
	__u64 recovered = 0;
	if (binding &&
	    se_op_exec_reader_recover(&owner, &binding->state, (__u64)bprm,
				      &recovered) == SE_OL_OK &&
	    recovered == receipt->invocation) {
		const struct se_snapshot *snapshot =
			&binding->state.records[bounded_record & 1ULL];
		if (snapshot->serial == auth.serial &&
		    snapshot->scope == receipt->scope &&
		    snapshot->generation == receipt->generation) {
			int prepared = real_owner_policy_bridge(
				&owner, receipt->scope, receipt->generation,
				snapshot);
			if (!prepared)
				real_owner_policy_note_prepared(
					physical, owner.lease.cookie,
					recovered);
			else if (prepared == 1)
				suspended = 1;
		}
	}
close_owner:
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* No successor may evaluate after the source failed to release its TASK
	 * lease. A failed close retains that exact handle; it grants no new one. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_POLICY_TASK_CLOSE_FAULT_DIAGNOSTIC
	/* Disposable test: reject only the first post-suspension close without
	 * corrupting metadata or pretending to hold an actual spinlock. */
	if (suspended)
		closed = SE_OL_CORRUPT;
	else
#endif
		closed = se_ol_payload_close(&owner);
	if (closed != SE_OL_OK) {
		real_owner_policy_close_fault(&owner, (__u64)bprm, suspended);
		suspended = 0;
	}
#else
	(void)se_ol_payload_close(&owner);
#endif
	return suspended;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
/* A missing stage target is not allowed to strand the suspended WORK. Reopen
 * the original current TASK and consume precisely its stage-one charge. */
static __attribute__((noinline)) int
real_owner_policy_finish_stage_one(__u64 physical, __u64 bprm)
{
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (!receipt || receipt->physical != physical ||
	    receipt->bprm != bprm || !receipt->cookie || !receipt->locator ||
	    !receipt->scope || receipt->phase != SE_EXEC_TERMINAL_REGISTERED ||
	    receipt->reserved)
		return -1;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&physical, &owner) != SE_OL_OK)
		return -1;
	int exact = owner.lease.cookie == receipt->cookie &&
		    owner.lease.locator == receipt->locator;
	struct se_owk_ticket ticket = {};
	/* Consume the WORK at whichever stage it is suspended. A stage
	 * mismatch is a non-mutating STALE replay in se_owk_resume. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
	/* Any pass's evaluation, prepare or terminal stage: an interpreter
	 * pass refused before its rebind leaves the previous pass's proposed
	 * WORK at its terminal stage 3p (G019 gap 4). */
	int resumed = exact && se_owk_resume(&owner, REAL_OWNER_EVAL_RESUME,
					     &ticket) == SE_OL_OK;
	if (exact && !resumed) {
		ticket = (struct se_owk_ticket){};
		resumed = se_owk_resume(&owner, REAL_OWNER_PREPARE_RESUME,
					&ticket) == SE_OL_OK;
	}
	if (exact && !resumed) {
		ticket = (struct se_owk_ticket){};
		resumed = se_owk_resume(&owner, REAL_OWNER_TERMINAL_RESUME,
					&ticket) == SE_OL_OK;
	}
#else
	int resumed = exact && se_owk_resume(&owner, REAL_OWNER_EVAL_STAGE,
					     &ticket) == SE_OL_OK;
	if (exact && !resumed && REAL_OWNER_EVAL_STAGE != 1) {
		ticket = (struct se_owk_ticket){};
		resumed = se_owk_resume(&owner, 1, &ticket) == SE_OL_OK;
	}
#endif
	int closed = resumed && se_owk_done(&owner, &ticket) == SE_OL_OK;
	(void)se_ol_payload_close(&owner);
	return closed ? 0 : -1;
}

#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* The successor claims the exact suspended WORK before looking at its policy
 * view, then releases the nonfinal claim before the stage-one closer. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_real_owner_policy_stage_target_candidate,
	     struct linux_binprm *bprm, int prior)
{
	if (prior)
		return prior;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
	real_owner_rule_progress(0, -8);
#endif
	__u64 physical = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (receipt && receipt->physical == physical &&
	    receipt->bprm == (__u64)bprm && receipt->cookie &&
	    receipt->locator && receipt->scope &&
	    receipt->phase == SE_EXEC_TERMINAL_REGISTERED &&
	    !receipt->reserved) {
		__u64 scope = receipt->scope;
		__u64 cookie = receipt->cookie;
		__u64 invocation = receipt->invocation;
		struct se_owk_payload *payload =
			se_owk_suspended_current(scope, 1, 1);
		if (payload) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
			int begun = real_owner_policy_stage_begin(payload);
			real_owner_rule_progress(0, begun);
			payload = 0;
			if (begun == 1)
				bpf_tail_call(ctx,
					      &opaque_real_owner_rule_targets,
					      0);
#else
			if (real_owner_policy_stage_begin(payload))
				real_owner_policy_note_prepared(
					physical, cookie, invocation);
			payload = 0;
#endif
			(void)se_owk_suspended_current(scope, 1, 2);
		}
	}
	(void)real_owner_policy_finish_stage_one(physical, (__u64)bprm);
	(void)real_owner_policy_abort_handoff(physical, (__u64)bprm);
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RULE_WINDOW_DIAGNOSTIC
/* No map-value pointer survives the first tail call. Reauthenticate the
 * reserved same-task WORK before any matcher read; failure only quarantines
 * this diagnostic Audit execution and closes its exact charge. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_real_owner_rule_target_candidate, struct linux_binprm *bprm,
	     int prior)
{
	if (prior)
		return prior;
	real_owner_rule_progress(1, -8);
	__u64 physical = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (receipt && receipt->physical == physical &&
	    receipt->bprm == (__u64)bprm && receipt->cookie &&
	    receipt->locator && receipt->scope && receipt->invocation &&
	    receipt->phase == SE_EXEC_TERMINAL_REGISTERED &&
	    !receipt->reserved) {
		__u64 scope = receipt->scope;
		__u64 cookie = receipt->cookie;
		__u64 invocation = receipt->invocation;
		int evaluated = real_owner_policy_rule_claimed_eval(scope);
		real_owner_rule_progress(1, evaluated);
		if (evaluated == 1)
			real_owner_policy_note_prepared(physical, cookie,
							invocation);
		(void)se_owk_suspended_current(scope, 1, 2);
	}
	(void)real_owner_policy_finish_stage_one(physical, (__u64)bprm);
	(void)real_owner_policy_abort_handoff(physical, (__u64)bprm);
	return 0;
}
/* Load-only ABI probe. No attachment or policy decision uses this program;
 * it asks the old verifier to accept a typed WORK-resident scalar request
 * through the complete alternative/matcher global-function boundary. */
SEC("tc")
int opaque_real_owner_alt_request_probe(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	struct se_owk_payload *payload =
		bpf_map_lookup_elem(&se_opaque_work_payload, &zero);
	if (!payload)
		return 0;
	struct se_invocation *work = &payload->semantic;
	(void)fe_match_alternative(
		&work->observation.facts, &work->observation.evaluator,
		&work->observation.stage_workspace.alt_request, 0);
	return 0;
}
#endif
#endif /* original Audit-only stage/rule programs */
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
#ifdef SE_VERDICT_EVENTS
/* G020 verdict events (event ABI 1, full/shared_verdict_event.h): the
 * node-wide ring of the "verdict" datasource and its counters
 * (fullruntime/shared_verdict_events.go: SharedVerdictRingMap,
 * SharedVerdictCountersMap). The ring's size is the profile's
 * enforce-exec-shared-verdict-ring geometry (SharedProfile.VerdictRing):
 * by default max(1 MiB, Bindings x 256 KiB) rounded up to a power of two. */
#include <gadget/macros.h>
#include "shared_verdict_event.h"
#define SE_VERDICT_RING_FOR(b)                            \
	((b) * 262144ULL <= (1ULL << 20) ? (1ULL << 20) : \
	 (b) * 262144ULL <= (1ULL << 21) ? (1ULL << 21) : \
	 (b) * 262144ULL <= (1ULL << 22) ? (1ULL << 22) : \
	 (b) * 262144ULL <= (1ULL << 23) ? (1ULL << 23) : \
	 (b) * 262144ULL <= (1ULL << 24) ? (1ULL << 24) : \
	 (b) * 262144ULL <= (1ULL << 25) ? (1ULL << 25) : \
	 (b) * 262144ULL <= (1ULL << 26) ? (1ULL << 26) : \
	 (b) * 262144ULL <= (1ULL << 27) ? (1ULL << 27) : \
	 (b) * 262144ULL <= (1ULL << 28) ? (1ULL << 28) : \
					   0ULL)
#ifndef SE_PROFILE_VERDICT_RING
#define SE_PROFILE_VERDICT_RING SE_VERDICT_RING_FOR(SE_PROFILE_BINDINGS)
#endif
_Static_assert(SE_PROFILE_VERDICT_RING >= 4096ULL &&
		       SE_PROFILE_VERDICT_RING <= (1ULL << 28) &&
		       !(SE_PROFILE_VERDICT_RING &
			 (SE_PROFILE_VERDICT_RING - 1ULL)),
	       "verdict ring: a power of two from 4 KiB to 256 MiB");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, SE_PROFILE_VERDICT_RING);
} opaque_real_verdict_events SEC(".maps");
GADGET_TRACER(verdict, opaque_real_verdict_events, shared_verdict_event);
/* submitted, lost (failed reservations), observation errors */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_verdict_counters SEC(".maps");
/* Cells of opaque_real_verdict_counters (SharedVerdictSubmitted, ...). */
#define SE_VERDICT_SUBMITTED 0U
#define SE_VERDICT_LOST 1U
#define SE_VERDICT_OBSERVATION_ERRORS 2U
static __always_inline void se_verdict_count(__u32 key)
{
	__u64 *count = bpf_map_lookup_elem(&opaque_real_verdict_counters, &key);
	/* Atomic: a non-sleepable LSM program can still be preempted by
	 * another on the same CPU (preemptible RCU). */
	if (count)
		__sync_fetch_and_add(count, 1);
}
/* se_verdict_emit info word: class (bits 0-7), kind (bit 8), pass (bits
 * 16-23, 0xff unknown). */
#define SE_VERDICT_INFO(class, kind, pass)                 \
	(((__u32)(class) & 0xffU) | ((__u32)(kind) << 8) | \
	 (((__u32)(pass) & 0xffU) << 16))
#define SE_VERDICT_INFO_PASS_UNKNOWN 0xffU
/* The event metadata of the LSM call: ctx is the bprm_check_security LSM
 * context; generation, scope, exec_id and task_cookie come from the exec's
 * receipt when it is still this physical task's and bprm's, else 0. */
static __always_inline void se_verdict_meta_of(void *ctx, __u32 info,
					       struct se_verdict_meta *meta)
{
	/* The physical task and bprm of the LSM call (the receipt's key and
	 * identity); ctx, never caller scalars: both are kernel pointers. */
	__u64 physical = (__u64)bpf_get_current_task_btf();
	struct linux_binprm *bprm =
		(struct linux_binprm *)((unsigned long long *)ctx)[0];
	__u32 pass = (info >> 16) & 0xffU;
	*meta = (struct se_verdict_meta){
		.cgroup = bpf_get_current_cgroup_id(),
		.host_pid = bpf_get_current_pid_tgid() >> 32,
		.exec_class = info & 0xffU,
		.pass = pass == SE_VERDICT_INFO_PASS_UNKNOWN ?
				SE_VERDICT_PASS_UNKNOWN :
				pass,
		.kind = (info >> 8) & 1U,
	};
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (receipt && receipt->physical == physical &&
	    receipt->bprm == (__u64)bprm) {
		meta->generation = receipt->generation;
		meta->scope = receipt->scope;
		meta->exec_id = receipt->invocation;
		meta->task_cookie = receipt->cookie;
	}
}
/* The one immediate emitter (global: verified once, whatever its call
 * sites), for an event whose verdict is already final (a fault, or a
 * decision whose verdict is the class failure). It returns nothing the
 * caller may act on (always 0): a full or missing ring loses the event and
 * counts it, never the verdict (Strict never depends on delivery). facts and
 * decision may be null (a fault). Never called after a prior LSM denial. */
__attribute__((noinline)) int
se_verdict_emit(void *ctx __attribute__((btf_decl_tag("arg:ctx"))),
		const struct fe_facts *facts,
		const struct fe_decision *decision, __u32 info)
{
	struct se_verdict_meta meta;
	se_verdict_meta_of(ctx, info, &meta);
	struct shared_verdict_event *event = bpf_ringbuf_reserve(
		&opaque_real_verdict_events, sizeof(*event), 0);
	if (!event) {
		se_verdict_count(SE_VERDICT_LOST);
		return 0;
	}
	/* A decision event without its decision is submitted as a fault. */
	if (se_verdict_event_fill(event, facts, decision, &meta))
		se_verdict_count(SE_VERDICT_OBSERVATION_ERRORS);
	bpf_ringbuf_submit(event, 0);
	se_verdict_count(SE_VERDICT_SUBMITTED);
	return 0;
}
/* A decision event whose verdict is not final yet (a clean proposal: the
 * WORK suspension, its release and the TASK close can still fail and turn
 * it into the class failure). It is staged in the exec'ing task's own
 * storage (no other task can touch it, preempted or not) while the WORK is
 * held, and published only after the verdict is final; a superseded staged
 * event is never published (the failure path emits the pass's one fault
 * event instead). */
struct se_verdict_staged {
	__u64 bprm;
	__u32 armed, reserved;
	struct shared_verdict_event event;
};
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct se_verdict_staged);
} se_verdict_staging SEC(".maps");
/* 0 staged, -1 not (no storage: the event is lost and counted). */
__attribute__((noinline)) int
se_verdict_stage(void *ctx __attribute__((btf_decl_tag("arg:ctx"))),
		 const struct fe_facts *facts,
		 const struct fe_decision *decision, __u32 info)
{
	struct se_verdict_staged *staged = bpf_task_storage_get(
		&se_verdict_staging, bpf_get_current_task_btf(), 0,
		BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!staged) {
		se_verdict_count(SE_VERDICT_LOST);
		return -1;
	}
	staged->armed = 0;
	struct se_verdict_meta meta;
	se_verdict_meta_of(ctx, info, &meta);
	if (se_verdict_event_fill(&staged->event, facts, decision, &meta))
		se_verdict_count(SE_VERDICT_OBSERVATION_ERRORS);
	staged->bprm = ((unsigned long long *)ctx)[0];
	staged->armed = 1;
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_VERDICT_SUSPEND_FAULT_DIAGNOSTIC
/* Test-only: the harness writes N; each of the next N clean proposals takes
 * the failed-suspension path (the WORK is released, the class failure
 * follows). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_verdict_suspend_fault SEC(".maps");
static __attribute__((noinline)) int real_owner_verdict_suspend_fault(void)
{
	__u32 zero = 0;
	__u64 *armed =
		bpf_map_lookup_elem(&opaque_real_verdict_suspend_fault, &zero);
	if (!armed || !*armed)
		return 0;
	__sync_fetch_and_sub(armed, 1);
	return 1;
}
#define SE_VERDICT_SUSPEND_FAULT() real_owner_verdict_suspend_fault()
#endif
/* Publishes the staged event of this bprm exactly once (always 0). */
__attribute__((noinline)) int
se_verdict_publish(void *ctx __attribute__((btf_decl_tag("arg:ctx"))))
{
	struct se_verdict_staged *staged = bpf_task_storage_get(
		&se_verdict_staging, bpf_get_current_task_btf(), 0, 0);
	if (!staged || staged->armed != 1 ||
	    staged->bprm != ((unsigned long long *)ctx)[0]) {
		se_verdict_count(SE_VERDICT_LOST);
		return 0;
	}
	staged->armed = 0;
	if (bpf_ringbuf_output(&opaque_real_verdict_events, &staged->event,
			       sizeof(staged->event), 0)) {
		se_verdict_count(SE_VERDICT_LOST);
		return 0;
	}
	se_verdict_count(SE_VERDICT_SUBMITTED);
	return 0;
}
#endif
#ifndef SE_VERDICT_SUSPEND_FAULT
#define SE_VERDICT_SUSPEND_FAULT() 0
#endif
/* Resume/propose uses new lexical authority, never the suspended-read pointer.
 * Bit 1 means proposal and lexical cleanup succeeded; bit 0 is a policy deny.
 * A clean deny leaves the reader/receipt for the actual failure terminal. */
static __attribute__((noinline)) int
real_owner_policy_propose_finished(__u64 physical, __u64 bprm, __u32 mode
#ifdef SE_VERDICT_EVENTS
				   ,
				   void *ctx
#endif
)
{
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (!receipt || receipt->physical != physical ||
	    receipt->bprm != bprm || !receipt->cookie || !receipt->locator ||
	    !receipt->scope || receipt->phase != SE_EXEC_TERMINAL_REGISTERED ||
	    receipt->reserved)
		return 0;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&physical, &owner) != SE_OL_OK)
		return 0;
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	int result = 0;
#ifdef SE_VERDICT_EVENTS
	int staged = 0;
#endif
	if (owner.lease.cookie != receipt->cookie ||
	    owner.lease.locator != receipt->locator ||
	    se_owk_resume(&owner, REAL_OWNER_EVAL_RESUME, &ticket) != SE_OL_OK)
		goto close;
	if (se_owk_semantic_open(&owner, &ticket, &semantic, &work) !=
	    SE_OL_OK) {
		(void)se_owk_done(&owner, &ticket);
		goto close;
	}
#ifdef SE_VERDICT_EVENTS
	if (work->history.transaction.execution_class == mode) {
		int proposed = se_owk_exec_propose_reader(&semantic, receipt,
							  physical,
							  0) == SE_OL_OK;
		const struct fe_decision *decision =
			&work->observation.evaluator.decision;
		int error = decision->error != FE_OK &&
			    decision->error != FE_AUDIT_UNKNOWN;
		if (proposed && !error)
			result = 2 |
				 (fe_lsm_verdict(mode, 0, 0, decision) != 0);
		/* One terminal event per evaluated pass, carrying its final
		 * verdict (H2). A decision the evaluator finished with an
		 * UNKNOWN fact or a role conflict is final now (its verdict is
		 * the class failure below): emitted, and bit 2 tells that
		 * failure path the event of this pass is out. A clean proposal
		 * is staged here and published below only once suspension,
		 * release and close all succeeded; otherwise the failure path
		 * emits the pass's fault event. Pass p evaluates at stage
		 * 3p+2. */
		__u32 info = SE_VERDICT_INFO(mode, SE_VERDICT_DECISION,
					     ticket.continuation_stage / 3);
		if (result & 2)
			staged = se_verdict_stage(ctx, &work->observation.facts,
						  decision, info) == 0;
		else if (error && (decision->error == FE_UNKNOWN ||
				   decision->error == FE_ROLE_CONFLICT)) {
			(void)se_verdict_emit(ctx, &work->observation.facts,
					      decision, info);
			result |= 4;
		}
	}
#else
	if (work->history.transaction.execution_class == mode &&
	    se_owk_exec_propose_reader(&semantic, receipt, physical, 0) ==
		    SE_OL_OK) {
		const struct fe_decision *decision =
			&work->observation.evaluator.decision;
		int error = decision->error != FE_OK &&
			    decision->error != FE_AUDIT_UNKNOWN;
		if (!error)
			result = 2 |
				 (fe_lsm_verdict(mode, 0, 0, decision) != 0);
	}
#endif
	/* A clean proposal keeps this WORK for the exec terminal; a failed
	 * suspension faults the ticket and falls back to the class verdict. */
	if ((result & 2) &&
	    (SE_VERDICT_SUSPEND_FAULT() ||
	     se_owk_semantic_suspend(
		     &semantic, &work,
		     REAL_OWNER_NEXT_STAGE(
			     ticket, REAL_OWNER_TERMINAL_STAGE)) != SE_OL_OK))
		result &= 4;
	if (semantic.held && work &&
	    se_owk_semantic_done(&semantic, &work) != SE_OL_OK)
		result &= 4;
close:
	if (!(result & 2))
		(void)se_op_task_owned_fault(&owner, bprm);
	if (se_ol_payload_close(&owner) != SE_OL_OK) {
		(void)se_op_task_owned_fault(&owner, bprm);
		result &= 4;
	}
#ifdef SE_VERDICT_EVENTS
	/* The verdict is final: publish the staged clean decision. */
	if ((result & 2) && staged) {
		(void)se_verdict_publish(ctx);
		result |= 4;
	}
#endif
	return result;
}

/* Failure class comes from the statically reached program, not a relookup of
 * a possibly absent receipt or a newer mutable route. Cleanup remains exact
 * and best-effort; neither a failure nor an Audit allow grants any role. */
static __attribute__((always_inline)) inline long
real_owner_policy_failure(__u64 physical, __u64 bprm, __u32 mode)
{
	(void)real_owner_policy_finish_stage_one(physical, bprm);
	(void)real_owner_policy_abort_handoff(physical, bprm);
	return fe_lsm_verdict(mode, 0, 1, 0);
}
#ifdef SE_VERDICT_EVENTS
/* G020: the failure path with its fault event (D1: Strict deny=1 mode=2,
 * Audit deny=1 mode=1, error 1), unless the pass's decision event is
 * already out (emitted). The verdict is the static class's, computed first;
 * the event goes before the cleanup retires the receipt it reports. */
static __attribute__((always_inline)) inline long
real_owner_policy_failure_event(void *ctx, __u64 physical, __u64 bprm,
				__u32 mode, int emitted)
{
	long verdict = fe_lsm_verdict(mode, 0, 1, 0);
	if (!emitted)
		(void)se_verdict_emit(
			ctx, 0, 0,
			SE_VERDICT_INFO(mode, SE_VERDICT_FAULT,
					SE_VERDICT_INFO_PASS_UNKNOWN));
	(void)real_owner_policy_finish_stage_one(physical, bprm);
	(void)real_owner_policy_abort_handoff(physical, bprm);
	return verdict;
}
#define REAL_OWNER_POLICY_FAILURE(ctx, physical, bprm, mode) \
	real_owner_policy_failure_event(ctx, physical, bprm, mode, 0)
#else
#define REAL_OWNER_POLICY_FAILURE(ctx, physical, bprm, mode) \
	real_owner_policy_failure(physical, bprm, mode)
#endif

/* Global (independently verified once) failure path for the policy class
 * program. Inlined into the policy program it exceeded 1M processed
 * instructions on exact AL2023 6.18 (g005b-verdict-load-20261109). The
 * arguments are scalars; the class comes from the statically reached
 * program, never a relookup. */
__attribute__((noinline)) long real_owner_policy_failure_global(
	void *ctx __attribute__((btf_decl_tag("arg:ctx"))), __u32 mode)
{
	struct linux_binprm *bprm =
		(struct linux_binprm *)((unsigned long long *)ctx)[0];
	return REAL_OWNER_POLICY_FAILURE(ctx, (__u64)bpf_get_current_task_btf(),
					 (__u64)bprm, mode == 1 ? 1 : 2);
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE
/* G020 per-pass exec facts (design O3, full/shared_pass_facts.h): one global
 * frame, called from the prepare frame on every evaluated pass (first pass
 * and interpreter continuation), writes straight into the WORK's observation
 * facts, so the prepare stack grows by one small frame only. The product has
 * no memfd marker: shmem/hugetlb files stay MEMFD-unknown, every other file
 * MEMFD-known-false. */
#define FULL_FS_SHARED_MARK(inode) ((void)(inode))
#define FULL_FS_SHARED_READ(inode) 0
#include "filesystem.h"
#include "stdio.h"
/* Per-reason fact counters (SE_PF_*), RDONLY to userspace; pinned by the Go
 * product admission (shared_fact_stats.go) and reported as node health. */
#define REAL_OWNER_FACT_STATS 17
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 17);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_fact_stats SEC(".maps");
/* An out-of-range cell is no reason of the collector: never counted
 * (under another cell's name). */
static __always_inline void real_owner_fact_stat(__u32 cell)
{
	if (cell >= REAL_OWNER_FACT_STATS)
		return;
	__u64 *count = bpf_map_lookup_elem(&opaque_real_fact_stats, &cell);
	if (count)
		__sync_fetch_and_add(count, 1);
}
/* MNT_NS_INTERNAL (fs/mount.h): the mnt_ns of a kernel-internal mount
 * (kern_mount: shmem's memfd files, anon inodes). */
#define REAL_OWNER_MNT_NS_INTERNAL ((unsigned long)-22L)
struct real_owner_reach_walk {
	struct dentry *dentry, *root_dentry;
	struct mount *mnt;
	struct vfsmount *root_mnt;
	int result;
};
/* One step up from (dentry, mount) toward the current task's root: d_path's
 * own walk (prepend_path), which d_path does not report when it ends at a
 * namespace root instead of the task's root. Reads only; BPF runs under RCU,
 * which keeps dentries and mounts alive. Each d_parent read is bracketed by
 * the dentry's d_seq (M3: a rename in flight or between the two reads makes
 * the walk unknown, never a stale answer); the mount tree is bracketed by
 * the caller (mount namespace event). */
static long real_owner_reach_step(__u64 index, void *opaque)
{
	struct real_owner_reach_walk *w = opaque;
	(void)index;
	/* Plain locals: BPF_CORE_READ(w->x, ...) would relocate the walk
	 * record's own field access against vmlinux (poisoned by CO-RE). */
	struct dentry *dentry = w->dentry;
	struct mount *mnt = w->mnt;
	struct vfsmount *vfs =
		(void *)mnt + bpf_core_field_offset(struct mount, mnt);
	if (dentry == w->root_dentry && vfs == w->root_mnt) {
		w->result = 1;
		return 1;
	}
	struct dentry *mnt_root = BPF_CORE_READ(vfs, mnt_root);
	if (dentry == mnt_root) {
		struct mount *parent = BPF_CORE_READ(mnt, mnt_parent);
		if (!parent || parent == mnt) {
			/* A namespace root or a detached mount; a
			 * kernel-internal one (a memfd) is told apart. */
			unsigned long ns =
				(unsigned long)BPF_CORE_READ(mnt, mnt_ns);
			w->result = ns == REAL_OWNER_MNT_NS_INTERNAL ? 2 : 0;
			return 1;
		}
		w->dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
		w->mnt = parent;
		return 0;
	}
	unsigned int seq = 0, again = 1;
	if (BPF_CORE_READ_INTO(&seq, dentry, d_seq.seqcount.sequence) ||
	    (seq & 1)) {
		w->result = -1;
		return 1;
	}
	struct dentry *up = BPF_CORE_READ(dentry, d_parent);
	if (BPF_CORE_READ_INTO(&again, dentry, d_seq.seqcount.sequence) ||
	    again != seq) {
		w->result = -1;
		return 1;
	}
	if (!up || up == dentry) {
		w->result = 0; /* disconnected */
		return 1;
	}
	w->dentry = up;
	return 0;
}
/* The current mount namespace's event counter (bumped by every mount tree
 * change), 0 unreadable; 1 when the kernel has none (nothing to bracket). */
static __always_inline __u64 real_owner_mount_event(struct task_struct *task)
{
	__u64 event = 0;
	if (!bpf_core_field_exists(struct mnt_namespace, event))
		return 1;
	if (BPF_CORE_READ_INTO(&event, task, nsproxy, mnt_ns, event))
		return 0;
	return event + 1;
}
/* 1: file is reachable from the current task's root; 0: it is not (D5);
 * 2: on a kernel-internal mount (memfd); -1: unknown (unreadable, longer
 * than the walk, or the mount tree changed during the walk: M3). */
static __always_inline int real_owner_reachable(struct file *file)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct real_owner_reach_walk w = { .result = -1 };
	struct vfsmount *vfs = 0;
	__u64 before = real_owner_mount_event(task);
	if (!before ||
	    BPF_CORE_READ_INTO(&w.root_dentry, task, fs, root.dentry) ||
	    BPF_CORE_READ_INTO(&w.root_mnt, task, fs, root.mnt) ||
	    BPF_CORE_READ_INTO(&w.dentry, file, f_path.dentry) ||
	    BPF_CORE_READ_INTO(&vfs, file, f_path.mnt) || !w.root_dentry ||
	    !w.root_mnt || !w.dentry || !vfs)
		return -1;
	w.mnt = (void *)vfs - bpf_core_field_offset(struct mount, mnt);
	if (bpf_loop(256, real_owner_reach_step, &w, 0) < 0)
		return -1;
	if (real_owner_mount_event(task) != before)
		return -1;
	return w.result;
}
/* M2: 1 the file's dentry is unlinked (d_unlinked: unhashed, not a root),
 * 0 linked, -1 unreadable. */
static __always_inline int real_owner_unlinked(struct file *file)
{
	struct dentry *dentry = 0, *parent = 0;
	void *pprev = 0;
	if (BPF_CORE_READ_INTO(&dentry, file, f_path.dentry) || !dentry ||
	    BPF_CORE_READ_INTO(&parent, dentry, d_parent) ||
	    BPF_CORE_READ_INTO(&pprev, dentry, d_hash.pprev))
		return -1;
	return !pprev && parent != dentry;
}
/* 1 the task has a TASK (it is a task of the enforced workload), 0 not. */
static __always_inline int real_owner_member(struct task_struct *task)
{
	__u64 physical = (__u64)task;
	return bpf_map_lookup_elem(&se_opaque_keys, &physical) ? 1 : 0;
}
#define SE_PF_TYPES_ONLY 1
#include "shared_pass_facts.h"
#undef SE_PF_TYPES_ONLY
/* M1: UTF-8 validation of a path (shared_pass_facts.h se_pf_utf8_step),
 * one bpf_loop callback verified once. */
struct real_owner_utf8_walk {
	const __u8 *bytes;
	__u32 n, state;
	int bad;
};
static long real_owner_utf8_step(__u64 index, void *opaque)
{
	struct real_owner_utf8_walk *w = opaque;
	if (index >= w->n || index >= 255) {
		w->bad |= w->state != 0;
		return 1;
	}
	const __u8 *bytes = w->bytes;
	__u32 state = w->state;
	if (se_pf_utf8_step(&state, bytes[index & 0xff])) {
		w->bad = 1;
		return 1;
	}
	w->state = state;
	return 0;
}
static __always_inline int real_owner_utf8(const __u8 *bytes, __u32 n)
{
	struct real_owner_utf8_walk w = { bytes, n, 0, 0 };
	if (n > 255 || bpf_loop(n + 1, real_owner_utf8_step, &w, 0) < 0)
		return 0;
	return !w.bad;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
/* H1: the binding's root anchor, recorded by the adoption finish
 * (opaque_real_adopt_finish) from the adopted init before the route's
 * adopting word clears: no claim of the binding is evaluated earlier. scope
 * names the binding the record is for (written last, re-checked by the
 * reader). RDONLY to userspace. */
struct se_binding_root {
	__u64 scope, init_start, root_ino;
	__u32 init_tgid, mntns, root_mnt_id, root_dev;
};
_Static_assert(sizeof(struct se_binding_root) == 40, "binding root anchor");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_BINDINGS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_binding_root);
} se_binding_roots SEC(".maps");
#endif
/* A task's fs root and mount namespace identity (each read at its field's
 * exact width): 0, or -1 unreadable. */
static __always_inline int real_owner_task_root(struct task_struct *task,
						__u64 *ino, __u32 *mnt_id,
						__u32 *dev, __u32 *mntns)
{
	struct vfsmount *vfs = 0;
	struct dentry *dentry = 0;
	int id = 0;
	unsigned long i_ino = 0;
	__u32 s_dev = 0;
	unsigned int inum = 0;
	if (BPF_CORE_READ_INTO(&vfs, task, fs, root.mnt) ||
	    BPF_CORE_READ_INTO(&dentry, task, fs, root.dentry) || !vfs ||
	    !dentry)
		return -1;
	struct mount *mnt =
		(void *)vfs - bpf_core_field_offset(struct mount, mnt);
	if (BPF_CORE_READ_INTO(&id, mnt, mnt_id) ||
	    BPF_CORE_READ_INTO(&i_ino, dentry, d_inode, i_ino) ||
	    BPF_CORE_READ_INTO(&s_dev, dentry, d_sb, s_dev) ||
	    BPF_CORE_READ_INTO(&inum, task, nsproxy, mnt_ns, ns.inum) ||
	    !i_ino || !inum)
		return -1;
	*ino = i_ino;
	*mnt_id = (__u32)id;
	*dev = s_dev;
	*mntns = inum;
	return 0;
}
/* H1 bracket: the fs_struct sequence count of the current task (bumped
 * around every root/pwd change: set_fs_root/set_fs_pwd). 6.12 has
 * seqcount_spinlock_t seq (seq.seqcount.sequence), 6.18 seqlock_t seq
 * (seq.seqcount.seqcount.sequence); either is read through its own CO-RE
 * flavour. 1 (odd: never a stable value) when unreadable or neither shape. */
struct se_pf_seqcount___l {
	unsigned int sequence;
} __attribute__((preserve_access_index));
struct se_pf_seqcount_spin___l {
	struct se_pf_seqcount___l seqcount;
} __attribute__((preserve_access_index));
struct se_pf_seqlock___l {
	struct se_pf_seqcount_spin___l seqcount;
} __attribute__((preserve_access_index));
struct fs_struct___se_pf_seqcount {
	struct se_pf_seqcount_spin___l seq;
} __attribute__((preserve_access_index));
struct fs_struct___se_pf_seqlock {
	struct se_pf_seqlock___l seq;
} __attribute__((preserve_access_index));
static __always_inline __u32 real_owner_fs_seq(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	void *fs = 0;
	unsigned int seq = 1;
	if (BPF_CORE_READ_INTO(&fs, task, fs) || !fs)
		return 1;
	if (bpf_core_field_exists(((struct fs_struct___se_pf_seqlock *)0)
					  ->seq.seqcount.seqcount.sequence)) {
		if (BPF_CORE_READ_INTO(&seq,
				       (struct fs_struct___se_pf_seqlock *)fs,
				       seq.seqcount.seqcount.sequence))
			return 1;
	} else if (bpf_core_field_exists(
			   ((struct fs_struct___se_pf_seqcount *)0)
				   ->seq.seqcount.sequence)) {
		if (BPF_CORE_READ_INTO(&seq,
				       (struct fs_struct___se_pf_seqcount *)fs,
				       seq.seqcount.sequence))
			return 1;
	} else {
		return 1;
	}
	asm volatile("" ::: "memory");
	return seq;
}
#define SE_PF_FS_SEQ() real_owner_fs_seq()
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
/* H1: 1 the current task's root is the binding's anchored root (same mount
 * namespace, root mount and root inode), 0 not (a chroot, pivot_root or
 * setns since Bind), -1 no anchor or unreadable. */
static __always_inline int real_owner_rooted(const struct se_pf_anchor *a)
{
	__u64 ino = 0;
	__u32 mnt_id = 0, dev = 0, mntns = 0;
	if (!a->known || real_owner_task_root(bpf_get_current_task_btf(), &ino,
					      &mnt_id, &dev, &mntns))
		return -1;
	return ino == a->root_ino && mnt_id == a->root_mnt_id &&
	       dev == a->root_dev && mntns == a->mntns;
}
/* 1 the task is the binding's init (tgid and leader start ticks). */
static __always_inline int real_owner_binding_init(struct task_struct *task,
						   const struct se_pf_anchor *a)
{
	__u32 tgid = 0;
	__u64 start = 0;
	if (!a->known || BPF_CORE_READ_INTO(&tgid, task, tgid) ||
	    tgid != a->init_tgid ||
	    BPF_CORE_READ_INTO(&start, task, group_leader, start_boottime))
		return 0;
	return start / (1000000000ULL / 100) == a->init_start;
}
#define SE_PF_ROOTED(anchor) real_owner_rooted(anchor)
#define SE_PF_INIT(task, anchor) real_owner_binding_init(task, anchor)
#else
/* No adoption (no anchor) outside the product publisher: these test objects
 * keep the exec'ing task's own root; every product object carries the
 * publisher. */
#define SE_PF_ROOTED(anchor) ((void)(anchor), 1)
#define SE_PF_INIT(task, anchor) ((void)(task), (void)(anchor), 0)
#endif
#define SE_PF_STAT(cell) real_owner_fact_stat(cell)
#define SE_PF_FS(file) full_file_filesystem(file)
#define SE_PF_STDIN(task) full_stdin_pipe(task)
#define SE_PF_REACHABLE(file) real_owner_reachable(file)
#define SE_PF_UNLINKED(file) real_owner_unlinked(file)
#define SE_PF_MEMBER(task) real_owner_member(task)
#define SE_PF_UTF8(bytes, n) real_owner_utf8(bytes, n)
/* G020 image facts (full/shared_image_classify.h). The image handle and
 * overlay dev come from the metadata of the snapshot record the exec's
 * reader holds (real_owner_prepare_image): that claim references the sealed
 * descriptor, so its keys stay in se_image_keys through the last lookup.
 * Objects without the product image index leave the image facts UNKNOWN. */
struct real_owner_image_ctx {
	__u64 handle;
	__u32 dev, known;
};
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
#include "shared_image_kernel.h"
#include "shared_image_classify.h"
/* The classifier's witness (classifier reasons; the command side counts its
 * own slots, opaque_real_owner_product_image.h). */
#define REAL_OWNER_IMAGE_WITNESS_MAP 1
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_image_class_witness);
} se_image_witness SEC(".maps");
static __always_inline int
real_owner_image_class(struct file *file,
		       const struct real_owner_image_ctx *image)
{
	__u32 zero = 0;
	struct se_image_class_witness *w =
		bpf_map_lookup_elem(&se_image_witness, &zero);
	if (!image->known)
		return se_image_class_note(w, SE_IMAGE_CLASS_AUTH, -1);
	return se_image_classify(file, image->handle, image->dev, w);
}
/* Global (its own frame, after real_owner_pass_facts: the classifier's
 * locals never share a stack chain with the facts' root-walk callback): the
 * target's and the actor's image facts, 1 from the binding's image, 0 not,
 * -1 UNKNOWN. The facts collector already reset both to -1 this pass. */
__attribute__((noinline)) int
real_owner_pass_image(struct linux_binprm *bprm __arg_trusted,
		      struct fe_facts *facts, __u64 image_handle,
		      __u32 image_dev, __u32 image_known)
{
	if (!bprm || !facts)
		return -1;
	struct real_owner_image_ctx image = { image_handle, image_dev,
					      image_known };
	struct file *target = bprm->file;
	if (target)
		facts->target_image = real_owner_image_class(target, &image);
	struct file *actor = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (actor) {
		facts->actor_image = real_owner_image_class(actor, &image);
		bpf_put_file(actor);
	}
	return 0;
}
#endif
#include "shared_pass_facts.h"
_Static_assert(SE_PF_STATS == REAL_OWNER_FACT_STATS,
	       "opaque_real_fact_stats has one cell per SE_PF_* reason");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_WITNESS
/* Test-only per-pass witness ring (diagnostic twins; refused in a product
 * object above and by sharedProductForbiddenMaps): [0].seq is the head,
 * [1..16] the last 16 passes. */
struct real_owner_pass_witness {
	__u64 seq, tgid;
	__s32 result, target_image, actor_image, stdin_pipe;
	__u32 fs_mask, fs_known, ancestor_count, ancestors_complete;
	__u32 target_length, actor_length, ancestor0_length, reserved;
	__u8 target[256], actor[256], ancestor0[256];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 17);
	__type(key, __u32);
	__type(value, struct real_owner_pass_witness);
} opaque_real_fact_witness SEC(".maps");
static __attribute__((noinline)) void
real_owner_pass_witness(const struct fe_facts *facts, int result)
{
	__u32 zero = 0;
	struct real_owner_pass_witness *head =
		bpf_map_lookup_elem(&opaque_real_fact_witness, &zero);
	if (!head)
		return;
	__u64 seq = __sync_fetch_and_add(&head->seq, 1) + 1;
	__u32 key = 1 + ((seq - 1) & 15);
	struct real_owner_pass_witness *w =
		bpf_map_lookup_elem(&opaque_real_fact_witness, &key);
	if (!w)
		return;
	w->seq = seq;
	w->tgid = bpf_get_current_pid_tgid() >> 32;
	w->result = result;
	w->target_image = facts->target_image;
	w->actor_image = facts->actor_image;
	w->stdin_pipe = facts->stdin_pipe;
	w->fs_mask = facts->fs_mask;
	w->fs_known = facts->fs_known;
	w->ancestor_count = facts->ancestor_count;
	w->ancestors_complete = facts->ancestors_complete;
	w->target_length = facts->target_path.length;
	w->actor_length = facts->actor_path.length;
	w->ancestor0_length = facts->ancestors[0].length;
	__builtin_memcpy(w->target, facts->target_path.bytes, 256);
	__builtin_memcpy(w->actor, facts->actor_path.bytes, 256);
	__builtin_memcpy(w->ancestor0, facts->ancestors[0].bytes, 256);
}
#endif
/* Global (verified once, its own frame): the facts of one evaluated pass into
 * the WORK's observation facts. bprm is the bprm_check argument of the
 * calling prepare program (trusted: bprm->file is BTF_TYPE_SAFE_TRUSTED on
 * the matrix kernels, as bpf_path_d_path's KF_TRUSTED_ARGS requires). */
__attribute__((noinline)) int
real_owner_pass_facts(struct linux_binprm *bprm __arg_trusted,
		      struct fe_facts *facts, const struct se_pf_anchor *anchor)
{
	return se_pass_facts_collect(bprm, facts, anchor);
}
#endif

#if defined(ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE)
/* The image identity of the snapshot record this exec's reader holds: the
 * reader claim (re-authenticated from the live TASK, as the policy bridge
 * does) keeps that record ACTIVE or RETIRING, so its immutable metadata and
 * the sealed descriptor it references (shared_image_snapshot.h) stay valid
 * through the classifier's last lookup. A revision between two passes of one
 * exec therefore never changes the handle a pass classifies against. Any
 * mismatch leaves image->known 0 (image facts UNKNOWN). */
static __attribute__((noinline)) void
real_owner_prepare_image(struct se_ol_payload_handle *owner,
			 const struct se_exec_terminal_receipt *receipt,
			 struct real_owner_image_ctx *image,
			 struct se_pf_anchor *anchor)
{
	struct real_owner_policy_auth auth = {};
	if (!real_owner_policy_authenticate(owner, receipt, receipt->bprm,
					    &auth) ||
	    auth.slot >= SE_OC_ACCOUNTS || auth.record >= 2 || !auth.serial)
		return;
	/* Scalar-bounded record index (old verifier state joins). */
	volatile __u64 bounded_record = auth.record;
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &auth.slot);
	if (!binding)
		return;
	const struct se_snapshot *snapshot =
		&binding->state.records[bounded_record & 1ULL];
	__u32 phase = snapshot->phase;
	if (snapshot->serial != auth.serial ||
	    snapshot->scope != receipt->scope ||
	    snapshot->generation != receipt->generation ||
	    (phase != SE_SNAPSHOT_ACTIVE && phase != SE_SNAPSHOT_RETIRING))
		return;
	image->handle = snapshot->metadata.image_handle;
	image->dev = snapshot->metadata.image_dev;
	/* The claim keeps the record ACTIVE or RETIRING; re-checked after
	 * the copy anyway (a record that moved on is no identity). */
	asm volatile("" ::: "memory");
	phase = snapshot->phase;
	image->known =
		snapshot->serial == auth.serial &&
		(phase == SE_SNAPSHOT_ACTIVE || phase == SE_SNAPSHOT_RETIRING);
	/* H1: the binding's root anchor, only when recorded for this exact
	 * binding scope (re-checked after the copy: a recycle in between
	 * leaves it unknown). */
	const struct se_binding_root *root =
		bpf_map_lookup_elem(&se_binding_roots, &auth.slot);
	if (!root || !root->scope || root->scope != receipt->scope)
		return;
	*anchor = (struct se_pf_anchor){
		.root_ino = root->root_ino,
		.init_start = root->init_start,
		.root_mnt_id = root->root_mnt_id,
		.root_dev = root->root_dev,
		.mntns = root->mntns,
		.init_tgid = root->init_tgid,
	};
	asm volatile("" ::: "memory");
	anchor->known = root->scope == receipt->scope && anchor->root_ino &&
			anchor->mntns;
}
#endif

/* Prepare program body: reopen the exact receipt TASK, resume the stage-1
 * WORK, snapshot history/catalogue/roles, suspend to the evaluation stage.
 * Returns 1 only when the WORK is suspended at REAL_OWNER_EVAL_STAGE. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE
static __attribute__((noinline)) int
real_owner_prepare_frame(__u64 physical, struct linux_binprm *bprm)
#else
static __attribute__((noinline)) int real_owner_prepare_frame(__u64 physical)
#endif
{
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (!receipt || receipt->physical != physical || !receipt->cookie ||
	    !receipt->locator || !receipt->scope || !receipt->invocation ||
	    receipt->phase != SE_EXEC_TERMINAL_REGISTERED || receipt->reserved)
		return 0;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&physical, &owner) != SE_OL_OK)
		return 0;
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	int result = 0;
	if (owner.lease.cookie != receipt->cookie ||
	    owner.lease.locator != receipt->locator ||
	    se_owk_resume(&owner, REAL_OWNER_PREPARE_RESUME, &ticket) !=
		    SE_OL_OK)
		goto close;
	if (se_owk_semantic_open(&owner, &ticket, &semantic, &work) !=
	    SE_OL_OK) {
		(void)se_owk_done(&owner, &ticket);
		goto close;
	}
	/* UNKNOWN until the per-pass facts below collect them (the image
	 * facts in real_owner_pass_image, after real_owner_pass_facts). */
	work->observation.facts.actor_image = -1;
	work->observation.facts.target_image = -1;
	work->observation.facts.stdin_pipe = -1;
#if defined(ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE)
	struct real_owner_image_ctx image = {};
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE
	/* H1: no anchor (known 0) unless the binding recorded one. */
	struct se_pf_anchor anchor = {};
#endif
	if (real_owner_prepare_reader_frame(&semantic, receipt, physical) ==
		    SE_OL_OK &&
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	    (real_owner_prepare_image(&owner, receipt, &image, &anchor), 1) &&
#endif
	    real_owner_pass_facts(bprm, &work->observation.facts, &anchor) >=
		    0 &&
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	    real_owner_pass_image(bprm, &work->observation.facts, image.handle,
				  image.dev, image.known) >= 0 &&
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_WITNESS
	    (real_owner_pass_witness(&work->observation.facts, 0), 1) &&
#endif
#endif
	    se_owk_semantic_suspend(
		    &semantic, &work,
		    REAL_OWNER_NEXT_STAGE(ticket, REAL_OWNER_EVAL_STAGE)) ==
		    SE_OL_OK)
		result = 1;
	else if (semantic.held && work)
		(void)se_owk_semantic_done(&semantic, &work);
close:
	if (se_ol_payload_close(&owner) != SE_OL_OK) {
		(void)se_op_task_owned_fault(&owner, receipt->bprm);
		result = 0;
	}
	return result;
}

static __attribute__((always_inline)) inline long
real_owner_prepare_class(unsigned long long *ctx, struct linux_binprm *bprm,
			 __u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_CANDIDATE
	if (real_owner_prepare_frame((__u64)bpf_get_current_task_btf(), bprm) ==
	    1) {
#else
	if (real_owner_prepare_frame((__u64)bpf_get_current_task_btf()) == 1) {
#endif
		if (mode == 1)
			bpf_tail_call(ctx, &opaque_real_stage_audit, 0);
		else
			bpf_tail_call(ctx, &opaque_real_stage_strict, 0);
		SE_GRAPH_MISS();
	}
	(void)bprm;
	if (real_owner_policy_failure_global(ctx, mode)) {
		asm volatile("" ::: "memory");
		return -1L;
	}
	return 0;
}

static __attribute__((always_inline)) inline long
real_owner_policy_class(unsigned long long *ctx, struct linux_binprm *bprm,
			__u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
	if (real_owner_policy_target_core(bprm)) {
		if (mode == 1)
			bpf_tail_call(ctx, &opaque_real_prepare_audit, 0);
		else
			bpf_tail_call(ctx, &opaque_real_prepare_strict, 0);
		SE_GRAPH_MISS();
	}
	/* A global function's result is an unknown scalar to the caller; map it
	 * to the two explicit signed-64 LSM verdicts (dead end #25). */
	if (real_owner_policy_failure_global(ctx, mode)) {
		asm volatile("" ::: "memory");
		return -1L;
	}
	return 0;
}

static __attribute__((always_inline)) inline long
real_owner_stage_class(unsigned long long *ctx, struct linux_binprm *bprm,
		       __u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
	__u64 physical = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	if (receipt && receipt->physical == physical &&
	    receipt->bprm == (__u64)bprm && receipt->cookie &&
	    receipt->locator && receipt->scope && receipt->invocation &&
	    receipt->phase == SE_EXEC_TERMINAL_REGISTERED &&
	    !receipt->reserved) {
		__u64 scope = receipt->scope;
		struct se_owk_payload *payload = se_owk_suspended_current(
			scope, REAL_OWNER_EVAL_RESUME, 1);
		if (payload) {
			int begun = real_owner_policy_stage_begin(payload);
			real_owner_rule_progress(0, begun);
			payload = 0;
			if (begun == 1) {
				if (mode == 1)
					bpf_tail_call(ctx,
						      &opaque_real_rule_audit,
						      0);
				else
					bpf_tail_call(ctx,
						      &opaque_real_rule_strict,
						      0);
				SE_GRAPH_MISS();
			}
			(void)se_owk_suspended_current(
				scope, REAL_OWNER_EVAL_RESUME, 2);
		}
	}
	return REAL_OWNER_POLICY_FAILURE(ctx, physical, (__u64)bprm, mode);
}

static __attribute__((always_inline)) inline long
real_owner_rule_class(unsigned long long *ctx, struct linux_binprm *bprm,
		      __u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
	__u64 physical = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &physical);
	int evaluated = 0;
	__u64 held = 0;
	if (receipt && receipt->physical == physical &&
	    receipt->bprm == (__u64)bprm && receipt->cookie &&
	    receipt->locator && receipt->scope && receipt->invocation &&
	    receipt->phase == SE_EXEC_TERMINAL_REGISTERED &&
	    !receipt->reserved) {
		__u64 scope = receipt->scope;
		evaluated = real_owner_policy_rule_claimed_eval(scope);
		if (evaluated == 2)
			held = scope;
		real_owner_rule_progress(1, evaluated);
		/* Keep the nonfinal reservation across window re-entry: the next
		 * window re-reads it with operation 3. Release only at the end. */
		if (evaluated != 2 &&
		    !se_owk_suspended_current(scope, REAL_OWNER_EVAL_RESUME, 2))
			evaluated = 0;
	}
	if (evaluated == 2) {
		/* Still reserved; the next window re-derives every TASK/charge/WORK
		 * fact through operation 3 before reading the cursor. */
		{
			__u32 zero = 0;
			__u64 *windows = bpf_map_lookup_elem(
				&opaque_real_owner_rule_windows, &zero);
			if (windows)
				__sync_fetch_and_add(windows, 1);
		}
		if (mode == 1)
			bpf_tail_call(ctx, &opaque_real_rule_audit, 0);
		else
			bpf_tail_call(ctx, &opaque_real_rule_strict, 0);
	} else {
		/* Proposal or exact failure cleanup runs on a fresh stack: with the
		 * evaluation window in this frame, propose/cleanup chains exceeded
		 * the 512-byte combined stack on exact AL2023 6.12. */
		if (mode == 1)
			bpf_tail_call(ctx, &opaque_real_finish_audit, 0);
		else
			bpf_tail_call(ctx, &opaque_real_finish_strict, 0);
	}
	SE_GRAPH_MISS();
	/* A missing frozen graph entry (or exhausted tail-call budget) is a
	 * configuration invariant breach. Return the static class verdict;
	 * Strict never allows here. A reservation kept for window re-entry is
	 * released first: se_owk_finish_suspended_death (task_free) and the reap
	 * paths require continuation_reserved clear. The WORK then stays
	 * suspended until task death and the pending receipt quarantines this
	 * task's next admission meanwhile. */
	if (held)
		(void)se_owk_suspended_current(held, REAL_OWNER_EVAL_RESUME, 2);
	(void)physical;
#ifdef SE_VERDICT_EVENTS
	/* The pass's one fault event (D1): the finish program, the only
	 * decision emitter, never ran for it. Last, with nothing live after
	 * it (the rule frame is at the 512-byte combined stack limit). */
	(void)se_verdict_emit(ctx, 0, 0,
			      SE_VERDICT_INFO(mode, SE_VERDICT_FAULT,
					      SE_VERDICT_INFO_PASS_UNKNOWN));
#endif
	if (mode == 2) {
		asm volatile("" ::: "memory");
		return -1L;
	}
	return 0;
}

/* Finish program: propose the completed evaluation, or perform the exact
 * failure cleanup and class verdict. propose_finished refuses anything that
 * did not reach a clean FINISHED decision. */
static __attribute__((always_inline)) inline long
real_owner_finish_class(unsigned long long *ctx, struct linux_binprm *bprm,
			__u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
	__u64 physical = (__u64)bpf_get_current_task_btf();
#ifdef SE_VERDICT_EVENTS
	int result = real_owner_policy_propose_finished(physical, (__u64)bprm,
							mode, ctx);
#else
	int result =
		real_owner_policy_propose_finished(physical, (__u64)bprm, mode);
#endif
	if (result & 2) {
		if (result & 1) {
			asm volatile("" ::: "memory");
			return -1L;
		}
		return 0;
	}
#ifdef SE_VERDICT_EVENTS
	return real_owner_policy_failure_event(ctx, physical, (__u64)bprm, mode,
					       result & 4);
#else
	return real_owner_policy_failure(physical, (__u64)bprm, mode);
#endif
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
/* G019 gap 4 (review H1): the same-bprm script-interpreter continuation.
 * A #! script (or binfmt_misc) exec runs one bprm_check per
 * search_binary_handler pass with the same bprm; pass 0 registered the
 * receipt and left its proposed evaluation WORK at its terminal stage. A
 * later pass p (1..5) is admitted on the capsule's frozen ORIGINAL route
 * and class (SE_CAP_LATER), then authenticated here before it evaluates its
 * own bprm->file through the unchanged prepare/stage/rule/finish graph:
 *  (a) the outer failure frame is still the single certain frame bound by
 *      pass 0 to exactly this receipt, and this pass's handler frame is
 *      for the same bprm;
 *  (b) the original reader classifies CONTINUE (the current-WORK premise
 *      relaxed only for CONTINUE; (d) proves which WORK it is);
 *  (c) reader recovery returns exactly the receipt's invocation (read
 *      only: never a second reader begin) and the reader still pins the
 *      same snapshot;
 *  (d) the current WORK resumes at a terminal-class stage 3p with p <= 5,
 *      and is the receipt's proposed WORK of the static class.
 * The WORK is then reset to exactly a fresh bridge's state (payload past
 * the view zeroed, view re-prepared from the pinned snapshot, evaluator
 * token re-issued) and suspended to 3p+1 for the prepare program, which
 * snapshots the TASK's accumulated exec transaction anew. No pass charges
 * a WORK credit; every proposal accumulates into the one transaction the
 * terminal commits once. Any refusal is a GAP [9] with its reason in
 * opaque_real_interp_stats, then the static class failure: Strict denies,
 * Audit allows; the reader is aborted quarantined and the TASK
 * quarantined. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_INTERP_STATS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_interp_stats SEC(".maps");
static __attribute__((noinline)) void real_owner_interp_stat(__u32 index)
{
	__u32 key = index < SE_INTERP_STATS ? index : SE_INTERP_STAT_REBIND;
	__u64 *count = bpf_map_lookup_elem(&opaque_real_interp_stats, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
}
/* reason < SE_INTERP_STATS: a GAP [9] continuation refusal with its reason;
 * SE_INTERP_STATS: a pass refused before any continuation (its rate class
 * already counted by the caller), with the same verdict and cleanup. */
static __attribute__((always_inline)) inline long
real_owner_continue_refuse(unsigned long long *ctx, __u32 reason, __u32 mode)
{
	if (reason < SE_INTERP_STATS) {
		real_owner_interp_stat(reason);
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_GAP);
	}
	long verdict = real_owner_policy_failure_global(ctx, mode);
	(void)real_owner_reader_quarantine_pending(
		(__u64)bpf_get_current_task_btf());
	if (mode != 1 || verdict) {
		asm volatile("" ::: "memory");
		return -1L;
	}
	return 0;
}
/* (a): the failure frames, in their own frame. */
static __attribute__((noinline)) int
real_owner_interp_frames(const struct se_exec_terminal_receipt *receipt,
			 __u64 key, __u64 bprm)
{
	const struct se_failure_outer_frame *outer =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	const struct se_failure_handler_frame *handler =
		bpf_map_lookup_elem(&se_failure_handler_frames, &key);
	return receipt->phase == SE_EXEC_TERMINAL_REGISTERED &&
	       !receipt->reserved &&
	       SE_EXEC_CONTINUE_FRAMES_EXACT(receipt, outer, handler, key,
					     bprm);
}
/* (b), (c): 0, or the refusal reason. */
static __attribute__((noinline)) int
real_owner_interp_reader(struct se_ol_payload_handle *owner,
			 const struct se_exec_terminal_receipt *receipt,
			 __u64 bprm, struct real_owner_policy_auth *auth)
{
	if (!real_owner_policy_authenticate(owner, receipt, bprm, auth) ||
	    auth->slot >= SE_OC_ACCOUNTS || auth->record >= 2 || !auth->serial)
		return SE_INTERP_STAT_CLASSIFY;
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &auth->slot);
	if (!binding || se_op_exec_reader_classify_continue(
				owner, &binding->state, receipt, key, bprm) !=
				SE_EXEC_READER_CONTINUE)
		return SE_INTERP_STAT_CLASSIFY;
	__u64 recovered = 0;
	if (se_op_exec_reader_recover(owner, &binding->state, bprm,
				      &recovered) != SE_OL_OK ||
	    recovered != receipt->invocation)
		return SE_INTERP_STAT_RECOVER;
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_STALE_RESUME_DIAGNOSTIC
/* Test-only: the harness writes N; each of the next N continuations
 * resumes with the prepare class instead of the terminal class. That is a
 * non-mutating STALE replay in se_owk_resume, refused as RESUME; the WORK
 * stays at its terminal stage for the refusal's cleanup cascade. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_interp_stale_resume SEC(".maps");
static __attribute__((noinline)) int real_owner_interp_stale_armed(void)
{
	__u32 zero = 0;
	__u64 *armed =
		bpf_map_lookup_elem(&opaque_real_interp_stale_resume, &zero);
	if (!armed || !*armed)
		return 0;
	__sync_fetch_and_sub(armed, 1);
	return 1;
}
#endif
/* (d) and the rebind: 0 with the WORK suspended at 3p+1, or the reason
 * with the WORK consumed (DONE) or never resumed. */
static __attribute__((noinline)) int
real_owner_interp_rebind(struct se_ol_payload_handle *owner,
			 const struct se_exec_terminal_receipt *receipt,
			 const struct se_snapshot *snapshot, __u32 mode)
{
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	__u32 resume = REAL_OWNER_TERMINAL_RESUME;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_STALE_RESUME_DIAGNOSTIC
	if (real_owner_interp_stale_armed())
		resume = REAL_OWNER_PREPARE_RESUME;
#endif
	if (se_owk_resume(owner, resume, &ticket) != SE_OL_OK)
		return SE_INTERP_STAT_RESUME;
	__u32 pass = se_exec_continue_pass(ticket.continuation_stage,
					   SE_OWK_EXEC_PASSES);
	int reason = SE_INTERP_STAT_DEPTH;
	if (!pass)
		goto done_ticket;
	reason = SE_INTERP_STAT_RESUME;
	if (se_owk_semantic_open(owner, &ticket, &semantic, &work) != SE_OL_OK)
		goto done_ticket;
	if (!se_exec_continue_work_exact(work, receipt, mode))
		goto done_semantic;
	reason = SE_INTERP_STAT_REBIND;
	__u32 zero = 0;
	const struct se_owk_payload *empty =
		bpf_map_lookup_elem(&se_opaque_work_zero, &zero);
	if (!empty || bpf_probe_read_kernel(
			      &semantic.payload->semantic.history,
			      sizeof(struct se_owk_payload) -
				      __builtin_offsetof(struct se_owk_payload,
							 semantic.history),
			      &empty->semantic.history))
		goto done_semantic;
	if (real_owner_policy_prepare(work, receipt->scope, receipt->generation,
				      snapshot))
		goto done_semantic;
	struct fm_global_token *token =
		&work->observation.stage_workspace.token;
	if (se_owk_evaluator_token(&semantic, token) != SE_OL_OK ||
	    se_owk_view_from_identity(token->slot, token->cookie) !=
		    &work->view)
		goto done_semantic;
	if (se_owk_semantic_suspend(&semantic, &work,
				    ticket.continuation_stage + 1U) != SE_OL_OK)
		goto done_semantic;
	real_owner_interp_stat(SE_INTERP_STAT_CONTINUED_FIRST + pass - 1);
	return 0;
done_semantic:
	if (semantic.held && work)
		(void)se_owk_semantic_done(&semantic, &work);
	return reason;
done_ticket:
	(void)se_owk_done(owner, &ticket);
	return reason;
}
/* 0 with the WORK suspended at 3p+1 and the TASK lease closed, or the
 * refusal reason. */
static __attribute__((noinline)) int
real_owner_interp_continue_core(struct linux_binprm *bprm, __u32 mode)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	if (!receipt || !real_owner_interp_frames(receipt, key, (__u64)bprm))
		return SE_INTERP_STAT_FRAME;
	struct se_ol_payload_handle owner = {};
	if (real_owner_child_open_parent(&owner) != SE_OL_OK)
		return SE_INTERP_STAT_CLASSIFY;
	struct real_owner_policy_auth auth = {};
	int reason =
		real_owner_interp_reader(&owner, receipt, (__u64)bprm, &auth);
	if (!reason) {
		/* Scalar-bounded record index (Rocky 4.18 state joins). */
		volatile __u64 bounded_record = auth.record;
		struct se_shared_binding *binding =
			auth.slot < SE_OC_ACCOUNTS ?
				bpf_map_lookup_elem(&se_bindings, &auth.slot) :
				0;
		const struct se_snapshot *snapshot =
			binding ?
				&binding->state.records[bounded_record & 1ULL] :
				0;
		if (!snapshot || snapshot->serial != auth.serial ||
		    snapshot->scope != receipt->scope ||
		    snapshot->generation != receipt->generation)
			reason = SE_INTERP_STAT_RECOVER;
		else
			reason = real_owner_interp_rebind(&owner, receipt,
							  snapshot, mode);
	}
	if (se_ol_payload_close(&owner) != SE_OL_OK) {
		/* Consumes a WORK already suspended at 3p+1 (prepare class). */
		real_owner_policy_close_fault(&owner, (__u64)bprm, !reason);
		if (!reason)
			reason = SE_INTERP_STAT_REBIND;
	}
	return reason;
}
static __attribute__((always_inline)) inline long
real_owner_continue_class(unsigned long long *ctx, struct linux_binprm *bprm,
			  __u32 mode)
{
	__s64 prior = (__s64)ctx[1];
	if (prior)
		return prior;
	__u32 reason = real_owner_interp_continue_core(bprm, mode);
	if (!reason) {
		if (mode == 1)
			bpf_tail_call(ctx, &opaque_real_prepare_audit, 0);
		else
			bpf_tail_call(ctx, &opaque_real_prepare_strict, 0);
		reason = SE_INTERP_STAT_GRAPH_MISS;
	}
	return real_owner_continue_refuse(ctx, reason, mode);
}
#endif
#define REAL_OWNER_CLASS_PROGRAM(name, body, mode)                \
	SEC("lsm/bprm_check_security")                            \
	long BPF_PROG(name, struct linux_binprm *bprm, int prior) \
	{                                                         \
		(void)prior;                                      \
		return body(ctx, bprm, mode);                     \
	}
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_policy_audit,
			 real_owner_policy_class, 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_policy_strict,
			 real_owner_policy_class, 2)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_prepare_audit,
			 real_owner_prepare_class, 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_prepare_strict,
			 real_owner_prepare_class, 2)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_stage_audit, real_owner_stage_class,
			 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_stage_strict, real_owner_stage_class,
			 2)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_rule_audit, real_owner_rule_class, 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_rule_strict, real_owner_rule_class,
			 2)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_finish_audit,
			 real_owner_finish_class, 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_finish_strict,
			 real_owner_finish_class, 2)
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_continue_audit,
			 real_owner_continue_class, 1)
REAL_OWNER_CLASS_PROGRAM(opaque_real_owner_continue_strict,
			 real_owner_continue_class, 2)
#endif
#undef REAL_OWNER_CLASS_PROGRAM
#endif

#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
/* This diagnostic always quarantines afterward: it has no evaluator,
 * verdict, event or role proposal. The small wrapper keeps the abort frame
 * disjoint from the policy frame on older verifier stack accounting. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_real_owner_policy_target_candidate,
	     struct linux_binprm *bprm, int prior)
{
	if (prior)
		return prior;
	int suspended = real_owner_policy_target_core(bprm);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_STAGE_BEGIN_DIAGNOSTIC
	if (suspended) {
		bpf_tail_call(ctx, &opaque_real_owner_policy_stage_targets, 0);
		(void)real_owner_policy_finish_stage_one(
			(__u64)bpf_get_current_task_btf(), (__u64)bprm);
	}
#else
	(void)suspended;
#endif
	(void)real_owner_policy_abort_handoff((__u64)bpf_get_current_task_btf(),
					      (__u64)bprm);
	return 0; /* Audit-only diagnostic; never grants a policy decision. */
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC
/* Leave the exact source-issued reader/receipt to the real terminal producer.
 * This target is test-only and has no evaluator, verdict or role proposal. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_real_owner_terminal_retain_target,
	     struct linux_binprm *bprm, int prior)
{
	(void)bprm;
	return prior;
}
#endif
#endif
/* Never selected by the product. This diagnostic exercises the exact TASK,
 * original route, snapshot and reader handoff in one verifier-visible LSM
 * callback. It immediately finishes as a failed exec: no policy evaluation,
 * role grant, event, or native Ready claim follows from this probe. */
/* The source's owner/reader frame must return before the tail-call fallback
 * reopens the TASK. Otherwise both stack frames are charged simultaneously. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
/* Begin/recover and terminal registration are separate lexical frames: the
 * old verifier charges every live BPF call stack, not just C local bytes. */
static __attribute__((noinline)) int
real_owner_reader_open_exact(struct se_ol_payload_handle *owner,
			     struct se_route_claim *claim,
			     struct linux_binprm *bprm, __u64 *invocation_out)
{
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &claim->slot);
	*invocation_out = 0;
	int good = binding &&
		   se_op_exec_reader_begin(owner, claim, &binding->state,
					   (__u64)bprm,
					   invocation_out) == SE_OL_OK;
	if (good) {
		__u64 recovered = 0;
		good = se_op_exec_reader_recover(owner, &binding->state,
						 (__u64)bprm,
						 &recovered) == SE_OL_OK &&
		       recovered == *invocation_out;
	}
	return good;
}

/* Bit 0 reports a clean lexical close; bit 1 reports an exact retained
 * reader (Audit only in the original diagnostic). The route claim and TASK
 * lease remain caller-owned. */
static __attribute__((noinline)) int real_owner_reader_finish_exact(
	struct se_ol_payload_handle *owner, struct se_route_claim *claim,
	struct linux_binprm *bprm, __u64 invocation, int good)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &claim->slot);
	if (!binding)
		good = 0;
	if (good &&
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	    (claim->execution_class == 1 || claim->execution_class == 2) &&
#else
	    claim->execution_class == 1 &&
#endif
	    !real_owner_failure_frame_ready(key, (__u64)bprm)) {
		SE_DEFERRED_STORAGE_REFUSED(4);
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_STORAGE);
		(void)se_op_exec_reader_abort_quarantined(
			owner, &binding->state, (__u64)bprm, invocation);
		invocation = 0;
		good = 0;
	}
	int retained =
		good &&
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
		(claim->execution_class == 1 || claim->execution_class == 2);
#else
		claim->execution_class == 1;
#endif
	if (retained && !real_owner_policy_register_receipt(
				owner, claim, (__u64)bprm, invocation)) {
		(void)se_op_exec_reader_abort_quarantined(
			owner, &binding->state, (__u64)bprm, invocation);
		retained = 0;
		invocation = 0;
		good = 0;
	}
	if (binding && invocation && !retained)
		good = se_op_exec_reader_finish_bounded(owner, &binding->state,
							(__u64)bprm, invocation,
							0) == SE_OL_OK &&
		       good;
	if (se_ol_payload_close(owner) != SE_OL_OK)
		good = 0;
	return (good ? 1 : 0) | (retained ? 2 : 0);
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC
static __attribute__((noinline)) int
real_owner_continue_frames(const struct se_exec_terminal_receipt *receipt,
			   __u64 key, __u64 bprm)
{
	const struct se_failure_outer_frame *outer =
		bpf_map_lookup_elem(&se_failure_outer_frames, &key);
	const struct se_failure_handler_frame *handler =
		bpf_map_lookup_elem(&se_failure_handler_frames, &key);
	return outer && handler && outer->physical == key &&
	       outer->depth == 1 && !outer->uncertain && outer->bprm == bprm &&
	       outer->bprm == receipt->bprm &&
	       outer->cookie == receipt->cookie &&
	       outer->locator == receipt->locator &&
	       outer->invocation == receipt->invocation &&
	       outer->scope == receipt->scope &&
	       outer->generation == receipt->generation &&
	       handler->bprm == bprm && handler->depth == 1 &&
	       !handler->uncertain;
}

/* 0: absent/terminal, 1: recovered Audit, 2: strict fault, 3: Audit
 * fault, 4: unknown disposition. REGISTERED never reaches a fresh begin. */
static __attribute__((noinline)) int
real_owner_continue_reader(struct linux_binprm *bprm, int prior_denied)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	if (!receipt || receipt->phase != SE_EXEC_TERMINAL_REGISTERED)
		return 0;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&key, &owner) != SE_OL_OK)
		return 4;
	__u32 slot = SE_OC_ACCOUNTS, mode = 0;
	__u64 record = 0, serial = 0;
	struct se_task_state *task = 0;
	if (se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		if (task->physical_cookie == owner.lease.cookie) {
			slot = task->scope_slot;
			mode = task->exec.execution_class;
			record = task->reader.token.record;
			serial = task->reader.token.serial;
		}
		se_op_task_semantic_end(&owner, &task);
	}
	struct se_shared_binding *binding =
		slot < SE_OC_ACCOUNTS ?
			bpf_map_lookup_elem(&se_bindings, &slot) :
			0;
	__u64 invocation = 0;
	int valid = binding &&
		    se_op_exec_reader_classify(&owner, &binding->state, receipt,
					       key, (__u64)bprm) ==
			    SE_EXEC_READER_CONTINUE &&
		    real_owner_continue_frames(receipt, key, (__u64)bprm) &&
		    se_op_exec_reader_recover(&owner, &binding->state,
					      (__u64)bprm,
					      &invocation) == SE_OL_OK &&
		    invocation == receipt->invocation;
	if (valid && prior_denied)
		valid = se_op_task_note_prior_deny(&owner, (__u64)bprm) ==
			SE_OL_OK;
	if (valid && !prior_denied && mode == 1)
		real_owner_continue_observe(receipt, (__u64)bprm, 1, record,
					    serial);
	if (se_ol_payload_close(&owner) != SE_OL_OK)
		valid = 0;
	if (mode == 2)
		return 2; /* This diagnostic never grants a strict verdict. */
	return mode == 1 ? (valid ? 1 : 3) : 4;
}
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE
/* Source-only physical-exec capsule (full/shared_exec_capsule.h, G005-A).
 * G019 M4 (user decision (ii)): capsule and marker live in BPF task local
 * storage on the executing task (no pid_max-sized ARRAY, no loader sizing),
 * created only for an exec that can matter; maps are private. The tgid/pid
 * adapter arguments are unused: the storage key is the current task. */
struct se_exec_capsule;
struct se_exec_marker;
static __always_inline struct se_exec_capsule *real_owner_capsule(__u64 flags);
static __always_inline struct se_exec_marker *real_owner_marker(__u64 flags);
static __always_inline int real_owner_capsule_matters(void);
static __always_inline __u64 real_owner_capsule_sequence(void);
static __always_inline void real_owner_capsule_stat(__u32 index);
#define SE_CAP_ABSENT_OK 1
#define SE_CAP_LOOKUP(tgid) ((void)(tgid), real_owner_capsule(0))
#define SE_CAP_CREATE(tgid) \
	((void)(tgid), real_owner_capsule(BPF_LOCAL_STORAGE_GET_F_CREATE))
#define SE_CAP_MARKER_LOOKUP(pid) ((void)(pid), real_owner_marker(0))
#define SE_CAP_MARKER_CREATE(pid) \
	((void)(pid), real_owner_marker(BPF_LOCAL_STORAGE_GET_F_CREATE))
/* Test-only (G019 M4 review M2 attached test): no exec matters at entry or
 * begin, so every exec is uncovered and freezes at its first selected
 * admission (the begin-time create skip, made deterministic). */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CAPSULE_UNCOVERED_DIAGNOSTIC
#ifdef SE_PRODUCT_NO_TEST_RUN
#error "the uncovered-capsule diagnostic is test only"
#endif
#define SE_CAP_MATTERS() (real_owner_capsule_matters() && 0)
#else
#define SE_CAP_MATTERS() real_owner_capsule_matters()
#endif
#define SE_CAP_NEXT_SEQUENCE() real_owner_capsule_sequence()
#define SE_CAP_STAT(index) real_owner_capsule_stat(index)
/* Product objects: an exec entry with a live capsule is always marked (review
 * OQ: stale-capsule detection after a missed terminal and a missed begin).
 * Gated so the Step-0 / Phase A IDENT objects keep their bytes. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
#define SE_CAP_ENTRY_MARKS_LIVE_CAPSULE 1
#endif
/* G019 gap 4: a frozen re-admission of the same exec reports SE_CAP_LATER
 * (the interpreter pass); real_owner_reader_begin_core masks it. Absent
 * storage must stay a first (uncovered) admission, never a later one. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
#ifndef SE_CAP_ABSENT_OK
#error "interpreter continuation requires the task-storage capsule adapter"
#endif
#define SE_CAP_REPORT_LATER 1
#endif
#include "shared_exec_capsule.h"
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct se_exec_capsule);
} se_exec_capsules SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct se_exec_marker);
} se_exec_markers SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} se_exec_capsule_sequence SEC(".maps");
struct real_owner_capsule_stats {
	__u64 events[SE_CAP_STATS];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct real_owner_capsule_stats);
} se_exec_capsule_stats SEC(".maps");
/* In the fentry/fexit capsule programs the kernel uses the tracing variant
 * of bpf_task_storage_get (bpf_task_storage_get_recur), which returns NULL
 * when this CPU's task-storage busy trylock is held (a nested task-storage
 * user), even for existing storage and even with F_CREATE. The adapter's
 * "absent means the exec never mattered" holds only because such a miss is
 * fail-closed or availability-only: a matters-begin whose lookup/create
 * misses is a counted FAULT (its admission then freezes uncovered, or
 * degrades and counts ADMISSION); a stale capsule left by a missed terminal
 * lookup is retired by the task's next begin, its first selected admission,
 * or lsm/task_free (its pin, if any, blocks publication until then). In the LSM
 * admission and the death retire the non-recursive helper is used. */
static __always_inline struct se_exec_capsule *real_owner_capsule(__u64 flags)
{
	return bpf_task_storage_get(&se_exec_capsules,
				    bpf_get_current_task_btf(), 0, flags);
}
static __always_inline struct se_exec_marker *real_owner_marker(__u64 flags)
{
	return bpf_task_storage_get(&se_exec_markers,
				    bpf_get_current_task_btf(), 0, flags);
}
/* An exec can matter when its current cgroup has a route-index entry (a
 * selected or faulting route) or its task holds a TASK key (it may migrate
 * into a selected cgroup with its TASK). Only those create storage before
 * admission; any other exec creates it only at its first selected
 * admission. A hint, read without the route lock. */
static __always_inline int real_owner_capsule_matters(void)
{
	__u64 cgroup = bpf_get_current_cgroup_id();
	const __u64 *entry = SE_ROUTE_INDEX_LOOKUP(&cgroup);
	if (entry && *entry)
		return 1;
	__u64 key = (__u64)bpf_get_current_task_btf();
	return bpf_map_lookup_elem(&se_opaque_keys, &key) != 0;
}
static __always_inline __u64 real_owner_capsule_sequence(void)
{
	__u32 zero = 0;
	__u64 *next = bpf_map_lookup_elem(&se_exec_capsule_sequence, &zero);
	if (!next)
		return 0;
	__u64 value = __sync_fetch_and_add(next, 1) + 1;
	return value && value < ~0ULL - 1 ? value : 0;
}
static __always_inline void real_owner_capsule_stat(__u32 index)
{
	__u32 zero = 0;
	struct real_owner_capsule_stats *s =
		bpf_map_lookup_elem(&se_exec_capsule_stats, &zero);
	if (s && index < SE_CAP_STATS)
		__sync_fetch_and_add(&s->events[index], 1);
}
/* Loader attach order is a hard invariant: the death retire
 * (real_owner_capsule_free), terminal, entry, begin, then the LSM
 * admission; detach in exact reverse (the death retire is attached before
 * any capsule can exist and detached after the last one can be created). */
SEC("fexit/bprm_execve")
int BPF_PROG(real_owner_capsule_terminal, struct linux_binprm *bprm, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	(void)se_cap_on_terminal(id >> 32, (__u32)id,
				 (__u64)bpf_get_current_task_btf(), (__u64)bprm,
				 ret);
	return 0;
}
SEC("fentry/bprm_execve")
int BPF_PROG(real_owner_capsule_entry, struct linux_binprm *bprm)
{
	__u64 id = bpf_get_current_pid_tgid();
	se_cap_on_entry((__u32)id, (__u64)bpf_get_current_task_btf(),
			(__u64)bprm);
	return 0;
}
struct linux_binprm___capsule_check {
	unsigned int is_check : 1;
} __attribute__((preserve_access_index));
SEC("fentry/security_bprm_creds_for_exec")
int BPF_PROG(real_owner_capsule_begin, struct linux_binprm *bprm)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 is_check = 0;
	struct linux_binprm___capsule_check *checked = (void *)bprm;
	if (bpf_core_field_exists(checked->is_check))
		is_check = BPF_CORE_READ_BITFIELD_PROBED(checked, is_check);
	(void)se_cap_on_begin(id >> 32, (__u32)id,
			      (__u64)bpf_get_current_task_btf(), (__u64)bprm,
			      is_check);
	return 0;
}
/* Task death (task-storage adapter): retire a capsule whose terminal was
 * missed, releasing its original-route pin, before the kernel frees the
 * task's storage (security_task_free runs before bpf_task_storage_free). Its
 * own program and frame: the product task_free program's 512-byte chain is
 * not touched. Lookup only, never create. */
SEC("lsm/task_free")
int BPF_PROG(real_owner_capsule_free, struct task_struct *task)
{
	(void)se_cap_on_free(
		bpf_task_storage_get(&se_exec_capsules, task, 0, 0));
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	se_birth_park_drop(bpf_task_storage_get(&se_birth_parks, task, 0, 0),
			   SE_BIRTH_PARK_STALE);
#endif
	return 0;
}
/* Separate frame: the capsule admission's views/tokens/lock sections must
 * not sum with the begin_core claim/TASK frames (dead ends 18/23). The class
 * is the frozen ORIGINAL class; the current cgroup never selects it after
 * the first selected admission of this physical exec. */
static __attribute__((noinline)) int
real_owner_cap_admit(struct linux_binprm *bprm, struct se_route_claim *claim,
		     __u32 *frozen)
{
	__u64 id = bpf_get_current_pid_tgid();
	return se_cap_admit(id >> 32, (__u32)id,
			    (__u64)bpf_get_current_task_btf(), (__u64)bprm,
			    bpf_get_current_cgroup_id(), claim, frozen);
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
/* G019 gap 4: the receipt classification in its own frame. A stale
 * same-bprm-address receipt at a first admission stays pending. */
static __attribute__((noinline)) int
real_owner_pending_class(__u64 key, __u64 bprm, __u32 later)
{
	return se_exec_receipt_pending_class(
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key), key,
		bprm, later);
}
#endif
static __attribute__((noinline)) int
real_owner_reader_begin_core(struct linux_binprm *bprm, int terminal_fault)
{
	if (!real_owner_image_configured())
		return 0;
	struct se_route_claim claim = {};
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE
	__u32 frozen_class = 0;
	int admission = real_owner_cap_admit(bprm, &claim, &frozen_class);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
	__u32 later = frozen_class & SE_CAP_LATER;
	frozen_class &= ~SE_CAP_LATER;
#endif
	if (admission == SE_ROUTE_OWNED &&
	    (frozen_class != claim.execution_class ||
	     SE_FC_EXEC_ADMISSION_FAULT(later))) {
		/* Defense in depth: an owned claim must carry the frozen class.
		 * Deny only a Strict frozen class; Audit never blocks. */
		(void)real_owner_child_release_claim(&claim);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		SE_RATE_ATTEMPT(1);
		SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_ADMISSION);
#endif
		return frozen_class == 2 ? 1 : 0;
	}
#else
	int admission = se_route_admit(bpf_get_current_cgroup_id(), &claim);
#endif
	if (admission != SE_ROUTE_OWNED) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		/* G019 M4: every admission fault is a counted attempt and a
		 * counted ADMISSION; Audit faults too (never silent). */
		if (admission == SE_ROUTE_STRICT_FAULT ||
		    admission == SE_ROUTE_AUDIT_FAULT ||
		    admission == SE_ROUTE_INVARIANT_FAULT) {
			SE_RATE_ATTEMPT(1);
			SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_ADMISSION);
		}
#endif
		return admission == SE_ROUTE_STRICT_FAULT ||
				       admission == SE_ROUTE_INVARIANT_FAULT ?
			       1 :
			       0;
	}
	__u32 mode = claim.execution_class;
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_ol_payload_handle owner = {};
	/* Do not mutate the TASK transaction while its prior terminal receipt is
	 * waiting for an authenticated consumer. Otherwise a second begin can
	 * replace the exact sequence needed for retry-safe receipt retirement. */
	int pending_terminal = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
	/* G019 gap 4: a later admission of the same exec whose pass-0 receipt
	 * is still REGISTERED is an interpreter pass, not a pending receipt.
	 * Its own frame returns before any TASK/reader frame (stack). The
	 * claim is released here; the continuation re-derives everything from
	 * the receipt, the failure frames and the original reader. Result 16
	 * (with 1 for a Strict frozen class) dispatches the static-class
	 * continuation; 32 is a failed claim release (refused). */
	int pending_class = real_owner_pending_class(key, (__u64)bprm, later);
	if (pending_class == SE_EXEC_PENDING_CONTINUE) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		SE_RATE_ATTEMPT(1); /* every pass is one exec attempt */
#endif
		int unreleased = real_owner_child_release_claim(&claim) != 0;
		return 16 | (unreleased ? 32 : 0) | (mode == 2 ? 1 : 0);
	}
	pending_terminal = pending_class != SE_EXEC_PENDING_NONE;
#elif defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE)
	pending_terminal =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key) != 0;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	/* U2: terminal and pending faults keep their own classes; a failed
	 * open is ENTRY only when the task has no TASK at all (lock-free key
	 * lookup: se_ol_observe's STALE does not distinguish), else [8]. */
	SE_RATE_ATTEMPT(1);
	int good = 0;
	if (!terminal_fault && !pending_terminal) {
		good = !SE_FC_EXEC_OPEN_PARENT_FAULT(key) &&
		       real_owner_child_open_parent(&owner) == SE_OL_OK;
		if (!good)
			SE_FAIL_CLOSED_RATE(
				bpf_map_lookup_elem(&se_opaque_keys, &key) ?
					REAL_OWNER_RATE_OPEN_PARENT :
					REAL_OWNER_RATE_ENTRY);
	}
#else
	int good = !terminal_fault && !pending_terminal &&
		   real_owner_child_open_parent(&owner) == SE_OL_OK;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
	int transfer = 0;
	if (good) {
		__u64 invocation = 0;
		/* The test-only reader-begin fault skips the begin (nothing
		 * begun, nothing to abort). */
		int opened = !SE_FC_READER_BEGIN_FAULT() &&
			     real_owner_reader_open_exact(&owner, &claim, bprm,
							  &invocation);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		/* The TASK opened but its reader could not begin: the Strict
		 * reserve refuses a QUARANTINED TASK (exec.h), or the begin or
		 * recover failed. A genuine fault, in Total; never ENTRY. */
		if (!opened)
			SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_OPEN_PARENT);
#endif
		int step = real_owner_reader_finish_exact(&owner, &claim, bprm,
							  invocation, opened);
		good = step & 1;
		transfer = !!(step & 2);
	}
#else
	if (good) {
		struct se_shared_binding *binding =
			bpf_map_lookup_elem(&se_bindings, &claim.slot);
		__u64 invocation = 0;
		good = binding &&
		       se_op_exec_reader_begin(&owner, &claim, &binding->state,
					       (__u64)bprm,
					       &invocation) == SE_OL_OK;
		if (good) {
			__u64 recovered = 0;
			good = se_op_exec_reader_recover(
				       &owner, &binding->state, (__u64)bprm,
				       &recovered) == SE_OL_OK &&
			       recovered == invocation;
		}
		/* The lifecycle variant leaves only a successfully recovered Audit
		 * reader to the actual terminal callback. Strict remains denied here;
		 * this diagnostic has no evaluator and never grants enforcement. */
		int retained = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
		/* An absent or ambiguous outer frame cannot leave a retained Audit
		 * reader with no trustworthy failure terminal. Quarantine history
		 * and release this invocation, but never deny audit execution. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE
		if (good && mode == 1 &&
		    !real_owner_failure_frame_ready(key, (__u64)bprm)) {
			(void)se_op_exec_reader_abort_quarantined(
				&owner, &binding->state, (__u64)bprm,
				invocation);
			invocation = 0;
			good = 0;
		}
#endif
		retained = good && mode == 1;
		if (retained) {
			struct se_exec_terminal_receipt receipt = {
				.physical = key,
				.bprm = (__u64)bprm,
				.cookie = owner.lease.cookie,
				.locator = owner.lease.locator,
				.invocation = invocation,
				.scope = claim.scope,
				.generation = claim.generation,
				.phase = SE_EXEC_TERMINAL_REGISTERED,
			};
			int recorded = !bpf_map_update_elem(
				&se_exec_terminal_receipts, &key, &receipt,
				BPF_NOEXIST);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE
			if (recorded &&
			    real_owner_failure_bind_receipt(&receipt)) {
				(void)bpf_map_delete_elem(
					&se_exec_terminal_receipts, &key);
				recorded = 0;
			}
#endif
			if (!recorded) {
				(void)se_op_exec_reader_abort_quarantined(
					&owner, &binding->state, (__u64)bprm,
					invocation);
				retained = 0;
				invocation = 0; /* no second terminal attempt */
				good = 0;
			}
		}
#endif
		if (invocation && !retained)
			good = se_op_exec_reader_finish_bounded(
				       &owner, &binding->state, (__u64)bprm,
				       invocation, 0) == SE_OL_OK &&
			       good;
		if (se_ol_payload_close(&owner) != SE_OL_OK)
			good = 0;
	}
#endif
	if (claim.owned && real_owner_child_release_claim(&claim))
		good = 0;
	/* This probe has no evaluator. Never allow a selected strict exec even
	 * when its ownership/cleanup diagnostics all succeeded. */
	int result = mode == 2 ? 1 : 0;
	if (pending_terminal || terminal_fault) {
		result |= 8;
		SE_EXEC_EXCLUSION_WITNESS(terminal_fault & 2 ? 0 : 1);
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
	if (transfer)
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
		result |= 2 | (good && (mode == 1 || mode == 2) ? 4 : 0);
#else
		result |= 2 | (good && mode == 1 ? 4 : 0);
#endif
#endif
	return result;
}

SEC("lsm/bprm_check_security")
long BPF_PROG(opaque_real_owner_reader_begin_probe, struct linux_binprm *bprm,
	      int prior)
{
	/* Keep the prior LSM result and our verdict in the signed 64-bit return
	 * domain; a 32-bit negation loses its range on the AL2023 6.12 verifier. */
	__s64 prior_ret = (__s64)ctx[1];
	if (prior_ret) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC
		(void)real_owner_continue_reader(bprm, 1);
#endif
		return prior_ret;
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SAME_BPRM_CONTINUE_DIAGNOSTIC
	int continuation = real_owner_continue_reader(bprm, 0);
	if (continuation) {
		if (continuation == 1) {
			bpf_tail_call(ctx, &opaque_real_owner_policy_targets,
				      0);
			(void)real_owner_policy_abort_handoff(
				(__u64)bpf_get_current_task_btf(), (__u64)bprm);
		} else {
			(void)real_owner_reader_quarantine_pending(
				(__u64)bpf_get_current_task_btf());
		}
		if (continuation == 2 ||
		    (continuation == 4 &&
		     (real_owner_reader_begin_core(bprm, 1) & 1))) {
			asm volatile("" ::: "memory");
			return -1L;
		}
		return 0;
	}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PENDING_RECEIPT_DIAGNOSTIC
	(void)real_pending_receipt_inject();
#endif
	/* 2: first-exec qualification fault (rate [6]); 1: terminal drain
	 * fault. Either, or a pending terminal receipt, refuses the exec. */
	int terminal_fault = 0;
#ifdef SE_REAL_OWNER_BIRTH_QUALIFY
	if (real_owner_image_configured() &&
	    SE_FC_QUALIFY_FAULT(real_owner_birth_qualify(
		    (struct task_struct *)bpf_get_current_task_btf())))
		terminal_fault = 2;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_TERMINAL_DRAIN_DIAGNOSTIC
	/* Keep completion outside the new claim/TASK-open stack frame. */
	if (real_owner_image_configured() && real_owner_source_terminal_drain())
		terminal_fault |= 1;
#endif
	int result = real_owner_reader_begin_core(bprm, terminal_fault);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE
	if (result & 16) {
		/* The class is the capsule's frozen ORIGINAL class. A graph miss
		 * (or a failed claim release) is a counted GAP refusal with the
		 * static class verdict: Strict denies, Audit allows. A terminal
		 * fault (2: first-exec qualification, 1: terminal drain) refuses
		 * the pass before any dispatch, counted once in its own class
		 * exactly as on a first pass (QUALIFY [6] or PENDING [7]), never
		 * also GAP: the continuation was never attempted. */
		__u32 reason = SE_INTERP_STAT_FRAME;
		if (terminal_fault) {
			SE_FAIL_CLOSED_RATE(terminal_fault & 2 ?
						    REAL_OWNER_RATE_QUALIFY :
						    REAL_OWNER_RATE_PENDING);
			reason = SE_INTERP_STATS;
		} else if (!(result & 32)) {
			if (result & 1)
				bpf_tail_call(ctx, &opaque_real_continue_strict,
					      0);
			else
				bpf_tail_call(ctx, &opaque_real_continue_audit,
					      0);
			reason = SE_INTERP_STAT_GRAPH_MISS;
		}
		if (result & 1)
			return real_owner_continue_refuse(ctx, reason, 2);
		return real_owner_continue_refuse(ctx, reason, 1);
	}
#endif
	if (result & 8) {
		(void)real_owner_reader_quarantine_pending(
			(__u64)bpf_get_current_task_btf());
		SE_FAIL_CLOSED_RATE(terminal_fault & 2 ?
					    REAL_OWNER_RATE_QUALIFY :
					    REAL_OWNER_RATE_PENDING);
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_BRIDGE_CANDIDATE
	if (result & 2) {
		if (result & 4) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
			if (result & 1)
				bpf_tail_call(ctx, &opaque_real_policy_strict,
					      0);
			else
				bpf_tail_call(ctx, &opaque_real_policy_audit,
					      0);
			SE_GRAPH_MISS();
#ifdef SE_VERDICT_EVENTS
			/* The pass's one fault event (D1): no policy program
			 * ran for it. */
			(void)se_verdict_emit(
				ctx, 0, 0,
				SE_VERDICT_INFO(result & 1 ? 2 : 1,
						SE_VERDICT_FAULT,
						SE_VERDICT_INFO_PASS_UNKNOWN));
#endif
#else
			bpf_tail_call(ctx, &opaque_real_owner_policy_targets,
				      0);
#endif
		}
		/* Missing target or failed lexical close: never retain an unknown
		 * reader as a successful role source. */
		(void)real_owner_policy_abort_handoff(
			(__u64)bpf_get_current_task_btf(), (__u64)bprm);
	}
#endif
	if (result & 1) {
		/* Do not fold the two constant verdicts into a 32-bit negation. */
		asm volatile("" ::: "memory");
		return -1L;
	}
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC
/* AL2023 diagnostic only: the winning success source attempts the existing
 * WORK completion path directly. A failed attempt retains the exact receipt
 * for the existing completion/settlement retry paths. No controller gate is
 * consulted; this does not qualify the hook on other kernels. */
#else
/* Success-side producer for the plain diagnostic mailbox. The callback does
 * not touch the lock-bearing TASK/route/WORK maps: Rocky 4.18 rejects spinlock
 * helpers in tp_btf programs. The receipt is not a release or a verdict. A
 * failed exec still needs a separate terminal; never arm/attach this variant
 * as a product or treat it as a complete lifecycle. */
#endif
SEC("tp_btf/sched_process_exec")
int BPF_PROG(opaque_real_owner_reader_success_probe,
	     struct task_struct *physical, int old_pid,
	     struct linux_binprm *bprm)
{
	(void)old_pid;
	__u64 key = (__u64)physical;
	struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC
	if (receipt && !SE_FC_PENDING_SKIP(key) &&
	    real_owner_terminal_transition(
		    receipt, key, (__u64)bprm, receipt->cookie,
		    receipt->locator, receipt->invocation, receipt->scope,
		    receipt->generation, SE_EXEC_TERMINAL_SUCCESS)) {
		/* The callee may delete the receipt; do not use its pointer again. */
		SE_WORK_SYNC_RETURN(
			SE_SETTLE_SLOT(real_owner_work_completion_shape(key)),
			REAL_OWNER_WORK_SYNC_SETTLED_EXEC);
	}
#else
	if (receipt)
		(void)real_owner_terminal_transition(
			receipt, key, (__u64)bprm, receipt->cookie,
			receipt->locator, receipt->invocation, receipt->scope,
			receipt->generation, SE_EXEC_TERMINAL_SUCCESS);
#endif
	return 0;
}
#endif
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_COMPLETION_PROBE
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE)
#error "prepared WORK receipt probe requires the reader and terminal producer"
#endif
/* Never attached or selected. The controller supplies only a physical-key
 * selector; the read-only plain receipt map is written by the actual success
 * tracepoint, never by userspace. This probe cannot invent a terminal. The
 * product object (SE_PRODUCT_NO_TEST_RUN) has neither the TEST_RUN probes
 * nor their selector maps; the completion helpers stay for the real
 * terminal producers. */
#ifndef SE_PRODUCT_NO_TEST_RUN
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_owner_work_completion_gate SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_owner_work_completion_selector SEC(".maps");
#endif

static __attribute__((noinline)) int
real_owner_work_delete_receipt_exact(__u64 key,
				     const struct se_ol_payload_handle *owner);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
static __attribute__((noinline)) int
real_owner_work_receipt_exact(__u64 key,
			      const struct se_ol_payload_handle *owner);

/* Terminal completion outcomes, read by the attached verdict test. */
#define REAL_OWNER_TERMINAL_RESUMED_COMPLETED 0
#define REAL_OWNER_TERMINAL_RESUMED_FAILED 1
#define REAL_OWNER_TERMINAL_FALLBACK_CHARGED 2
#define REAL_OWNER_TERMINAL_FALLBACK_REFUSED 3
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_real_terminal_outcomes SEC(".maps");

/* Leaf frame: keeps the key/pointer off the deep completion frame. */
static __attribute__((noinline)) void real_owner_terminal_outcome(__u32 outcome)
{
	__u64 *count =
		bpf_map_lookup_elem(&opaque_real_terminal_outcomes, &outcome);
	if (count)
		__sync_fetch_and_add(count, 1);
}
#endif

static __attribute__((noinline)) SE_SETTLE_T
real_owner_work_complete_active(struct se_ol_payload_handle *owner, __u64 key)
{
	struct se_owk_ticket ticket = {};
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* Complete into the proposed evaluation WORK. Only STALE (no WORK
	 * suspended at this stage) charges a fresh WORK, and only while the
	 * terminal receipt is still exact; CORRUPT or any other result refuses. */
	int resumed = se_owk_resume(owner, REAL_OWNER_TERMINAL_RESUME, &ticket);
	if (resumed != SE_OL_OK) {
		if (resumed != SE_OL_STALE ||
		    !real_owner_work_receipt_exact(key, owner)) {
			real_owner_terminal_outcome(
				REAL_OWNER_TERMINAL_FALLBACK_REFUSED);
			return -1;
		}
		ticket = (struct se_owk_ticket){};
		if (real_owner_child_start_work(owner, &ticket)) {
			real_owner_terminal_outcome(
				REAL_OWNER_TERMINAL_FALLBACK_REFUSED);
			goto abort_work;
		}
		real_owner_terminal_outcome(
			REAL_OWNER_TERMINAL_FALLBACK_CHARGED);
	}
#else
	if (real_owner_child_start_work(owner, &ticket))
		goto abort_work;
#endif
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	if (se_owk_semantic_open(owner, &ticket, &semantic, &work) != SE_OL_OK)
		goto done;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* The snapshot below rewrites history (transaction and view rows); the
	 * reader classify/prepare reset accepted_mask and patch. Only the
	 * prepare-stage catalogue must be emptied for a fresh exact fill. The
	 * evaluation's observation (decision witness) is left intact. */
	if (resumed == SE_OL_OK) {
		semantic.payload->catalogue.scope = 0;
		semantic.payload->catalogue.generation = 0;
		work->history.view.accepted_mask = 0;
	}
#endif
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	struct se_task_state *task = 0;
	if (se_op_task_semantic_begin(owner, &task) != SE_OL_OK)
		goto semantic_done;
	int success = receipt && receipt->phase == SE_EXEC_TERMINAL_SUCCESS;
	if (!se_owk_terminal_receipt_matches(receipt, key, owner, task,
					     success)) {
		se_op_task_semantic_end(owner, &task);
		goto semantic_done;
	}
	__u64 bprm = task->exec.bprm;
	__u64 invocation = task->exec.sequence;
	__u64 generation = task->exec.generation;
	se_exec_snapshot_locked(task, generation, &work->history);
	se_op_task_semantic_end(owner, &task);
	int completed = bprm && invocation && generation &&
			se_owk_catalogue_fill_reader(&semantic) == SE_OL_OK &&
			se_owk_exec_complete_reader(&semantic, bprm, invocation,
						    success) == SE_OL_OK;
	int closed = se_owk_semantic_done(&semantic, &work) == SE_OL_OK;
	int ok = completed && closed &&
		 !real_owner_work_delete_receipt_exact(key, owner);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	/* The resumed completion's final result; fallback was counted at charge. */
	if (resumed == SE_OL_OK)
		real_owner_terminal_outcome(
			ok ? REAL_OWNER_TERMINAL_RESUMED_COMPLETED :
			     REAL_OWNER_TERMINAL_RESUMED_FAILED);
#endif
	/* A closed (exactly DONE) evaluation WORK goes to the synchronous return
	 * in the high half of R0. */
	return SE_SETTLE_PACK(ok ? 0 : -1, closed ? ticket.work_slot + 1 : 0);
semantic_done:
	(void)se_owk_semantic_done(&semantic, &work);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	if (resumed == SE_OL_OK)
		real_owner_terminal_outcome(REAL_OWNER_TERMINAL_RESUMED_FAILED);
#endif
	return -1;
done:
	(void)se_owk_done(owner, &ticket);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE
	if (resumed == SE_OL_OK)
		real_owner_terminal_outcome(REAL_OWNER_TERMINAL_RESUMED_FAILED);
#endif
	return -1;
abort_work:
	if (ticket.held) {
		if (ticket.stage == 0)
			(void)se_owk_abort_building(owner, &ticket);
		else if (ticket.stage == 1 || ticket.stage == 2)
			(void)se_owk_abort(owner, &ticket);
		else if (ticket.stage == 3)
			(void)se_owk_done(owner, &ticket);
	}
	return -1;
}

static __attribute__((noinline)) int
real_owner_work_receipt_exact(__u64 key,
			      const struct se_ol_payload_handle *owner)
{
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	return receipt &&
	       (receipt->phase == SE_EXEC_TERMINAL_SUCCESS ||
		receipt->phase == SE_EXEC_TERMINAL_FAILURE) &&
	       receipt->physical == key &&
	       receipt->cookie == owner->lease.cookie &&
	       receipt->locator == owner->lease.locator;
}

static __attribute__((noinline)) int
real_owner_work_delete_receipt_exact(__u64 key,
				     const struct se_ol_payload_handle *owner)
{
	if (!real_owner_work_receipt_exact(key, owner))
		return -1;
	return bpf_map_delete_elem(&se_exec_terminal_receipts, &key);
}

/* The observation/lease stack frame ends before the WORK completion frame. */
static __attribute__((noinline)) int
real_owner_work_open_key(__u64 key, struct se_ol_payload_handle *owner)
{
	return se_ol_task_open(&key, owner);
}

#ifdef SE_TERMINAL_RACE_RENDEZVOUS
struct opaque_real_terminal_race_witness {
	__u64 attempts;
	__u64 commits;
	__u64 inflight;
	__u64 overlap;
	__u64 authenticated;
	__u64 auth_inflight;
	__u64 auth_overlap;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_real_terminal_race_witness);
} opaque_real_terminal_race_witness SEC(".maps");

/* A contender has already opened the exact TASK and validated the terminal
 * receipt before entering this bounded test-only rendezvous. */
static __attribute__((noinline)) void real_owner_terminal_auth_enter(void)
{
	__u32 zero = 0;
	struct opaque_real_terminal_race_witness *witness =
		bpf_map_lookup_elem(&opaque_real_terminal_race_witness, &zero);
	if (!witness)
		return;
	__sync_fetch_and_add(&witness->authenticated, 1);
	__u64 entered = __sync_add_and_fetch(&witness->auth_inflight, 1);
	if (entered > 1)
		__sync_fetch_and_add(&witness->auth_overlap, 1);
		/* SE_TERMINAL_RACE_NO_SPIN (the latency object only): keep the witness
	 * counts but not the wait, so the exec hot path is measured as the
	 * product runs it (up to 4096 bpf_ktime_get_ns spins, ~50 us, per
	 * completion otherwise). */
#ifndef SE_TERMINAL_RACE_NO_SPIN
	for (__u32 spin = 0; spin < 4096; spin++) {
		volatile __u64 tick = bpf_ktime_get_ns();
		(void)tick;
		if (*(volatile __u64 *)&witness->auth_inflight > 1)
			break;
	}
#endif
}
static __attribute__((noinline)) void real_owner_terminal_auth_exit(void)
{
	__u32 zero = 0;
	struct opaque_real_terminal_race_witness *witness =
		bpf_map_lookup_elem(&opaque_real_terminal_race_witness, &zero);
	if (witness)
		__sync_fetch_and_sub(&witness->auth_inflight, 1);
}
#endif

static __attribute__((noinline)) SE_SETTLE_T
real_owner_work_completion_shape(__u64 key)
{
	SE_SETTLE_T result = -1;
	struct se_ol_payload_handle owner = {};
	if (real_owner_work_open_key(key, &owner) != SE_OL_OK)
		return -1;
	if (!real_owner_work_receipt_exact(key, &owner))
		goto close;
#ifdef SE_TERMINAL_RACE_RENDEZVOUS
	real_owner_terminal_auth_enter();
#endif
	result = real_owner_work_complete_active(&owner, key);
#ifdef SE_TERMINAL_RACE_RENDEZVOUS
	real_owner_terminal_auth_exit();
#endif
close:
	/* A removed receipt is not permission to advance after a leaked lease. */
	if (se_ol_payload_close(&owner) != SE_OL_OK)
		return -2;
	return result;
}

#if defined(ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC) && \
	!defined(SE_PRODUCT_NO_TEST_RUN)
SEC("tc")
int opaque_real_owner_terminal_race_complete(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const __u32 *armed = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_gate, &zero);
	const __u64 *selected = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_selector, &zero);
	if (!armed || *armed != 1 || !selected || !*selected)
		return 0;
	struct opaque_real_terminal_race_witness *witness =
		bpf_map_lookup_elem(&opaque_real_terminal_race_witness, &zero);
	if (witness) {
		__sync_fetch_and_add(&witness->attempts, 1);
		__u64 entered = __sync_add_and_fetch(&witness->inflight, 1);
		if (entered > 1)
			__sync_fetch_and_add(&witness->overlap, 1);
	}
	int done = SE_SETTLE_RESULT(
			   real_owner_work_completion_shape(*selected)) == 0;
	if (witness) {
		if (done)
			__sync_fetch_and_add(&witness->commits, 1);
		__sync_fetch_and_sub(&witness->inflight, 1);
	}
	return 0;
}
#endif

#ifndef SE_PRODUCT_NO_TEST_RUN
SEC("tc")
int opaque_real_owner_work_completion_probe(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const __u32 *armed = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_gate, &zero);
	const __u64 *selected = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_selector, &zero);
	if (armed && *armed == 1 && selected && *selected)
		(void)SE_SETTLE_RESULT(
			real_owner_work_completion_shape(*selected));
	return 0;
}
#endif

/* Separate bounded retry program: a postcommit fault must never rerun the
 * accepted-role patch. An owned transaction is intentionally NOT handled by
 * this entrypoint and keeps its receipt for the normal WORK consumer. */
static __attribute__((noinline)) int real_owner_work_retry_shape(__u64 key)
{
	int result = -1;
	struct se_ol_payload_handle owner = {};
	if (real_owner_work_open_key(key, &owner) != SE_OL_OK)
		return -1;
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	if (real_owner_work_receipt_exact(key, &owner) && receipt &&
	    se_owk_exec_settle_committed_reader(&owner, receipt, key) ==
		    SE_OL_OK)
		result = real_owner_work_delete_receipt_exact(key, &owner);
	if (se_ol_payload_close(&owner) != SE_OL_OK)
		return -2;
	return result;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_TERMINAL_DRAIN_DIAGNOSTIC
/* Deferred current-task drain only, not a complete failure lifecycle: an
 * idle task can still retain the failed invocation's reader. Kretprobes only
 * certify the terminal; these LSM sources may touch the lock-bearing maps.
 * REGISTERED is deliberately retained: same-bprm continuation is separate. */
static __attribute__((noinline)) int real_owner_source_terminal_drain(void)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, &key);
	if (!receipt)
		return 0;
	if (!key || receipt->physical != key || !receipt->bprm ||
	    !receipt->cookie || !receipt->locator || !receipt->invocation ||
	    !receipt->scope || !receipt->generation || receipt->reserved ||
	    (receipt->phase != SE_EXEC_TERMINAL_SUCCESS &&
	     receipt->phase != SE_EXEC_TERMINAL_FAILURE))
		return -1;
	/* Retry first: a committed role patch must never be applied twice.
	 * -2 means lexical close failed, so absence alone cannot authorize a
	 * successor. Neither completion nor another retry may hide that fault. */
	int result = real_owner_work_retry_shape(key);
	if (result == -2)
		return -1;
	if (result) {
		result =
			SE_SETTLE_RESULT(real_owner_work_completion_shape(key));
		if (result == -2)
			return -1;
		if (result)
			result = real_owner_work_retry_shape(key);
	}
	if (result || bpf_map_lookup_elem(&se_exec_terminal_receipts, &key))
		return -1;
	return 0;
}
#endif

#ifndef SE_PRODUCT_NO_TEST_RUN
SEC("tc")
int opaque_real_owner_work_retry_probe(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const __u32 *armed = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_gate, &zero);
	const __u64 *selected = bpf_map_lookup_elem(
		&opaque_real_owner_work_completion_selector, &zero);
	if (armed && *armed == 1 && selected && *selected)
		(void)real_owner_work_retry_shape(*selected);
	return 0;
}
#endif
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
#include "opaque_real_owner_product_publisher.h"
#endif
char LICENSE[] SEC("license") = "GPL";
