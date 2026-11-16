/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_CORE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_CORE_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE) ||                 \
	!defined(ENFORCE_EXEC_ABI3_DEVELOPMENT) || !defined(SE_OL_TASKS) || \
	!defined(SE_OC_ACCOUNTS) || !defined(SE_OC_QUOTA) ||                \
	!defined(SE_OWK_ACCOUNTS) || !defined(SE_OWK_QUOTA) ||              \
	!defined(SE_OWK_WORKS)
#error "opaque owner core requires explicit candidate profile"
#endif
#ifndef FULL_EPOCH_ROLES_H
#error "opaque owner core requires epoch-role wire"
#endif
/* Shared candidate TASK/WORK types, operations and fourteen-map cohort.
 * Callers still supply real or synthetic route, binding, policy, source and
 * native authority; this header must not invent those or advertise Ready. */
struct se_ol_meta;
static struct se_ol_meta *meta_lookup(__u32 slot);
static const __u64 *opaque_lookup(const void *key);
static int archive_copy(__u32 slot, const void *key);
static int archive_zero(__u32 slot);
static const __u64 *archive_lookup(__u32 slot);
static int insert_zero(const void *key);
static __u64 *writer_lookup(const void *key);
static int delete_key(const void *key);
#define SE_OL_LOOKUP(key) opaque_lookup(key)
#define SE_OL_META_LOOKUP(slot) meta_lookup(slot)
#define SE_OW_ARCHIVE_COPY(slot, key) archive_copy(slot, key)
#define SE_OW_ARCHIVE_ZERO(slot) archive_zero(slot)
#define SE_OW_ARCHIVE_LOOKUP(slot) archive_lookup(slot)
#define SE_OW_INSERT_ZERO(key) insert_zero(key)
#define SE_OW_LOOKUP(key) writer_lookup(key)
#define SE_OW_CAS(value, old, new_value) \
	__sync_val_compare_and_swap(value, old, new_value)
#define SE_OW_DELETE(key) delete_key(key)
#include "shared_pool_opaque_writer_candidate.h"
#include "shared_pool_opaque_replace_candidate.h"
#include "shared_pool_opaque_final_free_candidate.h"
struct se_oc_account;
struct se_oc_charge;
struct se_oc_sequence;
static struct se_oc_account *account_lookup(__u32 slot);
static struct se_oc_charge *charge_lookup(__u32 slot);
static struct se_oc_sequence *sequence_lookup(void);
#define SE_OC_ACCOUNT_LOOKUP(slot) account_lookup(slot)
#define SE_OC_CHARGE_LOOKUP(slot) charge_lookup(slot)
#define SE_OC_SEQUENCE_LOOKUP() sequence_lookup()
#include "shared_pool_opaque_charge_candidate.h"
#include "shared_pool_opaque_refund_candidate.h"
#include "shared_route.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
#include "shared_policy_lookup.h"
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
#include "evaluator_stage_candidate.h"
#endif
#include "shared_exec.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
/* Match the selected ABI3 observation wire, not an invented WORK tail. */
struct observation {
	struct fe_facts facts;
	struct fe_scratch evaluator;
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
	/* Raw argument capture and evaluator continuation are disjoint phases.
	 * A future source must zero stage_cursor only after the last argv copy;
	 * successors must hold the exact WORK ticket through the last read. */
	union {
		char argument[4097];
		struct fe_stage_cursor stage_cursor;
		struct {
			struct fe_stage_cursor cursor;
			struct fm_global_token token;
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
			/* This aliases only raw argument capture after it is finished;
			 * it does not grow the fixed WORK wire. */
			struct fe_alt_request alt_request;
#endif
		} stage_workspace;
	};
#else
	char argument[4097];
#endif
};
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
_Static_assert(
	sizeof(struct fe_stage_cursor) == 56 &&
		sizeof(((struct observation *)0)->stage_workspace) <= 4097 &&
		__builtin_offsetof(struct observation, argument) ==
			__builtin_offsetof(struct observation, stage_cursor) &&
		__builtin_offsetof(struct observation, stage_cursor) % 8 == 0,
	"staged cursor must reuse aligned WORK observation scratch");
#endif
#include "shared_invocation_wire.h"
#endif
#endif
static struct se_route_anchor *route_lookup(__u32 slot);
#define SE_OC_ROUTE_LOOKUP(slot) route_lookup(slot)
#include "shared_pool_opaque_route_candidate.h"
static void *payload_lookup(__u32 slot);
#define SE_OL_PAYLOAD_LOOKUP(slot) payload_lookup(slot)
#include "shared_pool_opaque_payload_handle_candidate.h"
#include "shared_pool_opaque_task_open_candidate.h"
struct se_owk_account;
struct se_owk_charge;
struct se_owk_sequence;
static struct se_owk_account *work_account_lookup(__u32 slot);
static struct se_owk_charge *work_charge_lookup(__u32 slot);
static struct se_owk_sequence *work_sequence_lookup(void);
static struct se_owk_meta *work_meta_lookup(__u32 slot);
static struct se_owk_payload *work_payload_lookup(__u32 slot);
static int work_payload_zero(__u32 slot);
#define SE_OWK_ACCOUNT_LOOKUP(slot) work_account_lookup(slot)
#define SE_OWK_CHARGE_LOOKUP(slot) work_charge_lookup(slot)
#define SE_OWK_SEQUENCE_LOOKUP() work_sequence_lookup()
#define SE_OWK_META_LOOKUP(slot) work_meta_lookup(slot)
#define SE_OWK_PAYLOAD_LOOKUP(slot) work_payload_lookup(slot)
#define SE_OWK_PAYLOAD_ZERO(slot) work_payload_zero(slot)
#include "shared_pool_opaque_work_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
#include "shared_pool_opaque_work_continuation_candidate.h"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#include "shared_pool_opaque_work_semantic_candidate.h"
#endif
#include "shared_pool_opaque_work_reap_candidate.h"
static int payload_zero(__u32 slot);
#define SE_OP_PAYLOAD_INIT(slot) payload_zero(slot)
#include "shared_pool_opaque_task_semantic_candidate.h"
#define SE_OP_PAYLOAD_ZERO(slot) payload_zero(slot)
#include "shared_pool_opaque_payload_zero_candidate.h"

#include "shared_pool_opaque_maps_candidate.h"
#endif
