/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Host-only regression of the opaque-key observer candidate. No policy
 * authority is derived from this fixture or its synthetic HASH backing. */
#include <linux/bpf.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#if defined(ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE) &&                \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE))
#error "stage overlay requires typed TASK/WORK continuation"
#endif
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#define ER_ACCEPTED_EPOCH(uid) ((__u64)0)
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
static void bpf_spin_lock(struct bpf_spin_lock *lock);
static void bpf_spin_unlock(struct bpf_spin_lock *lock);
#include "shared_route.h"
#include "shared_policy_lookup.h"
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
#include "evaluator_stage_candidate.h"
#endif
/* Synthetic immutable source for the host-only policy-prepare bridge. This
 * does not stand in for the selected object's pin or snapshot authority. */
static struct fm_blob opaque_policy_blobs[10];
static inline const struct fm_blob *
se_policy_physical(void *context, fm_u32 slot, fm_u64 generation, fm_u32 key)
{
	return !context && slot == 0 && generation == 1 && key < 10 ?
		       &opaque_policy_blobs[key] :
		       0;
}
#endif
#include "epoch_roles.h"
#include "shared_inherit_roles.h"

#define ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE 1
#ifndef SE_OL_TASKS
#define SE_OL_TASKS 4
#endif
struct cell {
	__u64 key, locator;
	int present;
};
static struct cell cells[2];
static __u64 archives[SE_OL_TASKS];
static struct bpf_spin_lock *held;
static unsigned lock_errors, lookups;
static int archive_fail, archive_zero_fail, delete_busy;
static int insert_successor_after_delete;
static int replace_cas_fault;
static int vanish_after_eexist;
static int recycle_first_lookup_to_b;
static int open_race_mode;
static void open_race(void);
static const __u64 *lookup(const void *opaque_key);
static int archive_copy(__u32 slot, const void *opaque_key);
static int archive_zero(__u32 slot);
static const __u64 *archive_lookup(__u32 slot);
static int insert_zero(const void *opaque_key);
static int delete_key(const void *opaque_key);
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	if (held)
		lock_errors++;
	held = lock;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	if (held != lock)
		lock_errors++;
	held = NULL;
}
#define SE_OL_LOOKUP(key) lookup(key)
static struct se_ol_meta *meta_lookup(__u32 slot);
#define SE_OL_META_LOOKUP(slot) meta_lookup(slot)
#include "shared_pool_opaque_lookup_candidate.h"
#define SE_OW_ARCHIVE_COPY(slot, key) archive_copy(slot, key)
#define SE_OW_ARCHIVE_ZERO(slot) archive_zero(slot)
#define SE_OW_ARCHIVE_LOOKUP(slot) archive_lookup(slot)
#define SE_OW_INSERT_ZERO(key) insert_zero(key)
#define SE_OW_LOOKUP(key) ((__u64 *)lookup(key))
static __u64 host_locator_cas(__u64 *value, __u64 old, __u64 next)
{
	if (replace_cas_fault) {
		replace_cas_fault = 0;
		return old ^
		       1ULL; /* ambiguous failed CAS: no synthetic refund */
	}
	return __sync_val_compare_and_swap(value, old, next);
}
#define SE_OW_CAS(value, old, new_value) host_locator_cas(value, old, new_value)
#define SE_OW_DELETE(key) delete_key(key)
#include "shared_pool_opaque_writer_candidate.h"
#include "shared_pool_opaque_replace_candidate.h"
#include "shared_pool_opaque_final_free_candidate.h"
#ifndef SE_OC_ACCOUNTS
#define SE_OC_ACCOUNTS 1
#endif
#ifndef SE_OC_QUOTA
#define SE_OC_QUOTA 4
#endif
struct se_oc_account;
struct se_oc_charge;
struct se_oc_sequence;
static struct se_oc_account *account_lookup(__u32 slot);
static struct se_oc_charge *charge_lookup(__u32 slot);
static struct se_oc_sequence *sequence_lookup(void);
#define SE_OC_ACCOUNT_LOOKUP(slot) account_lookup(slot)
#define SE_OC_CHARGE_LOOKUP(slot) charge_lookup(slot)
#define SE_OC_SEQUENCE_LOOKUP() sequence_lookup()
static void steal_chosen_slot(__u32 slot);
#define SE_OC_AFTER_CHOOSE(slot) steal_chosen_slot(slot)
#include "shared_pool_opaque_charge_candidate.h"
#include "shared_pool_opaque_refund_candidate.h"
#include "shared_route.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#include "shared_exec.h"
struct observation {
	struct fe_facts facts;
	struct fe_scratch evaluator;
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
	union {
		char argument[4097];
		struct fe_stage_cursor stage_cursor;
		struct {
			struct fe_stage_cursor cursor;
			struct fm_global_token token;
		} stage_workspace;
	};
#else
	char argument[4097];
#endif
};
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
_Static_assert(
	sizeof(struct observation) == 16008 &&
		sizeof(((struct observation *)0)->stage_workspace) <= 4097 &&
		__builtin_offsetof(struct observation, argument) ==
			__builtin_offsetof(struct observation, stage_cursor) &&
		__builtin_offsetof(struct observation, stage_cursor) % 8 == 0,
	"candidate cursor overlay must preserve WORK observation ABI");
#endif
#include "shared_invocation_wire.h"
#endif
static struct se_route_anchor routes[SE_OC_ACCOUNTS];
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
static struct se_binding_snapshots bindings[SE_OC_ACCOUNTS];
static struct se_binding_snapshots *binding_lookup(__u32 slot)
{
	assert(!held);
	return slot < SE_OC_ACCOUNTS ? &bindings[slot] : NULL;
}
#define SE_OWK_BINDING_LOOKUP(slot) binding_lookup(slot)
#endif
static int recycle_race;
static struct se_route_anchor *route_lookup(__u32 slot)
{
	assert(!held);
	return slot < SE_OC_ACCOUNTS ? &routes[slot] : NULL;
}
static void after_recycle_account_check(void)
{
	if (!recycle_race)
		return;
	assert(!held);
	recycle_race = 0;
	routes[0].phase = SE_ROUTE_ACTIVE;
	routes[0].scope = 11;
	routes[0].incarnation++;
}
#define SE_OC_ROUTE_LOOKUP(slot) route_lookup(slot)
#define SE_OC_AFTER_RECYCLE_ACCOUNT_CHECK() after_recycle_account_check()
#include "shared_pool_opaque_route_candidate.h"
static void *payload_lookup(__u32 slot);
#define SE_OL_PAYLOAD_LOOKUP(slot) payload_lookup(slot)
#include "shared_pool_opaque_payload_handle_candidate.h"
#include "shared_pool_opaque_final_semantic_candidate.h"
#define SE_OL_TASK_OPEN_AFTER_HOLD() open_race()
#include "shared_pool_opaque_task_open_candidate.h"
#define SE_OWK_ACCOUNTS SE_OC_ACCOUNTS
#ifndef SE_OWK_QUOTA
#define SE_OWK_QUOTA 16
#endif
#define SE_OWK_WORKS (SE_OWK_ACCOUNTS * SE_OWK_QUOTA)
struct se_owk_account;
struct se_owk_charge;
struct se_owk_sequence;
static struct se_owk_account *work_account_lookup(__u32 slot);
static struct se_owk_charge *work_charge_lookup(__u32 slot);
static struct se_owk_sequence *work_sequence_lookup(void);
static struct se_owk_meta *work_meta_lookup(__u32 slot);
static struct se_owk_payload *work_payload_lookup(__u32 slot);
static int work_payload_zero(__u32 slot);
static void after_work_pin(void);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
static void after_work_resume_claim(void);
#endif
#define SE_OWK_ACCOUNT_LOOKUP(slot) work_account_lookup(slot)
#define SE_OWK_CHARGE_LOOKUP(slot) work_charge_lookup(slot)
#define SE_OWK_SEQUENCE_LOOKUP() work_sequence_lookup()
#define SE_OWK_META_LOOKUP(slot) work_meta_lookup(slot)
#define SE_OWK_PAYLOAD_LOOKUP(slot) work_payload_lookup(slot)
#define SE_OWK_PAYLOAD_ZERO(slot) work_payload_zero(slot)
#define SE_OWK_AFTER_PIN() after_work_pin()
#include "shared_pool_opaque_work_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
#define SE_OWK_RESUME_AFTER_CLAIM() after_work_resume_claim()
#include "shared_pool_opaque_work_continuation_candidate.h"
#endif
#ifdef ENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE
static __u64 suspended_current_task_key;
#define SE_OWK_CURRENT_TASK() suspended_current_task_key
#include "shared_pool_opaque_work_suspended_read_candidate.h"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#include "shared_pool_opaque_work_semantic_candidate.h"
#include "shared_pool_opaque_work_eval_candidate.h"
#include "shared_catalogue_wire.h"
static __u64 opaque_catalogue_epoch = 13;
static __u64 opaque_host_catalogue_epoch(__u64 scope, __u64 uid)
{
	/* Model a present index, including the malformed-cell/foreign-key
	 * distinction used by the real publication catalogue. */
	const struct se_epoch_cell cell = { .scope = 10,
					    .uid = 1,
					    .epoch = opaque_catalogue_epoch };
	return se_catalogue_indexed_read(1, &cell, scope, uid);
}
#define SE_OWK_CATALOGUE_EPOCH(scope, uid) \
	opaque_host_catalogue_epoch((scope), (uid))
#include "shared_pool_opaque_work_catalogue_candidate.h"
#endif
#include "shared_pool_opaque_work_reap_candidate.h"
static int payload_zero(__u32 slot);
#define SE_OP_PAYLOAD_INIT(slot) payload_zero(slot)
#include "shared_pool_opaque_task_semantic_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
#include "shared_pool_opaque_birth_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#include "shared_pool_opaque_inherit_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
#include "shared_pool_opaque_exec_reader_candidate.h"
#include "shared_pool_opaque_exec_work_completion_candidate.h"
#endif
#endif
#endif
#define SE_OP_PAYLOAD_ZERO(slot) payload_zero(slot)
#include "shared_pool_opaque_payload_zero_candidate.h"
static struct se_ol_meta metas[SE_OL_TASKS];
static struct se_oc_account accounts[SE_OC_ACCOUNTS];
static struct se_oc_charge charges[SE_OL_TASKS];
static struct se_oc_sequence sequence;
static struct se_owk_account work_accounts[SE_OWK_ACCOUNTS];
static struct se_owk_charge work_charges[SE_OWK_WORKS];
static struct se_owk_sequence work_sequence;
static struct se_owk_meta work_metas[SE_OWK_WORKS];
static struct se_owk_payload work_payloads[SE_OWK_WORKS];
static int work_payload_zero_fail;
static int work_pin_race;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
static int resume_death_race_mode;
#endif
static struct se_oc_reservation stolen[8];
static unsigned steal_remaining, steal_calls;
static struct se_pool_task_wire payloads[SE_OL_TASKS];
static int payload_zero_fail;
static int payload_missing;

static struct se_owk_account *work_account_lookup(__u32 slot)
{
	assert(!held);
	return slot < SE_OWK_ACCOUNTS ? &work_accounts[slot] : NULL;
}
static struct se_owk_charge *work_charge_lookup(__u32 slot)
{
	assert(!held);
	return slot < SE_OWK_WORKS ? &work_charges[slot] : NULL;
}
static struct se_owk_sequence *work_sequence_lookup(void)
{
	assert(!held);
	return &work_sequence;
}
static struct se_owk_meta *work_meta_lookup(__u32 slot)
{
	assert(!held);
	return slot < SE_OWK_WORKS ? &work_metas[slot] : NULL;
}
static struct se_owk_payload *work_payload_lookup(__u32 slot)
{
	assert(!held);
	return slot < SE_OWK_WORKS ? &work_payloads[slot] : NULL;
}
static int work_payload_zero(__u32 slot)
{
	assert(!held && slot < SE_OWK_WORKS);
	if (work_payload_zero_fail)
		return -1;
	memset(&work_payloads[slot], 0, sizeof(work_payloads[slot]));
	return 0;
}
static void after_work_pin(void)
{
	if (!work_pin_race)
		return;
	assert(!held);
	int mode = work_pin_race;
	work_pin_race = 0;
	struct task_struct *physical =
		(struct task_struct *)(unsigned long)0xa1;
	struct se_of_lease dying = {};
	assert(se_of_record_death(physical, &dying) == SE_OL_OK &&
	       metas[0].work_refs == 1 &&
	       !(metas[0].cleanup_done & SE_OL_WORK_DONE));
	assert(se_of_release(&dying, physical) == SE_OL_OK);
	if (mode == 1) {
		work_accounts[0].scope = 11;
		work_accounts[0].incarnation = 2;
	}
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
static void after_work_resume_claim(void)
{
	if (!resume_death_race_mode)
		return;
	resume_death_race_mode = 0;
	assert(!held);
	struct task_struct *physical =
		(struct task_struct *)(unsigned long)0xa1;
	struct se_of_lease dying = {};
	assert(se_of_record_death(physical, &dying) == SE_OL_OK);
	assert(se_of_release(&dying, physical) == SE_OL_OK);
}
#endif

static void *payload_lookup(__u32 slot)
{
	assert(!held);
	return slot < SE_OL_TASKS && !payload_missing ? &payloads[slot] : NULL;
}

static int payload_zero(__u32 slot)
{
	assert(!held && slot < SE_OL_TASKS);
	if (payload_zero_fail)
		return -1;
	memset(&payloads[slot], 0, sizeof(payloads[slot]));
	return 0;
}

static int archive_copy(__u32 slot, const void *opaque_key)
{
	assert(!held && slot < SE_OL_TASKS && opaque_key);
	archives[slot] = *(const __u64 *)opaque_key;
	return archive_fail ? -1 : 0; /* simulate a partial-copy failure */
}
static int archive_zero(__u32 slot)
{
	assert(!held && slot < SE_OL_TASKS);
	if (archive_zero_fail)
		return -1;
	archives[slot] = 0;
	return 0;
}
static const __u64 *archive_lookup(__u32 slot)
{
	assert(!held && slot < SE_OL_TASKS);
	lookups++;
	return &archives[slot];
}
static int insert_zero(const void *opaque_key)
{
	assert(!held && opaque_key);
	__u64 key = *(const __u64 *)opaque_key;
	for (unsigned i = 0; i < 2; i++)
		if (cells[i].present && cells[i].key == key) {
			if (vanish_after_eexist) {
				/* A reaper deletes the colliding key right after
				 * this EEXIST, before replacement observes it. */
				vanish_after_eexist = 0;
				cells[i].present = 0;
			}
			return SE_OL_CONTENDED;
		}
	for (unsigned i = 0; i < 2; i++)
		if (!cells[i].present) {
			cells[i] = (struct cell){ key, 0, 1 };
			return SE_OL_OK;
		}
	return SE_OL_LIMIT;
}
static int delete_key(const void *opaque_key)
{
	assert(!held && opaque_key);
	if (delete_busy)
		return SE_OL_CONTENDED;
	__u64 key = *(const __u64 *)opaque_key;
	for (unsigned i = 0; i < 2; i++) {
		if (!cells[i].present || cells[i].key != key)
			continue;
		assert(cells[i].locator == 0);
		cells[i].present = 0;
		if (insert_successor_after_delete) {
			insert_successor_after_delete = 0;
			assert(se_ow_insert_zero(&metas[1], 202,
						 &archives[1]) == SE_OL_OK);
		}
		return SE_OL_OK;
	}
	return SE_OL_CORRUPT;
}

static const __u64 *lookup(const void *opaque_key)
{
	assert(!held && opaque_key);
	lookups++;
	for (unsigned i = 0; i < 2; i++)
		if (cells[i].present &&
		    cells[i].key == *(const __u64 *)opaque_key) {
			const __u64 *first = &cells[i].locator;
			if (recycle_first_lookup_to_b) {
				recycle_first_lookup_to_b = 0;
				cells[1].present = 0;
				cells[i] = (struct cell){ 0xb2,
							  metas[1].locator, 1 };
			}
			return first;
		}
	return NULL;
}
static struct se_ol_meta *meta_lookup(__u32 slot)
{
	assert(!held);
	lookups++;
	return slot < SE_OL_TASKS ? &metas[slot] : NULL;
}
static struct se_oc_account *account_lookup(__u32 slot)
{
	assert(!held);
	return slot < SE_OC_ACCOUNTS ? &accounts[slot] : NULL;
}
static struct se_oc_charge *charge_lookup(__u32 slot)
{
	assert(!held);
	return slot < SE_OL_TASKS ? &charges[slot] : NULL;
}
static struct se_oc_sequence *sequence_lookup(void)
{
	assert(!held);
	return &sequence;
}
static void steal_chosen_slot(__u32 slot)
{
	if (!steal_remaining)
		return;
	unsigned at = steal_calls++;
	assert(at < 8);
	steal_remaining--;
	assert(se_oc_reserve(0, 10, 1, slot, &stolen[at]) == SE_OL_OK);
}
static void reset(void)
{
	memset(cells, 0, sizeof(cells));
	memset(metas, 0, sizeof(metas));
	memset(archives, 0, sizeof(archives));
	memset(accounts, 0, sizeof(accounts));
	memset(charges, 0, sizeof(charges));
	memset(&sequence, 0, sizeof(sequence));
	memset(work_accounts, 0, sizeof(work_accounts));
	memset(work_charges, 0, sizeof(work_charges));
	memset(&work_sequence, 0, sizeof(work_sequence));
	memset(work_metas, 0, sizeof(work_metas));
	memset(work_payloads, 0, sizeof(work_payloads));
	work_payload_zero_fail = 0;
	work_pin_race = 0;
	memset(routes, 0, sizeof(routes));
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
	memset(bindings, 0, sizeof(bindings));
#endif
	recycle_race = 0;
	memset(stolen, 0, sizeof(stolen));
	steal_remaining = steal_calls = 0;
	memset(payloads, 0, sizeof(payloads));
	payload_zero_fail = 0;
	payload_missing = 0;
	accounts[0].scope = 10;
	accounts[0].incarnation = 1;
	held = NULL;
	lock_errors = lookups = 0;
	archive_fail = archive_zero_fail = delete_busy = 0;
	insert_successor_after_delete = 0;
	replace_cas_fault = 0;
	vanish_after_eexist = 0;
	recycle_first_lookup_to_b = 0;
	open_race_mode = 0;
}
static void open_race(void)
{
	assert(!held);
	switch (open_race_mode) {
	case 1:
		cells[0].present = 0;
		break; /* key disappeared */
	case 2:
		metas[0].reserved = 1;
		break; /* cancelable contradiction */
	case 3:
		metas[0].cookie++;
		break; /* generation contradiction */
	}
	open_race_mode = 0;
}
static __u64 live(__u32 slot, __u64 key, unsigned cell)
{
	__u64 locator = 0;
	assert(slot < SE_OL_TASKS && cell < 2);
	assert(se_ol_next_locator(slot, 0, &locator) == SE_OL_OK);
	metas[slot].locator = locator;
	metas[slot].cookie = 100 + slot;
	metas[slot].phase = SE_OL_LIVE;
	metas[slot].directory_state = SE_OL_PUBLISHED;
	metas[slot].archive_ready = 1;
	cells[cell] = (struct cell){ key, locator, 1 };
	return locator;
}
static void normal_lease(void)
{
	reset();
	__u64 a = 0xa1;
	live(0, a, 0);
	struct se_ol_observation observation = { 0 };
	struct se_ol_lease lease = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ol_hold_observation(&observation) == SE_OL_OK);
	assert(metas[0].reader_holds == 1);
	/* A conforming writer must defer withdrawal while this hold exists. */
	assert(metas[0].reader_holds && !metas[0].exclusive);
	assert(se_ol_relookup_convert(&observation, &lease) == SE_OL_OK);
	assert(!metas[0].reader_holds && metas[0].active_leases == 1);
	assert(lease.locator == metas[0].locator &&
	       lease.cookie == metas[0].cookie);
	assert(se_ol_release_lease(&lease) == SE_OL_OK);
	assert(!metas[0].active_leases && !lease.held);
	assert(!held && !lock_errors && lookups == 3);
}
static void recycled_backing_wrong_key(void)
{
	reset();
	__u64 a = 0xa1, b = 0xb2;
	live(0, a, 0);
	live(1, b, 1);
	struct se_ol_observation observation = { 0 };
	struct se_ol_lease lease = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	/* Delete A and reuse its physical HASH cell for B before scalar read. */
	cells[1].present = 0;
	cells[0] = (struct cell){ b, metas[1].locator, 1 };
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(observation.slot == 1);
	assert(se_ol_hold_observation(&observation) == SE_OL_OK);
	assert(se_ol_relookup_convert(&observation, &lease) == SE_OL_STALE);
	assert(!metas[1].reader_holds && !metas[1].active_leases);
	assert(!lease.held && observation.stage == SE_OL_RELEASED);
	assert(!held && !lock_errors);
}
static void same_key_successor_before_hold(void)
{
	reset();
	__u64 a = 0xa1;
	__u64 first = live(0, a, 0), next = 0;
	struct se_ol_observation observation = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ol_next_locator(0, first, &next) == SE_OL_OK);
	metas[0].locator = cells[0].locator = next;
	metas[0].cookie++;
	assert(se_ol_hold_observation(&observation) == SE_OL_STALE);
	assert(!metas[0].reader_holds && !metas[0].active_leases);
	assert(!held && !lock_errors);
}
static void original_key_disappears_after_hold(void)
{
	reset();
	__u64 a = 0xa1;
	live(0, a, 0);
	struct se_ol_observation observation = { 0 };
	struct se_ol_lease lease = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ol_hold_observation(&observation) == SE_OL_OK);
	/* Simulate an inconsistent writer; observer must not grant a lease. */
	cells[0].present = 0;
	assert(se_ol_relookup_convert(&observation, &lease) == SE_OL_STALE);
	assert(!metas[0].reader_holds && !lease.held);
	assert(!held && !lock_errors);
}
static void locator_bounds(void)
{
	__u64 next = 0;
	__u32 slot = ~0U;
	assert(se_ol_decode(0, &slot) == SE_OL_STALE);
	assert(se_ol_decode((1ULL << SE_OL_SLOT_BITS) | SE_OL_TASKS, &slot) ==
	       SE_OL_STALE);
	assert(se_ol_next_locator(0, 0, &next) == SE_OL_OK);
	assert(se_ol_decode(next, &slot) == SE_OL_OK && slot == 0);
	assert(se_ol_next_locator(1, next, &next) == SE_OL_CORRUPT);
	assert(se_ol_next_locator(0, SE_OL_MAX_GENERATION << SE_OL_SLOT_BITS,
				  &next) == SE_OL_LIMIT);
}
static void contradiction_retains_hold(void)
{
	reset();
	__u64 a = 0xa1;
	live(0, a, 0);
	struct se_ol_observation observation = { 0 };
	struct se_ol_lease lease = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ol_hold_observation(&observation) == SE_OL_OK);
	metas[0].cookie++; /* a writer violating the hold protocol */
	assert(se_ol_relookup_convert(&observation, &lease) == SE_OL_CORRUPT);
	assert(metas[0].reader_holds == 1 && !lease.held);
	assert(observation.stage == SE_OL_HELD && !held && !lock_errors);
}
static void new_key_withdraw_and_successor(void)
{
	reset();
	__u64 a = 0xa1, locator = 0;
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	assert(locator == (1ULL << SE_OL_SLOT_BITS));
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_OK);
	assert(archives[0] == a && metas[0].archive_ready);
	assert(se_ow_insert_zero(&metas[0], 101, &archives[0]) == SE_OL_OK);
	assert(metas[0].directory_state == SE_OL_ZERO_OWNED);
	assert(lookup(&a) && !*lookup(&a));
	struct se_ol_observation zero = { 0 };
	assert(se_ol_observe(&a, &zero) == SE_OL_OK);
	assert(se_ol_read_observation(&zero) == SE_OL_STALE);
	assert(se_ow_publish_zero(&metas[0], 101, &archives[0]) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_PENDING_BIRTH &&
	       metas[0].directory_state == SE_OL_PUBLISHED);
	assert(*lookup(&a) == locator);
	assert(se_ow_finish_birth(&metas[0], 101) == SE_OL_OK);
	assert(metas[0].cleanup_done == SE_OL_CONSTRUCTION_DONE);
	struct se_ol_observation observation = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ol_hold_observation(&observation) == SE_OL_OK);
	metas[0].phase =
		SE_OL_DEAD; /* actual task_free authority is out of scope */
	assert(se_ow_claim_withdraw(&metas[0], 101) == SE_OL_CONTENDED);
	assert(se_ol_cancel_observation(&observation) == SE_OL_OK);
	assert(se_ow_claim_withdraw(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_advance_withdraw(&metas[0], 101, &archives[0]) ==
	       SE_OL_OK);
	assert(*lookup(&a) == 0 &&
	       metas[0].directory_state == SE_OL_WITHDRAWN_ZERO &&
	       !(metas[0].cleanup_done & SE_OL_DIR_DONE));
	delete_busy = 1;
	assert(se_ow_delete_withdrawn_zero(&metas[0], 101, &archives[0]) ==
	       SE_OL_CONTENDED);
	assert(*lookup(&a) == 0 &&
	       metas[0].directory_state == SE_OL_WITHDRAWN_ZERO &&
	       !(metas[0].cleanup_done & SE_OL_DIR_DONE));
	delete_busy = 0;
	assert(se_ow_begin(&metas[1], 1, 202, &locator) == SE_OL_OK);
	assert(se_ow_archive(&metas[1], 1, 202, &a) == SE_OL_OK);
	insert_successor_after_delete = 1;
	assert(se_ow_delete_withdrawn_zero(&metas[0], 101, &archives[0]) ==
	       SE_OL_OK);
	assert(metas[0].directory_state == SE_OL_DELETED &&
	       !metas[0].exclusive &&
	       metas[0].cleanup_done ==
		       (SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE));
	assert(metas[1].directory_state == SE_OL_ZERO_OWNED);
	assert(lookup(&a) && *lookup(&a) == 0);
	assert(se_ow_publish_zero(&metas[1], 202, &archives[1]) == SE_OL_OK);
	assert(se_ow_finish_birth(&metas[1], 202) == SE_OL_OK);
	assert(*lookup(&a) == metas[1].locator &&
	       metas[1].locator != metas[0].locator);
	assert(se_ow_delete_withdrawn_zero(&metas[0], 101, &archives[0]) ==
	       SE_OL_CORRUPT);
	assert(*lookup(&a) == metas[1].locator && !held && !lock_errors);
}
static void writer_failures_retain_charge(void)
{
	reset();
	__u64 a = 0xa1, locator = 0;
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	archive_fail = 1;
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_CONTENDED);
	assert(metas[0].archive_ready == 2 && archives[0] == a && !lookup(&a));
	assert(se_ow_insert_zero(&metas[0], 101, &archives[0]) ==
	       SE_OL_CONTENDED);
	assert(se_ow_abort_constructor(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_mark_absent_deleted(&metas[0], 101) == SE_OL_OK);
	assert(metas[0].cleanup_done ==
	       (SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE));
	assert(se_ow_zero_archive(&metas[0], 101) == SE_OL_OK);
	assert(!archives[0] && metas[0].phase == SE_OL_ARCHIVE_ZEROED);
	reset();
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_OK);
	cells[0] = (struct cell){ 0xb2, 1, 1 };
	cells[1] = (struct cell){ 0xc3, 1, 1 };
	assert(se_ow_insert_zero(&metas[0], 101, &archives[0]) == SE_OL_LIMIT);
	assert(metas[0].directory_state == SE_OL_NO_ENTRY &&
	       metas[0].cookie == 101 && metas[0].active_leases == 1);
	cells[1].present = 0;
	assert(se_ow_insert_zero(&metas[0], 101, &archives[0]) == SE_OL_OK);
	__u64 *value = (__u64 *)lookup(&a);
	assert(value && !*value);
	*value = 123; /* structural contradiction: CAS must not publish */
	assert(se_ow_publish_zero(&metas[0], 101, &archives[0]) ==
	       SE_OL_CORRUPT);
	assert(metas[0].directory_state == SE_OL_PUBLISH_INTENT &&
	       metas[0].phase == SE_OL_INITIALIZING &&
	       metas[0].active_leases == 1);
	assert(!held && !lock_errors);
}
static void post_cas_withdrawal_receipt_retry(void)
{
	reset();
	__u64 a = 0xa1;
	live(0, a, 0);
	archives[0] = a;
	metas[0].phase = SE_OL_DEAD;
	assert(se_ow_claim_withdraw(&metas[0], 100) == SE_OL_OK);
	assert(metas[0].directory_state == SE_OL_WITHDRAW_CLAIM);
	/* The old reaper's locator->zero CAS succeeded, but its receipt did
	 * not commit. A fresh invocation must promote the same charged claim. */
	cells[0].locator = 0;
	assert(se_ow_advance_withdraw(&metas[0], 100, &archives[0]) ==
	       SE_OL_OK);
	assert(metas[0].directory_state == SE_OL_WITHDRAWN_ZERO);
	assert(se_ow_delete_withdrawn_zero(&metas[0], 100, &archives[0]) ==
	       SE_OL_OK);
	assert(metas[0].directory_state == SE_OL_DELETED && !lookup(&a) &&
	       !held && !lock_errors);
}
static void aborted_before_hash_insert(void)
{
	reset();
	__u64 a = 0xa1, locator = 0;
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	archive_fail = 1;
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_CONTENDED);
	assert(se_ow_abort_constructor(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_mark_absent_deleted(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_zero_archive(&metas[0], 101) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_ARCHIVE_ZEROED &&
	       metas[0].cookie == 101 && !lookup(&a) && !archives[0]);
	assert(se_ow_begin(&metas[0], 0, 102, &locator) == SE_OL_CONTENDED);
	assert(!held && !lock_errors);

	reset();
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_OK);
	cells[0] = (struct cell){ 0xb2, 1, 1 };
	cells[1] = (struct cell){ 0xc3, 1, 1 };
	assert(se_ow_insert_zero(&metas[0], 101, &archives[0]) == SE_OL_LIMIT);
	assert(se_ow_abort_constructor(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_mark_absent_deleted(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_zero_archive(&metas[0], 101) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_ARCHIVE_ZEROED &&
	       metas[0].cookie == 101 && !archives[0] && cells[0].present &&
	       cells[1].present);
	assert(!held && !lock_errors);
}
static void aborted_zero_owned_cleanup(void)
{
	reset();
	__u64 a = 0xa1, locator = 0;
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_OK);
	assert(se_ow_insert_zero(&metas[0], 101, &archives[0]) == SE_OL_OK);
	assert(se_ow_abort_constructor(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_claim_aborted_zero(&metas[0], 101) == SE_OL_OK);
	delete_busy = 1;
	assert(se_ow_delete_withdrawn_zero(&metas[0], 101, &archives[0]) ==
	       SE_OL_CONTENDED);
	assert(metas[0].directory_state == SE_OL_WITHDRAWN_ZERO);
	delete_busy = 0;
	assert(se_ow_delete_withdrawn_zero(&metas[0], 101, &archives[0]) ==
	       SE_OL_OK);
	archive_zero_fail = 1;
	assert(se_ow_zero_archive(&metas[0], 101) == SE_OL_CONTENDED);
	assert(metas[0].phase == SE_OL_CLEANING && metas[0].archive_ready &&
	       archives[0] == a);
	archive_zero_fail = 0;
	assert(se_ow_zero_archive(&metas[0], 101) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_ARCHIVE_ZEROED &&
	       metas[0].directory_state == SE_OL_DELETED &&
	       metas[0].cookie == 101 && !archives[0] && !lookup(&a) &&
	       metas[0].cleanup_done ==
		       (SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE));
	assert(!held && !lock_errors);
}
static void aborted_publish_intent_reconciliation(void)
{
	reset();
	__u64 a = 0xa1, locator = 0;
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_OK);
	assert(se_ow_insert_zero(&metas[0], 101, &archives[0]) == SE_OL_OK);
	/* Simulate a failed post-CAS receipt: only the exact old locator may
	 * be reconciled. An unrelated value must leave the charge fault-held. */
	metas[0].directory_state = SE_OL_PUBLISH_INTENT;
	cells[0].locator = 123;
	assert(se_ow_abort_constructor(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_reconcile_publish_intent(&metas[0], 101, &archives[0]) ==
	       SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_ABORTED &&
	       metas[0].directory_state == SE_OL_PUBLISH_INTENT &&
	       metas[0].cookie == 101);
	cells[0].locator = locator;
	assert(se_ow_reconcile_publish_intent(&metas[0], 101, &archives[0]) ==
	       SE_OL_OK);
	assert(metas[0].directory_state == SE_OL_PUBLISHED);
	assert(se_ow_claim_withdraw(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_advance_withdraw(&metas[0], 101, &archives[0]) ==
	       SE_OL_OK);
	assert(se_ow_delete_withdrawn_zero(&metas[0], 101, &archives[0]) ==
	       SE_OL_OK);
	assert(se_ow_zero_archive(&metas[0], 101) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_ARCHIVE_ZEROED && !archives[0] &&
	       !lookup(&a) && !held && !lock_errors);
}
static void aborted_publish_intent_before_cas(void)
{
	reset();
	__u64 a = 0xa1, locator = 0;
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_OK);
	assert(se_ow_insert_zero(&metas[0], 101, &archives[0]) == SE_OL_OK);
	metas[0].directory_state = SE_OL_PUBLISH_INTENT;
	assert(*lookup(&a) == 0);
	assert(se_ow_abort_constructor(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_reconcile_publish_intent(&metas[0], 101, &archives[0]) ==
	       SE_OL_OK);
	assert(metas[0].directory_state == SE_OL_ZERO_OWNED);
	assert(se_ow_claim_aborted_zero(&metas[0], 101) == SE_OL_OK);
	assert(se_ow_delete_withdrawn_zero(&metas[0], 101, &archives[0]) ==
	       SE_OL_OK);
	assert(se_ow_zero_archive(&metas[0], 101) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_ARCHIVE_ZEROED && !archives[0] &&
	       !lookup(&a) && !held && !lock_errors);
}
static void unreconciled_insert_intent_remains_charged(void)
{
	reset();
	__u64 a = 0xa1, locator = 0;
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_OK);
	metas[0].directory_state = SE_OL_INSERT_INTENT;
	assert(se_ow_abort_constructor(&metas[0], 101) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_INITIALIZING &&
	       metas[0].active_leases == 1 && metas[0].cookie == 101 &&
	       archives[0] == a);
	assert(!held && !lock_errors);
}
static void replacement_constructor(__u32 slot, __u64 cookie, __u64 key)
{
	__u64 locator = 0;
	assert(se_ow_begin(&metas[slot], slot, cookie, &locator) == SE_OL_OK);
	assert(se_ow_archive(&metas[slot], slot, cookie, &key) == SE_OL_OK);
	assert(archives[slot] == key && metas[slot].locator == locator);
}
static void same_key_replacement_and_old_cleanup(void)
{
	reset();
	__u64 a = 0xa1;
	__u64 old_locator = live(0, a, 0);
	archives[0] = a;
	metas[0].phase = SE_OL_DEAD;
	replacement_constructor(1, 202, a);
	struct se_ol_observation observation = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ow_hold_replacement(&observation) == SE_OL_OK);
	assert(se_ow_claim_withdraw(&metas[0], 100) == SE_OL_CONTENDED);
	assert(se_ow_claim_replacement(&metas[1], 202, &observation,
				       &archives[1]) == SE_OL_OK);
	assert(metas[0].exclusive == 1 &&
	       metas[0].exclusive_owner == metas[1].locator &&
	       !metas[0].reader_holds && observation.stage == SE_OL_EXCLUSIVE);
	assert(se_ow_claim_withdraw(&metas[0], 100) == SE_OL_CONTENDED);
	assert(se_ow_publish_replacement(&metas[1], 202, &observation,
					 &archives[1]) == SE_OL_OK);
	assert(observation.stage == SE_OL_REPLACED &&
	       metas[0].directory_state == SE_OL_DELETED &&
	       (metas[0].cleanup_done & SE_OL_DIR_DONE) &&
	       !metas[0].exclusive && !metas[0].exclusive_owner &&
	       metas[1].directory_state == SE_OL_PUBLISHED &&
	       metas[1].phase == SE_OL_PENDING_BIRTH &&
	       cells[0].locator == metas[1].locator &&
	       cells[0].locator != old_locator);
	assert(se_ow_finish_birth(&metas[1], 202) == SE_OL_OK);
	/* Old cleanup must only zero its archive, never delete the successor. */
	assert(se_ow_delete_withdrawn_zero(&metas[0], 100, &archives[0]) ==
	       SE_OL_CORRUPT);
	assert(se_ow_zero_archive(&metas[0], 100) == SE_OL_OK);
	assert(!archives[0] && metas[0].phase == SE_OL_ARCHIVE_ZEROED &&
	       cells[0].locator == metas[1].locator && !held && !lock_errors);
}
static void replacement_two_reader_holds(void)
{
	reset();
	__u64 a = 0xa1;
	live(0, a, 0);
	archives[0] = a;
	metas[0].phase = SE_OL_DEAD;
	replacement_constructor(1, 202, a);
	struct se_ol_observation first = { 0 }, second = { 0 };
	assert(se_ol_observe(&a, &first) == SE_OL_OK);
	assert(se_ol_read_observation(&first) == SE_OL_OK);
	assert(se_ow_hold_replacement(&first) == SE_OL_OK);
	assert(se_ol_observe(&a, &second) == SE_OL_OK);
	assert(se_ol_read_observation(&second) == SE_OL_OK);
	assert(se_ow_hold_replacement(&second) == SE_OL_OK);
	assert(metas[0].reader_holds == 2);
	assert(se_ow_claim_replacement(&metas[1], 202, &first, &archives[1]) ==
	       SE_OL_CONTENDED);
	assert(first.stage == SE_OL_RELEASED && metas[0].reader_holds == 1);
	assert(se_ow_claim_replacement(&metas[1], 202, &second, &archives[1]) ==
	       SE_OL_OK);
	assert(se_ow_publish_replacement(&metas[1], 202, &second,
					 &archives[1]) == SE_OL_OK);
	assert(cells[0].locator == metas[1].locator && !held && !lock_errors);
}
static void replacement_recycled_wrong_backing(void)
{
	reset();
	__u64 a = 0xa1, b = 0xb2;
	live(0, a, 0);
	live(1, b, 1);
	metas[0].phase = metas[1].phase = SE_OL_DEAD;
	replacement_constructor(2, 202, a);
	struct se_ol_observation observation = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	cells[1].present = 0;
	cells[0] = (struct cell){ b, metas[1].locator, 1 };
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(observation.slot == 1);
	assert(se_ow_hold_replacement(&observation) == SE_OL_OK);
	assert(se_ow_claim_replacement(&metas[2], 202, &observation,
				       &archives[2]) == SE_OL_STALE);
	assert(observation.stage == SE_OL_RELEASED && !metas[1].reader_holds &&
	       !metas[1].exclusive && metas[2].phase == SE_OL_INITIALIZING &&
	       metas[2].active_leases == 1 && !held && !lock_errors);
}
static void replacement_cancel_and_cas_fault(void)
{
	reset();
	__u64 a = 0xa1;
	live(0, a, 0);
	archives[0] = a;
	metas[0].phase = SE_OL_DEAD;
	replacement_constructor(1, 202, a);
	struct se_ol_observation observation = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ow_hold_replacement(&observation) == SE_OL_OK);
	assert(se_ow_claim_replacement(&metas[1], 202, &observation,
				       &archives[1]) == SE_OL_OK);
	assert(se_ow_cancel_replacement_claim(&observation, metas[1].locator) ==
	       SE_OL_OK);
	assert(observation.stage == SE_OL_RELEASED && !metas[0].exclusive &&
	       !metas[0].exclusive_owner &&
	       cells[0].locator == metas[0].locator);
	assert(se_ow_abort_constructor(&metas[1], 202) == SE_OL_OK);
	assert(se_ow_mark_absent_deleted(&metas[1], 202) == SE_OL_OK);
	assert(se_ow_zero_archive(&metas[1], 202) == SE_OL_OK);
	assert(!archives[1] && !held && !lock_errors);
	reset();
	live(0, a, 0);
	archives[0] = a;
	metas[0].phase = SE_OL_DEAD;
	replacement_constructor(1, 202, a);
	observation = (struct se_ol_observation){ 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ow_hold_replacement(&observation) == SE_OL_OK);
	assert(se_ow_claim_replacement(&metas[1], 202, &observation,
				       &archives[1]) == SE_OL_OK);
	cells[0].locator =
		123; /* impossible under conforming exclusive owner */
	assert(se_ow_publish_replacement(&metas[1], 202, &observation,
					 &archives[1]) == SE_OL_CORRUPT);
	assert(observation.stage == SE_OL_CAS_ATTEMPTED &&
	       metas[0].exclusive == 1 &&
	       metas[0].exclusive_owner == metas[1].locator &&
	       metas[0].directory_state == SE_OL_PUBLISHED &&
	       !(metas[0].cleanup_done & SE_OL_DIR_DONE) &&
	       metas[1].directory_state == SE_OL_NO_ENTRY &&
	       metas[1].active_leases == 1 && !held && !lock_errors);
	assert(se_ow_cancel_replacement_claim(&observation, metas[1].locator) ==
	       SE_OL_CORRUPT);
}
static void replacement_refuses_active_old_lease(void)
{
	reset();
	__u64 a = 0xa1;
	live(0, a, 0);
	metas[0].phase = SE_OL_DEAD;
	metas[0].active_leases = 1; /* prior borrower still owns old task */
	replacement_constructor(1, 202, a);
	struct se_ol_observation observation = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ow_hold_replacement(&observation) == SE_OL_OK);
	assert(se_ow_claim_replacement(&metas[1], 202, &observation,
				       &archives[1]) == SE_OL_CONTENDED);
	assert(observation.stage == SE_OL_RELEASED && !metas[0].reader_holds &&
	       !metas[0].exclusive && metas[0].active_leases == 1 && !held &&
	       !lock_errors);
}
static void replacement_invalid_new_releases_old_hold(void)
{
	reset();
	__u64 a = 0xa1;
	live(0, a, 0);
	metas[0].phase = SE_OL_DEAD;
	replacement_constructor(1, 202, a);
	struct se_ol_observation observation = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ow_hold_replacement(&observation) == SE_OL_OK);
	metas[1].active_leases = 0; /* invalid successor constructor */
	assert(se_ow_claim_replacement(&metas[1], 202, &observation,
				       &archives[1]) == SE_OL_CONTENDED);
	assert(observation.stage == SE_OL_RELEASED && !metas[0].reader_holds &&
	       !metas[0].exclusive &&
	       metas[0].directory_state == SE_OL_PUBLISHED && !held &&
	       !lock_errors);
}
static void archived_key_must_be_exact_slot_value(void)
{
	reset();
	__u64 a = 0xa1, locator = 0;
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_OK);
	/* Same key bytes on the caller's stack are not the charged archive. */
	assert(se_ow_insert_zero(&metas[0], 101, &a) == SE_OL_CORRUPT);
	assert(metas[0].directory_state == SE_OL_NO_ENTRY && !lookup(&a));
	assert(se_ow_insert_zero(&metas[0], 101, &archives[0]) == SE_OL_OK);
	assert(se_ow_publish_zero(&metas[0], 101, &a) == SE_OL_CORRUPT);
	assert(metas[0].directory_state == SE_OL_ZERO_OWNED && !*lookup(&a) &&
	       !held && !lock_errors);
	reset();
	live(0, a, 0);
	metas[0].phase = SE_OL_DEAD;
	archives[0] = a;
	replacement_constructor(1, 202, a);
	struct se_ol_observation observation = { 0 };
	assert(se_ol_observe(&a, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ow_hold_replacement(&observation) == SE_OL_OK);
	/* Old slot's archive contains identical bytes but is not new authority. */
	assert(se_ow_claim_replacement(&metas[1], 202, &observation,
				       &archives[0]) == SE_OL_CORRUPT);
	assert(observation.stage == SE_OL_RELEASED && !metas[0].reader_holds &&
	       !metas[0].exclusive && metas[1].active_leases == 1 && !held &&
	       !lock_errors);
}
static void typed_final_free_records_exact_death(void)
{
	reset();
	__u64 a = 0xa1;
	live(0, a, 0);
	struct task_struct *physical = (struct task_struct *)(unsigned long)a;
	struct se_of_lease lease = { 0 };
	assert(se_of_record_death(physical, &lease) == SE_OL_OK);
	assert(lease.held == 1 && lease.physical == physical &&
	       lease.meta == &metas[0] && lease.locator == metas[0].locator &&
	       lease.cookie == metas[0].cookie &&
	       metas[0].phase == SE_OL_DEAD && metas[0].active_leases == 1 &&
	       !metas[0].reader_holds &&
	       (metas[0].cleanup_done & SE_OL_WORK_DONE));
	assert(se_of_release(&lease,
			     (struct task_struct *)(unsigned long)0xb2) ==
	       SE_OL_CORRUPT);
	assert(lease.held && metas[0].active_leases == 1);
	assert(se_of_release(&lease, physical) == SE_OL_OK);
	assert(!lease.held && !metas[0].active_leases && !held && !lock_errors);
	assert(se_of_record_death(physical, &lease) == SE_OL_CONTENDED);
}
static void native_empty_owner_receipt_requires_exact_death(void)
{
	reset();
	__u64 key = 0xa1;
	live(0, key, 0);
	struct task_struct *physical = (struct task_struct *)(unsigned long)key;
	struct se_of_lease lease = {};
	assert(se_of_record_death(physical, &lease) == SE_OL_OK);
	assert(se_of_complete_native_unheld(
		       &lease, (struct task_struct *)(unsigned long)0xb2) ==
	       SE_OL_CORRUPT);
	assert(!(metas[0].cleanup_done & SE_OL_NATIVE_DONE));
	metas[0].native_refs = 1;
	assert(se_of_complete_native_unheld(&lease, physical) ==
	       SE_OL_CONTENDED);
	assert(!(metas[0].cleanup_done & SE_OL_NATIVE_DONE));
	metas[0].native_refs = 0;
	assert(se_of_complete_native_unheld(&lease, physical) == SE_OL_OK);
	assert(metas[0].cleanup_done & SE_OL_NATIVE_DONE);
	assert(se_of_complete_native_unheld(&lease, physical) == SE_OL_STALE);
	assert(se_of_release(&lease, physical) == SE_OL_OK);
	assert(se_of_complete_native_unheld(&lease, physical) == SE_OL_CORRUPT);
	assert(!held && !lock_errors);
}
static void death_racing_constructor_finish_stays_dead(void)
{
	reset();
	__u64 a = 0xa1, locator = 0;
	assert(se_ow_begin(&metas[0], 0, 101, &locator) == SE_OL_OK);
	assert(se_ow_archive(&metas[0], 0, 101, &a) == SE_OL_OK);
	assert(se_ow_insert_zero(&metas[0], 101, &archives[0]) == SE_OL_OK);
	assert(se_ow_publish_zero(&metas[0], 101, &archives[0]) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_PENDING_BIRTH &&
	       metas[0].active_leases == 1);
	struct task_struct *physical = (struct task_struct *)(unsigned long)a;
	struct se_of_lease lease = { 0 };
	assert(se_of_record_death(physical, &lease) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_DEAD && metas[0].active_leases == 2);
	assert(se_ow_finish_birth(&metas[0], 101) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_DEAD && metas[0].active_leases == 1 &&
	       metas[0].cleanup_done ==
		       (SE_OL_CONSTRUCTION_DONE | SE_OL_WORK_DONE));
	assert(se_of_release(&lease, physical) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_DEAD && !metas[0].active_leases &&
	       !held && !lock_errors);
}
static void unmatched_final_free_has_no_authority(void)
{
	reset();
	__u64 a = 0xa1;
	live(0, a, 0);
	struct se_of_lease lease = { 0 };
	assert(se_of_record_death((struct task_struct *)(unsigned long)0xb2,
				  &lease) == SE_OL_STALE);
	assert(!lease.held && metas[0].phase == SE_OL_LIVE &&
	       !metas[0].active_leases && !held && !lock_errors);
}
/* Physical-reuse fix: the exact death lease withdraws the directory entry
 * before the address can be reused, with the reaper's three stages. */
static void final_free_withdraws_directory_before_reuse(void)
{
	reset();
	__u64 a = 0xa1, next = 0;
	__u64 locator = live(0, a, 0);
	archives[0] = a;
	struct task_struct *physical = (struct task_struct *)(unsigned long)a;
	struct se_of_lease lease = { 0 };
	assert(se_of_record_death(physical, &lease) == SE_OL_OK);
	/* The reaper cannot claim while the death lease is held. */
	assert(se_ow_claim_withdraw(&metas[0], metas[0].cookie) ==
		       SE_OL_CONTENDED &&
	       metas[0].directory_state == SE_OL_PUBLISHED);
	assert(se_of_withdraw_directory(&lease, physical) == SE_OL_OK);
	assert(!lookup(&a) && metas[0].directory_state == SE_OL_DELETED &&
	       (metas[0].cleanup_done & SE_OL_DIR_DONE) &&
	       !metas[0].exclusive && !metas[0].exclusive_owner &&
	       metas[0].phase == SE_OL_DEAD && metas[0].active_leases == 1 &&
	       metas[0].locator == locator);
	/* No second deleter: neither the hook nor the reaper claims again. */
	assert(se_of_withdraw_directory(&lease, physical) == SE_OL_CONTENDED);
	assert(se_of_release(&lease, physical) == SE_OL_OK &&
	       !metas[0].active_leases);
	assert(se_ow_claim_withdraw(&metas[0], metas[0].cookie) ==
	       SE_OL_CONTENDED);
	/* A successor at the same address inserts fresh (no replacement), and
	 * the reaper resumes the predecessor at the archive wipe. */
	assert(se_ow_begin(&metas[1], 1, 202, &next) == SE_OL_OK);
	assert(se_ow_archive(&metas[1], 1, 202, &a) == SE_OL_OK);
	assert(se_ow_insert_zero(&metas[1], 202, &archives[1]) == SE_OL_OK);
	assert(se_ow_publish_zero(&metas[1], 202, &archives[1]) == SE_OL_OK);
	assert(se_ow_zero_archive(&metas[0], metas[0].cookie) == SE_OL_OK &&
	       metas[0].phase == SE_OL_ARCHIVE_ZEROED && !archives[0]);
	assert(*lookup(&a) == metas[1].locator &&
	       metas[1].directory_state == SE_OL_PUBLISHED);
	assert(!held && !lock_errors);
}
/* Every refusal leaves the state as it is and the reaper path completes. */
static void final_free_withdrawal_falls_back_to_reaper(void)
{
	__u64 a = 0xa1;
	struct task_struct *physical = (struct task_struct *)(unsigned long)a;
	for (int mode = 0; mode < 4; mode++) {
		reset();
		__u64 locator = 0, cookie = 101;
		if (mode == 1) {
			/* Constructor lease still held (death in PENDING_BIRTH). */
			assert(se_ow_begin(&metas[0], 0, cookie, &locator) ==
			       SE_OL_OK);
			assert(se_ow_archive(&metas[0], 0, cookie, &a) ==
			       SE_OL_OK);
			assert(se_ow_insert_zero(&metas[0], cookie,
						 &archives[0]) == SE_OL_OK);
			assert(se_ow_publish_zero(&metas[0], cookie,
						  &archives[0]) == SE_OL_OK);
		} else {
			locator = live(0, a, 0);
			cookie = metas[0].cookie;
			archives[0] = mode == 3 ? 0xb2 : a;
		}
		struct se_ol_observation hold = { 0 };
		if (mode == 0) {
			/* A reader hold taken while LIVE survives the death. */
			assert(se_ol_observe(&a, &hold) == SE_OL_OK);
			assert(se_ol_read_observation(&hold) == SE_OL_OK);
			assert(se_ol_hold_observation(&hold) == SE_OL_OK);
		}
		struct se_of_lease lease = { 0 };
		assert(se_of_record_death(physical, &lease) == SE_OL_OK);
		if (mode == 2)
			delete_busy = 1;
		assert(se_of_withdraw_directory(&lease, physical) ==
		       SE_OL_CONTENDED);
		if (mode == 2) {
			/* Claimed and zeroed: the reaper resumes the delete. */
			assert(metas[0].directory_state ==
				       SE_OL_WITHDRAWN_ZERO &&
			       metas[0].exclusive == 1 &&
			       metas[0].exclusive_owner == locator &&
			       *lookup(&a) == 0);
			delete_busy = 0;
		} else {
			assert(metas[0].directory_state == SE_OL_PUBLISHED &&
			       !metas[0].exclusive &&
			       !metas[0].exclusive_owner &&
			       *lookup(&a) == locator);
		}
		assert(metas[0].phase == SE_OL_DEAD &&
		       !(metas[0].cleanup_done & SE_OL_DIR_DONE));
		if (mode == 1)
			assert(se_ow_finish_birth(&metas[0], cookie) ==
			       SE_OL_OK);
		assert(se_of_release(&lease, physical) == SE_OL_OK);
		if (mode == 0)
			assert(se_ol_cancel_observation(&hold) == SE_OL_OK);
		archives[0] = a;
		if (mode != 2) {
			assert(se_ow_claim_withdraw(&metas[0], cookie) ==
			       SE_OL_OK);
			assert(se_ow_advance_withdraw(&metas[0], cookie,
						      &archives[0]) ==
			       SE_OL_OK);
		}
		assert(se_ow_delete_withdrawn_zero(&metas[0], cookie,
						   &archives[0]) == SE_OL_OK);
		assert(metas[0].directory_state == SE_OL_DELETED &&
		       (metas[0].cleanup_done & SE_OL_DIR_DONE) &&
		       !lookup(&a) && !metas[0].exclusive &&
		       !metas[0].active_leases && !metas[0].reader_holds &&
		       !held && !lock_errors);
	}
}
static void final_free_recycled_backing_cannot_kill_other_task(void)
{
	reset();
	__u64 a = 0xa1, b = 0xb2;
	live(0, a, 0);
	live(1, b, 1);
	recycle_first_lookup_to_b = 1;
	struct se_of_lease lease = { 0 };
	assert(se_of_record_death((struct task_struct *)(unsigned long)a,
				  &lease) == SE_OL_STALE);
	assert(!lease.held && metas[0].phase == SE_OL_LIVE &&
	       metas[1].phase == SE_OL_LIVE && !metas[1].reader_holds &&
	       !metas[1].active_leases && !held && !lock_errors);
}
static void charged_constructor_retains_exact_credit(void)
{
	reset();
	__u64 a = 0xa1;
	struct se_oc_reservation reservation = { 0 }, contender = { 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(reservation.held == 1 && reservation.cookie == 1 &&
	       reservation.account == &accounts[0] &&
	       reservation.charge == &charges[0] &&
	       reservation.meta == &metas[0] && accounts[0].used == 1 &&
	       accounts[0].bits[0] == 1 && charges[0].state == SE_OC_BUILDING);
	assert(se_oc_reserve(0, 10, 1, 0, &contender) == SE_OL_CONTENDED);
	assert(!contender.held && accounts[0].used == 1);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(!reservation.held && reservation.locator == metas[0].locator &&
	       charges[0].state == SE_OC_OWNED &&
	       charges[0].locator == reservation.locator &&
	       charges[0].cookie == metas[0].cookie &&
	       metas[0].account_scope == 10 && metas[0].account_slot == 0 &&
	       metas[0].account_incarnation == 1);
	archive_fail = 1;
	assert(se_ow_archive(&metas[0], 0, reservation.cookie, &a) ==
	       SE_OL_CONTENDED);
	assert(se_ow_abort_constructor(&metas[0], reservation.cookie) ==
	       SE_OL_OK);
	assert(se_ow_mark_absent_deleted(&metas[0], reservation.cookie) ==
	       SE_OL_OK);
	assert(se_ow_zero_archive(&metas[0], reservation.cookie) == SE_OL_OK);
	/* Archive zero alone cannot produce source-owned cleanup receipts or
	 * advance the separate refund tail; the charge remains occupied. */
	assert(metas[0].phase == SE_OL_ARCHIVE_ZEROED &&
	       accounts[0].used == 1 && accounts[0].bits[0] == 1 &&
	       charges[0].state == SE_OC_OWNED && !accounts[0].fault && !held &&
	       !lock_errors);
	contender = (struct se_oc_reservation){ 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &contender) == SE_OL_CONTENDED);
	assert(!contender.held && metas[0].phase == SE_OL_ARCHIVE_ZEROED &&
	       charges[0].state == SE_OC_OWNED && accounts[0].used == 1);
}
static void charged_constructor_faults_do_not_refund(void)
{
	reset();
	struct se_oc_reservation reservation = { 0 };
	assert(se_oc_reserve(0, 11, 1, 0, &reservation) == SE_OL_STALE);
	assert(!accounts[0].used && !accounts[0].bits[0] &&
	       charges[0].state == SE_OC_FREE && !reservation.held);
	reset();
	sequence.next_cookie = SE_OC_COOKIE_LIMIT;
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_LIMIT);
	assert(!accounts[0].used && !charges[0].cookie);
	reset();
	accounts[0].used = 1; /* bitmap/count contradiction */
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_CORRUPT);
	assert(accounts[0].fault && accounts[0].used == 1 &&
	       !accounts[0].bits[0] && !charges[0].cookie);
	reset();
	charges[0].last_returned = 2; /* impossible replay vs global cookie 1 */
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_CORRUPT);
	assert(accounts[0].fault && !accounts[0].used && !accounts[0].bits[0]);
	reset();
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	metas[0].phase = SE_OL_LIVE; /* charged slot has impossible metadata */
	assert(se_oc_begin_charged(&reservation) == SE_OL_CORRUPT);
	assert(accounts[0].fault && accounts[0].used == 1 &&
	       accounts[0].bits[0] == 1 &&
	       charges[0].state == SE_OC_FAULT_HELD && reservation.held == 1 &&
	       !held && !lock_errors);
	reset();
	reservation = (struct se_oc_reservation){ 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	accounts[0].incarnation = 2; /* account changed after charge */
	assert(se_oc_begin_charged(&reservation) == SE_OL_CORRUPT);
	assert(accounts[0].fault && accounts[0].used == 1 &&
	       accounts[0].bits[0] == 1 &&
	       charges[0].state == SE_OC_FAULT_HELD &&
	       metas[0].phase == SE_OL_FREE && !held && !lock_errors);
	reset();
	reservation = (struct se_oc_reservation){ 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	metas[0].account_scope = 99; /* stale original-account metadata */
	assert(se_oc_begin_charged(&reservation) == SE_OL_CORRUPT);
	assert(accounts[0].fault && accounts[0].bits[0] == 1 &&
	       charges[0].state == SE_OC_FAULT_HELD &&
	       metas[0].account_scope == 99 && !held && !lock_errors);
}
static void charged_cookies_are_unique_across_slots(void)
{
	reset();
	struct se_oc_reservation first = { 0 }, second = { 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &first) == SE_OL_OK);
	assert(se_oc_reserve(0, 10, 1, 1, &second) == SE_OL_OK);
	assert(first.cookie == 1 && second.cookie == 2 &&
	       first.cookie != second.cookie && accounts[0].used == 2 &&
	       accounts[0].bits[0] == 3 &&
	       se_oc_bitmap_count(&accounts[0]) == 2);
	assert(se_oc_begin_charged(&first) == SE_OL_OK);
	assert(se_oc_begin_charged(&second) == SE_OL_OK);
	assert(first.locator != second.locator &&
	       charges[0].state == SE_OC_OWNED &&
	       charges[1].state == SE_OC_OWNED &&
	       metas[1].account_scope == 10 &&
	       metas[1].account_incarnation == 1 && !accounts[0].fault &&
	       !held && !lock_errors);
}
static void charged_refund_requires_all_source_receipts(void)
{
	reset();
	struct se_oc_reservation reservation = { 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	__u64 cookie = reservation.cookie;
	assert(se_oc_refund_step(0, cookie) == SE_OC_PENDING);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_oc_refund_step(0, cookie) == SE_OC_PENDING);
	assert(se_ow_abort_constructor(&metas[0], cookie) == SE_OL_OK);
	assert(se_ow_mark_absent_deleted(&metas[0], cookie) == SE_OL_OK);
	assert(se_ow_zero_archive(&metas[0], cookie) == SE_OL_OK);
	assert(metas[0].cleanup_done ==
	       (SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE));
	assert(se_oc_refund_step(0, cookie) == SE_OC_PENDING);
	assert(accounts[0].used == 1 && accounts[0].bits[0] == 1);
	/* Only exec/WORK/native are synthetic here. This is NOT actual process
	 * or thread churn in the selected gadget. */
	metas[0].cleanup_done |= SE_OL_ALL_DONE ^
				 (SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE |
				  SE_OL_NATIVE_DONE | SE_OL_PAYLOAD_ZERO_DONE);
	assert(se_oc_refund_step(0, cookie) == SE_OC_PENDING);
	assert(charges[0].state == SE_OC_OWNED && accounts[0].used == 1);
	metas[0].cleanup_done |= SE_OL_ALL_DONE ^
				 (SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE |
				  SE_OL_PAYLOAD_ZERO_DONE);
	payloads[0].bytes[0] = 0x77;
	payload_zero_fail = 1;
	assert(se_op_zero_payload(0, cookie) == SE_OC_PENDING);
	assert(payloads[0].bytes[0] == 0x77 &&
	       !(metas[0].cleanup_done & SE_OL_PAYLOAD_ZERO_DONE) &&
	       !metas[0].active_leases);
	payload_zero_fail = 0;
	assert(se_op_zero_payload(0, cookie) == SE_OC_PROGRESS);
	assert(!payloads[0].bytes[0] &&
	       (metas[0].cleanup_done & SE_OL_PAYLOAD_ZERO_DONE));
	assert(se_oc_refund_step(0, cookie) == SE_OC_PROGRESS);
	assert(metas[0].phase == SE_OL_REFUND_PENDING);
	assert(se_oc_refund_step(0, cookie) == SE_OC_PROGRESS);
	assert(charges[0].state == SE_OC_RETURN_READY && accounts[0].used == 1);
	assert(se_oc_refund_step(0, cookie) == SE_OC_PROGRESS);
	assert(metas[0].phase == SE_OL_FREE && metas[0].locator);
	assert(charges[0].state == SE_OC_RETURN_READY && accounts[0].used == 1);
	assert(se_oc_refund_step(0, cookie) == SE_OC_RETURNED);
	assert(charges[0].state == SE_OC_FREE && !charges[0].cookie &&
	       charges[0].last_returned == cookie && !accounts[0].used &&
	       !accounts[0].bits[0] && !accounts[0].fault);
	assert(se_oc_refund_step(0, cookie) == SE_OC_ALREADY_RETURNED);
	struct se_oc_reservation successor = { 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &successor) == SE_OL_OK);
	assert(successor.cookie > cookie);
	assert(se_oc_refund_step(0, cookie) == SE_OC_STALE);
	assert(charges[0].cookie == successor.cookie && accounts[0].used == 1);
	assert(!held && !lock_errors);
}
static void charged_refund_refuses_corrupt_metadata(void)
{
	reset();
	struct se_oc_reservation reservation = { 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_ow_abort_constructor(&metas[0], reservation.cookie) ==
	       SE_OL_OK);
	assert(se_ow_mark_absent_deleted(&metas[0], reservation.cookie) ==
	       SE_OL_OK);
	assert(se_ow_zero_archive(&metas[0], reservation.cookie) == SE_OL_OK);
	assert(metas[0].cleanup_done ==
	       (SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE));
	metas[0].cleanup_done |= SE_OL_ALL_DONE ^
				 (SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE |
				  SE_OL_PAYLOAD_ZERO_DONE);
	metas[0].native_refs = 1; /* forged cleanup receipt while still owned */
	assert(se_op_zero_payload(0, reservation.cookie) == SE_OC_PENDING);
	/* Deliberately forge the ZERO bit too: the refund tail must still
	 * reject an outstanding native reference. */
	metas[0].cleanup_done |= SE_OL_PAYLOAD_ZERO_DONE;
	assert(se_oc_refund_step(0, reservation.cookie) == SE_OC_CORRUPT);
	assert(metas[0].phase == SE_OL_ARCHIVE_ZEROED &&
	       accounts[0].used == 1 && accounts[0].bits[0] == 1 &&
	       charges[0].state == SE_OC_OWNED && !held && !lock_errors);
}
static void charged_refund_synthetic_lifetime_churn(void)
{
	reset();
	/* These are 4,097 synthetic constructor/abort/refund cycles, not
	 * process or thread births, kernel callbacks, or source proof. */
	for (unsigned i = 0; i < 4097; i++) {
		struct se_oc_reservation reservation = { 0 };
		assert(se_oc_reserve_any(0, 10, 1, &reservation) == SE_OL_OK &&
		       reservation.task_slot == 0);
		assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
		assert(se_ow_abort_constructor(&metas[0], reservation.cookie) ==
		       SE_OL_OK);
		assert(se_ow_mark_absent_deleted(
			       &metas[0], reservation.cookie) == SE_OL_OK);
		assert(se_ow_zero_archive(&metas[0], reservation.cookie) ==
		       SE_OL_OK);
		assert(metas[0].cleanup_done ==
		       (SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE));
		metas[0].cleanup_done |=
			SE_OL_ALL_DONE ^
			(SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE |
			 SE_OL_PAYLOAD_ZERO_DONE);
		/* The remaining three bits are synthetic in this test only. */
		payloads[0].bytes[0] = 0x77;
		assert(se_op_zero_payload(0, reservation.cookie) ==
		       SE_OC_PROGRESS);
		assert(!payloads[0].bytes[0]);
		assert(se_oc_refund_step(0, reservation.cookie) ==
		       SE_OC_PROGRESS);
		assert(se_oc_refund_step(0, reservation.cookie) ==
		       SE_OC_PROGRESS);
		assert(se_oc_refund_step(0, reservation.cookie) ==
		       SE_OC_PROGRESS);
		assert(se_oc_refund_step(0, reservation.cookie) ==
		       SE_OC_RETURNED);
		assert(!accounts[0].used && !accounts[0].bits[0] &&
		       !accounts[0].fault && charges[0].state == SE_OC_FREE);
	}
	assert(sequence.next_cookie == 4097 && !held && !lock_errors);
}
static void opaque_payload_handle_requires_exact_lease(void)
{
	reset();
	__u64 key = 0xa1;
	struct se_oc_reservation reservation = { 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	payload_zero_fail = 1;
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_CORRUPT);
	assert(reservation.charge->state == SE_OC_OWNED &&
	       reservation.meta->active_leases == 1 && accounts[0].used == 1);
	payload_zero_fail = 0;
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_OK);
	payloads[0].bytes[0] = 0x5a;
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_CORRUPT);
	assert(payloads[0].bytes[0] == 0x5a &&
	       payloads[0].identity.physical_cookie == reservation.cookie &&
	       metas[0].active_leases == 1);
	assert(se_ow_archive(&metas[0], 0, reservation.cookie, &key) ==
	       SE_OL_OK);
	assert(se_ow_insert_zero(&metas[0], reservation.cookie, &archives[0]) ==
	       SE_OL_OK);
	assert(se_ow_publish_zero(&metas[0], reservation.cookie,
				  &archives[0]) == SE_OL_OK);
	charges[0].state = SE_OC_FAULT_HELD;
	assert(se_op_finish_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_PENDING_BIRTH &&
	       metas[0].active_leases == 1);
	charges[0].state = SE_OC_OWNED;
	payloads[0].identity.scope_cookie++;
	assert(se_op_finish_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_PENDING_BIRTH &&
	       metas[0].active_leases == 1 &&
	       !(metas[0].cleanup_done & SE_OL_CONSTRUCTION_DONE));
	payloads[0].identity.scope_cookie--;
	assert(se_op_finish_semantic_birth(&reservation) == SE_OL_OK);
	assert(reservation.terminal == 1);
	assert(se_op_finish_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(se_op_abort_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_LIVE && !metas[0].active_leases &&
	       (metas[0].cleanup_done & SE_OL_CONSTRUCTION_DONE) &&
	       !accounts[0].fault && charges[0].state == SE_OC_OWNED);
	struct se_ol_observation observation = { 0 };
	struct se_ol_lease lease = { 0 };
	struct se_ol_payload_handle handle = { 0 };
	assert(se_ol_observe(&key, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ol_hold_observation(&observation) == SE_OL_OK);
	assert(se_ol_relookup_convert(&observation, &lease) == SE_OL_OK);
	assert(se_ol_payload_open(&lease, &handle) == SE_OL_OK);
	assert(!lease.held && handle.lease.held &&
	       handle.payload == &payloads[0] && metas[0].active_leases == 1);
	void *semantic = NULL;
	/* A charged locator cannot expose a mismatched or unlive semantic. */
	payloads[0].identity.physical_cookie++;
	assert(se_ol_payload_begin(&handle, &semantic) == SE_OL_CORRUPT);
	assert(!semantic && !held);
	payloads[0].identity.physical_cookie--;
	payloads[0].identity.scope_cookie++;
	assert(se_ol_payload_begin(&handle, &semantic) == SE_OL_CORRUPT);
	assert(!semantic && !held);
	payloads[0].identity.scope_cookie--;
	payloads[0].identity.scope_slot = 1;
	assert(se_ol_payload_begin(&handle, &semantic) == SE_OL_CORRUPT);
	assert(!semantic && !held);
	payloads[0].identity.scope_slot = 0;
	payloads[0].identity.reserved_lock = 1;
	assert(se_ol_payload_begin(&handle, &semantic) == SE_OL_CORRUPT);
	assert(!semantic && !held);
	payloads[0].identity.reserved_lock = 0;
	payloads[0].identity.identity_reserved = 1;
	assert(se_ol_payload_begin(&handle, &semantic) == SE_OL_CORRUPT);
	assert(!semantic && !held);
	payloads[0].identity.identity_reserved = 0;
	payloads[0].identity.flags = 0;
	assert(se_ol_payload_begin(&handle, &semantic) == SE_OL_CORRUPT);
	assert(!semantic && !held);
	payloads[0].identity.flags = SE_OL_TASK_LIVE;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
	struct se_task_state *typed = NULL;
	assert(se_op_task_semantic_begin(&handle, &typed) == SE_OL_OK);
	assert(typed == &payloads[0].semantic &&
	       typed->physical_cookie == reservation.cookie &&
	       held == &metas[0].lock);
	assert(se_op_task_semantic_begin(&handle, &typed) == SE_OL_CORRUPT);
	assert(se_ol_payload_close(&handle) == SE_OL_CORRUPT);
	assert(typed == &payloads[0].semantic && held == &metas[0].lock);
	se_op_task_semantic_end(&handle, &typed);
	assert(!typed && !held);
	payloads[0].semantic.exec = (struct se_exec_transaction){
		.owned = 1,
		.bprm = 0x20,
		.grants = 3,
	};
	assert(se_op_task_note_prior_deny(&handle, 0x10) == SE_OL_OK);
	assert(!payloads[0].semantic.exec.known_deny &&
	       payloads[0].semantic.exec.grants == 3 && !held);
	assert(se_op_task_note_prior_deny(&handle, 0x20) == SE_OL_OK);
	assert(payloads[0].semantic.exec.known_deny &&
	       !payloads[0].semantic.exec.grants && !held);
	assert(se_op_task_owned_fault(&handle, 0x20) == SE_OL_OK);
	assert(payloads[0].semantic.exec.hard_fault && !held);
	assert(se_op_task_note_prior_deny(&handle, 0) == SE_OL_CORRUPT &&
	       !held);
#endif
	assert(se_ol_payload_begin(&handle, &semantic) == SE_OL_OK);
	assert(held == &metas[0].lock && semantic == &payloads[0]);
	assert(se_ol_payload_close(&handle) == SE_OL_CORRUPT);
	assert(handle.lease.held && held == &metas[0].lock);
	((struct se_pool_task_wire *)semantic)->bytes[0] = 0x77;
	assert(se_ol_payload_end(&handle, &semantic) == SE_OL_OK);
	assert(!semantic && !held && payloads[0].bytes[0] == 0x77);
	assert(se_ol_payload_close(&handle) == SE_OL_OK);
	assert(!handle.lease.held && !handle.payload &&
	       !metas[0].active_leases);

	observation = (struct se_ol_observation){ 0 };
	lease = (struct se_ol_lease){ 0 };
	handle = (struct se_ol_payload_handle){ 0 };
	assert(se_ol_observe(&key, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ol_hold_observation(&observation) == SE_OL_OK);
	assert(se_ol_relookup_convert(&observation, &lease) == SE_OL_OK);
	charges[0].state = SE_OC_FAULT_HELD;
	assert(se_ol_payload_open(&lease, &handle) == SE_OL_CORRUPT);
	assert(lease.held && !handle.payload && metas[0].active_leases == 1);
	charges[0].state = SE_OC_OWNED;
	payload_missing = 1;
	assert(se_ol_payload_open(&lease, &handle) == SE_OL_CORRUPT);
	assert(lease.held && !handle.payload && metas[0].active_leases == 1);
	payload_missing = 0;
	assert(se_ol_payload_open(&lease, &handle) == SE_OL_OK);
	metas[0].phase = SE_OL_DEAD; /* task_free races after open */
	assert(se_ol_payload_begin(&handle, &semantic) == SE_OL_STALE);
	assert(!semantic && !held);
	assert(se_ol_payload_close(&handle) == SE_OL_OK);
	assert(!metas[0].active_leases && !lock_errors);
}
static __u64 seed_live_opaque_task_for_open(void)
{
	reset();
	__u64 key = 0xa1;
	struct se_oc_reservation reservation = {};
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_OK);
	assert(se_ow_archive(&metas[0], 0, reservation.cookie, &key) ==
	       SE_OL_OK);
	assert(se_ow_insert_zero(&metas[0], reservation.cookie, &archives[0]) ==
	       SE_OL_OK);
	assert(se_ow_publish_zero(&metas[0], reservation.cookie,
				  &archives[0]) == SE_OL_OK);
	assert(se_op_finish_semantic_birth(&reservation) == SE_OL_OK);
	return key;
}
static void opaque_final_free_has_exact_dead_semantic_lease(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct task_struct *physical = (struct task_struct *)(unsigned long)key;
	struct se_of_lease dying = {};
	struct se_of_semantic_handle semantic = {};
	struct se_pool_task_wire *payload = NULL;
	assert(se_of_record_death(physical, &dying) == SE_OL_OK);
	assert(se_of_semantic_begin(&dying,
				    (struct task_struct *)(unsigned long)0xb2,
				    &semantic, &payload) == SE_OL_CORRUPT);
	assert(!payload && !held && !dying.locked);
	payloads[0].identity.physical_cookie++;
	assert(se_of_semantic_begin(&dying, physical, &semantic, &payload) ==
	       SE_OL_CORRUPT);
	assert(!payload && !held && !dying.locked);
	payloads[0].identity.physical_cookie--;
	assert(se_of_semantic_begin(&dying, physical, &semantic, &payload) ==
	       SE_OL_OK);
	assert(payload == &payloads[0] && held == &metas[0].lock &&
	       dying.locked);
	assert(se_of_semantic_begin(&dying, physical, &semantic, &payload) ==
	       SE_OL_CORRUPT);
	assert(se_of_release(&dying, physical) == SE_OL_CORRUPT);
	payload->identity.next_invocation = 17;
	assert(se_of_semantic_end(&semantic, &payload) == SE_OL_OK);
	assert(!payload && !held && !dying.locked &&
	       payloads[0].identity.next_invocation == 17);
	assert(se_of_release(&dying, physical) == SE_OL_OK);
	assert(!dying.held && !metas[0].active_leases && !lock_errors);
}
static void opaque_work_credit_requires_held_exact_task(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	__u32 slot = 0;
	assert(se_owk_bind_owner(&owner) == SE_OL_CORRUPT);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_CORRUPT);
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_choose(&owner, &slot) == SE_OL_STALE);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(work_accounts[0].scope == 10 &&
	       work_accounts[0].incarnation == 1);
	assert(se_owk_choose(&owner, &slot) == SE_OL_OK && slot == 0);
	assert(se_owk_begin(&owner, slot, &ticket) == SE_OL_OK);
	assert(ticket.held == 1 && ticket.cookie == 1 &&
	       ticket.invocation_sequence == 1 &&
	       ticket.owner_locator == owner.lease.locator &&
	       ticket.owner_cookie == owner.lease.cookie &&
	       ticket.owner_slot == owner.lease.slot && ticket.scope == 10 &&
	       ticket.incarnation == 1 && work_accounts[0].used == 1 &&
	       work_accounts[0].bits == 1 &&
	       work_charges[0].state == SE_OWK_BUILDING &&
	       work_metas[0].phase == SE_OWK_INITIALIZING &&
	       work_metas[0].owner_ref_held == 1 && metas[0].work_refs == 1 &&
	       metas[0].current_work_cookie == ticket.cookie &&
	       work_charges[0].owner_locator == ticket.owner_locator);
	/* The charge cannot be copied into a second ticket or refunded merely
	 * because a callback or TASK lease ended. */
	struct se_owk_ticket duplicate = {};
	assert(se_owk_begin(&owner, 0, &duplicate) == SE_OL_CONTENDED &&
	       !duplicate.held && work_accounts[0].used == 1);
	assert(se_owk_abort_building(&owner, &ticket) == SE_OL_OK &&
	       work_metas[0].phase == SE_OWK_ABORTED &&
	       work_charges[0].state == SE_OWK_OWNED &&
	       metas[0].work_refs == 1 && !metas[0].current_work_owned);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(work_accounts[0].used == 1 && work_charges[0].cookie == 1);
	assert(se_owk_begin(&owner, 1, &duplicate) == SE_OL_CORRUPT);
	assert(!held && !lock_errors);
}
/* chain15 burst-nosync-s6: between a caller's slot choice/cookie and its
 * reserve, a newer WORK was charged, settled and returned at the same slot
 * (by the reaper or the synchronous return). The slot is free and intact;
 * only the caller's cookie is older than the slot's last return. CONTENDED
 * (retry with a fresh cookie), never an account fault; a retry with a
 * newer cookie charges the slot. */
static void opaque_work_reserve_older_cookie_is_contended(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	/* The next cookie this caller allocates is 1; slot 0 already saw 5,
	 * returned completely (its metadata FREE under cookie 5). */
	work_charges[0].last_returned = 5;
	work_metas[0].cookie = 5;
	work_metas[0].cleanup_done = 3;
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_CONTENDED &&
	       !ticket.held && !work_accounts[0].used &&
	       !work_accounts[0].fault && !work_charges[0].cookie);
	work_sequence.next_cookie = 9; /* the retry's cookie is newer */
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK && ticket.held &&
	       work_accounts[0].used == 1 && !work_accounts[0].fault &&
	       work_charges[0].cookie == 10);
	assert(!held && !lock_errors);
}
/* Review M1: a FREE slot whose last return EQUALS the caller's cookie is not
 * a reuse (cookies are unique): it stays an account fault. */
static void opaque_work_reserve_equal_cookie_faults(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	work_charges[0].last_returned = 1; /* the caller's next cookie is 1 */
	work_metas[0].cookie = 1;
	work_metas[0].cleanup_done = 3;
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_CORRUPT &&
	       !ticket.held && work_accounts[0].fault);
	assert(!held && !lock_errors);
}
static void opaque_work_credit_fails_closed_on_owner_or_account_fault(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	metas[0].phase = SE_OL_DEAD;
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_STALE &&
	       !ticket.held && !work_accounts[0].used);
	metas[0].phase = SE_OL_LIVE;
	accounts[0].fault = 1; /* TASK account fault after handle open */
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_CORRUPT &&
	       !ticket.held && !work_accounts[0].used);
	accounts[0].fault = 0;
	metas[0].next_work_sequence = SE_OWK_COOKIE_LIMIT;
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_LIMIT &&
	       !ticket.held && !work_accounts[0].used);
	metas[0].next_work_sequence = 0;
	work_accounts[0].bits = 1; /* impossible uncharged bit */
	assert(se_owk_choose(&owner, &(__u32){ 0 }) == SE_OL_CORRUPT);
	assert(work_accounts[0].fault == 1);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_CORRUPT &&
	       !ticket.held && !work_accounts[0].used);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);

	key = seed_live_opaque_task_for_open();
	owner = (struct se_ol_payload_handle){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	work_accounts[0].used = 1;
	work_accounts[0].bits = 1;
	work_accounts[0].scope = 11;
	work_accounts[0].incarnation = 2;
	assert(se_owk_bind_owner(&owner) == SE_OL_CONTENDED);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_STALE &&
	       !ticket.held && work_accounts[0].bits == 1);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
static void opaque_work_precharge_pin_rolls_back_after_death(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	work_pin_race = 1; /* source TASK death + account incarnation loss */
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_STALE &&
	       !ticket.held && !metas[0].work_refs &&
	       !metas[0].current_work_owned && !metas[0].current_work_cookie &&
	       !metas[0].current_work_slot &&
	       (metas[0].cleanup_done & SE_OL_WORK_DONE) &&
	       !work_accounts[0].used && !work_accounts[0].bits &&
	       !work_charges[0].cookie && !work_pin_race);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);

	key = seed_live_opaque_task_for_open();
	owner = (struct se_ol_payload_handle){};
	ticket = (struct se_owk_ticket){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	work_pin_race = 2; /* source death, but account charge succeeds */
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK && ticket.held &&
	       metas[0].work_refs == 1 && metas[0].phase == SE_OL_DEAD &&
	       !(metas[0].cleanup_done & SE_OL_WORK_DONE));
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_STALE);
	assert(se_owk_abort_building(&owner, &ticket) == SE_OL_OK &&
	       work_metas[0].phase == SE_OWK_ABORTED &&
	       work_charges[0].state == SE_OWK_OWNED &&
	       !metas[0].current_work_owned && metas[0].work_refs == 1);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	__u64 cookie = ticket.cookie;
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS &&
	       !metas[0].work_refs &&
	       (metas[0].cleanup_done & SE_OL_WORK_DONE));
	assert(!held && !lock_errors);
}
static void opaque_work_abort_building_quarantines_faulted_account(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	work_accounts[0].fault = 1; /* account fails after charge */
	assert(se_owk_abort_building(&owner, &ticket) == SE_OL_OK &&
	       work_metas[0].phase == SE_OWK_ABORTED &&
	       work_charges[0].state == SE_OWK_FAULT_HELD &&
	       work_accounts[0].used == 1 && work_accounts[0].bits == 1 &&
	       metas[0].work_refs == 1 && !metas[0].current_work_owned);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(se_owk_reap_step(0, ticket.cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, ticket.cookie) == SE_OWK_PROGRESS &&
	       !metas[0].work_refs);
	assert(!held && !lock_errors);

	key = seed_live_opaque_task_for_open();
	owner = (struct se_ol_payload_handle){};
	ticket = (struct se_owk_ticket){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	work_accounts[0].used++; /* impossible bitmap/count contradiction */
	assert(se_owk_abort_building(&owner, &ticket) == SE_OL_CORRUPT &&
	       work_metas[0].phase == SE_OWK_ABORTED &&
	       work_charges[0].state == SE_OWK_FAULT_HELD &&
	       work_accounts[0].fault && work_accounts[0].bits == 1 &&
	       metas[0].work_refs == 1 && !metas[0].current_work_owned);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
static void opaque_work_credit_partition_and_limit(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	struct se_owk_ticket ticket = {};
	assert(se_owk_begin(&owner, SE_OWK_WORKS, &ticket) == SE_OL_CORRUPT);
#if SE_OWK_ACCOUNTS > 1
	assert(se_owk_begin(&owner, SE_OWK_QUOTA, &ticket) == SE_OL_CORRUPT);
#endif
	for (unsigned i = 0; i < SE_OWK_QUOTA; i++) {
		__u32 selected = 0;
		struct se_owk_ticket next = {};
		assert(se_owk_choose(&owner, &selected) == SE_OL_OK &&
		       selected == i);
		assert(se_owk_begin(&owner, selected, &next) == SE_OL_OK &&
		       next.cookie == i + 1);
		assert(se_owk_abort_building(&owner, &next) == SE_OL_OK);
	}
	__u32 full = 0;
	assert(se_owk_choose(&owner, &full) == SE_OL_LIMIT &&
	       work_accounts[0].used == SE_OWK_QUOTA &&
	       work_accounts[0].bits == se_owk_valid_mask() &&
	       !work_accounts[0].fault);
	/* Exhaustion is transactional: returning one exact completed WORK
	 * reopens only that slot, without touching the other charged owners. */
	__u64 returned_cookie = work_charges[0].cookie;
	for (unsigned step = 0; step < 6; step++)
		assert(se_owk_reap_step(0, returned_cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, returned_cookie) == SE_OWK_RETURNED &&
	       work_accounts[0].used == SE_OWK_QUOTA - 1 &&
	       !(work_accounts[0].bits & 1) &&
	       metas[0].work_refs == SE_OWK_QUOTA - 1);
	full = 0;
	assert(se_owk_choose(&owner, &full) == SE_OL_OK && full == 0);
	struct se_owk_ticket replacement = {};
	assert(se_owk_begin(&owner, full, &replacement) == SE_OL_OK &&
	       replacement.cookie > returned_cookie &&
	       work_accounts[0].used == SE_OWK_QUOTA &&
	       work_accounts[0].bits == se_owk_valid_mask() &&
	       metas[0].work_refs == SE_OWK_QUOTA);
	assert(se_owk_reap_step(0, returned_cookie) == SE_OWK_STALE &&
	       work_charges[0].cookie == replacement.cookie);
	assert(se_owk_abort_building(&owner, &replacement) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
static void opaque_work_credit_reuses_one_slot_for_4097_lifetimes(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	for (unsigned i = 0; i < 4097; i++) {
		__u32 slot = 0;
		struct se_owk_ticket ticket = {};
		assert(se_owk_choose(&owner, &slot) == SE_OL_OK && slot == 0);
		assert(se_owk_begin(&owner, slot, &ticket) == SE_OL_OK &&
		       ticket.cookie == i + 1 &&
		       ticket.invocation_sequence == i + 1);
		assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
		assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
		assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
		assert(se_owk_done(&owner, &ticket) == SE_OL_OK);
		for (unsigned step = 0; step < 6; step++)
			assert(se_owk_reap_step(slot, ticket.cookie) ==
			       SE_OWK_PROGRESS);
		assert(se_owk_reap_step(slot, ticket.cookie) ==
		       SE_OWK_RETURNED);
		assert(!work_accounts[0].fault && !work_accounts[0].used &&
		       !work_accounts[0].bits && !metas[0].work_refs &&
		       !metas[0].current_work_owned &&
		       !(metas[0].cleanup_done & SE_OL_WORK_DONE));
	}
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	struct se_of_lease dying = {};
	assert(se_of_record_death((struct task_struct *)(unsigned long)key,
				  &dying) == SE_OL_OK &&
	       (metas[0].cleanup_done & SE_OL_WORK_DONE));
	assert(se_of_release(&dying,
			     (struct task_struct *)(unsigned long)key) ==
	       SE_OL_OK);
	assert(!held && !lock_errors);
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
static void opaque_work_catalogue_requires_held_authority(void)
{
	for (int unknown = 0; unknown < 2; unknown++) {
		__u64 key = seed_live_opaque_task_for_open();
		struct se_ol_payload_handle owner = {};
		struct se_owk_ticket ticket = {};
		struct se_owk_semantic_handle handle = {};
		struct se_invocation *work = 0;
		__u32 slot = 0;
		assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
		assert(se_owk_bind_owner(&owner) == SE_OL_OK);
		assert(se_owk_choose(&owner, &slot) == SE_OL_OK);
		assert(se_owk_begin(&owner, slot, &ticket) == SE_OL_OK);
		assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
		assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
		assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
		assert(se_owk_semantic_open(&owner, &ticket, &handle, &work) ==
		       SE_OL_OK);
		assert(!se_owk_view_from_identity(slot, ticket.cookie));
		struct fm_global_token token = { .slot = 99, .cookie = 99 };
		assert(se_owk_evaluator_token(&handle, &token) ==
			       SE_OL_CORRUPT &&
		       !token.slot && !token.cookie);
		memset(opaque_policy_blobs, 0, sizeof(opaque_policy_blobs));
		const struct fe_header header = {
			.policies = 1,
			.rule_base = 9,
		};
		struct fe_policy policy = { .uid = 1, .mode = 2 };
		memcpy(&opaque_policy_blobs[0], &header, sizeof(header));
		memcpy(&opaque_policy_blobs[1], &policy, sizeof(policy));
		const struct fe_string container = {
			.length = 1,
			.bytes = { '/' },
		};
		const struct se_policy_ref ref = {
			.slot = 0,
			.generation = 1,
			.root_epoch = 1,
			.entries = 10,
		};
		assert(se_policy_prepare(&work->view, 0, ticket.scope, 1,
					 &container, &ref, 1) &&
		       se_owk_evaluator_token(&handle, &token) ==
			       SE_OL_CORRUPT &&
		       !token.slot && !token.cookie);
		policy.root_role = 1;
		memcpy(&opaque_policy_blobs[1], &policy, sizeof(policy));
		assert(!se_policy_prepare(&work->view, 0, ticket.scope, 1,
					  &container, &ref, 1));
		assert(se_owk_evaluator_token(&handle, &token) == SE_OL_OK &&
		       token.slot == slot && token.cookie == ticket.cookie &&
		       !token.reserved);
		owner.lease.cookie++;
		assert(se_owk_evaluator_token(&handle, &token) ==
			       SE_OL_CORRUPT &&
		       !token.slot && !token.cookie);
		owner.lease.cookie--;
		assert(se_owk_view_from_identity(slot, ticket.cookie) ==
		       &work->view);
		assert(!se_owk_view_from_identity(slot, ticket.cookie + 1) &&
		       !se_owk_view_from_identity(SE_OWK_WORKS, ticket.cookie));
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
		assert(se_owk_view_from_lexical_token(slot, ticket.cookie) ==
		       &work->view);
		assert(!se_owk_view_from_lexical_token(slot,
						       ticket.cookie + 1) &&
		       !se_owk_view_from_lexical_token(SE_OWK_WORKS,
						       ticket.cookie));
#endif
		struct er_state state = { .version = 7 };
		state.rows[0] = er_known_row(1, 13, 3);
		work->history.scope_cookie = ticket.scope;
		er_snapshot(&work->history.view.work, &state, 1);
		struct se_route_claim claim = {
			.scope = ticket.scope,
			.generation = 1,
			.owned = 1,
		};
		claim.generation++;
		assert(se_owk_catalogue_fill(&handle, &claim) ==
			       SE_OL_CORRUPT &&
		       !handle.payload->catalogue.scope);
		claim.generation--;
		owner.lease.cookie++;
		assert(se_owk_catalogue_fill(&handle, &claim) ==
			       SE_OL_CORRUPT &&
		       !handle.payload->catalogue.scope);
		owner.lease.cookie--;
		opaque_catalogue_epoch = unknown ? ER_UNKNOWN : 13;
		int result = se_owk_catalogue_fill(&handle, &claim);
		if (unknown) {
			assert(result == SE_OL_CORRUPT &&
			       !handle.payload->catalogue.scope &&
			       !handle.payload->catalogue.generation);
			/* The source must fault rather than publish on unavailable
			 * COMPLETE history. */
			se_owk_fault_ticket(&ticket);
			assert(work_accounts[0].fault);
			continue;
		}
		assert(result == SE_OL_OK &&
		       handle.payload->catalogue.scope == claim.scope &&
		       handle.payload->catalogue.generation ==
			       claim.generation);
		assert(!se_pool_catalogue_classify(&work->history.view,
						   &handle.payload->catalogue,
						   &claim));
		struct er_work projected = {};
		assert(!er_canonical_project(&work->history.view, &projected));
		assert(se_pool_catalogue_projection_matches(
			&work->history.view, &projected,
			&handle.payload->catalogue, &claim));
		assert(se_owk_catalogue_fill(&handle, &claim) == SE_OL_CORRUPT);
		assert(se_owk_semantic_done(&handle, &work) == SE_OL_OK);
		assert(se_owk_evaluator_token(&handle, &token) ==
			       SE_OL_CORRUPT &&
		       !token.slot && !token.cookie);
		assert(!se_owk_view_from_identity(slot, ticket.cookie));
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
		assert(!se_owk_view_from_lexical_token(slot, ticket.cookie));
#endif
		assert(se_ol_payload_close(&owner) == SE_OL_OK);
	}
	opaque_catalogue_epoch = 13;
	assert(!held && !lock_errors);
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
static void opaque_dead_terminal_requires_source_exec_receipt(void)
{
	const __u64 physical = 0x4321, cookie = 99, locator = 0x4001;
	struct se_ol_meta meta = {
		.phase = SE_OL_DEAD,
		.locator = locator,
		.cookie = cookie,
		.directory_state = SE_OL_PUBLISHED,
		.archive_ready = 1,
		.account_scope = 10,
		.cleanup_done = SE_OL_EXEC_DONE,
	};
	struct se_task_state task = {
		.flags = SE_TASK_LIVE,
		.physical_cookie = cookie,
		.scope_cookie = 10,
		.scope_slot = 0,
		.exec = { .bprm = 0x1234, .sequence = 7, .generation = 3 },
	};
	struct se_exec_terminal_receipt receipt = {
		.physical = physical,
		.bprm = 0x1234,
		.cookie = cookie,
		.locator = locator,
		.invocation = 7,
		.scope = 10,
		.generation = 3,
		.phase = SE_EXEC_TERMINAL_REGISTERED,
	};
#define DEAD_RETIRABLE()                                                  \
	se_exec_terminal_dead_retirable(&meta, &task, &receipt, physical, \
					cookie, locator, 0)
	assert(DEAD_RETIRABLE());
	receipt.phase = SE_EXEC_TERMINAL_SUCCESS;
	assert(DEAD_RETIRABLE());
	receipt.phase = SE_EXEC_TERMINAL_FAILURE;
	assert(DEAD_RETIRABLE());
	meta.active_leases = 1;
	assert(!DEAD_RETIRABLE());
	meta.active_leases = 0;
	meta.cleanup_done = 0;
	assert(!DEAD_RETIRABLE());
	meta.cleanup_done = SE_OL_EXEC_DONE;
	meta.cleanup_error = 1;
	assert(!DEAD_RETIRABLE());
	meta.cleanup_error = 0;
	meta.account_scope = 11;
	assert(!DEAD_RETIRABLE());
	meta.account_scope = 10;
	meta.phase = SE_OL_LIVE;
	assert(!DEAD_RETIRABLE());
	meta.phase = SE_OL_DEAD;
	task.exec.owned = 1;
	assert(!DEAD_RETIRABLE());
	task.exec.owned = 0;
	receipt.invocation++;
	assert(!DEAD_RETIRABLE());
	receipt.invocation--;
	receipt.cookie++;
	assert(!DEAD_RETIRABLE());
	receipt.cookie--;
	receipt.phase = 4;
	assert(!DEAD_RETIRABLE());
	receipt.phase = SE_EXEC_TERMINAL_SUCCESS;
	assert(!se_exec_terminal_dead_retirable(&meta, &task, &receipt,
						physical, cookie, locator,
						SE_OC_ACCOUNTS));
	assert(DEAD_RETIRABLE() && !held && !lock_errors);
#undef DEAD_RETIRABLE
}

static void opaque_exec_reader_begin_uses_exact_task_and_route(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 7,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 1,
		.active_serial = 1,
		.execution_class = 1,
		.phase = SE_ROUTE_ACTIVE,
	};
	bindings[0] = (struct se_binding_snapshots){
		.scope = 10,
		.generation = 1,
		.active_serial = 1,
		.records = { { .scope = 10,
			       .serial = 1,
			       .generation = 1,
			       .phase = SE_SNAPSHOT_ACTIVE,
			       .count = 1,
			       .execution_class = 1,
			       .metadata = { .root_epochs = { 1 },
					     .policy_uids = { 1 },
					     .container_length = 1,
					     .container = "/" } } },
	};
	struct se_route_claim claim = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &claim) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	__u64 invocation = 0;
	bindings[0].records[0].metadata.root_epochs[0] = 0;
	assert(se_op_exec_reader_begin(&owner, &claim, &bindings[0], 0x1234,
				       &invocation) == SE_OL_CORRUPT);
	assert(!invocation && claim.owned && !payloads[0].semantic.exec.owned);
	bindings[0].records[0].metadata.root_epochs[0] = 1;
	assert(se_op_exec_reader_begin(&owner, &claim, &bindings[0], 0x1234,
				       &invocation) == SE_OL_OK);
	assert(invocation == 1 && !claim.owned && !routes[0].early_claims &&
	       bindings[0].records[0].claims == 1 &&
	       payloads[0].semantic.reader.owned &&
	       payloads[0].semantic.reader_invocation == invocation &&
	       payloads[0].semantic.exec.owned);
	/* A later bprm/completion callback must reopen the original physical
	 * TASK; neither the first callback's lease nor its pointer may survive. */
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	owner = (struct se_ol_payload_handle){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	__u64 recovered = 0;
	assert(se_op_exec_reader_recover(&owner, &bindings[0], 0x5678,
					 &recovered) == SE_OL_STALE);
	assert(!recovered);
	assert(se_op_exec_reader_recover(&owner, &bindings[0], 0x1234,
					 &recovered) == SE_OL_OK &&
	       recovered == invocation);
	__u64 duplicate = 0;
	assert(se_op_exec_reader_begin(&owner, &claim, &bindings[0], 0x1234,
				       &duplicate) == SE_OL_CORRUPT);
	assert(!duplicate && payloads[0].semantic.exec.owned &&
	       payloads[0].semantic.reader.owned);
	struct se_route_claim repeated = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &repeated) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	assert(se_op_exec_reader_begin(&owner, &repeated, &bindings[0], 0x1234,
				       &duplicate) == SE_OL_CORRUPT);
	assert(repeated.owned && !duplicate &&
	       payloads[0].semantic.exec.owned &&
	       !(payloads[0].semantic.flags & SE_TASK_QUARANTINED));
	bpf_spin_lock(&routes[0].lock);
	assert(!se_route_release_locked(&routes[0], &repeated));
	assert(se_route_withdraw_locked(&routes[0], &bindings[0]));
	bpf_spin_unlock(&routes[0].lock);
	assert(se_op_exec_reader_finish_bounded(&owner, &bindings[0], 0x1234,
						invocation + 1,
						0) == SE_OL_CORRUPT);
	assert(payloads[0].semantic.exec.owned &&
	       payloads[0].semantic.exec.hard_fault &&
	       payloads[0].semantic.reader.owned &&
	       bindings[0].records[0].claims == 1);
	assert(se_op_exec_reader_finish_bounded(&owner, &bindings[0], 0x1234,
						invocation, 0) == SE_OL_OK);
	assert(!payloads[0].semantic.exec.owned &&
	       !payloads[0].semantic.reader.owned &&
	       !payloads[0].semantic.reader_invocation &&
	       !bindings[0].records[0].claims);
	/* An authenticated terminal retry can recognize the exact already-settled
	 * invocation without touching another TASK or granting a second reader. */
	assert(se_op_exec_reader_settle_success(&owner, &bindings[0], 0x1234,
						invocation, 10, 1) == SE_OL_OK);
	assert(se_op_exec_reader_settle_success(&owner, &bindings[0], 0x1234,
						invocation + 1, 10,
						1) == SE_OL_CORRUPT);
	assert(!bindings[0].records[0].claims && !held && !lock_errors);
	recovered = 0;
	assert(se_op_exec_reader_recover(&owner, &bindings[0], 0x1234,
					 &recovered) == SE_OL_STALE &&
	       !recovered);
	/* Retry after the TASK mutation but before route-reader release. The
	 * terminal must release precisely this invocation's persistent claim. */
	struct se_route_claim partial = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &partial) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	__u64 partial_invocation = 0;
	assert(se_op_exec_reader_begin(&owner, &partial, &bindings[0], 0x9abc,
				       &partial_invocation) == SE_OL_OK);
	struct se_task_state *partial_task = 0;
	assert(se_op_task_semantic_begin(&owner, &partial_task) == SE_OL_OK);
	assert(se_exec_finish_bounded_locked(partial_task, owner.lease.cookie,
					     0x9abc, partial_invocation,
					     1) >= 0);
	se_op_task_semantic_end(&owner, &partial_task);
	assert(!payloads[0].semantic.exec.owned &&
	       payloads[0].semantic.reader.owned &&
	       bindings[0].records[0].claims == 1);
	assert(se_op_exec_reader_settle_success(&owner, &bindings[0], 0x9abc,
						partial_invocation, 11,
						1) == SE_OL_CORRUPT);
	assert(payloads[0].semantic.reader.owned);
	assert(se_op_exec_reader_settle_success(&owner, &bindings[0], 0x9abc,
						partial_invocation, 10,
						1) == SE_OL_OK);
	assert(!payloads[0].semantic.reader.owned &&
	       !bindings[0].records[0].claims && !held && !lock_errors);

	/* A failed original-route handoff must leave neither a live transaction
	 * nor a persistent reader, but must retain the caller's lexical claim. */
	struct se_route_claim stale = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &stale) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	stale.incarnation++;
	duplicate = 0;
	assert(se_op_exec_reader_begin(&owner, &stale, &bindings[0], 0x5678,
				       &duplicate) == SE_OL_CORRUPT);
	assert(!duplicate && stale.owned && !payloads[0].semantic.exec.owned &&
	       !payloads[0].semantic.reader.owned &&
	       !payloads[0].semantic.reader_invocation &&
	       (payloads[0].semantic.flags & SE_TASK_QUARANTINED) &&
	       !bindings[0].records[0].claims);
	stale.incarnation--;
	bpf_spin_lock(&routes[0].lock);
	assert(!se_route_release_locked(&routes[0], &stale));
	assert(!se_route_withdraw_locked(&routes[0], &bindings[0]));
	bpf_spin_unlock(&routes[0].lock);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
static void opaque_exec_reader_unobserved_success_quarantines(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 7,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 1,
		.active_serial = 1,
		.execution_class = 1,
		.phase = SE_ROUTE_ACTIVE,
	};
	bindings[0] = (struct se_binding_snapshots){
		.scope = 10,
		.generation = 1,
		.active_serial = 1,
		.records = { { .scope = 10,
			       .serial = 1,
			       .generation = 1,
			       .phase = SE_SNAPSHOT_ACTIVE,
			       .count = 1,
			       .execution_class = 1,
			       .metadata = { .root_epochs = { 1 },
					     .policy_uids = { 1 },
					     .role_writers = 1,
					     .container_length = 1,
					     .container = "/" } } },
	};
	struct se_route_claim claim = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &claim) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	__u64 invocation = 0;
	assert(se_op_exec_reader_begin(&owner, &claim, &bindings[0], 0x1234,
				       &invocation) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	owner = (struct se_ol_payload_handle){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_op_exec_reader_abort_quarantined(&owner, &bindings[0], 0x1234,
						   invocation + 1) ==
	       SE_OL_CORRUPT);
	assert(payloads[0].semantic.exec.owned &&
	       payloads[0].semantic.reader.owned &&
	       !(payloads[0].semantic.flags & SE_TASK_QUARANTINED) &&
	       payloads[0].semantic.eligibility_version == 1);
	assert(se_op_exec_reader_abort_quarantined(&owner, &bindings[0], 0x1234,
						   invocation) == SE_OL_OK);
	assert(!payloads[0].semantic.exec.owned &&
	       !payloads[0].semantic.reader.owned &&
	       !payloads[0].semantic.reader_invocation &&
	       !bindings[0].records[0].claims &&
	       payloads[0].semantic.exec.hard_fault &&
	       (payloads[0].semantic.flags & SE_TASK_QUARANTINED) &&
	       payloads[0].semantic.eligibility_version == 2);
	bpf_spin_lock(&routes[0].lock);
	assert(!se_route_withdraw_locked(&routes[0], &bindings[0]));
	bpf_spin_unlock(&routes[0].lock);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
static void opaque_exec_reader_failed_recovery_quarantines(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 7,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 1,
		.active_serial = 1,
		.execution_class = 1,
		.phase = SE_ROUTE_ACTIVE,
	};
	bindings[0] = (struct se_binding_snapshots){
		.scope = 10,
		.generation = 1,
		.active_serial = 1,
		.records = { { .scope = 10,
			       .serial = 1,
			       .generation = 1,
			       .phase = SE_SNAPSHOT_ACTIVE,
			       .count = 1,
			       .execution_class = 1,
			       .metadata = { .root_epochs = { 1 },
					     .policy_uids = { 1 },
					     .role_writers = 1,
					     .container_length = 1,
					     .container = "/" } } },
	};
	struct se_route_claim claim = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &claim) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	__u64 invocation = 0;
	assert(se_op_exec_reader_begin(&owner, &claim, &bindings[0], 0x1234,
				       &invocation) == SE_OL_OK);
	/* A contradictory route makes recovery fail before the old helper
	 * invalidates known role history. The exact TASK must be quarantined
	 * even though its reader cannot yet be released. */
	routes[0].phase = SE_ROUTE_FREE;
	assert(se_op_exec_reader_abort_quarantined(&owner, &bindings[0], 0x1234,
						   invocation) ==
	       SE_OL_CORRUPT);
	assert(payloads[0].semantic.exec.owned &&
	       payloads[0].semantic.reader.owned &&
	       (payloads[0].semantic.flags & SE_TASK_QUARANTINED) &&
	       payloads[0].semantic.eligibility_version == 2);
	/* Once the route contradiction is repaired, retry settles the same
	 * original invocation without granting a new role or reader claim. */
	routes[0].phase = SE_ROUTE_ACTIVE;
	assert(se_op_exec_reader_abort_quarantined(&owner, &bindings[0], 0x1234,
						   invocation) == SE_OL_OK);
	assert(!payloads[0].semantic.exec.owned &&
	       !payloads[0].semantic.reader.owned &&
	       !bindings[0].records[0].claims);
	bpf_spin_lock(&routes[0].lock);
	assert(!se_route_withdraw_locked(&routes[0], &bindings[0]));
	bpf_spin_unlock(&routes[0].lock);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
static void opaque_work_catalogue_accepts_only_exact_reader(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle handle = {};
	struct se_invocation *work = 0;
	__u32 slot = 0;
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_choose(&owner, &slot) == SE_OL_OK && slot == 0);
	assert(se_owk_begin(&owner, slot, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_semantic_open(&owner, &ticket, &handle, &work) ==
	       SE_OL_OK);
	struct se_task_state *task = &payloads[0].semantic;
	task->exec = (struct se_exec_transaction){
		.owned = 1,
		.bprm = 0x1234,
		.sequence = 9,
		.generation = 1,
		.execution_class = 1,
		.policy_count = 1,
	};
	assert(ticket.invocation_sequence != task->exec.sequence);
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 7,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 1,
		.active_serial = 1,
		.execution_class = 1,
		.phase = SE_ROUTE_ACTIVE,
	};
	bindings[0] = (struct se_binding_snapshots){
		.scope = 10,
		.generation = 1,
		.active_serial = 1,
		.records = { { .scope = 10,
			       .serial = 1,
			       .generation = 1,
			       .phase = SE_SNAPSHOT_ACTIVE,
			       .execution_class = 1 } },
	};
	struct se_route_claim claim = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &claim) == SE_ROUTE_OWNED);
	assert(!se_exec_reader_attach_locked(&routes[0], &bindings[0], task,
					     &claim, owner.lease.cookie,
					     task->exec.sequence));
	bpf_spin_unlock(&routes[0].lock);
	assert(!claim.owned && !routes[0].early_claims &&
	       bindings[0].records[0].claims == 1);
	task->committed.version = 7;
	task->committed.rows[0] = er_known_row(1, 13, 3);
	se_exec_snapshot_locked(task, 1, &work->history);
	assert(se_owk_catalogue_fill_reader(&handle) == SE_OL_OK);
	assert(se_owk_catalogue_classify_reader(&handle) == SE_OL_OK &&
	       work->history.view.accepted_mask == 1);
	work->history.transaction.sequence++;
	assert(se_owk_catalogue_classify_reader(&handle) == SE_OL_STALE);
	work->history.transaction.sequence--;
	work->history.transaction.generation++;
	assert(se_owk_catalogue_classify_reader(&handle) == SE_OL_CORRUPT);
	work->history.transaction.generation--;
	bindings[0].records[0].claims = 0;
	assert(se_owk_catalogue_classify_reader(&handle) == SE_OL_STALE);
	bindings[0].records[0].claims = 1;
	routes[0].incarnation++;
	assert(se_owk_catalogue_classify_reader(&handle) == SE_OL_STALE);
	routes[0].incarnation--;
	task->reader_invocation++;
	assert(se_owk_catalogue_classify_reader(&handle) == SE_OL_STALE);
	task->reader_invocation--;
	bpf_spin_lock(&routes[0].lock);
	assert(!se_exec_reader_release_locked(
		&bindings[0], task, owner.lease.cookie, task->exec.sequence));
	bpf_spin_unlock(&routes[0].lock);
	assert(se_owk_catalogue_classify_reader(&handle) == SE_OL_STALE);
	assert(se_owk_semantic_done(&handle, &work) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}

static void opaque_scoped_publisher_matches_canonical(void)
{
	for (__u32 count = 0; count <= ER_ACTIVE; count++) {
		struct er_state initial = { .version = 7 };
		struct se_exec_work work = { .eligibility_version = 1 };
		work.transaction = (struct se_exec_transaction){
			.owned = 1,
			.eligibility_version = 1,
			.policy_count = ER_ACTIVE,
			.grants = (1U << count) - 1,
			.uncertain = ((1U << count) - 1) & 0x55,
		};
		for (__u32 i = 0; i < ER_ACTIVE; i++) {
			initial.rows[i] = er_known_row(i + 1, 13, 3);
			work.transaction.policies[i] =
				(struct se_exec_policy){ i + 1, 13 };
			work.transaction.witnesses[i] = 7 + i;
		}
		er_snapshot(&work.view.work, &initial, 13);
		work.view.work.prepared = 1; /* scoped catalogue verdict */
		work.view.accepted_mask = 0xff;
		assert(!se_owk_exec_prepare_scoped(&work, 1));
		assert(work.patch.prepared && work.patch.count == count);
		struct er_state canonical = initial, scoped = initial;
		int a = er_canonical_patch_publish(&canonical, &work.patch, 13);
		int b = se_owk_patch_publish_scoped(&scoped, &work.patch, 13);
		assert(a == b && !memcmp(&canonical, &scoped, sizeof(scoped)));
		assert(!a && canonical.version == (count ? 8 : 7));
		if (!count)
			continue;
		struct er_fact_patch bad = work.patch;
		bad.changes[0].index = ER_SLOTS;
		canonical = scoped = initial;
		a = er_canonical_patch_publish(&canonical, &bad, 13);
		b = se_owk_patch_publish_scoped(&scoped, &bad, 13);
		assert(a == b && !memcmp(&canonical, &scoped, sizeof(scoped)));
		bad = work.patch;
		bad.changes[0].before.role++;
		canonical = scoped = initial;
		a = er_canonical_patch_publish(&canonical, &bad, 13);
		b = se_owk_patch_publish_scoped(&scoped, &bad, 13);
		assert(a == b && !memcmp(&canonical, &scoped, sizeof(scoped)));
		bad = work.patch;
		bad.changes[0].after.role = 0;
		canonical = scoped = initial;
		a = er_canonical_patch_publish(&canonical, &bad, 13);
		b = se_owk_patch_publish_scoped(&scoped, &bad, 13);
		assert(a == b && !memcmp(&canonical, &scoped, sizeof(scoped)));
		bad = work.patch;
		bad.base_version++;
		canonical = scoped = initial;
		a = er_canonical_patch_publish(&canonical, &bad, 13);
		b = se_owk_patch_publish_scoped(&scoped, &bad, 13);
		assert(a == b && !memcmp(&canonical, &scoped, sizeof(scoped)));
	}
}

static void opaque_work_prepared_exec_commits_under_exact_reader(int success)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 7,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 13,
		.active_serial = 1,
		.execution_class = 1,
		.phase = SE_ROUTE_ACTIVE,
	};
	bindings[0] = (struct se_binding_snapshots){
		.scope = 10,
		.generation = 13,
		.active_serial = 1,
		.records = { { .scope = 10,
			       .serial = 1,
			       .generation = 13,
			       .phase = SE_SNAPSHOT_ACTIVE,
			       .count = 1,
			       .execution_class = 1,
			       .metadata = { .root_epochs = { 13 },
					     .policy_uids = { 1 },
					     .role_writers = 1,
					     .container_length = 1,
					     .container = "/" } } },
	};
	struct se_task_state *task = &payloads[0].semantic;
	task->committed.version = 7;
	task->committed.rows[0] = er_known_row(1, 13, 3);
	struct se_route_claim claim = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &claim) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	__u64 invocation = 0;
	assert(se_op_exec_reader_begin(&owner, &claim, &bindings[0], 0x1234,
				       &invocation) == SE_OL_OK &&
	       invocation == 1);
	struct se_task_state *locked = 0;
	assert(se_op_task_semantic_begin(&owner, &locked) == SE_OL_OK);
	se_exec_fault_locked(
		&locked->exec); /* accepted writer becomes UNKNOWN */
	se_op_task_semantic_end(&owner, &locked);
	struct se_exec_terminal_receipt receipt = {
		.physical = key,
		.bprm = 0x1234,
		.cookie = owner.lease.cookie,
		.locator = owner.lease.locator,
		.invocation = invocation,
		.scope = 10,
		.generation = 13,
		.phase = success ? SE_EXEC_TERMINAL_SUCCESS :
				   SE_EXEC_TERMINAL_FAILURE,
	};
	assert(se_owk_terminal_receipt_matches(&receipt, key, &owner, task,
					       success));
	assert(!se_owk_terminal_receipt_matches(&receipt, key, &owner, task,
						!success));
	receipt.phase = SE_EXEC_TERMINAL_REGISTERED;
	assert(!se_owk_terminal_receipt_matches(&receipt, key, &owner, task,
						success));
	receipt.phase = success ? SE_EXEC_TERMINAL_SUCCESS :
				  SE_EXEC_TERMINAL_FAILURE;
	receipt.locator++;
	assert(!se_owk_terminal_receipt_matches(&receipt, key, &owner, task,
						success));
	receipt.locator--;
	receipt.invocation++;
	assert(!se_owk_terminal_receipt_matches(&receipt, key, &owner, task,
						success));
	receipt.invocation--;
	receipt.scope++;
	assert(!se_owk_terminal_receipt_matches(&receipt, key, &owner, task,
						success));
	receipt.scope--;
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle handle = {};
	struct se_invocation *work = 0;
	__u32 slot = 0;
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_choose(&owner, &slot) == SE_OL_OK && slot == 0);
	assert(se_owk_begin(&owner, slot, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_semantic_open(&owner, &ticket, &handle, &work) ==
	       SE_OL_OK);
	assert(se_op_task_semantic_begin(&owner, &locked) == SE_OL_OK);
	se_exec_snapshot_locked(locked, 13, &work->history);
	se_op_task_semantic_end(&owner, &locked);
	assert(se_owk_catalogue_fill_reader(&handle) == SE_OL_OK);
	assert(se_owk_exec_complete_reader(&handle, 0x1234, invocation + 1,
					   success) == SE_OL_CORRUPT);
	assert(task->exec.owned && task->reader.owned &&
	       task->committed.rows[0].knowledge == ER_ROLE_KNOWN);
	assert(se_owk_exec_complete_reader(&handle, 0x1234, invocation,
					   success) == SE_OL_OK);
	assert(!task->exec.owned && !task->reader.owned &&
	       !task->reader_invocation && !bindings[0].records[0].claims &&
	       task->committed.rows[0].knowledge ==
		       (success ? ER_ROLE_UNKNOWN : ER_ROLE_KNOWN) &&
	       task->committed.version == (success ? 8 : 7) && !held &&
	       !lock_errors);
	assert(se_owk_semantic_done(&handle, &work) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
}

static void opaque_postcommit_reader_retry_is_exact_and_patch_free(int success)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 7,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 13,
		.active_serial = 1,
		.execution_class = 1,
		.phase = SE_ROUTE_ACTIVE,
	};
	bindings[0] = (struct se_binding_snapshots){
		.scope = 10,
		.generation = 13,
		.active_serial = 1,
		.records = { { .scope = 10,
			       .serial = 1,
			       .generation = 13,
			       .phase = SE_SNAPSHOT_ACTIVE,
			       .count = 1,
			       .execution_class = 1,
			       .metadata = { .root_epochs = { 13 },
					     .policy_uids = { 1 },
					     .role_writers = 1,
					     .container_length = 1,
					     .container = "/" } } },
	};
	struct se_task_state *task = &payloads[0].semantic;
	task->committed.version = 8;
	task->committed.rows[0] = er_known_row(1, 13, 3);
	task->committed.rows[0].knowledge = ER_ROLE_UNKNOWN;
	struct se_route_claim claim = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &claim) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	__u64 invocation = 0;
	assert(se_op_exec_reader_begin(&owner, &claim, &bindings[0], 0x1234,
				       &invocation) == SE_OL_OK &&
	       invocation == 1);
	struct se_exec_terminal_receipt receipt = {
		.physical = key,
		.bprm = 0x1234,
		.cookie = owner.lease.cookie,
		.locator = owner.lease.locator,
		.invocation = invocation,
		.scope = 10,
		.generation = 13,
		.phase = success ? SE_EXEC_TERMINAL_SUCCESS :
				   SE_EXEC_TERMINAL_FAILURE,
	};
	assert(se_owk_exec_settle_committed_reader(&owner, &receipt, key) ==
	       SE_OL_CORRUPT); /* an owned transaction is not a retry */
	assert(task->reader.owned && bindings[0].records[0].claims == 1);
	struct se_task_state *locked = 0;
	assert(se_op_task_semantic_begin(&owner, &locked) == SE_OL_OK);
	locked->exec.owned = 0; /* model the patch publisher's final store */
	se_op_task_semantic_end(&owner, &locked);
	receipt.invocation++;
	assert(se_owk_exec_settle_committed_reader(&owner, &receipt, key) ==
	       SE_OL_CORRUPT);
	receipt.invocation--;
	assert(se_owk_exec_settle_committed_reader(&owner, &receipt, key) ==
	       SE_OL_OK);
	assert(!task->reader.owned && !task->reader_invocation &&
	       !bindings[0].records[0].claims && task->committed.version == 8 &&
	       task->committed.rows[0].knowledge == ER_ROLE_UNKNOWN);
	assert(se_owk_exec_settle_committed_reader(&owner, &receipt, key) ==
	       SE_OL_OK); /* deletion retry cannot apply a second patch */
	assert(task->committed.version == 8 && !held && !lock_errors);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
}
#endif

static void opaque_work_semantic_handle_requires_exact_ticket(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	__u32 slot = 0;
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_choose(&owner, &slot) == SE_OL_OK && slot == 0);
	assert(se_owk_begin(&owner, slot, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	assert(se_owk_semantic_open(&owner, &ticket, &semantic, &work) ==
	       SE_OL_CORRUPT); /* only ACTIVE WORK may expose semantic bytes */
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	owner.lease.cookie++;
	assert(se_owk_semantic_open(&owner, &ticket, &semantic, &work) ==
		       SE_OL_CORRUPT &&
	       !semantic.held && !work && !work_accounts[0].fault);
	owner.lease.cookie--;
	assert(se_owk_semantic_open(&owner, &ticket, &semantic, &work) ==
		       SE_OL_OK &&
	       work == &work_payloads[slot].semantic);
	assert(se_owk_semantic_open(&owner, &ticket, &semantic, &work) ==
	       SE_OL_CORRUPT);
	work->view.scope_cookie = 11;
	assert(work_payloads[slot].semantic.view.scope_cookie == 11);
	struct se_of_lease dying = {};
	assert(se_of_record_death((struct task_struct *)(unsigned long)key,
				  &dying) == SE_OL_OK &&
	       !(metas[0].cleanup_done & SE_OL_WORK_DONE));
	assert(se_of_release(&dying,
			     (struct task_struct *)(unsigned long)key) ==
	       SE_OL_OK);
	assert(work->view.scope_cookie == 11); /* retained WORK lease */
	assert(se_owk_semantic_done(&semantic, &work) == SE_OL_OK && !work &&
	       !semantic.held && !ticket.held);
	assert(se_owk_semantic_done(&semantic, &work) == SE_OL_CORRUPT);
	for (unsigned step = 0; step < 6; step++)
		assert(se_owk_reap_step(slot, ticket.cookie) ==
		       SE_OWK_PROGRESS);
	assert(se_owk_reap_step(slot, ticket.cookie) == SE_OWK_RETURNED);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(metas[0].cleanup_done & SE_OL_WORK_DONE);
	assert(!held && !lock_errors);
}

static void opaque_parent_snapshot_requires_exact_task_and_work(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	struct se_route_claim claim = {};
	__u32 slot = 0;
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 81,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 1,
		.active_serial = 1,
		.execution_class = 2,
		.phase = SE_ROUTE_ACTIVE,
	};
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 81,
				     &claim) == SE_ROUTE_OWNED);
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_choose(&owner, &slot) == SE_OL_OK);
	assert(se_owk_begin(&owner, slot, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_semantic_open(&owner, &ticket, &semantic, &work) ==
	       SE_OL_OK);
	claim.scope++;
	assert(se_op_parent_snapshot_held(&owner, &semantic, work, &claim) ==
		       SE_OL_CORRUPT &&
	       !work->history.physical_cookie);
	claim.scope--;
	assert(se_op_parent_snapshot_held(&owner, &semantic, work, &claim) ==
		       SE_OL_STALE &&
	       !work->history.physical_cookie);
	payloads[0].semantic.flags = SE_TASK_QUALIFIED;
	payloads[0].semantic.committed.version = 7;
	payloads[0].semantic.committed.rows[0] = er_known_row(1, 1, 7);
	assert(se_op_parent_snapshot_held(&owner, &semantic, work, &claim) ==
		       SE_OL_OK &&
	       work->history.physical_cookie == owner.lease.cookie &&
	       work->history.scope_cookie == 10 &&
	       work->history.flags == SE_TASK_QUALIFIED &&
	       work->history.view.work.base_version == 7 &&
	       work->history.view.work.authority_version == 1 &&
	       work->history.view.work.rows[0].uid == 1 && !held &&
	       !lock_errors);
	opaque_catalogue_epoch = 1;
	assert(se_op_parent_project_held(&semantic, work, &claim) == SE_OL_OK &&
	       work->history.view.accepted_mask == 1 &&
	       work->inherited.prepared && work->inherited.rows[0].uid == 1 &&
	       work->inherited.rows[0].role == 7 && !held && !lock_errors);
	struct se_snapshot snapshot = {
		.scope = 10, .serial = 1, .generation = 1, .count = 1,
		.metadata = {
			.root_epochs = { 1 }, .policy_uids = { 1 },
			.container_length = 1, .container = "/",
		},
	};
	/* Snapshot/cache rejection must precede child charge. Neither failed
	 * preflight may consume a TASK slot or create a directory entry. */
	__u32 used_before = accounts[0].used;
	struct se_snapshot stale_snapshot = snapshot;
	stale_snapshot.serial++;
	__u64 rejected_key = 0xa1;
	assert(se_op_construct_child_from_parent_work(
		       &semantic, &claim, &stale_snapshot, &rejected_key) ==
		       SE_OL_CORRUPT &&
	       accounts[0].used == used_before && !cells[1].present);
	semantic.payload->catalogue.rows[0].uid++;
	assert(se_op_construct_child_from_parent_work(
		       &semantic, &claim, &snapshot, &rejected_key) ==
		       SE_OL_CORRUPT &&
	       accounts[0].used == used_before && !cells[1].present);
	semantic.payload->catalogue.rows[0].uid--;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
	/* Model the callback boundary: source consumes its lexical WORK lease
	 * and route claim; successor reopens the same physical TASK and charged
	 * WORK, then takes a fresh exact route claim. No pointer is transferred. */
	work = 0;
	semantic = (struct se_owk_semantic_handle){};
	assert(se_owk_suspend(&owner, &ticket, 1) == SE_OL_OK &&
	       work_metas[ticket.work_slot].phase == SE_OWK_SUSPENDED);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!se_route_release_locked(&routes[0], &claim) &&
	       routes[0].early_claims == 0);
	owner = (struct se_ol_payload_handle){};
	ticket = (struct se_owk_ticket){};
	claim = (struct se_route_claim){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_resume(&owner, 1, &ticket) == SE_OL_OK &&
	       ticket.continuation_stage == 1);
	assert(se_owk_semantic_open(&owner, &ticket, &semantic, &work) ==
	       SE_OL_OK);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 81,
				     &claim) == SE_ROUTE_OWNED &&
	       claim.generation == 1 && claim.serial == snapshot.serial);
#endif
	__u64 child_key = 0xb2;
	assert(se_op_construct_child_from_parent_work(
		       &semantic, &claim, &snapshot, &child_key) == SE_OL_OK);
	assert(cells[1].present && cells[1].key == child_key &&
	       payloads[1].semantic.committed.version == 1 &&
	       payloads[1].semantic.committed.rows[0].uid == 1 &&
	       payloads[1].semantic.committed.rows[0].role == 7 && !held &&
	       !lock_errors);
	struct se_oc_reservation stale_child = {};
	__u64 stale_key = 0xc3;
	assert(se_op_prepare_charged_child(&claim, &stale_child) == SE_OL_OK);
	payloads[0].semantic.committed.version++;
	assert(se_op_publish_child_from_parent_work(
		       &semantic, &claim, &snapshot, &stale_key,
		       &stale_child) == SE_OL_STALE &&
	       stale_child.terminal && cells[0].key == key &&
	       cells[1].key == child_key &&
	       !payloads[stale_child.task_slot].semantic.committed.version);
	payloads[0].semantic.committed.version--;
	struct se_oc_reservation bad_cache_child = {};
	__u64 bad_cache_key = 0xd4;
	assert(se_op_prepare_charged_child(&claim, &bad_cache_child) ==
	       SE_OL_OK);
	semantic.payload->catalogue.rows[0].uid++;
	assert(se_op_publish_child_from_parent_work(
		       &semantic, &claim, &snapshot, &bad_cache_key,
		       &bad_cache_child) == SE_OL_CORRUPT &&
	       bad_cache_child.terminal &&
	       !payloads[bad_cache_child.task_slot].semantic.committed.version);
	semantic.payload->catalogue.rows[0].uid--;
	assert(!held && !lock_errors);
	opaque_catalogue_epoch = 13;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
	/* A second handoff sees a withdrawn route. The successor may resume
	 * WORK to clean it, but must not create a child from a stale claim. */
	work = 0;
	semantic = (struct se_owk_semantic_handle){};
	assert(se_owk_suspend(&owner, &ticket, 2) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!se_route_release_locked(&routes[0], &claim));
	routes[0].phase = SE_ROUTE_WITHDRAWN;
	owner = (struct se_ol_payload_handle){};
	ticket = (struct se_owk_ticket){};
	claim = (struct se_route_claim){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_resume(&owner, 2, &ticket) == SE_OL_OK);
	assert(se_owk_semantic_open(&owner, &ticket, &semantic, &work) ==
	       SE_OL_OK);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 81,
				     &claim) == SE_ROUTE_UNSELECTED &&
	       !claim.owned && !routes[0].early_claims);
	assert(se_owk_semantic_done(&semantic, &work) == SE_OL_OK &&
	       work_metas[ticket.work_slot].phase == SE_OWK_DONE);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
#else
	assert(se_owk_semantic_done(&semantic, &work) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!se_route_release_locked(&routes[0], &claim));
#endif
	assert(!held && !lock_errors);
}

static void opaque_work_semantic_bad_ticket_faults_credit(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	__u32 slot = 0;
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_choose(&owner, &slot) == SE_OL_OK);
	assert(se_owk_begin(&owner, slot, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	ticket.invocation_sequence++;
	assert(se_owk_semantic_open(&owner, &ticket, &semantic, &work) ==
		       SE_OL_CORRUPT &&
	       !semantic.held && !work && work_accounts[0].fault &&
	       work_charges[slot].state == SE_OWK_FAULT_HELD);
	assert(!held && !lock_errors);
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
static void opaque_work_continuation_reopens_one_exact_lease(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	__u64 cookie = ticket.cookie;
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
	/* The raw argv copy buffer is dead after fact capture. Explicitly clear
	 * it before beginning a cursor; a nonzero argument must not masquerade
	 * as a valid stage or block the first begin. */
	struct fe_stage_cursor *cursor =
		&work_payloads[0].semantic.observation.stage_cursor;
	work_payloads[0].semantic.observation.argument[0] = 'x';
	memset(cursor, 0, sizeof(*cursor));
	assert(!work_payloads[0].semantic.observation.argument[0]);
	*cursor = (struct fe_stage_cursor){
		.generation = 77,
		.policies = 1,
		.rules = 17,
		.next_rule = 16,
		.state = FE_STAGE_ACTIVE,
		.allow_mode = 1,
		.deny_mode = 1,
	};
	work_payloads[0].semantic.observation.stage_workspace.token =
		(struct fm_global_token){ .slot = 0, .cookie = cookie };
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
	{
		struct se_owk_semantic_handle semantic = {};
		struct se_invocation *work = 0;
		assert(se_owk_semantic_open(&owner, &ticket, &semantic,
					    &work) == SE_OL_OK &&
		       work);
		assert(se_owk_semantic_suspend(&semantic, &work, 2) ==
			       SE_OL_CORRUPT &&
		       semantic.held == 1 && work && ticket.held == 1);
		assert(se_owk_semantic_suspend(&semantic, &work, 1) ==
			       SE_OL_OK &&
		       !semantic.held && !work);
	}
#else
	assert(se_owk_suspend(&owner, &ticket, 1) == SE_OL_OK);
#endif
	assert(!ticket.held && ticket.stage == 6 &&
	       work_metas[0].phase == SE_OWK_SUSPENDED &&
	       !work_metas[0].active_leases &&
	       work_metas[0].continuation_stage == 1 &&
	       work_accounts[0].used == 1 && metas[0].work_refs == 1);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PENDING);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	owner = (struct se_ol_payload_handle){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	struct se_owk_ticket successor = {};
	assert(se_owk_resume(&owner, 2, &successor) == SE_OL_STALE &&
	       !successor.held && !successor.cookie && !work_accounts[0].fault);
	assert(se_owk_resume(&owner, 1, &successor) == SE_OL_OK &&
	       successor.held && successor.cookie == cookie &&
	       successor.continuation_stage == 1 &&
	       work_metas[0].phase == SE_OWK_ACTIVE &&
	       work_metas[0].active_leases == 1);
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
	assert(cursor->generation == 77 && cursor->rules == 17 &&
	       cursor->next_rule == 16 && cursor->state == FE_STAGE_ACTIVE);
	assert(work_payloads[0]
		       .semantic.observation.stage_workspace.token.cookie ==
	       cookie);
#endif
	struct se_owk_ticket replay = {};
	assert(se_owk_resume(&owner, 1, &replay) == SE_OL_STALE &&
	       !replay.held && !replay.cookie && !work_accounts[0].fault);
	assert(se_owk_suspend(&owner, &successor, 2) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	owner = (struct se_ol_payload_handle){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	struct se_owk_ticket final = {};
	assert(se_owk_resume(&owner, 1, &final) == SE_OL_STALE);
	assert(se_owk_resume(&owner, 2, &final) == SE_OL_OK);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	assert(se_owk_semantic_open(&owner, &final, &semantic, &work) ==
		       SE_OL_OK &&
	       work);
	assert(se_owk_semantic_done(&semantic, &work) == SE_OL_OK && !work);
#else
	assert(se_owk_done(&owner, &final) == SE_OL_OK);
#endif
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(work_metas[0].phase == SE_OWK_DONE &&
	       !work_metas[0].continuation_stage && !work_accounts[0].fault &&
	       !held && !lock_errors);
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
	for (unsigned step = 0; step < 6; step++)
		assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_RETURNED &&
	       !cursor->generation && !cursor->next_rule && !cursor->state &&
	       !work_payloads[0]
			.semantic.observation.stage_workspace.token.cookie);
#endif
}

static void opaque_work_continuation_faults_bad_charge(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_suspend(&owner, &ticket, 2) == SE_OL_CORRUPT &&
	       ticket.held && work_metas[0].phase == SE_OWK_ACTIVE &&
	       !work_accounts[0].fault);
	assert(se_owk_suspend(&owner, &ticket, 1) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	owner = (struct se_ol_payload_handle){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	work_charges[0].owner_cookie++;
	struct se_owk_ticket successor = {};
	assert(se_owk_resume(&owner, 1, &successor) == SE_OL_CORRUPT &&
	       !successor.held && !successor.cookie && work_accounts[0].fault &&
	       work_charges[0].state == SE_OWK_OWNED &&
	       work_accounts[0].bits == 1 && metas[0].work_refs == 1 &&
	       work_metas[0].phase == SE_OWK_SUSPENDED);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}

#ifdef ENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE
static void opaque_suspended_current_read_requires_exact_identity(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	suspended_current_task_key = key;
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	assert(se_owk_semantic_open(&owner, &ticket, &semantic, &work) ==
		       SE_OL_OK &&
	       work);
	memset(opaque_policy_blobs, 0, sizeof(opaque_policy_blobs));
	const struct fe_header header = { .policies = 1, .rule_base = 9 };
	const struct fe_policy policy = {
		.uid = 1,
		.root_role = 1,
		.mode = 2,
	};
	memcpy(&opaque_policy_blobs[0], &header, sizeof(header));
	memcpy(&opaque_policy_blobs[1], &policy, sizeof(policy));
	const struct fe_string container = {
		.length = 1,
		.bytes = { '/' },
	};
	const struct se_policy_ref ref = {
		.slot = 0,
		.generation = 1,
		.root_epoch = 1,
		.entries = 10,
	};
	assert(!se_policy_prepare(&work->view, 0, ticket.scope, 1, &container,
				  &ref, 1));
	struct se_owk_payload *expected = &work_payloads[0];
	work = 0;
	semantic = (struct se_owk_semantic_handle){};
	assert(se_owk_suspend(&owner, &ticket, 1) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(se_owk_suspended_current(10, 1, 0) == expected);
#ifndef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
	assert(!se_owk_suspended_current(10, 1, 1) &&
	       !se_owk_suspended_current(10, 1, 2) &&
	       !work_metas[0].continuation_reserved);
#endif
	assert(!se_owk_suspended_current(10, 2, 0) &&
	       !se_owk_suspended_current(11, 1, 0));
	suspended_current_task_key = 0xb2;
	assert(!se_owk_suspended_current(10, 1, 0));
	suspended_current_task_key = key;
	work_charges[0].cookie++;
	assert(!se_owk_suspended_current(10, 1, 0));
	work_charges[0].cookie--;
	metas[0].current_work_cookie++;
	assert(!se_owk_suspended_current(10, 1, 0));
	metas[0].current_work_cookie--;
	accounts[0].used++;
	assert(!se_owk_suspended_current(10, 1, 0));
	accounts[0].used--;
	work_accounts[0].used++;
	assert(!se_owk_suspended_current(10, 1, 0));
	work_accounts[0].used--;
	work_metas[0].continuation_stage = 2;
	assert(!se_owk_suspended_current(10, 1, 0));
	work_metas[0].continuation_stage = 1;
	work_payloads[0].semantic.view.ready = 0;
	assert(!se_owk_suspended_current(10, 1, 0));
	work_payloads[0].semantic.view.ready = 1;
	assert(se_owk_suspended_current(10, 1, 0) == expected);
	__u32 resumed_stage = 1;
#ifdef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
	assert(!se_owk_suspended_view_from_token(0, expected->semantic.cookie));
	assert(!se_owk_suspended_current(10, 1, 3));
	assert(!se_owk_suspended_current(11, 1, 1));
	assert(!se_owk_suspended_current(10, 2, 1));
	work_accounts[0].used++;
	assert(!se_owk_suspended_current(10, 1, 1));
	assert(!work_metas[0].continuation_reserved);
	work_accounts[0].used--;
	suspended_current_task_key = 0xb2;
	assert(!se_owk_suspended_current(10, 1, 1));
	suspended_current_task_key = key;
	assert(se_owk_suspended_current(10, 1, 1) == expected);
	assert(se_owk_suspended_current(10, 1, 3) == expected);
	assert(!se_owk_suspended_current(10, 1, 1));
	assert(!se_owk_suspended_current(10, 1, 0));
	assert(se_owk_suspended_view_from_token(0, expected->semantic.cookie) ==
	       &expected->semantic.view);
	assert(!se_owk_suspended_view_from_token(0, expected->semantic.cookie +
							    1));
	suspended_current_task_key = 0xb2;
	assert(!se_owk_suspended_current(10, 1, 3));
	assert(!se_owk_suspended_current(10, 1, 2) &&
	       work_metas[0].continuation_reserved == 1);
	suspended_current_task_key = key;
	assert(se_owk_commit_suspended_stage(expected, 11, 1) != SE_OL_OK);
	assert(se_owk_suspended_current(10, 1, 2) == expected);
	assert(!se_owk_suspended_current(10, 1, 3));
	assert(!work_metas[0].continuation_reserved);
	assert(!se_owk_suspended_current(10, 1, 2));
	assert(!se_owk_suspended_view_from_token(0, expected->semantic.cookie));
	assert(se_owk_suspended_current(10, 1, 1) == expected);
	assert(se_owk_commit_suspended_stage(expected, 10, 1) == SE_OL_OK);
	assert(se_owk_commit_suspended_stage(expected, 10, 1) != SE_OL_OK);
	assert(!se_owk_suspended_view_from_token(0, expected->semantic.cookie));
	resumed_stage = 2;
#endif
	assert(!held && !lock_errors);
	owner = (struct se_ol_payload_handle){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	struct se_owk_ticket resumed = {};
	assert(se_owk_resume(&owner, resumed_stage, &resumed) == SE_OL_OK);
	assert(!se_owk_suspended_current(10, 1, 0));
#ifdef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
	assert(!se_owk_suspended_view_from_token(0, resumed.cookie));
#endif
	semantic = (struct se_owk_semantic_handle){};
	assert(se_owk_semantic_open(&owner, &resumed, &semantic, &work) ==
		       SE_OL_OK &&
	       work);
	assert(se_owk_semantic_done(&semantic, &work) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!se_owk_suspended_current(10, 1, 0) && !held && !lock_errors);
	suspended_current_task_key = 0;
}
#ifdef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
static void opaque_suspended_corrupt_commit_never_refunds(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	work_payloads[0].semantic.view.scope_cookie = 10;
	work_payloads[0].semantic.view.ready = 1;
	__u64 cookie = ticket.cookie;
	assert(se_owk_suspend(&owner, &ticket, 1) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	suspended_current_task_key = key;
	struct se_owk_payload *payload = se_owk_suspended_current(10, 1, 1);
	assert(payload == &work_payloads[0]);
	payload->semantic.sequence++; /* structural contradiction after claim */
	assert(se_owk_commit_suspended_stage(payload, 10, 1) != SE_OL_OK);
	assert(!se_owk_suspended_current(10, 1, 2) &&
	       work_metas[0].continuation_reserved == 1 &&
	       work_accounts[0].used == 1 && work_accounts[0].bits == 1);
	struct task_struct *physical = (struct task_struct *)(unsigned long)key;
	struct se_of_lease dying = {};
	assert(se_of_record_death(physical, &dying) == SE_OL_OK);
	assert(se_owk_finish_suspended_death(&dying) == SE_OL_CORRUPT &&
	       work_accounts[0].fault == 1 &&
	       work_charges[0].state == SE_OWK_FAULT_HELD &&
	       work_accounts[0].bits == 1 && work_accounts[0].used == 1);
	assert(se_of_release(&dying, physical) == SE_OL_OK);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PENDING &&
	       work_accounts[0].bits == 1 && work_accounts[0].used == 1 &&
	       !held && !lock_errors);
	suspended_current_task_key = 0;
}
#endif
#endif

static void opaque_work_continuation_death_closes_suspended_work(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	__u64 cookie = ticket.cookie;
	assert(se_owk_suspend(&owner, &ticket, 1) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	struct task_struct *physical = (struct task_struct *)(unsigned long)key;
	struct se_of_lease dying = {};
	assert(se_of_record_death(physical, &dying) == SE_OL_OK);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PENDING);
	struct se_of_lease wrong = dying;
	wrong.cookie++;
	assert(se_owk_finish_suspended_death(&wrong) == SE_OL_STALE &&
	       work_metas[0].phase == SE_OWK_SUSPENDED &&
	       metas[0].current_work_owned);
	assert(se_owk_finish_suspended_death(&dying) == SE_OL_OK &&
	       work_metas[0].phase == SE_OWK_DONE &&
	       !work_metas[0].continuation_stage &&
	       !metas[0].current_work_owned && metas[0].work_refs == 1 &&
	       work_accounts[0].used == 1);
	assert(se_of_release(&dying, physical) == SE_OL_OK);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_RETURNED &&
	       !work_accounts[0].used && !work_accounts[0].bits &&
	       !metas[0].work_refs &&
	       (metas[0].cleanup_done & SE_OL_WORK_DONE) && !held &&
	       !lock_errors);
}

static void opaque_work_continuation_death_after_resume_claim(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_suspend(&owner, &ticket, 1) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	owner = (struct se_ol_payload_handle){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	resume_death_race_mode = 1;
	struct se_owk_ticket successor = {};
	assert(se_owk_resume(&owner, 1, &successor) == SE_OL_STALE &&
	       !successor.held && !successor.cookie &&
	       !resume_death_race_mode && work_metas[0].phase == SE_OWK_DONE &&
	       !work_metas[0].active_leases && !metas[0].current_work_owned &&
	       metas[0].work_refs == 1 && !work_accounts[0].fault &&
	       work_accounts[0].used == 1);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
#endif
static void opaque_work_owner_attach_is_exact_and_persistent(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	__u32 slot = 0;
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_choose(&owner, &slot) == SE_OL_OK && slot == 0);
	assert(se_owk_begin(&owner, slot, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(ticket.stage == 1);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_CORRUPT &&
	       !work_accounts[0].fault);
	work_payloads[0].bytes[0] = 0x5a;
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK &&
	       ticket.stage == 2 && !work_payloads[0].bytes[0] &&
	       work_payloads[0].scope == ticket.scope &&
	       work_payloads[0].cookie == ticket.cookie &&
	       work_payloads[0].sequence == 1 &&
	       work_payloads[0].slot == ticket.work_slot);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK &&
	       ticket.stage == 3 && work_metas[0].phase == SE_OWK_ACTIVE);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_CORRUPT &&
	       !work_accounts[0].fault);
	assert(work_charges[0].state == SE_OWK_OWNED &&
	       work_metas[0].phase == SE_OWK_ACTIVE &&
	       work_metas[0].active_leases == 1 &&
	       work_metas[0].owner_ref_held == 1 &&
	       work_metas[0].invocation_sequence == 1 &&
	       work_metas[0].owner_locator == metas[0].locator &&
	       work_metas[0].owner_cookie == metas[0].cookie &&
	       metas[0].work_refs == 1 && metas[0].current_work_owned == 1 &&
	       metas[0].current_work_cookie == ticket.cookie &&
	       metas[0].current_work_slot == 0);
	__u32 second = 0;
	assert(se_owk_choose(&owner, &second) == SE_OL_CONTENDED &&
	       work_accounts[0].used == 1 && !work_accounts[0].fault);
	metas[0].phase = SE_OL_DEAD; /* task_free races callback completion */
	assert(se_owk_done(&owner, &ticket) == SE_OL_OK && ticket.held == 0 &&
	       ticket.stage == 5 && work_metas[0].phase == SE_OWK_DONE &&
	       !work_metas[0].active_leases && !metas[0].current_work_owned &&
	       !metas[0].current_work_cookie && !metas[0].current_work_slot &&
	       metas[0].work_refs == 1 && work_accounts[0].used == 1);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(metas[0].work_refs == 1 && work_accounts[0].used == 1 &&
	       work_charges[0].state == SE_OWK_OWNED && !held && !lock_errors);
}
static void opaque_work_attach_faults_after_task_death(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	metas[0].phase = SE_OL_DEAD;
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_STALE &&
	       !work_accounts[0].fault &&
	       work_charges[0].state == SE_OWK_BUILDING &&
	       work_accounts[0].bits == 1 && metas[0].work_refs == 1);
	assert(se_owk_abort_building(&owner, &ticket) == SE_OL_OK &&
	       work_metas[0].phase == SE_OWK_ABORTED &&
	       work_charges[0].state == SE_OWK_OWNED &&
	       !metas[0].current_work_owned && metas[0].work_refs == 1);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);

	key = seed_live_opaque_task_for_open();
	owner = (struct se_ol_payload_handle){};
	ticket = (struct se_owk_ticket){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	work_metas[0].cookie = 99; /* dirty FREE slot must not be reused */
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_CORRUPT &&
	       ticket.held == 1 && metas[0].work_refs == 1 &&
	       work_accounts[0].fault == 1 &&
	       work_charges[0].state == SE_OWK_FAULT_HELD &&
	       work_accounts[0].bits == 1);
	assert(se_owk_abort_building(&owner, &ticket) == SE_OL_CORRUPT &&
	       metas[0].work_refs == 1 && metas[0].current_work_owned);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);

	key = seed_live_opaque_task_for_open();
	owner = (struct se_ol_payload_handle){};
	ticket = (struct se_owk_ticket){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	metas[0].current_work_cookie++; /* impossible token contradiction */
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_CORRUPT &&
	       work_accounts[0].fault == 1 &&
	       work_charges[0].state == SE_OWK_FAULT_HELD &&
	       work_metas[0].phase == SE_OWK_INITIALIZING &&
	       work_metas[0].owner_ref_held && metas[0].work_refs == 1);
	assert(se_owk_abort_building(&owner, &ticket) == SE_OL_CORRUPT &&
	       metas[0].cleanup_error == 1);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
static void opaque_work_semantic_failure_retains_owner_and_credit(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	work_payload_zero_fail = 1;
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_CORRUPT &&
	       ticket.stage == 1 &&
	       work_metas[0].phase == SE_OWK_OWNER_ATTACHED &&
	       work_metas[0].owner_ref_held && metas[0].work_refs == 1 &&
	       work_accounts[0].bits == 1 &&
	       work_charges[0].state == SE_OWK_FAULT_HELD &&
	       work_accounts[0].fault);
	assert(se_owk_abort(&owner, &ticket) == SE_OL_OK && ticket.held == 0 &&
	       ticket.stage == 4 && work_metas[0].phase == SE_OWK_ABORTED &&
	       !work_metas[0].active_leases && !metas[0].current_work_owned &&
	       metas[0].work_refs == 1);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);

	key = seed_live_opaque_task_for_open();
	owner = (struct se_ol_payload_handle){};
	ticket = (struct se_owk_ticket){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	work_payloads[0].cookie++; /* semantic identity contradiction */
	assert(se_owk_commit(&owner, &ticket) == SE_OL_CORRUPT &&
	       ticket.stage == 2 &&
	       work_metas[0].phase == SE_OWK_OWNER_ATTACHED &&
	       work_metas[0].owner_ref_held && metas[0].work_refs == 1 &&
	       work_accounts[0].bits == 1 &&
	       work_charges[0].state == SE_OWK_FAULT_HELD &&
	       work_accounts[0].fault);
	assert(se_owk_abort(&owner, &ticket) == SE_OL_OK &&
	       work_metas[0].phase == SE_OWK_ABORTED &&
	       !metas[0].current_work_owned && metas[0].work_refs == 1);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
static void opaque_work_done_faults_corrupt_semantic_but_closes_lease(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	work_payloads[0].cookie++;
	assert(se_owk_done(&owner, &ticket) == SE_OL_CORRUPT && !ticket.held &&
	       ticket.stage == 5 && work_metas[0].phase == SE_OWK_DONE &&
	       !work_metas[0].active_leases && !metas[0].current_work_owned &&
	       metas[0].work_refs == 1 &&
	       work_charges[0].state == SE_OWK_FAULT_HELD &&
	       work_accounts[0].fault);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
static void opaque_work_reaper_releases_exact_owner_and_credit(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	__u64 cookie = ticket.cookie;
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PENDING &&
	       metas[0].work_refs == 1 && work_accounts[0].used == 1);
	struct task_struct *physical = (struct task_struct *)(unsigned long)key;
	struct se_of_lease dying = {};
	assert(se_of_record_death(physical, &dying) == SE_OL_OK &&
	       !(metas[0].cleanup_done & SE_OL_WORK_DONE));
	assert(se_of_release(&dying, physical) == SE_OL_OK);
	assert(se_owk_done(&owner, &ticket) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS &&
	       work_metas[0].phase == SE_OWK_CLEANING);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS &&
	       !work_metas[0].owner_ref_held &&
	       work_metas[0].cleanup_done == SE_OWK_OWNER_RELEASED &&
	       !metas[0].work_refs &&
	       (metas[0].cleanup_done & SE_OL_WORK_DONE));
	work_payload_zero_fail = 1;
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PENDING &&
	       work_metas[0].cleanup_done == SE_OWK_OWNER_RELEASED &&
	       work_payloads[0].cookie == cookie);
	work_payload_zero_fail = 0;
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS &&
	       work_metas[0].cleanup_done == 3 && !work_payloads[0].cookie &&
	       !work_payloads[0].scope);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS &&
	       work_metas[0].phase == SE_OWK_REFUND_PENDING);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS &&
	       work_charges[0].state == SE_OWK_RETURN_READY);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS &&
	       work_metas[0].phase == SE_OWK_META_FREE &&
	       work_metas[0].cookie == cookie && !work_metas[0].owner_locator &&
	       !work_metas[0].owner_cookie);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_RETURNED &&
	       work_charges[0].state == SE_OWK_FREE &&
	       work_charges[0].last_returned == cookie &&
	       !work_charges[0].cookie && !work_accounts[0].used &&
	       !work_accounts[0].bits && !metas[0].work_refs);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_ALREADY_RETURNED);
	assert(se_owk_reap_step(0, cookie + 1) == SE_OWK_STALE);
	/* A different exact TASK may reuse the returned WORK slot, but an old
	 * cookie cannot reclaim or mutate the successor's BUILDING credit. */
	struct se_oc_reservation successor_task = {};
	__u64 next_key = 0xb2;
	assert(se_oc_reserve(0, 10, 1, 1, &successor_task) == SE_OL_OK);
	assert(se_oc_begin_charged(&successor_task) == SE_OL_OK);
	assert(se_op_initialize_task_semantic(&successor_task) == SE_OL_OK);
	assert(se_ow_archive(&metas[1], 1, successor_task.cookie, &next_key) ==
	       SE_OL_OK);
	assert(se_ow_insert_zero(&metas[1], successor_task.cookie,
				 &archives[1]) == SE_OL_OK);
	assert(se_ow_publish_zero(&metas[1], successor_task.cookie,
				  &archives[1]) == SE_OL_OK);
	assert(se_op_finish_semantic_birth(&successor_task) == SE_OL_OK);
	struct se_ol_payload_handle next_owner = {};
	assert(se_ol_task_open(&next_key, &next_owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&next_owner) == SE_OL_OK);
	struct se_owk_ticket successor_work = {};
	assert(se_owk_begin(&next_owner, 0, &successor_work) == SE_OL_OK &&
	       successor_work.cookie > cookie &&
	       work_charges[0].state == SE_OWK_BUILDING);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_STALE &&
	       work_charges[0].cookie == successor_work.cookie &&
	       work_accounts[0].bits == 1 && work_accounts[0].used == 1);
	assert(se_owk_attach_owner(&next_owner, &successor_work) == SE_OL_OK &&
	       work_metas[0].cookie == successor_work.cookie &&
	       work_charges[0].state == SE_OWK_OWNED);
	assert(se_ol_payload_close(&next_owner) == SE_OL_OK);
	assert(!held && !lock_errors);
}
static void opaque_work_reaper_receipts_after_task_directory_retirement(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	__u64 cookie = ticket.cookie;
	struct task_struct *physical = (struct task_struct *)(unsigned long)key;
	struct se_of_lease dying = {};
	assert(se_of_record_death(physical, &dying) == SE_OL_OK);
	assert(se_of_release(&dying, physical) == SE_OL_OK);
	assert(se_owk_done(&owner, &ticket) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	/* The independent TASK reaper may retire its directory before the
	 * WORK reaper drops its last exact owner ref. This must not strand the
	 * TASK refund without WORK_DONE. */
	assert(se_ow_claim_withdraw(&metas[0], metas[0].cookie) == SE_OL_OK);
	assert(se_ow_advance_withdraw(&metas[0], metas[0].cookie,
				      &archives[0]) == SE_OL_OK);
	assert(se_ow_delete_withdrawn_zero(&metas[0], metas[0].cookie,
					   &archives[0]) == SE_OL_OK);
	assert(se_ow_zero_archive(&metas[0], metas[0].cookie) == SE_OL_OK);
	assert(metas[0].phase == SE_OL_ARCHIVE_ZEROED &&
	       metas[0].work_refs == 1 &&
	       !(metas[0].cleanup_done & SE_OL_WORK_DONE));
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(!metas[0].work_refs &&
	       (metas[0].cleanup_done & SE_OL_WORK_DONE));
	assert(!held && !lock_errors);
}
static void opaque_work_fault_cleanup_retains_quarantined_credit(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	work_payload_zero_fail = 1;
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_CORRUPT);
	assert(se_owk_abort(&owner, &ticket) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	struct task_struct *physical = (struct task_struct *)(unsigned long)key;
	struct se_of_lease dying = {};
	assert(se_of_record_death(physical, &dying) == SE_OL_OK &&
	       !(metas[0].cleanup_done & SE_OL_WORK_DONE));
	assert(se_of_release(&dying, physical) == SE_OL_OK);
	__u64 cookie = ticket.cookie;
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS &&
	       !metas[0].work_refs &&
	       (metas[0].cleanup_done & SE_OL_WORK_DONE));
	work_payload_zero_fail = 0;
	assert(se_owk_reap_step(0, cookie) == SE_OWK_PROGRESS &&
	       work_metas[0].cleanup_done == 3);
	assert(se_owk_reap_step(0, cookie) == SE_OWK_CORRUPT &&
	       work_metas[0].phase == SE_OWK_CLEANING &&
	       work_accounts[0].fault && work_accounts[0].bits == 1 &&
	       work_charges[0].state == SE_OWK_FAULT_HELD &&
	       !work_payloads[0].cookie && !held && !lock_errors);
}
static void opaque_work_reaper_quarantines_account_contradiction(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, &ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, &ticket) == SE_OL_OK);
	assert(se_owk_done(&owner, &ticket) == SE_OL_OK);
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	work_accounts[0].used = 2; /* bit count contradicts sole credit */
	assert(se_owk_reap_step(0, ticket.cookie) == SE_OWK_CORRUPT &&
	       work_accounts[0].fault &&
	       work_charges[0].state == SE_OWK_FAULT_HELD &&
	       work_accounts[0].bits == 1 && metas[0].work_refs == 1 && !held &&
	       !lock_errors);
}
static void opaque_route_recycle_waits_for_both_owner_accounts(void)
{
	reset();
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.scope = 10,
		.payload_slot = 0,
		.phase = SE_ROUTE_WITHDRAWN,
	};
	struct se_binding_snapshots snapshots = { .scope = 10 };
	work_accounts[0].scope = 10;
	work_accounts[0].incarnation = 1;
	work_accounts[0].used = 1;
	work_accounts[0].bits = 1;
	assert(se_owk_route_recycle(0, &snapshots) == SE_OL_CONTENDED &&
	       routes[0].phase == SE_ROUTE_WITHDRAWN);
	work_accounts[0].used = 0;
	work_accounts[0].bits = 1; /* contradictory zero is not permission */
	assert(se_owk_route_recycle(0, &snapshots) == SE_OL_CORRUPT &&
	       routes[0].phase == SE_ROUTE_WITHDRAWN);
	work_accounts[0].bits = 0;
	assert(se_owk_route_recycle(0, &snapshots) == SE_OL_OK &&
	       routes[0].phase == SE_ROUTE_FREE && !held && !lock_errors);
}
static void opaque_task_open_is_one_exact_lexical_lease(void)
{
	__u64 key = seed_live_opaque_task_for_open();
	struct se_ol_payload_handle handle = {};
	assert(se_ol_task_open(&key, &handle) == SE_OL_OK &&
	       handle.lease.held == 1 && handle.payload == &payloads[0] &&
	       metas[0].active_leases == 1 && !metas[0].reader_holds);
	void *semantic = 0;
	assert(se_ol_payload_begin(&handle, &semantic) == SE_OL_OK &&
	       semantic == &payloads[0] && held == &metas[0].lock);
	assert(se_ol_payload_end(&handle, &semantic) == SE_OL_OK);
	assert(se_ol_payload_close(&handle) == SE_OL_OK && !handle.lease.held &&
	       !metas[0].active_leases && !metas[0].reader_holds && !held &&
	       !lock_errors);
	__u64 missing = 0xb2;
	assert(se_ol_task_open(&missing, &handle) == SE_OL_STALE &&
	       !metas[0].reader_holds && !metas[0].active_leases);

	key = seed_live_opaque_task_for_open();
	open_race_mode = 1;
	assert(se_ol_task_open(&key, &handle) == SE_OL_STALE &&
	       !metas[0].reader_holds && !metas[0].active_leases && !held &&
	       !lock_errors);
	key = seed_live_opaque_task_for_open();
	open_race_mode = 2;
	assert(se_ol_task_open(&key, &handle) == SE_OL_CORRUPT &&
	       !metas[0].reader_holds && !metas[0].active_leases && !held &&
	       !lock_errors);
	key = seed_live_opaque_task_for_open();
	open_race_mode = 3;
	assert(se_ol_task_open(&key, &handle) == SE_OL_CORRUPT &&
	       metas[0].reader_holds == 1 && !metas[0].active_leases && !held &&
	       !lock_errors); /* fault-held, never wrong release */

	key = seed_live_opaque_task_for_open();
	charges[0].state = SE_OC_FAULT_HELD;
	assert(se_ol_task_open(&key, &handle) == SE_OL_CORRUPT &&
	       !metas[0].reader_holds && !metas[0].active_leases && !held &&
	       !lock_errors);
	charges[0].state = SE_OC_OWNED;
	payload_missing = 1;
	assert(se_ol_task_open(&key, &handle) == SE_OL_CORRUPT &&
	       !metas[0].reader_holds && !metas[0].active_leases && !held &&
	       !lock_errors);
}
static void opaque_semantic_constructor_abort_retains_charge(void)
{
	reset();
	struct se_oc_reservation reservation = { 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	payload_zero_fail = 1;
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_CORRUPT);
	assert(se_op_abort_semantic_birth(&reservation) == SE_OL_OK);
	assert(reservation.terminal == 1 &&
	       se_op_abort_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_ABORTED && !metas[0].active_leases &&
	       metas[0].cleanup_done ==
		       (SE_OL_CONSTRUCTION_DONE | SE_OL_EXEC_DONE |
			SE_OL_WORK_DONE | SE_OL_NATIVE_DONE) &&
	       charges[0].state == SE_OC_OWNED && accounts[0].used == 1 &&
	       accounts[0].bits[0] == 1 && !accounts[0].fault && !held &&
	       !lock_errors);

	reset();
	reservation = (struct se_oc_reservation){ 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_OK);
	__u64 key = 0xa1;
	assert(se_ow_archive(&metas[0], 0, reservation.cookie, &key) ==
	       SE_OL_OK);
	metas[0].directory_state = SE_OL_INSERT_INTENT;
	assert(se_op_abort_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_INITIALIZING &&
	       metas[0].active_leases == 1 &&
	       !(metas[0].cleanup_done & SE_OL_CONSTRUCTION_DONE) &&
	       accounts[0].fault && charges[0].state == SE_OC_FAULT_HELD &&
	       accounts[0].used == 1 && accounts[0].bits[0] == 1 && !held &&
	       !lock_errors);

	reset();
	reservation = (struct se_oc_reservation){ 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_OK);
	assert(se_ow_archive(&metas[0], 0, reservation.cookie, &key) ==
	       SE_OL_OK);
	assert(se_ow_insert_zero(&metas[0], reservation.cookie, &archives[0]) ==
	       SE_OL_OK);
	assert(se_ow_publish_zero(&metas[0], reservation.cookie,
				  &archives[0]) == SE_OL_OK);
	assert(se_op_abort_semantic_birth(&reservation) == SE_OL_OK);
	assert(reservation.terminal == 1 &&
	       se_op_abort_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_ABORTED && !metas[0].active_leases &&
	       metas[0].cleanup_done ==
		       (SE_OL_CONSTRUCTION_DONE | SE_OL_EXEC_DONE |
			SE_OL_WORK_DONE | SE_OL_NATIVE_DONE) &&
	       charges[0].state == SE_OC_OWNED && accounts[0].used == 1 &&
	       accounts[0].bits[0] == 1 && !accounts[0].fault && !held &&
	       !lock_errors);

	/* An apparent owner invalidates the empty-owner certificate. The charge
	 * becomes fault-held rather than gaining fabricated cleanup receipts. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
	reset();
	reservation = (struct se_oc_reservation){ 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_OK);
	payloads[0].semantic.exec.owned = 1;
	assert(se_op_abort_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_INITIALIZING &&
	       metas[0].active_leases == 1 && !metas[0].cleanup_done &&
	       accounts[0].fault && charges[0].state == SE_OC_FAULT_HELD &&
	       !held && !lock_errors);
#endif

	reset();
	reservation = (struct se_oc_reservation){ 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_OK);
	metas[0].work_refs = 1;
	assert(se_op_abort_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_INITIALIZING &&
	       metas[0].active_leases == 1 && !metas[0].cleanup_done &&
	       accounts[0].fault && charges[0].state == SE_OC_FAULT_HELD &&
	       !held && !lock_errors);

	reset();
	reservation = (struct se_oc_reservation){ 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_OK);
	payloads[0].identity.scope_slot++;
	assert(se_op_abort_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_INITIALIZING &&
	       metas[0].active_leases == 1 && !metas[0].cleanup_done &&
	       accounts[0].fault && charges[0].state == SE_OC_FAULT_HELD &&
	       !held && !lock_errors);

	reset();
	reservation = (struct se_oc_reservation){ 0 };
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_OK);
	metas[0].account_scope++;
	assert(se_op_abort_semantic_birth(&reservation) == SE_OL_CORRUPT);
	assert(metas[0].phase == SE_OL_INITIALIZING &&
	       metas[0].active_leases == 1 && !metas[0].cleanup_done &&
	       accounts[0].fault && charges[0].state == SE_OC_FAULT_HELD &&
	       !held && !lock_errors);
}
static void opaque_unpublished_child_roles_use_exact_constructor(void)
{
	reset();
	struct se_oc_reservation reservation = {};
	assert(se_oc_reserve(0, 10, 1, 0, &reservation) == SE_OL_OK);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_OK);
	struct se_op_child_roles_handle handle = {};
	struct er_state *roles = 0;
	assert(se_op_child_roles_begin(&reservation, &handle, &roles) ==
		       SE_OL_OK &&
	       handle.locked && held == &metas[0].lock &&
	       roles == (struct er_state *)payloads[0].bytes);
	struct er_work projected = {};
	projected.rows[0] = er_known_row(17, 2, 7);
	assert(!se_child_roles_publish(roles, &projected) &&
	       roles->version == 1 && roles->rows[0].uid == 17);
	se_op_child_roles_end(&handle, &roles);
	assert(!roles && !handle.locked && !handle.meta && !held &&
	       !lock_errors);
	payloads[0].identity.scope_cookie++;
	assert(se_op_child_roles_begin(&reservation, &handle, &roles) ==
		       SE_OL_CORRUPT &&
	       !roles && !held);
	payloads[0].identity.scope_cookie--;
	assert(se_op_abort_semantic_birth(&reservation) == SE_OL_OK);
	assert(se_op_child_roles_begin(&reservation, &handle, &roles) ==
		       SE_OL_CORRUPT &&
	       !roles && !held && !lock_errors);
}
static void opaque_second_account_partition(void)
{
#if SE_OC_ACCOUNTS > 1
	reset();
	assert(se_oc_bind_account(1, 20, 2) == SE_OL_OK);
	__u32 slot = 0;
	__u64 key = 0xb2;
	struct se_oc_reservation reservation = { 0 };
	assert(se_oc_choose_task(1, 20, 2, &slot) == SE_OL_OK &&
	       slot == SE_OC_QUOTA);
	assert(se_oc_reserve_any(1, 20, 2, &reservation) == SE_OL_OK &&
	       reservation.task_slot == slot);
	__u32 next_slot = 0;
	assert(se_oc_choose_task(1, 20, 2, &next_slot) == SE_OL_OK &&
	       next_slot == slot + 1);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_op_initialize_task_semantic(&reservation) == SE_OL_OK);
	struct se_op_child_roles_handle child_roles = {};
	struct er_state *roles = 0;
	assert(se_op_child_roles_begin(&reservation, &child_roles, &roles) ==
		       SE_OL_OK &&
	       roles == (struct er_state *)payloads[slot].bytes);
	se_op_child_roles_end(&child_roles, &roles);
	assert(se_ow_archive(&metas[slot], slot, reservation.cookie, &key) ==
	       SE_OL_OK);
	assert(se_ow_insert_zero(&metas[slot], reservation.cookie,
				 &archives[slot]) == SE_OL_OK);
	assert(se_ow_publish_zero(&metas[slot], reservation.cookie,
				  &archives[slot]) == SE_OL_OK);
	assert(se_op_finish_semantic_birth(&reservation) == SE_OL_OK);
	assert(!accounts[0].used && accounts[1].used == 1 &&
	       accounts[1].bits[0] == 1 && charges[slot].state == SE_OC_OWNED &&
	       metas[slot].account_slot == 1 &&
	       payloads[slot].identity.scope_slot == 1 &&
	       payloads[slot].identity.scope_cookie == 20);
	struct se_ol_observation observation = { 0 };
	struct se_ol_lease lease = { 0 };
	struct se_ol_payload_handle handle = { 0 };
	assert(se_ol_observe(&key, &observation) == SE_OL_OK);
	assert(se_ol_read_observation(&observation) == SE_OL_OK);
	assert(se_ol_hold_observation(&observation) == SE_OL_OK);
	assert(se_ol_relookup_convert(&observation, &lease) == SE_OL_OK);
	assert(se_ol_payload_open(&lease, &handle) == SE_OL_OK);
	void *payload = NULL;
	assert(se_ol_payload_begin(&handle, &payload) == SE_OL_OK);
	assert(payload == &payloads[slot]);
	assert(se_ol_payload_end(&handle, &payload) == SE_OL_OK);
	assert(se_ol_payload_close(&handle) == SE_OL_OK);
	assert(!metas[slot].active_leases && !held && !lock_errors);
#endif
}
static void opaque_account_bind_requires_empty_healthy_partition(void)
{
	reset();
	assert(se_oc_bind_account(0, 10, 1) == SE_OL_OK);
	struct se_oc_reservation reservation = { 0 };
	assert(se_oc_reserve_any(0, 10, 1, &reservation) == SE_OL_OK);
	assert(se_oc_bind_account(0, 11, 2) == SE_OL_CONTENDED &&
	       accounts[0].scope == 10 && accounts[0].incarnation == 1 &&
	       accounts[0].used == 1 && !accounts[0].fault);
	reset();
	assert(se_oc_bind_account(0, 11, 2) == SE_OL_OK &&
	       se_oc_bind_account(0, 11, 2) == SE_OL_OK &&
	       accounts[0].scope == 11 && accounts[0].incarnation == 2 &&
	       !accounts[0].used);
	assert(se_oc_bind_account(0, 0, 2) == SE_OL_CORRUPT &&
	       se_oc_bind_account(0, 11, 0) == SE_OL_CORRUPT &&
	       accounts[0].scope == 11 && !accounts[0].fault);
	reset();
	accounts[0].scope = 0;
	assert(se_oc_bind_account(0, 11, 2) == SE_OL_CORRUPT &&
	       accounts[0].fault);
	reset();
	accounts[0].used = 1; /* bitmap/count disagreement */
	assert(se_oc_bind_account(0, 11, 2) == SE_OL_CORRUPT &&
	       accounts[0].fault && !held && !lock_errors);
}
static void opaque_route_claim_charges_actual_account(void)
{
	reset();
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 81,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 1,
		.active_serial = 1,
		.execution_class = 2,
		.phase = SE_ROUTE_ACTIVE,
	};
	struct se_route_claim claim = {};
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 81,
				     &claim) == SE_ROUTE_OWNED);
	struct se_oc_reservation reservation = {};
	routes[0].tasks_used = 1; /* never mix legacy and opaque TASK credit */
	assert(se_oc_reserve_route_claim(&claim, &reservation) ==
		       SE_OL_CORRUPT &&
	       !accounts[0].used);
	routes[0].tasks_used = 0;
	routes[0].scratch_used =
		1; /* legacy WORK credit is equally incompatible */
	assert(se_oc_reserve_route_claim(&claim, &reservation) ==
		       SE_OL_CORRUPT &&
	       !accounts[0].used && !reservation.held);
	routes[0].scratch_used = 0;
	sequence.next_cookie = SE_OC_COOKIE_LIMIT;
	assert(se_oc_reserve_route_claim(&claim, &reservation) == SE_OL_LIMIT &&
	       !routes[0].tasks_used && !accounts[0].used &&
	       !reservation.held && !held && !lock_errors);
	sequence.next_cookie = 0;
	assert(se_oc_reserve_route_claim(&claim, &reservation) == SE_OL_OK &&
	       !routes[0].tasks_used && accounts[0].used == 1 &&
	       reservation.held && charges[0].state == SE_OC_BUILDING &&
	       !held && !lock_errors);
	/* A consumed or terminal reservation must not take another account bit. */
	assert(se_oc_reserve_route_claim(&claim, &reservation) ==
		       SE_OL_CORRUPT &&
	       !routes[0].tasks_used && accounts[0].used == 1);
	struct se_oc_reservation terminal = { .terminal = 1 };
	assert(se_oc_reserve_route_claim(&claim, &terminal) == SE_OL_CORRUPT &&
	       accounts[0].used == 1);
	struct se_binding_snapshots snapshots = { .scope = 10 };
	assert(se_oc_route_recycle(0, &snapshots) == SE_OL_STALE);
	assert(!se_route_release_locked(&routes[0], &claim));
	reservation = (struct se_oc_reservation){};
	assert(se_oc_reserve_route_claim(&claim, &reservation) ==
		       SE_OL_CORRUPT &&
	       !routes[0].tasks_used && accounts[0].used == 1 && !held &&
	       !lock_errors);
	routes[0].phase = SE_ROUTE_WITHDRAWN;
	assert(se_oc_route_recycle(0, &snapshots) == SE_OL_CONTENDED &&
	       routes[0].phase == SE_ROUTE_WITHDRAWN && accounts[0].used == 1);
#if SE_OC_ACCOUNTS > 1
	/* A second original route binds only its own empty account partition. */
	routes[1] = (struct se_route_anchor){
		.incarnation = 2,
		.cgroup_identity = 82,
		.scope = 20,
		.payload_slot = 1,
		.execution_class = 2,
		.phase = SE_ROUTE_ACTIVE,
	};
	claim = (struct se_route_claim){};
	assert(se_route_claim_locked(&routes[1], se_route_locator(1, 2), 82,
				     &claim) == SE_ROUTE_OWNED);
	assert(se_oc_reserve_route_claim(&claim, &reservation) == SE_OL_OK &&
	       reservation.task_slot == SE_OC_QUOTA && !routes[1].tasks_used &&
	       accounts[1].used == 1 && accounts[1].scope == 20 &&
	       accounts[1].incarnation == 2 && !routes[0].tasks_used &&
	       accounts[0].used == 1 && !held && !lock_errors);
	assert(!se_route_release_locked(&routes[1], &claim));
#endif
	/* The ordinary refund core is tested separately; reset represents its
	 * completed exact return, not a fabricated cleanup producer. */
	reset();
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.scope = 10,
		.payload_slot = 0,
		.phase = SE_ROUTE_WITHDRAWN,
	};
	snapshots = (struct se_binding_snapshots){ .scope = 10 };
	assert(se_oc_route_recycle(0, &snapshots) == SE_OL_OK &&
	       routes[0].phase == SE_ROUTE_FREE);
	reset();
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.scope = 10,
		.payload_slot = 0,
		.phase = SE_ROUTE_WITHDRAWN,
	};
	accounts[0].fault = 1;
	assert(se_oc_route_recycle(0, &snapshots) == SE_OL_CORRUPT &&
	       routes[0].phase == SE_ROUTE_WITHDRAWN);
	accounts[0].fault = 0;
	recycle_race = 1;
	assert(se_oc_route_recycle(0, &snapshots) == SE_OL_STALE &&
	       routes[0].phase == SE_ROUTE_ACTIVE && routes[0].scope == 11 &&
	       routes[0].incarnation == 2 && !held && !lock_errors);
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
static void opaque_charged_birth_requires_role_projection(void)
{
	reset();
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 81,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 1,
		.active_serial = 1,
		.execution_class = 2,
		.phase = SE_ROUTE_ACTIVE,
	};
	struct se_route_claim claim = {};
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 81,
				     &claim) == SE_ROUTE_OWNED);
	struct se_oc_reservation reservation = {};
	assert(se_op_prepare_charged_child(&claim, &reservation) == SE_OL_OK);
	__u32 slot = reservation.task_slot;
	__u64 key = 0xa1;
	struct se_snapshot snapshot = {
		.scope = 10, .serial = 1, .generation = 1, .count = 1,
		.metadata = {
			.root_epochs = { 1 }, .policy_uids = { 17 },
			.container_length = 1, .container = "/",
		},
	};
	struct er_work projected = { .authority_version = 1 };
	assert(se_op_publish_charged_child(&claim, &snapshot, &projected, &key,
					   &reservation) != SE_OL_OK);
	assert(reservation.terminal && !cells[0].present &&
	       !payloads[slot].semantic.committed.version && !held &&
	       !lock_errors);
	assert(!se_route_release_locked(&routes[0], &claim));

	reset();
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 81,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 1,
		.active_serial = 1,
		.execution_class = 2,
		.phase = SE_ROUTE_ACTIVE,
	};
	claim = (struct se_route_claim){};
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 81,
				     &claim) == SE_ROUTE_OWNED);
	reservation = (struct se_oc_reservation){};
	assert(se_op_prepare_charged_child(&claim, &reservation) == SE_OL_OK);
	slot = reservation.task_slot;
	projected = (struct er_work){ .authority_version = 1, .prepared = 1 };
	projected.rows[0] = er_known_row(17, 1, 7);
	snapshot.metadata.policy_uids[0] = 18; /* valid but wrong root */
	assert(se_op_publish_charged_child(&claim, &snapshot, &projected, &key,
					   &reservation) != SE_OL_OK);
	assert(reservation.terminal && !cells[0].present &&
	       !payloads[slot].semantic.committed.version && !held &&
	       !lock_errors);
	assert(!se_route_release_locked(&routes[0], &claim));
	snapshot.metadata.policy_uids[0] = 17;

	reset();
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 81,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 1,
		.active_serial = 1,
		.execution_class = 2,
		.phase = SE_ROUTE_ACTIVE,
	};
	claim = (struct se_route_claim){};
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 81,
				     &claim) == SE_ROUTE_OWNED);
	reservation = (struct se_oc_reservation){};
	assert(se_op_prepare_charged_child(&claim, &reservation) == SE_OL_OK);
	slot = reservation.task_slot;
	projected = (struct er_work){ .authority_version = 1, .prepared = 1 };
	projected.rows[0] = er_known_row(17, 1, 7);
	assert(se_op_publish_charged_child(&claim, &snapshot, &projected, &key,
					   &reservation) == SE_OL_OK);
	assert(reservation.terminal && cells[0].present &&
	       cells[0].key == key &&
	       payloads[slot].semantic.committed.version == 1 &&
	       payloads[slot].semantic.committed.rows[0].uid == 17 && !held &&
	       !lock_errors);
	assert(!se_route_release_locked(&routes[0], &claim));
}

static void opaque_charged_birth_replaces_only_dead_same_key(void)
{
	struct se_snapshot snapshot = {
		.scope = 10, .serial = 1, .generation = 1, .count = 1,
		.metadata = {
			.root_epochs = { 1 }, .policy_uids = { 17 },
			.container_length = 1, .container = "/",
		},
	};
	struct er_work projected = { .authority_version = 1, .prepared = 1 };
	projected.rows[0] = er_known_row(17, 1, 7);
	__u64 key = 0xa1;
	for (int mode = 0; mode < 4; mode++) {
		reset();
		routes[0] = (struct se_route_anchor){
			.incarnation = 1,
			.cgroup_identity = 81,
			.scope = 10,
			.payload_slot = 0,
			.payload_generation = 1,
			.active_serial = 1,
			.execution_class = 2,
			.phase = SE_ROUTE_ACTIVE,
		};
		struct se_route_claim claim = {};
		assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1),
					     81, &claim) == SE_ROUTE_OWNED);
		struct se_oc_reservation first = {};
		assert(se_op_prepare_charged_child(&claim, &first) == SE_OL_OK);
		assert(se_op_publish_charged_child(&claim, &snapshot,
						   &projected, &key,
						   &first) == SE_OL_OK);
		__u32 old_slot = first.task_slot;
		__u64 old_locator = first.locator;
		if (mode != 0)
			metas[old_slot].phase =
				SE_OL_DEAD; /* synthetic death edge */
		struct se_oc_reservation second = {};
		assert(se_op_prepare_charged_child(&claim, &second) ==
			       SE_OL_OK &&
		       second.task_slot != old_slot);
		if (mode == 2)
			replace_cas_fault = 1;
		if (mode == 3)
			vanish_after_eexist = 1;
		int result = se_op_publish_charged_child(
			&claim, &snapshot, &projected, &key, &second);
		if (mode == 3) {
			/* The key vanished after EEXIST: one fresh insertion,
			 * no abort and no replacement of the old charge. */
			assert(result == SE_OL_OK && second.terminal &&
			       metas[second.task_slot].phase == SE_OL_LIVE &&
			       metas[old_slot].phase == SE_OL_DEAD &&
			       !metas[old_slot].exclusive && cells[0].present &&
			       cells[0].key == key &&
			       cells[0].locator == second.locator &&
			       !vanish_after_eexist);
		} else if (mode == 1) {
			assert(result == SE_OL_OK && second.terminal &&
			       metas[old_slot].directory_state ==
				       SE_OL_DELETED &&
			       (metas[old_slot].cleanup_done &
				SE_OL_DIR_DONE) &&
			       metas[second.task_slot].phase == SE_OL_LIVE &&
			       cells[0].locator == second.locator &&
			       cells[0].locator != old_locator);
		} else if (mode == 0) {
			assert(result != SE_OL_OK && second.terminal &&
			       metas[old_slot].phase == SE_OL_LIVE &&
			       metas[old_slot].directory_state ==
				       SE_OL_PUBLISHED &&
			       metas[second.task_slot].phase == SE_OL_ABORTED &&
			       cells[0].locator == old_locator);
		} else {
			assert(result != SE_OL_OK && !second.terminal &&
			       accounts[0].fault &&
			       charges[second.task_slot].state ==
				       SE_OC_FAULT_HELD &&
			       metas[old_slot].exclusive &&
			       metas[old_slot].exclusive_owner ==
				       second.locator &&
			       metas[old_slot].directory_state ==
				       SE_OL_PUBLISHED &&
			       cells[0].locator == old_locator);
		}
		assert(accounts[0].used == 2 && !held && !lock_errors);
		if (mode != 2)
			assert(!accounts[0].fault &&
			       !metas[old_slot].exclusive);
		assert(!se_route_release_locked(&routes[0], &claim));
	}
}
#endif
static void opaque_route_recycle_follows_exact_account_refund(void)
{
	reset();
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 81,
		.scope = 10,
		.payload_slot = 0,
		.execution_class = 2,
		.phase = SE_ROUTE_ACTIVE,
	};
	struct se_route_claim claim = {};
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 81,
				     &claim) == SE_ROUTE_OWNED);
	struct se_oc_reservation reservation = {};
	assert(se_oc_reserve_route_claim(&claim, &reservation) == SE_OL_OK);
	__u64 cookie = reservation.cookie;
	assert(!se_route_release_locked(&routes[0], &claim));
	/* This host-only withdrawal stands in for the separately tested route
	 * snapshot/locator protocol; it does not forge TASK cleanup receipts. */
	routes[0].phase = SE_ROUTE_WITHDRAWN;
	struct se_binding_snapshots snapshots = { .scope = 10 };
	assert(se_oc_route_recycle(0, &snapshots) == SE_OL_CONTENDED);
	assert(se_oc_begin_charged(&reservation) == SE_OL_OK);
	assert(se_ow_abort_constructor(&metas[0], cookie) == SE_OL_OK);
	assert(se_ow_mark_absent_deleted(&metas[0], cookie) == SE_OL_OK);
	assert(se_ow_zero_archive(&metas[0], cookie) == SE_OL_OK);
	assert(se_oc_route_recycle(0, &snapshots) == SE_OL_CONTENDED);
	/* EXEC/WORK/native completion remains synthetic here; the refund
	 * transition itself is the real candidate implementation. */
	metas[0].cleanup_done |= SE_OL_ALL_DONE ^
				 (SE_OL_CONSTRUCTION_DONE | SE_OL_DIR_DONE |
				  SE_OL_PAYLOAD_ZERO_DONE);
	assert(se_op_zero_payload(0, cookie) == SE_OC_PROGRESS);
	for (unsigned i = 0; i < 3; i++) {
		assert(se_oc_refund_step(0, cookie) == SE_OC_PROGRESS);
		assert(se_oc_route_recycle(0, &snapshots) == SE_OL_CONTENDED);
	}
	assert(se_oc_refund_step(0, cookie) == SE_OC_RETURNED &&
	       !accounts[0].used && !accounts[0].bits[0] &&
	       charges[0].last_returned == cookie);
	assert(se_oc_route_recycle(0, &snapshots) == SE_OL_OK &&
	       routes[0].phase == SE_ROUTE_FREE);
	assert(se_oc_refund_step(0, cookie) == SE_OC_ALREADY_RETURNED);
	/* A successor route may reuse this empty account only after recycle;
	 * the old cookie must never refund the new TASK. */
	assert(!se_route_open_locked(&routes[0], 82, 20, 0));
	routes[0].execution_class = 2;
	routes[0].phase = SE_ROUTE_ACTIVE;
	claim = (struct se_route_claim){};
	reservation = (struct se_oc_reservation){};
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 2), 82,
				     &claim) == SE_ROUTE_OWNED);
	assert(se_oc_reserve_route_claim(&claim, &reservation) == SE_OL_OK &&
	       reservation.cookie > cookie && accounts[0].used == 1 &&
	       accounts[0].scope == 20 && accounts[0].incarnation == 2);
	assert(!se_route_release_locked(&routes[0], &claim));
	assert(se_oc_refund_step(0, cookie) == SE_OC_STALE &&
	       accounts[0].used == 1 && !held && !lock_errors);
}
static void opaque_choose_refuses_bad_account(void)
{
	reset();
	__u32 slot = 0;
	assert(se_oc_choose_task(0, 11, 1, &slot) == SE_OL_STALE);
	assert(!slot && !accounts[0].fault);
	accounts[0].used = 1; /* bitmap/count contradiction */
	assert(se_oc_choose_task(0, 10, 1, &slot) == SE_OL_CORRUPT);
	assert(!slot && accounts[0].fault && !held && !lock_errors);
#if SE_OC_QUOTA <= 64
	reset();
#if SE_OC_QUOTA == 64
	accounts[0].bits[0] = ~0ULL;
#else
	accounts[0].bits[0] = (1ULL << SE_OC_QUOTA) - 1ULL;
#endif
	accounts[0].used = SE_OC_QUOTA;
	assert(se_oc_choose_task(0, 10, 1, &slot) == SE_OL_LIMIT);
	struct se_oc_reservation reservation = { 0 };
	assert(se_oc_reserve_any(0, 10, 1, &reservation) == SE_OL_LIMIT);
	assert(!slot && !accounts[0].fault && !held && !lock_errors);
#endif
}
static void opaque_reserve_reobserves_after_lost_slot(void)
{
	reset();
	__u32 observed = 0;
	struct se_oc_reservation winner = { 0 }, loser = { 0 }, next = { 0 };
	assert(se_oc_choose_task(0, 10, 1, &observed) == SE_OL_OK &&
	       observed == 0);
	assert(se_oc_reserve(0, 10, 1, observed, &winner) == SE_OL_OK);
	assert(se_oc_reserve(0, 10, 1, observed, &loser) == SE_OL_CONTENDED);
	assert(!loser.held && !loser.charge && accounts[0].used == 1 &&
	       accounts[0].bits[0] == 1);
	assert(se_oc_reserve_any(0, 10, 1, &next) == SE_OL_OK &&
	       next.task_slot == 1 && accounts[0].used == 2 &&
	       accounts[0].bits[0] == 3 && !accounts[0].fault && !held &&
	       !lock_errors);
}
static void opaque_reserve_retries_interleaved_winners(void)
{
	reset();
	struct se_oc_reservation reservation = { 0 };
	steal_remaining = 3;
	assert(se_oc_reserve_any(0, 10, 1, &reservation) == SE_OL_OK);
	assert(steal_calls == 3 && !steal_remaining &&
	       reservation.task_slot == 3 && reservation.held == 1 &&
	       accounts[0].used == 4 && accounts[0].bits[0] == 0xf &&
	       !accounts[0].fault && !held && !lock_errors);
	for (unsigned i = 0; i < 4; i++)
		assert(charges[i].state == SE_OC_BUILDING);
#if SE_OC_QUOTA > 8
	reset();
	reservation = (struct se_oc_reservation){ 0 };
	steal_remaining = 8;
	assert(se_oc_reserve_any(0, 10, 1, &reservation) == SE_OL_CONTENDED);
	assert(steal_calls == 8 && !steal_remaining && !reservation.held &&
	       !reservation.charge && accounts[0].used == 8 &&
	       accounts[0].bits[0] == 0xff && sequence.next_cookie == 16 &&
	       !accounts[0].fault && !held && !lock_errors);
	for (unsigned i = 0; i < 8; i++)
		assert(charges[i].state == SE_OC_BUILDING);
	assert(se_oc_reserve_any(0, 10, 1, &reservation) == SE_OL_OK &&
	       reservation.task_slot == 8 && accounts[0].used == 9 &&
	       accounts[0].bits[0] == 0x1ff && !held && !lock_errors);
#endif
}
#if defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE)
/* G019 gap 3: a reader (or a parked birth claim) of generation 1 keeps its
 * record after generation 2 commits (record 0 RETIRING). Its catalogue is
 * the binding's write-once (scope, UID) cell: the cache it fills after the
 * commit is identical, and any epoch change fails closed. */
struct opaque_retiring_fixture {
	struct se_ol_payload_handle owner;
	struct se_owk_ticket ticket;
	struct se_owk_semantic_handle handle;
	struct se_invocation *work;
	struct se_task_state *task;
};
static void opaque_retiring_open(struct opaque_retiring_fixture *f)
{
	__u64 key = seed_live_opaque_task_for_open();
	__u32 slot = 0;
	*f = (struct opaque_retiring_fixture){};
	assert(se_ol_task_open(&key, &f->owner) == SE_OL_OK);
	assert(se_owk_bind_owner(&f->owner) == SE_OL_OK);
	assert(se_owk_choose(&f->owner, &slot) == SE_OL_OK && slot == 0);
	assert(se_owk_begin(&f->owner, slot, &f->ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&f->owner, &f->ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&f->owner, &f->ticket) == SE_OL_OK);
	assert(se_owk_commit(&f->owner, &f->ticket) == SE_OL_OK);
	assert(se_owk_semantic_open(&f->owner, &f->ticket, &f->handle,
				    &f->work) == SE_OL_OK);
	f->task = &payloads[0].semantic;
	f->task->exec = (struct se_exec_transaction){
		.owned = 1,
		.bprm = 0x1234,
		.sequence = 9,
		.generation = 1,
		.execution_class = 1,
		.policy_count = 1,
	};
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 7,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 1,
		.active_serial = 1,
		.execution_class = 1,
		.phase = SE_ROUTE_ACTIVE,
		.rec = { { .serial = 1,
			   .generation = 1,
			   .phase = SE_SNAPSHOT_ACTIVE } },
	};
	bindings[0] = (struct se_binding_snapshots){
		.scope = 10,
		.generation = 1,
		.active_serial = 1,
		.records = { { .scope = 10,
			       .serial = 1,
			       .generation = 1,
			       .phase = SE_SNAPSHOT_ACTIVE,
			       .execution_class = 1 } },
	};
	f->task->committed.version = 7;
	f->task->committed.rows[0] = er_known_row(1, 13, 3);
	se_exec_snapshot_locked(f->task, 1, &f->work->history);
}
/* Generation 2 commits into record 1; record 0 keeps its holders. */
static void opaque_retiring_commit(void)
{
	bindings[0].generation = 2;
	bindings[0].active_record = 1;
	bindings[0].active_serial = 2;
	bindings[0].records[0].phase = SE_SNAPSHOT_RETIRING;
	bindings[0].records[1] = (struct se_snapshot){
		.scope = 10,
		.serial = 2,
		.generation = 2,
		.phase = SE_SNAPSHOT_ACTIVE,
		.execution_class = 1,
	};
	routes[0].payload_generation = 2;
	routes[0].active_serial = 2;
	routes[0].active_record = 1;
	routes[0].rec[0].phase = SE_SNAPSHOT_RETIRING;
	routes[0].rec[1] = (struct se_route_rec){ .serial = 2,
						  .generation = 2,
						  .phase = SE_SNAPSHOT_ACTIVE };
}
static void opaque_retiring_close(struct opaque_retiring_fixture *f)
{
	assert(se_owk_semantic_done(&f->handle, &f->work) == SE_OL_OK);
	assert(se_ol_payload_close(&f->owner) == SE_OL_OK);
	assert(!held && !lock_errors);
	opaque_catalogue_epoch = 13;
}
static void opaque_retiring_reader(struct opaque_retiring_fixture *f)
{
	struct se_route_claim claim = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &claim) == SE_ROUTE_OWNED);
	assert(!se_exec_reader_attach_locked(&routes[0], &bindings[0], f->task,
					     &claim, f->owner.lease.cookie,
					     f->task->exec.sequence));
	bpf_spin_unlock(&routes[0].lock);
	assert(bindings[0].records[0].claims == 1 && !routes[0].early_claims);
}

/* (a) The reader's catalogue after the commit is the identical one. */
static void retiring_reader_catalogue_after_commit_is_identical(void)
{
	struct opaque_retiring_fixture f;
	opaque_retiring_open(&f);
	opaque_retiring_reader(&f);
	assert(se_owk_catalogue_fill_reader(&f.handle) == SE_OL_OK);
	struct se_pool_epoch_cache before = f.handle.payload->catalogue;
	opaque_retiring_commit();
	f.handle.payload->catalogue = (struct se_pool_epoch_cache){};
	assert(se_owk_catalogue_fill_reader(&f.handle) == SE_OL_OK);
	assert(!memcmp(&before, &f.handle.payload->catalogue, sizeof(before)));
	assert(se_owk_catalogue_classify_reader(&f.handle) == SE_OL_OK &&
	       f.work->history.view.accepted_mask == 1);
	/* The reader releases on its RETIRING record. */
	bpf_spin_lock(&routes[0].lock);
	assert(!se_exec_reader_release_locked(&bindings[0], f.task,
					      f.owner.lease.cookie,
					      f.task->exec.sequence));
	bpf_spin_unlock(&routes[0].lock);
	assert(!bindings[0].records[0].claims);
	opaque_retiring_close(&f);
}

/* (b) An epoch changed behind the reader (E+1) fails closed: CORRUPT, no
 * accepted role. */
static void retiring_reader_epoch_mismatch_fails_closed(void)
{
	struct opaque_retiring_fixture f;
	opaque_retiring_open(&f);
	opaque_retiring_reader(&f);
	opaque_retiring_commit();
	opaque_catalogue_epoch = 14;
	assert(se_owk_catalogue_fill_reader(&f.handle) == SE_OL_OK);
	assert(se_owk_catalogue_classify_reader(&f.handle) == SE_OL_CORRUPT &&
	       !f.work->history.view.accepted_mask);
	bindings[0].records[0].claims = 0;
	opaque_retiring_close(&f);
}

/* (c) An epoch 0 cell (never activated) fails the role fill closed. */
static void retiring_reader_epoch_zero_fails_closed(void)
{
	struct opaque_retiring_fixture f;
	opaque_retiring_open(&f);
	opaque_retiring_reader(&f);
	opaque_retiring_commit();
	opaque_catalogue_epoch = 0;
	/* The present index's cell reads ER_UNKNOWN (se_catalogue_read). */
	assert(se_owk_catalogue_fill_reader(&f.handle) == SE_OL_CORRUPT);
	assert(!f.handle.payload->catalogue.scope &&
	       !f.handle.payload->catalogue.generation);
	bindings[0].records[0].claims = 0;
	opaque_retiring_close(&f);
}

/* (d) A parked birth claim of generation 1 (record 0) projects against the
 * identical catalogue after generation 2 commits, and fails closed when the
 * epoch changed. */
static void retiring_parked_claim_projects_exactly(void)
{
	struct opaque_retiring_fixture f;
	opaque_retiring_open(&f);
	struct se_route_claim parked = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &parked) == SE_ROUTE_OWNED &&
	       parked.record == 0);
	bpf_spin_unlock(&routes[0].lock);
	opaque_retiring_commit();
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_valid(&routes[0], &parked));
	bpf_spin_unlock(&routes[0].lock);
	assert(se_owk_catalogue_fill(&f.handle, &parked) == SE_OL_OK);
	assert(!se_pool_catalogue_classify_after_authority(
		       &f.work->history.view, &f.handle.payload->catalogue, 10,
		       1) &&
	       f.work->history.view.accepted_mask == 1);
	opaque_catalogue_epoch = 14;
	f.handle.payload->catalogue = (struct se_pool_epoch_cache){};
	assert(se_owk_catalogue_fill(&f.handle, &parked) == SE_OL_OK);
	assert(se_pool_catalogue_classify_after_authority(
		       &f.work->history.view, &f.handle.payload->catalogue, 10,
		       1) &&
	       !f.work->history.view.accepted_mask);
	bpf_spin_lock(&routes[0].lock);
	assert(!se_route_release_locked(&routes[0], &parked));
	bpf_spin_unlock(&routes[0].lock);
	assert(!routes[0].early_claims && !routes[0].rec[0].early_claims);
	opaque_retiring_close(&f);
}
#endif

int main(void)
{
#if defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) && \
	defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE)
	/* The product variant (per-record route holders, G019 gap 3) runs only
	 * its own scenarios: every other one seeds pre-gap-3 routes. */
	reset();
	retiring_reader_catalogue_after_commit_is_identical();
	reset();
	retiring_reader_epoch_mismatch_fails_closed();
	reset();
	retiring_reader_epoch_zero_fails_closed();
	reset();
	retiring_parked_claim_projects_exactly();
	puts("opaque locator candidate host regressions: PASS");
	return 0;
#endif
	normal_lease();
	recycled_backing_wrong_key();
	same_key_successor_before_hold();
	original_key_disappears_after_hold();
	locator_bounds();
	contradiction_retains_hold();
	new_key_withdraw_and_successor();
	writer_failures_retain_charge();
	post_cas_withdrawal_receipt_retry();
	aborted_before_hash_insert();
	aborted_zero_owned_cleanup();
	aborted_publish_intent_reconciliation();
	aborted_publish_intent_before_cas();
	unreconciled_insert_intent_remains_charged();
	same_key_replacement_and_old_cleanup();
	replacement_two_reader_holds();
	replacement_recycled_wrong_backing();
	replacement_cancel_and_cas_fault();
	replacement_refuses_active_old_lease();
	replacement_invalid_new_releases_old_hold();
	archived_key_must_be_exact_slot_value();
	typed_final_free_records_exact_death();
	native_empty_owner_receipt_requires_exact_death();
	opaque_final_free_has_exact_dead_semantic_lease();
	death_racing_constructor_finish_stays_dead();
	unmatched_final_free_has_no_authority();
	final_free_withdraws_directory_before_reuse();
	final_free_withdrawal_falls_back_to_reaper();
	final_free_recycled_backing_cannot_kill_other_task();
	charged_constructor_retains_exact_credit();
	charged_constructor_faults_do_not_refund();
	charged_cookies_are_unique_across_slots();
	charged_refund_requires_all_source_receipts();
	charged_refund_refuses_corrupt_metadata();
	charged_refund_synthetic_lifetime_churn();
	opaque_payload_handle_requires_exact_lease();
	opaque_task_open_is_one_exact_lexical_lease();
	opaque_work_credit_requires_held_exact_task();
	opaque_work_credit_fails_closed_on_owner_or_account_fault();
	reset();
	opaque_work_reserve_older_cookie_is_contended();
	reset();
	opaque_work_reserve_equal_cookie_faults();
	reset();
	opaque_work_precharge_pin_rolls_back_after_death();
	opaque_work_abort_building_quarantines_faulted_account();
	opaque_work_credit_partition_and_limit();
	opaque_work_credit_reuses_one_slot_for_4097_lifetimes();
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
	opaque_work_catalogue_requires_held_authority();
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
	opaque_dead_terminal_requires_source_exec_receipt();
	opaque_exec_reader_begin_uses_exact_task_and_route();
	opaque_exec_reader_unobserved_success_quarantines();
	opaque_exec_reader_failed_recovery_quarantines();
	opaque_work_catalogue_accepts_only_exact_reader();
	opaque_scoped_publisher_matches_canonical();
	opaque_work_prepared_exec_commits_under_exact_reader(1);
	opaque_work_prepared_exec_commits_under_exact_reader(0);
	opaque_postcommit_reader_retry_is_exact_and_patch_free(1);
	opaque_postcommit_reader_retry_is_exact_and_patch_free(0);
#endif
	opaque_work_semantic_handle_requires_exact_ticket();
	opaque_parent_snapshot_requires_exact_task_and_work();
	opaque_work_semantic_bad_ticket_faults_credit();
#endif
	opaque_work_owner_attach_is_exact_and_persistent();
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
	opaque_work_continuation_reopens_one_exact_lease();
#ifdef ENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE
	opaque_suspended_current_read_requires_exact_identity();
#ifdef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
	opaque_suspended_corrupt_commit_never_refunds();
#endif
#endif
	opaque_work_continuation_faults_bad_charge();
	opaque_work_continuation_death_closes_suspended_work();
	opaque_work_continuation_death_after_resume_claim();
#endif
	opaque_work_attach_faults_after_task_death();
	opaque_work_semantic_failure_retains_owner_and_credit();
	opaque_work_done_faults_corrupt_semantic_but_closes_lease();
	opaque_work_reaper_releases_exact_owner_and_credit();
	opaque_work_reaper_receipts_after_task_directory_retirement();
	opaque_work_fault_cleanup_retains_quarantined_credit();
	opaque_work_reaper_quarantines_account_contradiction();
	opaque_route_recycle_waits_for_both_owner_accounts();
	opaque_semantic_constructor_abort_retains_charge();
	opaque_unpublished_child_roles_use_exact_constructor();
	opaque_second_account_partition();
	opaque_account_bind_requires_empty_healthy_partition();
	opaque_route_claim_charges_actual_account();
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
	opaque_charged_birth_requires_role_projection();
	opaque_charged_birth_replaces_only_dead_same_key();
#endif
	opaque_route_recycle_follows_exact_account_refund();
	opaque_choose_refuses_bad_account();
	opaque_reserve_reobserves_after_lost_slot();
	opaque_reserve_retries_interleaved_winners();
	puts("opaque locator candidate host regressions: PASS");
	return 0;
}
