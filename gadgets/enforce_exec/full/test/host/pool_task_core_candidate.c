/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Host regression of the copied product headers. Semantic payload shells only
 * satisfy unrelated ABI layout checks; all pool transitions use real headers. */
#include <linux/bpf.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __uint(name, val) int(*name)[val]
#define __type(name, val) val *name
#define SEC(name)
#define ENFORCE_EXEC_POOL_DEVELOPMENT 1
#define ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY 1
#define ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE 1
#define ENFORCE_EXEC_SHARED_RECOVERY 1
#define SE_TASK_VERIFIED 1u
#define SE_TASK_QUARANTINED 2u
#define SE_TASK_LIVE 4u
#define SE_TASK_QUALIFIED (SE_TASK_VERIFIED | SE_TASK_LIVE)
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#define ENFORCE_EXEC_SHARED_NODE 1
#define SE_PROFILE_TASKS 16384
#define SE_PROFILE_SCRATCH 256
#define SE_PROFILE_BINDINGS 2
#define SE_PROFILE_TASK_QUOTA 8192
#define SE_PROFILE_SCRATCH_QUOTA 128
static __u64 accepted_epochs[64];
static __u64 test_catalogue_epoch(__u64 scope, __u64 uid)
{
	return scope == 0x200 && uid < 64 ? accepted_epochs[uid] : ~(__u64)0;
}
#define ER_ACCEPTED_EPOCH(uid) test_catalogue_epoch(0x200, (uid))
#include "epoch_roles.h"
#include "shared_inherit_roles.h"
struct se_task_stage {
	_Alignas(8) char v[64];
};
struct se_exec_transaction {
	__u64 bprm, sequence, generation, eligibility_version;
	__u32 owned, known_deny, grants, hard_fault;
	char v[272 - 48];
};
_Static_assert(sizeof(struct se_exec_transaction) == 272,
	       "host transaction shell retains product size");
struct se_policy_view {
	_Alignas(8) char v[904];
};
struct se_exec_work {
	__u64 physical_cookie, scope_cookie, eligibility_version;
	__u32 flags, reserved;
	struct se_exec_transaction transaction;
	struct er_canonical_view view;
	struct er_fact_patch patch;
	struct er_row desired[8];
};
struct observation {
	_Alignas(8) char v[16008];
};
struct se_invocation {
	__u64 scope, cookie, sequence;
	__u32 slot, reserved;
	struct se_policy_view view;
	struct se_exec_work history;
	struct er_work inherited;
	struct observation observation;
};
static struct bpf_spin_lock *held;
static unsigned failures, lookups, locks, unlocks;
static unsigned movement_faults;
static void se_exec_fault_locked(struct se_exec_transaction *tx)
{
	assert(tx && held);
	tx->hard_fault = 1;
	tx->grants = 0;
	movement_faults++;
}
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	if (held)
		failures++;
	held = lock;
	locks++;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	if (held != lock)
		failures++;
	held = 0;
	unlocks++;
}
static void *bpf_map_lookup_elem(const void *, const void *);
static long bpf_map_update_elem(const void *, const void *, const void *,
				__u64);
#include "shared_route.h"
struct se_task_state {
	__u32 reserved_lock, flags;
	__u64 physical_cookie, scope_cookie, eligibility_version,
		next_invocation;
	__u32 scope_slot, identity_reserved;
	struct er_state committed;
	struct se_task_stage staged;
	struct se_reader_owner reader;
	__u64 reader_invocation;
	struct se_exec_transaction exec;
};
#include "shared_inherit_snapshot.h"
static struct se_route_anchor *se_route_anchor_lookup(const __u32 *);
static void task_tail_after_charge(void);
static void task_tail_after_meta(void);
static void task_tail_before_meta_free(void);
#define SE_POOL_TASK_TAIL_AFTER_CHARGE() task_tail_after_charge()
#define SE_POOL_TASK_TAIL_AFTER_META() task_tail_after_meta()
#define SE_POOL_TASK_TAIL_BEFORE_META_FREE() task_tail_before_meta_free()
#include "shared_pool_abi_candidate.h"
#include "shared_pool_task_core.h"
#include "shared_pool_work_core.h"
#include "shared_pool_task_semantic_candidate.h"
#include "shared_pool_task_movement_candidate.h"
#include "shared_pool_exec_fault_candidate.h"
#include "shared_pool_work_semantic_candidate.h"
struct fm_global_token {
	__u32 slot, reserved;
	__u64 cookie;
};
_Static_assert(sizeof(struct fm_global_token) == 16,
	       "scalar matcher token ABI");
#include "shared_pool_eval_candidate.h"
#define SE_POOL_CATALOGUE_EPOCH(scope, uid) test_catalogue_epoch((scope), (uid))
#include "shared_pool_catalogue_candidate.h"
#include "shared_pool_inherit_candidate.h"
#include "shared_pool_task_reap_candidate.h"
struct task_struct {
	int unused;
};
#include "shared_recovery_abi.h"
static struct rm_config recovery_config;
static struct rm_control recovery_control;
static __u64 current_task;
static __u64 bpf_get_current_task(void)
{
	return current_task;
}
#define SE_RECOVERY_TEST 1
#define SE_RM_CONFIG_LOOKUP(key) ((void)(key), &recovery_config)
#define SE_RM_CONTROL_LOOKUP(key) ((void)(key), &recovery_control)
#include "shared_recovery_kernel.h"
#include "shared_pool_reaper_control_candidate.h"
#include "shared_pool_reaper_visit_candidate.h"
#include "shared_pool_reaper_chunk_candidate.h"
static struct se_route_anchor route[SE_POOL_B];
static struct se_route_anchor *se_route_anchor_lookup(const __u32 *key)
{
	if (held || !key)
		failures++;
	lookups++;
	return key && *key < SE_POOL_B ? &route[*key] : 0;
}
static struct se_pool_bitmap bitmaps[SE_POOL_B];
static struct se_pool_charge charges[SE_POOL_T + SE_POOL_W];
static struct se_pool_task_meta tasks[SE_POOL_T];
static struct se_pool_task_payload *payloads;
static const struct se_pool_task_payload zero_task;
static struct se_pool_work_meta works[SE_POOL_W];
static struct se_pool_work_payload *work_payloads;
static const struct se_pool_work_payload zero_work;
static int omit_zero_task, fail_zero_update;
static struct se_pool_directory dirs[SE_POOL_D];
static struct se_pool_sequence sequence;
static int tail_cut;
static void task_tail_cut_charge(void)
{
	assert(!held && !route[0].tasks_used &&
	       charges[0].state == SE_POOL_CH_FREE);
	bpf_spin_lock(&route[0].lock);
	charges[0].current_cookie = 1;
	charges[0].account_scope = route[0].scope;
	charges[0].account_incarnation = route[0].incarnation;
	charges[0].state = SE_POOL_CH_BUILDING;
	bitmaps[0].words[0] |= 1;
	route[0].tasks_used = 1;
	bpf_spin_unlock(&route[0].lock);
	tail_cut = 0;
}
static void task_tail_after_charge(void)
{
	if (tail_cut == 1)
		task_tail_cut_charge();
}
static void task_tail_after_meta(void)
{
	if (tail_cut == 2)
		task_tail_cut_charge();
}
static void task_tail_before_meta_free(void)
{
	if (tail_cut != 3)
		return;
	assert(!held && tasks[0].phase == SE_POOL_REFUND_PENDING);
	bpf_spin_lock(&tasks[0].lock);
	tasks[0].active_leases = 1;
	bpf_spin_unlock(&tasks[0].lock);
	tail_cut = 0;
}
static void *bpf_map_lookup_elem(const void *map, const void *key)
{
	if (held || !key)
		failures++;
	lookups++;
	if (!key)
		return 0;
	__u32 n = *(__u32 *)key;
	if (map == &se_pool_bitmaps)
		return n < SE_POOL_B ? &bitmaps[n] : 0;
	if (map == &se_pool_charges)
		return n < SE_POOL_T + SE_POOL_W ? &charges[n] : 0;
	if (map == &se_pool_task_meta)
		return n < SE_POOL_T ? &tasks[n] : 0;
	if (map == &se_pool_task_payload)
		return n < SE_POOL_T ? &payloads[n] : 0;
	if (map == &se_pool_task_zero)
		return n == 0 && !omit_zero_task ? (void *)&zero_task : 0;
	if (map == &se_pool_work_meta)
		return n < SE_POOL_W ? &works[n] : 0;
	if (map == &se_pool_work_payload)
		return n < SE_POOL_W ? &work_payloads[n] : 0;
	if (map == &se_pool_work_zero)
		return n == 0 ? (void *)&zero_work : 0;
	if (map == &se_pool_directory)
		return n < SE_POOL_D ? &dirs[n] : 0;
	if (map == &se_pool_sequence)
		return n == 0 ? &sequence : 0;
	failures++;
	return 0;
}
static long bpf_map_update_elem(const void *map, const void *key,
				const void *value, __u64 flags)
{
	if (held || !key || !value || flags != BPF_ANY) {
		failures++;
		return -1;
	}
	__u32 slot = *(__u32 *)key;
	if (map == &se_pool_task_payload && value == &zero_task &&
	    slot < SE_POOL_T) {
		if (fail_zero_update)
			return -1;
		memcpy(&payloads[slot], value, sizeof(payloads[slot]));
		return 0;
	}
	if (map == &se_pool_work_payload && value == &zero_work &&
	    slot < SE_POOL_W) {
		memcpy(&work_payloads[slot], value,
		       sizeof(work_payloads[slot]));
		return 0;
	}
	failures++;
	return -1;
}
static void reset(void)
{
	memset(route, 0, sizeof(route));
	memset(bitmaps, 0, sizeof(bitmaps));
	memset(accepted_epochs, 0, sizeof(accepted_epochs));
	memset(charges, 0, sizeof(charges));
	memset(tasks, 0, sizeof(tasks));
	memset(works, 0, sizeof(works));
	memset(work_payloads, 0, SE_POOL_W * sizeof(*work_payloads));
	memset(dirs, 0, sizeof(dirs));
	memset(&sequence, 0, sizeof(sequence));
	for (unsigned i = 0; i < SE_POOL_B; i++) {
		route[i].phase = SE_ROUTE_ACTIVE;
		route[i].incarnation = 1;
		route[i].cgroup_identity = 0x100 + i;
		route[i].scope = 0x200 + i;
		route[i].payload_slot = i;
		route[i].active_serial = 1;
		route[i].payload_generation = 1;
		route[i].execution_class = 2;
	}
	held = 0;
	failures = lookups = locks = unlocks = 0;
	tail_cut = 0;
	omit_zero_task = fail_zero_update = 0;
}
static struct se_route_claim claim(unsigned account)
{
	struct se_route_claim c = {};
	struct se_route_anchor *a = &route[account];
	bpf_spin_lock(&a->lock);
	assert(se_route_claim_locked(a, se_route_locator(account, 1),
				     a->cgroup_identity, &c) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&a->lock);
	return c;
}
static void drop(unsigned account, struct se_route_claim *c)
{
	bpf_spin_lock(&route[account].lock);
	assert(se_route_release_locked(&route[account], c) == 0);
	bpf_spin_unlock(&route[account].lock);
}
static struct se_pool_token reserve(unsigned account, __u64 addr, int publish,
				    struct se_pool_reservation *out)
{
	struct se_route_claim c = claim(account);
	if (publish) {
		struct se_pool_task_birth_candidate birth = {};
		assert(se_pool_task_birth_prepare(&route[account], &c, addr,
						  &birth) == SE_POOL_OK);
		struct se_pool_token t = birth.token;
		assert(birth.state == 1 && birth.reservation.held == 1 &&
		       birth.refs.meta == &tasks[t.slot] &&
		       birth.refs.payload == &payloads[t.slot]);
		struct er_state *child = 0;
		assert(se_pool_task_birth_child_view(&birth, &child) ==
			       SE_POOL_OK &&
		       child == &payloads[t.slot].semantic.committed);
		child = 0;
		assert(se_pool_task_birth_finish(&birth) == SE_POOL_OK);
		assert(se_pool_task_birth_child_view(&birth, &child) ==
			       SE_POOL_CORRUPT &&
		       !child);
		assert(birth.state == 2 && !birth.reservation.held &&
		       tasks[t.slot].phase == SE_POOL_LIVE &&
		       tasks[t.slot].cleanup_done ==
			       SE_POOL_CONSTRUCTION_DONE &&
		       charges[t.slot].state == SE_POOL_CH_OWNED);
		*out = birth.reservation;
		drop(account, &c);
		return t;
	}
	struct se_pool_task_refs refs = {};
	assert(se_pool_task_reserve(&route[account], &c, addr, out, &refs) ==
	       SE_POOL_OK);
	struct se_pool_token t = se_pool_reservation_token(out);
	assert(refs.meta == &tasks[t.slot] &&
	       refs.payload == &payloads[t.slot]);
	assert(se_pool_task_semantic_initialize(&refs, out) == SE_POOL_OK);
	assert(refs.payload->semantic.physical_cookie == t.cookie &&
	       refs.payload->semantic.scope_cookie == route[account].scope &&
	       refs.payload->semantic.flags == SE_TASK_LIVE);
	assert(se_pool_task_complete(&route[account], refs.bitmap, refs.charge,
				     refs.meta, out) == SE_POOL_OK);
	assert(!out->held && charges[t.slot].state == SE_POOL_CH_OWNED);
	drop(account, &c);
	return t;
}
static void assert_clean(void)
{
	assert(!held && locks == unlocks && !failures);
}
static void test_abort_churn(void)
{
	reset();
	for (unsigned i = 0; i < 4097; i++) {
		struct se_pool_reservation r = {};
		struct se_pool_token t =
			reserve(0, 0x100000 + (__u64)i * 8, 0, &r);
		assert(tasks[t.slot].phase == SE_POOL_ABORTED);
	}
	assert(route[0].tasks_used == 4097 && route[1].tasks_used == 0);
	assert(charges[0].account_scope == route[0].scope &&
	       charges[4096].account_incarnation == 1);
	assert_clean();
	puts("4097 reserve/abort retained charges: PASS");
}
static void test_capacity_contention_withdrawal(void)
{
	reset();
	struct se_route_claim c = claim(0);
	struct se_pool_reservation a = {}, b = {};
	assert(se_pool_task_select(&route[0], &c, &bitmaps[0], 0x1000, &a) ==
	       SE_POOL_OK);
	assert(se_pool_task_select(&route[0], &c, &bitmaps[0], 0x2000, &b) ==
	       SE_POOL_OK);
	assert(a.pool_slot == b.pool_slot);
	assert(se_pool_next_cookie(&sequence, &a) == SE_POOL_OK);
	assert(se_pool_next_cookie(&sequence, &b) == SE_POOL_OK);
	assert(se_pool_task_charge(&route[0], &c, &bitmaps[0],
				   &charges[a.pool_slot], &a) == SE_POOL_OK);
	assert(se_pool_task_charge(&route[0], &c, &bitmaps[0],
				   &charges[b.pool_slot],
				   &b) == SE_POOL_CONTENDED);
	assert(se_pool_task_initialize(&tasks[a.pool_slot], &a) == SE_POOL_OK);
	assert(se_pool_task_complete(&route[0], &bitmaps[0],
				     &charges[a.pool_slot], &tasks[a.pool_slot],
				     &a) == SE_POOL_OK);
	drop(0, &c);
	for (unsigned i = 1; i < SE_POOL_QT; i++) {
		struct se_pool_reservation r = {};
		reserve(0, 0x3000 + (__u64)i * 8, 0, &r);
	}
	c = claim(0);
	struct se_pool_reservation full = {};
	assert(se_pool_task_select(&route[0], &c, &bitmaps[0], 0xabcde,
				   &full) == SE_POOL_CAPACITY);
	drop(0, &c);
	route[0].phase = SE_ROUTE_WITHDRAWN;
	assert(route[0].tasks_used == SE_POOL_QT && route[1].tasks_used == 0);
	assert(charges[0].account_scope == route[0].scope &&
	       charges[0].state == SE_POOL_CH_OWNED);
	struct se_binding_snapshots snapshot = { .scope = route[0].scope };
	assert(se_route_recycle_locked(&route[0], &snapshot) == -1);
	assert_clean();
	puts("quota/contention/withdrawn original account: PASS");
}
static void test_directory_collision(void)
{
	reset();
	__u64 addresses[17];
	unsigned count = 0;
	for (__u64 a = 0x1000; count < 17; a += 8)
		if (se_pool_bucket(a) == 0)
			addresses[count++] = a;
	for (unsigned i = 0; i < 16; i++) {
		struct se_pool_reservation r = {};
		reserve(0, addresses[i], 1, &r);
	}
	struct se_route_claim c = claim(0);
	struct se_pool_reservation r = {};
	struct se_pool_task_refs refs = {};
	assert(se_pool_task_reserve(&route[0], &c, addresses[16], &r, &refs) ==
	       SE_POOL_OK);
	struct se_pool_token t = se_pool_reservation_token(&r);
	assert(se_pool_publish_first(refs.directory, refs.meta, &t) ==
	       SE_POOL_DIRECTORY_CAPACITY);
	assert(charges[t.slot].state == SE_POOL_CH_BUILDING && r.held);
	assert(se_pool_task_complete(&route[0], refs.bitmap, refs.charge,
				     refs.meta, &r) == SE_POOL_OK);
	assert(tasks[t.slot].phase == SE_POOL_ABORTED &&
	       charges[t.slot].state == SE_POOL_CH_OWNED);
	assert(route[0].tasks_used == 17 && route[0].tasks_used < SE_POOL_QT);
	drop(0, &c);
	assert_clean();
	puts("mixed-address 16-way directory pressure: PASS");
}
static void test_displacement_and_stale(void)
{
	reset();
	struct se_pool_reservation r = {};
	__u64 address = 0x12345000;
	struct se_pool_token old = reserve(0, address, 1, &r);
	tasks[old.slot].phase = SE_POOL_LIVE;
	struct se_pool_lease lease = {};
	assert(se_pool_borrow(&tasks[old.slot], &old, &lease) == SE_POOL_OK);
	struct se_pool_final_free_lease final_free = {};
	assert(se_pool_final_free_acquire(
		       (struct task_struct *)(unsigned long)address,
		       &tasks[old.slot], &old, &final_free) == SE_POOL_OK);
	assert(se_pool_death_at_final_free(
		       (struct task_struct *)(unsigned long)(address + 8),
		       &tasks[old.slot], &final_free) == SE_POOL_STALE);
	assert(tasks[old.slot].phase == SE_POOL_LIVE);
	assert(se_pool_death_at_final_free(
		       (struct task_struct *)(unsigned long)address,
		       &tasks[old.slot], &final_free) == SE_POOL_OK);
	assert(se_pool_final_free_release(&tasks[old.slot], &final_free) ==
	       SE_POOL_OK);
	assert(se_pool_release(&tasks[old.slot], &lease) == SE_POOL_OK);
	tasks[old.slot].phase = SE_POOL_CLEANING;
	tasks[old.slot].cleanup_done = SE_POOL_EXEC_DONE |
				       SE_POOL_CONSTRUCTION_DONE |
				       SE_POOL_WORK_DONE | SE_POOL_NATIVE_DONE;
	struct se_pool_token stale = old;
	stale.cookie += 100;
	assert(se_pool_borrow(&tasks[old.slot], &stale, &lease) ==
	       SE_POOL_STALE);
	struct se_route_claim c = claim(0);
	struct se_pool_reservation successor = {};
	struct se_pool_task_refs refs = {};
	assert(se_pool_task_reserve(&route[0], &c, address, &successor,
				    &refs) == SE_POOL_OK);
	struct se_pool_token fresh = se_pool_reservation_token(&successor);
	struct se_pool_hold hold = {};
	assert(se_pool_hold_old(refs.meta, &tasks[old.slot], &fresh, &stale,
				&hold) == SE_POOL_CONTENDED);
	assert(!hold.held);
	assert(se_pool_hold_old(refs.meta, &tasks[old.slot], &fresh, &old,
				&hold) == SE_POOL_OK);
	assert(se_pool_dir_cleanup(refs.directory, &tasks[old.slot], &old) ==
	       SE_POOL_PENDING_CLEANUP);
	assert(se_pool_replace(refs.directory, refs.meta, &tasks[old.slot],
			       &hold) == SE_POOL_OK);
	assert(!hold.held && (tasks[old.slot].cleanup_done & SE_POOL_DIR_DONE));
	assert(se_pool_task_complete(&route[0], refs.bitmap, refs.charge,
				     refs.meta, &successor) == SE_POOL_OK);
	drop(0, &c);
	tasks[fresh.slot].phase = SE_POOL_DEAD;
	tasks[fresh.slot].phase = SE_POOL_CLEANING;
	tasks[fresh.slot].cleanup_done =
		SE_POOL_EXEC_DONE | SE_POOL_CONSTRUCTION_DONE |
		SE_POOL_WORK_DONE | SE_POOL_NATIVE_DONE;
	assert(se_pool_dir_cleanup(refs.directory, &tasks[fresh.slot],
				   &fresh) == SE_POOL_OK);
	assert(se_pool_lookup(refs.directory, address, &stale) ==
	       SE_POOL_MISSING);
	assert(se_pool_dir_cleanup(refs.directory, &tasks[old.slot], &old) ==
	       SE_POOL_OK);
	assert(charges[old.slot].state == SE_POOL_CH_OWNED &&
	       charges[fresh.slot].state == SE_POOL_CH_OWNED);
	assert_clean();
	puts("successor-first displacement and stale cookie: PASS");
}
static void test_failed_initialize(void)
{
	reset();
	tasks[0].phase = SE_POOL_LIVE;
	struct se_route_claim c = claim(0);
	struct se_pool_reservation r = {};
	struct se_pool_task_refs refs = {};
	assert(se_pool_task_reserve(&route[0], &c, 0xabc, &r, &refs) ==
	       SE_POOL_CORRUPT);
	assert(charges[0].state == SE_POOL_CH_FAULT_HELD &&
	       route[0].tasks_used == 1);
	assert(!r.held);
	drop(0, &c);
	assert_clean();
	puts("failed initialize exits BUILDING with retained charge: PASS");
}
/* Empty-obligation host fixture only. Native/source closure is test-certified,
 * not a product producer; this proves the candidate terminal path can reuse
 * fixed charges without manually erasing the payload or refunding the bit. */
static void test_recycled_task_churn(void)
{
	reset();
	__u64 last = 0;
	for (unsigned i = 0; i < 5000; i++) {
		__u64 address = 0x200000 + (__u64)i * 8;
		struct se_pool_reservation reservation = {};
		struct se_pool_token token =
			reserve(0, address, 1, &reservation);
		assert(token.cookie > last);
		last = token.cookie;
		struct se_pool_task_meta *meta = &tasks[token.slot];
		assert(payloads[token.slot].semantic.physical_cookie ==
			       token.cookie &&
		       payloads[token.slot].semantic.scope_cookie ==
			       route[0].scope &&
		       payloads[token.slot].semantic.eligibility_version == 1 &&
		       payloads[token.slot].semantic.flags == SE_TASK_LIVE);
		struct se_pool_final_free_lease final_free = {};
		struct task_struct *physical =
			(struct task_struct *)(unsigned long)address;
		assert(se_pool_final_free_acquire(physical, meta, &token,
						  &final_free) == SE_POOL_OK);
		assert(se_pool_death_at_final_free(physical, meta,
						   &final_free) == SE_POOL_OK);
		assert(se_pool_final_free_release(meta, &final_free) ==
		       SE_POOL_OK);
		assert(se_pool_task_exec_reap_step(&token) == SE_POOL_OK);
		assert(se_pool_task_work_reap_step(&token) == SE_POOL_OK);
		meta->cleanup_done |=
			SE_POOL_NATIVE_DONE; /* host-only certification */
		assert(se_pool_task_live_reap_step(&token) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(se_pool_task_live_reap_step(&token) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(!payloads[token.slot].semantic.physical_cookie &&
		       !payloads[token.slot].semantic.flags);
		__u32 slot = token.slot;
		assert(se_pool_task_live_reap_step(&token) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(se_pool_task_live_reap_step(&token) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(se_pool_task_live_reap_step(&token) == SE_POOL_OK);
		assert(se_pool_task_live_reap_step(&token) ==
		       SE_POOL_ALREADY_RETURNED);
		assert(!route[0].tasks_used && !(bitmaps[0].words[0] & 1) &&
		       charges[slot].state == SE_POOL_CH_FREE &&
		       charges[slot].last_returned_cookie == token.cookie &&
		       meta->phase == SE_POOL_FREE);
		struct se_pool_token absent = {};
		assert(se_pool_lookup(&dirs[se_pool_bucket(address)], address,
				      &absent) == SE_POOL_MISSING);
	}
	assert(sequence.next == 5000 && !route[0].reserved);
	route[0].phase = SE_ROUTE_FREE;
	route[0].scope = 0;
	route[0].incarnation = 0;
	assert(se_pool_task_refund_tail(&route[0], &bitmaps[0], &charges[0],
					&tasks[0],
					0) == SE_POOL_ALREADY_RETURNED);
	assert_clean();
	puts("5000 candidate TASK terminal recycle cycles: PASS");
}
static void test_recycled_abort_churn(void)
{
	reset();
	__u64 last = 0;
	for (unsigned i = 0; i < 5000; i++) {
		struct se_route_claim c = claim(0);
		struct se_pool_task_birth_candidate birth = {};
		__u64 address = 0x300000 + (__u64)i * 8;
		assert(se_pool_task_birth_prepare(&route[0], &c, address,
						  &birth) == SE_POOL_OK);
		assert(birth.token.cookie > last);
		last = birth.token.cookie;
		assert(se_pool_task_birth_abort(&birth) == SE_POOL_OK);
		__u32 slot = birth.token.slot;
		assert(se_pool_task_abort_reap_step(slot) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(tasks[slot].phase == SE_POOL_CLEANING &&
		       tasks[slot].cleanup_done == 31u);
		assert(se_pool_task_abort_reap_step(slot) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(tasks[slot].phase == SE_POOL_REFUND_PENDING &&
		       tasks[slot].cleanup_done == 63u &&
		       !tasks[slot].active_leases &&
		       !payloads[slot].semantic.physical_cookie);
		assert(se_pool_task_abort_reap_step(slot) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(se_pool_task_abort_reap_step(slot) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(se_pool_task_abort_reap_step(slot) == SE_POOL_OK);
		assert(!route[0].tasks_used &&
		       charges[slot].state == SE_POOL_CH_FREE &&
		       charges[slot].last_returned_cookie ==
			       birth.token.cookie &&
		       tasks[slot].phase == SE_POOL_FREE);
		assert(se_pool_task_abort_reap_step(slot) ==
		       SE_POOL_ALREADY_RETURNED);
		drop(0, &c);
	}
	assert(sequence.next == 5000 && !route[0].reserved);
	assert_clean();
	puts("5000 denied unpublished TASK births reclaimed: PASS");
}
static void test_abort_reap_zero_retry(void)
{
	reset();
	struct se_route_claim c = claim(0);
	struct se_pool_task_birth_candidate birth = {};
	assert(se_pool_task_birth_prepare(&route[0], &c, 0x400000, &birth) ==
	       SE_POOL_OK);
	assert(se_pool_task_birth_abort(&birth) == SE_POOL_OK);
	__u32 slot = birth.token.slot;
	assert(se_pool_task_abort_reap_step(slot) == SE_POOL_PENDING_CLEANUP);
	tasks[slot].active_leases =
		1; /* another reaper owns the zero-write claim */
	assert(se_pool_task_abort_reap_step(slot) == SE_POOL_PENDING_CLEANUP);
	tasks[slot].active_leases = 0;
	omit_zero_task = 1;
	assert(se_pool_task_abort_reap_step(slot) == SE_POOL_CORRUPT);
	assert(tasks[slot].phase == SE_POOL_CLEANING &&
	       !tasks[slot].active_leases &&
	       charges[slot].state == SE_POOL_CH_OWNED &&
	       route[0].tasks_used == 1);
	omit_zero_task = 0;
	fail_zero_update = 1;
	assert(se_pool_task_abort_reap_step(slot) == SE_POOL_CORRUPT);
	assert(tasks[slot].phase == SE_POOL_CLEANING &&
	       !tasks[slot].active_leases &&
	       charges[slot].state == SE_POOL_CH_OWNED);
	fail_zero_update = 0;
	assert(se_pool_task_abort_reap_step(slot) == SE_POOL_PENDING_CLEANUP);
	assert(se_pool_task_abort_reap_step(slot) == SE_POOL_PENDING_CLEANUP);
	assert(se_pool_task_abort_reap_step(slot) == SE_POOL_PENDING_CLEANUP);
	assert(se_pool_task_abort_reap_step(slot) == SE_POOL_OK);
	drop(0, &c);
	assert_clean();
	puts("unpublished abort zero retry retains charge: PASS");
}
static void test_refund_tail_faults(void)
{
	reset();
	struct se_pool_reservation reservation = {};
	struct se_pool_token token = reserve(0, 0x400000, 1, &reservation);
	struct se_pool_task_meta *meta = &tasks[token.slot];
	meta->phase = SE_POOL_REFUND_PENDING;
	meta->cleanup_done = 63u;
	meta->active_leases = 1; /* Contradictory terminal claim: no refund. */
	assert(se_pool_task_refund_tail(&route[0], &bitmaps[0],
					&charges[token.slot], meta,
					token.slot) == SE_POOL_CORRUPT);
	assert(route[0].reserved && route[0].tasks_used == 1 &&
	       charges[token.slot].state == SE_POOL_CH_FAULT_HELD &&
	       (bitmaps[0].words[0] & 1));
	reset();
	token = reserve(0, 0x500000, 1, &reservation);
	meta = &tasks[token.slot];
	meta->cookie++;
	assert(se_pool_task_refund_tail(&route[0], &bitmaps[0],
					&charges[token.slot], meta,
					token.slot) == SE_POOL_CORRUPT);
	assert(route[0].reserved && route[0].tasks_used == 1 &&
	       charges[token.slot].state == SE_POOL_CH_FAULT_HELD);
	reset();
	tasks[0].reserved1 = 1;
	assert(se_pool_task_refund_tail(&route[0], &bitmaps[0], &charges[0],
					&tasks[0], 0) == SE_POOL_CORRUPT);
	assert(route[0].reserved && charges[0].state == SE_POOL_CH_FAULT_HELD);
	reset();
	charges[0].last_returned_cookie = 11;
	assert(se_pool_task_refund_tail(&route[0], &bitmaps[0], &charges[0],
					&tasks[0], 0) == SE_POOL_CORRUPT);
	assert(route[0].reserved && charges[0].state == SE_POOL_CH_FAULT_HELD);
	reset();
	assert(se_pool_task_refund_tail(&route[1], &bitmaps[0], &charges[0],
					&tasks[0], 0) == SE_POOL_CORRUPT);
	assert(!route[0].reserved && !route[1].reserved &&
	       charges[0].state == SE_POOL_CH_FREE);
	reset();
	token = reserve(0, 0x600000, 1, &reservation);
	route[0].reserved = 1;
	assert(se_pool_task_refund_tail(
		       &route[0], &bitmaps[0], &charges[token.slot],
		       &tasks[token.slot], token.slot) == SE_POOL_CORRUPT);
	assert(route[0].tasks_used == 1 &&
	       charges[token.slot].state == SE_POOL_CH_OWNED &&
	       (bitmaps[0].words[0] & 1));
	assert_clean();
	puts("TASK tail faults retain accounting: PASS");
}
static void test_refund_tail_constructor_cuts(void)
{
	for (int cut = 1; cut <= 2; cut++) {
		reset();
		tail_cut = cut;
		assert(se_pool_task_refund_tail(&route[0], &bitmaps[0],
						&charges[0], &tasks[0],
						0) == SE_POOL_PENDING_CLEANUP);
		assert(!tail_cut && !route[0].reserved &&
		       route[0].tasks_used == 1 &&
		       charges[0].state == SE_POOL_CH_BUILDING &&
		       (bitmaps[0].words[0] & 1));
		assert_clean();
	}
	puts("TASK tail constructor observation cuts: PASS");
}
static void test_refund_tail_late_meta_fault(void)
{
	reset();
	struct se_pool_reservation reservation = {};
	struct se_pool_token token = reserve(0, 0x700000, 1, &reservation);
	struct se_pool_task_meta *meta = &tasks[token.slot];
	meta->phase = SE_POOL_REFUND_PENDING;
	meta->cleanup_done = 63u;
	assert(se_pool_task_refund_tail(&route[0], &bitmaps[0],
					&charges[token.slot], meta,
					token.slot) == SE_POOL_PENDING_CLEANUP);
	assert(charges[token.slot].state == SE_POOL_CH_RETURN_READY);
	tail_cut = 3;
	assert(se_pool_task_refund_tail(&route[0], &bitmaps[0],
					&charges[token.slot], meta,
					token.slot) == SE_POOL_CORRUPT);
	assert(!tail_cut && route[0].reserved && route[0].tasks_used == 1 &&
	       charges[token.slot].state == SE_POOL_CH_FAULT_HELD &&
	       (bitmaps[0].words[0] & 1));
	assert_clean();
	puts("TASK tail late metadata fault retained: PASS");
}
static void test_typed_semantic_handle(void)
{
	reset();
	struct se_pool_reservation reservation = {};
	__u64 address = 0x800000;
	struct se_pool_token token = reserve(0, address, 1, &reservation);
	struct se_pool_task_meta *meta = &tasks[token.slot];
	struct se_task_state *semantic = &payloads[token.slot].semantic;
	semantic->physical_cookie = token.cookie;
	semantic->scope_cookie = meta->account_scope;
	semantic->scope_slot = meta->account_slot;
	semantic->flags = SE_TASK_LIVE;
	meta->phase = SE_POOL_LIVE;
	struct se_pool_task_semantic_handle handle = {};
	assert(se_pool_task_semantic_open(address, &handle) == SE_POOL_OK);
	assert(handle.meta == meta && handle.payload == &payloads[token.slot] &&
	       handle.lease.held == 1 && meta->active_leases == 1);
	assert(se_pool_task_semantic_begin(&handle) == SE_POOL_OK);
	assert(held == &meta->lock && handle.locked == 1);
	assert(se_pool_task_semantic_close(&handle) == SE_POOL_CORRUPT);
	assert(handle.lease.held == 1 && meta->active_leases == 1);
	semantic->eligibility_version = 7;
	assert(se_pool_task_semantic_end(&handle) == SE_POOL_OK);
	assert(!held && !handle.locked && semantic->eligibility_version == 7);
	assert(se_pool_task_semantic_close(&handle) == SE_POOL_OK);
	assert(!handle.lease.held && !handle.meta && !handle.payload &&
	       !meta->active_leases);
	semantic->physical_cookie++;
	assert(se_pool_task_semantic_open(address, &handle) == SE_POOL_CORRUPT);
	assert(!handle.lease.held && !meta->active_leases);
	semantic->physical_cookie = token.cookie;
	assert(se_pool_task_semantic_open(address, &handle) == SE_POOL_OK);
	meta->phase = SE_POOL_DEAD;
	assert(se_pool_task_semantic_begin(&handle) == SE_POOL_NOT_ELIGIBLE);
	assert(!held && !handle.locked);
	assert(se_pool_task_semantic_close(&handle) == SE_POOL_OK);
	assert(se_pool_task_semantic_open(address, &handle) ==
	       SE_POOL_NOT_ELIGIBLE);
	assert(!meta->active_leases);
	assert_clean();
	puts("typed TASK semantic handle/lease: PASS");
}
static void test_typed_task_movement(void)
{
	reset();
	struct se_pool_reservation reservation = {};
	__u64 address = 0x810000;
	struct se_pool_token token = reserve(0, address, 1, &reservation);
	struct se_pool_task_meta *meta = &tasks[token.slot];
	struct se_task_state *task = &payloads[token.slot].semantic;
	struct se_pool_task_semantic_handle handle = {};
	task->eligibility_version = 7;
	task->exec.owned = 1;
	movement_faults = 0;
	assert(se_pool_task_semantic_open(address, &handle) == SE_POOL_OK);
	assert(se_pool_observe_task_movement(
		       &handle, route[0].cgroup_identity) == SE_POOL_OK);
	assert(task->flags == SE_TASK_LIVE && task->eligibility_version == 7 &&
	       !movement_faults && !handle.locked);
	assert(se_pool_observe_task_movement(&handle, 0x999) == SE_POOL_OK);
	assert(task->flags == (SE_TASK_LIVE | SE_TASK_QUARANTINED) &&
	       task->eligibility_version == 8 && movement_faults == 1 &&
	       !handle.locked);
	assert(se_pool_observe_task_movement(&handle, 0x999) == SE_POOL_OK);
	assert(task->eligibility_version == 8 && movement_faults == 2);
	task->physical_cookie++;
	assert(se_pool_observe_task_movement(&handle, 0x999) ==
	       SE_POOL_CORRUPT);
	assert(!handle.locked && movement_faults == 2);
	task->physical_cookie = token.cookie;
	assert(se_pool_task_semantic_close(&handle) == SE_POOL_OK);
	assert(!meta->active_leases && !held);
	assert_clean();
	puts("typed TASK movement preserves original account: PASS");
}
static void test_typed_exec_fault(void)
{
	reset();
	struct se_pool_reservation reservation = {};
	__u64 address = 0x820000;
	struct se_pool_token token = reserve(0, address, 1, &reservation);
	struct se_task_state *task = &payloads[token.slot].semantic;
	struct se_pool_task_semantic_handle handle = {};
	assert(se_pool_task_semantic_open(address, &handle) == SE_POOL_OK);
	task->eligibility_version = 9;
	movement_faults = 0;
	assert(se_pool_owned_exec_fault(&handle, 0x10) == SE_POOL_OK);
	assert(task->flags == (SE_TASK_LIVE | SE_TASK_QUARANTINED) &&
	       task->eligibility_version == 10 && !movement_faults);
	task->exec = (struct se_exec_transaction){ .owned = 1,
						   .bprm = 0x20,
						   .grants = 7 };
	assert(se_pool_owned_exec_fault(&handle, 0x10) == SE_POOL_OK);
	assert(!task->exec.hard_fault && task->exec.grants == 7 &&
	       task->eligibility_version == 10);
	assert(se_pool_note_prior_exec_deny(&handle, 0x10) == SE_POOL_OK);
	assert(!task->exec.known_deny && task->exec.grants == 7);
	assert(se_pool_note_prior_exec_deny(&handle, 0x20) == SE_POOL_OK);
	assert(task->exec.known_deny && !task->exec.grants);
	task->exec.known_deny = 0;
	task->exec.grants = 7;
	assert(se_pool_owned_exec_fault(&handle, 0x20) == SE_POOL_OK);
	assert(task->exec.hard_fault && !task->exec.grants &&
	       movement_faults == 1 && task->eligibility_version == 10);
	assert(se_pool_task_semantic_close(&handle) == SE_POOL_OK);
	assert(!held && !tasks[token.slot].active_leases);
	assert_clean();
	puts("typed TASK exec fault and prior denial: PASS");
}
static void test_semantic_zero_failure_retains_charge(void)
{
	for (int fault = 1; fault <= 2; fault++) {
		reset();
		struct se_route_claim c = claim(0);
		struct se_pool_reservation reservation = {};
		struct se_pool_task_refs refs = {};
		__u64 address = 0x900000 + (__u64)fault * 8;
		assert(se_pool_task_reserve(&route[0], &c, address,
					    &reservation, &refs) == SE_POOL_OK);
		struct se_pool_token token =
			se_pool_reservation_token(&reservation);
		if (fault == 1)
			omit_zero_task = 1;
		else
			fail_zero_update = 1;
		assert(se_pool_task_semantic_initialize(&refs, &reservation) ==
		       SE_POOL_CORRUPT);
		assert(reservation.held == 1 &&
		       refs.meta->phase == SE_POOL_INITIALIZING);
		assert(se_pool_task_complete(&route[0], refs.bitmap,
					     refs.charge, refs.meta,
					     &reservation) == SE_POOL_OK);
		assert(!reservation.held &&
		       refs.meta->phase == SE_POOL_ABORTED &&
		       route[0].tasks_used == 1 &&
		       charges[token.slot].state == SE_POOL_CH_OWNED);
		struct se_pool_token absent = {};
		assert(se_pool_lookup(refs.directory, address, &absent) ==
		       SE_POOL_MISSING);
		drop(0, &c);
		assert_clean();
	}
	puts("typed TASK zero failure retains charge: PASS");
}
static void test_semantic_finish_fault_holds_account(void)
{
	reset();
	struct se_route_claim c = claim(0);
	struct se_pool_reservation reservation = {};
	struct se_pool_task_refs refs = {};
	__u64 address = 0xa00000;
	assert(se_pool_task_reserve(&route[0], &c, address, &reservation,
				    &refs) == SE_POOL_OK);
	struct se_pool_token token = se_pool_reservation_token(&reservation);
	assert(refs.route == &route[0]);
	assert(se_pool_task_semantic_initialize(&refs, &reservation) ==
	       SE_POOL_OK);
	assert(se_pool_publish_first(refs.directory, refs.meta, &token) ==
	       SE_POOL_OK);
	assert(se_pool_task_complete(&route[0], refs.bitmap, refs.charge,
				     refs.meta, &reservation) == SE_POOL_OK);
	refs.payload->semantic.physical_cookie++;
	assert(se_pool_task_semantic_finish_birth(&refs, &reservation) ==
	       SE_POOL_CORRUPT);
	assert(route[0].reserved && route[0].tasks_used == 1 &&
	       refs.meta->phase == SE_POOL_PENDING_BIRTH &&
	       charges[token.slot].state == SE_POOL_CH_OWNED);
	struct se_pool_task_semantic_handle handle = {};
	assert(se_pool_task_semantic_open(address, &handle) ==
	       SE_POOL_NOT_ELIGIBLE);
	assert(!handle.lease.held);
	drop(0, &c);
	assert_clean();
	puts("typed TASK finish fault holds account: PASS");
}
static void test_birth_successor_and_failures(void)
{
	reset();
	const __u64 address = 0xa10000;
	struct se_pool_reservation first = {};
	struct se_pool_token old = reserve(0, address, 1, &first);
	tasks[old.slot].phase = SE_POOL_CLEANING;
	tasks[old.slot].cleanup_done = SE_POOL_EXEC_DONE |
				       SE_POOL_CONSTRUCTION_DONE |
				       SE_POOL_WORK_DONE | SE_POOL_NATIVE_DONE;
	struct se_route_claim c = claim(0);
	struct se_pool_task_birth_candidate birth = {};
	assert(se_pool_task_birth_prepare(&route[0], &c, address, &birth) ==
	       SE_POOL_OK);
	struct er_state *child = 0;
	child = &birth.refs.payload->semantic.committed;
	assert(se_pool_task_birth_child_view(&birth, &child) ==
	       SE_POOL_CORRUPT);
	child = 0;
	birth.token.cookie++;
	assert(se_pool_task_birth_child_view(&birth, &child) ==
		       SE_POOL_CORRUPT &&
	       !child);
	birth.token.cookie--;
	birth.refs.payload->semantic.scope_cookie++;
	assert(se_pool_task_birth_child_view(&birth, &child) ==
		       SE_POOL_CORRUPT &&
	       !child);
	birth.refs.payload->semantic.scope_cookie--;
	assert(se_pool_task_birth_child_view(&birth, &child) == SE_POOL_OK &&
	       child == &birth.refs.payload->semantic.committed);
	struct er_work projected = {};
	projected.rows[0] = er_known_row(17, 2, 3);
	projected.rows[15] = er_known_row(23, 4, 5);
	assert(se_child_roles_publish(child, &projected) == 0 &&
	       child->version == 1 && child->rows[15].uid == 23);
	child = 0;
	assert(birth.state == 1 && birth.reservation.held == 1 &&
	       birth.token.cookie > old.cookie &&
	       birth.token.slot != old.slot &&
	       !(tasks[old.slot].cleanup_done & SE_POOL_DIR_DONE) &&
	       !tasks[old.slot].directory_holds);
	struct se_pool_token found = {};
	assert(se_pool_lookup(birth.refs.directory, address, &found) ==
		       SE_POOL_OK &&
	       se_pool_same(&found, &old));
	assert(se_pool_task_birth_finish(&birth) == SE_POOL_OK);
	assert(birth.state == 2 &&
	       tasks[birth.token.slot].phase == SE_POOL_LIVE &&
	       (tasks[old.slot].cleanup_done & SE_POOL_DIR_DONE));
	assert(payloads[birth.token.slot].semantic.committed.version == 1 &&
	       payloads[birth.token.slot].semantic.committed.rows[0].uid == 17);
	assert(se_pool_lookup(birth.refs.directory, address, &found) ==
		       SE_POOL_OK &&
	       se_pool_same(&found, &birth.token));
	assert(se_pool_dir_cleanup(birth.refs.directory, &tasks[old.slot],
				   &old) == SE_POOL_OK);
	drop(0, &c);
	assert_clean();

	reset();
	struct se_pool_reservation live = {};
	old = reserve(0, address, 1, &live);
	c = claim(0);
	birth = (struct se_pool_task_birth_candidate){};
	assert(se_pool_task_birth_prepare(&route[0], &c, address, &birth) ==
	       SE_POOL_OK);
	assert(birth.state == 1 && birth.reservation.held &&
	       tasks[birth.token.slot].phase == SE_POOL_INITIALIZING);
	assert(se_pool_task_birth_finish(&birth) == SE_POOL_CONTENDED);
	assert(birth.state == 2 && !birth.reservation.held &&
	       tasks[birth.token.slot].phase == SE_POOL_ABORTED &&
	       charges[birth.token.slot].state == SE_POOL_CH_OWNED &&
	       route[0].tasks_used == 2 &&
	       tasks[old.slot].phase == SE_POOL_LIVE);
	assert(se_pool_lookup(&dirs[se_pool_bucket(address)], address,
			      &found) == SE_POOL_OK &&
	       se_pool_same(&found, &old));
	__u32 failed_slot = birth.token.slot;
	assert(se_pool_task_abort_reap_step(failed_slot) ==
	       SE_POOL_PENDING_CLEANUP);
	assert(se_pool_task_abort_reap_step(failed_slot) ==
	       SE_POOL_PENDING_CLEANUP);
	assert(se_pool_task_abort_reap_step(failed_slot) ==
	       SE_POOL_PENDING_CLEANUP);
	assert(se_pool_task_abort_reap_step(failed_slot) ==
	       SE_POOL_PENDING_CLEANUP);
	assert(se_pool_task_abort_reap_step(failed_slot) == SE_POOL_OK);
	assert(route[0].tasks_used == 1 &&
	       tasks[old.slot].phase == SE_POOL_LIVE);
	drop(0, &c);
	assert_clean();

	reset();
	c = claim(0);
	birth = (struct se_pool_task_birth_candidate){};
	assert(se_pool_task_birth_prepare(&route[0], &c, address, &birth) ==
	       SE_POOL_OK);
	assert(se_pool_lookup(birth.refs.directory, address, &found) ==
	       SE_POOL_MISSING);
	child = 0;
	assert(se_pool_task_birth_child_view(&birth, &child) == SE_POOL_OK);
	projected = (struct er_work){};
	projected.rows[0] = er_known_row(17, 2, 3);
	child->rows[15].reserved = 1;
	struct er_state before = *child;
	assert(se_child_roles_publish(child, &projected) == -1 &&
	       !memcmp(child, &before, sizeof(before)));
	assert(se_pool_task_birth_abort(&birth) == SE_POOL_OK);
	assert(birth.state == 2 && !birth.reservation.held &&
	       tasks[birth.token.slot].phase == SE_POOL_ABORTED &&
	       charges[birth.token.slot].state == SE_POOL_CH_OWNED &&
	       route[0].tasks_used == 1);
	assert(se_pool_task_birth_finish(&birth) == SE_POOL_CORRUPT);
	assert(se_pool_lookup(birth.refs.directory, address, &found) ==
	       SE_POOL_MISSING);
	drop(0, &c);
	assert_clean();

	for (int fault = 1; fault <= 2; fault++) {
		reset();
		c = claim(0);
		birth = (struct se_pool_task_birth_candidate){};
		if (fault == 1)
			omit_zero_task = 1;
		else
			fail_zero_update = 1;
		assert(se_pool_task_birth_prepare(&route[0], &c, address,
						  &birth) == SE_POOL_CORRUPT);
		assert(birth.state == 2 && !birth.reservation.held &&
		       tasks[birth.token.slot].phase == SE_POOL_ABORTED &&
		       charges[birth.token.slot].state == SE_POOL_CH_OWNED &&
		       route[0].tasks_used == 1);
		assert(se_pool_lookup(&dirs[se_pool_bucket(address)], address,
				      &found) == SE_POOL_MISSING);
		omit_zero_task = fail_zero_update = 0;
		__u32 failed_slot = birth.token.slot;
		assert(se_pool_task_abort_reap_step(failed_slot) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(se_pool_task_abort_reap_step(failed_slot) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(se_pool_task_abort_reap_step(failed_slot) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(se_pool_task_abort_reap_step(failed_slot) ==
		       SE_POOL_PENDING_CLEANUP);
		assert(se_pool_task_abort_reap_step(failed_slot) == SE_POOL_OK);
		assert(!route[0].tasks_used);
		drop(0, &c);
		assert_clean();
	}
	puts("TASK birth deferred publish, abort, collision, and zero faults: PASS");
}
static void test_task_work_lease_bridge(void)
{
	reset();
	struct se_pool_reservation reservation = {};
	__u64 address = 0xb00000;
	struct se_pool_token token = reserve(0, address, 1, &reservation);
	payloads[token.slot].semantic.flags = SE_TASK_QUALIFIED;
	payloads[token.slot].semantic.committed.version = 7;
	payloads[token.slot].semantic.committed.rows[0] =
		er_known_row(17, 2, 3);
	payloads[token.slot].semantic.committed.rows[15] =
		er_known_row(23, 4, 5);
	payloads[token.slot].semantic.eligibility_version = 3;
	struct se_pool_task_semantic_handle task_handle = {};
	assert(se_pool_task_semantic_open(address, &task_handle) == SE_POOL_OK);
	assert(task_handle.lease.token.cookie == token.cookie);
	struct se_pw_task_lease work_lease = {};
	assert(se_pool_work_lease_from_task(&task_handle, &work_lease) ==
	       SE_PW_OK);
	assert(task_handle.work_borrows == 1 && work_lease.held == 1 &&
	       work_lease.cookie == token.cookie &&
	       work_lease.slot == token.slot);
	struct se_pw_task_lease second = {};
	assert(se_pool_work_lease_from_task(&task_handle, &second) ==
	       SE_PW_FAULT);
	assert(se_pool_task_semantic_close(&task_handle) == SE_POOL_CORRUPT);
	__u32 work_slot = SE_POOL_W;
	assert(se_pw_select(&route[0], &bitmaps[0], &work_lease, &work_slot) ==
	       SE_PW_OK);
	assert(work_slot < SE_POOL_W);
	struct se_pool_work_refs work_refs = {};
	assert(se_pool_work_prefetch(&work_lease, work_slot, &work_refs) ==
	       SE_PW_OK);
	assert(work_refs.route == &route[0] &&
	       work_refs.bitmap == &bitmaps[0] &&
	       work_refs.charge == &charges[SE_POOL_T + work_slot] &&
	       work_refs.task == &tasks[token.slot] &&
	       work_refs.previous_task == &tasks[token.slot]);
	struct se_pw_ticket ticket = {};
	assert(se_pw_begin(work_refs.route, work_refs.bitmap, work_refs.charge,
			   work_refs.sequence, work_refs.task, work_refs.work,
			   work_refs.payload, work_refs.previous_task,
			   &work_lease, work_slot, &ticket) == SE_PW_OK);
	assert(se_pw_attach(&tasks[token.slot], &works[work_slot], &work_lease,
			    &ticket) == SE_PW_OK);
	struct se_pool_work_payload *work_payload = &work_payloads[work_slot];
	assert(se_pool_work_semantic_initialize(
		       &tasks[token.slot], &works[work_slot],
		       &charges[SE_POOL_T + work_slot], &work_payload,
		       &work_lease, &ticket) == SE_PW_OK);
	assert(se_pw_commit(&works[work_slot], &route[0], &bitmaps[0],
			    &charges[SE_POOL_T + work_slot],
			    &ticket) == SE_PW_OK);
	struct se_pool_work_semantic_handle work_handle = {};
	assert(se_pool_work_semantic_open(&tasks[token.slot], &work_lease,
					  &works[work_slot], work_payload,
					  &ticket, &route[0],
					  &charges[SE_POOL_T + work_slot],
					  &work_handle) == SE_PW_OK);
	struct fm_global_token eval_token = { .slot = work_slot,
					      .cookie = ticket.cookie };
	assert(se_pool_view_from_token(&eval_token) ==
	       &work_payload->semantic.view);
	eval_token.cookie++;
	assert(!se_pool_view_from_token(&eval_token));
	eval_token.cookie--;
	works[work_slot].active_leases = 0;
	assert(!se_pool_view_from_token(&eval_token));
	works[work_slot].active_leases = 1;
	work_payload->semantic.sequence++;
	assert(!se_pool_view_from_token(&eval_token));
	work_payload->semantic.sequence--;
	struct se_route_claim c = claim(0);
	struct se_pool_task_birth_candidate child_birth = {};
	assert(se_pool_task_birth_prepare(&route[0], &c, address + 8,
					  &child_birth) == SE_POOL_OK);
	struct se_exec_work *history = &work_payload->semantic.history;
	history->physical_cookie = token.cookie;
	history->scope_cookie = c.scope;
	history->eligibility_version = 3;
	history->flags = SE_TASK_QUALIFIED;
	history->view.work.base_version = 7;
	history->view.work.authority_version = c.generation;
	history->view.work.rows[0] =
		payloads[token.slot].semantic.committed.rows[0];
	history->view.work.rows[15] =
		payloads[token.slot].semantic.committed.rows[15];
	accepted_epochs[17] = ER_UNKNOWN;
	assert(se_pool_catalogue_fill(&work_handle, &c) == SE_POOL_CORRUPT);
	assert(!work_payload->catalogue.scope &&
	       !work_payload->catalogue.generation);
	accepted_epochs[17] = 2;
	assert(se_pool_catalogue_fill(&work_handle, &c) == SE_POOL_OK);
	struct er_canonical_view legacy = history->view;
	assert(er_canonical_classify(&legacy) == 0);
	assert(se_pool_catalogue_classify(&history->view,
					  &work_payload->catalogue, &c) == 0);
	assert(history->view.accepted_mask == legacy.accepted_mask &&
	       history->view.accepted_mask == 1 &&
	       history->view.work.prepared == 1);
	struct er_work *projected = &work_payload->semantic.inherited;
	assert(er_canonical_project(&history->view, projected) == 0);
	assert(projected->rows[0].uid == 17 && !projected->rows[15].uid);
	work_payload->catalogue.scope++;
	assert(se_pool_inherit_child_commit(&task_handle, &child_birth,
					    &work_handle, &c) == SE_POOL_STALE);
	work_payload->catalogue.scope--;
	work_payload->catalogue.rows[0].uid++;
	assert(se_pool_inherit_child_commit(&task_handle, &child_birth,
					    &work_handle, &c) == SE_POOL_STALE);
	work_payload->catalogue.rows[0].uid--;
	work_payload->catalogue.rows[0].accepted_epoch = 0;
	assert(se_pool_inherit_child_commit(&task_handle, &child_birth,
					    &work_handle, &c) == SE_POOL_STALE);
	work_payload->catalogue.rows[0].accepted_epoch = 2;
	projected->rows[0].role++;
	assert(se_pool_inherit_child_commit(&task_handle, &child_birth,
					    &work_handle, &c) == SE_POOL_STALE);
	projected->rows[0].role--;
	projected->rows[15].uid = 23;
	assert(se_pool_inherit_child_commit(&task_handle, &child_birth,
					    &work_handle, &c) == SE_POOL_STALE);
	projected->rows[15].uid = 0;
	assert(!child_birth.refs.payload->semantic.committed.version);
	c.generation++;
	assert(se_pool_inherit_child_commit(&task_handle, &child_birth,
					    &work_handle, &c) == SE_POOL_STALE);
	assert(!child_birth.refs.payload->semantic.committed.version);
	c.generation--;
	payloads[token.slot].semantic.committed.version++;
	assert(se_pool_inherit_child_commit(&task_handle, &child_birth,
					    &work_handle, &c) == SE_POOL_STALE);
	assert(!child_birth.refs.payload->semantic.committed.version);
	payloads[token.slot].semantic.committed.version--;
	child_birth.refs.payload->semantic.committed.rows[15].reserved = 1;
	assert(se_pool_inherit_child_commit(&task_handle, &child_birth,
					    &work_handle,
					    &c) == SE_POOL_CORRUPT);
	assert(!child_birth.refs.payload->semantic.committed.version &&
	       child_birth.refs.payload->semantic.committed.rows[15].reserved ==
		       1);
	child_birth.refs.payload->semantic.committed.rows[15].reserved = 0;
	assert(se_pool_inherit_child_commit(&task_handle, &child_birth,
					    &work_handle, &c) == SE_POOL_OK);
	assert(child_birth.refs.payload->semantic.committed.version == 1 &&
	       child_birth.refs.payload->semantic.committed.rows[0].uid == 17);
	assert(se_pool_task_birth_finish(&child_birth) == SE_POOL_OK);
	drop(0, &c);
	assert(se_pool_work_lease_to_task(&task_handle, &work_lease, &ticket) ==
	       SE_PW_FAULT);
	assert(se_pool_task_semantic_close(&task_handle) == SE_POOL_CORRUPT);
	assert(se_pool_work_semantic_done(&work_handle) == SE_PW_OK);
	assert(!se_pool_view_from_token(&eval_token));
	assert(se_pool_work_lease_to_task(&task_handle, &work_lease, &ticket) ==
	       SE_PW_OK);
	assert(!task_handle.work_borrows && !work_lease.held &&
	       tasks[token.slot].active_leases ==
		       1); /* TASK lease still held */
	assert(se_pool_task_semantic_close(&task_handle) == SE_POOL_OK);
	assert(!tasks[token.slot].active_leases &&
	       tasks[token.slot].work_refs == 1 &&
	       charges[SE_POOL_T + work_slot].state == SE_PW_CH_OWNED);
	assert(se_pool_task_work_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	struct se_pool_final_free_lease final_free = {};
	struct task_struct *physical =
		(struct task_struct *)(unsigned long)address;
	assert(se_pool_final_free_acquire(physical, &tasks[token.slot], &token,
					  &final_free) == SE_POOL_OK);
	assert(se_pool_death_at_final_free(physical, &tasks[token.slot],
					   &final_free) == SE_POOL_OK);
	assert(se_pool_final_free_release(&tasks[token.slot], &final_free) ==
	       SE_POOL_OK);
	assert(se_pool_task_exec_reap_step(&token) == SE_POOL_OK);
	assert(se_pool_task_work_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	assert(!(tasks[token.slot].cleanup_done & SE_POOL_WORK_DONE));
	assert(se_pool_reap_work_visit_slot(work_slot) == SE_PW_RETURNED);
	assert(!tasks[token.slot].work_refs && !route[0].scratch_used &&
	       charges[SE_POOL_T + work_slot].state == SE_PW_CH_FREE);
	assert(se_pool_task_work_reap_step(&token) == SE_POOL_OK);
	assert(se_pool_task_work_reap_step(&token) == SE_POOL_OK);
	assert(tasks[token.slot].cleanup_done ==
	       (SE_POOL_CONSTRUCTION_DONE | SE_POOL_EXEC_DONE |
		SE_POOL_WORK_DONE));
	assert_clean();
	puts("exact TASK-to-WORK lease bridge: PASS");
}
static void test_work_prefetch_prior_owner_slot(void)
{
	reset();
	assert(se_pool_reap_work_visit_slot(0) == SE_PW_FREE);
	assert(se_pool_reap_work_visit_slot(SE_POOL_W) == SE_PW_FAULT);
	assert(!route[0].reserved && !held);
	struct se_pw_task_lease new_task = { .cookie = 22,
					     .physical_address = 0xc00000,
					     .scope = route[0].scope,
					     .slot = 1,
					     .account_slot = 0,
					     .account_incarnation =
						     route[0].incarnation,
					     .held = 1 };
	works[0].cookie = 11;
	works[0].owner_task_slot = 0;
	struct se_pool_work_refs refs = {};
	assert(se_pool_work_prefetch(&new_task, 0, &refs) == SE_PW_OK);
	assert(refs.task == &tasks[1] && refs.previous_task == &tasks[0] &&
	       refs.charge == &charges[SE_POOL_T]);
	assert(se_pool_work_prefetch(&new_task, 0, &refs) == SE_PW_FAULT);
	works[0].owner_task_slot = SE_POOL_T;
	refs = (struct se_pool_work_refs){};
	assert(se_pool_work_prefetch(&new_task, 0, &refs) == SE_PW_FAULT);
	assert(se_pool_reap_work_visit_slot(0) == SE_PW_FAULT);
	assert(!refs.task && !refs.previous_task && !route[0].reserved);
	assert_clean();
	puts("WORK prefetch retains distinct prior TASK slot: PASS");
}
static void test_scoped_catalogue_equivalence(void)
{
	for (int scenario = 0; scenario < 9; scenario++) {
		reset();
		accepted_epochs[17] = 2;
		struct er_state parent = { .version = 7 };
		if (scenario != 0)
			parent.rows[0] = er_known_row(17, 2, 3);
		if (scenario == 2)
			parent.rows[0].knowledge = ER_ROLE_UNKNOWN;
		if (scenario == 3)
			parent.rows[15] = er_known_row(23, 4, 5);
		if (scenario == 4)
			parent.rows[0].epoch = 9;
		if (scenario == 5)
			accepted_epochs[17] = ER_UNKNOWN;
		if (scenario == 6)
			parent.rows[15].role = 1;
		if (scenario == 7)
			parent.rows[15] = parent.rows[0];
		if (scenario == 8)
			parent.rows[0].reserved = 1;
		struct er_canonical_view legacy = {}, scoped = {};
		er_snapshot(&legacy.work, &parent, 1);
		scoped = legacy;
		struct se_pool_epoch_cache cache = { .scope = 0x200,
						     .generation = 1 };
		for (unsigned i = 0; i < 16; i++) {
			cache.rows[i].uid = scoped.work.rows[i].uid;
			cache.rows[i].accepted_epoch =
				cache.rows[i].uid ?
					test_catalogue_epoch(
						0x200, cache.rows[i].uid) :
					0;
		}
		struct se_route_claim c = {
			.scope = 0x200, .generation = 1, .owned = 1, .slot = 0
		};
		int old = er_canonical_classify(&legacy);
		int now = se_pool_catalogue_classify(&scoped, &cache, &c);
		assert(old == now && legacy.work.error == scoped.work.error &&
		       legacy.accepted_mask == scoped.accepted_mask &&
		       legacy.work.prepared == scoped.work.prepared);
		if (!old) {
			struct er_work old_projection = {}, new_projection = {};
			assert(er_canonical_project(&legacy, &old_projection) ==
			       0);
			assert(er_canonical_project(&scoped, &new_projection) ==
			       0);
			assert(!memcmp(&old_projection, &new_projection,
				       sizeof(old_projection)));
		}
	}
	reset();
	accepted_epochs[17] = 2;
	struct er_state parent = { .version = 7 };
	parent.rows[0] = er_known_row(17, 2, 3);
	struct er_canonical_view view = {};
	er_snapshot(&view.work, &parent, 1);
	struct se_pool_epoch_cache cache = { .scope = 0x200, .generation = 1 };
	cache.rows[0].uid = 23;
	cache.rows[0].accepted_epoch = 2;
	struct se_route_claim c = {
		.scope = 0x200, .generation = 1, .owned = 1, .slot = 0
	};
	assert(se_pool_catalogue_classify(&view, &cache, &c) == ER_INVALID &&
	       view.work.error == ER_INVALID && !view.work.prepared);
	er_snapshot(&view.work, &parent, 1);
	c.generation++;
	assert(se_pool_catalogue_classify(&view, &cache, &c) == ER_INVALID &&
	       view.work.error == ER_INVALID && !view.accepted_mask);
	assert_clean();
	puts("explicit-scope catalogue matches canonical role classifier: PASS");
}
static void test_exact_exec_reap_obligation(void)
{
	reset();
	struct se_pool_reservation reservation = {};
	const __u64 address = 0xd00000;
	struct se_pool_token token = reserve(0, address, 1, &reservation);
	struct se_pool_task_meta *meta = &tasks[token.slot];
	struct se_task_state *semantic = &payloads[token.slot].semantic;
	assert(se_pool_task_exec_reap_step(&token) == SE_POOL_NOT_ELIGIBLE);
	struct se_pool_final_free_lease final_free = {};
	struct task_struct *physical =
		(struct task_struct *)(unsigned long)address;
	assert(se_pool_final_free_acquire(physical, meta, &token,
					  &final_free) == SE_POOL_OK);
	assert(se_pool_death_at_final_free(physical, meta, &final_free) ==
	       SE_POOL_OK);
	assert(se_pool_task_exec_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	assert(!(meta->cleanup_done & SE_POOL_EXEC_DONE));
	assert(se_pool_final_free_release(meta, &final_free) == SE_POOL_OK);
	semantic->exec.owned = 1;
	assert(se_pool_task_exec_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	semantic->exec.owned = 0;
	semantic->reader.owned = 1;
	semantic->reader_invocation = 1;
	assert(se_pool_task_exec_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	semantic->reader.owned = 0;
	assert(se_pool_task_exec_reap_step(&token) == SE_POOL_CORRUPT);
	semantic->reader_invocation = 0;
	route[0].scope++;
	assert(se_pool_task_exec_reap_step(&token) == SE_POOL_CORRUPT);
	route[0].scope--;
	struct se_pool_token stale = token;
	stale.cookie++;
	assert(se_pool_task_exec_reap_step(&stale) == SE_POOL_STALE);
	assert(!(meta->cleanup_done & SE_POOL_EXEC_DONE));
	assert(se_pool_task_exec_reap_step(&token) == SE_POOL_OK);
	assert(meta->phase == SE_POOL_CLEANING &&
	       meta->cleanup_done ==
		       (SE_POOL_CONSTRUCTION_DONE | SE_POOL_EXEC_DONE));
	assert(se_pool_task_exec_reap_step(&token) == SE_POOL_OK);
	assert_clean();
	puts("exact final-free exec/reader reap obligation: PASS");
}
static void test_published_task_terminal_reap(void)
{
	reset();
	struct se_pool_reservation reservation = {};
	const __u64 address = 0xe00000;
	struct se_pool_token token = reserve(0, address, 1, &reservation);
	struct se_pool_task_meta *meta = &tasks[token.slot];
	struct se_pool_final_free_lease final_free = {};
	struct task_struct *physical =
		(struct task_struct *)(unsigned long)address;
	assert(se_pool_final_free_acquire(physical, meta, &token,
					  &final_free) == SE_POOL_OK);
	assert(se_pool_death_at_final_free(physical, meta, &final_free) ==
	       SE_POOL_OK);
	assert(se_pool_final_free_release(meta, &final_free) == SE_POOL_OK);
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_NOT_ELIGIBLE);
	assert(se_pool_task_exec_reap_step(&token) == SE_POOL_OK);
	assert(se_pool_task_work_reap_step(&token) == SE_POOL_OK);
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	assert(!(meta->cleanup_done & SE_POOL_DIR_DONE));
	struct se_pool_token found = {};
	assert(se_pool_lookup(&dirs[se_pool_bucket(address)], address,
			      &found) == SE_POOL_OK);
	/* Test-only independent native/source closure; no product producer exists. */
	meta->cleanup_done |= SE_POOL_NATIVE_DONE;
	meta->native_refs = 1;
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	assert(!(meta->cleanup_done & SE_POOL_DIR_DONE));
	meta->native_refs = 0;
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	assert(meta->cleanup_done & SE_POOL_DIR_DONE);
	assert(se_pool_lookup(&dirs[se_pool_bucket(address)], address,
			      &found) == SE_POOL_MISSING);
	omit_zero_task = 1;
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_CORRUPT);
	assert(meta->phase == SE_POOL_CLEANING && !meta->active_leases &&
	       charges[token.slot].state == SE_POOL_CH_OWNED);
	omit_zero_task = 0;
	fail_zero_update = 1;
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_CORRUPT);
	assert(meta->phase == SE_POOL_CLEANING && !meta->active_leases &&
	       charges[token.slot].state == SE_POOL_CH_OWNED);
	fail_zero_update = 0;
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	assert(meta->phase == SE_POOL_REFUND_PENDING &&
	       meta->cleanup_done == 63u &&
	       !payloads[token.slot].semantic.physical_cookie);
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_PENDING_CLEANUP);
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_OK);
	assert(se_pool_task_live_reap_step(&token) == SE_POOL_ALREADY_RETURNED);
	assert(!route[0].tasks_used &&
	       charges[token.slot].state == SE_POOL_CH_FREE);
	struct se_pool_token stale = token;
	stale.cookie++;
	assert(se_pool_task_live_reap_step(&stale) == SE_POOL_STALE);
	assert_clean();
	puts("published exact TASK terminal reap with native gate: PASS");
}
static void setup_recovery_admin(void)
{
	recovery_config = (struct rm_config){ .incarnation = 11,
					      .bootstrap_nonce = 13,
					      .abi = RM_ABI,
					      .clone_flags = RM_CLONE_FLAGS };
	recovery_control = (struct rm_control){};
	struct rm_grequest register_guardian = { .incarnation = 11,
						 .nonce = 13,
						 .sequence = 1,
						 .operation = RM_REGISTER };
	struct rm_grequest arm = { .incarnation = 11,
				   .nonce = 13,
				   .sequence = 2,
				   .operation = RM_ARM };
	struct rm_arequest ready = { .incarnation = 11,
				     .generation = 1,
				     .sequence = 1,
				     .recovery_epoch = 1,
				     .operation = RM_A_READY };
	struct rm_grequest commit = { .incarnation = 11,
				      .nonce = 13,
				      .sequence = 3,
				      .recovery_epoch = 1,
				      .operation = RM_COMMIT };
	bpf_spin_lock(&recovery_control.lock);
	assert(rt_guardian_step(&recovery_config, &recovery_control,
				&register_guardian, 100) == RM_ACCEPT);
	assert(rt_guardian_step(&recovery_config, &recovery_control, &arm,
				100) == RM_ACCEPT);
	assert(rt_rm_alloc(&recovery_config, &recovery_control, 100, 200,
			   RM_CLONE_FLAGS, 0) == 0);
	assert(rt_admin_step(&recovery_config, &recovery_control, &ready,
			     200) == RM_ACCEPT);
	assert(rt_guardian_step(&recovery_config, &recovery_control, &commit,
				100) == RM_ACCEPT);
	bpf_spin_unlock(&recovery_control.lock);
	current_task = 200;
}
static void test_reap_control_single_flight(void)
{
	setup_recovery_admin();
	struct rm_grequest arm = {};
	struct rm_arequest ready = {};
	struct rm_grequest commit = {};
	struct se_pool_control control = {};
	struct se_pool_receipt receipt = {};
	struct se_pool_request accepted = {};
	struct se_pool_request request = { .abi = SE_POOL_REAP_ABI,
					   .operation = SE_POOL_REAP_STEP,
					   .node_incarnation = 11,
					   .admin_generation = 1,
					   .reap_sequence = 1,
					   .task_budget = 32,
					   .work_budget = 32 };
	struct se_pool_control before = control;
	struct se_pool_receipt receipt_before = receipt;
	current_task = 201;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	assert(!memcmp(&control, &before, sizeof(control)) &&
	       !memcmp(&receipt, &receipt_before, sizeof(receipt)));
	current_task = 200;
	request.reserved1 = 1;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	request.reserved1 = 0;
	request.task_budget = 31;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	request.task_budget = 32;
	request.expected_epoch = 1;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	request.expected_epoch = 0;
	request.node_incarnation = 12;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	request.node_incarnation = 11;
	assert(!memcmp(&control, &before, sizeof(control)) &&
	       !memcmp(&receipt, &receipt_before, sizeof(receipt)));
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_ACCEPT);
	assert(control.flags == SE_POOL_REAP_BUSY &&
	       control.last_reap_sequence == 1 && !control.scan_epoch &&
	       !memcmp(&accepted, &request, sizeof(request)));
	assert(se_pool_reap_begin(&request, &control,
				  &(struct se_pool_request){}) ==
	       SE_POOL_REAP_IN_FLIGHT);
	struct se_pool_reap_progress progress = { .task_cursor = 32,
						  .work_cursor = 32,
						  .task_examined = 32,
						  .work_examined = 31 };
	assert(se_pool_reap_finish(&control, &receipt, &accepted, &progress) ==
		       SE_POOL_REAP_FAULT &&
	       control.flags == SE_POOL_REAP_BUSY);
	assert(!memcmp(&receipt, &receipt_before, sizeof(receipt)));
	accepted.task_budget = 31;
	assert(se_pool_reap_finish(&control, &receipt, &accepted, &progress) ==
		       SE_POOL_REAP_FAULT &&
	       control.flags == SE_POOL_REAP_BUSY);
	accepted.task_budget = 32;
	progress.work_examined = 32;
	progress.task_pending = 32;
	progress.work_pending = 32;
	assert(se_pool_reap_finish(&control, &receipt, &accepted, &progress) ==
	       SE_POOL_REAP_ACCEPT);
	assert(!control.flags && control.scan_epoch == 1 &&
	       control.task_cursor == 32 && control.work_cursor == 32 &&
	       control.task_visits == 32 && control.work_visits == 32 &&
	       receipt.flags == (SE_POOL_REAP_RECEIPT_VALID |
				 SE_POOL_REAP_RECEIPT_METRICS_INCOMPLETE) &&
	       receipt.reap_sequence == 1 && receipt.epoch_after == 1 &&
	       receipt.task_examined == 32 && receipt.work_examined == 32);
	before = control;
	receipt_before = receipt;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	assert(!memcmp(&control, &before, sizeof(control)) &&
	       !memcmp(&receipt, &receipt_before, sizeof(receipt)));
	request.reap_sequence = 2;
	request.expected_epoch = 1;
	request.admin_generation = 2;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	bpf_spin_lock(&recovery_control.lock);
	assert(!rt_rm_free(&recovery_control, 200));
	arm = (struct rm_grequest){ .incarnation = 11,
				    .nonce = 13,
				    .sequence = 4,
				    .expected_admin_generation = 1,
				    .expected_admin_sequence = 1,
				    .recovery_epoch = 1,
				    .operation = RM_ARM };
	assert(rt_guardian_step(&recovery_config, &recovery_control, &arm,
				100) == RM_ACCEPT);
	assert(rt_rm_alloc(&recovery_config, &recovery_control, 100, 201,
			   RM_CLONE_FLAGS, 0) == 0);
	ready = (struct rm_arequest){ .incarnation = 11,
				      .generation = 2,
				      .sequence = 1,
				      .recovery_epoch = 2,
				      .operation = RM_A_READY };
	assert(rt_admin_step(&recovery_config, &recovery_control, &ready,
			     201) == RM_ACCEPT);
	commit = (struct rm_grequest){ .incarnation = 11,
				       .nonce = 13,
				       .sequence = 5,
				       .expected_admin_generation = 1,
				       .expected_admin_sequence = 1,
				       .recovery_epoch = 2,
				       .operation = RM_COMMIT };
	assert(rt_guardian_step(&recovery_config, &recovery_control, &commit,
				100) == RM_ACCEPT);
	bpf_spin_unlock(&recovery_control.lock);
	current_task = 201;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_ACCEPT);
	progress.task_cursor = 64;
	progress.work_cursor = 64;
	assert(se_pool_reap_finish(&control, &receipt, &accepted, &progress) ==
		       SE_POOL_REAP_ACCEPT &&
	       control.scan_epoch == 2 && control.last_admin_generation == 2 &&
	       receipt.reap_sequence == 2);
	request.admin_generation = 1;
	request.reap_sequence = 3;
	request.expected_epoch = 2;
	before = control;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	assert(!memcmp(&control, &before, sizeof(control)));
	request.admin_generation = 2;
	for (__u64 sequence_number = 3; sequence_number <= 8;
	     sequence_number++) {
		request.reap_sequence = sequence_number;
		request.expected_epoch = sequence_number - 1;
		assert(se_pool_reap_begin(&request, &control, &accepted) ==
		       SE_POOL_REAP_ACCEPT);
		progress.task_cursor = (__u32)(sequence_number * 32);
		progress.work_cursor =
			(__u32)((sequence_number * 32) % SE_POOL_W);
		assert(se_pool_reap_finish(&control, &receipt, &accepted,
					   &progress) == SE_POOL_REAP_ACCEPT);
	}
	assert(control.task_cursor == 256 && control.work_cursor == 0 &&
	       control.task_visits == 256 && control.work_visits == 256 &&
	       receipt.work_after == 0 && receipt.reap_sequence == 8);
	struct rm_control living = recovery_control;
	before = control;
	receipt_before = receipt;
	request.reap_sequence = 9;
	request.expected_epoch = 8;
	bpf_spin_lock(&recovery_control.lock);
	assert(!rt_rm_free(&recovery_control, 100));
	bpf_spin_unlock(&recovery_control.lock);
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	recovery_control = living;
	bpf_spin_lock(&recovery_control.lock);
	assert(!rt_rm_free(&recovery_control, 201));
	bpf_spin_unlock(&recovery_control.lock);
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	assert(!memcmp(&control, &before, sizeof(control)) &&
	       !memcmp(&receipt, &receipt_before, sizeof(receipt)));
	assert(!held);
	puts("reaper single-flight admission and receipts: PASS");
}
static void test_reaper_partial_abort(void)
{
	setup_recovery_admin();
	struct se_pool_control control = {};
	struct se_pool_receipt receipt = {};
	struct se_pool_request request = { .abi = SE_POOL_REAP_ABI,
					   .operation = SE_POOL_REAP_STEP,
					   .node_incarnation = 11,
					   .admin_generation = 1,
					   .reap_sequence = 1,
					   .task_budget = 32,
					   .work_budget = 32 };
	struct se_pool_request accepted = {};
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_ACCEPT);
	struct se_pool_reap_progress progress = { .task_cursor = 4,
						  .work_cursor = 3,
						  .task_examined = 4,
						  .work_examined = 3,
						  .task_pending = 4,
						  .work_pending = 3 };
	struct se_pool_reap_progress invalid = progress;
	invalid.work_cursor = 4;
	assert(se_pool_reap_abort(&control, &receipt, &accepted, &invalid) ==
		       SE_POOL_REAP_FAULT &&
	       control.flags == SE_POOL_REAP_BUSY && !receipt.flags);
	assert(se_pool_reap_abort(&control, &receipt, &accepted, &progress) ==
		       SE_POOL_REAP_FAULT &&
	       !control.flags && control.scan_epoch == 1 &&
	       control.task_cursor == 4 && control.work_cursor == 3 &&
	       control.task_visits == 4 && control.work_visits == 3 &&
	       receipt.status == SE_POOL_REAP_FAULT &&
	       receipt.task_examined == 4 && receipt.work_examined == 3 &&
	       receipt.task_after == 4 && receipt.work_after == 3 &&
	       receipt.epoch_after == 1 &&
	       (receipt.flags & SE_POOL_REAP_RECEIPT_VALID));
	struct se_pool_control before = control;
	struct se_pool_receipt previous = receipt;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_REFUSE);
	assert(!memcmp(&control, &before, sizeof(control)) &&
	       !memcmp(&receipt, &previous, sizeof(receipt)));
	request.reap_sequence = 2;
	request.expected_epoch = 1;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_ACCEPT);
	progress = (struct se_pool_reap_progress){ .task_cursor = 36,
						   .work_cursor = 35,
						   .task_examined = 32,
						   .work_examined = 32,
						   .task_pending = 32,
						   .work_pending = 32 };
	assert(se_pool_reap_abort(&control, &receipt, &accepted, &progress) ==
		       SE_POOL_REAP_FAULT &&
	       control.flags == SE_POOL_REAP_BUSY);
	assert(se_pool_reap_finish(&control, &receipt, &accepted, &progress) ==
		       SE_POOL_REAP_ACCEPT &&
	       !control.flags && control.scan_epoch == 2 &&
	       control.task_cursor == 36 && control.work_cursor == 35 &&
	       control.task_visits == 36 && control.work_visits == 35);
	request.reap_sequence = 3;
	request.expected_epoch = 2;
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_ACCEPT);
	progress = (struct se_pool_reap_progress){ .task_cursor = 36,
						   .work_cursor = 35 };
	assert(se_pool_reap_abort(&control, &receipt, &accepted, &progress) ==
		       SE_POOL_REAP_FAULT &&
	       !control.flags && control.scan_epoch == 3 &&
	       control.task_cursor == 36 && control.work_cursor == 35 &&
	       control.task_visits == 36 && control.work_visits == 35 &&
	       !receipt.task_examined && !receipt.work_examined &&
	       receipt.status == SE_POOL_REAP_FAULT);
	assert(!held);
	puts("partial and zero-visit reaper abort receipts: PASS");
}
static void test_reaper_task_slot_visit(void)
{
	reset();
	assert(se_pool_reap_task_visit_slot(0) == SE_POOL_ALREADY_RETURNED);
	assert(se_pool_reap_task_visit_slot(SE_POOL_T) == SE_POOL_CORRUPT);
	struct se_pool_reservation reservation = {};
	__u64 address = 0xf00000;
	struct se_pool_token token = reserve(0, address, 1, &reservation);
	assert(se_pool_reap_task_visit_slot(token.slot) ==
	       SE_POOL_PENDING_CLEANUP);
	struct se_pool_final_free_lease final_free = {};
	struct task_struct *physical =
		(struct task_struct *)(unsigned long)address;
	assert(se_pool_final_free_acquire(physical, &tasks[token.slot], &token,
					  &final_free) == SE_POOL_OK);
	assert(se_pool_death_at_final_free(physical, &tasks[token.slot],
					   &final_free) == SE_POOL_OK);
	assert(se_pool_final_free_release(&tasks[token.slot], &final_free) ==
	       SE_POOL_OK);
	assert(se_pool_reap_task_visit_slot(token.slot) ==
	       SE_POOL_PENDING_CLEANUP);
	assert(tasks[token.slot].cleanup_done ==
	       (SE_POOL_CONSTRUCTION_DONE | SE_POOL_EXEC_DONE |
		SE_POOL_WORK_DONE));
	assert(charges[token.slot].state == SE_POOL_CH_OWNED);
	/* This is deliberately a host-only native/source certification. */
	tasks[token.slot].cleanup_done |= SE_POOL_NATIVE_DONE;
	omit_zero_task = 1;
	assert(se_pool_reap_task_visit_slot(token.slot) == SE_POOL_CORRUPT);
	assert(charges[token.slot].state == SE_POOL_CH_OWNED &&
	       tasks[token.slot].flags ==
		       (SE_POOL_PUBLISHED | SE_POOL_DIR_CLAIM));
	omit_zero_task = 0;
	assert(se_pool_reap_task_visit_slot(token.slot) == SE_POOL_OK);
	assert(charges[token.slot].state == SE_POOL_CH_FREE &&
	       !route[0].tasks_used && tasks[token.slot].phase == SE_POOL_FREE);
	assert(se_pool_reap_task_visit_slot(token.slot) ==
	       SE_POOL_ALREADY_RETURNED);
	assert_clean();

	reset();
	struct se_route_claim c = claim(0);
	struct se_pool_task_birth_candidate birth = {};
	assert(se_pool_task_birth_prepare(&route[0], &c, 0xf10000, &birth) ==
	       SE_POOL_OK);
	__u32 slot = birth.token.slot;
	assert(se_pool_task_birth_abort(&birth) == SE_POOL_OK);
	drop(0, &c);
	assert(tasks[slot].phase == SE_POOL_ABORTED &&
	       se_pool_reap_task_visit_slot(slot) == SE_POOL_OK);
	assert(charges[slot].state == SE_POOL_CH_FREE && !route[0].tasks_used);
	assert(se_pool_reap_task_visit_slot(slot) == SE_POOL_ALREADY_RETURNED);
	assert_clean();
	puts("fixed TASK slot visitor and native wait: PASS");
}
static void test_reaper_eight_real_chunks(void)
{
	reset();
	setup_recovery_admin();
	struct se_pool_reservation reservation = {};
	const __u64 address = 0xf20000;
	struct se_pool_token live = reserve(0, address, 1, &reservation);
	struct se_pool_task_semantic_handle task_handle = {};
	assert(se_pool_task_semantic_open(address, &task_handle) == SE_POOL_OK);
	struct se_pw_task_lease work_lease = {};
	assert(se_pool_work_lease_from_task(&task_handle, &work_lease) ==
	       SE_PW_OK);
	__u32 work_slot = SE_POOL_W;
	assert(se_pw_select(&route[0], &bitmaps[0], &work_lease, &work_slot) ==
	       SE_PW_OK);
	struct se_pool_work_refs work_refs = {};
	assert(se_pool_work_prefetch(&work_lease, work_slot, &work_refs) ==
	       SE_PW_OK);
	struct se_pw_ticket ticket = {};
	assert(se_pw_begin(work_refs.route, work_refs.bitmap, work_refs.charge,
			   work_refs.sequence, work_refs.task, work_refs.work,
			   work_refs.payload, work_refs.previous_task,
			   &work_lease, work_slot, &ticket) == SE_PW_OK);
	assert(se_pw_attach(&tasks[live.slot], &works[work_slot], &work_lease,
			    &ticket) == SE_PW_OK);
	struct se_pool_work_payload *work_payload = &work_payloads[work_slot];
	assert(se_pool_work_semantic_initialize(
		       &tasks[live.slot], &works[work_slot],
		       &charges[SE_POOL_T + work_slot], &work_payload,
		       &work_lease, &ticket) == SE_PW_OK);
	assert(se_pw_commit(&works[work_slot], &route[0], &bitmaps[0],
			    &charges[SE_POOL_T + work_slot],
			    &ticket) == SE_PW_OK);
	struct se_pool_work_semantic_handle work_handle = {};
	assert(se_pool_work_semantic_open(&tasks[live.slot], &work_lease,
					  &works[work_slot], work_payload,
					  &ticket, &route[0],
					  &charges[SE_POOL_T + work_slot],
					  &work_handle) == SE_PW_OK);
	assert(se_pool_work_semantic_done(&work_handle) == SE_PW_OK);
	assert(se_pool_work_lease_to_task(&task_handle, &work_lease, &ticket) ==
	       SE_PW_OK);
	assert(se_pool_task_semantic_close(&task_handle) == SE_POOL_OK);
	assert(tasks[live.slot].work_refs == 1 &&
	       charges[SE_POOL_T + work_slot].state == SE_PW_CH_OWNED);
	struct se_pool_final_free_lease final_free = {};
	struct task_struct *physical =
		(struct task_struct *)(unsigned long)address;
	assert(se_pool_final_free_acquire(physical, &tasks[live.slot], &live,
					  &final_free) == SE_POOL_OK);
	assert(se_pool_death_at_final_free(physical, &tasks[live.slot],
					   &final_free) == SE_POOL_OK);
	assert(se_pool_final_free_release(&tasks[live.slot], &final_free) ==
	       SE_POOL_OK);
	struct se_route_claim claim0 = claim(0);
	struct se_pool_task_birth_candidate aborted = {};
	assert(se_pool_task_birth_prepare(&route[0], &claim0, 0xf30000,
					  &aborted) == SE_POOL_OK);
	assert(aborted.token.slot != live.slot);
	assert(se_pool_task_birth_abort(&aborted) == SE_POOL_OK);
	drop(0, &claim0);
	__u32 aborted_slot = aborted.token.slot;

	struct se_pool_control control = {};
	struct se_pool_receipt receipt = {};
	struct se_pool_request request = { .abi = SE_POOL_REAP_ABI,
					   .operation = SE_POOL_REAP_STEP,
					   .node_incarnation = 11,
					   .admin_generation = 1,
					   .reap_sequence = 1,
					   .task_budget = 32,
					   .work_budget = 32 };
	struct se_pool_request accepted = {};
	assert(se_pool_reap_begin(&request, &control, &accepted) ==
	       SE_POOL_REAP_ACCEPT);
	struct se_pool_reap_progress progress = {};
	progress.work_cursor = 1;
	assert(se_pool_reap_chunk4(&accepted, 0, 0, &progress) ==
	       SE_POOL_REAP_FAULT);
	assert(!progress.work_examined && !progress.task_examined);
	progress.work_cursor = 0;
	for (int i = 0; i < 7; i++)
		assert(se_pool_reap_chunk4(&accepted, 0, 0, &progress) ==
		       SE_POOL_REAP_ACCEPT);
	assert(progress.work_examined == 28 && progress.task_examined == 28 &&
	       progress.work_cursor == 28 && progress.task_cursor == 28 &&
	       progress.work_reclaimed == 1 && progress.task_reclaimed == 1 &&
	       progress.task_pending == 1 && !progress.task_faults &&
	       !progress.work_faults);
	assert(se_pool_reap_finish(&control, &receipt, &accepted, &progress) ==
		       SE_POOL_REAP_FAULT &&
	       control.flags == SE_POOL_REAP_BUSY && !receipt.flags);
	assert(se_pool_reap_chunk4(&accepted, 0, 0, &progress) ==
	       SE_POOL_REAP_ACCEPT);
	assert(se_pool_reap_chunk4(&accepted, 0, 0, &progress) ==
	       SE_POOL_REAP_REFUSE);
	assert(progress.work_examined == 32 && progress.task_examined == 32 &&
	       progress.work_cursor == 32 && progress.task_cursor == 32);
	assert(se_pool_reap_finish(&control, &receipt, &accepted, &progress) ==
	       SE_POOL_REAP_ACCEPT);
	assert(!control.flags && control.scan_epoch == 1 &&
	       control.work_visits == 32 && control.task_visits == 32 &&
	       receipt.work_examined == 32 && receipt.task_examined == 32 &&
	       receipt.work_reclaimed == 1 && receipt.task_reclaimed == 1 &&
	       receipt.task_pending == 1 && !receipt.task_faults &&
	       !receipt.work_faults &&
	       (receipt.flags & SE_POOL_REAP_RECEIPT_METRICS_INCOMPLETE) &&
	       charges[aborted_slot].state == SE_POOL_CH_FREE &&
	       charges[SE_POOL_T + work_slot].state == SE_PW_CH_FREE &&
	       charges[live.slot].state == SE_POOL_CH_OWNED &&
	       !(tasks[live.slot].cleanup_done & SE_POOL_NATIVE_DONE));
	assert_clean();
	puts("eight real four-slot chunks and exact 32/32 receipt: PASS");
}
static void test_reaper_full_cursor_lap(void)
{
	reset();
	setup_recovery_admin();
	struct se_pool_control control = {};
	struct se_pool_receipt receipt = {};
	struct se_pool_request request = { .abi = SE_POOL_REAP_ABI,
					   .operation = SE_POOL_REAP_STEP,
					   .node_incarnation = 11,
					   .admin_generation = 1,
					   .task_budget = 32,
					   .work_budget = 32 };
	for (__u64 step = 0; step < SE_POOL_T / 32u; step++) {
		request.reap_sequence = step + 1;
		request.expected_epoch = step;
		struct se_pool_request accepted = {};
		assert(se_pool_reap_begin(&request, &control, &accepted) ==
		       SE_POOL_REAP_ACCEPT);
		__u32 task_start = control.task_cursor,
		      work_start = control.work_cursor;
		struct se_pool_reap_progress progress = {
			.task_cursor = task_start, .work_cursor = work_start
		};
		for (int chunk = 0; chunk < 8; chunk++)
			assert(se_pool_reap_chunk4(&accepted, task_start,
						   work_start, &progress) ==
			       SE_POOL_REAP_ACCEPT);
		assert(se_pool_reap_finish(&control, &receipt, &accepted,
					   &progress) == SE_POOL_REAP_ACCEPT);
		assert(receipt.task_examined == 32 &&
		       receipt.work_examined == 32 && !receipt.task_reclaimed &&
		       !receipt.work_reclaimed && !receipt.task_pending &&
		       !receipt.work_pending && !receipt.task_faults &&
		       !receipt.work_faults &&
		       control.task_cursor == ((step + 1) * 32) % SE_POOL_T &&
		       control.work_cursor == ((step + 1) * 32) % SE_POOL_W);
	}
	assert(control.task_cursor == 0 && control.work_cursor == 0 &&
	       control.task_visits == SE_POOL_T &&
	       control.work_visits == SE_POOL_T &&
	       control.scan_epoch == SE_POOL_T / 32u &&
	       receipt.reap_sequence == SE_POOL_T / 32u);
	assert_clean();
	puts("512 accepted 32/32 scans cover every TASK slot: PASS");
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SNAPSHOT_BRANCHLESS_DIAGNOSTIC
/* Independent scalar oracle for the legacy nested search. Keep this here
 * while the branchless verifier path is being qualified for the real hook. */
static int snapshot_match_oracle(const struct se_route_claim *claim,
				 const struct se_snapshot *snapshot,
				 const struct er_work *projected)
{
	if (!claim || !snapshot || !projected ||
	    snapshot->scope != claim->scope ||
	    snapshot->serial != claim->serial ||
	    snapshot->generation != claim->generation ||
	    !se_snapshot_metadata_valid(&snapshot->metadata, snapshot->count,
					claim->generation))
		return 0;
	for (__u32 i = 0; i < snapshot->count; i++) {
		int found = 0;
		for (__u32 j = 0; j < 16; j++) {
			const struct er_row *row = &projected->rows[j];
			if (row->uid != snapshot->metadata.policy_uids[i] ||
			    row->epoch != snapshot->metadata.root_epochs[i])
				continue;
			found++;
			if (claim->execution_class == 2 &&
			    (snapshot->metadata.required_known & (1U << i)) &&
			    !er_role_known(row))
				return 0;
		}
		if (found != 1)
			return 0;
	}
	return 1;
}
static void test_snapshot_match_branchless(void)
{
	struct se_route_claim claim = { .scope = 0x200,
					.serial = 7,
					.generation = 16,
					.execution_class = 2 };
	struct se_snapshot snapshot = {
		.scope = 0x200, .serial = 7, .generation = 16, .count = 8
	};
	struct er_work projected = {};
	snapshot.metadata.container_length = 1;
	for (__u32 i = 0; i < 8; i++) {
		snapshot.metadata.policy_uids[i] = i + 1;
		snapshot.metadata.root_epochs[i] = i + 1;
		projected.rows[i] =
			(struct er_row){ .uid = i + 1,
					 .epoch = i + 1,
					 .role = 1,
					 .knowledge = ER_ROLE_KNOWN };
	}
#define CHECK()                                                              \
	assert(se_inherit_snapshot_matches(&claim, &snapshot, &projected) == \
	       snapshot_match_oracle(&claim, &snapshot, &projected))
	for (__u32 count = 1; count <= 8; count++) {
		snapshot.count = count;
		for (__u32 i = count; i < 8; i++) {
			__u64 uid = snapshot.metadata.policy_uids[i];
			__u64 epoch = snapshot.metadata.root_epochs[i];
			snapshot.metadata.policy_uids[i] = 0;
			snapshot.metadata.root_epochs[i] = 0;
			CHECK();
			snapshot.metadata.policy_uids[i] = uid;
			snapshot.metadata.root_epochs[i] = epoch;
		}
	}
	snapshot.count = 8;
	snapshot.metadata.required_known = 0xff;
	CHECK();
	projected.rows[0].knowledge = ER_ROLE_UNKNOWN;
	CHECK();
	claim.execution_class = 1;
	CHECK();
	claim.execution_class = 2;
	projected.rows[0].knowledge = ER_ROLE_KNOWN;
	projected.rows[8] = projected.rows[0];
	CHECK();
	projected.rows[8] = (struct er_row){};
	projected.rows[0].epoch++;
	CHECK();
	projected.rows[0].epoch--;
	snapshot.serial++;
	CHECK();
	snapshot.serial--;
	snapshot.metadata.policy_uids[1] = snapshot.metadata.policy_uids[0];
	CHECK();
	snapshot.metadata.policy_uids[1] = 2;
	__u64 random = 0x6b4b543fa1875729ULL;
	for (int t = 0; t < 2000; t++) {
		random = random * 6364136223846793005ULL + 1;
		__u32 idx = (__u32)((random >> 32) & 15);
		struct er_row saved = projected.rows[idx];
		projected.rows[idx].uid = (random >> 40) & 15;
		projected.rows[idx].epoch = (random >> 48) & 31;
		projected.rows[idx].knowledge = (random >> 56) & 3;
		CHECK();
		projected.rows[idx] = saved;
	}
#undef CHECK
	puts("branchless snapshot matcher oracle: PASS");
}
#endif
int main(void)
{
	payloads = calloc(SE_POOL_T, sizeof(*payloads));
	assert(payloads);
	work_payloads = calloc(SE_POOL_W, sizeof(*work_payloads));
	assert(work_payloads);
	test_abort_churn();
	test_capacity_contention_withdrawal();
	test_directory_collision();
	test_displacement_and_stale();
	test_failed_initialize();
	test_recycled_task_churn();
	test_recycled_abort_churn();
	test_abort_reap_zero_retry();
	test_refund_tail_faults();
	test_refund_tail_constructor_cuts();
	test_refund_tail_late_meta_fault();
	test_typed_semantic_handle();
	test_typed_task_movement();
	test_typed_exec_fault();
	test_semantic_zero_failure_retains_charge();
	test_semantic_finish_fault_holds_account();
	test_birth_successor_and_failures();
	test_task_work_lease_bridge();
	test_work_prefetch_prior_owner_slot();
	test_scoped_catalogue_equivalence();
	test_exact_exec_reap_obligation();
	test_published_task_terminal_reap();
	test_reap_control_single_flight();
	test_reaper_partial_abort();
	test_reaper_task_slot_visit();
	test_reaper_eight_real_chunks();
	test_reaper_full_cursor_lap();
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SNAPSHOT_BRANCHLESS_DIAGNOSTIC
	test_snapshot_match_branchless();
#endif
	free(work_payloads);
	free(payloads);
	puts("candidate task-core host regressions: PASS");
	return 0;
}
