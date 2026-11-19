/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
struct bpf_spin_lock {
	unsigned held;
};
static unsigned locks;
static void bpf_spin_lock(struct bpf_spin_lock *l)
{
	assert(!l->held);
	l->held = 1;
	locks++;
}
static void bpf_spin_unlock(struct bpf_spin_lock *l)
{
	assert(l->held && locks);
	l->held = 0;
	locks--;
}
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#include "shared_route.h"
#include "shared_policy_lookup.h"
static inline const struct fm_blob *
se_policy_physical(void *ctx, fm_u32 slot, fm_u64 generation, fm_u32 key)
{
	(void)ctx;
	(void)slot;
	(void)generation;
	(void)key;
	return 0;
}
#define ER_ACCEPTED_EPOCH(uid) ((void)(uid), 0ULL)
#include "epoch_roles.h"
#include "shared_exec.h"

#define POOL 3
#define BPF_NOEXIST 1
struct cell {
	__u64 address;
	struct se_task_state task;
};
static struct cell cells[POOL];
static const unsigned char zero_template[960];
struct account {
	__u64 scope;
	unsigned used, limit, retired;
};
static struct account accounts[2];
/* Test-only bounded ownership assertions for parent callbacks, NOT a new
 * production cookie registry. At most POOL rows plus one insertion attempt. */
struct charge {
	__u64 cookie, scope;
	__u32 slot;
};
static struct charge charges[POOL + 1];
static __u64 next_cookie, last_insert, highest_cookie;
static unsigned insert_fail, delete_fail, missing_template, hide_inserted;
static unsigned after_delete, inserts, deletes, refunds, quota_calls;
static unsigned physical_key_exclusive;
static void map_access(void)
{
	assert(physical_key_exclusive && !locks && !after_delete);
}
static struct se_task_state *lookup(__u64 key)
{
	map_access();
	if (hide_inserted && key == last_insert) {
		hide_inserted = 0;
		return 0;
	}
	for (unsigned i = 0; i < POOL; i++)
		if (cells[i].address == key)
			return &cells[i].task;
	return 0;
}
static const void *zero(void)
{
	map_access();
	return missing_template ? 0 : zero_template;
}
static int insert(__u64 key, const void *value, unsigned flags)
{
	map_access();
	inserts++;
	assert(flags == BPF_NOEXIST && value == zero_template);
	if (insert_fail)
		return -1;
	for (unsigned i = 0; i < POOL; i++)
		if (cells[i].address == key)
			return -1;
	for (unsigned i = 0; i < POOL; i++)
		if (!cells[i].address) {
			memcpy(&cells[i].task, value, sizeof(cells[i].task));
			cells[i].address = key;
			last_insert = key;
			return 0;
		}
	return -1;
}
static int delete_key(__u64 key)
{
	map_access();
	deletes++;
	if (delete_fail)
		return -1;
	for (unsigned i = 0; i < POOL; i++)
		if (cells[i].address == key) {
			assert(!(cells[i].task.flags & SE_TASK_LIVE));
			/* Poison immediately, before refund: later row reads are forbidden. */
			memset(&cells[i].task, 0xa5, sizeof(cells[i].task));
			cells[i].address = 0;
			after_delete = 1;
			return 0;
		}
	return -1;
}
static int reserve(__u32 slot, __u64 scope, __u64 *cookie)
{
	map_access();
	quota_calls++;
	if (slot >= 2 || accounts[slot].scope != scope ||
	    accounts[slot].retired ||
	    accounts[slot].used >= accounts[slot].limit ||
	    next_cookie >= ~0ULL - 1 || next_cookie < highest_cookie)
		return -1;
	for (unsigned i = 0; i < POOL + 1; i++)
		if (!charges[i].cookie) {
			*cookie = ++next_cookie;
			highest_cookie = *cookie;
			charges[i] = (struct charge){ *cookie, scope, slot };
			accounts[slot].used++;
			return 0;
		}
	return -1;
}
static void refund(__u32 slot, __u64 scope, __u64 cookie)
{
	assert(physical_key_exclusive && !locks);
	assert(slot < 2 && accounts[slot].scope == scope &&
	       accounts[slot].used);
	for (unsigned i = 0; i < POOL + 1; i++)
		if (charges[i].cookie == cookie) {
			assert(charges[i].scope == scope &&
			       charges[i].slot == slot);
			charges[i] = (struct charge){};
			accounts[slot].used--;
			refunds++;
			after_delete = 0;
			return;
		}
	assert(!"refund without exactly one owned charge");
}
#define SE_TASK_LOOKUP(key) lookup(key)
#define SE_TASK_INSERT_NOEXIST(key, value) insert(key, value, BPF_NOEXIST)
#define SE_TASK_DELETE(key) delete_key(key)
#define SE_TASK_ZERO_TEMPLATE() zero()
#define SE_TASK_RESERVE(slot, scope, cookie) reserve(slot, scope, cookie)
#define SE_TASK_REFUND(slot, scope, cookie) refund(slot, scope, cookie)
#include "shared_task_identity.h"

static void reset_node(void)
{
	memset(cells, 0, sizeof(cells));
	memset(charges, 0, sizeof(charges));
	accounts[0] = (struct account){ .scope = 11, .limit = 2 };
	accounts[1] = (struct account){ .scope = 22, .limit = 1 };
	locks = insert_fail = delete_fail = missing_template = hide_inserted =
		0;
	after_delete = inserts = deletes = refunds = quota_calls = 0;
	next_cookie = highest_cookie = last_insert = 0;
	physical_key_exclusive = 1;
}
static void birth_death_and_collision(void)
{
	reset_node();
	assert(se_task_birth(100, 0, 11) == SE_TASK_ID_OK);
	struct se_task_state *task = lookup(100);
	assert(task && task->flags == SE_TASK_LIVE &&
	       task->physical_cookie == 1);
	assert(task->scope_slot == 0 && task->scope_cookie == 11 &&
	       task->eligibility_version == 1);
	struct er_state empty = {};
	assert(!memcmp(&task->committed, &empty,
		       sizeof(empty))); /* no root grant */
	assert(!task->exec.owned && !task->reader.owned &&
	       !task->staged.attempt);
	assert(se_task_birth(100, 1, 22) == SE_TASK_ID_COLLISION);
	assert(!(task->flags & SE_TASK_LIVE) &&
	       (task->flags & SE_TASK_QUARANTINED));
	assert(task->physical_cookie == 1 && task->scope_cookie == 11 &&
	       task->scope_slot == 0);
	assert(quota_calls == 1 && accounts[0].used == 1 && !accounts[1].used);
	/* Original account survives binding removal; no current-cgroup refund. */
	accounts[0].retired = 1;
	assert(se_task_death(100) == SE_TASK_ID_OK && !accounts[0].used &&
	       !accounts[1].used);
	unsigned prior = refunds;
	assert(se_task_death(100) == SE_TASK_ID_OK && refunds == prior);
	assert(se_task_birth(100, 1, 22) == SE_TASK_ID_OK);
	assert(lookup(100)->scope_cookie == 22 &&
	       lookup(100)->physical_cookie == 2);
	assert(se_task_death(100) == SE_TASK_ID_OK);
}
static void pressure_and_failures(void)
{
	reset_node();
	missing_template = 1;
	assert(se_task_birth(100, 0, 11) == SE_TASK_ID_INVALID && !quota_calls);
	missing_template = 0;
	assert(se_task_birth(100, 0, 11) == SE_TASK_ID_OK);
	insert_fail = 1;
	assert(se_task_birth(101, 0, 11) == SE_TASK_ID_INSERT_FAILED);
	assert(accounts[0].used == 1 && refunds == 1 &&
	       lookup(100)->flags == SE_TASK_LIVE);
	insert_fail = 0;
	assert(se_task_birth(101, 0, 11) == SE_TASK_ID_OK);
	assert(se_task_birth(102, 0, 11) == SE_TASK_ID_QUOTA);
	assert(se_task_birth(102, 1, 22) ==
	       SE_TASK_ID_OK); /* neighbor reservation */
	delete_fail = 1;
	assert(se_task_death(100) == SE_TASK_ID_DELETE_FAILED);
	assert(accounts[0].used == 2 && !(lookup(100)->flags & SE_TASK_LIVE));
	assert(se_task_birth(100, 1, 22) == SE_TASK_ID_COLLISION);
	delete_fail = 0;
	assert(se_task_death(100) == SE_TASK_ID_OK && accounts[0].used == 1);
	assert(se_task_death(101) == SE_TASK_ID_OK &&
	       se_task_death(102) == SE_TASK_ID_OK);
	assert(!accounts[0].used && !accounts[1].used);
}
static void readers_and_cookie_refusal(void)
{
	reset_node();
	assert(!se_task_birth(100, 0, 11));
	struct se_task_state *task = lookup(100);
	task->exec.owned = 1;
	assert(se_task_death(100) == SE_TASK_ID_BUSY && !deletes &&
	       accounts[0].used == 1);
	task->exec.owned = 0;
	task->reader.owned = 1;
	assert(se_task_death(100) == SE_TASK_ID_BUSY && !deletes);
	task->reader.owned = 0;
	task->reader_invocation = 9;
	assert(se_task_death(100) == SE_TASK_ID_BUSY && !deletes);
	task->reader_invocation =
		0; /* parent resolves within held final lifetime */
	assert(!se_task_death(100));
	next_cookie =
		0; /* parent allocator must refuse duplicate cookie issue */
	assert(se_task_birth(101, 0, 11) == SE_TASK_ID_QUOTA &&
	       !accounts[0].used);
	next_cookie = ~0ULL - 1;
	assert(se_task_birth(101, 0, 11) == SE_TASK_ID_QUOTA &&
	       !accounts[0].used);
}
static void failed_children_and_later_lsm_denial(void)
{
	reset_node();
	/* Simulate the source-backed callback ordering, not kernel coverage: both
  * an own post-birth qualification refusal and a later LSM alloc denial end
  * in actual death-body cleanup before the unpublished child can escape. */
	for (unsigned refusal_stage = 0; refusal_stage < 2; refusal_stage++) {
		unsigned child_published = 0;
		assert(!se_task_birth(200, 0, 11));
		assert(accounts[0].used == 1 &&
		       lookup(200)->flags == SE_TASK_LIVE);
		int allocation_result = refusal_stage ? -13 : -1;
		if (allocation_result)
			assert(!se_task_death(200));
		else
			child_published = 1;
		assert(!child_published && !lookup(200) && !accounts[0].used);
	}
	unsigned prior = refunds;
	/* Failure before this adapter acquired a row/charge must not refund one. */
	assert(se_task_birth(201, 0, 22) == SE_TASK_ID_QUOTA);
	assert(!se_task_death(201) && refunds == prior);
}
static void impossible_lookup_stays_charged(void)
{
	reset_node();
	hide_inserted = 1;
	assert(se_task_birth(100, 0, 11) == SE_TASK_ID_FATAL_CHARGED);
	assert(accounts[0].used == 1 && !refunds && lookup(100));
	assert(se_task_death(100) == SE_TASK_ID_FATAL_CHARGED &&
	       accounts[0].used == 1);
	/* Deliberately violated insertion/lookup invariant: no ordinary recovery
	 * claim. Only complete node teardown discards this orphan fixture below. */
	reset_node();
}
int main(void)
{
	birth_death_and_collision();
	pressure_and_failures();
	readers_and_cookie_refusal();
	failed_children_and_later_lsm_denial();
	impossible_lookup_stays_charged();
	/* Actual map-operation body reused for failed children, later-LSM-denied
	 * children and ordinary task death. Kernel callback coverage is NOT proved. */
	for (unsigned i = 0; i < 100001; i++) {
		unsigned slot = i & 1;
		__u64 scope = accounts[slot].scope;
		assert(!se_task_birth(100, slot, scope));
		assert(lookup(100)->flags == SE_TASK_LIVE);
		assert(!se_task_death(100));
		assert(!accounts[0].used && !accounts[1].used);
	}
	assert(inserts == 100001 && deletes == 100001 && refunds == 100001);
	puts("shared task identity HASH body with mock fixed account: 100001 lifetime cycles, failed-child cleanup, original quota, quarantine and charged invariant faults passed");
}
