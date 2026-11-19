// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
struct bpf_spin_lock {
	int held;
};
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	assert(!lock->held);
	lock->held = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	assert(lock->held);
	lock->held = 0;
}
#include "shared_snapshot.h"
#include "shared_policy_lookup.h"
static struct se_shared_object object;
static struct fm_blob cells[10];
static inline const struct fm_blob *
se_policy_physical(void *context, fm_u32 slot, fm_u64 generation, fm_u32 key)
{
	return !context && !slot && generation == 1 && key < 10 ? &cells[key] :
								  0;
}
static struct se_shared_object *object_lookup(const __u32 *slot)
{
	return *slot == 0 ? &object : 0;
}
#define SE_OBJECT_LOOKUP(key) object_lookup(key)
#include "shared_policy_prepare.h"

int main(void)
{
	const struct fe_header header = { .policies = 1, .rule_base = 9 };
	const struct fe_policy policy = {
		.uid = 1,
		.root_role = 1,
		.mode = 2,
	};
	memcpy(&cells[0], &header, sizeof(header));
	memcpy(&cells[1], &policy, sizeof(policy));
	object.state = (struct se_object){
		.generation = 1,
		.pins = 1,
		.length = 10,
	};
	struct se_snapshot snapshot = {
		.scope = 11, .serial = 5, .generation = 20,
		.phase = SE_SNAPSHOT_ACTIVE, .count = 1, .claims = 1,
		.tickets = {{
			.scope = 11, .snapshot_serial = 5,
			.object_generation = 1, .object_slot = 0,
			.phase = SE_TICKET_HELD,
		}},
		.metadata = {
			.root_epochs = {13}, .policy_uids = {1},
			.container_length = 1, .container = {'/'},
		},
	};
	struct se_policy_view view = {};
	assert(!se_prepare_policy_view(&view, 11, &snapshot, 20));
	assert(view.ready && view.scope_cookie == 11 &&
	       view.policies[0].uid == 1);
	snapshot.phase = SE_SNAPSHOT_RETIRING;
	assert(!se_prepare_policy_view(&view, 11, &snapshot, 20));
	snapshot.phase = SE_SNAPSHOT_ACTIVE;
	snapshot.claims = 0;
	assert(se_prepare_policy_view(&view, 11, &snapshot, 20));
	assert(!view.ready && !se_policy_header(&view));
	snapshot.claims = 1;
	assert(!se_prepare_policy_view(&view, 11, &snapshot, 20));
	snapshot.scope = 12;
	assert(se_prepare_policy_view(&view, 11, &snapshot, 20));
	assert(!view.ready && !se_policy_header(&view));
	snapshot.scope = 11;
	assert(!se_prepare_policy_view(&view, 11, &snapshot, 20));
	snapshot.generation = 19;
	assert(se_prepare_policy_view(&view, 11, &snapshot, 20));
	assert(!view.ready && !se_policy_header(&view));
	snapshot.generation = 20;
	assert(!se_prepare_policy_view(&view, 11, &snapshot, 20));
	snapshot.serial = 0;
	assert(se_prepare_policy_view(&view, 11, &snapshot, 20));
	assert(!view.ready && !se_policy_header(&view));
	snapshot.serial = 5;
	assert(!se_prepare_policy_view(&view, 11, &snapshot, 20));

	/* This failure happens AFTER se_policy_prepare published ready. */
	snapshot.metadata.policy_uids[0] = 2;
	assert(se_prepare_policy_view(&view, 11, &snapshot, 20));
	assert(!view.ready && !se_policy_header(&view));
	snapshot.metadata.policy_uids[0] = 1;
	assert(!se_prepare_policy_view(&view, 11, &snapshot, 20));
	snapshot.tickets[0].phase = SE_TICKET_RELEASED;
	assert(se_prepare_policy_view(&view, 11, &snapshot, 20));
	assert(!view.ready && !se_policy_header(&view));
	snapshot.tickets[0].phase = SE_TICKET_HELD;
	assert(!se_prepare_policy_view(&view, 11, &snapshot, 20));
	object.state.pins = 0;
	assert(se_prepare_policy_view(&view, 11, &snapshot, 20));
	assert(!view.ready && !se_policy_header(&view));
	object.state.pins = 1;
	assert(!se_prepare_policy_view(&view, 11, &snapshot, 20));
	assert(se_prepare_policy_view(&view, 11, 0, 20));
	assert(!view.ready && !se_policy_header(&view));
	return 0;
}
