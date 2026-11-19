// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
struct bpf_spin_lock {
	int held;
};
static int lock_depth;
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	assert(!lock_depth && !lock->held);
	lock->held = 1;
	lock_depth++;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	assert(lock_depth == 1 && lock->held);
	lock->held = 0;
	lock_depth--;
}
static void pause_after_release(void *binding);
#define SE_TICKET_BEFORE_COMMAND_END(binding) pause_after_release(binding)
#include "shared_snapshot.h"
static struct bpf_spin_lock authority_lock;
_Static_assert(sizeof(struct se_object) == 72, "object state wire");
_Static_assert(sizeof(struct se_shared_object) == 80, "locked object wire");
_Static_assert(sizeof(struct se_pin_ticket) == 40, "ticket wire");
_Static_assert(sizeof(struct se_snapshot) == 784, "snapshot wire");
_Static_assert(sizeof(struct se_shared_binding) == 1632,
	       "two-snapshot binding wire");
static int pause_count;
static void pause_after_release(void *binding)
{
	struct se_shared_binding *b = binding;
	assert(!lock_depth);
	if (!pause_count)
		return;
	pause_count--;
	bpf_spin_lock(&authority_lock);
	assert(b->state.records[0].tickets[0].phase == SE_TICKET_RELEASED);
	assert(se_snapshot_reclaim_locked(&b->state.records[0]) < 0);
	struct se_snapshot_command stale = {};
	assert(se_snapshot_command_begin_locked(
		       &b->state, 0, 11, 1, SE_COMMAND_RELEASE, &stale) < 0);
	bpf_spin_unlock(&authority_lock);
}
static void malformed_ticket_positions(void)
{
	struct se_shared_binding b = { .state.scope = 11 };
	struct se_shared_object o = { .state = { .slot = 7,
						 .size_class = 0,
						 .phase = SE_OBJECT_READY,
						 .generation = 3 } };
	struct se_pin_ticket handles[8] = {};
	for (__u32 i = 0; i < 8; i++) {
		handles[i].object_generation = 3;
		handles[i].object_slot = 7;
	}
	assert(!se_snapshot_prepare_locked(&b.state, 0, handles, 8, 1));
	struct se_ticket_request request = { .scope = 11,
					     .serial = 1,
					     .record = 0,
					     .position = 7,
					     .kind = SE_COMMAND_PIN };
	__u32 receipt = 99;
	assert(!se_ticket_command(&authority_lock, &b, &o, &request, &receipt));
	assert(receipt == SE_TICKET_HELD && o.state.pins == 1);
	const __u32 invalid[] = { 8, UINT32_MAX };
	for (__u32 kind = SE_COMMAND_PIN; kind <= SE_COMMAND_RELEASE; kind++) {
		if (kind == SE_COMMAND_RELEASE)
			assert(!se_snapshot_retire_locked(&b.state.records[0]));
		request.kind = kind;
		for (unsigned int i = 0;
		     i < sizeof(invalid) / sizeof(invalid[0]); i++) {
			request.position = invalid[i];
			struct se_shared_binding saved_binding = b;
			struct se_shared_object saved_object = o;
			receipt = 99;
			assert(se_ticket_command(&authority_lock, &b, &o,
						 &request, &receipt) < 0);
			assert(!memcmp(&b, &saved_binding, sizeof(b)));
			assert(!memcmp(&o, &saved_object, sizeof(o)));
			assert(receipt == 99 && !lock_depth &&
			       !authority_lock.held);
		}
	}
	request.position = 7;
	assert(!se_ticket_command(&authority_lock, &b, &o, &request, &receipt));
	assert(receipt == SE_TICKET_RELEASED && !o.state.pins);
}
int main(void)
{
	malformed_ticket_positions();
	struct se_shared_binding b = { .state.scope = 11 };
	struct se_shared_object o = { .state = { .slot = 7,
						 .size_class = 0,
						 .phase = SE_OBJECT_READY,
						 .generation = 3 } };
	struct se_pin_ticket handle = { .object_generation = 3,
					.object_slot = 7 };
	assert(!se_snapshot_prepare_locked(&b.state, 0, &handle, 1, 1));
	struct se_ticket_request request = { .scope = 11,
					     .serial = 1,
					     .record = 0,
					     .position = 0,
					     .kind = SE_COMMAND_PIN };
	__u32 receipt = 99;
	assert(!se_ticket_command(&authority_lock, &b, &o, &request,
				  &receipt) &&
	       receipt == SE_TICKET_HELD && o.state.pins == 1);
	assert(!se_ticket_command(&authority_lock, &b, &o, &request,
				  &receipt) &&
	       o.state.pins == 1); /* retry same pin */
	assert(!se_snapshot_prepared_locked(&b.state.records[0]));
	b.state.records[0].claims = 1;
	assert(se_snapshot_retire_locked(&b.state.records[0]) < 0);
	b.state.records[0].claims = 0;
	assert(!se_snapshot_retire_locked(&b.state.records[0]));
	assert(se_ticket_command(&authority_lock, &b, &o, &request, &receipt) <
	       0); /* no retiring acquisition */
	request.kind = SE_COMMAND_RELEASE;
	pause_count = 1;
	assert(!se_ticket_command(&authority_lock, &b, &o, &request,
				  &receipt) &&
	       receipt == SE_TICKET_RELEASED && !o.state.pins && !pause_count);
	assert(!se_ticket_command(&authority_lock, &b, &o, &request,
				  &receipt) &&
	       !o.state.pins);
	assert(!se_object_retire_locked(&o.state, 3));
	assert(!se_object_reclaim_locked(&o.state, 3));
	assert(!se_object_begin_locked(&o.state, 2, 1));
	struct se_write_claim write = {};
	assert(!se_object_write_begin_locked(&o.state, 4, 2, 0, &write));
	assert(!se_object_write_finish_locked(&o.state, &write));
	assert(!se_object_finalize_locked(&o.state, 4, 2, 1, 1));
	o.state.pins = 5;
	assert(!se_ticket_command(&authority_lock, &b, &o, &request,
				  &receipt) &&
	       o.state.pins == 5); /* old receipt, new object */
	assert(!se_snapshot_reclaim_locked(&b.state.records[0]));
	assert(!se_snapshot_prepare_locked(&b.state, 0, &handle, 1, 1));
	assert(se_ticket_command(&authority_lock, &b, &o, &request, &receipt) <
	       0); /* stale serial */
	request.serial = 2;
	request.kind = SE_COMMAND_PIN;
	assert(se_ticket_command(&authority_lock, &b, &o, &request, &receipt) <
		       0 &&
	       !b.state.records[0].commands); /* stale object generation */
	request.scope = 12;
	assert(se_ticket_command(&authority_lock, &b, &o, &request, &receipt) <
	       0);
	struct se_snapshot_command cmd = {}, copy = {}, later = {};
	assert(!se_snapshot_command_begin_locked(&b.state, 0, 11, 2,
						 SE_COMMAND_INSPECT, &cmd));
	copy = cmd;
	assert(!se_snapshot_command_end_locked(&b.state, &cmd));
	assert(!se_snapshot_command_begin_locked(&b.state, 0, 11, 2,
						 SE_COMMAND_INSPECT, &later));
	assert(se_snapshot_command_end_locked(&b.state, &copy) < 0 &&
	       b.state.records[0].commands == 1);
	assert(!se_snapshot_command_end_locked(&b.state, &later));
	assert(!lock_depth);
	puts("shared snapshot ticket command lifetime and duplicate-release controls passed");
}
