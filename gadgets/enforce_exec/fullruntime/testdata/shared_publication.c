// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
struct bpf_spin_lock {
	int held;
};
static void bpf_spin_lock(struct bpf_spin_lock *l)
{
	assert(!l->held);
	l->held = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *l)
{
	assert(l->held);
	l->held = 0;
}
#include "shared_snapshot.h"
static struct bpf_spin_lock authority_lock;
static void prepared(struct se_shared_binding *b, struct se_shared_object *o,
		     __u32 record)
{
	struct se_pin_ticket h = { .object_slot = o->state.slot,
				   .object_generation = o->state.generation };
	assert(!se_snapshot_prepare_locked(&b->state, record, &h, 1, 1));
	struct se_ticket_request r = { .scope = b->state.scope,
				       .serial =
					       b->state.records[record].serial,
				       .record = record,
				       .kind = SE_COMMAND_PIN };
	__u32 receipt;
	assert(!se_ticket_command(&authority_lock, b, o, &r, &receipt));
	assert(!se_snapshot_prepared_locked(&b->state.records[record]));
}

static void partial_and_overflow(void)
{
	struct se_shared_binding b = { .state.scope = 21 };
	struct se_shared_object objects[8] = {};
	struct se_pin_ticket handles[8] = {};
	for (__u32 i = 0; i < 8; i++) {
		objects[i].state = (struct se_object){
			.slot = i, .generation = 1, .phase = SE_OBJECT_READY
		};
		handles[i] = (struct se_pin_ticket){ .object_slot = i,
						     .object_generation = 1 };
	}
	assert(!se_snapshot_prepare_locked(&b.state, 0, handles, 8, 2));
	__u32 receipt;
	struct se_ticket_request r = { .scope = 21,
				       .serial = 1,
				       .kind = SE_COMMAND_PIN };
	for (__u32 i = 0; i < 3; i++) {
		r.position = i;
		assert(!se_ticket_command(&authority_lock, &b, &objects[i], &r,
					  &receipt));
	}
	assert(se_snapshot_prepared_locked(&b.state.records[0]) < 0);
	assert(!se_snapshot_retire_locked(&b.state.records[0]));
	assert(se_snapshot_reclaim_locked(&b.state.records[0]) < 0);
	r.kind = SE_COMMAND_RELEASE;
	for (__u32 i = 0; i < 3; i++) {
		r.position = i;
		assert(!se_ticket_command(&authority_lock, &b, &objects[i], &r,
					  &receipt));
		assert(!objects[i].state.pins);
	}
	r.position = 7;
	assert(se_ticket_command(&authority_lock, &b, &objects[7], &r,
				 &receipt) < 0 &&
	       !objects[7].state.pins);
	assert(!se_snapshot_reclaim_locked(&b.state.records[0]));
	b.state.next_serial = ~0ULL - 1;
	assert(se_snapshot_prepare_locked(&b.state, 0, handles, 8, 2) < 0 &&
	       b.state.records[0].phase == SE_SNAPSHOT_FREE);
	b.state.next_serial = 1;
	assert(!se_snapshot_prepare_locked(&b.state, 0, handles, 8, 2));
	r.serial = 2;
	r.position = 0;
	r.kind = SE_COMMAND_PIN;
	b.state.next_command = ~0ULL - 1;
	assert(se_ticket_command(&authority_lock, &b, &objects[0], &r,
				 &receipt) < 0 &&
	       !b.state.records[0].commands);
	b.state.next_command = 0;
	objects[0].state.pins = (__u32)~0U;
	assert(se_ticket_command(&authority_lock, &b, &objects[0], &r,
				 &receipt) < 0 &&
	       objects[0].state.pins == (__u32)~0U &&
	       !b.state.records[0].commands);
	objects[0].state.pins = 0;
	assert(!se_ticket_command(&authority_lock, &b, &objects[0], &r,
				  &receipt));
}

static void remove_readd(void)
{
	struct se_shared_binding b = { .state.scope = 31 };
	struct se_shared_object o = { .state = { .slot = 9,
						 .generation = 1,
						 .phase = SE_OBJECT_READY } };
	prepared(&b, &o, 0);
	assert(!se_binding_commit_preflight_locked(&b.state, 0, 1, 0, 0));
	se_binding_commit_publish_locked(&b.state, 0);
	struct se_reader_owner owner = {};
	struct se_reader_token token = {};
	assert(!se_reader_acquire_locked(&b.state, 31, 100, &owner, &token));
	assert(se_binding_withdraw_preflight_locked(
		       &b.state, 1, b.state.admission_serial) < 0);
	assert(!se_reader_release_locked(&b.state, &owner, &token));
	assert(!se_binding_withdraw_preflight_locked(&b.state, 1,
						     b.state.admission_serial));
	se_binding_withdraw_publish_locked(&b.state);
	assert(!b.state.active_serial && b.state.generation == 1);
	assert(se_reader_acquire_locked(&b.state, 31, 100, &owner, &token) < 0);
	struct se_ticket_request r = { .scope = 31,
				       .serial = 1,
				       .record = 0,
				       .kind = SE_COMMAND_RELEASE };
	__u32 receipt;
	assert(!se_ticket_command(&authority_lock, &b, &o, &r, &receipt));
	assert(!se_snapshot_reclaim_locked(&b.state.records[0]));
	prepared(&b, &o, 0);
	assert(!se_binding_commit_preflight_locked(&b.state, 0,
						   b.state.records[0].serial, 1,
						   b.state.admission_serial));
	se_binding_commit_publish_locked(&b.state, 0);
	assert(b.state.generation == 2 && b.state.active_serial == 2 &&
	       b.state.scope == 31 && o.state.pins == 1);
}
int main(void)
{
	partial_and_overflow();
	remove_readd();
	struct se_shared_binding b = { .state.scope = 11 };
	struct se_shared_object o = { .state = { .slot = 7,
						 .generation = 3,
						 .phase = SE_OBJECT_READY } };
	prepared(&b, &o, 0);
	__u64 serial = b.state.records[0].serial;
	assert(!se_binding_commit_preflight_locked(&b.state, 0, serial, 0, 0));
	se_binding_commit_publish_locked(
		&b.state, 0); /* no epoch stores in this helper test */
	assert(b.state.generation == 1 && b.state.active_serial == serial &&
	       o.state.pins == 1);
	assert(se_snapshot_retire_locked(&b.state.records[0]) < 0);
	struct se_reader_owner owner = {}, other = {};
	struct se_reader_token token = {}, copy = {}, newer = {};
	assert(!se_reader_acquire_locked(&b.state, 11, 42, &owner, &token));
	copy = token;
	prepared(&b, &o, 1);
	__u64 candidate = b.state.records[1].serial;
	struct se_binding_snapshots unchanged = b.state;
	assert(se_binding_commit_preflight_locked(&b.state, 1, candidate, 1,
						  b.state.admission_serial) <
	       0);
	assert(!memcmp(&unchanged, &b.state, sizeof(unchanged)));
	assert(!se_reader_release_locked(&b.state, &owner, &token));
	assert(!se_reader_acquire_locked(&b.state, 11, 42, &owner, &newer));
	assert(!se_reader_acquire_locked(&b.state, 11, 43, &other, &token));
	assert(se_reader_release_locked(&b.state, &owner, &copy) < 0 &&
	       b.state.records[0].claims == 2);
	assert(!se_reader_release_locked(&b.state, &owner, &newer));
	assert(!se_reader_release_locked(&b.state, &other, &token));
	assert(se_binding_commit_preflight_locked(&b.state, 1, candidate, 1,
						  unchanged.admission_serial) <
	       0); /* completed admission invalidates proof */
	struct se_snapshot_command cmd = {};
	assert(!se_snapshot_command_begin_locked(&b.state, 0, 11, serial,
						 SE_COMMAND_INSPECT, &cmd));
	assert(se_binding_commit_preflight_locked(&b.state, 1, candidate, 1,
						  b.state.admission_serial) <
	       0);
	assert(!se_snapshot_command_end_locked(&b.state, &cmd));
	b.state.inflight = 1;
	assert(se_binding_commit_preflight_locked(&b.state, 1, candidate, 1,
						  b.state.admission_serial) <
	       0);
	b.state.inflight = 0;
	assert(!se_binding_commit_preflight_locked(&b.state, 1, candidate, 1,
						   b.state.admission_serial));
	se_binding_commit_publish_locked(&b.state, 1);
	assert(b.state.generation == 2 &&
	       b.state.records[0].phase == SE_SNAPSHOT_RETIRING &&
	       b.state.records[1].phase == SE_SNAPSHOT_ACTIVE &&
	       o.state.pins == 2);
	assert(se_binding_commit_preflight_locked(&b.state, 1, candidate, 1,
						  b.state.admission_serial) <
	       0);
	assert(se_reader_acquire_record_locked(&b.state, 0, serial, 11, 44,
					       &owner, &token) < 0);
	assert(!se_reader_acquire_locked(&b.state, 11, 44, &owner, &token) &&
	       token.serial == candidate);
	assert(!se_reader_release_locked(&b.state, &owner, &token));
	struct se_pin_ticket h = { .object_slot = 7, .object_generation = 3 };
	assert(se_snapshot_prepare_locked(&b.state, 0, &h, 1, 1) <
	       0); /* retirement occupies second record */
	assert(se_snapshot_prepare_locked(&b.state, 1, &h, 1, 1) < 0);
	struct se_shared_binding neighbor = { .state.scope = 12 };
	prepared(&neighbor, &o,
		 0); /* no node-wide stall despite b's exhausted records */
	assert(!se_binding_commit_preflight_locked(
		&neighbor.state, 0, neighbor.state.records[0].serial, 0, 0));
	se_binding_commit_publish_locked(&neighbor.state, 0);
	assert(!se_reader_acquire_locked(&neighbor.state, 12, 55, &owner,
					 &token));
	assert(!se_reader_release_locked(&neighbor.state, &owner, &token));
	b.state.records[1].claims = (__u32)~0U;
	assert(se_reader_acquire_locked(&b.state, 11, 56, &owner, &token) < 0 &&
	       !owner.owned);
	b.state.records[1].claims = 0;
	b.state.next_reader = ~0ULL - 1;
	assert(se_reader_acquire_locked(&b.state, 11, 56, &owner, &token) < 0 &&
	       !owner.owned);
	puts("shared commit/reader same-lock linearization and unchanged pin transfer passed");
}
