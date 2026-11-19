/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <string.h>
#include <stdint.h>
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
#define SE_PUBLICATION_ARM_TEST 1
#include "shared_publication_arm.h"

static void hold_ticket(struct se_binding_snapshots *b)
{
	b->records[0].tickets[0] =
		(struct se_pin_ticket){ .scope = 11,
					.snapshot_serial = 1,
					.object_generation = 3,
					.phase = SE_TICKET_HELD };
	b->records[0].metadata.root_epochs[0] = 1;
	b->records[0].metadata.policy_uids[0] = 9;
	b->records[0].metadata.container_length = 1;
	b->records[0].metadata.container[0] = '/';
}

static struct se_arm_request commit_request(void)
{
	return (struct se_arm_request){ .node_cookie = 4,
					.nonce = 5,
					.sequence = 8,
					.scope = 11,
					.serial = 1,
					.expected_generation = 0,
					.qualification = 0,
					.operation = SE_ARM_COMMIT,
					.record = 0,
					.count = 1,
					.bank_index = { 2 },
					.epochs = { 1 } };
}

int main(void)
{
	assert(SE_ARM_COMMIT != 16 && SE_ARM_WITHDRAW != 16 &&
	       SE_ARM_BIND != 16);
	struct se_route_anchor a = {};
	struct se_binding_snapshots b = { .scope = 11, .next_serial = 1 };
	b.records[0] = (struct se_snapshot){ .scope = 11,
					     .serial = 1,
					     .phase = SE_SNAPSHOT_PREPARED,
					     .count = 1,
					     .execution_class = 1 };
	hold_ticket(&b);
	assert(!se_route_open_locked(&a, 7, 11, 0));
	assert(se_arm_target_cgroup_matches(7, &a));
	assert(!se_arm_target_cgroup_matches(8, &a));
	assert(!se_arm_target_cgroup_matches(0, &a));
	assert(!se_arm_target_cgroup_matches(7, 0));
	struct se_epoch_cell cell = {};
	struct se_epoch_cell neighbor = { .scope = 99, .uid = 8, .epoch = 4 };
	struct se_epoch_cell *cells[8] = { &cell };
	struct se_arm_request req = commit_request();
	struct se_route_anchor before_a = a;
	struct se_binding_snapshots before_b = b;
	assert(se_arm_commit_locked(0, &a, &b, &req, cells));
	assert(!memcmp(&a, &before_a, sizeof(a)));
	assert(!memcmp(&b, &before_b, sizeof(b)));
	assert(!cell.epoch && neighbor.epoch == 4);
	assert(se_arm_commit_locked(1, &a, &b, &req, cells) == 0);
	assert(b.generation == 1 && a.phase == SE_ROUTE_ACTIVE &&
	       a.payload_generation == 1 && cell.scope == 11 && cell.uid == 9 &&
	       cell.epoch == 1 && neighbor.scope == 99 && neighbor.epoch == 4);
	struct se_epoch_cell other = {};
	struct se_binding_snapshots foreign = b;
	struct se_route_anchor foreign_route = a;
	foreign.scope = 12;
	foreign_route.scope = 12;
	req.scope = 12;
	req.expected_generation = 1;
	cells[0] = &other;
	assert(se_arm_commit_locked(1, &foreign_route, &foreign, &req, cells));
	assert(!other.epoch && neighbor.epoch == 4);
	req = commit_request();
	req.expected_generation = 0;
	req.sequence = 9;
	cells[0] = &cell;
	assert(se_arm_commit_locked(1, &a, &b, &req, cells));
	assert(b.generation == 1 && cell.epoch == 1);
	struct se_epoch_cell occupied = { .scope = 11, .uid = 9, .epoch = 2 };
	cells[0] = &occupied;
	req.expected_generation = 1;
	req.qualification = a.admission_serial;
	assert(se_arm_commit_locked(1, &a, &b, &req, cells));
	assert(occupied.epoch == 2);
	/* A route admission that releases its lexical claim never acquires a
	 * persistent snapshot reader. It still invalidates the route proof. */
	struct se_route_claim lexical = {};
	assert(se_route_claim_locked(&a, se_route_locator(0, a.incarnation), 7,
				     &lexical) == SE_ROUTE_OWNED);
	assert(!se_route_release_locked(&a, &lexical));
	assert(a.admission_serial == b.admission_serial + 1);
	struct se_arm_request withdraw = commit_request();
	withdraw.operation = SE_ARM_WITHDRAW;
	withdraw.expected_generation = 1;
	withdraw.qualification = b.admission_serial;
	assert(se_arm_withdraw_locked(1, &a, &b, &withdraw));
	withdraw.qualification = a.admission_serial;
	struct se_epoch_cell epoch_before = cell;
	assert(se_arm_withdraw_locked(0, &a, &b, &withdraw));
	assert(!se_arm_withdraw_locked(1, &a, &b, &withdraw));
	assert(b.generation == 1 && !b.active_serial &&
	       a.phase == SE_ROUTE_WITHDRAWN &&
	       !memcmp(&cell, &epoch_before, sizeof(cell)));
	assert(se_arm_withdraw_locked(1, &a, &b, &withdraw));
	assert(se_catalogue_read(&cell, 11, 9) == 1);
	assert(se_catalogue_indexed_read(0, &cell, 11, 9) == 0);
	assert(se_catalogue_indexed_read(1, &cell, 11, 9) == 1);
	assert(se_catalogue_indexed_read(1, 0, 11, 9) == ~0ULL);
	assert(se_catalogue_read(&cell, 12, 9) == ~0ULL);
	assert(se_catalogue_indexed_read(1, &cell, 12, 9) == ~0ULL);
	assert(se_catalogue_read(0, 11, 9) == ~0ULL);
	struct se_epoch_cell malformed = cell;
	malformed.epoch = 0;
	assert(se_catalogue_read(&malformed, 11, 9) == ~0ULL);
	malformed = cell;
	malformed.reserved0 = 1;
	assert(se_catalogue_read(&malformed, 11, 9) == ~0ULL);
	__u32 bank = 2;
	assert(se_arm_index_decision(0, 2, &cell, 11, 9) == 1);
	assert(se_arm_index_decision(&bank, 2, &cell, 11, 9) == 0);
	assert(se_arm_index_decision(&bank, 3, &cell, 11, 9));
	struct se_epoch_cell foreign_cell = { .scope = 12,
					      .uid = 9,
					      .epoch = 1 };
	assert(se_arm_index_decision(0, 2, &foreign_cell, 11, 9));
	__u64 uids[8] = { 9 };
	assert(!se_arm_uids_match(&b.records[0], &withdraw, uids));
	uids[0] = 8;
	assert(se_arm_uids_match(&b.records[0], &withdraw, uids));
	return 0;
}
