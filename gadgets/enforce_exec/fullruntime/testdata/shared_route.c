/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
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
struct se_route_anchor;
static const __u64 *index_lookup(const __u64 *);
static struct se_route_anchor *anchor_lookup(const __u32 *);
static void after_copy(void);
#define SE_ROUTE_INDEX_LOOKUP index_lookup
#define SE_ROUTE_ANCHOR_LOOKUP anchor_lookup
#define SE_ROUTE_AFTER_LOCATOR_COPY after_copy
#define SE_ROUTE_CAPACITY 2
#include "shared_route.h"

static struct se_route_anchor routes[2];
static __u64 locator_value, index_cgroup;
static int stall;
static const __u64 *index_lookup(const __u64 *key)
{
	return *key == index_cgroup ? &locator_value : 0;
}
static struct se_route_anchor *anchor_lookup(const __u32 *key)
{
	return *key < 2 ? &routes[*key] : 0;
}
static void after_copy(void)
{
	if (!stall)
		return;
	/* Explicit old withdrawal/unlink/reuse occurred before this delayed lock.
  * The stale HASH pointer is not accessed again by actual se_route_admit. */
	routes[0].incarnation++;
	routes[0].scope++;
	routes[0].execution_class = 2;
	locator_value = se_route_locator(0, routes[0].incarnation);
	stall = 0;
}
int main(void)
{
	struct se_route_anchor a = {};
	struct se_binding_snapshots b = { .scope = 11, .next_serial = 1 };
	b.records[0] = (struct se_snapshot){ .scope = 11,
					     .serial = 1,
					     .phase = SE_SNAPSHOT_PREPARED,
					     .count = 1,
					     .execution_class = 1 };
	assert(!se_route_open_locked(&a, 7, 11, 0));
	b.records[0].tickets[0] =
		(struct se_pin_ticket){ .scope = 11,
					.snapshot_serial = 1,
					.object_generation = 1,
					.phase = SE_TICKET_HELD };
	struct se_route_anchor before_a = a;
	struct se_binding_snapshots before_b = b;
	__u64 epoch = 4;
	a.reserved = 1;
	assert(se_route_commit_preflight_locked(&a, &b, 0, 1,
						a.admission_serial));
	assert(epoch == 4 && !memcmp(&b, &before_b, sizeof(b)));
	a.reserved = 0;
	assert(!memcmp(&a, &before_a, sizeof(a)));
	assert(!se_route_commit_preflight_locked(&a, &b, 0, 1,
						 a.admission_serial));
	se_route_commit_publish_locked(&a, &b, 0);
	__u64 locator = se_route_locator(0, a.incarnation);
	struct se_route_claim c = {};
	assert(se_route_claim_locked(&a, locator, 7, &c) == SE_ROUTE_OWNED);
	assert(a.early_claims == 1 && c.execution_class == 1);
	assert(se_route_claim_locked(&a, locator, 7, &c) ==
	       SE_ROUTE_AUDIT_FAULT);
	assert(a.early_claims == 1);
	a.reserved = 1;
	struct se_route_claim empty = {};
	assert(se_route_claim_locked(&a, locator, 7, &empty) ==
	       SE_ROUTE_AUDIT_FAULT);
	assert(!empty.owned && a.early_claims == 1);
	a.reserved = 0;
	assert(se_route_withdraw_locked(&a, &b));
	struct se_reader_owner owner = {};
	struct se_reader_token token = {};
	assert(!se_route_transfer_locked(&a, &b, &c, 42, &owner, &token));
	assert(!a.early_claims && b.records[0].claims == 1 && !c.owned);
	assert(se_route_withdraw_locked(&a, &b));
	assert(!se_reader_release_locked(&b, &owner, &token));
	assert(se_reader_release_locked(&b, &owner, &token));
	assert(!se_route_withdraw_locked(&a, &b));
	assert(se_route_claim_locked(&a, locator, 7, &c) ==
	       SE_ROUTE_UNSELECTED);
	/* Cleanup/locator unlink must complete before recycle, represented explicitly. */
	assert(se_route_recycle_locked(&a, &b));
	b.records[0] =
		(struct se_snapshot){}; /* tickets reclaimed, locator unlinked */
	/* A sticky structural fault must retain the withdrawn account even when
	 * all counted obligations have drained. Refusal must not alter the anchor. */
	a.reserved = 1;
	before_a = a;
	assert(se_route_recycle_locked(&a, &b));
	assert(!memcmp(&a, &before_a, sizeof(a)));
	a.reserved = 0;
	assert(!se_route_recycle_locked(&a, &b));
	assert(!se_route_open_locked(&a, 8, 12, 0));
	assert(se_route_claim_locked(&a, locator, 7, &c) ==
	       SE_ROUTE_UNSELECTED);
	/* Actual lookup entry: missing payload after OWNED must use retained class.
  * No payload lookup is needed to decide terminal counter overflow. */
	routes[0] = (struct se_route_anchor){ .incarnation = 7,
					      .cgroup_identity = 99,
					      .scope = 100,
					      .payload_generation = 1,
					      .active_serial = 1,
					      .phase = SE_ROUTE_ACTIVE,
					      .execution_class = 1 };
	index_cgroup = 99;
	locator_value = se_route_locator(0, 7);
	c = (struct se_route_claim){};
	assert(se_route_admit(98, &c) == SE_ROUTE_UNSELECTED);
	assert(se_route_admit(99, &c) == SE_ROUTE_OWNED);
	assert(c.execution_class == 1 && routes[0].early_claims == 1);
	assert(!se_route_release_locked(&routes[0], &c));
	assert(se_route_release_locked(&routes[0], &c));
	routes[0].early_claims = ~0U;
	assert(se_route_admit(99, &c) == SE_ROUTE_AUDIT_FAULT && !c.owned);
	routes[0].execution_class = 2;
	assert(se_route_admit(99, &c) == SE_ROUTE_STRICT_FAULT && !c.owned);
	routes[0].early_claims = 0;
	routes[0].execution_class = 1;
	routes[0].admission_serial = ~0ULL - 1;
	assert(se_route_admit(99, &c) == SE_ROUTE_AUDIT_FAULT);
	routes[0].admission_serial = 0;
	stall = 1;
	assert(se_route_admit(99, &c) == SE_ROUTE_UNSELECTED);
	assert(!routes[0].early_claims && !c.owned);
	assert(se_route_admit(99, &c) == SE_ROUTE_OWNED &&
	       c.execution_class == 2);
	assert(!se_route_release_locked(&routes[0], &c));
	/* Neighbor remains admissible while route zero is retiring. */
	routes[0].phase = SE_ROUTE_WITHDRAWN;
	routes[1] = (struct se_route_anchor){ .incarnation = 1,
					      .cgroup_identity = 55,
					      .scope = 56,
					      .payload_slot = 1,
					      .payload_generation = 1,
					      .active_serial = 1,
					      .phase = SE_ROUTE_ACTIVE,
					      .execution_class = 1 };
	index_cgroup = 55;
	locator_value = se_route_locator(1, 1);
	assert(se_route_admit(55, &c) == SE_ROUTE_OWNED && c.scope == 56);
	assert(!se_route_release_locked(&routes[1], &c));
	return 0;
}
