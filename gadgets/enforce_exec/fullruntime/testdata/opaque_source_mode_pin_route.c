/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Host contract for route barriers only. Source header lookup/lifetime and
 * actual terminal authentication are caller obligations, not proved here. */
#define ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE 1
#define main opaque_locator_fixture_main
#include "../../full/test/host/opaque_locator_candidate.c"
#undef main

static void prepare(__u32 mode, struct se_ol_payload_handle *owner,
		    __u64 *physical, __u64 *invocation)
{
	*invocation = 0;
	*physical = seed_live_opaque_task_for_open();
	assert(se_ol_task_open(physical, owner) == SE_OL_OK);
	payloads[0].semantic.flags = SE_TASK_QUALIFIED;
	routes[0] = (struct se_route_anchor){ .incarnation = 1,
					      .cgroup_identity = 7,
					      .scope = 10,
					      .payload_slot = 0,
					      .payload_generation = 13,
					      .active_serial = 1,
					      .execution_class = mode,
					      .phase = SE_ROUTE_ACTIVE };
	bindings[0] = (struct se_binding_snapshots){
		.scope = 10,
		.generation = 13,
		.next_serial = 2,
		.active_serial = 1,
		.records = { { .scope = 10,
			       .serial = 1,
			       .generation = 13,
			       .phase = SE_SNAPSHOT_ACTIVE,
			       .count = 1,
			       .execution_class = mode,
			       .metadata = { .root_epochs = { 13 },
					     .policy_uids = { 1 },
					     .role_writers = 1,
					     .container_length = 1,
					     .container = "/" } } }
	};
	bindings[0].records[1] = (struct se_snapshot){
		.scope = 10,
		.serial = 2,
		.phase = SE_SNAPSHOT_PREPARED,
		.count = 1,
		.execution_class = mode == 1 ? 2 : 1,
		.tickets = { { .scope = 10,
			       .snapshot_serial = 2,
			       .object_generation = 1,
			       .phase = SE_TICKET_HELD } }
	};
	struct se_route_claim claim = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &claim) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	assert(se_op_exec_reader_begin(owner, &claim, &bindings[0], 0x1234,
				       invocation) == SE_OL_OK);
}

static struct se_route_claim claim(void)
{
	struct se_route_claim c = {};
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &c) == SE_ROUTE_OWNED);
	return c;
}

static int publish(int withdraw)
{
	if (withdraw)
		return se_route_withdraw_locked(&routes[0], &bindings[0]);
	int result = se_route_commit_preflight_locked(
		&routes[0], &bindings[0], 1, 2, routes[0].admission_serial);
	if (!result)
		se_route_commit_publish_locked(&routes[0], &bindings[0], 1);
	return result;
}

static void publication_case(__u32 mode, int withdraw, int latch)
{
	struct se_ol_payload_handle task = {};
	__u64 physical, invocation;
	prepare(mode, &task, &physical, &invocation);
	if (withdraw)
		bindings[0].records[1] = (struct se_snapshot){};
	struct se_source_mode_owner source = {};
	struct se_source_mode_token token = {};
	bpf_spin_lock(&routes[0].lock);
	struct se_route_claim c = claim();
	if (latch) {
		assert(!se_route_source_latch_locked(&routes[0], &c));
		assert(!se_route_source_latch_locked(&routes[0], &c));
		assert(routes[0].unresolved_sources == 1);
	} else {
		assert(!se_route_source_pin_acquire_locked(
			&routes[0], &c, physical, 17, &source, &token));
		assert(routes[0].source_pins == 1 && source.owned == 1);
	}
	assert(!se_route_release_locked(&routes[0], &c));
	bpf_spin_unlock(&routes[0].lock);
	/* Actual existing abort drops evaluator/reader ownership, not our
	 * independent protected physical-source barrier. */
	assert(se_op_exec_reader_abort_quarantined(&task, &bindings[0], 0x1234,
						   invocation) == SE_OL_OK);
	assert(bindings[0].records[0].claims == 0);
	bpf_spin_lock(&routes[0].lock);
	struct se_route_anchor before = routes[0];
	struct se_binding_snapshots before_b = bindings[0];
	assert(publish(withdraw));
	assert(!memcmp(&before, &routes[0], sizeof(before)));
	assert(!memcmp(&before_b, &bindings[0], sizeof(before_b)));
	/* Neither pin nor latch denies new Audit/Strict admission to last-good. */
	c = claim();
	assert(c.execution_class == mode);
	assert(!se_route_release_locked(&routes[0], &c));
	if (!latch) {
		/* Source terminal consumes the protected owner exactly once. */
		assert(!se_route_source_pin_release_locked(
			&routes[0], &source, &token, physical, 17));
		assert(se_route_source_pin_release_locked(
			&routes[0], &source, &token, physical, 17));
		assert(!publish(withdraw));
	} else {
		assert(routes[0].source_pins == 0);
		assert(routes[0].unresolved_sources == 1);
		assert(publish(withdraw));
	}
	bpf_spin_unlock(&routes[0].lock);
	assert(se_ol_payload_close(&task) == SE_OL_OK);
}

static void identity_cases(void)
{
	struct se_ol_payload_handle task = {};
	__u64 physical, invocation;
	prepare(1, &task, &physical, &invocation);
	struct se_source_mode_owner source = {};
	struct se_source_mode_token token = {};
	bpf_spin_lock(&routes[0].lock);
	struct se_route_claim c = claim();
	assert(!se_route_source_pin_acquire_locked(&routes[0], &c, physical, 17,
						   &source, &token));
	assert(!se_route_release_locked(&routes[0], &c));
	/* Admission changes its serial while the physical source stays live. */
	c = claim();
	assert(!se_route_release_locked(&routes[0], &c));
	for (int i = 0; i < 9; i++) {
		struct se_source_mode_token bad = token;
		switch (i) {
		case 0:
			bad.scope++;
			break;
		case 1:
			bad.generation++;
			break;
		case 2:
			bad.physical++;
			break;
		case 3:
			bad.source_sequence++;
			break;
		case 4:
			bad.pin_sequence++;
			break;
		case 5:
			bad.slot++;
			break;
		case 6:
			bad.incarnation++;
			break;
		case 7:
			bad.execution_class = 2;
			break;
		case 8:
			bad.reserved = 1;
			break;
		}
		struct se_route_anchor before = routes[0];
		struct se_source_mode_owner before_owner = source;
		assert(se_route_source_pin_release_locked(&routes[0], &source,
							  &bad, physical, 17));
		assert(!memcmp(&before, &routes[0], sizeof(before)));
		assert(!memcmp(&before_owner, &source, sizeof(source)));
	}
	assert(se_route_source_pin_release_locked(&routes[0], &source, &token,
						  physical + 1, 17));
	assert(se_route_source_pin_release_locked(&routes[0], &source, &token,
						  physical, 18));
	assert(!se_route_source_pin_release_locked(&routes[0], &source, &token,
						   physical, 17));
	struct se_source_mode_token old = token;
	c = claim();
	assert(!se_route_source_pin_acquire_locked(&routes[0], &c, physical, 18,
						   &source, &token));
	assert(token.pin_sequence > old.pin_sequence);
	assert(!se_route_release_locked(&routes[0], &c));
	assert(se_route_source_pin_release_locked(&routes[0], &source, &old,
						  physical, 17));
	assert(source.owned && routes[0].source_pins == 1);
	assert(!se_route_source_pin_release_locked(&routes[0], &source, &token,
						   physical, 18));
	c = claim();
	/* Bounded pin counter refuses overflow without consuming the claim. */
	routes[0].source_pins = (__u32)~0U;
	struct se_route_anchor saturated = routes[0];
	assert(se_route_source_pin_acquire_locked(&routes[0], &c, physical, 19,
						  &source, &token));
	assert(!memcmp(&saturated, &routes[0], sizeof(saturated)));
	assert(!source.owned && c.owned);
	routes[0].source_pins = 0;
	routes[0].next_source_pin = ~0ULL - 1;
	struct se_route_anchor before = routes[0];
	assert(se_route_source_pin_acquire_locked(&routes[0], &c, physical, 19,
						  &source, &token));
	assert(!memcmp(&before, &routes[0], sizeof(before)));
	assert(!se_route_source_latch_locked(&routes[0], &c));
	assert(!se_route_release_locked(&routes[0], &c));
	assert(se_route_source_latch_locked(&routes[0], &c));
	bpf_spin_unlock(&routes[0].lock);
	assert(se_op_exec_reader_abort_quarantined(&task, &bindings[0], 0x1234,
						   invocation) == SE_OL_OK);
	assert(se_ol_payload_close(&task) == SE_OL_OK);
}

static void lifecycle_guards(void)
{
	struct se_binding_snapshots b = { .scope = 10 };
	struct se_route_anchor a = { .scope = 10, .phase = SE_ROUTE_WITHDRAWN };
	a.source_pins = 1;
	assert(se_route_recycle_locked(&a, &b));
	a.source_pins = 0;
	a.unresolved_sources = 1;
	assert(se_route_recycle_locked(&a, &b));
	a.phase = SE_ROUTE_FREE;
	assert(se_route_open_locked(&a, 7, 10, 0));
	a.unresolved_sources = 0;
	a.source_pins = 1;
	assert(se_route_open_locked(&a, 7, 10, 0));
	a.source_pins = 0;
	a.phase = SE_ROUTE_WITHDRAWN;
	a.next_source_pin = 99;
	assert(!se_route_recycle_locked(&a, &b));
	assert(a.next_source_pin == 99);
	assert(!se_route_open_locked(&a, 8, 20, 0));
	assert(a.next_source_pin == 99);
}

int main(void)
{
	for (__u32 mode = 1; mode <= 2; mode++)
		for (int withdraw = 0; withdraw <= 1; withdraw++)
			for (int latch = 0; latch <= 1; latch++)
				publication_case(mode, withdraw, latch);
	identity_cases();
	lifecycle_guards();
	assert(!held && !lock_errors);
	puts("source mode route pin/latch: PASS");
	return 0;
}
