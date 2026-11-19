/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Host sequencing contract, not a kernel source-lifetime proof. The RED cases
 * abandon evaluation without calling any physical success/failure/death source.
 * They exercise the actual abort and publication helpers, not a model pin API.
 *
 * Follow-up tests require an implementation-owned mode-pin/latch interface:
 * - exact original-source release after terminal permits publication;
 * - stale/foreign/duplicate source release cannot decrement a successor pin;
 * - header insertion failure sets a constant-storage sticky original-route
 *   latch, preserving last-good and refusing publish/withdraw/recycle;
 * - neither timeout nor empty WORK count clears that latch.
 * Those APIs do not exist yet. Do not substitute test-side counters or make
 * their absence a passing implementation test. Headerless migration is a
 * separate architecture gate, not proved by these same-scope tests. */
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE 1
#define main opaque_locator_fixture_main
#include "../../full/test/host/opaque_locator_candidate.c"
#undef main

struct source_fixture {
	__u64 key, invocation;
	struct se_ol_payload_handle owner;
};

static void source_setup(struct source_fixture *f, __u32 execution_class)
{
	*f = (struct source_fixture){};
	f->key = seed_live_opaque_task_for_open();
	assert(se_ol_task_open(&f->key, &f->owner) == SE_OL_OK);
	/* Strict admission requires an already qualified task. */
	payloads[0].semantic.flags = SE_TASK_QUALIFIED;
	routes[0] =
		(struct se_route_anchor){ .incarnation = 1,
					  .cgroup_identity = 7,
					  .scope = 10,
					  .payload_slot = 0,
					  .payload_generation = 13,
					  .active_serial = 1,
					  .execution_class = execution_class,
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
			       .execution_class = execution_class,
			       .metadata = { .root_epochs = { 13 },
					     .policy_uids = { 1 },
					     .role_writers = 1,
					     .container_length = 1,
					     .container = "/" } } }
	};
	/* The opposite-class revision is ready, but must not replace the
	 * original classification while the original physical source lives. */
	bindings[0].records[1] = (struct se_snapshot){
		.scope = 10,
		.serial = 2,
		.phase = SE_SNAPSHOT_PREPARED,
		.count = 1,
		.execution_class = execution_class == 1 ? 2 : 1,
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
	assert(se_op_exec_reader_begin(&f->owner, &claim, &bindings[0], 0x1234,
				       &f->invocation) == SE_OL_OK);
	assert(f->invocation && !claim.owned &&
	       bindings[0].records[0].claims == 1);
}

static int publication_attempt(int withdraw)
{
	int result;
	bpf_spin_lock(&routes[0].lock);
	if (withdraw) {
		result = se_route_withdraw_locked(&routes[0], &bindings[0]);
	} else {
		result = se_route_commit_preflight_locked(
			&routes[0], &bindings[0], 1, 2,
			routes[0].admission_serial);
		if (!result)
			se_route_commit_publish_locked(&routes[0], &bindings[0],
						       1);
	}
	bpf_spin_unlock(&routes[0].lock);
	return result;
}

int main(int argc, char **argv)
{
	assert(argc == 3);
	__u32 execution_class = !strcmp(argv[2], "audit") ? 1 : 2;
	assert(execution_class == 1 || !strcmp(argv[2], "strict"));
	int withdraw = strstr(argv[1], "withdraw") != 0;
	struct source_fixture f;
	source_setup(&f, execution_class);
	/* A prepared candidate independently blocks withdrawal; remove it so
	 * these cases isolate protection of the original source. */
	if (withdraw)
		bindings[0].records[1] = (struct se_snapshot){};
	if (!strcmp(argv[1], "stale-release")) {
		struct se_task_state before = payloads[0].semantic;
		bpf_spin_lock(&routes[0].lock);
		assert(se_exec_reader_release_locked(
			&bindings[0], &payloads[0].semantic,
			f.owner.lease.cookie + 1, f.invocation));
		assert(se_exec_reader_release_locked(
			&bindings[0], &payloads[0].semantic,
			f.owner.lease.cookie, f.invocation + 1));
		bpf_spin_unlock(&routes[0].lock);
		assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
		assert(bindings[0].records[0].claims == 1);
		assert(publication_attempt(0));
	} else if (!strncmp(argv[1], "terminal-", 9)) {
		/* Existing reader-release control only: not the proposed new pin. */
		assert(se_op_exec_reader_finish_bounded(&f.owner, &bindings[0],
							0x1234, f.invocation,
							0) == SE_OL_OK);
		assert(!publication_attempt(withdraw));
		assert(withdraw ? routes[0].phase == SE_ROUTE_WITHDRAWN :
				  routes[0].execution_class != execution_class);
	} else {
		int abandoned = !strncmp(argv[1], "abort-", 6);
		if (abandoned) {
			assert(se_op_exec_reader_abort_quarantined(
				       &f.owner, &bindings[0], 0x1234,
				       f.invocation) == SE_OL_OK);
			assert(payloads[0].semantic.flags &
			       SE_TASK_QUARANTINED);
			assert(payloads[0].semantic.flags & SE_TASK_LIVE);
			assert(metas[0].phase == SE_OL_LIVE);
		}
		struct se_route_anchor route_before = routes[0];
		struct se_binding_snapshots binding_before = bindings[0];
		int result = publication_attempt(withdraw);
		if (!result) {
			fprintf(stderr,
				"RED: %s %s succeeded after evaluation "
				"abort without a physical exec terminal; original "
				"class=%u new class=%u phase=%u\n",
				argv[2],
				withdraw ? "withdrawal" :
					   "class-changing publication",
				execution_class, routes[0].execution_class,
				routes[0].phase);
			return 1;
		}
		assert(!memcmp(&route_before, &routes[0],
			       sizeof(route_before)));
		assert(!memcmp(&binding_before, &bindings[0],
			       sizeof(binding_before)));
	}
	assert(se_ol_payload_close(&f.owner) == SE_OL_OK);
	assert(!held && !lock_errors);
	puts("source mode publication contract: PASS");
	return 0;
}
