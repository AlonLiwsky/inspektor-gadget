/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0
 * Host map/observation model, NOT kernel lifetime or observation proof. Map
 * storage is fixed and single-threaded; full_observe supplies empty facts.
 * All admission, evaluator, ledger, transaction and release bodies are real.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
struct bpf_spin_lock {
	int held;
};
static int locks;
static void inheritance_lock_fault(struct bpf_spin_lock *l);
static void bpf_spin_lock(struct bpf_spin_lock *l)
{
	assert(!locks && !l->held);
	inheritance_lock_fault(l);
	locks = 1;
	l->held = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *l)
{
	assert(locks && l->held);
	locks = 0;
	l->held = 0;
}
#define SEC(x)
#define __uint(n, v) int n
#define __type(n, t) t *n
#define BPF_PROG(n, ...) n(__VA_ARGS__)
#define BPF_NOEXIST 1
#define SE_PROFILE_BINDINGS 2
#define SE_PROFILE_SLOTS_256 2
#define SE_PROFILE_SLOTS_1024 0
#define SE_PROFILE_SLOTS_4096 0
#define SE_PROFILE_SLOTS_16384 0
#define SE_PROFILE_TASKS 2
#define SE_PROFILE_SCRATCH 2
#define SE_PROFILE_ACCEPTED_UIDS 8
#define SE_PROFILE_TASK_QUOTA 1
#define SE_PROFILE_SCRATCH_QUOTA 1
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#ifdef TEST_SHARED_SCALAR_EVAL
#define ENFORCE_EXEC_SHARED_SCALAR_EVAL_CANDIDATE 1
#endif
struct task_struct {
	int unused;
};
struct linux_binprm {
	int unused;
};
static struct task_struct physical;
static __u64 cgroup = 7;
static void *bpf_map_lookup_elem(void *, const void *);
static int bpf_map_update_elem(void *, const void *, const void *, int);
static int bpf_map_delete_elem(void *, const void *);
static void *bpf_task_storage_get(void *m, void *t, void *v, int f)
{
	(void)m;
	(void)t;
	(void)v;
	(void)f;
	return 0;
}
static struct task_struct *bpf_get_current_task_btf(void)
{
	return &physical;
}
static __u64 bpf_get_current_cgroup_id(void)
{
	return cgroup;
}
struct se_policy_view;
static inline struct se_policy_view *full_shared_view(void);
#ifdef TEST_SHARED_SCALAR_EVAL
struct fm_global_token;
static inline struct se_policy_view *
se_shared_view_from_token(const struct fm_global_token *);
static inline const struct fm_blob *
se_shared_blob_from_token(unsigned int, unsigned long long, unsigned int);
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	se_shared_blob_from_token((slot), (cookie), (key))
#define SE_POLICY_VIEW(ctx) \
	se_shared_view_from_token((const struct fm_global_token *)(ctx))
#else
#define FM_GLOBAL_BLOB_LOOKUP(key) se_policy_data(full_shared_view(), key)
#define SE_POLICY_VIEW(ctx) ((void)(ctx), full_shared_view())
#endif
#include "shared_policy_lookup.h"
struct se_route_anchor;
static inline const __u64 *se_route_index_lookup(const __u64 *);
static inline struct se_route_anchor *se_route_anchor_lookup(const __u32 *);
#define SE_ROUTE_CAPACITY SE_PROFILE_BINDINGS
#define SE_ROUTE_INDEX_LOOKUP(k) se_route_index_lookup(k)
#define SE_ROUTE_ANCHOR_LOOKUP(k) se_route_anchor_lookup(k)
#include "shared_control.h"
struct observation {
	struct fe_facts facts;
	struct fe_scratch evaluator;
	char argument[4097];
};
static int observations;
static int full_observe(struct linux_binprm *b, struct observation *o)
{
	(void)b;
	assert(!locks);
	observations++;
	memset(o, 0, sizeof(*o));
	return 0;
}
#include "shared_kernel.h"
static struct se_route_anchor routes[2];
static struct se_shared_binding bindings[2];
static struct se_shared_object objects[2];
static struct se_arena_cell arena[512];
static struct se_task_state task, child_task;
static struct task_struct child_physical;
static struct se_invocation invocation;
static struct se_zero_task zero_task;
static struct se_zero_invocation zero_invocation;
static struct se_sequence sequence;
static __u64 locators[2], epoch = 13;
static int work_present, refuse_work, missing_object, missing_anchor;
static unsigned inheritance_fault, inheritance_parent_locks;
static struct se_task_state fault_parent_expected, fault_child_expected;
static void inheritance_lock_fault(struct bpf_spin_lock *l)
{
	if (!inheritance_fault || l != &task.lock ||
	    ++inheritance_parent_locks != 2)
		return;
	/* Change one identity after the actual parent snapshot, before revalidation. */
	switch (inheritance_fault) {
	case 1:
		task.physical_cookie++;
		break;
	case 2:
		task.scope_cookie++;
		break;
	case 3:
		task.flags ^= SE_TASK_VERIFIED;
		break;
	case 4:
		task.eligibility_version++;
		break;
	case 5:
		task.committed.version++;
		break;
	case 6:
		child_task.scope_cookie++;
		break;
	case 7:
		child_task.scope_slot++;
		break;
	case 8:
		child_task.flags ^= SE_TASK_VERIFIED;
		break;
	case 9:
		child_task.committed.version++;
		break;
	case 10:
		child_task.exec.owned = 1;
		break;
	case 11:
		child_task.reader.owned = 1;
		break;
	case 12:
		child_task.next_invocation++;
		break;
	}
	fault_parent_expected = task;
	fault_child_expected = child_task;
}
static struct se_node_config config = { .node_cookie = 1,
					.nonce = 2,
					.abi = 3,
					.profile_version = 1,
					.bindings = 2,
					.objects = 2,
					.cells = 512,
					.slots = { 2, 0, 0, 0 } };
static void *bpf_map_lookup_elem(void *map, const void *key)
{
	assert(!locks);
	if (map == &se_tasks)
		return *(__u64 *)key == (__u64)&physical       ? &task :
		       *(__u64 *)key == (__u64)&child_physical ? &child_task :
								 0;
	if (map == &se_invocations)
		return work_present ? &invocation : 0;
	if (map == &se_zero_tasks)
		return &zero_task;
	if (map == &se_zero_invocations)
		return &zero_invocation;
	if (map == &se_task_sequences)
		return &sequence;
	if (map == &se_configuration)
		return &config;
	if (map == &se_accepted_epochs)
		return ((const struct se_epoch_key *)key)->uid <= 2 ? &epoch :
								      0;
	if (map == &se_route_index) {
		__u64 k = *(__u64 *)key;
		return k == 7 ? &locators[0] : k == 8 ? &locators[1] : 0;
	}
	__u32 k = *(__u32 *)key;
	if (map == &se_routes)
		return k < 2 && !(missing_anchor && k == 1) ? &routes[k] : 0;
	if (map == &se_bindings)
		return k < 2 ? &bindings[k] : 0;
	if (map == &se_objects)
		return k < 2 && !missing_object ? &objects[k] : 0;
	if (map == &se_arena)
		return k < 512 ? &arena[k] : 0;
	return 0;
}
static int bpf_map_update_elem(void *map, const void *key, const void *value,
			       int flags)
{
	assert(!locks && flags == BPF_NOEXIST);
	(void)key;
	if (map != &se_invocations || refuse_work || work_present)
		return -1;
	memcpy(&invocation, value, sizeof(invocation));
	work_present = 1;
	return 0;
}
static int bpf_map_delete_elem(void *map, const void *key)
{
	assert(!locks);
	(void)key;
	if (map != &se_invocations || !work_present)
		return -1;
	work_present = 0;
	return 0;
}
static void setup(unsigned mode)
{
	memset(routes, 0, sizeof(routes));
	memset(bindings, 0, sizeof(bindings));
	memset(objects, 0, sizeof(objects));
	memset(arena, 0, sizeof(arena));
	memset(&task, 0, sizeof(task));
	work_present = refuse_work = missing_object = missing_anchor =
		observations = 0;
	cgroup = 7;
	task.flags = SE_TASK_QUALIFIED;
	task.physical_cookie = 99;
	task.scope_cookie = 11;
	task.eligibility_version = 1;
	task.committed.rows[0] = er_known_row(1, 13, 3);
	task.committed.rows[1] = er_known_row(2, 13, 9);
	task.committed.rows[2] =
		er_known_row(3, 22, 8); /* provisional, never accepted */
	for (unsigned i = 0; i < 2; i++) {
		routes[i] =
			(struct se_route_anchor){ .incarnation = 1,
						  .cgroup_identity = 7 + i,
						  .scope = 11 + i,
						  .payload_generation = 20,
						  .active_serial = 1,
						  .payload_slot = i,
						  .execution_class = mode,
						  .phase = SE_ROUTE_ACTIVE };
		locators[i] = se_route_locator(i, 1);
		bindings[i].state = (struct se_binding_snapshots){
			.scope = 11 + i, .generation = 20, .active_serial = 1
		};
		struct se_snapshot *s = &bindings[i].state.records[0];
		*s = (struct se_snapshot){ .scope = 11 + i,
					   .serial = 1,
					   .generation = 20,
					   .phase = SE_SNAPSHOT_ACTIVE,
					   .count = 1,
					   .execution_class = mode };
		s->metadata.root_epochs[0] = 13;
		s->metadata.policy_uids[0] = 1;
		s->metadata.role_writers = 1;
		s->metadata.container_length = 1;
		s->metadata.container[0] = 'c';
		s->tickets[0] =
			(struct se_pin_ticket){ .scope = 11 + i,
						.snapshot_serial = 1,
						.object_generation = 1,
						.object_slot = i,
						.phase = SE_TICKET_HELD };
		objects[i].state =
			(struct se_object){ .generation = 1,
					    .pins = 1,
					    .length = 12,
					    .phase = SE_OBJECT_READY };
		struct fe_header h = { .policies = 1,
				       .rule_base = 9,
				       .rules = 1 };
		struct fe_policy p = {
			.uid = 1, .root_role = 3, .fallback = 1, .mode = mode
		};
		struct fe_rule r = { .mode = mode,
				     .actor_image = -1,
				     .target_image = -1,
				     .stdin_pipe = -1,
				     .set_role = 7 };
		memcpy(&arena[i * 256], &h, sizeof(h));
		memcpy(&arena[i * 256 + 1], &p, sizeof(p));
		memcpy(&arena[i * 256 + 9], &r, sizeof(r));
	}
}
#ifdef TEST_SHARED_SCALAR_EVAL
static void scalar_evaluator_token_requires_exact_work(void)
{
	setup(1);
	invocation = (struct se_invocation){
		.scope = 11,
		.cookie = 42,
		.slot = 0,
	};
	invocation.view.ready = 1;
	invocation.view.scope_cookie = 11;
	work_present = 1;
	struct fm_global_token token = { .slot = 0, .cookie = 42 };
	assert(se_shared_view_from_token(&token) == &invocation.view);
	token.cookie++;
	assert(!se_shared_view_from_token(&token));
	token.cookie--;
	token.slot = 1;
	assert(!se_shared_view_from_token(&token));
	token.slot = 0;
	token.reserved = 1;
	assert(!se_shared_view_from_token(&token));
	token.reserved = 0;
	invocation.view.scope_cookie++;
	assert(!se_shared_view_from_token(&token));
	invocation.view.scope_cookie--;
	work_present = 0;
	assert(!se_shared_view_from_token(&token) && !locks);
}
#endif
static void refusal(int missing, int success, int denied, int finish_refusal)
{
	setup(1);
	struct linux_binprm b = {};
	struct er_state before = task.committed;
	refuse_work = missing == 0;
	missing_object = missing == 1;
	if (missing == 2)
		routes[0].scratch_used = SE_PROFILE_SCRATCH_QUOTA;
	assert(se_shared_check(&b, 0) == 0);
	assert(!observations);
	refuse_work = missing_object = 0;
	routes[0].scratch_used = 0;
	if (denied)
		assert(se_shared_check(&b, -13) == -13);
	refuse_work = finish_refusal;
	assert(!se_shared_finish(&physical, &b, success));
	if (success && !denied) {
		assert(task.committed.rows[0].knowledge == ER_ROLE_UNKNOWN);
		assert(task.committed.rows[0].role == 3);
	} else
		assert(!memcmp(&before, &task.committed, sizeof(before)));
	assert(!memcmp(&before.rows[1], &task.committed.rows[1],
		       sizeof(before.rows) - sizeof(before.rows[0])));
	assert(!routes[0].early_claims && !routes[0].scratch_used &&
	       !bindings[0].state.records[0].claims && !work_present);
}
static void migration(unsigned a, unsigned b, int admission, int prior)
{
	setup(a);
	struct linux_binprm exec = {};
	routes[1].execution_class = b;
	bindings[1].state.records[0].execution_class = b;
	struct er_state before = task.committed;
	assert(se_shared_check(&exec, 0) == 0);
	assert(observations == 1 && task.exec.owned && task.reader.owned);
	assert(bindings[0].state.records[0].claims == 1 &&
	       !routes[0].scratch_used);
	struct se_reader_owner reader = task.reader;
	__u64 reader_invocation = task.reader_invocation;
	cgroup = 8;
	if (admission == 1)
		routes[1].early_claims = ~0U;
	if (admission == 2)
		locators[1] = 0;
	unsigned early_b = routes[1].early_claims;
	long result = se_shared_check(&exec, prior);
	if (prior)
		assert(result == prior);
	else
		assert((result < 0) == (a == 2 || (b == 2 && admission != 2)));
	assert(!memcmp(&reader, &task.reader, sizeof(reader)));
	assert(task.reader_invocation == reader_invocation);
	assert(bindings[0].state.records[0].claims == 1 &&
	       !bindings[1].state.records[0].claims);
	assert(routes[1].early_claims == early_b && !routes[0].early_claims);
	assert(!routes[0].scratch_used && !routes[1].scratch_used &&
	       !work_present);
	assert(!se_shared_finish(&physical, &exec, 1));
	if (prior)
		assert(!memcmp(&before, &task.committed, sizeof(before)));
	assert(!task.exec.owned && !task.reader.owned &&
	       !bindings[0].state.records[0].claims);
	assert(!se_shared_finish(&physical, &exec, 1));
	assert(!bindings[0].state.records[0].claims &&
	       routes[1].early_claims == early_b);
}
static void recovery_invalid(void)
{
	setup(1);
	struct linux_binprm exec = {};
	assert(!se_shared_check(&exec, 0));
	struct se_reader_owner reader = task.reader;
	task.reader.token.execution_class =
		2; /* no class guessed from current route */
	cgroup = 8;
	assert(se_shared_check(&exec, 0) < 0);
	assert(bindings[0].state.records[0].claims == 1 &&
	       !routes[1].early_claims);
	assert(!routes[0].scratch_used && !routes[1].scratch_used);
	task.reader = reader;
	assert(!se_shared_finish(&physical, &exec, 0));
	assert(!task.reader.owned && !bindings[0].state.records[0].claims);
}
static void recovery_unpinned_reader(void)
{
	setup(1);
	struct linux_binprm exec = {};
	assert(!se_shared_check(&exec, 0));
	assert(task.reader.owned && bindings[0].state.records[0].claims == 1);
	/* A copied reader token cannot authorize the original catalogue once the
	 * binding's persistent claim has disappeared. Restore this deliberately
	 * corrupted host state only to exercise ordinary source cleanup. */
	bindings[0].state.records[0].claims = 0;
	int observed = observations;
	assert(se_shared_check(&exec, 0) < 0);
	assert(observations == observed && task.reader.owned);
	bindings[0].state.records[0].claims = 1;
	assert(!se_shared_finish(&physical, &exec, 0));
	assert(!task.reader.owned && !bindings[0].state.records[0].claims);
}
static void ingress_invariant(int continuing, int fault, int prior)
{
	setup(1);
	struct linux_binprm exec = {};
	if (continuing)
		assert(!se_shared_check(&exec, 0));
	int observed = observations;
	struct er_state before = task.committed;
	cgroup = 8;
	if (fault == 0)
		routes[1].execution_class = 0;
	if (fault == 1)
		locators[1] = se_route_locator(2, 1);
	if (fault == 2)
		missing_anchor = 1;
	if (fault == 3)
		routes[1].early_claims = ~0U;
	if (fault == 4)
		routes[1].reserved = 1;
	long result = se_shared_check(&exec, prior);
	if (prior)
		assert(result == prior);
	else if (fault < 3)
		assert(result < 0);
	else
		assert(result == 0);
	if (fault < 3 || prior || !continuing)
		assert(observations == observed);
	assert(!routes[0].early_claims && !routes[0].scratch_used &&
	       !routes[1].scratch_used);
	if (continuing) {
		assert(task.reader.owned &&
		       bindings[0].state.records[0].claims == 1);
		assert(!se_shared_finish(&physical, &exec, 0));
		assert(!task.reader.owned &&
		       !bindings[0].state.records[0].claims);
	}
	assert(!memcmp(&before, &task.committed, sizeof(before)));
}
static void fresh_movement(int destination)
{
	setup(2);
	struct linux_binprm exec = {};
	struct er_state before = task.committed;
	__u64 version = task.eligibility_version;
	cgroup = 8;
	routes[1].execution_class = 1;
	if (destination == 0)
		locators[1] = 0;
	if (destination == 1)
		routes[1].early_claims = ~0U;
	assert(se_shared_check(&exec, 0) == 0);
	assert((task.flags & SE_TASK_QUARANTINED) &&
	       task.eligibility_version > version);
	assert(!task.exec.owned && !task.reader.owned);
	assert(!memcmp(&before, &task.committed, sizeof(before)));
	cgroup = 7;
	assert(se_shared_check(&exec, 0) < 0);
	assert(!task.exec.owned && !task.reader.owned);
}
static void same_scope_withdrawal(void)
{
	setup(2);
	struct linux_binprm exec = {};
	struct se_task_state before = task;
	routes[0].phase = SE_ROUTE_WITHDRAWN;
	locators[0] = 0;
	assert(!se_shared_check(&exec, 0));
	assert(!memcmp(&before, &task, sizeof(task)));
}
static void same_scope_audit_fault(int reserved)
{
	setup(1);
	struct linux_binprm exec = {};
	struct er_state before = task.committed;
	__u64 version = task.eligibility_version;
	if (reserved)
		routes[0].reserved = 1;
	else
		routes[0].early_claims = ~0U;
	assert(!se_shared_check(&exec, 0));
	assert(!se_shared_finish(&physical, &exec, 1));
	assert((task.flags & SE_TASK_QUARANTINED) &&
	       task.eligibility_version > version);
	assert(!memcmp(&before, &task.committed, sizeof(before)));
	routes[0].reserved = 0;
	routes[0].early_claims = 0;
	/* Restored admission cannot export the stale role as qualified authority. */
	routes[0].execution_class = 2;
	bindings[0].state.records[0].execution_class = 2;
	assert(se_shared_check(&exec, 0) < 0);
	assert(!task.exec.owned && !task.reader.owned);
}
/* Actual inheritance body with the existing fixed host-map model. No birth,
 * kernel task lifetime or successful-child qualification is asserted here. */
static void child_high_row_preflight(void)
{
	const unsigned positions[] = { 0, 7, 15 };
	for (unsigned pos = 0; pos < sizeof(positions) / sizeof(positions[0]);
	     pos++) {
		for (int field = 0; field < 7; field++) {
			setup(1);
			child_task =
				(struct se_task_state){ .flags = SE_TASK_LIVE,
							.physical_cookie = 100,
							.scope_cookie = 11,
							.scope_slot = 0 };
			struct er_row *last =
				&child_task.committed.rows[positions[pos]];
			if (field == 1)
				last->uid = 1;
			if (field == 2)
				last->epoch = 13;
			if (field == 3)
				last->role = 3;
			if (field == 4)
				last->knowledge = ER_ROLE_KNOWN;
			if (field == 5)
				last->reserved = 1;
			if (field == 6)
				*last = er_known_row(3, 22,
						     8); /* provisional */
			struct se_task_state before = child_task,
					     parent_before = task;
			struct se_route_claim claim = {};
			assert(se_route_admit(7, &claim) == SE_ROUTE_OWNED);
			int result = se_inherit_child((__u64)&physical,
						      (__u64)&child_physical,
						      &claim, 0);
			assert(result == (field ? -1 : 0));
			assert(!memcmp(&task, &parent_before, sizeof(task)));
			if (field)
				assert(!memcmp(&child_task, &before,
					       sizeof(child_task)));
			else {
				assert(child_task.committed.version == 1 &&
				       child_task.flags == SE_TASK_LIVE);
				assert(!memcmp(child_task.committed.rows,
					       task.committed.rows,
					       2 * sizeof(struct er_row)));
				for (unsigned j = 2; j < 16; j++) {
					struct er_row empty = {};
					assert(!memcmp(
						&child_task.committed.rows[j],
						&empty, sizeof(empty)));
				}
			}
			se_early_release(&claim);
			assert(!routes[0].early_claims &&
			       !routes[0].scratch_used && !work_present &&
			       !locks);
		}
	}
}
static void child_identity_revalidation(void)
{
	for (unsigned fault = 1; fault <= 12; fault++) {
		setup(1);
		child_task = (struct se_task_state){ .flags = SE_TASK_LIVE,
						     .physical_cookie = 100,
						     .scope_cookie = 11,
						     .scope_slot = 0 };
		inheritance_fault = fault;
		inheritance_parent_locks = 0;
		struct se_route_claim claim = {};
		assert(se_route_admit(7, &claim) == SE_ROUTE_OWNED);
		assert(se_inherit_child((__u64)&physical,
					(__u64)&child_physical, &claim,
					0) == -1);
		assert(inheritance_parent_locks == 2);
		assert(!memcmp(&task, &fault_parent_expected, sizeof(task)));
		assert(!memcmp(&child_task, &fault_child_expected,
			       sizeof(child_task)));
		assert(!work_present && !routes[0].scratch_used && !locks);
		se_early_release(&claim);
		assert(!claim.owned && !routes[0].early_claims && !locks);
		inheritance_fault = 0;
	}
}
static void child_snapshot_preflight_refusal(void)
{
	for (unsigned fault = 0; fault < 5; fault++) {
		setup(1);
		child_task = (struct se_task_state){ .flags = SE_TASK_LIVE,
						     .physical_cookie = 100,
						     .scope_cookie = 11,
						     .scope_slot = 0 };
		struct se_task_state before = child_task;
		struct se_route_claim claim = {};
		assert(se_route_admit(7, &claim) == SE_ROUTE_OWNED);
		struct se_snapshot *snapshot = &bindings[0].state.records[0];
		switch (fault) {
		case 0:
			snapshot->scope++;
			break;
		case 1:
			snapshot->serial++;
			break;
		case 2:
			snapshot->generation++;
			break;
		case 3:
			snapshot->metadata.root_epochs[0]++;
			break;
		case 4:
			snapshot->metadata.policy_uids[0] = 99;
			break;
		}
		assert(se_inherit_child((__u64)&physical,
					(__u64)&child_physical, &claim,
					0) == -1);
		assert(!memcmp(&child_task, &before, sizeof(before)));
		assert(!work_present && !routes[0].scratch_used && !locks);
		se_early_release(&claim);
		assert(!claim.owned && !routes[0].early_claims);
	}
}
static void policy_view_preflight_refusal(void)
{
	for (unsigned fault = 0; fault < 8; fault++) {
		setup(1);
		struct se_invocation work = { .scope = 11 };
		struct se_snapshot *snapshot = &bindings[0].state.records[0];
		/* Preparation is only legal after the reader retained this record.
		 * Otherwise each malformed-ticket case would fail for the wrong
		 * reason and cease to cover its intended preflight. */
		snapshot->claims = 1;
		switch (fault) {
		case 0:
			snapshot->tickets[0].scope++;
			break;
		case 1:
			snapshot->tickets[0].snapshot_serial++;
			break;
		case 2:
			snapshot->tickets[0].position++;
			break;
		case 3:
			snapshot->tickets[0].phase = 0;
			break;
		case 4:
			objects[0].state.generation++;
			break;
		case 5:
			missing_object = 1;
			break;
		case 6:
			snapshot->metadata.policy_uids[0] = 99;
			break;
		case 7:
			snapshot->claims = 0;
			break;
		}
		assert(se_prepare_view(&work, snapshot, 20) == -1);
		assert(!locks);
	}
	setup(1);
	struct se_invocation work = { .scope = 11 };
	bindings[0].state.records[0].claims = 1;
	assert(se_prepare_view(&work, &bindings[0].state.records[0], 20) == 0);
	assert(work.view.ready && work.view.scope_cookie == 11 &&
	       work.view.policies[0].uid == 1 && work.view.refs[0].slot == 0);
}
int main(void)
{
#ifdef TEST_SHARED_SCALAR_EVAL
	scalar_evaluator_token_requires_exact_work();
#endif
	child_high_row_preflight();
	child_identity_revalidation();
	child_snapshot_preflight_refusal();
	policy_view_preflight_refusal();
	for (int missing = 0; missing < 3; missing++)
		for (int success = 0; success < 2; success++)
			for (int denied = 0; denied < 2; denied++)
				for (int finish_refusal = 0; finish_refusal < 2;
				     finish_refusal++)
					refusal(missing, success, denied,
						finish_refusal);
	for (unsigned a = 1; a <= 2; a++)
		for (unsigned b = 1; b <= 2; b++)
			for (int admission = 0; admission < 3; admission++)
				for (int prior = 0; prior < 2; prior++)
					migration(a, b, admission,
						  prior ? -13 : 0);
	recovery_invalid();
	recovery_unpinned_reader();
	same_scope_audit_fault(0);
	same_scope_audit_fault(1);
	same_scope_withdrawal();
	for (int destination = 0; destination < 2; destination++)
		fresh_movement(destination);
	for (int continuing = 0; continuing < 2; continuing++)
		for (int fault = 0; fault < 5; fault++)
			for (int prior = 0; prior < 2; prior++)
				ingress_invariant(continuing, fault,
						  prior ? -13 : 0);
	puts("actual shared kernel entry regression passed");
	return 0;
}
