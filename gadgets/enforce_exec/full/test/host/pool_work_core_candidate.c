#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint8_t __u8;
struct bpf_spin_lock {
	__u32 value;
};
static void bpf_spin_lock(struct bpf_spin_lock *l)
{
	assert(l->value == 0);
	l->value = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *l)
{
	assert(l->value == 1);
	l->value = 0;
}
#define __uint(n, v) int(*n)[v]
#define __type(n, v) v *n
#define SEC(x) __attribute__((section(x)))
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_F_RDONLY (1U << 3)
#define BPF_F_RDONLY_PROG (1U << 7)
#define BPF_ANY 0
#define SE_PROFILE_TASKS 8
#define SE_PROFILE_SCRATCH 2
#define SE_PROFILE_BINDINGS 1
#define SE_PROFILE_TASK_QUOTA 8
#define SE_PROFILE_SCRATCH_QUOTA 2
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#define ENFORCE_EXEC_SHARED_NODE 1
#define ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY 1
#define ENFORCE_EXEC_POOL_DEVELOPMENT 1
#define ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE 1
#define SE_TASK_LIVE 4u
struct er_state {
	_Alignas(8) char bytes[520];
};
struct se_task_stage {
	_Alignas(8) char bytes[64];
};
struct se_reader_owner {
	_Alignas(8) char bytes[48];
};
struct se_exec_transaction {
	_Alignas(8) char bytes[272];
};
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
struct se_policy_view {
	_Alignas(8) char bytes[904];
};
struct se_exec_work {
	_Alignas(8) char bytes[1704];
};
struct er_work {
	_Alignas(8) char bytes[536];
};
struct observation {
	_Alignas(8) char bytes[16008];
};
struct se_invocation {
	__u64 scope, cookie, sequence;
	__u32 slot, reserved;
	struct se_policy_view view;
	struct se_exec_work history;
	struct er_work inherited;
	struct observation observation;
};
#include "shared_pool_abi_candidate.h"
#define SE_ROUTE_ACTIVE 2
#define SE_ROUTE_WITHDRAWN 3
struct se_route_anchor {
	struct bpf_spin_lock lock;
	__u32 incarnation;
	__u64 cgroup_identity, scope, payload_generation, active_serial,
		admission_serial;
	__u32 payload_slot, active_record, execution_class, phase, early_claims,
		reserved, tasks_used, scratch_used, inode_refs, inode_reserved;
};
_Static_assert(sizeof(struct se_route_anchor) == 88, "route geometry");
static struct se_pool_work_payload payloads[SE_POOL_W];
static struct se_route_anchor route;
static struct se_pool_bitmap bits;
static struct se_pool_charge charges[SE_POOL_W];
static struct se_pool_work_meta works[SE_POOL_W];
static struct se_pool_task_meta owner;
static int zero_fail;
static int test_zero(__u32 slot, const struct se_pool_work_payload *zero)
{
	assert(slot < SE_POOL_W);
	assert(!route.lock.value && !works[slot].lock.value &&
	       !owner.lock.value);
	assert(works[slot].phase == 5 && works[slot].active_leases == 0);
	assert(works[slot].cleanup_done & 1);
	bpf_spin_lock(&owner.lock);
	assert(works[slot].owner_ref_held == 0);
	bpf_spin_unlock(&owner.lock);
	assert(charges[slot].state == 2 && route.scratch_used > 0);
	assert(bits.words[SE_POOL_TASK_WORDS] & (1ULL << slot));
	if (zero_fail) {
		zero_fail = 0;
		return -1;
	}
	payloads[slot] = *zero;
	return 0;
}
#define SE_PW_ZERO_PAYLOAD(slot, zero) test_zero((slot), (zero))
#include "shared_pool_work_core.h"
static struct se_pool_sequence seq;
static struct se_pool_work_payload zero_template;
static struct se_pw_task_lease lease;
static int semantic_zero_fail;
static struct se_route_anchor *se_route_anchor_lookup(const __u32 *key)
{
	assert(!route.lock.value && key);
	return *key == 0 ? &route : 0;
}
static void *bpf_map_lookup_elem(const void *map, const void *key)
{
	assert(!route.lock.value && !owner.lock.value);
	assert(key);
	__u32 slot = *(__u32 *)key;
	if (map == &se_pool_task_meta)
		return slot == 0 ? &owner : 0;
	if (map == &se_pool_bitmaps)
		return slot == 0 ? &bits : 0;
	if (map == &se_pool_sequence)
		return slot == 0 ? &seq : 0;
	if (map == &se_pool_work_meta)
		return slot < SE_POOL_W ? &works[slot] : 0;
	if (map == &se_pool_charges)
		return slot >= SE_POOL_T && slot < SE_POOL_T + SE_POOL_W ?
			       &charges[slot - SE_POOL_T] :
			       0;
	if (map == &se_pool_work_payload)
		return slot < SE_POOL_W ? &payloads[slot] : 0;
	if (map == &se_pool_work_zero)
		return slot == 0 ? &zero_template : 0;
	assert(0);
	return 0;
}
static long bpf_map_update_elem(const void *map, const void *key,
				const void *value, __u64 flags)
{
	assert(!route.lock.value && !owner.lock.value && key && value);
	__u32 slot = *(__u32 *)key;
	assert(map == &se_pool_work_payload && slot < SE_POOL_W &&
	       value == &zero_template && flags == BPF_ANY);
	if (semantic_zero_fail) {
		semantic_zero_fail = 0;
		return -1;
	}
	payloads[slot] = *(const struct se_pool_work_payload *)value;
	return 0;
}
#include "shared_pool_work_semantic_candidate.h"
static void init(void)
{
	memset(&route, 0, sizeof(route));
	memset(&bits, 0, sizeof(bits));
	memset(charges, 0, sizeof(charges));
	memset(works, 0, sizeof(works));
	memset(&owner, 0, sizeof(owner));
	memset(&seq, 0, sizeof(seq));
	memset(payloads, 0, sizeof(payloads));
	route.scope = 7;
	route.incarnation = 3;
	route.phase = SE_ROUTE_ACTIVE;
	owner.phase = 4;
	owner.cookie = 11;
	owner.physical_address = 0x1000;
	owner.account_scope = 7;
	owner.account_incarnation = 3;
	owner.active_leases = 1;
	lease = (struct se_pw_task_lease){ .cookie = 11,
					   .physical_address = 0x1000,
					   .scope = 7,
					   .account_incarnation = 3,
					   .held = 1 };
	semantic_zero_fail = 0;
}
static struct se_pw_ticket begin(void)
{
	__u32 slot = 99;
	assert(se_pw_select(&route, &bits, &lease, &slot) == SE_PW_OK);
	struct se_pool_work_refs refs = {};
	assert(se_pool_work_prefetch(&lease, slot, &refs) == SE_PW_OK);
	assert(refs.route == &route && refs.bitmap == &bits &&
	       refs.charge == &charges[slot] && refs.sequence == &seq &&
	       refs.task == &owner && refs.work == &works[slot] &&
	       refs.payload == &payloads[slot]);
	struct se_pw_ticket t = {};
	assert(se_pw_begin(refs.route, refs.bitmap, refs.charge, refs.sequence,
			   refs.task, refs.work, refs.payload,
			   refs.previous_task, &lease, slot, &t) == SE_PW_OK);
	assert(charges[slot].state == SE_PW_CH_BUILDING);
	assert(route.scratch_used == 1 || route.scratch_used == 2);
	return t;
}
static void attach_commit(struct se_pw_ticket *t)
{
	assert(se_pw_attach(&owner, &works[t->slot], &lease, t) == SE_PW_OK);
	struct se_pool_work_payload *payload = &payloads[t->slot];
	assert(se_pool_work_semantic_initialize(&owner, &works[t->slot],
						&charges[t->slot], &payload,
						&lease, t) == SE_PW_OK);
	assert(payload == &payloads[t->slot] &&
	       payload->semantic.scope == t->scope &&
	       payload->semantic.cookie == t->cookie &&
	       payload->semantic.sequence ==
		       works[t->slot].invocation_sequence);
	assert(se_pw_commit(&works[t->slot], &route, &bits, &charges[t->slot],
			    t) == SE_PW_OK);
	assert(charges[t->slot].state == SE_PW_CH_OWNED);
	assert(se_pool_work_semantic_active(&owner, &lease, &works[t->slot],
					    payload, t, &route,
					    &charges[t->slot]) == SE_PW_OK);
}
static void reap(__u32 slot)
{
	int r = se_pw_visit(&route, &bits, &charges[slot], &works[slot], &owner,
			    &zero_template, slot);
	assert(r == SE_PW_RETURNED);
	assert(charges[slot].state == SE_PW_CH_FREE);
	assert(!charges[slot].current_cookie);
	assert(works[slot].phase == SE_PW_FREE_PHASE);
	assert(!memcmp(&payloads[slot], &zero_template, sizeof(zero_template)));
}
static void churn(void)
{
	init();
	__u64 last = 0;
	for (int i = 0; i < 5000; i++) {
		struct se_pw_ticket t = begin();
		assert(t.cookie > last);
		last = t.cookie;
		attach_commit(&t);
		struct se_pool_work_semantic_handle handle = {};
		assert(se_pool_work_semantic_open(
			       &owner, &lease, &works[t.slot],
			       &payloads[t.slot], &t, &route, &charges[t.slot],
			       &handle) == SE_PW_OK);
		assert(handle.held &&
		       handle.payload->semantic.cookie == t.cookie);
		assert(se_pool_work_semantic_done(&handle) == SE_PW_OK);
		assert(!handle.held && !handle.payload && !t.held);
		assert(owner.work_refs == 1 && !owner.current_work_owned);
		reap(t.slot);
		assert(!owner.work_refs && !route.scratch_used &&
		       !bits.words[SE_POOL_TASK_WORDS]);
	}
	assert(seq.next == 5000);
}
static void old_retained_new_starts(void)
{
	init();
	struct se_pw_ticket old = begin();
	attach_commit(&old);
	__u32 old_slot = old.slot;
	__u64 old_cookie = old.cookie;
	assert(se_pw_done(&owner, &works[old_slot], &lease, &old) == SE_PW_OK);
	struct se_pw_ticket newer = begin();
	assert(newer.slot != old_slot);
	attach_commit(&newer);
	assert(owner.work_refs == 2);
	__u32 refused = 99;
	assert(se_pw_select(&route, &bits, &lease, &refused) == SE_PW_CAPACITY);
	assert(owner.current_work_cookie == newer.cookie);
	reap(old_slot);
	assert(owner.work_refs == 1);
	assert(owner.current_work_cookie == newer.cookie &&
	       owner.current_work_owned);
	assert(se_pw_done(&owner, &works[newer.slot], &lease, &newer) ==
	       SE_PW_OK);
	reap(newer.slot);
	assert(!owner.work_refs && !route.scratch_used);
	assert(charges[old_slot].last_returned_cookie == old_cookie);
}
static void failed_construction(void)
{
	init();
	struct se_pw_ticket t = begin();
	assert(se_pw_abort(&owner, &works[t.slot], &route, &bits,
			   &charges[t.slot], &lease, &t) == SE_PW_OK);
	assert(charges[t.slot].state == SE_PW_CH_OWNED && !owner.work_refs);
	reap(t.slot);
	t = begin();
	assert(se_pw_attach(&owner, &works[t.slot], &lease, &t) == SE_PW_OK);
	assert(se_pw_abort(&owner, &works[t.slot], &route, &bits,
			   &charges[t.slot], &lease, &t) == SE_PW_OK);
	assert(owner.work_refs == 1 && !owner.current_work_owned);
	reap(t.slot);
	assert(!owner.work_refs);
	/* Contradictory allegedly FREE metadata retains its charged bit. */
	works[0].active_leases = 1;
	t = (struct se_pw_ticket){};
	assert(se_pw_begin(&route, &bits, &charges[0], &seq, &owner, &works[0],
			   &payloads[0], &owner, &lease, 0, &t) == SE_PW_FAULT);
	assert(charges[0].state == SE_PW_CH_FAULT_HELD &&
	       route.scratch_used == 1);
}
static void retry_and_aba(void)
{
	init();
	struct se_pw_ticket t = begin();
	attach_commit(&t);
	assert(se_pw_done(&owner, &works[t.slot], &lease, &t) == SE_PW_OK);
	__u32 slot = t.slot;
	__u64 old = t.cookie;
	zero_fail = 1;
	assert(se_pw_visit(&route, &bits, &charges[slot], &works[slot], &owner,
			   &zero_template, slot) == SE_PW_PENDING);
	assert(owner.work_refs == 0 && charges[slot].state == SE_PW_CH_OWNED);
	assert(works[slot].cleanup_done == SE_PW_OWNER_RELEASED);
	assert(payloads[slot].semantic.scope !=
	       0); /* zero helper failed; payload retained */
	reap(slot);
	t = begin();
	assert(t.cookie != old && t.slot == slot);
	struct se_pw_ticket stale = t;
	stale.cookie = old;
	assert(se_pw_promote(&route, &bits, &charges[slot], &stale) ==
	       SE_PW_STALE);
	assert(charges[slot].current_cookie == t.cookie &&
	       charges[slot].state == SE_PW_CH_BUILDING);
	assert(!route.reserved);
	assert(se_pw_abort(&owner, &works[slot], &route, &bits, &charges[slot],
			   &lease, &t) == SE_PW_OK);
	reap(slot);
}
static void stale_owner_lease(void)
{
	init();
	struct se_pw_task_lease stale = lease;
	stale.cookie++;
	__u32 slot = 99;
	assert(se_pw_select(&route, &bits, &stale, &slot) == SE_PW_OK);
	struct se_pw_ticket t = {};
	assert(se_pw_begin(&route, &bits, &charges[slot], &seq, &owner,
			   &works[slot], &payloads[slot], &owner, &stale, slot,
			   &t) == SE_PW_STALE);
	assert(!route.scratch_used && charges[slot].state == SE_PW_CH_FREE);
}
static void resume_refund_tail(void)
{
	for (int meta_free = 0; meta_free < 2; meta_free++) {
		init();
		struct se_pw_ticket t = begin();
		attach_commit(&t);
		__u32 s = t.slot;
		assert(se_pw_done(&owner, &works[s], &lease, &t) == SE_PW_OK);
		works[s].phase = SE_PW_CLEANING;
		assert(se_pw_release_owner(&owner, &works[s]) == SE_PW_OK);
		assert(!owner.work_refs &&
		       works[s].cleanup_done == SE_PW_OWNER_RELEASED);
		payloads[s] = zero_template;
		works[s].cleanup_done |= SE_PW_PAYLOAD_ZERO;
		works[s].phase = meta_free ? SE_PW_FREE_PHASE :
					     SE_PW_REFUND_PENDING;
		charges[s].state = SE_PW_CH_RETURN_READY;
		route.phase = SE_ROUTE_WITHDRAWN;
		reap(s);
		assert(se_pw_visit(&route, &bits, &charges[s], &works[s],
				   &owner, &zero_template, s) == SE_PW_FREE);
		assert(!route.scratch_used &&
		       charges[s].last_returned_cookie == t.cookie);
	}
}
static void contradictory_free_begin(void)
{
	init();
	works[0].owner_ref_held = 1;
	owner.work_refs = 1;
	__u32 slot = 99;
	assert(se_pw_select(&route, &bits, &lease, &slot) == SE_PW_OK &&
	       slot == 0);
	struct se_pw_ticket t = {};
	assert(se_pw_begin(&route, &bits, &charges[slot], &seq, &owner,
			   &works[slot], &payloads[slot], &owner, &lease, slot,
			   &t) == SE_PW_FAULT);
	assert(charges[slot].state == SE_PW_CH_FAULT_HELD && route.reserved);
	assert(route.scratch_used == 1 && (bits.words[SE_POOL_TASK_WORDS] & 1));
	assert(works[slot].phase == SE_PW_FREE_PHASE &&
	       works[slot].owner_ref_held == 1);
	assert(owner.work_refs == 1 && !t.held);
	/* Reused metadata requires the prefetched prior exact TASK slot. */
	init();
	t = begin();
	attach_commit(&t);
	assert(se_pw_done(&owner, &works[t.slot], &lease, &t) == SE_PW_OK);
	reap(t.slot);
	struct se_pool_task_meta wrong_task = owner;
	wrong_task.slot = 1;
	t = (struct se_pw_ticket){};
	assert(se_pw_begin(&route, &bits, &charges[0], &seq, &owner, &works[0],
			   &payloads[0], &wrong_task, &lease, 0,
			   &t) == SE_PW_FAULT);
	assert(charges[0].state == SE_PW_CH_FAULT_HELD &&
	       route.scratch_used == 1);
	assert(works[0].phase == SE_PW_FREE_PHASE && !t.held);
}
static void contradictory_cleanup_visit(void)
{
	const __u32 phases[] = { SE_PW_CLEANING, SE_PW_REFUND_PENDING,
				 SE_PW_FREE_PHASE };
	for (__u32 i = 0; i < 3; i++) {
		init();
		struct se_pw_ticket t = begin();
		attach_commit(&t);
		__u32 slot = t.slot;
		assert(se_pw_done(&owner, &works[slot], &lease, &t) ==
		       SE_PW_OK);
		works[slot].phase = phases[i];
		works[slot].cleanup_done = i ? 3 : SE_PW_OWNER_RELEASED;
		if (phases[i] == SE_PW_FREE_PHASE)
			charges[slot].state = SE_PW_CH_RETURN_READY;
		assert(se_pw_visit(&route, &bits, &charges[slot], &works[slot],
				   &owner, &zero_template,
				   slot) == SE_PW_FAULT);
		assert(charges[slot].state == SE_PW_CH_FAULT_HELD &&
		       route.reserved);
		assert(route.scratch_used == 1 &&
		       (bits.words[SE_POOL_TASK_WORDS] & 1));
		assert(works[slot].phase == phases[i] &&
		       works[slot].owner_ref_held == 1);
		assert(owner.work_refs == 1);
	}
	/* A zero TASK count cannot justify a held owner flag. */
	init();
	struct se_pw_ticket t = begin();
	attach_commit(&t);
	__u32 slot = t.slot;
	assert(se_pw_done(&owner, &works[slot], &lease, &t) == SE_PW_OK);
	works[slot].phase = SE_PW_CLEANING;
	owner.work_refs = 0;
	assert(se_pw_visit(&route, &bits, &charges[slot], &works[slot], &owner,
			   &zero_template, slot) == SE_PW_FAULT);
	assert(charges[slot].state == SE_PW_CH_FAULT_HELD &&
	       route.scratch_used == 1);
	assert(works[slot].owner_ref_held == 1);
	/* Already-FREE charge remains diagnostically reserved on contradiction. */
	init();
	t = begin();
	attach_commit(&t);
	slot = t.slot;
	assert(se_pw_done(&owner, &works[slot], &lease, &t) == SE_PW_OK);
	reap(slot);
	works[slot].owner_ref_held = 1;
	owner.work_refs = 1;
	assert(se_pw_visit(&route, &bits, &charges[slot], &works[slot], &owner,
			   &zero_template, slot) == SE_PW_FAULT);
	assert(route.reserved && charges[slot].state == SE_PW_CH_FREE);
	assert(works[slot].owner_ref_held == 1 && owner.work_refs == 1);
}
static void sequence_rollback(void)
{
	for (__u64 higher = 0; higher <= 1; higher++) {
		init();
		struct se_pw_ticket t = begin();
		attach_commit(&t);
		__u32 slot = t.slot;
		__u64 prior = t.cookie;
		assert(se_pw_done(&owner, &works[slot], &lease, &t) ==
		       SE_PW_OK);
		reap(slot);
		charges[slot].last_returned_cookie = prior + higher;
		seq.next = 0;
		__u32 selected = 99;
		assert(se_pw_select(&route, &bits, &lease, &selected) ==
			       SE_PW_OK &&
		       selected == slot);
		t = (struct se_pw_ticket){};
		assert(se_pw_begin(&route, &bits, &charges[slot], &seq, &owner,
				   &works[slot], &payloads[slot], &owner,
				   &lease, slot, &t) == SE_PW_FAULT);
		assert(seq.next == prior && !t.held && route.reserved);
		assert(charges[slot].state == SE_PW_CH_FREE &&
		       charges[slot].last_returned_cookie == prior + higher);
		assert(!route.scratch_used &&
		       !(bits.words[SE_POOL_TASK_WORDS] & 1));
	}
}
static void task_recycle_after_work_return(void)
{
	init();
	struct se_pw_ticket old = begin();
	attach_commit(&old);
	__u32 slot = old.slot;
	assert(se_pw_done(&owner, &works[slot], &lease, &old) == SE_PW_OK);
	reap(slot);
	assert(!owner.work_refs && !works[slot].owner_ref_held);
	__u64 old_cookie = works[slot].owner_task_cookie;
	/* The TASK peer may recycle a FREE slot once its WORK refs are zero. */
	owner.cookie = 12;
	owner.physical_address = 0x2000;
	owner.next_work_sequence = 0;
	lease.cookie = 12;
	lease.physical_address = 0x2000;
	assert(works[slot].owner_task_cookie == old_cookie &&
	       old_cookie != owner.cookie);
	__u32 selected = 99;
	assert(se_pw_select(&route, &bits, &lease, &selected) == SE_PW_OK &&
	       selected == slot);
	struct se_pw_ticket next = {};
	assert(se_pw_begin(&route, &bits, &charges[slot], &seq, &owner,
			   &works[slot], &payloads[slot], &owner, &lease, slot,
			   &next) == SE_PW_OK);
	assert(!route.reserved && charges[slot].state == SE_PW_CH_BUILDING);
	assert(works[slot].owner_task_cookie == owner.cookie);
	attach_commit(&next);
	assert(se_pw_done(&owner, &works[slot], &lease, &next) == SE_PW_OK);
	reap(slot);
	assert(!route.reserved && !route.scratch_used && !owner.work_refs);
}
static void missing_prior_identity(void)
{
	for (int field = 0; field < 12; field++) {
		init();
		struct se_pw_ticket t = begin();
		attach_commit(&t);
		__u32 slot = t.slot;
		assert(se_pw_done(&owner, &works[slot], &lease, &t) ==
		       SE_PW_OK);
		reap(slot);
		switch (field) {
		case 0:
			works[slot].owner_task_cookie = 0;
			break;
		case 1:
			works[slot].owner_task_address = 0;
			break;
		case 2:
			works[slot].account_scope = 0;
			break;
		case 3:
			works[slot].account_incarnation = 0;
			break;
		case 4:
			works[slot].invocation_sequence = 0;
			break;
		case 5:
			works[slot].owner_task_cookie = SE_PW_U64_LIMIT + 1;
			break;
		case 6:
			works[slot].account_scope = SE_PW_U64_LIMIT + 1;
			break;
		case 7:
			works[slot].invocation_sequence = SE_PW_U64_LIMIT + 1;
			break;
		case 8:
			works[slot].owner_task_slot = SE_POOL_T;
			break;
		case 9:
			works[slot].account_slot = SE_POOL_B;
			break;
		case 10:
			works[slot].cleanup_done = SE_PW_PAYLOAD_ZERO;
			break;
		default:
			works[slot].cookie++;
			break;
		}
		struct se_pool_work_meta before = works[slot];
		t = (struct se_pw_ticket){};
		assert(se_pw_begin(&route, &bits, &charges[slot], &seq, &owner,
				   &works[slot], &payloads[slot], &owner,
				   &lease, slot, &t) == SE_PW_FAULT);
		assert(charges[slot].state == SE_PW_CH_FAULT_HELD &&
		       route.reserved);
		assert(route.scratch_used == 1 &&
		       (bits.words[SE_POOL_TASK_WORDS] & (1ULL << slot)));
		assert(works[slot].phase == SE_PW_FREE_PHASE && !t.held);
		assert(!memcmp(&works[slot], &before, sizeof(before)));
	}
}
static void charged_count_conservation(void)
{
	for (int field = 0; field < 5; field++) {
		init();
		struct se_pw_ticket t = begin();
		attach_commit(&t);
		__u32 slot = t.slot;
		if (field)
			assert(se_pw_done(&owner, &works[slot], &lease, &t) ==
			       SE_PW_OK);
		if (field == 0 || field == 1)
			route.scratch_used = 0;
		if (field == 2)
			route.scratch_used = SE_POOL_QW + 1;
		if (field == 3)
			route.scratch_used = 2; /* one bit, count in range */
		if (field == 4)
			bits.words[SE_POOL_TASK_WORDS] |=
				2; /* two bits, count one */
		__u64 bits_before = bits.words[SE_POOL_TASK_WORDS];
		__u32 count_before = route.scratch_used,
		      refs_before = owner.work_refs;
		struct se_pool_work_meta work_before = works[slot];
		struct se_pool_work_payload payload_before = payloads[slot];
		__u64 cookie_before = charges[slot].current_cookie;
		assert(se_pw_visit(&route, &bits, &charges[slot], &works[slot],
				   &owner, &zero_template,
				   slot) == SE_PW_FAULT);
		assert(route.reserved &&
		       charges[slot].state == SE_PW_CH_FAULT_HELD);
		assert(charges[slot].current_cookie == cookie_before);
		assert(route.scratch_used == count_before &&
		       bits.words[SE_POOL_TASK_WORDS] == bits_before);
		assert(owner.work_refs == refs_before &&
		       works[slot].owner_ref_held == 1);
		assert(!memcmp(&works[slot], &work_before,
			       sizeof(work_before)));
		assert(!memcmp(&payloads[slot], &payload_before,
			       sizeof(payload_before)));
	}
}
static void expect_charged_visit_fault(__u32 slot)
{
	__u64 cookie = charges[slot].current_cookie;
	__u32 count = route.scratch_used;
	assert(se_pw_visit(&route, &bits, &charges[slot], &works[slot], &owner,
			   &zero_template, slot) == SE_PW_FAULT);
	assert(charges[slot].state == SE_PW_CH_FAULT_HELD && route.reserved);
	assert(charges[slot].current_cookie == cookie &&
	       route.scratch_used == count);
}
static void structural_visit_faults(void)
{
	for (int field = 0; field < 10; field++) {
		init();
		struct se_pw_ticket t = begin();
		attach_commit(&t);
		__u32 slot = t.slot;
		assert(se_pw_done(&owner, &works[slot], &lease, &t) ==
		       SE_PW_OK);
		switch (field) {
		case 0:
			works[slot].phase = SE_PW_FREE_PHASE;
			works[slot].cleanup_done = 3;
			break; /* OWNED + FREE metadata */
		case 1:
			route.scope = 8;
			break; /* wrong original route */
		case 2:
			bits.words[SE_POOL_TASK_WORDS] &= ~(1ULL << slot);
			break;
		case 3:
			charges[slot].current_cookie = 0;
			break;
		case 4:
			charges[slot].account_scope = 0;
			break;
		case 5:
			charges[slot].account_incarnation = 0;
			break;
		case 6:
			works[slot].cookie = 0;
			break;
		case 7:
			charges[slot].state = SE_PW_CH_RETURN_READY;
			break;
		case 8:
			route.scratch_used = 0;
			works[slot].phase = SE_PW_REFUND_PENDING;
			works[slot].cleanup_done = 3;
			works[slot].owner_ref_held = 0;
			owner.work_refs = 0;
			break;
		default:
			works[slot].phase = SE_PW_REFUND_PENDING;
			works[slot].cleanup_done = 3;
			works[slot].owner_ref_held = 0;
			owner.work_refs = 0;
			route.phase = 0;
			break;
		}
		__u64 bit_before = bits.words[SE_POOL_TASK_WORDS];
		expect_charged_visit_fault(slot);
		assert(bits.words[SE_POOL_TASK_WORDS] == bit_before);
	}
	init();
	struct se_pw_ticket malformed = begin();
	attach_commit(&malformed);
	__u32 malformed_slot = malformed.slot;
	assert(se_pw_visit(&route, &bits, &charges[malformed_slot],
			   &works[malformed_slot], &owner, 0,
			   malformed_slot) == SE_PW_FAULT);
	assert(charges[malformed_slot].state == SE_PW_CH_FAULT_HELD &&
	       route.reserved);
	assert(route.scratch_used == 1 &&
	       (bits.words[SE_POOL_TASK_WORDS] & (1ULL << malformed_slot)));
	for (int field = 0; field < 3; field++) {
		init();
		if (field == 0)
			bits.words[SE_POOL_TASK_WORDS] = 1;
		if (field == 1)
			charges[0].account_scope = 7;
		if (field == 2)
			charges[0].account_incarnation = 3;
		__u64 bit_before = bits.words[SE_POOL_TASK_WORDS];
		assert(se_pw_visit(&route, &bits, &charges[0], &works[0],
				   &owner, &zero_template, 0) == SE_PW_FAULT);
		assert(route.reserved && charges[0].state == SE_PW_CH_FREE);
		assert(!route.scratch_used &&
		       bits.words[SE_POOL_TASK_WORDS] == bit_before);
	}
}
static __u32 random_state = 0x9e3779b9u;
static __u32 random_u32(void)
{
	random_state ^= random_state << 13;
	random_state ^= random_state >> 17;
	random_state ^= random_state << 5;
	return random_state;
}
static void conservation(void)
{
	__u32 charged = 0, refs = 0;
	for (__u32 i = 0; i < SE_POOL_W; i++) {
		if (charges[i].state != SE_PW_CH_FREE)
			charged++;
		if (works[i].owner_ref_held)
			refs++;
		assert(!!(bits.words[SE_POOL_TASK_WORDS] & (1ULL << i)) ==
		       (charges[i].state != SE_PW_CH_FREE));
	}
	assert(charged == route.scratch_used && refs == owner.work_refs);
	assert(charged <= SE_POOL_QW && refs <= charged);
}
static void randomized_pressure(void)
{
	init();
	struct se_pw_ticket tickets[SE_POOL_W] = {};
	__u32 state[SE_POOL_W] = {}; /* 0 free, 1 active, 2 terminal */
	for (int step = 0; step < 20000; step++) {
		__u32 op = random_u32() % 3;
		if (op == 0 && route.scratch_used < SE_POOL_QW &&
		    !owner.current_work_owned) {
			struct se_pw_ticket t = begin();
			__u32 s = t.slot;
			if (random_u32() & 1) {
				attach_commit(&t);
				tickets[s] = t;
				state[s] = 1;
			} else {
				assert(se_pw_abort(&owner, &works[s], &route,
						   &bits, &charges[s], &lease,
						   &t) == SE_PW_OK);
				state[s] = 2;
			}
		} else if (op == 1 && owner.current_work_owned) {
			__u32 s = owner.current_work_slot;
			assert(state[s] == 1);
			assert(se_pw_done(&owner, &works[s], &lease,
					  &tickets[s]) == SE_PW_OK);
			state[s] = 2;
		} else {
			for (__u32 s = 0; s < SE_POOL_W; s++)
				if (state[s] == 2) {
					reap(s);
					state[s] = 0;
					break;
				}
		}
		conservation();
	}
	if (owner.current_work_owned) {
		__u32 s = owner.current_work_slot;
		assert(se_pw_done(&owner, &works[s], &lease, &tickets[s]) ==
		       SE_PW_OK);
		state[s] = 2;
	}
	for (__u32 s = 0; s < SE_POOL_W; s++)
		if (state[s] == 2)
			reap(s);
	conservation();
	assert(!route.scratch_used && !owner.work_refs);
}
static void typed_semantic_failures(void)
{
	init();
	struct se_pw_ticket t = begin();
	assert(se_pw_attach(&owner, &works[t.slot], &lease, &t) == SE_PW_OK);
	struct se_pool_work_payload *payload = &payloads[t.slot];
	semantic_zero_fail = 1;
	assert(se_pool_work_semantic_initialize(&owner, &works[t.slot],
						&charges[t.slot], &payload,
						&lease, &t) == SE_PW_FAULT);
	assert(t.held && works[t.slot].phase == SE_PW_INITIALIZING &&
	       charges[t.slot].state == SE_PW_CH_BUILDING);
	assert(se_pw_abort(&owner, &works[t.slot], &route, &bits,
			   &charges[t.slot], &lease, &t) == SE_PW_OK);
	assert(!t.held && charges[0].state == SE_PW_CH_OWNED);
	reap(0);
	init();
	t = begin();
	assert(se_pw_attach(&owner, &works[t.slot], &lease, &t) == SE_PW_OK);
	payload = &payloads[t.slot];
	assert(se_pool_work_semantic_initialize(&owner, &works[t.slot],
						&charges[1 - t.slot], &payload,
						&lease, &t) == SE_PW_FAULT);
	assert(t.held && charges[t.slot].state == SE_PW_CH_BUILDING);
	assert(se_pw_abort(&owner, &works[t.slot], &route, &bits,
			   &charges[t.slot], &lease, &t) == SE_PW_OK);
	reap(0);
	init();
	t = begin();
	attach_commit(&t);
	payloads[t.slot].semantic.cookie++;
	assert(se_pool_work_semantic_active(&owner, &lease, &works[t.slot],
					    &payloads[t.slot], &t, &route,
					    &charges[t.slot]) == SE_PW_FAULT);
	assert(route.reserved && charges[t.slot].state == SE_PW_CH_FAULT_HELD &&
	       t.held && works[t.slot].phase == SE_PW_ACTIVE &&
	       owner.work_refs == 1);
	assert(se_pw_done(&owner, &works[t.slot], &lease, &t) == SE_PW_OK);
	assert(charges[0].state == SE_PW_CH_FAULT_HELD &&
	       route.scratch_used == 1);
	init();
	t = begin();
	attach_commit(&t);
	struct se_pool_work_semantic_handle handle = {};
	assert(se_pool_work_semantic_open(
		       &owner, &lease, &works[t.slot], &payloads[t.slot], &t,
		       &route, &charges[t.slot], &handle) == SE_PW_OK);
	payloads[t.slot].semantic.cookie++;
	assert(se_pool_work_semantic_done(&handle) == SE_PW_FAULT);
	assert(!handle.held && !t.held && route.reserved &&
	       charges[t.slot].state == SE_PW_CH_FAULT_HELD &&
	       works[t.slot].phase == SE_PW_DONE);
	init();
	t = begin();
	attach_commit(&t);
	__u32 final_slot = t.slot;
	assert(final_slot < SE_POOL_W);
	lease.held = 0;
	handle = (struct se_pool_work_semantic_handle){};
	assert(se_pool_work_semantic_open(&owner, &lease, &works[final_slot],
					  &payloads[final_slot], &t, &route,
					  &charges[final_slot],
					  &handle) == SE_PW_FAULT);
	assert(!handle.held && route.reserved &&
	       charges[final_slot].state == SE_PW_CH_FAULT_HELD);
	lease.held = 1;
	assert(se_pw_done(&owner, &works[final_slot], &lease, &t) == SE_PW_OK);
	puts("typed WORK semantic failure retention: PASS");
}
int main(void)
{
	churn();
	old_retained_new_starts();
	failed_construction();
	retry_and_aba();
	stale_owner_lease();
	resume_refund_tail();
	contradictory_free_begin();
	contradictory_cleanup_visit();
	sequence_rollback();
	task_recycle_after_work_return();
	missing_prior_identity();
	charged_count_conservation();
	structural_visit_faults();
	randomized_pressure();
	typed_semantic_failures();
	puts("work core host tests OK");
}
