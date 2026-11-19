/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* G019 M4 product publisher (ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE,
 * product and product-source twins only; scratchpad g019-m4-design.md
 * sections 2-4 and 13). Included once, at the end of
 * opaque_real_owner_child_candidate.bpf.c, after every primitive it uses.
 *
 * Authority (B2): the product commands are SEC("syscall") programs run by the
 * node agent's single admin thread. Each request starts with
 * struct opaque_real_cmd_header. A command is authenticated exactly like the
 * protocol se_command (shared_control.h) minus its protocol command fields:
 *   - se_configuration[0] matches the compiled profile (se_profile_matches);
 *   - the calling thread's se_admin task storage equals the configured nonce
 *     and the request carries that nonce (the product); in a recovered-
 *     control test twin (ENFORCE_EXEC_SHARED_RECOVERY, no se_admin) the
 *     committed live physical admin authorizes instead, exactly as the
 *     protocol se_command does there;
 *   - the request's node cookie equals the configured one;
 *   - the request's sequence is nonzero, not ~0, and strictly above the last
 *     one this node consumed in opaque_real_cmd_receipt.
 * An authenticated command consumes its sequence before it changes any
 * state, whatever its outcome. A refused authentication returns
 * OPAQUE_REAL_CMD_AUTH and changes nothing, the receipt included. */
#ifndef ENFORCE_EXEC_OPAQUE_REAL_OWNER_PRODUCT_PUBLISHER_H
#define ENFORCE_EXEC_OPAQUE_REAL_OWNER_PRODUCT_PUBLISHER_H

#if !defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_POLICY_VERDICT_CANDIDATE) || \
	!defined(ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE)
#error "the product publisher requires the verdict candidate's source-pinned route"
#endif

/* B1: the product route anchor is the 104-byte source-pinned anchor plus
 * adopting and adopting_faults, and (G019 gap 3) the two per-record holder
 * mirrors (struct se_route_rec, 32 B each). The protocol (88 B) and
 * non-product candidate (104 B) layouts are unchanged: the fields exist only
 * here. */
_Static_assert(sizeof(struct se_route_rec) == 32, "per-record route holders");
_Static_assert(sizeof(struct se_route_anchor) == 176,
	       "product route anchor: source-pinned 104 B + adopting marker + "
	       "per-record holders");

/* Command return codes, shared by every product command (section 13.6). */
#define OPAQUE_REAL_CMD_OK 0
#define OPAQUE_REAL_CMD_RETRY 1 /* retryable, or not found */
#define OPAQUE_REAL_CMD_REFUSED 2 /* terminal for this adoption */
#define OPAQUE_REAL_CMD_LATCHED 3 /* route reserved / unresolved sources */
#define OPAQUE_REAL_CMD_REUSED 4 /* cgroup published before */
#define OPAQUE_REAL_CMD_AUTH 5 /* authentication refused, nothing changed */
/* The image is not armed (real_owner_image_configured(): the node
 * configuration is not installed); nothing changed but the sequence. A
 * route must never be published or adopted onto hooks that would not
 * enforce it. */
#define OPAQUE_REAL_CMD_UNARMED 7
#define OPAQUE_REAL_CMD_INVARIANT -1

struct opaque_real_cmd_header {
	__u64 node_cookie, nonce, sequence;
};
_Static_assert(sizeof(struct opaque_real_cmd_header) == 24,
	       "product command header wire");

/* The last sequence each node consumed. Written only by BPF (the agent
 * reads it back after a lost acknowledgement). */
struct opaque_real_cmd_receipt {
	__u64 node_cookie, sequence;
};
_Static_assert(sizeof(struct opaque_real_cmd_receipt) == 16,
	       "product command receipt wire");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_real_cmd_receipt);
} opaque_real_cmd_receipt SEC(".maps");

/* 1: authenticated and the sequence consumed; 0: refused, nothing changed.
 * The compare-and-swap makes the consumption exact even if a second thread
 * ever passed the se_admin check: one sequence is consumed once. */
/* Its own frame: the recovered twin's authority copies its configuration
 * to the stack, which must not add to a command's deepest chain. */
static __attribute__((noinline)) int
real_owner_cmd_authenticate(const struct opaque_real_cmd_header *h)
{
	__u32 zero = 0;
	const struct se_node_config *config = SE_CONFIG_LOOKUP(&zero);
	struct opaque_real_cmd_receipt *receipt =
		bpf_map_lookup_elem(&opaque_real_cmd_receipt, &zero);
	if (!h || !se_profile_matches(config) || !receipt ||
	    h->node_cookie != config->node_cookie || !h->sequence ||
	    h->sequence == ~0ULL)
		return 0;
#ifdef ENFORCE_EXEC_SHARED_RECOVERY
	if (!se_rm_command_authorized(config->node_cookie))
		return 0;
#else
	const __u64 *admin = SE_ADMIN_LOOKUP();
	if (!admin || *admin != config->nonce || h->nonce != config->nonce)
		return 0;
#endif
	__u64 node = receipt->node_cookie, seen = receipt->sequence;
	if ((node && node != config->node_cookie) || h->sequence <= seen ||
	    __sync_val_compare_and_swap(&receipt->sequence, seen,
					h->sequence) != seen)
		return 0;
	if (!node)
		receipt->node_cookie = config->node_cookie;
	return 1;
}

/* G020: the image index commands and the PREPARE/FREE image lifetime. */
#include "opaque_real_owner_product_image.h"

/* B3: opaque_real_policy_stage (design section 3.1). One authenticated run
 * per object step, through the exact object state machine of the protocol
 * (full/shared_arena.h, shared_control.h se_command): BEGIN a FREE slot with
 * its length, WRITE cell index (in order, one per run: the request carries
 * one 288-byte cell), FINALIZE to READY with its rule count and class, and
 * ABORT, RETIRE, RECLAIM. The slot's size class is derived from the
 * configured profile (se_object_range), never from the request, so an
 * object can never exceed its slot class's cells. Codes: 0 done, 1 refused
 * (no state change beyond the consumed sequence), 5 authentication refused,
 * -1 invariant (a cell write that could not finish). */
#define OPAQUE_REAL_STAGE_BEGIN 1
#define OPAQUE_REAL_STAGE_WRITE 2
#define OPAQUE_REAL_STAGE_FINALIZE 3
#define OPAQUE_REAL_STAGE_ABORT 4
#define OPAQUE_REAL_STAGE_RETIRE 5
#define OPAQUE_REAL_STAGE_RECLAIM 6
struct opaque_real_policy_stage_request {
	struct opaque_real_cmd_header header;
	__u64 generation, attempt;
	__u32 op, object, index, count, execution_class, reserved;
	struct se_arena_cell cell;
};
_Static_assert(sizeof(struct opaque_real_policy_stage_request) == 352,
	       "product stage request wire");

SEC("syscall")
int opaque_real_policy_stage(struct opaque_real_policy_stage_request *r)
{
	if (!r || !real_owner_cmd_authenticate(&r->header))
		return OPAQUE_REAL_CMD_AUTH;
	__u32 zero = 0, slot = r->object, op = r->op, size_class = 0, base = 0;
	const struct se_node_config *config = SE_CONFIG_LOOKUP(&zero);
	if (!config || r->reserved || slot >= config->objects ||
	    se_object_range(config, slot, &size_class, &base))
		return OPAQUE_REAL_CMD_RETRY;
	struct se_shared_object *object = SE_OBJECT_LOOKUP(&slot);
	if (!object)
		return OPAQUE_REAL_CMD_INVARIANT;
	int result = -1;
	if (op == OPAQUE_REAL_STAGE_WRITE) {
		if (r->index >= se_object_capacity(size_class))
			return OPAQUE_REAL_CMD_RETRY;
		__u32 key = base + r->index;
		struct se_arena_cell *cell = SE_CELL_LOOKUP(&key);
		if (!cell)
			return OPAQUE_REAL_CMD_INVARIANT;
		struct se_write_claim claim = {};
		bpf_spin_lock(&object->lock);
		if (object->state.slot == slot &&
		    object->state.size_class == size_class)
			result = se_object_write_begin_locked(&object->state,
							      r->generation,
							      r->attempt,
							      r->index, &claim);
		bpf_spin_unlock(&object->lock);
		if (result)
			return OPAQUE_REAL_CMD_RETRY;
		__builtin_memcpy(cell, &r->cell, sizeof(*cell));
		bpf_spin_lock(&object->lock);
		result = se_object_write_finish_locked(&object->state, &claim);
		bpf_spin_unlock(&object->lock);
		return result ? OPAQUE_REAL_CMD_INVARIANT : OPAQUE_REAL_CMD_OK;
	}
	bpf_spin_lock(&object->lock);
	struct se_object *s = &object->state;
	if (op == OPAQUE_REAL_STAGE_BEGIN) {
		if (s->generation == r->generation &&
		    s->phase == SE_OBJECT_FREE && !s->pins && !s->commands &&
		    !s->writer_sequence && !s->reserved && r->count &&
		    r->count <= se_object_capacity(size_class)) {
			s->slot = slot;
			s->size_class = size_class;
			result =
				se_object_begin_locked(s, r->attempt, r->count);
		}
	} else if (s->slot == slot && s->size_class == size_class) {
		switch (op) {
		case OPAQUE_REAL_STAGE_FINALIZE:
			result = se_object_finalize_locked(s, r->generation,
							   r->attempt, r->count,
							   r->execution_class);
			break;
		case OPAQUE_REAL_STAGE_ABORT:
			result = se_object_abort_locked(s, r->generation,
							r->attempt);
			break;
		case OPAQUE_REAL_STAGE_RETIRE:
			result = se_object_retire_locked(s, r->generation);
			break;
		case OPAQUE_REAL_STAGE_RECLAIM:
			result = se_object_reclaim_locked(s, r->generation);
			break;
		}
	}
	bpf_spin_unlock(&object->lock);
	return result ? OPAQUE_REAL_CMD_RETRY : OPAQUE_REAL_CMD_OK;
}

/* Per-binding publication and adoption state (B4/B5, design 13.2). Only the
 * route anchor's adopting word is authoritative for claims; this entry
 * carries what the adoption commands check against (the route incarnation
 * and generation captured at publish, the init identity) and the BPF-owned
 * counts. last_cgroup survives recycle: the cgroup-reuse refusal (code 4). */
struct opaque_real_adopt_state {
	struct bpf_spin_lock lock;
	__u32 adopting, adopt_failed, adopted, iterated, bad, leaders,
		incarnation, init_tgid, quarantined, missed, exiting, faults,
		finishes, gone, recorded;
	__u64 generation, cgroup, scope, last_cgroup, init_start_ticks,
		init_mntns, init_role;
};
_Static_assert(sizeof(struct opaque_real_adopt_state) == 120,
	       "product adoption state wire");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_BINDINGS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_real_adopt_state);
} opaque_real_adopt_state SEC(".maps");
/* The adopted set (design 13.1): one entry per adopted task, keyed by the
 * binding slot and the task pointer (the se_opaque_keys key), valued with
 * the adopted TASK's lease cookie and locator. Inserted BPF_NOEXIST outside
 * any lock; removed only by recycle. */
struct opaque_real_adopted_key {
	__u64 task;
	__u32 slot, reserved;
};
struct opaque_real_adopted_value {
	__u64 cookie, locator;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_PROFILE_TASKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, struct opaque_real_adopted_key);
	__type(value, struct opaque_real_adopted_value);
} opaque_real_adopted SEC(".maps");

/* Test-only publication fault injector (twins, never the product): the
 * agent's VM tests select one fault point; the publication then takes its
 * real undo path from there. 1: after pin and seal; 2: after the epoch
 * index bind; 3: after the cgroup locator insert, before the commit. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PUBLISH_FAULT_DIAGNOSTIC
/* Never in a product object. The one exception is the explicit test twin
 * (SE_PRODUCT_DIAGNOSTIC_TWIN): product composition, se_admin authority,
 * plus this injector, so the product admin control runs the VM undo-path
 * tests; the product admission refuses its injector map. */
#if defined(SE_PRODUCT_NO_TEST_RUN) && !defined(SE_PRODUCT_DIAGNOSTIC_TWIN)
#error "the publication fault injector is diagnostic only"
#endif
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_publish_fault SEC(".maps");
static __always_inline int real_owner_publish_fault(__u32 point)
{
	__u32 zero = 0;
	const __u32 *armed =
		bpf_map_lookup_elem(&opaque_real_publish_fault, &zero);
	return armed && *armed == point;
}
#define SE_PUBLISH_FAULT(point) real_owner_publish_fault(point)
#else
#define SE_PUBLISH_FAULT(point) 0
#endif

/* B4: opaque_real_route_publish (design 3.2). A product snapshot has exactly
 * one policy object and one policy UID (one ticket, metadata count 1).
 *   first (generation_expected 0): binding open, route open (PREPARING),
 *     snapshot prepare + pin + seal, the accepted-epoch index, the cgroup
 *     locator, then under one route lock the commit pair with adopting = 1;
 *   revision: route ACTIVE, not adopting, the expected generation; the
 *     candidate record's retiring predecessor is released first, then the
 *     same prepare/pin/seal/commit; the last-good record stays ACTIVE on any
 *     failure.
 * Every map update is outside the route lock and undone on failure.
 * Codes: 0 published, 1 retryable (preflight refused: early claims, source
 * pins, a busy record), 2 refused, not retryable (first publication: the
 * staged object's policy UID, root role, class or epoch is not the
 * request's; revision: the same prefix check, or a different policy UID
 * than the active snapshot's (a G019 limit: one policy
 * object and one policy UID per binding, multi-policy is M8), 3 not
 * retryable (route reserved, unresolved
 * sources), 4 cgroup published before, 5 authentication, -1 invariant (an
 * undo failed: the slot needs the reaper/recycle path). */
struct opaque_real_route_publish_request {
	struct opaque_real_cmd_header header;
	__u64 cgroup, scope, generation_expected, object_generation,
		init_start_ticks, init_mntns, init_role;
	__u32 slot, execution_class, object_slot, init_tgid, bank, reserved;
	struct se_snapshot_metadata metadata;
};
_Static_assert(sizeof(struct opaque_real_route_publish_request) == 512,
	       "product publish request wire");

/* Request fields read from the syscall ctx with a fixed offset on the
 * UNMODIFIED ctx pointer. The verifier refuses a load through ctx+off
 * ("dereference of modified ctx ptr"): clang may otherwise hoist
 * ctx+offsetof(metadata) into a base register (pub-load refused
 * opaque_real_route_publish exactly so). The empty asm hands each access a
 * fresh copy of the ctx register, so no base is shared between accesses. */
static __always_inline __u64 real_owner_request_u64(
	const struct opaque_real_route_publish_request *r, __u32 offset)
{
	const struct opaque_real_route_publish_request *c = r;
	asm volatile("" : "+r"(c));
	return *(const __u64 *)((const char *)c + offset);
}
#define REAL_OWNER_REQUEST_UID(r)                                            \
	real_owner_request_u64(                                              \
		(r),                                                         \
		__builtin_offsetof(struct opaque_real_route_publish_request, \
				   metadata.policy_uids[0]))
#define REAL_OWNER_REQUEST_EPOCH(r)                                          \
	real_owner_request_u64(                                              \
		(r),                                                         \
		__builtin_offsetof(struct opaque_real_route_publish_request, \
				   metadata.root_epochs[0]))
/* The request's metadata into a snapshot record, word by word, each word a
 * fixed-offset ctx load (see real_owner_request_u64). No helper call: safe
 * under the route lock. */
_Static_assert(sizeof(struct se_snapshot_metadata) % 8 == 0,
	       "metadata copied in words");
static __always_inline void real_owner_metadata_copy_locked(
	struct se_snapshot_metadata *dst,
	const struct opaque_real_route_publish_request *r)
{
	__u64 *d = (__u64 *)dst;
#ifdef __clang__
#pragma unroll
#endif
	for (__u32 i = 0; i < sizeof(*dst) / 8; i++)
		d[i] = real_owner_request_u64(
			r, __builtin_offsetof(
				   struct opaque_real_route_publish_request,
				   metadata) +
				   8 * i);
}

static __always_inline int
real_owner_epoch_cell_ready(const struct se_epoch_cell *cell, __u64 scope,
			    __u64 uid, __u64 epoch)
{
	if (!cell || !scope || !uid || !epoch || cell->reserved0 ||
	    cell->reserved1)
		return 0;
	int empty = !cell->scope && !cell->uid && !cell->epoch;
	int same = cell->scope == scope && cell->uid == uid &&
		   (cell->epoch == 0 || cell->epoch == epoch);
	return empty || same;
}

/* A record index (0 or 1) proven bounded at its use. A u32 spilled next to
 * another u32 in one 8-byte stack slot comes back unbounded (the slot is
 * "misc" to the verifier); the pub-load gate refused route_publish exactly
 * so ("R8 unbounded memory access" after bpf_spin_lock). The empty asm makes
 * clang forget any earlier mask, so the "& 1" is recomputed on the register
 * right where the record is indexed. Every records[] index in this header
 * is a literal or goes through this. */
static __always_inline __u32 real_owner_record(__u32 record)
{
	asm volatile("" : "+r"(record));
	return record & 1;
}

/* Release the single ticket of a RETIRING record and reclaim the record.
 * 0 done (or nothing to do), 1 holders remain (G019 gap 3: an early claim,
 * a source pin or a reader still holds the record; retryable), -1 refused.
 * Route lock NOT held. The holders are checked under the route lock before
 * the ticket is released, so a holder never loses its object (the RELEASE
 * command re-checks the readers); a RETIRING record's holder set only
 * shrinks (fresh claims stamp the ACTIVE record), so none can appear
 * between that check and the release. */
static __attribute__((noinline)) int real_owner_snapshot_drop(__u32 slot,
							      __u32 record)
{
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	struct se_binding_images *images =
		bpf_map_lookup_elem(&se_image_bindings, &slot);
	if (!binding || !route || !images || record >= 2)
		return -1;
	record &= 1;
	struct se_ticket_request request = { .record = record,
					     .kind = SE_COMMAND_RELEASE };
	__u32 phase, count, object_slot = 0, ticket = SE_TICKET_EMPTY;
	bpf_spin_lock(&route->lock);
	const struct se_snapshot *s =
		&binding->state.records[real_owner_record(record)];
	phase = s->phase;
	count = s->count;
	/* Readers (claims) and the route holders of this record. */
	__u32 held = s->claims || se_route_rec_held(route, record);
	request.scope = s->scope;
	request.serial = s->serial;
	object_slot = s->tickets[0].object_slot;
	ticket = s->tickets[0].phase;
	bpf_spin_unlock(&route->lock);
	if (phase == SE_SNAPSHOT_FREE)
		return 0;
	if (phase != SE_SNAPSHOT_RETIRING || count != 1)
		return -1;
	if (held)
		return 1;
	if (ticket == SE_TICKET_HELD) {
		struct se_shared_object *object =
			SE_OBJECT_LOOKUP(&object_slot);
		__u32 receipt = 0;
		if (!object || se_ticket_command(&route->lock, binding, object,
						 &request, &receipt))
			return -1;
	}
	bpf_spin_lock(&route->lock);
	struct se_snapshot *reclaim =
		&binding->state.records[real_owner_record(record)];
	/* G020: FREE releases the record's image reference, exactly once, in
	 * this same locked transition (full/shared_image_snapshot.h). */
	int result = reclaim->serial == request.serial ?
			     se_image_snapshot_reclaim_locked(
				     images, &binding->state,
				     real_owner_record(record)) :
			     -1;
	if (!result && !se_route_rec_held(route, record))
		*SE_ROUTE_REC(route, record) = (struct se_route_rec){};
	bpf_spin_unlock(&route->lock);
	return result;
}

/* Abort an uncommitted candidate: retire it, release its ticket, reclaim. */
static __attribute__((noinline)) int
real_owner_snapshot_abort(__u32 slot, __u32 record, __u64 serial)
{
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	if (!binding || !route || record >= 2)
		return -1;
	record &= 1;
	bpf_spin_lock(&route->lock);
	struct se_snapshot *s =
		&binding->state.records[real_owner_record(record)];
	int result = s->serial == serial ? se_snapshot_retire_locked(s) : -1;
	bpf_spin_unlock(&route->lock);
	return result ? -1 : real_owner_snapshot_drop(slot, record);
}

/* An empty binding again (both records FREE, nothing in flight): the
 * scalar header only, the records are already zero (reclaim zeroes them). */
static __always_inline void
real_owner_binding_clear_locked(struct se_binding_snapshots *b)
{
	b->scope = 0;
	b->next_serial = 0;
	b->next_command = 0;
	b->generation = 0;
	b->admission_serial = 0;
	b->next_reader = 0;
	b->active_serial = 0;
	b->active_record = 0;
}

/* Code 4 (design 3.4): a first publication of a cgroup that is any
 * binding's last published cgroup. last_cgroup is written only by a
 * successful first publication of its slot and is NEVER cleared: withdraw
 * and recycle keep it, so the same cgroup stays refused after its slot was
 * recycled, until that slot's next successful first publication of a
 * different cgroup overwrites it. Older cgroups are refused by the agent's
 * node-lifetime withdrawn scope state (ErrSharedBindingWithdrawn); this is
 * the fail-closed belt and braces for the most recent one per slot. */
static __always_inline int real_owner_cgroup_reused(__u64 cgroup)
{
	for (__u32 i = 0; i < SE_PROFILE_BINDINGS; i++) {
		__u32 key = i;
		const struct opaque_real_adopt_state *state =
			bpf_map_lookup_elem(&opaque_real_adopt_state, &key);
		if (!state || state->last_cgroup == cgroup)
			return 1;
	}
	return 0;
}

/* Pin the candidate's single ticket on the READY object of the requested
 * class and seal the record. 0 sealed, -1 refused (candidate left
 * PREPARING for the caller's abort). Route lock NOT held. */
static __attribute__((noinline)) int
real_owner_snapshot_pin_seal(__u32 slot, __u32 record, __u64 serial,
			     __u32 object_slot, __u32 execution_class)
{
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	struct se_shared_object *object = SE_OBJECT_LOOKUP(&object_slot);
	if (!binding || !route || !object || record >= 2)
		return -1;
	record &= 1;
	bpf_spin_lock(&object->lock);
	int ready = object->state.phase == SE_OBJECT_READY &&
		    object->state.slot == object_slot &&
		    object->state.execution_class == execution_class;
	bpf_spin_unlock(&object->lock);
	if (!ready)
		return -1;
	struct se_ticket_request request = { .serial = serial,
					     .record = record,
					     .kind = SE_COMMAND_PIN };
	bpf_spin_lock(&route->lock);
	request.scope = binding->state.scope;
	bpf_spin_unlock(&route->lock);
	__u32 receipt = 0;
	if (se_ticket_command(&route->lock, binding, object, &request,
			      &receipt) ||
	    receipt != SE_TICKET_HELD)
		return -1;
	bpf_spin_lock(&route->lock);
	struct se_snapshot *s =
		&binding->state.records[real_owner_record(record)];
	int result = s->serial == serial ? se_snapshot_prepared_locked(s) : -1;
	bpf_spin_unlock(&route->lock);
	return result;
}

/* The accepted-epoch index entry (scope, uid) -> bank, inserted outside any
 * lock. 1 created, 0 already this bank, -1 refused. */
static __attribute__((noinline)) int
real_owner_epoch_bind(__u64 scope, __u64 uid, __u32 bank)
{
	struct se_epoch_key key = { scope, uid };
	struct se_epoch_cell *cell = SE_EPOCH_BANK_LOOKUP(&bank);
	if (bank >= SE_PROFILE_ACCEPTED_UIDS || !cell)
		return -1;
	const __u32 *have = bpf_map_lookup_elem(&se_epoch_index, &key);
	int decision = se_arm_index_decision(have, bank, cell, scope, uid);
	if (decision <= 0)
		return decision;
	if (bpf_map_update_elem(&se_epoch_index, &key, &bank, BPF_NOEXIST)) {
		have = bpf_map_lookup_elem(&se_epoch_index, &key);
		return have && *have == bank ? 0 : -1;
	}
	return 1;
}

/* Under the route lock: the complete commit preflight, the epoch store and
 * the commit pair, with the adoption marker for a first publication.
 * 0 committed, 1 preflight refused (retryable), 3 latched. */
static __always_inline int real_owner_commit_locked(
	struct se_route_anchor *route, struct se_binding_snapshots *b,
	__u32 record, __u64 serial, struct se_epoch_cell *cell,
	const struct opaque_real_route_publish_request *r, __u32 first)
{
	if (record >= 2)
		return OPAQUE_REAL_CMD_INVARIANT;
	record = real_owner_record(record);
	const struct se_snapshot *s = &b->records[record];
	__u64 uid = s->metadata.policy_uids[0],
	      epoch = s->metadata.root_epochs[0];
	if (route->reserved || route->unresolved_sources)
		return OPAQUE_REAL_CMD_LATCHED;
	if (route->scope != r->scope || route->cgroup_identity != r->cgroup ||
	    route->payload_slot != r->slot || route->adopting != 0 ||
	    (first ? route->phase != SE_ROUTE_PREPARING :
		     route->phase != SE_ROUTE_ACTIVE) ||
	    s->count != 1 ||
	    /* A revision keeps the route's class (review M1). */
	    (!first && s->execution_class != route->execution_class) ||
	    !se_snapshot_metadata_valid(&s->metadata, 1, b->generation + 1) ||
	    !real_owner_epoch_cell_ready(cell, route->scope, uid, epoch) ||
	    se_route_commit_preflight_locked(route, b,
					     real_owner_record(record), serial,
					     route->admission_serial))
		return OPAQUE_REAL_CMD_RETRY;
	cell->scope = route->scope;
	cell->uid = uid;
	cell->epoch = epoch;
	se_route_commit_publish_locked(route, b, real_owner_record(record));
	if (first) {
		route->adopting = 1;
		route->adopting_faults = 0;
	}
	return OPAQUE_REAL_CMD_OK;
}

/* The staged object's own policy prefix (fullpolicy KernelPolicyBase = 1:
 * struct fe_policy) must name the snapshot's policy UID, the requested init
 * role and the requested class (mode: 1 Audit, 2 Enforce = Strict); its
 * root_epoch must be 0, as every shared object (the epoch is the snapshot's
 * metadata, root_epochs[0], checked by se_snapshot_metadata_valid; the
 * evaluator's lookup refuses a nonzero object epoch). The agent sends the
 * compiled values, so a mismatch is a forged or stale request. Only after
 * pin and seal (the object is pinned READY, its cells immutable). 1 matches. */
static __attribute__((noinline)) int
real_owner_root_role_matches(__u32 object_slot, __u64 object_generation,
			     __u64 uid, __u64 role, __u32 execution_class)
{
	const struct fe_policy *p = (const void *)se_policy_physical(
		0, object_slot, object_generation, 1);
	return p && uid && role && p->uid == uid && p->root_role == role &&
	       !p->root_epoch && p->mode == execution_class;
}

static __attribute__((noinline)) int
real_owner_publish_first(const struct opaque_real_route_publish_request *r)
{
	__u32 slot = r->slot, record = 0;
	__u64 cgroup = r->cgroup, scope = r->scope;
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	struct opaque_real_adopt_state *state =
		bpf_map_lookup_elem(&opaque_real_adopt_state, &slot);
	struct se_binding_images *images =
		bpf_map_lookup_elem(&se_image_bindings, &slot);
	__u32 bank = r->bank;
	struct se_epoch_cell *cell = SE_EPOCH_BANK_LOOKUP(&bank);
	if (!binding || !route || !state || !images || !cell)
		return OPAQUE_REAL_CMD_INVARIANT;
	if (!r->init_tgid || !r->init_start_ticks || !r->init_mntns ||
	    !r->init_role)
		return OPAQUE_REAL_CMD_RETRY;
	if (real_owner_cgroup_reused(cgroup) ||
	    bpf_map_lookup_elem(&se_route_index, &cgroup))
		return OPAQUE_REAL_CMD_REUSED;
	struct se_pin_ticket handle = {
		.object_generation = r->object_generation,
		.object_slot = r->object_slot,
	};
	int code = OPAQUE_REAL_CMD_RETRY;
	__u64 serial = 0;
	__u32 incarnation = 0;
	/* Open: an empty binding on a FREE route (recycle cleared both). */
	bpf_spin_lock(&route->lock);
	struct se_binding_snapshots *b = &binding->state;
	if (route->reserved || route->unresolved_sources) {
		code = OPAQUE_REAL_CMD_LATCHED;
	} else if (!b->scope && !b->next_serial && !b->next_command &&
		   !b->generation && !b->active_serial && !b->inflight &&
		   !b->records[0].phase && !b->records[1].phase &&
		   !se_route_open_locked(route, cgroup, scope, slot)) {
		b->scope = scope;
		if (se_snapshot_prepare_locked(b, record, &handle, 1,
					       r->execution_class)) {
			/* Undo the open: FREE again, incarnation kept. */
			b->scope = 0;
			route->cgroup_identity = 0;
			route->scope = 0;
			route->payload_slot = 0;
			route->phase = SE_ROUTE_FREE;
		} else {
			real_owner_metadata_copy_locked(&b->records[0].metadata,
							r);
			if (se_image_snapshot_prepare_locked(images, b, 0)) {
				/* G020: no sealed image of the handle: undo
				 * the prepare and the open (an empty binding
				 * on a FREE route again). */
				b->records[0] = (struct se_snapshot){};
				real_owner_binding_clear_locked(b);
				route->cgroup_identity = 0;
				route->scope = 0;
				route->payload_slot = 0;
				route->phase = SE_ROUTE_FREE;
				code = OPAQUE_REAL_CMD_IMAGE;
			} else {
				serial = b->records[0].serial;
				incarnation = route->incarnation;
				code = OPAQUE_REAL_CMD_OK;
			}
		}
	}
	bpf_spin_unlock(&route->lock);
	if (code == OPAQUE_REAL_CMD_IMAGE)
		real_owner_image_witness(SE_IMAGE_CLASS_PREPARE_REFUSED);
	if (code != OPAQUE_REAL_CMD_OK)
		return code;
	__u64 locator = se_route_locator(slot, incarnation);
	int epoch = -1, indexed = 0;
	code = OPAQUE_REAL_CMD_RETRY;
	if (real_owner_snapshot_pin_seal(slot, record, serial, r->object_slot,
					 r->execution_class) ||
	    SE_PUBLISH_FAULT(1))
		goto undo;
	if (!real_owner_root_role_matches(r->object_slot, r->object_generation,
					  r->metadata.policy_uids[0],
					  r->init_role, r->execution_class)) {
		code = OPAQUE_REAL_CMD_REFUSED;
		goto undo;
	}
	epoch = real_owner_epoch_bind(scope, r->metadata.policy_uids[0], bank);
	if (epoch < 0 || SE_PUBLISH_FAULT(2))
		goto undo;
	if (bpf_map_update_elem(&se_route_index, &cgroup, &locator,
				BPF_NOEXIST)) {
		code = OPAQUE_REAL_CMD_REUSED;
		goto undo;
	}
	indexed = 1;
	if (SE_PUBLISH_FAULT(3))
		goto undo;
	bpf_spin_lock(&route->lock);
	code = route->incarnation == incarnation ?
		       real_owner_commit_locked(route, b, record, serial, cell,
						r, 1) :
		       OPAQUE_REAL_CMD_RETRY;
	bpf_spin_unlock(&route->lock);
	if (code != OPAQUE_REAL_CMD_OK)
		goto undo;
	bpf_spin_lock(&state->lock);
	state->adopting = 1;
	state->adopt_failed = 0;
	state->adopted = 0;
	state->iterated = 0;
	state->bad = 0;
	state->leaders = 0;
	state->incarnation = incarnation;
	state->generation = b->generation;
	state->cgroup = cgroup;
	state->scope = scope;
	state->last_cgroup = cgroup;
	state->init_tgid = r->init_tgid;
	state->init_start_ticks = r->init_start_ticks;
	state->init_mntns = r->init_mntns;
	state->init_role = r->init_role;
	state->quarantined = 0;
	state->missed = 0;
	state->exiting = 0;
	state->faults = 0;
	state->finishes = 0;
	state->gone = 0;
	state->recorded = 0;
	bpf_spin_unlock(&state->lock);
	return OPAQUE_REAL_CMD_OK;
undo:
	/* Reverse order: locator, epoch index, candidate, open. */
	if (indexed) {
		const __u64 *have =
			bpf_map_lookup_elem(&se_route_index, &cgroup);
		if (have && *have == locator)
			bpf_map_delete_elem(&se_route_index, &cgroup);
	}
	if (epoch == 1)
		se_arm_rollback_one(scope, r->metadata.policy_uids[0], 1, cell);
	if (real_owner_snapshot_abort(slot, record, serial))
		return OPAQUE_REAL_CMD_INVARIANT;
	bpf_spin_lock(&route->lock);
	int reopened = route->phase == SE_ROUTE_PREPARING &&
		       route->incarnation == incarnation &&
		       !route->early_claims && !b->records[0].phase &&
		       !b->records[1].phase && !b->active_serial &&
		       !b->inflight;
	if (reopened) {
		real_owner_binding_clear_locked(b);
		route->cgroup_identity = 0;
		route->scope = 0;
		route->payload_slot = 0;
		route->phase = SE_ROUTE_FREE;
	}
	bpf_spin_unlock(&route->lock);
	return reopened ? code : OPAQUE_REAL_CMD_INVARIANT;
}

static __attribute__((noinline)) int
real_owner_publish_revision(const struct opaque_real_route_publish_request *r)
{
	__u32 slot = r->slot;
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	struct opaque_real_adopt_state *state =
		bpf_map_lookup_elem(&opaque_real_adopt_state, &slot);
	__u32 bank = r->bank;
	struct se_epoch_cell *cell = SE_EPOCH_BANK_LOOKUP(&bank);
	if (!binding || !route || !state || !cell)
		return OPAQUE_REAL_CMD_INVARIANT;
	struct se_binding_images *images =
		bpf_map_lookup_elem(&se_image_bindings, &slot);
	if (!images)
		return OPAQUE_REAL_CMD_INVARIANT;
	struct se_binding_snapshots *b = &binding->state;
	__u32 record = 0, incarnation = 0;
	int code = OPAQUE_REAL_CMD_RETRY;
	/* Review M1 follow-up: a revision keeps the published init role (the
	 * adopted tasks' root role); a change is refused, not retried. The
	 * state lock is taken alone, never nested with the route lock. */
	bpf_spin_lock(&state->lock);
	int role_kept = state->init_role == r->init_role;
	bpf_spin_unlock(&state->lock);
	if (!role_kept)
		return OPAQUE_REAL_CMD_REFUSED;
	__u64 request_uid = REAL_OWNER_REQUEST_UID(r);
	__u64 request_epoch = REAL_OWNER_REQUEST_EPOCH(r);
	bpf_spin_lock(&route->lock);
	if (route->reserved || route->unresolved_sources)
		code = OPAQUE_REAL_CMD_LATCHED;
	else if (route->phase == SE_ROUTE_ACTIVE && !route->adopting &&
		 route->scope == r->scope &&
		 route->cgroup_identity == r->cgroup &&
		 route->payload_slot == slot &&
		 b->generation == r->generation_expected && b->active_serial) {
		/* G019 limit (review L-6): a revision keeps the binding's policy
		 * UID. The binding's one epoch cell holds (scope, UID), so a new
		 * UID could never commit: refuse it, not retryable. */
		__u64 active_uid =
			b->records[b->active_record & 1].metadata.policy_uids[0];
		/* ... nor its root epoch (the binding's catalogue is
		 * write-once per (scope, UID): the commit's epoch-cell check
		 * would refuse it there, retryably; refuse it here,
		 * terminally, before anything is staged or pinned). */
		__u64 active_epoch =
			b->records[b->active_record & 1].metadata.root_epochs[0];
		if (active_uid != request_uid ||
		    active_epoch != request_epoch ||
		    route->execution_class != r->execution_class) {
			/* ... nor its class (refused here; the commit
			 * check stays as the locked backstop). */
			code = OPAQUE_REAL_CMD_REFUSED;
		} else {
			record = (b->active_record & 1) ^ 1;
			incarnation = route->incarnation;
			code = OPAQUE_REAL_CMD_OK;
		}
	}
	bpf_spin_unlock(&route->lock);
	if (code != OPAQUE_REAL_CMD_OK)
		return code;
	/* The record's previous generation retired at the last commit. */
	if (real_owner_snapshot_drop(slot, record))
		return OPAQUE_REAL_CMD_RETRY;
	struct se_pin_ticket handle = {
		.object_generation = r->object_generation,
		.object_slot = r->object_slot,
	};
	__u64 serial = 0;
	code = OPAQUE_REAL_CMD_RETRY;
	bpf_spin_lock(&route->lock);
	if (route->incarnation == incarnation &&
	    b->generation == r->generation_expected &&
	    !se_snapshot_prepare_locked(b, real_owner_record(record), &handle,
					1, r->execution_class)) {
		struct se_snapshot *candidate =
			&b->records[real_owner_record(record)];
		real_owner_metadata_copy_locked(&candidate->metadata, r);
		if (se_image_snapshot_prepare_locked(
			    images, b, real_owner_record(record))) {
			/* G020: undo the prepare; the record was FREE. Both
			 * records reference one descriptor otherwise (the
			 * revision grace period, references == 2). */
			*candidate = (struct se_snapshot){};
			code = OPAQUE_REAL_CMD_IMAGE;
		} else {
			serial = candidate->serial;
			code = OPAQUE_REAL_CMD_OK;
		}
	}
	bpf_spin_unlock(&route->lock);
	if (code == OPAQUE_REAL_CMD_IMAGE)
		real_owner_image_witness(SE_IMAGE_CLASS_PREPARE_REFUSED);
	if (code != OPAQUE_REAL_CMD_OK)
		return code;
	int epoch = -1;
	code = OPAQUE_REAL_CMD_RETRY;
	if (real_owner_snapshot_pin_seal(slot, record, serial, r->object_slot,
					 r->execution_class) ||
	    SE_PUBLISH_FAULT(1))
		goto undo;
	/* Review M1: a revision's staged object is checked exactly like a first
	 * publication's (UID, root role, class, zero epoch). */
	if (!real_owner_root_role_matches(r->object_slot, r->object_generation,
					  request_uid, r->init_role,
					  r->execution_class)) {
		code = OPAQUE_REAL_CMD_REFUSED;
		goto undo;
	}
	epoch = real_owner_epoch_bind(r->scope, request_uid, bank);
	if (epoch < 0 || SE_PUBLISH_FAULT(2))
		goto undo;
	bpf_spin_lock(&route->lock);
	code = route->incarnation == incarnation ?
		       real_owner_commit_locked(route, b, record, serial, cell,
						r, 0) :
		       OPAQUE_REAL_CMD_RETRY;
	__u64 generation = b->generation;
	bpf_spin_unlock(&route->lock);
	if (code != OPAQUE_REAL_CMD_OK)
		goto undo;
	bpf_spin_lock(&state->lock);
	state->generation = generation;
	bpf_spin_unlock(&state->lock);
	/* Revision deadlock fix (architect, step 0): the commit left the
	 * previous record RETIRING with its object pinned. Drop it now, best
	 * effort: otherwise the object stays pinned until this slot's next
	 * revision, which userspace cannot stage while every other object is
	 * held (Bindings + 1 objects). The commit preflight proved it has no
	 * claim; a refused drop is retried by the next revision's start and by
	 * withdraw/recycle. */
	(void)real_owner_snapshot_drop(slot, record ^ 1);
	return OPAQUE_REAL_CMD_OK;
undo:
	if (epoch == 1)
		se_arm_rollback_one(r->scope, request_uid, 1, cell);
	return real_owner_snapshot_abort(slot, record, serial) ?
		       OPAQUE_REAL_CMD_INVARIANT :
		       code;
}

/* G019 gap 3: opaque_real_route_drop_retired. Drops the slot's RETIRING
 * record of exactly (scope, generation) once its holders are gone (the
 * revision drops it best effort right after its commit; the agent retries
 * this while a later revision waits for the record). Codes: 0 dropped (or
 * already FREE), 1 holders remain (early claims, source pins or readers of
 * that record; retryable), 5, -1 invariant (no such RETIRING record of
 * this route, or the drop itself refused). */
struct opaque_real_route_drop_request {
	struct opaque_real_cmd_header header;
	__u32 slot, reserved;
	__u64 scope, generation;
};
_Static_assert(sizeof(struct opaque_real_route_drop_request) == 48,
	       "product drop_retired request wire");

SEC("syscall")
int opaque_real_route_drop_retired(struct opaque_real_route_drop_request *r)
{
	if (!r || !real_owner_cmd_authenticate(&r->header))
		return OPAQUE_REAL_CMD_AUTH;
	__u32 slot = r->slot;
	if (r->reserved || slot >= SE_PROFILE_BINDINGS || !r->scope ||
	    !r->generation)
		return OPAQUE_REAL_CMD_INVARIANT;
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	if (!binding || !route)
		return OPAQUE_REAL_CMD_INVARIANT;
	__u32 record = 2;
	int dropped = 0;
	bpf_spin_lock(&route->lock);
	if (route->scope == r->scope && binding->state.scope == r->scope) {
		const struct se_snapshot *s0 = &binding->state.records[0];
		const struct se_snapshot *s1 = &binding->state.records[1];
		if (s0->generation == r->generation &&
		    s0->phase == SE_SNAPSHOT_RETIRING)
			record = 0;
		else if (s1->generation == r->generation &&
			 s1->phase == SE_SNAPSHOT_RETIRING)
			record = 1;
		else
			/* Dropped already (the record was reclaimed, or reused
			 * by a later generation): no RETIRING record of it. */
			dropped = s0->generation != r->generation &&
				  s1->generation != r->generation &&
				  r->generation < binding->state.generation;
	}
	bpf_spin_unlock(&route->lock);
	if (record >= 2)
		return dropped ? OPAQUE_REAL_CMD_OK : OPAQUE_REAL_CMD_INVARIANT;
	int result = real_owner_snapshot_drop(slot, record);
	return result == 0 ? OPAQUE_REAL_CMD_OK :
	       result == 1 ? OPAQUE_REAL_CMD_RETRY :
			     OPAQUE_REAL_CMD_INVARIANT;
}

SEC("syscall")
int opaque_real_route_publish(struct opaque_real_route_publish_request *r)
{
	if (!r || !real_owner_cmd_authenticate(&r->header))
		return OPAQUE_REAL_CMD_AUTH;
	if (!real_owner_image_configured())
		return OPAQUE_REAL_CMD_UNARMED;
	if (r->reserved || r->slot >= SE_PROFILE_BINDINGS || !r->cgroup ||
	    !r->scope || r->scope == ~0ULL || r->execution_class < 1 ||
	    r->execution_class > 2 || !r->object_generation ||
	    r->object_generation == ~0ULL ||
	    r->bank >= SE_PROFILE_ACCEPTED_UIDS ||
	    !se_snapshot_metadata_valid(&r->metadata, 1,
					r->generation_expected + 1))
		return OPAQUE_REAL_CMD_RETRY;
	return r->generation_expected ? real_owner_publish_revision(r) :
					real_owner_publish_first(r);
}

/* B4: opaque_real_route_withdraw (design 3.3, 4.5). ACTIVE -> WITHDRAWN
 * (claims of a WITHDRAWN route are UNSELECTED), then outside the lock the
 * cgroup locator is unlinked and both records' tickets released and the
 * records reclaimed. Idempotent: a WITHDRAWN route of the same publication
 * only repeats the unlink and the release, so a lost acknowledgement or a
 * record still read by an in-flight exec is retried. An adopting route may
 * be withdrawn: the adoption failure path and the emptied cgroup (4.5) are
 * the agent's decision. Codes: 0 withdrawn and released, 1 retryable (early
 * claims, source pins, a record still read), 3 latched, 5, -1. */
struct opaque_real_route_withdraw_request {
	struct opaque_real_cmd_header header;
	__u64 cgroup, scope;
	__u32 slot, reserved;
};
_Static_assert(sizeof(struct opaque_real_route_withdraw_request) == 48,
	       "product withdraw request wire");

SEC("syscall")
int opaque_real_route_withdraw(struct opaque_real_route_withdraw_request *r)
{
	if (!r || !real_owner_cmd_authenticate(&r->header))
		return OPAQUE_REAL_CMD_AUTH;
	__u32 slot = r->slot;
	__u64 cgroup = r->cgroup;
	if (r->reserved || slot >= SE_PROFILE_BINDINGS || !cgroup || !r->scope)
		return OPAQUE_REAL_CMD_RETRY;
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	if (!binding || !route)
		return OPAQUE_REAL_CMD_INVARIANT;
	int code = OPAQUE_REAL_CMD_RETRY;
	__u32 incarnation = 0;
	bpf_spin_lock(&route->lock);
	if (route->scope != r->scope || route->cgroup_identity != cgroup ||
	    route->payload_slot != slot)
		code = OPAQUE_REAL_CMD_RETRY;
	else if (route->reserved || route->unresolved_sources)
		code = OPAQUE_REAL_CMD_LATCHED;
	else if (route->phase == SE_ROUTE_WITHDRAWN ||
		 (route->phase == SE_ROUTE_ACTIVE &&
		  !se_route_withdraw_locked(route, &binding->state)))
		code = OPAQUE_REAL_CMD_OK;
	incarnation = route->incarnation;
	bpf_spin_unlock(&route->lock);
	if (code != OPAQUE_REAL_CMD_OK)
		return code;
	__u64 locator = se_route_locator(slot, incarnation);
	const __u64 *have = bpf_map_lookup_elem(&se_route_index, &cgroup);
	if (have && *have == locator)
		bpf_map_delete_elem(&se_route_index, &cgroup);
	if (real_owner_snapshot_drop(slot, 0) ||
	    real_owner_snapshot_drop(slot, 1))
		return OPAQUE_REAL_CMD_RETRY;
	return OPAQUE_REAL_CMD_OK;
}

/* B4: opaque_real_route_recycle. A WITHDRAWN route whose TASK and WORK
 * accounts are empty becomes FREE (se_owk_route_recycle, the only recycle
 * adapter once WORK charges exist); then its binding is emptied, the
 * accepted-epoch cells and index entries of its scope are released, its
 * adopted set is removed, and its adoption state is cleared except
 * last_cgroup. The agent keeps the slot occupied until this returns 0.
 * Idempotent: on a FREE route (a lost acknowledgement, or an earlier
 * cleanup that did not finish) only the cleanup runs.
 * Codes: 0 FREE and clean, 1 contended (a credit is still charged) or a
 * record still retiring, 3 stale/corrupt, 6 OPAQUE_REAL_RECYCLE_UNCLEAN:
 * the route is FREE but its cleanup could not run (it is still claimed or
 * its binding still holds a record); fail-closed: the slot's next first
 * publication is refused (it requires an empty binding) and the agent
 * retries the recycle, never reuses the slot; 5, -1. */
#define OPAQUE_REAL_RECYCLE_UNCLEAN 6
struct opaque_real_route_recycle_request {
	struct opaque_real_cmd_header header;
	__u32 slot, reserved;
};
_Static_assert(sizeof(struct opaque_real_route_recycle_request) == 32,
	       "product recycle request wire");

static long real_owner_adopted_clear(struct bpf_map *map,
				     struct opaque_real_adopted_key *key,
				     struct opaque_real_adopted_value *value,
				     void *ctx)
{
	(void)value;
	if (key->slot == *(__u32 *)ctx)
		bpf_map_delete_elem(map, key);
	return 0;
}

/* The post-recycle cleanup of a FREE route, idempotent (review L-2/L-3).
 * 0 clean; -1 the route is not FREE or still claimed, or the binding still
 * holds a record: nothing is cleared and the next first publication of the
 * slot is refused (it requires an empty binding) until a retry cleans. */
static __attribute__((noinline)) int real_owner_recycle_clean(__u32 slot)
{
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	struct opaque_real_adopt_state *state =
		bpf_map_lookup_elem(&opaque_real_adopt_state, &slot);
	if (!binding || !route || !state)
		return -1;
	struct se_binding_snapshots *b = &binding->state;
	bpf_spin_lock(&route->lock);
	int clear = route->phase == SE_ROUTE_FREE && !route->early_claims &&
		    !b->records[0].phase && !b->records[1].phase &&
		    !b->active_serial && !b->inflight;
	if (clear) {
		route->adopting = 0;
		route->adopting_faults = 0;
		real_owner_binding_clear_locked(b);
	}
	bpf_spin_unlock(&route->lock);
	if (!clear)
		return -1;
	/* The publication's own scope (the route's is already reset). */
	__u64 scope = 0;
	bpf_spin_lock(&state->lock);
	scope = state->scope;
	bpf_spin_unlock(&state->lock);
	for (__u32 i = 0; i < SE_PROFILE_ACCEPTED_UIDS; i++) {
		__u32 bank = i;
		struct se_epoch_cell *cell = SE_EPOCH_BANK_LOOKUP(&bank);
		if (!cell || !scope || cell->scope != scope)
			continue;
		struct se_epoch_key key = { scope, cell->uid };
		const __u32 *have = bpf_map_lookup_elem(&se_epoch_index, &key);
		if (have && *have == bank)
			bpf_map_delete_elem(&se_epoch_index, &key);
		cell->scope = 0;
		cell->uid = 0;
		cell->epoch = 0;
	}
	bpf_for_each_map_elem(&opaque_real_adopted, real_owner_adopted_clear,
			      &slot, 0);
	bpf_spin_lock(&state->lock);
	state->adopting = 0;
	state->adopt_failed = 0;
	state->adopted = 0;
	state->iterated = 0;
	state->bad = 0;
	state->leaders = 0;
	state->incarnation = 0;
	state->generation = 0;
	state->cgroup = 0;
	state->scope = 0;
	state->init_tgid = 0;
	state->init_start_ticks = 0;
	state->init_mntns = 0;
	state->init_role = 0;
	state->quarantined = 0;
	state->missed = 0;
	state->exiting = 0;
	state->faults = 0;
	state->finishes = 0;
	state->gone = 0;
	state->recorded = 0;
	bpf_spin_unlock(&state->lock);
	return 0;
}

SEC("syscall")
int opaque_real_route_recycle(struct opaque_real_route_recycle_request *r)
{
	if (!r || !real_owner_cmd_authenticate(&r->header))
		return OPAQUE_REAL_CMD_AUTH;
	__u32 slot = r->slot;
	if (r->reserved || slot >= SE_PROFILE_BINDINGS)
		return OPAQUE_REAL_CMD_RETRY;
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	if (!binding || !route)
		return OPAQUE_REAL_CMD_INVARIANT;
	if (real_owner_snapshot_drop(slot, 0) ||
	    real_owner_snapshot_drop(slot, 1))
		return OPAQUE_REAL_CMD_RETRY;
	/* A FREE route was recycled before (a lost acknowledgement, or a
	 * cleanup that did not finish): only the idempotent cleanup runs. */
	bpf_spin_lock(&route->lock);
	int free = route->phase == SE_ROUTE_FREE;
	bpf_spin_unlock(&route->lock);
	if (!free) {
		int result = se_owk_route_recycle(slot, &binding->state);
		if (result == SE_OL_CONTENDED)
			return OPAQUE_REAL_CMD_RETRY;
		if (result != SE_OL_OK)
			return OPAQUE_REAL_CMD_LATCHED;
	}
	return real_owner_recycle_clean(slot) ? OPAQUE_REAL_RECYCLE_UNCLEAN :
						OPAQUE_REAL_CMD_OK;
}

/* B5: root-task adoption (design 4 and 13). Cursor-shaped, with the route's
 * adopting marker held across every run:
 *   opaque_real_adopt_verify  (syscall.s) one css-iterator pass over the
 *     cgroup: one tgid (the init's), one leader whose start time in clock
 *     ticks equals the published one, the init's mount namespace, the
 *     cgroup itself, nobody exiting, count <= the TASK quota;
 *   opaque_real_adopt_task    (syscall) one tid per run, under
 *     bpf_task_from_pid's reference: the same predicate, then charge +
 *     publish (the adoption's own route claim, which the adopting marker
 *     does not fault) + qualify, recorded in opaque_real_adopted;
 *   opaque_real_adopt_finish  (syscall.s) every task of the cgroup is in
 *     the adopted set with the recorded locator, none exiting, iterated ==
 *     adopted, no claim faulted during the adoption; then the marker is
 *     cleared under the route lock;
 *   opaque_real_adopt_quarantine (syscall) every adopted entry of the
 *     slot, in one run.
 * Every command checks, under the route lock and then the state lock, that
 * the route is ACTIVE and adopting, and that its incarnation, generation,
 * slot and cgroup are the ones captured at publish. Any mismatch, and any
 * failure after a charge, latches adopt_failed (only recycle clears it).
 * Codes: 0 ok, 1 retryable / not found (adopt_task: the tid is gone), 2
 * refused (terminal for this adoption: quarantine follows), 5 auth, -1
 * invariant. */
#define OPAQUE_REAL_PF_EXITING 0x00000004
#define OPAQUE_REAL_TICK_NS (1000000000ULL / 100) /* USER_HZ */
extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;
extern struct cgroup *bpf_cgroup_from_id(__u64 id) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgroup) __ksym;
extern int bpf_iter_css_task_new(struct bpf_iter_css_task *,
				 struct cgroup_subsys_state *,
				 unsigned int) __ksym;
extern struct task_struct *
bpf_iter_css_task_next(struct bpf_iter_css_task *) __ksym;
extern void bpf_iter_css_task_destroy(struct bpf_iter_css_task *) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

struct opaque_real_adopt_request {
	struct opaque_real_cmd_header header;
	__u64 cgroup;
	__u32 slot, tid;
};
_Static_assert(sizeof(struct opaque_real_adopt_request) == 40,
	       "product adoption request wire");

/* The init roles of an adopted task (design 3.1): one known row for the
 * ACTIVE snapshot's policy UID at its root epoch with the published init
 * role. Per CPU: an er_work does not fit the stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct er_work);
} opaque_real_adopt_roles SEC(".maps");

static __always_inline void
real_owner_adopt_fail(struct opaque_real_adopt_state *state)
{
	bpf_spin_lock(&state->lock);
	state->adopt_failed = 1;
	bpf_spin_unlock(&state->lock);
}

/* The 13.2 check. 0 live, 2 refused (and adopt_failed latched). */
static __attribute__((noinline)) int real_owner_adopt_live(__u32 slot,
							   __u64 cgroup)
{
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	struct opaque_real_adopt_state *state =
		bpf_map_lookup_elem(&opaque_real_adopt_state, &slot);
	if (!route || !state)
		return OPAQUE_REAL_CMD_INVARIANT;
	bpf_spin_lock(&route->lock);
	int live = route->phase == SE_ROUTE_ACTIVE && route->adopting == 1 &&
		   route->cgroup_identity == cgroup &&
		   route->payload_slot == slot;
	__u32 incarnation = route->incarnation;
	__u64 generation = route->payload_generation;
	bpf_spin_unlock(&route->lock);
	bpf_spin_lock(&state->lock);
	live = live && state->adopting == 1 && !state->adopt_failed &&
	       state->incarnation == incarnation &&
	       state->generation == generation && state->cgroup == cgroup;
	if (!live)
		state->adopt_failed = 1;
	bpf_spin_unlock(&state->lock);
	return live ? OPAQUE_REAL_CMD_OK : OPAQUE_REAL_CMD_REFUSED;
}

/* Pass-1/2 predicate on one task whose reference the caller holds (or
 * under bpf_rcu_read_lock in the iterator). 0 matches; *leader set for the
 * thread-group leader. */
static __always_inline int
real_owner_adopt_identity(struct task_struct *task,
			  const struct opaque_real_adopt_state *state,
			  __u32 *leader)
{
	/* Each destination has its field's exact width: BPF_CORE_READ_INTO reads
	 * sizeof(*dst) bytes, so a __u64 for the 4-byte ns_common.inum also read
	 * the next field and no mount namespace ever matched (chain13: every
	 * adoption refused as AdoptionIdentity). Pinned by
	 * TestProductPublisherSourcePins. */
	__u32 tgid = 0, pid = 0, flags = 0, inum = 0;
	__u64 cgroup = 0, start = 0;
	if (!task || BPF_CORE_READ_INTO(&tgid, task, tgid) ||
	    BPF_CORE_READ_INTO(&pid, task, pid) ||
	    BPF_CORE_READ_INTO(&flags, task, flags) ||
	    (flags & OPAQUE_REAL_PF_EXITING) ||
	    BPF_CORE_READ_INTO(&cgroup, task, cgroups, dfl_cgrp, kn, id) ||
	    BPF_CORE_READ_INTO(&inum, task, nsproxy, mnt_ns, ns.inum))
		return 1;
	if (tgid != state->init_tgid || cgroup != state->cgroup || !inum ||
	    (__u64)inum != state->init_mntns)
		return 1;
	if (pid == tgid) {
		if (BPF_CORE_READ_INTO(&start, task, start_boottime) ||
		    start / OPAQUE_REAL_TICK_NS != state->init_start_ticks)
			return 1;
		*leader = 1;
	}
	return 0;
}

SEC("syscall.s")
int opaque_real_adopt_verify(struct opaque_real_adopt_request *r)
{
	if (!r || !real_owner_cmd_authenticate(&r->header))
		return OPAQUE_REAL_CMD_AUTH;
	if (!real_owner_image_configured())
		return OPAQUE_REAL_CMD_UNARMED;
	__u32 slot = r->slot;
	if (slot >= SE_PROFILE_BINDINGS)
		return OPAQUE_REAL_CMD_RETRY;
	int live = real_owner_adopt_live(slot, r->cgroup);
	if (live != OPAQUE_REAL_CMD_OK)
		return live;
	struct opaque_real_adopt_state *state =
		bpf_map_lookup_elem(&opaque_real_adopt_state, &slot);
	if (!state)
		return OPAQUE_REAL_CMD_INVARIANT;
	state->iterated = 0;
	state->bad = 0;
	state->leaders = 0;
	state->exiting = 0;
	struct cgroup *group = bpf_cgroup_from_id(r->cgroup);
	if (!group) {
		real_owner_adopt_fail(state);
		return OPAQUE_REAL_CMD_REFUSED;
	}
	struct bpf_iter_css_task it;
	struct task_struct *task;
	int started = bpf_iter_css_task_new(&it, &group->self, 0) == 0;
	bpf_rcu_read_lock();
	while (started && (task = bpf_iter_css_task_next(&it))) {
		__u32 leader = 0, flags = 0;
		__sync_fetch_and_add(&state->iterated, 1);
		/* A task already exiting is a mismatch (refused) and is also
		 * counted apart, as finish does: the agent reports a refusal
		 * whose every mismatch is an exiting task (bad == exiting) as
		 * AdoptionThreadExited, any other as AdoptionIdentity. */
		if (!BPF_CORE_READ_INTO(&flags, task, flags) &&
		    (flags & OPAQUE_REAL_PF_EXITING)) {
			/* Only a thread of the init's own process counts as
			 * exiting; a foreign exiting task is a plain mismatch
			 * (reported as Identity, review L1). */
			__u32 tgid = 0;
			if (!BPF_CORE_READ_INTO(&tgid, task, tgid) &&
			    tgid == state->init_tgid)
				__sync_fetch_and_add(&state->exiting, 1);
			__sync_fetch_and_add(&state->bad, 1);
		} else if (real_owner_adopt_identity(task, state, &leader)) {
			__sync_fetch_and_add(&state->bad, 1);
		}
		if (leader)
			__sync_fetch_and_add(&state->leaders, 1);
	}
	bpf_rcu_read_unlock();
	bpf_iter_css_task_destroy(&it);
	bpf_cgroup_release(group);
	if (!started || state->bad || !state->iterated ||
	    state->iterated > SE_PROFILE_TASK_QUOTA || state->leaders != 1) {
		real_owner_adopt_fail(state);
		return OPAQUE_REAL_CMD_REFUSED;
	}
	return OPAQUE_REAL_CMD_OK;
}

/* The adoption's own route claim: the exact claim_locked transition
 * without the adopting fault, only for the adopting route of this slot. */
static __attribute__((noinline)) int
real_owner_adopt_claim(__u32 slot, __u64 cgroup, struct se_route_claim *c)
{
	struct se_route_anchor *a = SE_ROUTE_LOOKUP(&slot);
	if (!a || !c)
		return -1;
	int result = -1;
	bpf_spin_lock(&a->lock);
	if (a->phase == SE_ROUTE_ACTIVE && a->adopting == 1 &&
	    a->active_record < 2 && a->cgroup_identity == cgroup &&
	    a->payload_slot == slot && a->incarnation &&
	    a->execution_class >= 1 && a->execution_class <= 2 && !c->owned &&
	    !a->reserved && a->early_claims != (__u32)~0U &&
	    a->admission_serial < ~0ULL - 1) {
		a->early_claims++;
		SE_ROUTE_REC_ADD(a, a->active_record, early_claims, 1);
		a->admission_serial++;
		*c = (struct se_route_claim){
			.scope = a->scope,
			.serial = a->active_serial,
			.generation = a->payload_generation,
			.admission_serial = a->admission_serial,
			.incarnation = a->incarnation,
			.record = a->active_record,
			.execution_class = a->execution_class,
			.owned = 1,
			.slot = a->payload_slot
		};
		result = 0;
	}
	bpf_spin_unlock(&a->lock);
	return result;
}

/* Charge + publish one referenced task under the adoption claim (released
 * here on every path). 0 published and the claim released; 1 the charge or
 * publication failed or the claim release failed (a TASK may exist: the
 * caller still opens and records it); -1 no claim, nothing charged. */
static __attribute__((noinline)) int
real_owner_adopt_publish(struct task_struct *task, __u32 slot, __u64 cgroup,
			 __u64 *scope)
{
	__u32 zero = 0;
	struct er_work *roles =
		bpf_map_lookup_elem(&opaque_real_adopt_roles, &zero);
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct opaque_real_adopt_state *state =
		bpf_map_lookup_elem(&opaque_real_adopt_state, &slot);
	if (!roles || !binding || !state)
		return -1;
	struct se_route_claim claim = {};
	if (real_owner_adopt_claim(slot, cgroup, &claim))
		return -1;
	const struct se_snapshot *snapshot =
		&binding->state.records[claim.record & 1];
	__builtin_memset(roles, 0, sizeof(*roles));
	roles->authority_version = 1;
	roles->prepared = 1;
	roles->rows[0].uid = snapshot->metadata.policy_uids[0];
	roles->rows[0].epoch = snapshot->metadata.root_epochs[0];
	roles->rows[0].role = state->init_role;
	roles->rows[0].knowledge = ER_ROLE_KNOWN;
	struct se_oc_reservation res = {};
	int status = se_op_prepare_charged_child(&claim, &res);
	if (status == SE_OL_OK) {
		struct task_struct *key = task;
		status = se_op_publish_charged_child(&claim, snapshot, roles,
						     &key, &res);
	}
	*scope = claim.scope;
	int released = real_owner_child_release_claim(&claim);
	return status == SE_OL_OK && !released ? 0 : 1;
}

/* Open the adopted TASK by key: report its lease cookie and locator and
 * qualify it with the birth path's checks (design 13.6). 0 qualified, 1
 * open but not qualified (cookie/locator valid), -1 no TASK to record. */
static __attribute__((noinline)) int
real_owner_adopt_qualify(__u64 key, __u64 scope, __u32 slot, __u64 *cookie,
			 __u64 *locator)
{
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&key, &owner) != SE_OL_OK)
		return -1;
	const __u64 *directory = bpf_map_lookup_elem(&se_opaque_keys, &key);
	int result = 1;
	*cookie = owner.lease.cookie;
	*locator = owner.lease.locator;
	struct se_task_state *t = 0;
	if (se_op_task_semantic_begin(&owner, &t) == SE_OL_OK) {
		if (!owner.lease.meta->cleanup_error && directory &&
		    *directory == owner.lease.locator &&
		    t->physical_cookie == owner.lease.cookie &&
		    t->flags == SE_TASK_LIVE && t->scope_cookie == scope &&
		    t->scope_slot == slot && t->committed.version &&
		    !t->exec.owned && !t->reader.owned && !t->next_invocation) {
			t->flags = SE_TASK_QUALIFIED;
			result = 0;
		}
		se_op_task_semantic_end(&owner, &t);
	}
	if (se_ol_payload_close(&owner) != SE_OL_OK)
		result = 1;
	return result;
}

SEC("syscall")
int opaque_real_adopt_task(struct opaque_real_adopt_request *r)
{
	if (!r || !real_owner_cmd_authenticate(&r->header))
		return OPAQUE_REAL_CMD_AUTH;
	__u32 slot = r->slot;
	__u64 cgroup = r->cgroup;
	if (slot >= SE_PROFILE_BINDINGS)
		return OPAQUE_REAL_CMD_RETRY;
	int live = real_owner_adopt_live(slot, cgroup);
	if (live != OPAQUE_REAL_CMD_OK)
		return live;
	struct opaque_real_adopt_state *state =
		bpf_map_lookup_elem(&opaque_real_adopt_state, &slot);
	if (!state)
		return OPAQUE_REAL_CMD_INVARIANT;
	if (!r->tid) {
		real_owner_adopt_fail(state);
		return OPAQUE_REAL_CMD_REFUSED;
	}
	struct task_struct *task = bpf_task_from_pid(r->tid);
	if (!task)
		return OPAQUE_REAL_CMD_RETRY;
	__u32 leader = 0;
	__u64 cookie = 0, locator = 0, scope = 0;
	int published = -1, qualified = -1;
	if (!real_owner_adopt_identity(task, state, &leader))
		published =
			real_owner_adopt_publish(task, slot, cgroup, &scope);
	/* Every TASK that may exist after a charge attempt is recorded, so the
	 * quarantine covers each published adopted TASK (review M-5): opened,
	 * with its exact cookie and locator; or present in the directory but
	 * not openable, with cookie 0 (quarantine then counts it missed: the
	 * slot stays latched, fail-closed; the unqualified LIVE TASK can
	 * neither fork nor exec in Strict). */
	if (published >= 0) {
		__u64 physical = (__u64)task;
		qualified = real_owner_adopt_qualify(physical, scope, slot,
						     &cookie, &locator);
		if (qualified < 0) {
			const __u64 *directory =
				bpf_map_lookup_elem(&se_opaque_keys, &physical);
			if (directory) {
				cookie = 0;
				locator = *directory;
				qualified = 1;
			}
		}
	}
	int code = OPAQUE_REAL_CMD_REFUSED;
	if (qualified >= 0) {
		struct opaque_real_adopted_key key = { .task = (__u64)task,
						       .slot = slot };
		struct opaque_real_adopted_value value = { .cookie = cookie,
							   .locator = locator };
		/* Per-slot cap (review L-4): the set is shared by every binding
		 * and sized Bindings x quota; one slot records at most its
		 * quota. */
		__u32 recorded = __sync_fetch_and_add(&state->recorded, 1);
		if (recorded >= SE_PROFILE_TASK_QUOTA ||
		    bpf_map_update_elem(&opaque_real_adopted, &key, &value,
					BPF_NOEXIST)) {
			/* Unrecordable: never leave it usable. */
			if (cookie)
				(void)real_owner_birth_quarantine(
					(__u64)task, cookie, locator);
		} else if (!published && !qualified) {
			__sync_fetch_and_add(&state->adopted, 1);
			code = OPAQUE_REAL_CMD_OK;
		}
	}
	bpf_task_release(task);
	if (code != OPAQUE_REAL_CMD_OK)
		real_owner_adopt_fail(state);
	return code;
}

SEC("syscall.s")
int opaque_real_adopt_finish(struct opaque_real_adopt_request *r)
{
	if (!r || !real_owner_cmd_authenticate(&r->header))
		return OPAQUE_REAL_CMD_AUTH;
	__u32 slot = r->slot;
	__u64 cgroup = r->cgroup;
	if (slot >= SE_PROFILE_BINDINGS)
		return OPAQUE_REAL_CMD_RETRY;
	int live = real_owner_adopt_live(slot, cgroup);
	if (live != OPAQUE_REAL_CMD_OK)
		return live;
	struct opaque_real_adopt_state *state =
		bpf_map_lookup_elem(&opaque_real_adopt_state, &slot);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	if (!state || !route)
		return OPAQUE_REAL_CMD_INVARIANT;
	/* L-7: one finish run past the live check; the agent reads its detail
	 * (iterated, adopted, exiting) only if this advanced by exactly 1. */
	__sync_fetch_and_add(&state->finishes, 1);
	state->iterated = 0;
	state->bad = 0;
	state->exiting = 0;
	struct cgroup *group = bpf_cgroup_from_id(cgroup);
	if (!group) {
		real_owner_adopt_fail(state);
		return OPAQUE_REAL_CMD_REFUSED;
	}
	struct bpf_iter_css_task it;
	struct task_struct *task;
	int started = bpf_iter_css_task_new(&it, &group->self, 0) == 0;
	bpf_rcu_read_lock();
	while (started && (task = bpf_iter_css_task_next(&it))) {
		__u32 flags = 0;
		struct opaque_real_adopted_key key = { .task = (__u64)task,
						       .slot = slot };
		__u64 physical = (__u64)task;
		__sync_fetch_and_add(&state->iterated, 1);
		const struct opaque_real_adopted_value *want =
			bpf_map_lookup_elem(&opaque_real_adopted, &key);
		const __u64 *have =
			bpf_map_lookup_elem(&se_opaque_keys, &physical);
		int unreadable = BPF_CORE_READ_INTO(&flags, task, flags);
		if (!unreadable && (flags & OPAQUE_REAL_PF_EXITING)) {
			/* As in verify: only the init's own exiting threads
			 * count as exiting; any exiting task is bad. */
			__u32 tgid = 0;
			if (!BPF_CORE_READ_INTO(&tgid, task, tgid) &&
			    tgid == state->init_tgid)
				__sync_fetch_and_add(&state->exiting, 1);
		}
		if (unreadable || (flags & OPAQUE_REAL_PF_EXITING) || !want ||
		    !have || *have != want->locator)
			__sync_fetch_and_add(&state->bad, 1);
	}
	bpf_rcu_read_unlock();
	bpf_iter_css_task_destroy(&it);
	bpf_cgroup_release(group);
	if (!started || state->bad || !state->iterated ||
	    state->iterated != state->adopted || !state->scope) {
		real_owner_adopt_fail(state);
		return OPAQUE_REAL_CMD_REFUSED;
	}
	/* H1: the binding's root anchor, read from the init leader (looked
	 * up outside the iteration: one task, no per-iteration state). */
	struct se_binding_root anchor = { .init_tgid = state->init_tgid,
					  .init_start =
						  state->init_start_ticks };
	struct task_struct *init = bpf_task_from_pid(state->init_tgid);
	__u32 leader = 0;
	int rooted = init && !real_owner_adopt_identity(init, state, &leader) &&
		     leader &&
		     !real_owner_task_root(init, &anchor.root_ino,
					   &anchor.root_mnt_id,
					   &anchor.root_dev, &anchor.mntns) &&
		     anchor.mntns == state->init_mntns;
	if (init)
		bpf_task_release(init);
	if (!rooted) {
		real_owner_adopt_fail(state);
		return OPAQUE_REAL_CMD_REFUSED;
	}
	/* H1: record the anchor before the adopting word clears (no claim
	 * of this binding is evaluated earlier); scope last, so an exec
	 * reader never takes a half-written record for this binding. */
	struct se_binding_root *root =
		bpf_map_lookup_elem(&se_binding_roots, &slot);
	if (!root) {
		real_owner_adopt_fail(state);
		return OPAQUE_REAL_CMD_INVARIANT;
	}
	root->scope = 0;
	asm volatile("" ::: "memory");
	root->init_start = anchor.init_start;
	root->root_ino = anchor.root_ino;
	root->init_tgid = anchor.init_tgid;
	root->mntns = anchor.mntns;
	root->root_mnt_id = anchor.root_mnt_id;
	root->root_dev = anchor.root_dev;
	asm volatile("" ::: "memory");
	root->scope = state->scope;
	bpf_spin_lock(&state->lock);
	__u32 incarnation = state->incarnation;
	__u64 generation = state->generation;
	int ok = state->adopting == 1 && !state->adopt_failed;
	bpf_spin_unlock(&state->lock);
	int cleared = 0;
	__u32 faults = 0;
	bpf_spin_lock(&route->lock);
	faults = route->adopting_faults;
	if (ok && route->phase == SE_ROUTE_ACTIVE && route->adopting == 1 &&
	    !route->adopting_faults && route->incarnation == incarnation &&
	    route->payload_generation == generation &&
	    route->cgroup_identity == cgroup && route->payload_slot == slot) {
		route->adopting = 0;
		cleared = 1;
	}
	bpf_spin_unlock(&route->lock);
	bpf_spin_lock(&state->lock);
	state->faults = faults;
	if (cleared)
		state->adopting = 0;
	else
		state->adopt_failed = 1;
	bpf_spin_unlock(&state->lock);
	return cleared ? OPAQUE_REAL_CMD_OK : OPAQUE_REAL_CMD_REFUSED;
}

/* Quarantine every adopted entry of this slot in one run (design 13.6;
 * BPF programs have no map get-next-key helper, so the walk is one
 * bpf_for_each_map_elem over the adopted set, verified once). Each entry
 * goes through real_owner_birth_quarantine: QUARANTINED set, LIVE kept, the
 * exact generation only. Quarantining latches adopt_failed: a quarantined
 * adoption never finishes. Each entry is counted once (review I-3):
 *   gone:   no se_opaque_keys entry at its address: credit at exit already
 *           withdrew the TASK (the thread exited), nothing is left to mark;
 *   marked: QUARANTINED;
 *   missed: a TASK is present at the address but is not the recorded one
 *           (another cookie or locator, an unopenable TASK, a semantic
 *           failure): it could not be marked.
 * 0 no entry missed (marked and gone only), 1 at least one missed (the
 * agent retries, then latches the slot), 2 not adopting this cgroup. */
struct real_owner_quarantine_walk {
	__u32 slot, marked, missed, gone;
};
static long
real_owner_adopted_quarantine(struct bpf_map *map,
			      struct opaque_real_adopted_key *key,
			      struct opaque_real_adopted_value *value,
			      struct real_owner_quarantine_walk *walk)
{
	(void)map;
	if (key->slot != walk->slot)
		return 0;
	__u64 physical = key->task;
	if (!bpf_map_lookup_elem(&se_opaque_keys, &physical))
		walk->gone++;
	else if (real_owner_birth_quarantine(key->task, value->cookie,
					     value->locator))
		walk->missed++;
	else
		walk->marked++;
	return 0;
}

SEC("syscall")
int opaque_real_adopt_quarantine(struct opaque_real_adopt_request *r)
{
	if (!r || !real_owner_cmd_authenticate(&r->header))
		return OPAQUE_REAL_CMD_AUTH;
	__u32 slot = r->slot;
	if (slot >= SE_PROFILE_BINDINGS)
		return OPAQUE_REAL_CMD_RETRY;
	struct opaque_real_adopt_state *state =
		bpf_map_lookup_elem(&opaque_real_adopt_state, &slot);
	if (!state)
		return OPAQUE_REAL_CMD_INVARIANT;
	bpf_spin_lock(&state->lock);
	int adopting = state->adopting == 1 && state->cgroup == r->cgroup;
	if (adopting)
		state->adopt_failed = 1;
	bpf_spin_unlock(&state->lock);
	if (!adopting)
		return OPAQUE_REAL_CMD_REFUSED;
	struct real_owner_quarantine_walk walk = { .slot = slot };
	bpf_for_each_map_elem(&opaque_real_adopted,
			      real_owner_adopted_quarantine, &walk, 0);
	bpf_spin_lock(&state->lock);
	state->quarantined = walk.marked;
	state->missed = walk.missed;
	state->gone = walk.gone;
	bpf_spin_unlock(&state->lock);
	return walk.missed ? OPAQUE_REAL_CMD_RETRY : OPAQUE_REAL_CMD_OK;
}

#endif
