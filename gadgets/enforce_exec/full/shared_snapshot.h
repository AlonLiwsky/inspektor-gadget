/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ENFORCE_EXEC_SHARED_SNAPSHOT_H
#define ENFORCE_EXEC_SHARED_SNAPSHOT_H
#include "shared_arena.h"

#define SE_SNAPSHOT_FREE 0
#define SE_SNAPSHOT_PREPARING 1
#define SE_SNAPSHOT_PREPARED 2
#define SE_SNAPSHOT_ACTIVE 3
#define SE_SNAPSHOT_RETIRING 4
#define SE_TICKET_EMPTY 0
#define SE_TICKET_HELD 1
#define SE_TICKET_RELEASED 2
#define SE_COMMAND_PIN 1
#define SE_COMMAND_RELEASE 2
#define SE_COMMAND_INSPECT 3

struct se_pin_ticket {
	__u64 scope, snapshot_serial, object_generation;
	__u32 position, object_slot, phase, reserved;
};
/* Scoped factual metadata is not part of a deduplicated compiled object.
 * PREPARE supplies it, Commit authenticates epochs/image authority; immutable
 * once PREPARED. It never certifies successful history by itself. */
/* G020: image_handle names the binding's sealed image index descriptor
 * (shared_image.h) and image_dev is the container root overlay's kernel
 * dev_t (MKDEV(0, minor), super_block->s_dev); both zero without an index.
 * The product publisher references the descriptor at PREPARE and releases
 * it when the record is reclaimed (full/shared_image_snapshot.h). */
struct se_snapshot_metadata {
	__u64 root_epochs[8], policy_uids[8], image_handle;
	__u32 role_writers, required_known, container_length;
	unsigned char container[256];
	__u32 image_dev;
};
_Static_assert(sizeof(struct se_snapshot_metadata) == 408,
	       "scoped metadata wire");
struct se_snapshot {
	__u64 scope, serial, command_sequence, generation;
	__u32 phase, count, claims, commands, execution_class, reserved;
	struct se_pin_ticket tickets[8];
	struct se_snapshot_metadata metadata;
};
/* Exactly two records and sixteen tickets. No release outbox or dynamic queue.
 * A single command per record is intentionally serialized; exec claims are
 * independent. This gives exact replay-resistant lifetime ownership without
 * adding a command-token registry. Different records/bindings remain independent.
 */
struct se_binding_snapshots {
	__u64 scope, next_serial, next_command;
	__u64 generation, admission_serial, next_reader, active_serial;
	__u32 active_record, inflight;
	struct se_snapshot records[2];
};
struct se_snapshot_command {
	__u64 scope, serial, sequence;
	__u32 record, kind, owned, reserved;
};

static __attribute__((always_inline)) inline int
se_snapshot_metadata_valid(const struct se_snapshot_metadata *m, __u32 count,
			   __u64 generation)
{
	if (!count || count > 8 || !generation || generation == ~0ULL ||
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	    /* G020: a handle names exactly one anonymous overlay (major 0). */
	    !m->image_handle != !m->image_dev || (m->image_dev >> 20) ||
#else
	    /* No image index outside the product publisher: the former
	     * reserved word stays zero (IDENT objects unchanged). */
	    m->image_dev ||
#endif
	    !m->container_length || m->container_length > 255 ||
	    ((m->role_writers | m->required_known) >> count))
		return 0;
	for (__u32 i = 0; i < 8; i++) {
		if (i < count) {
			if (!m->root_epochs[i] ||
			    m->root_epochs[i] > generation ||
			    !m->policy_uids[i])
				return 0;
			for (__u32 j = 0; j < i; j++)
				if (m->policy_uids[j] == m->policy_uids[i])
					return 0;
		} else if (m->root_epochs[i] || m->policy_uids[i])
			return 0;
	}
	return 1;
}
/* Binding lock held. Handles are fully validated before any persistent store. */
/* Called while holding the original route lock. Older kernels reject BPF
 * subprogram calls from that lexical region, even when Clang chose not to
 * inline an ordinary static inline as the surrounding image grew. */
static __attribute__((always_inline)) inline int
se_snapshot_prepare_locked(struct se_binding_snapshots *b, __u32 record,
			   const struct se_pin_ticket *handles, __u32 count,
			   __u32 execution_class)
{
	if (!b->scope || record >= 2 || !count || count > 8 ||
	    b->next_serial >= ~0ULL - 1 || execution_class < 1 ||
	    execution_class > 2)
		return -1;
	struct se_snapshot *s = &b->records[record];
	const struct se_snapshot *other = &b->records[record ^ 1];
	if (other->phase != SE_SNAPSHOT_FREE &&
	    other->phase != SE_SNAPSHOT_ACTIVE)
		return -1;
	if (s->phase != SE_SNAPSHOT_FREE || s->commands || s->claims)
		return -1;
		/* Literal ticket offsets keep older verifiers inside the two-record map. */
#ifdef __clang__
#pragma unroll
#endif
	for (__u32 i = 0; i < 8; i++) {
		if (i >= count)
			continue;
		if (!handles[i].object_generation ||
		    handles[i].object_generation == ~0ULL)
			return -1;
	}
	*s = (struct se_snapshot){ .scope = b->scope,
				   .serial = ++b->next_serial,
				   .phase = SE_SNAPSHOT_PREPARING,
				   .count = count,
				   .execution_class = execution_class };
#ifdef __clang__
#pragma unroll
#endif
	for (__u32 i = 0; i < 8; i++) {
		if (i >= count)
			continue;
		s->tickets[i] = (struct se_pin_ticket){
			.scope = s->scope,
			.snapshot_serial = s->serial,
			.object_generation = handles[i].object_generation,
			.object_slot = handles[i].object_slot,
			.position = i
		};
	}
	return 0;
}
/* Acquire BEFORE retaining a record/ticket pointer outside the binding lock,
 * including retries, release and receipt inspection. RETIRING excludes PIN.
 * Product publisher: RELEASE also requires a record without holders (no
 * reader claim), so a ticket release can never take a reader's object away
 * (claims cannot grow on a RETIRING record: readers acquire ACTIVE only).
 */
static __attribute__((always_inline)) inline int
se_snapshot_command_begin_locked(struct se_binding_snapshots *b, __u32 record,
				 __u64 scope, __u64 serial, __u32 kind,
				 struct se_snapshot_command *c)
{
	if (record >= 2 || !scope || !serial || scope != b->scope || c->owned ||
	    kind < SE_COMMAND_PIN || kind > SE_COMMAND_INSPECT ||
	    b->next_command >= ~0ULL - 1)
		return -1;
	struct se_snapshot *s = &b->records[record];
	if (s->scope != scope || s->serial != serial ||
	    s->phase == SE_SNAPSHOT_FREE || s->phase > SE_SNAPSHOT_RETIRING ||
	    s->commands ||
	    (kind == SE_COMMAND_PIN && s->phase != SE_SNAPSHOT_PREPARING) ||
	    (kind == SE_COMMAND_RELEASE && s->phase != SE_SNAPSHOT_RETIRING))
		return -1;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	if (kind == SE_COMMAND_RELEASE && s->claims)
		return -1;
#endif
	s->commands = 1;
	s->command_sequence = ++b->next_command;
	*c = (struct se_snapshot_command){ .scope = scope,
					   .serial = serial,
					   .sequence = s->command_sequence,
					   .record = record,
					   .kind = kind,
					   .owned = 1 };
	return 0;
}
/* Caller consumed every record/ticket access and copied receipt to local memory
 * BEFORE this call; after it, only the local receipt/token may be touched. */
static __attribute__((always_inline)) inline int
se_snapshot_command_end_locked(struct se_binding_snapshots *b,
			       struct se_snapshot_command *c)
{
	if (!c->owned || c->reserved || c->record >= 2 || c->scope != b->scope)
		return -1;
	struct se_snapshot *s = &b->records[c->record];
	if (s->scope != c->scope || s->serial != c->serial ||
	    s->commands != 1 || !c->sequence ||
	    s->command_sequence != c->sequence)
		return -1;
	s->commands = 0;
	s->command_sequence = 0;
	c->owned = 0;
	return 0;
}
/* Object lock ONLY, with an already-owned snapshot command spanning this call.
 * The caller supplies the selected ticket pointer from that stable record. */
static __attribute__((always_inline)) inline int
se_ticket_pin_locked(struct se_object *o, struct se_pin_ticket *t,
		     const struct se_snapshot_command *c, __u32 position)
{
	if (!c->owned || c->kind != SE_COMMAND_PIN || c->reserved ||
	    position >= 8 || t->scope != c->scope ||
	    t->snapshot_serial != c->serial || t->position != position ||
	    t->reserved || o->slot != t->object_slot ||
	    o->generation != t->object_generation ||
	    o->phase != SE_OBJECT_READY)
		return -1;
	if (t->phase == SE_TICKET_HELD)
		return 0;
	if (t->phase != SE_TICKET_EMPTY || o->pins == (__u32)~0U)
		return -1;
	o->pins++;
	t->phase = SE_TICKET_HELD;
	return 0;
}
static __attribute__((always_inline)) inline int
se_ticket_release_locked(struct se_object *o, struct se_pin_ticket *t,
			 const struct se_snapshot_command *c, __u32 position)
{
	if (!c->owned || c->kind != SE_COMMAND_RELEASE || c->reserved ||
	    position >= 8 || t->scope != c->scope ||
	    t->snapshot_serial != c->serial || t->position != position ||
	    t->reserved || o->slot != t->object_slot)
		return -1;
	/* The stable receipt remains authoritative even if the unpinned object has
     * since retired/reused. Never touch its new pin count on duplicate release. */
	if (t->phase == SE_TICKET_RELEASED)
		return 0;
	if (t->phase != SE_TICKET_HELD ||
	    o->generation != t->object_generation ||
	    o->phase != SE_OBJECT_READY || !o->pins)
		return -1;
	o->pins--;
	t->phase = SE_TICKET_RELEASED;
	return 0;
}
static __attribute__((always_inline)) inline int
se_snapshot_prepared_locked(struct se_snapshot *s)
{
	__u32 count = s->count;
	if (s->phase != SE_SNAPSHOT_PREPARING || s->commands || !count ||
	    count > 8)
		return -1;
#ifdef __clang__
#pragma unroll
#endif
	for (__u32 i = 0; i < 8; i++) {
		if (i >= count)
			continue;
		if (s->tickets[i].phase != SE_TICKET_HELD)
			return -1;
	}
	s->phase = SE_SNAPSHOT_PREPARED;
	return 0;
}
/* Abort only an uncommitted candidate. ACTIVE retirement is exclusively the
 * binding-level Commit/Remove transition with all admission counts checked. */
static __attribute__((always_inline)) inline int
se_snapshot_retire_locked(struct se_snapshot *s)
{
	if (s->phase < SE_SNAPSHOT_PREPARING ||
	    s->phase > SE_SNAPSHOT_PREPARED || s->commands || s->claims)
		return -1;
	s->phase = SE_SNAPSHOT_RETIRING;
	return 0;
}
static __attribute__((always_inline)) inline int
se_snapshot_reclaim_locked(struct se_snapshot *s)
{
	__u32 count = s->count;
	if (s->phase != SE_SNAPSHOT_RETIRING || s->commands || s->claims ||
	    count > 8)
		return -1;
#ifdef __clang__
#pragma unroll
#endif
	for (__u32 i = 0; i < 8; i++) {
		if (i >= count)
			continue;
		if (s->tickets[i].phase != SE_TICKET_EMPTY &&
		    s->tickets[i].phase != SE_TICKET_RELEASED)
			return -1;
	}
	*s = (struct se_snapshot){};
	return 0;
}

/* The adapter keeps the binding lock from this complete preflight, across all
 * prevalidated accepted-epoch stores, through publish. No map lookups, task
 * locks, helpers or fallible operations may enter that irreversible block.
 * Inventory/epoch-target validation is additionally required by the adapter;
 * this primitive proves only snapshot/pin/admission preconditions.
 */
static __attribute__((always_inline)) inline int
se_binding_commit_preflight_locked(struct se_binding_snapshots *b, __u32 record,
				   __u64 serial, __u64 expected_generation,
				   __u64 qualification_serial)
{
	if (record >= 2 || !b->scope || !serial ||
	    b->generation != expected_generation ||
	    b->generation >= ~0ULL - 1 ||
	    b->admission_serial != qualification_serial ||
	    b->admission_serial >= ~0ULL - 1 || b->inflight)
		return -1;
	struct se_snapshot *s = &b->records[record];
	/* Copy the pin count before the loop. Reloading it from the map lets
	 * the verifier treat the trip count as unbounded and walk off tickets. */
	__u32 n = s->count;
	if (s->scope != b->scope || s->serial != serial ||
	    s->phase != SE_SNAPSHOT_PREPARED || s->commands || s->claims ||
	    !n || n > 8 || s->reserved || s->execution_class < 1 ||
	    s->execution_class > 2)
		return -1;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= n)
			break;
		const struct se_pin_ticket *t = &s->tickets[i];
		if (t->phase != SE_TICKET_HELD || t->scope != b->scope ||
		    t->snapshot_serial != serial || t->position != i ||
		    !t->object_generation || t->reserved)
			return -1;
	}
	if (b->active_serial) {
		__u32 old_index = b->active_record;
		if (old_index >= 2 || old_index == record)
			return -1;
		const struct se_snapshot *old = &b->records[old_index & 1];
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		/* G019 gap 3: the old record keeps its readers as RETIRING. */
		if (old->phase != SE_SNAPSHOT_ACTIVE ||
		    old->scope != b->scope || old->serial != b->active_serial ||
		    old->generation != b->generation || old->commands)
			return -1;
#else
		if (old->phase != SE_SNAPSHOT_ACTIVE ||
		    old->scope != b->scope || old->serial != b->active_serial ||
		    old->generation != b->generation || old->claims ||
		    old->commands)
			return -1;
#endif
	} else if (b->records[record ^ 1].phase != SE_SNAPSHOT_FREE) {
		return -1;
	}
	return 0;
}
/* Infallible only under the above same-lock preflight contract. Pin counts are
 * untouched: candidate pins become ACTIVE pins, old pins remain RETIRING pins.
 */
static __attribute__((always_inline)) inline void
se_binding_commit_publish_locked(struct se_binding_snapshots *b, __u32 record)
{
	/* Two records. The mask is the verifier bound; preflight already
	 * rejected every other index. */
	__u32 old = b->active_record & 1;
	record &= 1;
	if (b->active_serial)
		b->records[old].phase = SE_SNAPSHOT_RETIRING;
	struct se_snapshot *s = &b->records[record];
	s->generation = ++b->generation;
	s->phase = SE_SNAPSHOT_ACTIVE;
	b->active_record = record;
	b->active_serial = s->serial;
	b->admission_serial++;
}
/* Withdrawal preserves scope/generation and all accepted history. The adapter
 * must atomically tombstone routing in the SAME lock after this preflight; only
 * after ticket/routing-reader cleanup may it remove/reuse the routing cell. */
static __attribute__((always_inline)) inline int
se_binding_withdraw_preflight_locked(struct se_binding_snapshots *b,
				     __u64 expected_generation,
				     __u64 qualification_serial)
{
	if (!b->scope || !b->active_serial || b->active_record >= 2 ||
	    b->generation != expected_generation ||
	    b->admission_serial != qualification_serial ||
	    b->admission_serial >= ~0ULL - 1 || b->inflight)
		return -1;
	const struct se_snapshot *active = &b->records[b->active_record];
	if (active->phase != SE_SNAPSHOT_ACTIVE || active->scope != b->scope ||
	    active->serial != b->active_serial ||
	    active->generation != b->generation || active->claims ||
	    active->commands)
		return -1;
	const struct se_snapshot *other = &b->records[b->active_record ^ 1];
	if (other->claims || other->commands ||
	    (other->phase != SE_SNAPSHOT_FREE &&
	     other->phase != SE_SNAPSHOT_RETIRING))
		return -1;
	return 0;
}
static __attribute__((always_inline)) inline void
se_binding_withdraw_publish_locked(struct se_binding_snapshots *b)
{
	/* Two records. The mask is the verifier bound; preflight already
	 * rejected every other index. */
	b->records[b->active_record & 1].phase = SE_SNAPSHOT_RETIRING;
	b->active_serial = 0;
	b->active_record = 0;
	b->admission_serial++;
}

struct se_reader_token {
	__u64 scope, serial, sequence, task_cookie;
	__u32 record, execution_class;
};
/* The production adapter must select this persistent owner by pinned physical
 * task/invocation identity, NEVER from user-supplied/copyable scratch authority.
 * Reader fields are owned by the binding lock, separate from task role fields.
 */
struct se_reader_owner {
	struct se_reader_token token;
	__u32 owned, reserved;
};
static __attribute__((always_inline)) inline int
se_reader_acquire_record_locked(struct se_binding_snapshots *b, __u32 record,
				__u64 serial, __u64 scope, __u64 task_cookie,
				struct se_reader_owner *owner,
				struct se_reader_token *token)
{
	if (record >= 2 || !serial || scope != b->scope || !scope ||
	    !task_cookie || owner->owned || owner->reserved ||
	    b->active_serial != serial || b->active_record != record ||
	    b->next_reader >= ~0ULL - 1 || b->admission_serial >= ~0ULL - 1)
		return -1;
	/* Clang otherwise removes a redundant mask after the strict check. Keep
	 * the scalar barrier so older verifiers retain the two-record bound. */
	asm volatile("" : "+r"(record));
	record &= 1U;
	struct se_snapshot *s = &b->records[record];
	if (s->scope != scope || s->serial != serial ||
	    s->phase != SE_SNAPSHOT_ACTIVE || s->generation != b->generation ||
	    s->claims == (__u32)~0U || s->execution_class < 1 ||
	    s->execution_class > 2)
		return -1;
	struct se_reader_token next = { .scope = scope,
					.serial = serial,
					.sequence = ++b->next_reader,
					.task_cookie = task_cookie,
					.record = record,
					.execution_class = s->execution_class };
	s->claims++;
	b->admission_serial++;
	owner->token = next;
	owner->owned = 1;
	*token = next;
	return 0;
}
static inline int se_reader_acquire_locked(struct se_binding_snapshots *b,
					   __u64 scope, __u64 task_cookie,
					   struct se_reader_owner *owner,
					   struct se_reader_token *token)
{
	return se_reader_acquire_record_locked(b, b->active_record,
					       b->active_serial, scope,
					       task_cookie, owner, token);
}
static __attribute__((always_inline)) inline int
se_reader_release_locked(struct se_binding_snapshots *b,
			 struct se_reader_owner *owner,
			 const struct se_reader_token *token)
{
	if (!owner->owned || owner->reserved || token->record >= 2 ||
	    token->scope != b->scope || !token->sequence ||
	    owner->token.scope != token->scope ||
	    owner->token.serial != token->serial ||
	    owner->token.sequence != token->sequence ||
	    owner->token.task_cookie != token->task_cookie ||
	    owner->token.record != token->record ||
	    owner->token.execution_class != token->execution_class)
		return -1;
	__u32 bounded_record = token->record;
	asm volatile("" : "+r"(bounded_record));
	bounded_record &= 1U;
	struct se_snapshot *s = &b->records[bounded_record];
	if (s->scope != token->scope || s->serial != token->serial ||
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	    /* G019 gap 3: a reader of the RETIRING record releases it too. */
	    (s->phase != SE_SNAPSHOT_ACTIVE &&
	     s->phase != SE_SNAPSHOT_RETIRING) ||
	    !s->claims)
#else
	    s->phase != SE_SNAPSHOT_ACTIVE || !s->claims)
#endif
		return -1;
	owner->owned = 0;
	s->claims--;
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
/* G019 gap 3: the reader of a claim already bound to the RETIRING record
 * (the caller proved the claim valid under the same lock and consumes it):
 * the holder moves, the record's holder set never grows. */
static __attribute__((always_inline)) inline int
se_reader_acquire_retiring_locked(struct se_binding_snapshots *b, __u32 record,
				  __u64 serial, __u64 generation, __u64 scope,
				  __u64 task_cookie,
				  struct se_reader_owner *owner,
				  struct se_reader_token *token)
{
	if (record >= 2 || !serial || !generation || !scope ||
	    scope != b->scope || !task_cookie || owner->owned ||
	    owner->reserved || b->next_reader >= ~0ULL - 1)
		return -1;
	asm volatile("" : "+r"(record));
	record &= 1U;
	struct se_snapshot *s = &b->records[record];
	if (s->scope != scope || s->serial != serial ||
	    s->phase != SE_SNAPSHOT_RETIRING || s->generation != generation ||
	    s->claims == (__u32)~0U || s->execution_class < 1 ||
	    s->execution_class > 2)
		return -1;
	struct se_reader_token next = { .scope = scope,
					.serial = serial,
					.sequence = ++b->next_reader,
					.task_cookie = task_cookie,
					.record = record,
					.execution_class = s->execution_class };
	s->claims++;
	owner->token = next;
	owner->owned = 1;
	*token = next;
	return 0;
}
#endif

struct se_shared_binding {
	struct se_binding_snapshots state;
};
struct se_shared_object {
	struct bpf_spin_lock lock;
	struct se_object state;
};
struct se_ticket_request {
	__u64 scope, serial;
	__u32 record, position, kind, reserved;
};
#ifndef SE_TICKET_BEFORE_COMMAND_END
#define SE_TICKET_BEFORE_COMMAND_END(binding) \
	do {                                  \
	} while (0)
#endif
/* Production-reuse command body. Map lookup/authentication remain the adapter's
 * prerequisites. This wrapper, unlike the raw locked primitives, never exports
 * its live claim or a retained record pointer. No binding/object lock nesting.
 * A fixed map object pointer is safe across reuse: ticket generation is checked
 * while holding that object's lock, before touching its current pin count.
 */
static inline int se_ticket_command(struct bpf_spin_lock *authority_lock,
				    struct se_shared_binding *binding,
				    struct se_shared_object *object,
				    const struct se_ticket_request *request,
				    __u32 *receipt)
{
	/* Keep the checked scalar across helper calls; do not reload map input. */
	__u32 position = request->position;
	if (position >= 8 || request->reserved)
		return -1;
	struct se_snapshot_command command = {};
	bpf_spin_lock(authority_lock);
	int result = se_snapshot_command_begin_locked(
		&binding->state, request->record, request->scope,
		request->serial, request->kind, &command);
	bpf_spin_unlock(authority_lock);
	if (result)
		return result;
	/* Record storage cannot be cleared/reused until this owned command ends. */
	struct se_snapshot *snapshot = &binding->state.records[command.record];
	__u32 local_receipt = 0;
	if (position >= snapshot->count) {
		result = -1;
	} else {
		struct se_pin_ticket *ticket = &snapshot->tickets[position];
		bpf_spin_lock(&object->lock);
		if (command.kind == SE_COMMAND_PIN)
			result = se_ticket_pin_locked(&object->state, ticket,
						      &command, position);
		else if (command.kind == SE_COMMAND_RELEASE)
			result = se_ticket_release_locked(
				&object->state, ticket, &command, position);
		bpf_spin_unlock(&object->lock);
		SE_TICKET_BEFORE_COMMAND_END(binding);
		/* The command excludes every other ticket command and record reuse.
         * Copy the receipt after the pause, before releasing record ownership. */
		if (!result)
			local_receipt = ticket->phase;
	}
	bpf_spin_lock(authority_lock);
	int end = se_snapshot_command_end_locked(&binding->state, &command);
	bpf_spin_unlock(authority_lock);
	/* No snapshot/ticket dereference beyond this point. */
	if (end || result)
		return -1;
	*receipt = local_receipt;
	return 0;
}
#endif
