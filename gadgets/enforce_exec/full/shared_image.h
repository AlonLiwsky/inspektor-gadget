/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_IMAGE_H
#define ENFORCE_EXEC_SHARED_IMAGE_H

/* Pure state under the binding's existing sole authority lock. No map helpers,
 * extra lock, object registry, completeness attestation or kernel adapter here.
 *
 * Adapter obligations (NOT discharged by these helpers):
 * - identities, keys and operation tokens are private adapter-owned copies,
 *   not user-supplied authority; they must not alias this persistent state.
 * - scope/limit and fixed storage stay pinned until every descriptor is FREE;
 *   limit counts KEY CELLS, including active/candidate/retiring reservations.
 *   Admission reserves sum(binding limits) <= global Images. Do not reassign a
 *   binding's quota on logical Remove while any descriptor/operation survives.
 * - begin's allocation_sequence is the CURRENT authenticated GLOBAL command
 *   sequence, never a user-chosen handle. The existing node admin protocol
 *   guarantees uniqueness/nonwrap across ALL bindings in this collection.
 *   last_handle rejects local stale allocation only; it cannot authenticate a
 *   foreign command or prove global uniqueness independently.
 * - operations retain their original account, key list and evidence lease;
 *   perform exact {handle,key} map operations OUTSIDE the binding spin lock,
 *   while the matching operation is held. Insert is NOEXIST, never ANY.
 *   APPLIED means one NEW distinct key inserted or one owned key definitively
 *   removed. NOT_APPLIED means this attempt definitely made no change (including
 *   an insertion conflict). Ambiguous outcomes remain UNCERTAIN until reconciled
 *   under exclusive ownership; a missing delete is not automatically APPLIED.
 * - seal requires separate trusted re-attestation of COMPLETE immutable evidence
 *   and the full key list; count equality alone is not that authority. An empty
 *   complete set is legitimate. Missing/incomplete evidence is never negative.
 * - references correspond to the existing two snapshot records. Authenticate
 *   each nonreused snapshot serial. Release only AFTER its last reader/command
 *   access; retain the original evidence lease until final successful reclaim.
 *   A raw reference count is not a replacement for snapshot quiescence proof.
 *
 * Every helper is always inlined: the BPF adapters call them while holding
 * the route spin lock, where a subprogram call is refused on older kernels.
 *
 * Two independent descriptors allow the same immutable image to be referenced
 * by alternating snapshot slots without stranding the descriptor's birth slot.
 * Expected keys are reserved up front; even aborted or partially deleted sets
 * retain their entire reservation until exact cleanup is complete.
 */
#define SE_IMAGE_FREE 0
#define SE_IMAGE_BUILDING 1
#define SE_IMAGE_COMPLETE 2
#define SE_IMAGE_RETIRING 3
#define SE_IMAGE_INSERT 1
#define SE_IMAGE_DELETE 2
#define SE_IMAGE_NOT_APPLIED 0
#define SE_IMAGE_APPLIED 1
#define SE_IMAGE_UNCERTAIN 2

struct se_image_key {
	__u64 inode;
	__u32 major, minor;
};
struct se_image_identity {
	__u64 scope, handle;
	__u32 descriptor;
};
struct se_image_descriptor {
	__u64 scope, handle, next_operation, pending_sequence;
	struct se_image_key pending_key;
	__u32 expected, present, phase, references, pending_kind;
	/* G020: the container root overlay's kernel dev_t (MKDEV(0, minor))
	 * this key set was attested for; in the former tail padding. */
	__u32 overlay_dev;
};
_Static_assert(sizeof(struct se_image_descriptor) == 72,
	       "image descriptor (overlay_dev in the former padding)");
struct se_image_reference {
	__u64 serial, handle;
	__u32 descriptor, held;
};
struct se_binding_images {
	__u64 scope, last_handle;
	__u32 limit, reserved;
	struct se_image_descriptor descriptors[2];
	struct se_image_reference snapshots[2];
};
_Static_assert(sizeof(struct se_binding_images) == 216,
	       "per-binding image state wire (se_image_bindings value)");
struct se_image_operation {
	struct se_image_identity identity;
	struct se_image_key key;
	__u64 sequence;
	__u32 kind, owned;
};

static __attribute__((always_inline)) inline struct se_image_descriptor *
se_image_descriptor_locked(struct se_binding_images *b,
			   const struct se_image_identity *id)
{
	__u32 index = id->descriptor;
	if (index >= 2 || !id->scope || id->scope != b->scope || !id->handle ||
	    id->handle == ~0ULL)
		return 0;
	struct se_image_descriptor *d = &b->descriptors[index];
	if (d->scope != id->scope || d->handle != id->handle ||
	    d->phase < SE_IMAGE_BUILDING || d->phase > SE_IMAGE_RETIRING)
		return 0;
	return d;
}
static __attribute__((always_inline)) inline int
se_image_begin_locked(struct se_binding_images *b, __u64 scope,
		      __u64 allocation_sequence, __u32 index, __u32 expected,
		      struct se_image_identity *out)
{
	if (!scope || scope == ~0ULL || scope != b->scope || index >= 2 ||
	    !allocation_sequence || allocation_sequence == ~0ULL ||
	    allocation_sequence <= b->last_handle || !b->limit ||
	    b->reserved > b->limit || expected > b->limit - b->reserved)
		return -1;
	struct se_image_descriptor *d = &b->descriptors[index];
	if (d->phase != SE_IMAGE_FREE || d->references || d->pending_sequence ||
	    d->present || d->expected)
		return -1;
	/* All preflight above; no fallible operation after the first store. */
	*d = (struct se_image_descriptor){ .scope = scope,
					   .handle = allocation_sequence,
					   .expected = expected,
					   .phase = SE_IMAGE_BUILDING };
	b->last_handle = allocation_sequence;
	b->reserved += expected;
	*out = (struct se_image_identity){ .scope = scope,
					   .handle = allocation_sequence,
					   .descriptor = index };
	return 0;
}
/* G020 command adapter: (re)open a binding's image state for scope. A
 * binding keeps one scope while any descriptor, reservation or snapshot
 * reference survives; only a fully empty state takes a new scope (a
 * recycled route slot restarts its snapshot serials, so the per-record
 * stale-serial floors are reset with it). last_handle is kept: handles are
 * global command sequences and never go backwards. */
static __attribute__((always_inline)) inline int
se_image_open_locked(struct se_binding_images *b, __u64 scope, __u32 limit)
{
	if (!scope || scope == ~0ULL || !limit)
		return -1;
	if (b->scope == scope)
		return b->limit == limit ? 0 : -1;
	if (b->reserved || b->snapshots[0].held || b->snapshots[1].held)
		return -1;
	for (__u32 i = 0; i < 2; i++) {
		const struct se_image_descriptor *d = &b->descriptors[i];
		if (d->phase != SE_IMAGE_FREE || d->references ||
		    d->pending_sequence || d->present || d->expected)
			return -1;
	}
	__u64 last = b->last_handle;
	*b = (struct se_binding_images){ .scope = scope,
					 .last_handle = last,
					 .limit = limit };
	return 0;
}
/* se_image_begin_locked plus the attested overlay dev_t (nonzero, major 0),
 * stored after the infallible begin under the same lock. */
static __attribute__((always_inline)) inline int
se_image_begin_dev_locked(struct se_binding_images *b, __u64 scope,
			  __u64 allocation_sequence, __u32 index,
			  __u32 expected, __u32 overlay_dev,
			  struct se_image_identity *out)
{
	if (!overlay_dev || (overlay_dev >> 20) ||
	    se_image_begin_locked(b, scope, allocation_sequence, index,
				  expected, out))
		return -1;
	b->descriptors[index & 1].overlay_dev = overlay_dev;
	return 0;
}
static __attribute__((always_inline)) inline int
se_image_operation_begin_locked(struct se_binding_images *b,
				const struct se_image_identity *id, __u32 kind,
				const struct se_image_key *key,
				struct se_image_operation *op)
{
	struct se_image_descriptor *d = se_image_descriptor_locked(b, id);
	if (!d || op->owned || d->pending_sequence || d->pending_kind ||
	    d->next_operation >= ~0ULL - 1 || d->present > d->expected ||
	    key->major >= (1U << 12) || key->minor >= (1U << 20))
		return -1;
	if (kind == SE_IMAGE_INSERT) {
		if (d->phase != SE_IMAGE_BUILDING || d->references ||
		    d->present == d->expected)
			return -1;
	} else if (kind == SE_IMAGE_DELETE) {
		if (d->phase != SE_IMAGE_RETIRING || d->references ||
		    !d->present)
			return -1;
	} else
		return -1;
	d->pending_sequence = ++d->next_operation;
	d->pending_key = *key;
	d->pending_kind = kind;
	*op = (struct se_image_operation){ .identity = *id,
					   .key = *key,
					   .sequence = d->pending_sequence,
					   .kind = kind,
					   .owned = 1 };
	return 0;
}
/* Call after the LAST physical map access, not while an asynchronous map
 * operation can still finish. A copied stale token cannot consume a new op. */
static __attribute__((always_inline)) inline int
se_image_operation_finish_locked(struct se_binding_images *b,
				 struct se_image_operation *op, int outcome)
{
	struct se_image_descriptor *d =
		se_image_descriptor_locked(b, &op->identity);
	if (!d || op->owned != 1 || !op->sequence ||
	    d->pending_sequence != op->sequence ||
	    d->pending_kind != op->kind ||
	    d->pending_key.inode != op->key.inode ||
	    d->pending_key.major != op->key.major ||
	    d->pending_key.minor != op->key.minor || d->references ||
	    d->present > d->expected || outcome < SE_IMAGE_NOT_APPLIED ||
	    outcome > SE_IMAGE_UNCERTAIN)
		return -1;
	if (op->kind == SE_IMAGE_INSERT) {
		if (d->phase != SE_IMAGE_BUILDING || d->present == d->expected)
			return -1;
	} else if (op->kind == SE_IMAGE_DELETE) {
		if (d->phase != SE_IMAGE_RETIRING || !d->present)
			return -1;
	} else
		return -1;
	if (outcome == SE_IMAGE_UNCERTAIN)
		return 1; /* ownership/charge unchanged until exact reconciliation */
	if (outcome == SE_IMAGE_APPLIED) {
		if (op->kind == SE_IMAGE_INSERT)
			d->present++;
		else
			d->present--;
	}
	d->pending_sequence = 0;
	d->pending_kind = 0;
	d->pending_key = (struct se_image_key){};
	op->owned = 0;
	return 0;
}
static __attribute__((always_inline)) inline int
se_image_seal_locked(struct se_binding_images *b,
		     const struct se_image_identity *id)
{
	struct se_image_descriptor *d = se_image_descriptor_locked(b, id);
	if (!d || d->phase != SE_IMAGE_BUILDING || d->pending_sequence ||
	    d->references || d->present != d->expected)
		return -1;
	d->phase = SE_IMAGE_COMPLETE;
	return 0;
}
static __attribute__((always_inline)) inline int
se_image_reference_locked(struct se_binding_images *b,
			  const struct se_image_identity *id, __u32 record,
			  __u64 serial)
{
	struct se_image_descriptor *d = se_image_descriptor_locked(b, id);
	if (!d || record >= 2 || !serial || serial == ~0ULL ||
	    d->phase != SE_IMAGE_COMPLETE || d->pending_sequence ||
	    d->present != d->expected || d->references >= 2)
		return -1;
	struct se_image_reference *r = &b->snapshots[record];
	if (r->held || serial <= r->serial)
		return -1;
	*r = (struct se_image_reference){ .serial = serial,
					  .handle = id->handle,
					  .descriptor = id->descriptor,
					  .held = 1 };
	d->references++;
	return 0;
}
static __attribute__((always_inline)) inline int
se_image_known_locked(struct se_binding_images *b,
		      const struct se_image_identity *id, __u32 record,
		      __u64 serial)
{
	struct se_image_descriptor *d = se_image_descriptor_locked(b, id);
	if (!d || record >= 2 || !serial || d->phase != SE_IMAGE_COMPLETE ||
	    d->pending_sequence || !d->references || d->present != d->expected)
		return 0;
	const struct se_image_reference *r = &b->snapshots[record];
	return r->held == 1 && r->serial == serial && r->handle == id->handle &&
	       r->descriptor == id->descriptor;
}
static __attribute__((always_inline)) inline int
se_image_release_locked(struct se_binding_images *b,
			const struct se_image_identity *id, __u32 record,
			__u64 serial)
{
	__u32 index = id->descriptor;
	if (index >= 2 || !se_image_known_locked(b, id, record, serial))
		return -1;
	struct se_image_descriptor *d = &b->descriptors[index];
	b->snapshots[record].held = 0; /* retain serial to reject stale reuse */
	d->references--;
	if (!d->references)
		d->phase = SE_IMAGE_RETIRING;
	return 0;
}
static __attribute__((always_inline)) inline int
se_image_abort_locked(struct se_binding_images *b,
		      const struct se_image_identity *id)
{
	struct se_image_descriptor *d = se_image_descriptor_locked(b, id);
	if (!d || d->references || d->pending_sequence)
		return -1;
	d->phase = SE_IMAGE_RETIRING;
	return 0;
}
static __attribute__((always_inline)) inline int
se_image_reclaim_locked(struct se_binding_images *b,
			const struct se_image_identity *id)
{
	struct se_image_descriptor *d = se_image_descriptor_locked(b, id);
	if (!d || d->phase != SE_IMAGE_RETIRING || d->references ||
	    d->pending_sequence || d->present || d->expected > b->reserved)
		return -1;
	b->reserved -= d->expected;
	*d = (struct se_image_descriptor){};
	return 0;
}
#endif
