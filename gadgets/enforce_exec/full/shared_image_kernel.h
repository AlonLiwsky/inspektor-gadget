/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_IMAGE_KERNEL_H
#define ENFORCE_EXEC_SHARED_IMAGE_KERNEL_H
#include "shared_image.h"
#if !defined(SE_PROFILE_IMAGES) || !defined(SE_PROFILE_IMAGE_QUOTA) || \
	!defined(SE_PROFILE_BINDINGS)
#error "shared image key-cell pool and quota must be explicit"
#endif
_Static_assert(SE_PROFILE_IMAGES > 0 && SE_PROFILE_IMAGES <= 0xffffffffULL &&
		       SE_PROFILE_IMAGE_QUOTA > 0 &&
		       SE_PROFILE_IMAGE_QUOTA <= 0xffffffffULL &&
		       SE_PROFILE_BINDINGS > 0 &&
		       SE_PROFILE_BINDINGS <= 0xffffffffULL &&
		       (0ULL + SE_PROFILE_BINDINGS) * SE_PROFILE_IMAGE_QUOTA <=
			       SE_PROFILE_IMAGES,
	       "image reservations exceed fixed key-cell pool");

struct se_image_map_key {
	__u64 image_handle;
	struct se_image_key origin;
};
_Static_assert(sizeof(struct se_image_map_key) == 24,
	       "shared image key layout");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_PROFILE_IMAGES);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, struct se_image_map_key);
	__type(value, __u8);
} se_image_keys SEC(".maps");

struct se_image_map_request {
	struct se_image_identity identity;
	struct se_image_key key;
	__u32 slot, kind;
};
struct se_image_lookup_request {
	struct se_image_identity identity;
	struct se_image_key key;
	__u64 serial;
	__u32 slot, record;
};
/* Linux helper errors, not policy/receipt status codes. No error is success. */
#define SE_IMAGE_MAP_EEXIST 17
#define SE_IMAGE_MAP_ENOENT 2

/* Invoke with NO spin lock held; these functions manage the supplied lock.
 * The authenticated caller must resolve this exact slot's fixed image state and
 * sole route/binding lock BEFORE calling, and pin both through the final unlock.
 * These explicit pointers do NOT authenticate their own slot association.
 * scope/handle are minted by the real command adapter, not this helper. Inputs
 * and operation are private nonaliasing copies, never user-provided authority.
 *
 * The operation must be initially unowned. This executes a physical map change
 * ONCE; it cannot resume/replay a held or uncertain operation. Return APPLIED,
 * NOT_APPLIED, UNCERTAIN, or -1 for refusal/invariant failure. If op->owned remains
 * set on ANY return, retain the original account/lease/key list and reconcile
 * its exact last-access outcome before reclaim; never discard it on an error.
 *
 * Only the exact pinned descriptor's operation can mutate its handle's keys.
 * This exclusivity plus globally unique handles makes {handle,key} deletion
 * ownership-specific without a nonexistent atomic compare-delete API.
 */
static __always_inline int
se_image_map_change(struct bpf_spin_lock *lock, struct se_binding_images *b,
		    const struct se_image_map_request *request,
		    struct se_image_operation *op)
{
	if (!lock || !b || !request || !op)
		return -1;
	struct se_image_map_request r = *request;
	if (r.slot >= SE_PROFILE_BINDINGS)
		return -1;
	bpf_spin_lock(lock);
	int result = -1;
	if (b->limit == SE_PROFILE_IMAGE_QUOTA && b->reserved <= b->limit)
		result = se_image_operation_begin_locked(b, &r.identity, r.kind,
							 &r.key, op);
	bpf_spin_unlock(lock);
	if (result)
		return -1;
	struct se_image_map_key key = { .image_handle = r.identity.handle,
					.origin = r.key };
	long error;
	if (r.kind == SE_IMAGE_INSERT) {
		__u8 membership = 1;
		error = bpf_map_update_elem(&se_image_keys, &key, &membership,
					    BPF_NOEXIST);
	} else {
		error = bpf_map_delete_elem(&se_image_keys, &key);
	}
	int outcome = SE_IMAGE_UNCERTAIN;
	if (!error)
		outcome = SE_IMAGE_APPLIED;
	else if ((r.kind == SE_IMAGE_INSERT && error == -SE_IMAGE_MAP_EEXIST) ||
		 (r.kind == SE_IMAGE_DELETE && error == -SE_IMAGE_MAP_ENOENT))
		outcome = SE_IMAGE_NOT_APPLIED;
	/* Unknown errors conservatively retain exact ownership. Neither a retry
	 * nor an absent lookup is an invented successful-delete receipt. */
	bpf_spin_lock(lock);
	result = se_image_operation_finish_locked(b, op, outcome);
	bpf_spin_unlock(lock);
	return result < 0 ? -1 : outcome;
}

/* G020 IMAGE_INSPECT: reconcile the descriptor's pending (UNCERTAIN)
 * operation under EXCLUSIVE ownership. Invoke with NO spin lock held. The
 * authenticated caller is the node's single admin and no map operation of
 * this handle can be in flight (se_image_map_change is synchronous and only
 * the pinned descriptor's operation mutates its handle's keys), so the
 * pending {handle, key}'s membership now IS the operation's outcome: an
 * insert whose key is present was APPLIED, absent NOT_APPLIED; a delete
 * whose key is absent was APPLIED, present NOT_APPLIED. The key list's
 * distinctness stays the adapter's obligation (a duplicate is never sent).
 * 0 with *outcome = APPLIED/NOT_APPLIED (settled), or -1 when nothing was
 * pending; -1 refused or malformed membership (still pending). */
static __always_inline int
se_image_map_reconcile(struct bpf_spin_lock *lock, struct se_binding_images *b,
		       const struct se_image_identity *identity, int *outcome)
{
	if (!lock || !b || !identity || !outcome)
		return -1;
	struct se_image_identity id = *identity;
	struct se_image_operation op = {};
	int valid = 0, pending = 0;
	*outcome = -1;
	bpf_spin_lock(lock);
	struct se_image_descriptor *d = 0;
	if (b->limit == SE_PROFILE_IMAGE_QUOTA && b->reserved <= b->limit)
		d = se_image_descriptor_locked(b, &id);
	if (d) {
		valid = 1;
		if (d->pending_sequence) {
			pending = 1;
			op = (struct se_image_operation){
				.identity = id,
				.key = d->pending_key,
				.sequence = d->pending_sequence,
				.kind = d->pending_kind,
				.owned = 1
			};
		}
	}
	bpf_spin_unlock(lock);
	if (!valid)
		return -1;
	if (!pending)
		return 0;
	if (op.kind != SE_IMAGE_INSERT && op.kind != SE_IMAGE_DELETE)
		return -1;
	struct se_image_map_key key = { .image_handle = id.handle,
					.origin = op.key };
	const __u8 *membership = bpf_map_lookup_elem(&se_image_keys, &key);
	if (membership && *membership != 1)
		return -1;
	int result = (op.kind == SE_IMAGE_INSERT) == !!membership ?
			     SE_IMAGE_APPLIED :
			     SE_IMAGE_NOT_APPLIED;
	bpf_spin_lock(lock);
	int finished = se_image_operation_finish_locked(b, &op, result);
	bpf_spin_unlock(lock);
	if (finished)
		return -1;
	*outcome = result;
	return 0;
}

/* Return -1 UNKNOWN, 0 known absent, 1 known present. The caller ALREADY owns an
 * actual snapshot reader/claim for {slot,scope,record,serial}; retain it through
 * the LAST map lookup/value read. Image-reference validation here does not
 * acquire that reader, authenticate completeness, or replace quiescence proof.
 * The decoder supplies the existing inode/major/minor identity; no filesystem
 * classification or collection-global readiness authority is introduced here.
 */
static __always_inline int
se_image_map_lookup(struct bpf_spin_lock *lock, struct se_binding_images *b,
		    const struct se_image_lookup_request *request)
{
	if (!lock || !b || !request)
		return -1;
	struct se_image_lookup_request r = *request;
	if (r.slot >= SE_PROFILE_BINDINGS || r.key.major >= (1U << 12) ||
	    r.key.minor >= (1U << 20))
		return -1;
	bpf_spin_lock(lock);
	int known = b->limit == SE_PROFILE_IMAGE_QUOTA &&
		    b->reserved <= b->limit &&
		    se_image_known_locked(b, &r.identity, r.record, r.serial);
	bpf_spin_unlock(lock);
	if (!known)
		return -1;
	struct se_image_map_key key = { .image_handle = r.identity.handle,
					.origin = r.key };
	const __u8 *membership = bpf_map_lookup_elem(&se_image_keys, &key);
	if (!membership)
		return 0;
	return *membership == 1 ? 1 : -1;
}
#endif
