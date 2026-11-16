/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* G020 image index, command side (product publisher only; included by
 * opaque_real_owner_product_publisher.h after the command authenticator).
 *
 * Maps:
 *   se_image_keys      HASH {handle, layer root ino, major, minor} -> 1,
 *                      SE_PROFILE_IMAGES preallocated cells, userspace
 *                      read-only (full/shared_image_kernel.h);
 *   se_image_bindings  ARRAY[SE_PROFILE_BINDINGS] struct se_binding_images,
 *                      written only under the binding's route lock
 *                      (se_routes[slot].lock, as se_bindings[slot]);
 *   se_image_scratch   PERCPU_ARRAY[1] the KEYS/DELETE loop state (keys
 *                      off the stack), BPF-private;
 *   se_image_witness   PERCPU_ARRAY[1] struct se_image_class_witness, the
 *                      classifier's witness enum (full/shared_image_classify.h)
 *                      whose command-side slots count INSERT_UNCERTAIN,
 *                      DELETE_UNCERTAIN and PREPARE_REFUSED.
 *
 * Lifetime (full/shared_image_snapshot.h): PREPARE references the sealed
 * descriptor its metadata names, in the locked transition that prepares
 * the record; the reclaim that makes the record FREE releases it in the
 * same transition. The last release retires the descriptor; only then can
 * IMAGE_DELETE remove its keys and IMAGE_RECLAIM return its cells.
 *
 * opaque_real_image_command, authenticated like every product command
 * (real_owner_cmd_authenticate: se_admin nonce, node cookie, strictly
 * increasing sequence, consumed before any state change):
 *   BEGIN    (slot, scope, descriptor, expected, overlay_dev): opens the
 *            binding's image state for scope (or keeps it) and begins the
 *            descriptor; its handle is THIS command's authenticated global
 *            sequence (shared_image.h), read back from se_image_bindings;
 *   KEYS     (slot, scope, handle, descriptor, count <= 16, keys): one
 *            NOEXIST insert per key through se_image_map_change in a
 *            bpf_loop, stopping at the first key not APPLIED;
 *   SEAL     present == expected, nothing pending;
 *   ABORT    an unreferenced descriptor -> RETIRING;
 *   DELETE   (as KEYS) exact deletes of a RETIRING descriptor's keys;
 *   RECLAIM  a RETIRING descriptor without keys or pending operation;
 *   INSPECT  reconciles the pending (UNCERTAIN) operation under exclusive
 *            ownership (se_image_map_reconcile).
 * Codes: 0 done; 1 refused, nothing changed (KEYS/DELETE: at the first key;
 * earlier keys of the command stay APPLIED: the agent reads present); 2 a
 * key NOT_APPLIED (insert: already present; delete: absent); 5
 * authentication; 8 UNCERTAIN (the operation stays pending and charged
 * until INSPECT); -1 invariant. */
#ifndef ENFORCE_EXEC_OPAQUE_REAL_OWNER_PRODUCT_IMAGE_H
#define ENFORCE_EXEC_OPAQUE_REAL_OWNER_PRODUCT_IMAGE_H

#include "shared_image_kernel.h"
#include "shared_image_classify.h"
#include "shared_image_snapshot.h"

_Static_assert(SE_PROFILE_IMAGE_QUOTA <= 128,
	       "per-binding image layer roots (sharedImageLayersMax)");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_BINDINGS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_binding_images);
} se_image_bindings SEC(".maps");

/* Defined with the exec-side classifier (real_owner_pass_facts) when the
 * per-pass facts precede this header; the same map either way. */
#ifndef REAL_OWNER_IMAGE_WITNESS_MAP
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_image_class_witness);
} se_image_witness SEC(".maps");
#endif

static __always_inline void real_owner_image_witness(__u32 reason)
{
	__u32 zero = 0;
	struct se_image_class_witness *w =
		bpf_map_lookup_elem(&se_image_witness, &zero);
	if (w && reason < SE_IMAGE_CLASS_SLOTS)
		__sync_fetch_and_add(&w->count[reason], 1);
}

#define OPAQUE_REAL_IMAGE_BEGIN 1
#define OPAQUE_REAL_IMAGE_KEYS 2
#define OPAQUE_REAL_IMAGE_SEAL 3
#define OPAQUE_REAL_IMAGE_ABORT 4
#define OPAQUE_REAL_IMAGE_DELETE 5
#define OPAQUE_REAL_IMAGE_RECLAIM 6
#define OPAQUE_REAL_IMAGE_INSPECT 7
#define OPAQUE_REAL_IMAGE_KEYS_MAX 16
/* A key operation stays UNCERTAIN (pending and charged until INSPECT). */
#define OPAQUE_REAL_CMD_UNCERTAIN 8
/* opaque_real_route_publish: the metadata's image handle is not a sealed
 * descriptor of this binding with that overlay dev (or the record still held
 * a reference): the PREPARE was undone, nothing changed but the sequence,
 * and PREPARE_REFUSED is counted. Rebuild the index, then publish again. */
#define OPAQUE_REAL_CMD_IMAGE 9

struct opaque_real_image_request {
	struct opaque_real_cmd_header header;
	__u64 scope, handle;
	__u32 op, slot, descriptor, expected, overlay_dev, count;
	struct se_image_key keys[OPAQUE_REAL_IMAGE_KEYS_MAX];
};
_Static_assert(sizeof(struct opaque_real_image_request) == 320,
	       "product image request wire");

/* One fixed-offset load from the UNMODIFIED syscall ctx (see
 * real_owner_request_u64: the verifier refuses ctx+off bases). */
static __always_inline __u64
real_owner_image_u64(const struct opaque_real_image_request *r, __u32 offset)
{
	const struct opaque_real_image_request *c = r;
	asm volatile("" : "+r"(c));
	return *(const __u64 *)((const char *)c + offset);
}

struct real_owner_image_loop {
	struct se_image_identity id;
	__u32 slot, kind, count, done;
	int outcome, owned;
	struct se_image_key keys[OPAQUE_REAL_IMAGE_KEYS_MAX];
};
_Static_assert(sizeof(struct real_owner_image_loop) == 304,
	       "image key loop scratch");
/* The KEYS/DELETE loop state lives in this per-CPU scratch, not on the
 * stack: the command, the loop callback and se_image_map_change stay far
 * below the 512-byte combined stack (a stack copy of the keys put the chain
 * over it). A syscall program runs pinned to its CPU and the single admin
 * thread is the only caller, so the cell is never shared mid-command. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct real_owner_image_loop);
} se_image_scratch SEC(".maps");

/* One key: lock, begin, map change, lock, finish (se_image_map_change).
 * The maps are looked up per key; the route lock protects the image state. */
static long real_owner_image_step(__u64 index, void *unused)
{
	(void)unused;
	__u32 i = index, zero = 0;
	struct real_owner_image_loop *l =
		bpf_map_lookup_elem(&se_image_scratch, &zero);
	if (!l)
		return 1;
	if (i >= OPAQUE_REAL_IMAGE_KEYS_MAX || i >= l->count)
		return 1;
	__u32 slot = l->slot;
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	struct se_binding_images *images =
		bpf_map_lookup_elem(&se_image_bindings, &slot);
	if (!route || !images) {
		l->outcome = -1;
		return 1;
	}
	struct se_image_map_request request = {
		.identity = l->id,
		.key = l->keys[i & (OPAQUE_REAL_IMAGE_KEYS_MAX - 1)],
		.slot = slot,
		.kind = l->kind,
	};
	struct se_image_operation op = {};
	int outcome = se_image_map_change(&route->lock, images, &request, &op);
	l->outcome = outcome;
	l->owned = op.owned;
	if (outcome != SE_IMAGE_APPLIED)
		return 1;
	l->done++;
	return 0;
}

static __attribute__((noinline)) int
real_owner_image_keys(const struct opaque_real_image_request *r, __u32 kind)
{
	__u32 zero = 0, count = r->count;
	struct real_owner_image_loop *l =
		bpf_map_lookup_elem(&se_image_scratch, &zero);
	if (!l)
		return OPAQUE_REAL_CMD_INVARIANT;
	if (!count || count > OPAQUE_REAL_IMAGE_KEYS_MAX)
		return OPAQUE_REAL_CMD_RETRY;
	l->id.scope = r->scope;
	l->id.handle = r->handle;
	l->id.descriptor = r->descriptor;
	l->slot = r->slot;
	l->kind = kind;
	l->count = count;
	l->done = 0;
	l->outcome = -1;
	l->owned = 0;
	/* Word by word, each a fixed-offset ctx load. */
	__u64 *keys = (__u64 *)l->keys;
#ifdef __clang__
#pragma unroll
#endif
	for (__u32 w = 0; w < sizeof(l->keys) / 8; w++)
		keys[w] = real_owner_image_u64(
			r, __builtin_offsetof(struct opaque_real_image_request,
					      keys) +
				   8 * w);
	bpf_loop(count, real_owner_image_step, 0, 0);
	if (l->done == count)
		return OPAQUE_REAL_CMD_OK;
	if (l->outcome == SE_IMAGE_UNCERTAIN) {
		real_owner_image_witness(
			kind == SE_IMAGE_INSERT ?
				SE_IMAGE_CLASS_INSERT_UNCERTAIN :
				SE_IMAGE_CLASS_DELETE_UNCERTAIN);
		return OPAQUE_REAL_CMD_UNCERTAIN;
	}
	if (l->outcome == SE_IMAGE_NOT_APPLIED)
		return OPAQUE_REAL_CMD_REFUSED;
	/* -1 with the operation still owned: the finish refused after the map
	 * change (an invariant: the single admin is the only mutator). */
	return l->owned ? OPAQUE_REAL_CMD_INVARIANT : OPAQUE_REAL_CMD_RETRY;
}

/* BEGIN, SEAL, ABORT, RECLAIM and INSPECT. Its own frame, so the command's
 * deepest chain is the KEYS/DELETE loop (stack: 512-byte combined limit). */
static __attribute__((noinline)) int
real_owner_image_state(const struct opaque_real_image_request *r, __u32 op)
{
	__u32 slot = r->slot;
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&slot);
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&slot);
	struct se_binding_images *images =
		bpf_map_lookup_elem(&se_image_bindings, &slot);
	if (!route || !binding || !images)
		return OPAQUE_REAL_CMD_INVARIANT;
	struct se_image_identity id = { .scope = r->scope,
					.handle = r->handle,
					.descriptor = r->descriptor };
	if (op == OPAQUE_REAL_IMAGE_INSPECT) {
		int outcome = -1;
		return se_image_map_reconcile(&route->lock, images, &id,
					      &outcome) ?
			       OPAQUE_REAL_CMD_RETRY :
			       OPAQUE_REAL_CMD_OK;
	}
	/* The authenticated sequence this command consumed. */
	__u64 sequence = r->header.sequence;
	__u32 expected = r->expected, overlay_dev = r->overlay_dev;
	int result = -1;
	bpf_spin_lock(&route->lock);
	switch (op) {
	case OPAQUE_REAL_IMAGE_BEGIN:
		/* The image scope is the binding's: an open binding of another
		 * scope never gets an index. */
		if (!r->handle &&
		    (!binding->state.scope ||
		     binding->state.scope == id.scope) &&
		    !se_image_open_locked(images, id.scope,
					  SE_PROFILE_IMAGE_QUOTA))
			result = se_image_begin_dev_locked(
				images, id.scope, sequence, id.descriptor,
				expected, overlay_dev, &id);
		break;
	case OPAQUE_REAL_IMAGE_SEAL:
		result = se_image_seal_locked(images, &id);
		break;
	case OPAQUE_REAL_IMAGE_ABORT:
		result = se_image_abort_locked(images, &id);
		break;
	case OPAQUE_REAL_IMAGE_RECLAIM:
		result = se_image_reclaim_locked(images, &id);
		break;
	}
	bpf_spin_unlock(&route->lock);
	return result ? OPAQUE_REAL_CMD_RETRY : OPAQUE_REAL_CMD_OK;
}

SEC("syscall")
int opaque_real_image_command(struct opaque_real_image_request *r)
{
	if (!r || !real_owner_cmd_authenticate(&r->header))
		return OPAQUE_REAL_CMD_AUTH;
	__u32 op = r->op;
	if (r->slot >= SE_PROFILE_BINDINGS || r->descriptor >= 2 || !r->scope ||
	    r->scope == ~0ULL)
		return OPAQUE_REAL_CMD_RETRY;
	if (op == OPAQUE_REAL_IMAGE_KEYS)
		return real_owner_image_keys(r, SE_IMAGE_INSERT);
	if (op == OPAQUE_REAL_IMAGE_DELETE)
		return real_owner_image_keys(r, SE_IMAGE_DELETE);
	return real_owner_image_state(r, op);
}

#endif
