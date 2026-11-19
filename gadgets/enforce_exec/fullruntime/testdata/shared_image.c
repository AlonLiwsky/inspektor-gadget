/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
#include "shared_image.h"
_Static_assert(sizeof(struct se_image_descriptor) == 72, "bounded descriptor");
_Static_assert(sizeof(struct se_image_operation) == 56, "bounded operation");
_Static_assert(sizeof(struct se_binding_images) == 216,
	       "two descriptors and two references");

static struct se_image_key key(__u64 inode)
{
	return (struct se_image_key){ .inode = inode, .major = 8, .minor = 1 };
}
#define REFUSE(b, expression)                             \
	do {                                              \
		struct se_binding_images saved = (b);     \
		assert((expression) < 0);                 \
		assert(!memcmp(&saved, &(b), sizeof(b))); \
	} while (0)

static void put(struct se_binding_images *b, struct se_image_identity id,
		__u64 inode, int result)
{
	struct se_image_operation op = {};
	struct se_image_key k = key(inode);
	assert(!se_image_operation_begin_locked(b, &id, SE_IMAGE_INSERT, &k,
						&op));
	assert(!se_image_operation_finish_locked(b, &op, result));
	assert(!op.owned);
}
static void remove_key(struct se_binding_images *b, struct se_image_identity id,
		       __u64 inode, int result)
{
	struct se_image_operation op = {};
	struct se_image_key k = key(inode);
	assert(!se_image_operation_begin_locked(b, &id, SE_IMAGE_DELETE, &k,
						&op));
	assert(!se_image_operation_finish_locked(b, &op, result));
}
static void allocation_and_completion(void)
{
	struct se_binding_images b = { .scope = 11, .limit = 3 };
	struct se_image_identity id = {}, empty = {};
	REFUSE(b, se_image_begin_locked(&b, 11, 0, 0, 2, &id));
	REFUSE(b, se_image_begin_locked(&b, 12, 1, 0, 2, &id));
	REFUSE(b, se_image_begin_locked(&b, 11, 1, 2, 2, &id));
	REFUSE(b, se_image_begin_locked(&b, 11, UINT64_MAX, 0, 2, &id));
	assert(!se_image_begin_locked(&b, 11, 100, 0, 2, &id));
	assert(b.reserved == 2 && b.descriptors[0].present == 0);
	assert(!se_image_known_locked(&b, &id, 0, 1));
	REFUSE(b, se_image_seal_locked(&b, &id));
	REFUSE(b, se_image_reference_locked(&b, &id, 0, 1));
	REFUSE(b, se_image_begin_locked(&b, 11, 101, 1, 2, &empty));
	put(&b, id, 1, SE_IMAGE_NOT_APPLIED); /* definite failed insert */
	assert(b.reserved == 2 && b.descriptors[0].present == 0);
	put(&b, id, 1, SE_IMAGE_APPLIED);
	put(&b, id, 1, SE_IMAGE_NOT_APPLIED); /* NOEXIST conflict */
	assert(b.descriptors[0].present == 1);
	REFUSE(b, se_image_seal_locked(&b, &id));
	put(&b, id, 2, SE_IMAGE_APPLIED);
	assert(!se_image_seal_locked(&b, &id));
	struct se_image_operation op = {};
	struct se_image_key k = key(3);
	REFUSE(b, se_image_operation_begin_locked(&b, &id, SE_IMAGE_INSERT, &k,
						  &op));
	assert(!se_image_reference_locked(&b, &id, 0, 1));
	assert(se_image_known_locked(&b, &id, 0, 1));
	REFUSE(b, se_image_reference_locked(&b, &id, 0, 2));
	REFUSE(b, se_image_reference_locked(&b, &id, 2, 2));
	REFUSE(b, se_image_reference_locked(&b, &id, UINT32_MAX, 2));
	REFUSE(b, se_image_reference_locked(&b, &id, 1, 0));
	REFUSE(b, se_image_reference_locked(&b, &id, 1, UINT64_MAX));
	REFUSE(b, se_image_release_locked(&b, &id, 0, 2));
	assert(!se_image_known_locked(&b, &id, 0, 2));
	REFUSE(b, se_image_abort_locked(&b, &id));
	assert(!se_image_begin_locked(&b, 11, 102, 1, 0, &empty));
	assert(!se_image_known_locked(&b, &empty, 1, 2));
	assert(!se_image_seal_locked(&b, &empty));
	assert(!se_image_reference_locked(&b, &empty, 1, 2));
	assert(se_image_known_locked(&b, &empty, 1, 2)); /* complete empty */
	assert(!se_image_release_locked(&b, &empty, 1, 2));
	assert(!se_image_reclaim_locked(&b, &empty));
	assert(b.reserved == 2);
	assert(!se_image_release_locked(&b, &id, 0, 1));
	REFUSE(b, se_image_reclaim_locked(&b, &id));
	remove_key(&b, id, 1, SE_IMAGE_NOT_APPLIED);
	assert(b.reserved == 2 && b.descriptors[0].present == 2);
	remove_key(&b, id, 1, SE_IMAGE_APPLIED);
	REFUSE(b, se_image_reclaim_locked(&b, &id));
	remove_key(&b, id, 2, SE_IMAGE_APPLIED);
	assert(b.reserved ==
	       2); /* refund only after final operation and reclaim */
	assert(!se_image_reclaim_locked(&b, &id));
	assert(!b.reserved && b.last_handle == 102);
	REFUSE(b, se_image_reclaim_locked(&b, &id));
	REFUSE(b, se_image_begin_locked(&b, 11, 102, 0, 1, &id));
}

static void operation_ownership(void)
{
	struct se_binding_images b = { .scope = 11, .limit = 1 };
	struct se_image_identity id = {};
	assert(!se_image_begin_locked(&b, 11, 101, 0, 1, &id));
	struct se_image_operation op = {}, other = {};
	struct se_image_key k = key(1);
	assert(!se_image_operation_begin_locked(&b, &id, SE_IMAGE_INSERT, &k,
						&op));
	struct se_image_operation stale = op;
	REFUSE(b, se_image_operation_finish_locked(&b, &op, -1));
	REFUSE(b, se_image_operation_finish_locked(&b, &op, 3));
	op.identity.scope++;
	REFUSE(b, se_image_operation_finish_locked(&b, &op, SE_IMAGE_APPLIED));
	op = stale;
	struct se_binding_images saved = b;
	assert(se_image_operation_finish_locked(&b, &op, SE_IMAGE_UNCERTAIN) ==
	       1);
	assert(!memcmp(&b, &saved, sizeof(b)) && op.owned);
	REFUSE(b, se_image_seal_locked(&b, &id));
	REFUSE(b, se_image_abort_locked(&b, &id));
	REFUSE(b, se_image_operation_begin_locked(&b, &id, SE_IMAGE_INSERT, &k,
						  &other));
	op.key.inode++;
	REFUSE(b, se_image_operation_finish_locked(&b, &op, SE_IMAGE_APPLIED));
	op = stale;
	assert(!se_image_operation_finish_locked(&b, &op, SE_IMAGE_APPLIED));
	REFUSE(b,
	       se_image_operation_finish_locked(&b, &stale, SE_IMAGE_APPLIED));
	assert(!se_image_abort_locked(&b, &id));
	assert(!se_image_operation_begin_locked(&b, &id, SE_IMAGE_DELETE, &k,
						&op));
	saved = b;
	assert(se_image_operation_finish_locked(&b, &op, SE_IMAGE_UNCERTAIN) ==
	       1);
	assert(!memcmp(&b, &saved, sizeof(b)));
	REFUSE(b, se_image_reclaim_locked(&b, &id));
	assert(!se_image_operation_finish_locked(&b, &op,
						 SE_IMAGE_NOT_APPLIED));
	assert(b.reserved == 1 && b.descriptors[0].present == 1);
	remove_key(&b, id, 1, SE_IMAGE_APPLIED);
	assert(!se_image_reclaim_locked(&b, &id));
	REFUSE(b,
	       se_image_operation_finish_locked(&b, &stale, SE_IMAGE_APPLIED));
}

static void reload_and_isolation(void)
{
	struct se_binding_images a = { .scope = 11, .limit = 2 };
	struct se_binding_images b = { .scope = 22, .limit = 2 };
	struct se_image_identity first = {}, foreign = {}, second = {};
	/* Distinct globally authenticated allocation-command sequences. The pure
	 * helper does not authenticate that external node-global ordering. */
	assert(!se_image_begin_locked(&a, 11, 100, 0, 1, &first));
	assert(!se_image_begin_locked(&b, 22, 101, 0, 1, &foreign));
	put(&a, first, 1, SE_IMAGE_APPLIED);
	put(&b, foreign, 1, SE_IMAGE_APPLIED);
	assert(!se_image_seal_locked(&a, &first));
	assert(!se_image_seal_locked(&b, &foreign));
	REFUSE(b, se_image_reference_locked(&b, &first, 0, 1));
	REFUSE(a, se_image_abort_locked(&a, &foreign));
	assert(!se_image_reference_locked(&a, &first, 0, 1));
	__u64 serial = 1;
	__u32 active = 0;
	for (int i = 0; i < 100000; i++) {
		__u32 next = active ^ 1;
		assert(!se_image_reference_locked(&a, &first, next,
						  serial + 1));
		assert(!se_image_release_locked(&a, &first, active, serial));
		REFUSE(a, se_image_release_locked(&a, &first, active, serial));
		REFUSE(a,
		       se_image_reference_locked(&a, &first, active, serial));
		active = next;
		serial++;
		assert(a.reserved == 1 && a.descriptors[0].references == 1);
		assert(se_image_known_locked(&a, &first, active, serial));
	}
	/* Descriptor one may be prepared while descriptor zero remains referenced,
	 * independent of which snapshot slot is active. */
	assert(!se_image_begin_locked(&a, 11, 102, 1, 1, &second));
	put(&a, second, 2, SE_IMAGE_APPLIED);
	assert(!se_image_seal_locked(&a, &second));
	assert(a.reserved == 2);
	REFUSE(a, se_image_begin_locked(&a, 11, 103, 0, 1, &foreign));
	assert(!se_image_reference_locked(&a, &second, active ^ 1, serial + 1));
	assert(!se_image_release_locked(&a, &first, active, serial));
	assert(a.descriptors[0].phase == SE_IMAGE_RETIRING);
	assert(se_image_known_locked(&a, &second, active ^ 1, serial + 1));
	remove_key(&a, first, 1, SE_IMAGE_APPLIED);
	assert(!se_image_reclaim_locked(&a, &first));
	assert(a.reserved == 1 && b.reserved == 1);
}

static void partial_candidate_abort(void)
{
	struct se_binding_images b = { .scope = 9, .limit = 3 };
	struct se_image_identity id = {};
	assert(!se_image_begin_locked(&b, 9, 10, 0, 3, &id));
	put(&b, id, 1, SE_IMAGE_APPLIED);
	assert(!se_image_abort_locked(&b, &id));
	assert(b.reserved == 3 && b.descriptors[0].present == 1);
	REFUSE(b, se_image_reclaim_locked(&b, &id));
	remove_key(&b, id, 1, SE_IMAGE_NOT_APPLIED);
	assert(b.reserved == 3 && b.descriptors[0].present == 1);
	remove_key(&b, id, 1, SE_IMAGE_APPLIED);
	assert(b.reserved == 3);
	assert(!se_image_reclaim_locked(&b, &id));
	assert(!b.reserved);
	struct se_image_identity replacement = {};
	assert(!se_image_begin_locked(&b, 9, 11, 0, 0, &replacement));
	REFUSE(b, se_image_abort_locked(&b, &id));
	REFUSE(b, se_image_reclaim_locked(&b, &id));
	assert(!se_image_abort_locked(&b, &replacement));
	assert(!se_image_reclaim_locked(&b, &replacement));
}

static void boundaries(void)
{
	struct se_binding_images b = { .scope = 1, .limit = UINT32_MAX };
	struct se_image_identity id = {}, other = {};
	assert(!se_image_begin_locked(&b, 1, 2, 0, UINT32_MAX, &id));
	REFUSE(b, se_image_begin_locked(&b, 1, 3, 1, 1, &other));
	assert(!se_image_abort_locked(&b, &id));
	assert(!se_image_reclaim_locked(&b, &id));
	assert(!b.reserved);
	assert(!se_image_begin_locked(&b, 1, UINT64_MAX - 1, 0, 1, &id));
	REFUSE(b, se_image_begin_locked(&b, 1, UINT64_MAX, 1, 0, &other));
	b.descriptors[0].next_operation = UINT64_MAX - 1;
	struct se_image_operation op = {};
	struct se_image_key k = key(1);
	REFUSE(b, se_image_operation_begin_locked(&b, &id, SE_IMAGE_INSERT, &k,
						  &op));
	b.descriptors[0].next_operation = 0;
	k.major = 1U << 12;
	REFUSE(b, se_image_operation_begin_locked(&b, &id, SE_IMAGE_INSERT, &k,
						  &op));
	k = key(1);
	k.minor = 1U << 20;
	REFUSE(b, se_image_operation_begin_locked(&b, &id, SE_IMAGE_INSERT, &k,
						  &op));
}
int main(void)
{
	allocation_and_completion();
	operation_ownership();
	reload_and_isolation();
	partial_candidate_abort();
	boundaries();
	puts("shared image state: ownership, quota, completion, 100000 reloads, retirement PASS");
}
