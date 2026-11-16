/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_IMAGE_SNAPSHOT_H
#define ENFORCE_EXEC_SHARED_IMAGE_SNAPSHOT_H
#include "shared_snapshot.h"
#include "shared_image.h"

/* G020 image index lifetime, bound to the two snapshot records of one
 * binding. Pure state; the caller holds the binding's sole route lock
 * (se_routes[slot].lock), which protects both se_bindings[slot] and
 * se_image_bindings[slot]. No helper call: safe in the locked region.
 *
 * Invariant: a record that is not FREE and whose metadata names an image
 * handle holds exactly one reference (se_image_reference_locked) on the
 * sealed descriptor of that handle, taken in the same locked transition
 * that PREPAREd it and released in the same locked transition that makes
 * it FREE again (se_snapshot_reclaim_locked). A reader claim on (record,
 * serial) is only held on an ACTIVE or RETIRING record, so it implies the
 * reference: the descriptor stays COMPLETE (never RETIRING), its keys are
 * never deleted, and the exec-side lookup needs no lock. During the
 * two-record grace period of a revision both records reference the same
 * descriptor (references == 2). A record without a handle holds none.
 */

/* The sealed descriptor of handle with the attested overlay dev_t. */
static __attribute__((always_inline)) inline int
se_image_snapshot_identity_locked(const struct se_binding_images *img,
				  __u64 scope, __u64 handle, __u32 image_dev,
				  struct se_image_identity *id)
{
	if (!scope || img->scope != scope || !handle || !image_dev)
		return -1;
#ifdef __clang__
#pragma unroll
#endif
	for (__u32 i = 0; i < 2; i++) {
		const struct se_image_descriptor *d = &img->descriptors[i];
		if (d->scope == scope && d->handle == handle &&
		    d->phase == SE_IMAGE_COMPLETE &&
		    d->overlay_dev == image_dev) {
			*id = (struct se_image_identity){ .scope = scope,
							  .handle = handle,
							  .descriptor = i };
			return 0;
		}
	}
	return -1;
}

/* Right after se_snapshot_prepare_locked and the metadata copy, under the
 * same lock: reference the image the PREPARING record names. 0 referenced
 * (or no image), -1 refused: the caller undoes the PREPARE in this lock. */
static __attribute__((always_inline)) inline int
se_image_snapshot_prepare_locked(struct se_binding_images *img,
				 const struct se_binding_snapshots *b,
				 __u32 record)
{
	if (record >= 2)
		return -1;
	asm volatile("" : "+r"(record));
	record &= 1U;
	const struct se_snapshot *s = &b->records[record];
	if (s->phase != SE_SNAPSHOT_PREPARING || !b->scope ||
	    s->scope != b->scope || !s->serial)
		return -1;
	/* A FREE record never keeps a reference (released at reclaim). */
	if (img->snapshots[record].held)
		return -1;
	__u64 handle = s->metadata.image_handle;
	__u32 image_dev = s->metadata.image_dev;
	if (!handle && !image_dev)
		return 0;
	struct se_image_identity id = {};
	if (se_image_snapshot_identity_locked(img, b->scope, handle, image_dev,
					      &id))
		return -1;
	return se_image_reference_locked(img, &id, record, s->serial);
}

/* Replaces se_snapshot_reclaim_locked for a binding with an image index:
 * the record becomes FREE and its image reference is released in one
 * transition, exactly once. Every precondition of both halves is checked
 * before the first store. 0 reclaimed (and released), -1 nothing changed:
 * a record that names a handle without holding its exact reference, or an
 * imageless record with a reference, is refused (it stays RETIRING). */
static __attribute__((always_inline)) inline int
se_image_snapshot_reclaim_locked(struct se_binding_images *img,
				 struct se_binding_snapshots *b, __u32 record)
{
	if (record >= 2)
		return -1;
	asm volatile("" : "+r"(record));
	record &= 1U;
	struct se_snapshot *s = &b->records[record];
	const struct se_image_reference *r = &img->snapshots[record];
	__u64 serial = s->serial, handle = s->metadata.image_handle;
	struct se_image_identity id = {};
	if (handle) {
		if (r->held != 1 || r->serial != serial ||
		    r->handle != handle || r->descriptor >= 2)
			return -1;
		id = (struct se_image_identity){ .scope = b->scope,
						 .handle = handle,
						 .descriptor = r->descriptor &
							       1U };
		if (!se_image_known_locked(img, &id, record, serial))
			return -1;
	} else if (r->held) {
		return -1;
	}
	if (se_snapshot_reclaim_locked(s))
		return -1;
	/* Infallible: known above, nothing changed it since. */
	if (handle && se_image_release_locked(img, &id, record, serial))
		return -1;
	return 0;
}
#endif
