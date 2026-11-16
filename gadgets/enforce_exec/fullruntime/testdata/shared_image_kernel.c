/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
struct bpf_spin_lock {
	int held;
};
static int lock_depth, lookups, updates, deletes, update_error, delete_error;
static int update_applied_error, delete_applied_error;
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	assert(!lock_depth && !lock->held);
	lock_depth = lock->held = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	assert(lock_depth == 1 && lock->held);
	lock_depth = lock->held = 0;
}
#define SEC(x)
#define __uint(n, v) int(*n)[v]
#define __type(n, t) t *n
#define BPF_MAP_TYPE_HASH 1
#define BPF_F_RDONLY 8
#define BPF_NOEXIST 1
#define SE_PROFILE_IMAGES 8
#define SE_PROFILE_BINDINGS 2
#define SE_PROFILE_IMAGE_QUOTA 4
static void *bpf_map_lookup_elem(void *, const void *);
static long bpf_map_update_elem(void *, const void *, const void *, __u64);
static long bpf_map_delete_elem(void *, const void *);
#define ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE 1
#include "shared_image_kernel.h"
#include "shared_image_snapshot.h"
_Static_assert(SE_IMAGE_MAP_EEXIST == EEXIST && SE_IMAGE_MAP_ENOENT == ENOENT,
	       "Linux helper errors");
_Static_assert(sizeof(*se_image_keys.type) / sizeof(int) == BPF_MAP_TYPE_HASH,
	       "fixed hash membership map");
_Static_assert(sizeof(*se_image_keys.max_entries) / sizeof(int) == 8,
	       "explicit key pool");
_Static_assert(sizeof(*se_image_keys.map_flags) / sizeof(int) == BPF_F_RDONLY,
	       "preallocated and userspace read-only");
_Static_assert(sizeof(*se_image_keys.key) == 24,
	       "handle plus existing origin identity");
_Static_assert(sizeof(*se_image_keys.value) == 1, "membership only");
struct row {
	int used;
	struct se_image_map_key key;
	__u8 value;
};
static struct row rows[SE_PROFILE_IMAGES];
static struct bpf_spin_lock locks[2];
static struct se_binding_images bindings[2];
static int equal(const struct se_image_map_key *a,
		 const struct se_image_map_key *b)
{
	return a->image_handle == b->image_handle &&
	       a->origin.inode == b->origin.inode &&
	       a->origin.major == b->origin.major &&
	       a->origin.minor == b->origin.minor;
}
static struct row *find(const struct se_image_map_key *key)
{
	for (unsigned i = 0; i < SE_PROFILE_IMAGES; i++)
		if (rows[i].used && equal(&rows[i].key, key))
			return &rows[i];
	return 0;
}
static void *bpf_map_lookup_elem(void *map, const void *key)
{
	assert(!lock_depth && map == &se_image_keys);
	lookups++;
	struct row *r = find(key);
	return r ? &r->value : 0;
}
static void assert_owned_map_operation(const struct se_image_map_key *key,
				       __u32 kind)
{
	int found = 0;
	for (__u32 slot = 0; slot < 2; slot++) {
		for (__u32 index = 0; index < 2; index++) {
			struct se_image_descriptor *d =
				&bindings[slot].descriptors[index];
			if (d->handle != key->image_handle)
				continue;
			assert(d->pending_sequence && d->pending_kind == kind &&
			       d->pending_key.inode == key->origin.inode &&
			       d->pending_key.major == key->origin.major &&
			       d->pending_key.minor == key->origin.minor);
			struct se_image_identity id = { .scope = d->scope,
							.handle = d->handle,
							.descriptor = index };
			bpf_spin_lock(&locks[slot]);
			assert(se_image_abort_locked(&bindings[slot], &id) < 0);
			assert(se_image_seal_locked(&bindings[slot], &id) < 0);
			assert(se_image_reclaim_locked(&bindings[slot], &id) <
			       0);
			bpf_spin_unlock(&locks[slot]);
			found++;
		}
	}
	assert(found == 1);
}
static long bpf_map_update_elem(void *map, const void *key, const void *value,
				__u64 flags)
{
	assert(!lock_depth && map == &se_image_keys && flags == BPF_NOEXIST);
	updates++;
	assert_owned_map_operation(key, SE_IMAGE_INSERT);
	if (update_error)
		return update_error;
	if (find(key))
		return -17;
	for (unsigned i = 0; i < SE_PROFILE_IMAGES; i++)
		if (!rows[i].used) {
			rows[i] = (struct row){
				.used = 1,
				.key = *(const struct se_image_map_key *)key,
				.value = *(const __u8 *)value
			};
			return update_applied_error;
		}
	return -12;
}
static long bpf_map_delete_elem(void *map, const void *key)
{
	assert(!lock_depth && map == &se_image_keys);
	deletes++;
	assert_owned_map_operation(key, SE_IMAGE_DELETE);
	if (delete_error)
		return delete_error;
	struct row *r = find(key);
	if (!r)
		return -2;
	memset(r, 0, sizeof(*r));
	return delete_applied_error;
}
static void reset(void)
{
	memset(rows, 0, sizeof(rows));
	memset(locks, 0, sizeof(locks));
	bindings[0] = (struct se_binding_images){ .scope = 11, .limit = 4 };
	bindings[1] = (struct se_binding_images){ .scope = 22, .limit = 4 };
	lock_depth = lookups = updates = deletes = update_error = delete_error =
		0;
	update_applied_error = delete_applied_error = 0;
}
static struct se_image_identity allocate(__u32 slot, __u64 sequence,
					 __u32 expected)
{
	struct se_image_identity id = {};
	bpf_spin_lock(&locks[slot]);
	assert(!se_image_begin_locked(&bindings[slot], bindings[slot].scope,
				      sequence, 0, expected, &id));
	bpf_spin_unlock(&locks[slot]);
	return id;
}
static struct se_image_map_request
request(__u32 slot, struct se_image_identity id, __u32 kind, __u64 inode)
{
	return (struct se_image_map_request){
		.slot = slot,
		.identity = id,
		.kind = kind,
		.key = { .inode = inode, .major = 8, .minor = 1 }
	};
}
static void ready(__u32 slot, struct se_image_identity id)
{
	bpf_spin_lock(&locks[slot]);
	assert(!se_image_seal_locked(&bindings[slot], &id));
	assert(!se_image_reference_locked(&bindings[slot], &id, 0, 1));
	bpf_spin_unlock(&locks[slot]);
}
static int lookup(__u32 slot, struct se_image_identity id, __u64 inode)
{
	struct se_image_lookup_request r = {
		.slot = slot,
		.identity = id,
		.record = 0,
		.serial = 1,
		.key = { .inode = inode, .major = 8, .minor = 1 }
	};
	return se_image_map_lookup(&locks[slot], &bindings[slot], &r);
}
static void normal_lifecycle(void)
{
	reset();
	struct se_image_identity id = allocate(0, 100, 2);
	assert(lookup(0, id, 1) == -1 && !lookups);
	struct se_image_map_request r = request(0, id, SE_IMAGE_INSERT, 1);
	struct se_image_operation op = {};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	assert(!op.owned && bindings[0].descriptors[0].present == 1);
	struct se_image_map_key mapkey = { .image_handle = id.handle,
					   .origin = r.key };
	struct row *existing = find(&mapkey);
	assert(existing && existing->value == 1);
	existing->value =
		7; /* duplicate must not overwrite even malformed membership */
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_NOT_APPLIED);
	assert(existing->value == 7 && bindings[0].descriptors[0].present == 1);
	existing->value = 1;
	r.key.inode = 2;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	ready(0, id);
	assert(lookup(0, id, 1) == 1);
	assert(lookup(0, id, 3) == 0);
	existing->value = 7;
	assert(lookup(0, id, 1) == -1);
	existing->value = 1;
	int calls = updates;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) < 0);
	assert(updates == calls);
	bpf_spin_lock(&locks[0]);
	assert(!se_image_release_locked(&bindings[0], &id, 0, 1));
	bpf_spin_unlock(&locks[0]);
	assert(lookup(0, id, 1) == -1);
	r.kind = SE_IMAGE_DELETE;
	r.key.inode = 3;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_NOT_APPLIED);
	assert(bindings[0].descriptors[0].present == 2 &&
	       bindings[0].reserved == 2);
	r.key.inode = 1;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	assert(bindings[0].descriptors[0].present == 1 &&
	       bindings[0].reserved == 2);
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_NOT_APPLIED);
	assert(bindings[0].descriptors[0].present == 1);
	r.key.inode = 2;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	assert(bindings[0].reserved == 2);
	bpf_spin_lock(&locks[0]);
	assert(!se_image_reclaim_locked(&bindings[0], &id));
	bpf_spin_unlock(&locks[0]);
	assert(!bindings[0].reserved && !lock_depth);
}
static void invalid_and_uncertain(void)
{
	reset();
	struct se_image_identity id = allocate(0, 100, 1);
	struct se_image_map_request r = request(0, id, SE_IMAGE_INSERT, 1);
	struct se_image_operation op = {};
	struct se_binding_images saved = bindings[0];
	r.slot = SE_PROFILE_BINDINGS;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) < 0);
	r.slot = 0;
	r.identity.scope++;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) < 0);
	r.identity = id;
	r.identity.handle++;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) < 0);
	r.identity = id;
	r.key.major = 1U << 12;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) < 0);
	assert(!updates && !memcmp(&saved, &bindings[0], sizeof(saved)));
	r.key.major = 8;
	update_error = -5;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_UNCERTAIN);
	assert(op.owned && bindings[0].reserved == 1 &&
	       !bindings[0].descriptors[0].present);
	saved = bindings[0];
	int calls = updates;
	struct se_image_operation forged = op;
	forged.sequence++;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &forged) < 0);
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) < 0);
	struct se_image_operation fresh = {};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &fresh) < 0);
	assert(updates == calls &&
	       !memcmp(&saved, &bindings[0], sizeof(saved)));
	bpf_spin_lock(&locks[0]);
	assert(se_image_abort_locked(&bindings[0], &id) < 0);
	assert(se_image_reclaim_locked(&bindings[0], &id) < 0);
	bpf_spin_unlock(&locks[0]);
	/* Unknown mutation stays pending: this fixture does not invent a receipt. */
	reset();
	id = allocate(0, 101, 1);
	r = request(0, id, SE_IMAGE_INSERT, 1);
	op = (struct se_image_operation){};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	bpf_spin_lock(&locks[0]);
	assert(!se_image_abort_locked(&bindings[0], &id));
	bpf_spin_unlock(&locks[0]);
	delete_error = -5;
	r.kind = SE_IMAGE_DELETE;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_UNCERTAIN);
	assert(op.owned && bindings[0].reserved == 1 &&
	       bindings[0].descriptors[0].present == 1);
	struct se_image_map_key mk = { .image_handle = id.handle,
				       .origin = r.key };
	assert(find(&mk));
	calls = deletes;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) < 0 &&
	       deletes == calls);
}
static void ambiguous_applied_outcomes(void)
{
	/* Deliberately stronger synthetic failures than normal Linux hash errors:
	 * physical mutation followed by an unknown reported outcome. No claim of
	 * kernel behavior or successful cleanup of either unresolved operation. */
	reset();
	struct se_image_identity id = allocate(0, 200, 1);
	struct se_image_map_request r = request(0, id, SE_IMAGE_INSERT, 4);
	struct se_image_operation op = {};
	update_applied_error = -5;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_UNCERTAIN);
	struct se_image_map_key key = { .image_handle = id.handle,
					.origin = r.key };
	assert(find(&key) && op.owned && !bindings[0].descriptors[0].present);
	assert(bindings[0].reserved == 1);
	bpf_spin_lock(&locks[0]);
	assert(se_image_abort_locked(&bindings[0], &id) < 0);
	assert(se_image_reclaim_locked(&bindings[0], &id) < 0);
	bpf_spin_unlock(&locks[0]);
	reset(); /* Independent fixture, NOT resource-reclamation evidence. */
	id = allocate(0, 201, 1);
	r = request(0, id, SE_IMAGE_INSERT, 4);
	op = (struct se_image_operation){};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	bpf_spin_lock(&locks[0]);
	assert(!se_image_abort_locked(&bindings[0], &id));
	bpf_spin_unlock(&locks[0]);
	delete_applied_error = -5;
	r.kind = SE_IMAGE_DELETE;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_UNCERTAIN);
	key.image_handle = id.handle;
	assert(!find(&key) && op.owned &&
	       bindings[0].descriptors[0].present == 1);
	assert(bindings[0].reserved == 1);
	bpf_spin_lock(&locks[0]);
	assert(se_image_reclaim_locked(&bindings[0], &id) < 0);
	bpf_spin_unlock(&locks[0]);
}

static void lookup_and_isolation(void)
{
	reset();
	struct se_image_identity a = allocate(0, 100, 0);
	struct se_image_identity b = allocate(1, 101, 1);
	assert(lookup(0, a, 1) == -1);
	ready(0, a);
	assert(lookup(0, a, 1) == 0); /* complete-empty, not absent evidence */
	assert(se_image_map_lookup(&locks[0], &bindings[0], 0) == -1);
	assert(se_image_map_lookup(&locks[0], 0, 0) == -1);
	assert(lookup(0, (struct se_image_identity){}, 1) == -1);
	struct se_image_map_request r = request(1, b, SE_IMAGE_INSERT, 1);
	struct se_image_operation op = {};
	assert(se_image_map_change(&locks[1], &bindings[1], &r, &op) ==
	       SE_IMAGE_APPLIED);
	ready(1, b);
	assert(lookup(1, b, 1) == 1 && lookup(0, a, 1) == 0);
	assert(lookup(0, b, 1) == -1 && lookup(1, a, 1) == -1);
	struct se_image_lookup_request q = {
		.slot = 1,
		.identity = b,
		.record = 0,
		.serial = 2,
		.key = { .inode = 1, .major = 8, .minor = 1 }
	};
	int calls = lookups;
	assert(se_image_map_lookup(&locks[1], &bindings[1], &q) == -1);
	q.serial = 1;
	q.key.minor = 1U << 20;
	assert(se_image_map_lookup(&locks[1], &bindings[1], &q) == -1 &&
	       lookups == calls);
}
static void independent_same_key_bindings(void)
{
	reset();
	struct se_image_identity a = allocate(0, 100, 1);
	struct se_image_identity b = allocate(1, 101, 1);
	struct se_image_map_request r = request(0, a, SE_IMAGE_INSERT, 9);
	struct se_image_operation op = {};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	r = request(1, b, SE_IMAGE_INSERT, 9);
	assert(se_image_map_change(&locks[1], &bindings[1], &r, &op) ==
	       SE_IMAGE_APPLIED);
	ready(0, a);
	ready(1, b);
	assert(lookup(0, a, 9) == 1 && lookup(1, b, 9) == 1);
	bpf_spin_lock(&locks[0]);
	assert(!se_image_release_locked(&bindings[0], &a, 0, 1));
	bpf_spin_unlock(&locks[0]);
	r = request(0, b, SE_IMAGE_DELETE, 9);
	int calls = deletes;
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) < 0);
	assert(deletes == calls);
	r = request(0, a, SE_IMAGE_DELETE, 9);
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	bpf_spin_lock(&locks[0]);
	assert(!se_image_reclaim_locked(&bindings[0], &a));
	bpf_spin_unlock(&locks[0]);
	assert(!bindings[0].reserved && bindings[1].reserved == 1);
	assert(bindings[1].descriptors[0].present == 1 && lookup(1, b, 9) == 1);
}

/* G020: exclusive-ownership reconciliation of an UNCERTAIN operation. The
 * charge is retained (no seal, abort or reclaim) until it is reconciled. */
static void reconcile_uncertain(void)
{
	reset();
	struct se_image_identity id = allocate(0, 300, 2);
	struct se_image_map_request r = request(0, id, SE_IMAGE_INSERT, 1);
	struct se_image_operation op = {};
	int outcome = 7;
	assert(!se_image_map_reconcile(&locks[0], &bindings[0], &id,
				       &outcome) &&
	       outcome == -1); /* nothing pending */
	update_applied_error = -5; /* physically inserted, outcome unknown */
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_UNCERTAIN);
	update_applied_error = 0;
	bpf_spin_lock(&locks[0]);
	assert(se_image_seal_locked(&bindings[0], &id) < 0);
	assert(se_image_abort_locked(&bindings[0], &id) < 0);
	assert(se_image_reclaim_locked(&bindings[0], &id) < 0);
	bpf_spin_unlock(&locks[0]);
	assert(bindings[0].reserved == 2);
	struct se_image_identity forged = id;
	forged.handle++;
	assert(se_image_map_reconcile(&locks[0], &bindings[0], &forged,
				      &outcome) < 0);
	assert(!se_image_map_reconcile(&locks[0], &bindings[0], &id,
				       &outcome) &&
	       outcome == SE_IMAGE_APPLIED);
	assert(bindings[0].descriptors[0].present == 1 &&
	       !bindings[0].descriptors[0].pending_sequence);
	update_error = -5; /* definitely not inserted, outcome unknown */
	r.key.inode = 2;
	op = (struct se_image_operation){};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_UNCERTAIN);
	update_error = 0;
	assert(!se_image_map_reconcile(&locks[0], &bindings[0], &id,
				       &outcome) &&
	       outcome == SE_IMAGE_NOT_APPLIED);
	assert(bindings[0].descriptors[0].present == 1);
	op = (struct se_image_operation){};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	/* Malformed membership never settles a pending delete. */
	bpf_spin_lock(&locks[0]);
	assert(!se_image_abort_locked(&bindings[0], &id));
	bpf_spin_unlock(&locks[0]);
	r.kind = SE_IMAGE_DELETE;
	delete_error = -5;
	op = (struct se_image_operation){};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_UNCERTAIN);
	delete_error = 0;
	struct se_image_map_key mk = { .image_handle = id.handle,
				       .origin = r.key };
	find(&mk)->value = 3;
	assert(se_image_map_reconcile(&locks[0], &bindings[0], &id, &outcome) <
	       0);
	find(&mk)->value = 1;
	assert(!se_image_map_reconcile(&locks[0], &bindings[0], &id,
				       &outcome) &&
	       outcome == SE_IMAGE_NOT_APPLIED);
	op = (struct se_image_operation){};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	delete_applied_error = -5; /* physically deleted, outcome unknown */
	r.key.inode = 1;
	op = (struct se_image_operation){};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_UNCERTAIN);
	delete_applied_error = 0;
	assert(!se_image_map_reconcile(&locks[0], &bindings[0], &id,
				       &outcome) &&
	       outcome == SE_IMAGE_APPLIED);
	assert(!bindings[0].descriptors[0].present);
	bpf_spin_lock(&locks[0]);
	assert(!se_image_reclaim_locked(&bindings[0], &id));
	bpf_spin_unlock(&locks[0]);
	assert(!bindings[0].reserved && !lock_depth);
}

static struct se_binding_snapshots snaps;
static struct se_image_identity sealed(__u32 index, __u64 sequence, __u32 dev,
				       __u64 inode)
{
	struct se_image_identity id = {};
	bpf_spin_lock(&locks[0]);
	assert(!se_image_begin_dev_locked(&bindings[0], bindings[0].scope,
					  sequence, index, 1, dev, &id));
	bpf_spin_unlock(&locks[0]);
	struct se_image_map_request r = request(0, id, SE_IMAGE_INSERT, inode);
	struct se_image_operation op = {};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	bpf_spin_lock(&locks[0]);
	assert(!se_image_seal_locked(&bindings[0], &id));
	bpf_spin_unlock(&locks[0]);
	return id;
}
/* The publisher's PREPARE: prepare, metadata, image reference, or undo. */
static int prepare(__u32 record, __u64 handle, __u32 dev)
{
	struct se_pin_ticket ticket = { .object_generation = 1,
					.object_slot = 0 };
	bpf_spin_lock(&locks[0]);
	int result = se_snapshot_prepare_locked(&snaps, record, &ticket, 1, 1);
	if (!result) {
		snaps.records[record].metadata.image_handle = handle;
		snaps.records[record].metadata.image_dev = dev;
		result = se_image_snapshot_prepare_locked(&bindings[0], &snaps,
							  record);
		if (result)
			snaps.records[record] = (struct se_snapshot){};
	}
	bpf_spin_unlock(&locks[0]);
	return result;
}
static int reclaim(__u32 record)
{
	bpf_spin_lock(&locks[0]);
	int result =
		se_image_snapshot_reclaim_locked(&bindings[0], &snaps, record);
	bpf_spin_unlock(&locks[0]);
	return result;
}
/* PREPARE references, FREE releases exactly once, the two-record grace
 * period holds two references, and stale or unsealed handles are refused. */
static void snapshot_lifetime(void)
{
	reset();
	snaps = (struct se_binding_snapshots){ .scope = 11 };
	struct se_snapshot_metadata m = { .root_epochs = { 1 },
					  .policy_uids = { 9 },
					  .container_length = 1 };
	assert(se_snapshot_metadata_valid(&m, 1, 1));
	m.image_handle = 100;
	assert(!se_snapshot_metadata_valid(&m, 1, 1)); /* handle without dev */
	m.image_dev = 0x2a;
	assert(se_snapshot_metadata_valid(&m, 1, 1));
	m.image_dev = 8U << 20 | 1; /* not an anonymous (major 0) overlay */
	assert(!se_snapshot_metadata_valid(&m, 1, 1));
	m.image_handle = 0;
	m.image_dev = 0x2a;
	assert(!se_snapshot_metadata_valid(&m, 1, 1)); /* dev without handle */

	struct se_image_identity a = sealed(0, 100, 0x2a, 1);
	struct se_image_descriptor *d = &bindings[0].descriptors[0];
	assert(prepare(0, 100, 0x2a) == 0 && d->references == 1 &&
	       bindings[0].snapshots[0].held &&
	       bindings[0].snapshots[0].serial == snaps.records[0].serial);
	__u64 first = snaps.records[0].serial;
	snaps.records[0].phase = SE_SNAPSHOT_ACTIVE;
	/* Wrong dev, unknown handle and an unsealed handle are refused, and
	 * the refused PREPARE leaves the record FREE without a reference. */
	assert(prepare(1, 100, 0x2b) < 0 && !snaps.records[1].phase);
	assert(prepare(1, 555, 0x2a) < 0 && !snaps.records[1].phase);
	struct se_image_identity building = {};
	bpf_spin_lock(&locks[0]);
	assert(!se_image_begin_dev_locked(&bindings[0], 11, 101, 1, 1, 0x2a,
					  &building));
	bpf_spin_unlock(&locks[0]);
	assert(prepare(1, 101, 0x2a) < 0 && !snaps.records[1].phase);
	assert(d->references == 1 && !bindings[0].snapshots[1].held);
	bpf_spin_lock(&locks[0]);
	assert(!se_image_abort_locked(&bindings[0], &building));
	assert(!se_image_reclaim_locked(&bindings[0], &building));
	/* A stale serial is never referenced again on its record. */
	assert(se_image_reference_locked(&bindings[0], &a, 0, first) < 0);
	/* The open state never takes a new scope while referenced. */
	assert(se_image_open_locked(&bindings[0], 12, 4) < 0);
	bpf_spin_unlock(&locks[0]);
	/* Imageless revision record: no reference. */
	assert(prepare(1, 0, 0) == 0 && d->references == 1 &&
	       !bindings[0].snapshots[1].held);
	snaps.records[1].phase = SE_SNAPSHOT_RETIRING;
	assert(reclaim(1) == 0 && !snaps.records[1].phase);
	/* Revision grace period: both records reference one descriptor. */
	assert(prepare(1, 100, 0x2a) == 0 && d->references == 2);
	snaps.records[1].phase = SE_SNAPSHOT_ACTIVE;
	snaps.records[0].phase = SE_SNAPSHOT_RETIRING;
	snaps.records[0].claims = 1; /* a reader still holds the old record */
	assert(reclaim(0) < 0 && d->references == 2 &&
	       snaps.records[0].phase == SE_SNAPSHOT_RETIRING);
	assert(lookup(0, a, 1) == 1); /* the reader's lookup stays known */
	snaps.records[0].claims = 0;
	assert(reclaim(0) == 0 && d->references == 1 &&
	       !bindings[0].snapshots[0].held &&
	       bindings[0].snapshots[0].serial == first &&
	       d->phase == SE_IMAGE_COMPLETE);
	/* Exactly once: a second reclaim of the FREE record is refused. */
	assert(reclaim(0) < 0 && d->references == 1);
	/* A record naming a handle without its reference is never freed. */
	assert(prepare(0, 0, 0) == 0);
	snaps.records[0].metadata.image_handle = 100;
	snaps.records[0].metadata.image_dev = 0x2a;
	snaps.records[0].phase = SE_SNAPSHOT_RETIRING;
	assert(reclaim(0) < 0 &&
	       snaps.records[0].phase == SE_SNAPSHOT_RETIRING &&
	       d->references == 1);
	snaps.records[0].metadata.image_handle = 0;
	snaps.records[0].metadata.image_dev = 0;
	assert(reclaim(0) == 0);
	/* An imageless record with a held reference is refused too. */
	assert(prepare(0, 0, 0) == 0);
	snaps.records[0].phase = SE_SNAPSHOT_RETIRING;
	bindings[0].snapshots[0].held = 1;
	assert(reclaim(0) < 0);
	bindings[0].snapshots[0].held = 0;
	assert(reclaim(0) == 0);
	/* Unbind: the last FREE retires the descriptor; exact deletes, then
	 * reclaim, then the state takes the next binding's scope. */
	snaps.records[1].phase = SE_SNAPSHOT_RETIRING;
	assert(reclaim(1) == 0 && !d->references &&
	       d->phase == SE_IMAGE_RETIRING);
	assert(lookup(0, a, 1) == -1);
	struct se_image_map_request r = request(0, a, SE_IMAGE_DELETE, 1);
	struct se_image_operation op = {};
	assert(se_image_map_change(&locks[0], &bindings[0], &r, &op) ==
	       SE_IMAGE_APPLIED);
	bpf_spin_lock(&locks[0]);
	assert(se_image_open_locked(&bindings[0], 12, 4) < 0);
	assert(!se_image_reclaim_locked(&bindings[0], &a));
	assert(!se_image_open_locked(&bindings[0], 12, 4));
	assert(bindings[0].scope == 12 && bindings[0].last_handle == 101 &&
	       !bindings[0].snapshots[0].serial);
	/* Handles never go backwards across scopes. */
	struct se_image_identity again = {};
	assert(se_image_begin_dev_locked(&bindings[0], 12, 101, 0, 1, 0x2a,
					 &again) < 0);
	assert(se_image_begin_dev_locked(&bindings[0], 12, 102, 0, 1, 0,
					 &again) < 0);
	assert(!se_image_begin_dev_locked(&bindings[0], 12, 102, 0, 1, 0x2a,
					  &again));
	assert(bindings[0].descriptors[0].overlay_dev == 0x2a);
	bpf_spin_unlock(&locks[0]);
	assert(!lock_depth);
}

int main(void)
{
	reconcile_uncertain();
	snapshot_lifetime();
	normal_lifecycle();
	invalid_and_uncertain();
	ambiguous_applied_outcomes();
	lookup_and_isolation();
	independent_same_key_bindings();
	puts("shared image adapter: exact keys, NOEXIST, outside-lock maps, uncertainty, reconciliation, snapshot lifetime and isolation PASS");
}
