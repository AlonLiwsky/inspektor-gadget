/* SPDX-License-Identifier: GPL-2.0 */
/* Role lifecycle SPIKE: no bootstrap lineage validation or production owner. */
#ifndef FULL_ROLES_H
#define FULL_ROLES_H
#define FR_SLOTS 16
#define FR_ACTIVE 8
struct fr_entry {
	__u64 uid, roles;
};
struct fr_seed {
	__u64 revision;
	struct fr_entry entries[FR_SLOTS];
};
/* A working copy avoids helper calls under task locks and keeps verifier work
 * bounded. Caller snapshots committed entries under lock, merges OUTSIDE the
 * lock, then publishes the whole validated result under lock. Only current-task
 * hooks mutate runnable state; fork initializes a child before it is runnable.
 * Failed merge never publishes its partially changed working copy. */
struct fr_merge_work {
	struct fr_seed seed;
	struct fr_entry entries[FR_SLOTS];
	int error;
};
struct fr_merge_context {
	struct fr_merge_work *work;
};
struct fr_find_context {
	struct fr_merge_work *work;
	__u64 uid;
	__u32 source;
	int free, found, duplicate;
};
static long fr_find_slot(__u32 j, void *opaque)
{
	struct fr_find_context *c = opaque;
	if (j >= FR_SLOTS)
		return 1;
	struct fr_merge_work *w = c->work;
	if (j < c->source && w->seed.entries[j].uid == c->uid)
		c->duplicate = 1;
	if (w->entries[j].uid == c->uid)
		c->found = 1;
	if (!w->entries[j].uid && c->free < 0)
		c->free = j;
	return 0;
}
static long fr_merge_one(__u32 i, void *opaque)
{
	struct fr_merge_context *ctx = opaque;
	struct fr_merge_work *w = ctx->work;
	if (i >= FR_SLOTS || w->error)
		return 1;
	__u64 uid = w->seed.entries[i].uid;
	if (!uid)
		return 0;
	struct fr_find_context find = {
		.work = w, .uid = uid, .source = i, .free = -1
	};
	if (bpf_loop(FR_SLOTS, fr_find_slot, &find, 0) < 0 || find.duplicate) {
		w->error = 1;
		return 1;
	}
	if (find.found)
		return 0;
	int free = find.free;
	if (free < 0 || free >= FR_SLOTS) {
		w->error = 1;
		return 1;
	}
	w->entries[free] = w->seed.entries[i];
	return 0;
}
static __always_inline int fr_merge(struct fr_merge_work *w)
{
	w->error = 0;
	struct fr_merge_context ctx = { w };
	return bpf_loop(FR_SLOTS, fr_merge_one, &ctx, 0) < 0 || w->error ? -1 :
									   0;
}
static __always_inline __u64 fr_lookup(struct fr_entry *entries, __u64 uid)
{
#pragma clang loop unroll(full)
	for (int i = 0; i < FR_SLOTS; i++)
		if (entries[i].uid == uid)
			return entries[i].roles;
	return 0;
}
#endif
