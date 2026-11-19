/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ENFORCE_EXEC_SHARED_ARENA_H
#define ENFORCE_EXEC_SHARED_ARENA_H

/* Shared-development object state. Production adapters must authenticate admin
 * commands and hold this object's lock for every _locked call. A writer claim
 * remains live outside that lock through its LAST actual arena store. These
 * helpers neither authorize a map FD nor implement snapshot pin tickets.
 * Slot/class are immutable profile-derived identities; no caller-provided base.
 */
#define SE_OBJECT_FREE 0
#define SE_OBJECT_LOADING 1
#define SE_OBJECT_READY 2
#define SE_OBJECT_RETIRING 3
struct se_object {
	__u64 generation, attempt, writer_sequence, next_sequence;
	__u32 slot, size_class, phase, length, completed, pins, commands;
	__u32 rule_count, execution_class, reserved;
};
struct se_write_claim {
	__u64 generation, attempt, sequence;
	__u32 slot, index, owned, reserved;
};
/* All object transitions below run under the object spinlock. Stock Rocky
 * 4.18 disallows a BPF-to-BPF call in that lexical region. */
static __attribute__((always_inline)) inline __u32
se_object_capacity(__u32 size_class)
{
	switch (size_class) {
	case 0:
		return 256;
	case 1:
		return 1024;
	case 2:
		return 4096;
	case 3:
		return 16384;
	default:
		return 0;
	}
}
static __attribute__((always_inline)) inline int
se_object_begin_locked(struct se_object *s, __u64 attempt, __u32 length)
{
	__u32 capacity = se_object_capacity(s->size_class);
	if (s->phase != SE_OBJECT_FREE || s->pins || s->commands ||
	    s->writer_sequence || s->reserved || !capacity || !length ||
	    length > capacity || !attempt || attempt == ~0ULL ||
	    s->generation >= ~0ULL - 1)
		return -1;
	s->generation++;
	s->attempt = attempt;
	s->next_sequence = 0;
	s->length = length;
	s->completed = 0;
	s->rule_count = 0;
	s->execution_class = 0;
	s->phase = SE_OBJECT_LOADING;
	return 0;
}
static __attribute__((always_inline)) inline int
se_object_write_begin_locked(struct se_object *s, __u64 generation,
			     __u64 attempt, __u32 index,
			     struct se_write_claim *w)
{
	if (s->phase != SE_OBJECT_LOADING || s->generation != generation ||
	    s->attempt != attempt || !generation || !attempt ||
	    s->writer_sequence || s->completed != index || index >= s->length ||
	    s->length > se_object_capacity(s->size_class) || s->reserved ||
	    s->next_sequence >= ~0ULL - 1 || w->owned)
		return -1;
	s->writer_sequence = ++s->next_sequence;
	*w = (struct se_write_claim){ .generation = generation,
				      .attempt = attempt,
				      .sequence = s->writer_sequence,
				      .slot = s->slot,
				      .index = index,
				      .owned = 1 };
	return 0;
}
/* Exact active sequence, not caller-owned alone, prevents copied stale tokens
 * refunding a later writer. Call only AFTER the last physical cell store. */
static __attribute__((always_inline)) inline int
se_object_write_finish_locked(struct se_object *s, struct se_write_claim *w)
{
	if (!w->owned || w->reserved || !w->sequence ||
	    s->phase != SE_OBJECT_LOADING || s->slot != w->slot ||
	    s->generation != w->generation || s->attempt != w->attempt ||
	    s->writer_sequence != w->sequence || s->completed != w->index ||
	    s->completed >= s->length)
		return -1;
	s->completed++;
	s->writer_sequence = 0;
	w->owned = 0;
	return 0;
}
/* The trusted native compiler has validated all semantic data/references. This
 * publication boundary checks complete sequential installation and scalar
 * metadata; it deliberately does not repeat the deep native bytecode walk. */
static __attribute__((always_inline)) inline int
se_object_finalize_locked(struct se_object *s, __u64 generation, __u64 attempt,
			  __u32 rule_count, __u32 execution_class)
{
	if (!generation || !attempt || s->generation != generation ||
	    s->attempt != attempt || s->writer_sequence || s->commands ||
	    !s->length || s->completed != s->length ||
	    s->length > se_object_capacity(s->size_class) || rule_count > 256 ||
	    execution_class < 1 || execution_class > 2 || s->reserved)
		return -1;
	if (s->phase == SE_OBJECT_READY)
		return s->rule_count == rule_count &&
				       s->execution_class == execution_class ?
			       0 :
			       -1;
	if (s->phase != SE_OBJECT_LOADING || s->pins)
		return -1;
	s->rule_count = rule_count;
	s->execution_class = execution_class;
	s->phase = SE_OBJECT_READY;
	return 0;
}
static __attribute__((always_inline)) inline int
se_object_abort_locked(struct se_object *s, __u64 generation, __u64 attempt)
{
	if (!generation || !attempt || s->generation != generation ||
	    s->attempt != attempt || s->writer_sequence || s->pins ||
	    s->commands ||
	    (s->phase != SE_OBJECT_LOADING && s->phase != SE_OBJECT_FREE))
		return -1;
	s->phase = SE_OBJECT_FREE;
	s->length = s->completed = s->rule_count = s->execution_class = 0;
	return 0;
}
static __attribute__((always_inline)) inline int
se_object_retire_locked(struct se_object *s, __u64 generation)
{
	if (!generation || s->generation != generation ||
	    s->phase != SE_OBJECT_READY || s->pins || s->commands ||
	    s->writer_sequence)
		return -1;
	s->phase = SE_OBJECT_RETIRING;
	return 0;
}
static __attribute__((always_inline)) inline int
se_object_reclaim_locked(struct se_object *s, __u64 generation)
{
	if (!generation || s->generation != generation ||
	    s->phase != SE_OBJECT_RETIRING || s->pins || s->commands ||
	    s->writer_sequence)
		return -1;
	s->phase = SE_OBJECT_FREE;
	s->length = s->completed = s->rule_count = s->execution_class = 0;
	return 0;
}
#endif
