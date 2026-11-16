// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
#include "shared_arena.h"

int main(void)
{
	struct se_object s = { .slot = 7, .size_class = 0 };
	struct se_write_claim w = {}, copy = {}, next = {};
	assert(se_object_begin_locked(&s, 1, 2) == 0);
	assert(s.generation == 1 && s.phase == SE_OBJECT_LOADING);
	assert(se_object_write_begin_locked(&s, 1, 1, 1, &w) <
	       0); /* out of order */
	assert(se_object_finalize_locked(&s, 1, 1, 1, 1) < 0); /* incomplete */
	assert(!se_object_write_begin_locked(&s, 1, 1, 0, &w));
	copy = w;
	assert(se_object_write_begin_locked(&s, 1, 1, 0, &next) < 0);
	assert(se_object_abort_locked(&s, 1, 1) <
	       0); /* writer still touches cells */
	assert(!se_object_write_finish_locked(&s, &w));
	assert(se_object_write_finish_locked(&s, &copy) < 0);
	assert(!se_object_write_begin_locked(&s, 1, 1, 1, &next));
	assert(se_object_write_finish_locked(&s, &copy) < 0 &&
	       s.writer_sequence == next.sequence);
	assert(se_object_finalize_locked(&s, 1, 1, 1, 1) < 0);
	assert(!se_object_write_finish_locked(&s, &next));
	assert(!se_object_finalize_locked(&s, 1, 1, 1, 1));
	struct se_object ready = s;
	assert(se_object_write_begin_locked(&s, 1, 1, 0, &w) < 0);
	assert(se_object_abort_locked(&s, 1, 1) < 0);
	assert(!memcmp(&s, &ready, sizeof(s)));
	s.pins = 1;
	assert(se_object_retire_locked(&s, 1) < 0);
	s.pins = 0;
	s.commands = 1;
	assert(se_object_retire_locked(&s, 1) < 0);
	s.commands = 0;
	assert(!se_object_retire_locked(&s, 1));
	assert(!se_object_reclaim_locked(&s, 1));
	assert(!se_object_begin_locked(&s, 2, 1) && s.generation == 2);
	assert(se_object_write_begin_locked(&s, 1, 1, 0, &w) < 0);
	assert(se_object_abort_locked(&s, 1, 1) < 0);
	assert(!se_object_write_begin_locked(&s, 2, 2, 0, &w));
	struct se_object other = { .slot = 8, .size_class = 0 };
	assert(!se_object_begin_locked(&other, 2, 1));
	assert(!se_object_write_begin_locked(&other, 1, 2, 0, &next));
	assert(se_object_write_finish_locked(&other, &w) < 0);
	assert(!se_object_write_finish_locked(&other, &next));
	assert(!se_object_write_finish_locked(&s, &w));
	assert(!se_object_abort_locked(&s, 2, 2));
	s.generation = ~0ULL;
	assert(se_object_begin_locked(&s, 3, 1) < 0);
	for (__u32 c = 0; c < 4; c++) {
		struct se_object x = { .size_class = c };
		__u32 cap = se_object_capacity(c);
		assert(cap && se_object_begin_locked(&x, 1, cap + 1) < 0);
		assert(!se_object_begin_locked(&x, 1, cap));
	}
	puts("shared arena sequential ownership, immutable READY and reuse controls passed");
}
