/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 The Inspektor Gadget authors */
#ifndef IG_EXEC_GATE_H
#define IG_EXEC_GATE_H

typedef unsigned long long fg_u64;
#define FG_CLOSED (1ULL << 63)
#define FG_COUNT_MASK (FG_CLOSED - 1)
#define FG_MAX_ADMITTED 4096U
#define FG_CAS_ATTEMPTS 64U
#define FG_OK 0
#define FG_BUSY 1
#define FG_CAPACITY 2
#define FG_CORRUPT 3
#define FG_UNDERFLOW 4
#define FG_INLINE static __inline __attribute__((always_inline))

/* Aligned atomic access only; never replace a live word with a map update.
 * The no-change CAS is an atomic load supported by the BPF instruction set.
 */
FG_INLINE fg_u64 fg_read(fg_u64 *word)
{
	return __sync_val_compare_and_swap(word, 0, 0);
}

/* On success the actual task transaction must record release ownership before
 * any path can complete. Never inherit this ownership on fork/clone.
 */
FG_INLINE int fg_enter(fg_u64 *word)
{
	if (!word)
		return FG_CORRUPT;
#pragma clang loop unroll(disable)
	for (unsigned int attempt = 0; attempt < FG_CAS_ATTEMPTS; attempt++) {
		fg_u64 value = fg_read(word);
		fg_u64 count = value & FG_COUNT_MASK;
		if (count > FG_MAX_ADMITTED)
			return FG_CORRUPT;
		if (value & FG_CLOSED)
			return FG_BUSY;
		if (count == FG_MAX_ADMITTED)
			return FG_CAPACITY;
		if (__sync_val_compare_and_swap(word, value, value + 1) ==
		    value)
			return FG_OK;
	}
	return FG_BUSY;
}

/* Call after committed-role writes and pending-state cleanup, exactly once for
 * each successful enter. A contention error retains release ownership/count:
 * retry or report a stuck admission, never claim the transaction was released.
 */
FG_INLINE int fg_leave(fg_u64 *word)
{
	if (!word)
		return FG_CORRUPT;
#pragma clang loop unroll(disable)
	for (unsigned int attempt = 0; attempt < FG_CAS_ATTEMPTS; attempt++) {
		fg_u64 value = fg_read(word);
		fg_u64 count = value & FG_COUNT_MASK;
		if (count > FG_MAX_ADMITTED)
			return FG_CORRUPT;
		if (!count)
			return FG_UNDERFLOW;
		if (__sync_val_compare_and_swap(word, value, value - 1) ==
		    value)
			return FG_OK;
	}
	return FG_BUSY;
}
/* The caller has exclusively claimed/cleared transaction ownership, completed
 * committed/pending writes and UNLOCKED before calling this helper. A false
 * claim is a duplicate completion and does nothing. On the valid path the
 * count decrement is the final mutation; no bounded-CAS release can strand it.
 * Sticky faults are never repaired/reset by this helper. */
FG_INLINE int fg_leave_owned(fg_u64 *word, unsigned int claimed, fg_u64 *faults)
{
	if (!claimed)
		return FG_OK;
	if (!word || !faults)
		return FG_CORRUPT;
	fg_u64 value = fg_read(word);
	/* A semantic/lineage fault still forbids new work/readiness, but must not
     * strand an already claimed exact-once release after ownership was cleared.
     * Preserve the fault; validate the counter independently. */
	if (!(value & FG_COUNT_MASK) ||
	    (value & FG_COUNT_MASK) > FG_MAX_ADMITTED) {
		__sync_fetch_and_or(faults, 1);
		return (value & FG_COUNT_MASK) ? FG_CORRUPT : FG_UNDERFLOW;
	}
	value = __sync_fetch_and_sub(word, 1);
	if (!(value & FG_COUNT_MASK) ||
	    (value & FG_COUNT_MASK) > FG_MAX_ADMITTED) {
		/* Impossible with valid exact-once owners: preserve corruption and
         * latch a fault, never repair the count or reopen the gate. */
		__sync_fetch_and_or(faults, 1);
		return FG_CORRUPT;
	}
	return FG_OK;
}
#endif
