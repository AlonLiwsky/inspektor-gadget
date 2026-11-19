/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_LOOKUP_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_LOOKUP_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque locator observer is candidate-only"
#endif
#ifndef SE_OL_LOOKUP
#error "provide an opaque-key HASH lookup; never hash the typed task pointer"
#endif
#ifndef SE_OL_META_LOOKUP
#error "provide a stable ARRAY metadata lookup by bounded scalar slot"
#endif
#ifndef SE_OL_TASKS
#error "provide the fixed TASK slot count"
#endif

/* Only a model-to-C observer slice, NOT a selected TASK lease or product ABI.
 * The writer must separately prove zero-before-reuse, unique generations,
 * hold/exclusive exclusion, exact charge and durable withdrawal receipts.
 * No caller may treat a returned lease as policy authority without those
 * proofs. The metadata lock is the only owner of reader_holds/active_leases. */
#define SE_OL_SLOT_BITS 14U
#define SE_OL_SLOT_MASK ((1ULL << SE_OL_SLOT_BITS) - 1ULL)
#define SE_OL_MAX_GENERATION ((1ULL << (64U - SE_OL_SLOT_BITS)) - 1ULL)
#define SE_OL_U32_MAX ((__u32)~0U)
_Static_assert(SE_OL_TASKS > 0 && SE_OL_TASKS <= (1U << SE_OL_SLOT_BITS),
	       "opaque locator TASK geometry");

enum se_ol_result {
	SE_OL_OK = 0,
	SE_OL_STALE,
	SE_OL_CONTENDED,
	SE_OL_LIMIT,
	SE_OL_CORRUPT,
};
enum se_ol_phase {
	SE_OL_FREE = 0,
	SE_OL_LIVE = 1,
	SE_OL_DEAD = 2,
	SE_OL_INITIALIZING = 3,
	SE_OL_PENDING_BIRTH = 4,
	SE_OL_CLEANING = 5,
	SE_OL_ABORTED = 6,
	SE_OL_ARCHIVE_ZEROED = 7,
	SE_OL_REFUND_PENDING = 8,
};
_Static_assert(SE_OL_ARCHIVE_ZEROED != SE_OL_REFUND_PENDING,
	       "archive wipe is not refund authority");
enum se_ol_cleanup_bit {
	SE_OL_EXEC_DONE = 1U,
	SE_OL_CONSTRUCTION_DONE = 2U,
	SE_OL_WORK_DONE = 4U,
	SE_OL_NATIVE_DONE = 8U,
	SE_OL_DIR_DONE = 16U,
	SE_OL_PAYLOAD_ZERO_DONE = 32U,
	SE_OL_ALL_DONE = 63U,
};
enum se_ol_directory_state {
	SE_OL_NO_ENTRY = 0,
	SE_OL_INSERT_INTENT,
	SE_OL_ZERO_OWNED,
	SE_OL_PUBLISH_INTENT,
	SE_OL_PUBLISHED,
	SE_OL_WITHDRAW_CLAIM,
	SE_OL_WITHDRAWN_ZERO,
	SE_OL_DELETED,
};
enum se_ol_stage {
	SE_OL_EMPTY = 0,
	SE_OL_LOOKED,
	SE_OL_READ,
	SE_OL_HELD,
	SE_OL_CONVERTED,
	SE_OL_RELEASED,
	SE_OL_EXCLUSIVE,
	SE_OL_CAS_ATTEMPTED,
	SE_OL_REPLACED,
};

struct se_ol_meta {
	struct bpf_spin_lock lock;
	__u32 phase;
	__u64 locator, cookie;
	__u32 reader_holds, active_leases, exclusive, reserved;
	__u32 directory_state, archive_ready;
	__u64 exclusive_owner;
	/* Future source-owned cleanup and original-account proof. No generic
	 * setter may manufacture these receipts on behalf of WORK/native/UID. */
	__u64 account_scope;
	__u32 account_slot, account_incarnation, work_refs, native_refs;
	__u32 cleanup_done, cleanup_error, current_work_slot,
		current_work_owned;
	__u64 current_work_cookie, next_work_sequence, last_reap_sequence,
		reserved2;
};
_Static_assert(sizeof(struct se_ol_meta) == 128,
	       "test-only opaque metadata geometry");
struct se_ol_observation {
	const void *original_key;
	const __u64 *first_backing;
	struct se_ol_meta *meta;
	__u64 observed_locator, held_cookie;
	__u32 slot, stage;
};
struct se_ol_lease {
	struct se_ol_meta *meta;
	__u64 locator, cookie;
	__u32 slot, held;
};

static __attribute__((always_inline)) inline int se_ol_decode(__u64 locator,
							      __u32 *slot)
{
	__u32 candidate = (__u32)(locator & SE_OL_SLOT_MASK);
	if (!slot || !locator || !(locator >> SE_OL_SLOT_BITS) ||
	    candidate >= SE_OL_TASKS)
		return SE_OL_STALE;
	*slot = candidate;
	return SE_OL_OK;
}

/* The HASH value is an aligned single __u64 scalar. BPF has an aligned 64-bit
 * load instruction but its backend cannot lower an acquire AtomicLoad here.
 * A volatile load forces one scalar read; the writer's CAS and the later
 * metadata hold/relookup establish the protocol, not this read alone. */
static inline __u64 se_ol_load_scalar(const __u64 *value)
{
	return *(volatile const __u64 *)value;
}

/* Previous generation survives metadata FREE/refund. This function does not
 * allocate a charge or change storage; its caller must own that transition. */
static inline int se_ol_next_locator(__u32 slot, __u64 previous, __u64 *next)
{
	if (!next || slot >= SE_OL_TASKS ||
	    (previous && (previous & SE_OL_SLOT_MASK) != slot))
		return SE_OL_CORRUPT;
	__u64 generation = previous >> SE_OL_SLOT_BITS;
	if (generation >= SE_OL_MAX_GENERATION)
		return SE_OL_LIMIT;
	*next = ((generation + 1) << SE_OL_SLOT_BITS) | slot;
	return SE_OL_OK;
}

/* Split lookup from scalar read so a preallocated HASH backing may be
 * deleted/reused in between. The first pointer is observation, not authority. */
static inline int se_ol_observe(const void *opaque_key,
				struct se_ol_observation *observation)
{
	if (!opaque_key || !observation || observation->stage)
		return SE_OL_CORRUPT;
	const __u64 *first = SE_OL_LOOKUP(opaque_key);
	if (!first)
		return SE_OL_STALE;
	observation->original_key = opaque_key;
	observation->first_backing = first;
	observation->stage = SE_OL_LOOKED;
	return SE_OL_OK;
}

static inline int se_ol_read_observation(struct se_ol_observation *observation)
{
	if (!observation || observation->stage != SE_OL_LOOKED ||
	    !observation->first_backing)
		return SE_OL_CORRUPT;
	__u64 locator = se_ol_load_scalar(observation->first_backing);
	__u32 slot = 0;
	if (se_ol_decode(locator, &slot) != SE_OL_OK) {
		observation->stage = SE_OL_RELEASED;
		return SE_OL_STALE;
	}
	observation->observed_locator = locator;
	observation->slot = slot;
	observation->stage = SE_OL_READ;
	return SE_OL_OK;
}

/* A speculative reader hold pins the exact metadata generation. This does
 * not yet prove that the original HASH key still maps to that generation. */
static inline int se_ol_hold_observation(struct se_ol_observation *observation)
{
	if (!observation || observation->stage != SE_OL_READ)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = SE_OL_META_LOOKUP(observation->slot);
	if (!meta)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int result = SE_OL_OK;
	if (meta->locator != observation->observed_locator)
		result = SE_OL_STALE;
	else if (meta->phase != SE_OL_LIVE || meta->exclusive ||
		 meta->directory_state != SE_OL_PUBLISHED)
		result = SE_OL_CONTENDED;
	else if (!meta->cookie || meta->reserved || meta->exclusive_owner)
		result = SE_OL_CORRUPT;
	else if (meta->reader_holds == SE_OL_U32_MAX)
		result = SE_OL_LIMIT;
	else {
		meta->reader_holds++;
		observation->meta = meta;
		observation->held_cookie = meta->cookie;
		observation->stage = SE_OL_HELD;
	}
	bpf_spin_unlock(&meta->lock);
	return result;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_CANCEL_OBSERVATION_INLINE_DIAGNOSTIC
#define SE_OL_CANCEL_OBSERVATION_INLINE __attribute__((always_inline)) inline
#else
#define SE_OL_CANCEL_OBSERVATION_INLINE inline
#endif
static SE_OL_CANCEL_OBSERVATION_INLINE int
se_ol_cancel_observation(struct se_ol_observation *observation)
{
	if (!observation || observation->stage != SE_OL_HELD ||
	    !observation->meta)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = observation->meta;
	bpf_spin_lock(&meta->lock);
	int exact = meta->locator == observation->observed_locator &&
		    meta->cookie == observation->held_cookie &&
		    meta->reader_holds;
	if (exact) {
		meta->reader_holds--;
		observation->stage = SE_OL_RELEASED;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}
#undef SE_OL_CANCEL_OBSERVATION_INLINE

/* A second helper lookup of the ORIGINAL key is mandatory. A stale backing
 * may now contain an unrelated key; matching the first scalar is never enough.
 * Every ordinary refusal releases exactly this observation's hold. A metadata
 * contradiction leaves it pinned for fault diagnosis instead of authorizing
 * the wrong task. */
static inline int se_ol_relookup_convert(struct se_ol_observation *observation,
					 struct se_ol_lease *lease)
{
	if (!observation || observation->stage != SE_OL_HELD ||
	    !observation->meta || !observation->original_key || !lease ||
	    lease->held)
		return SE_OL_CORRUPT;
	const __u64 *fresh = SE_OL_LOOKUP(observation->original_key);
	__u64 value = fresh ? se_ol_load_scalar(fresh) : 0;
	struct se_ol_meta *meta = observation->meta;
	bpf_spin_lock(&meta->lock);
	int result = SE_OL_OK;
	if (meta->locator != observation->observed_locator ||
	    meta->cookie != observation->held_cookie || !meta->reader_holds ||
	    meta->reserved || meta->exclusive_owner) {
		result = SE_OL_CORRUPT; /* retain hold; do not fake a release */
	} else if (value != observation->observed_locator ||
		   meta->phase != SE_OL_LIVE || meta->exclusive ||
		   meta->directory_state != SE_OL_PUBLISHED) {
		meta->reader_holds--;
		observation->stage = SE_OL_RELEASED;
		result = SE_OL_STALE;
	} else if (meta->active_leases == SE_OL_U32_MAX) {
		meta->reader_holds--;
		observation->stage = SE_OL_RELEASED;
		result = SE_OL_LIMIT;
	} else {
		meta->reader_holds--;
		meta->active_leases++;
		*lease = (struct se_ol_lease){ meta,
					       observation->observed_locator,
					       observation->held_cookie,
					       observation->slot, 1 };
		observation->stage = SE_OL_CONVERTED;
	}
	bpf_spin_unlock(&meta->lock);
	return result;
}

static inline int se_ol_release_lease(struct se_ol_lease *lease)
{
	if (!lease || lease->held != 1 || !lease->meta)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = lease->meta;
	bpf_spin_lock(&meta->lock);
	int exact = meta->locator == lease->locator &&
		    meta->cookie == lease->cookie && meta->active_leases;
	if (exact) {
		meta->active_leases--;
		lease->held = 0;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}
#endif
