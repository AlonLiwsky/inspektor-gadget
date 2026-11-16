/* G025 UID-history bound: ER_CAPACITY reachability and pruning.
 *
 * Proof that live history rows never exceed ER_SLOTS in a qualified build
 * (SE_PROFILE_ACCEPTED_UIDS = ACCEPTED_UIDS = 8, ER_ACTIVE = 8, ER_SLOTS = 16):
 *
 * 1. The successful-activation catalogue (se_epoch_index/se_epoch_bank) has
 *    ACCEPTED_UIDS entries and never evicts, so at most ACCEPTED_UIDS UIDs
 *    have ER_ACCEPTED_EPOCH(uid) != 0.
 * 2. er_rows_valid rejects duplicate UIDs, so live rows have distinct UIDs.
 * 3. Every merge (er_stage_roots, er_inherit, er_canonical_stage_prepare)
 *    runs er_prepare before any insert. er_prepare clears every kind-0 row
 *    (never activated and not a new UID of the current candidate). A
 *    surviving row is kind 1 (its UID is accepted: by 1 and 2 at most
 *    ACCEPTED_UIDS such rows) or kind 2 (its UID is a new_uid authority of
 *    the current candidate: at most ER_ACTIVE, and disjoint from kind 1 since
 *    new_uid requires an accepted epoch of 0).
 * 4. er_insert only adds kind-1 rows (inherited accepted) or kind-2 roots of
 *    the same candidate, deduplicated by UID, so the bound of 3 still holds.
 *    Publication copies (or, canonically, writes only unaccepted indices of)
 *    exactly that work copy.
 * Hence accepted rows <= ACCEPTED_UIDS <= ER_SLOTS, and all live rows <=
 * ACCEPTED_UIDS + ER_ACTIVE = 16 = ER_SLOTS: er_insert always finds a vacant
 * slot and ER_CAPACITY is unreachable while the catalogue bound holds. The
 * bound is tight: one more accepted UID than ACCEPTED_UIDS plus a full
 * candidate of new UIDs reaches ER_CAPACITY (checked below), and without the
 * pruning in 3 a second candidate's roots would overflow (checked below). */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
#define ACCEPTED_UIDS 8
#define UIDS 40
static __u64 history[UIDS + 1];
static int accepted_count;
static __u64 accepted(__u64 uid)
{
	return uid <= UIDS ? history[uid] : UINT64_MAX;
}
#define ER_ACCEPTED_EPOCH(uid) accepted(uid)
#include "epoch_roles.h"
_Static_assert(ACCEPTED_UIDS + ER_ACTIVE == ER_SLOTS,
	       "the qualified profile fills the history exactly");

/* Non-evicting catalogue of ACCEPTED_UIDS: activation fails when full. */
static int activate(__u64 uid, __u64 epoch)
{
	if (history[uid])
		return history[uid] == epoch ? 0 : -1;
	if (accepted_count >= ACCEPTED_UIDS)
		return -1;
	history[uid] = epoch;
	accepted_count++;
	return 0;
}

static __u64 rng = 0x9e3779b97f4a7c15ULL;
static __u32 next(__u32 n)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (__u32)(rng % n);
}

/* Live rows, of which accepted (kind 1) and current new roots (kind 2). */
static void check_bound(const struct er_state *s, const struct er_candidate *c)
{
	int live = 0, kind1 = 0, kind2 = 0;
	for (int i = 0; i < ER_SLOTS; i++) {
		if (!s->rows[i].uid)
			continue;
		live++;
		int kind = er_row_kind(&s->rows[i], c);
		assert(kind == 1 || kind == 2);
		kind1 += kind == 1;
		kind2 += kind == 2;
	}
	int fresh = 0;
	for (__u32 i = 0; i < c->count; i++)
		fresh += c->active[i].new_uid == 1;
	assert(kind1 <= accepted_count && accepted_count <= ACCEPTED_UIDS);
	assert(kind2 <= fresh && fresh <= ER_ACTIVE);
	assert(live == kind1 + kind2 && live <= ER_SLOTS);
}

/* A valid candidate of up to ER_ACTIVE distinct UIDs drawn from 1..UIDS. */
static struct er_candidate draw(__u64 epoch)
{
	struct er_candidate c = {};
	__u32 want = 1 + next(ER_ACTIVE);
	for (int tries = 0; c.count < want && tries < 64; tries++) {
		__u64 uid = 1 + next(UIDS);
		int dup = 0;
		for (__u32 j = 0; j < c.count; j++)
			dup |= c.active[j].uid == uid;
		if (dup)
			continue;
		int isnew = history[uid] == 0;
		c.active[c.count++] = (struct er_authority){
			uid, isnew ? epoch : history[uid], 1000 + uid, isnew, 0
		};
	}
	return c;
}

int main(void)
{
	struct er_state state = {}, child = {}, before;
	struct er_work work;
	struct er_candidate c;

	/* Pruning: eight accepted rows plus eight never-activated roots of an
	 * older candidate fill all 16 slots. A new candidate with eight other
	 * new UIDs fits only because er_prepare drops the stale roots. */
	for (int i = 0; i < ACCEPTED_UIDS; i++) {
		assert(!activate(i + 1, 5));
		state.rows[i] = er_known_row(i + 1, 5, 100 + i);
	}
	for (int i = 0; i < ER_ACTIVE; i++)
		state.rows[ACCEPTED_UIDS + i] =
			er_known_row(20 + i, 6, 200 + i);
	c = (struct er_candidate){ .count = ER_ACTIVE };
	for (int i = 0; i < ER_ACTIVE; i++)
		c.active[i] = (struct er_authority){ 30 + i, 7, 300 + i, 1, 0 };
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &c, 1));
	assert(!er_publish(&state, &work, 100));
	for (int i = 0; i < ER_SLOTS; i++)
		assert(state.rows[i].uid ==
		       (__u64)(i < ACCEPTED_UIDS ? i + 1 :
						   30 + i - ACCEPTED_UIDS));
	check_bound(&state, &c);
	/* Roots the candidate still authorizes are kept in place; a stale root
	 * (38) of an older candidate is pruned, and its slot takes the new 39. */
	struct er_candidate both = c;
	for (int i = 0; i < ER_ACTIVE; i++)
		state.rows[ACCEPTED_UIDS + i] =
			er_known_row(30 + i, 7, 300 + i);
	both.count = ER_ACTIVE;
	both.active[ER_ACTIVE - 1] = (struct er_authority){ 39, 7, 399, 1, 0 };
	state.rows[ACCEPTED_UIDS + ER_ACTIVE - 1] = er_known_row(38, 7, 398);
	/* 38 is a stale root (not in both); 39 replaces it after pruning. */
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &both, 1));
	assert(!er_publish(&state, &work, 100));
	check_bound(&state, &both);

	/* Tightness: a ninth accepted UID (beyond ACCEPTED_UIDS) plus eight new
	 * roots needs 17 rows. */
	memset(&state, 0, sizeof(state));
	for (int i = 0; i < ACCEPTED_UIDS + 1; i++) {
		history[i + 1] = 5;
		state.rows[i] = er_known_row(i + 1, 5, 100 + i);
	}
	c = (struct er_candidate){ .count = ER_ACTIVE };
	for (int i = 0; i < ER_ACTIVE; i++)
		c.active[i] = (struct er_authority){ 30 + i, 7, 300 + i, 1, 0 };
	before = state;
	er_snapshot(&work, &state, 100);
	assert(er_stage_roots(&work, &c, 1) == ER_CAPACITY);
	assert(er_publish(&state, &work, 100) == ER_CAPACITY);
	assert(!memcmp(&state, &before, sizeof(state)));

	/* Churn within the bound: 4096 merges (roots, child inheritance and,
	 * in ABI3, the canonical stage) with random candidates and activations
	 * against an 8-entry non-evicting catalogue. ER_CAPACITY never occurs. */
	memset(history, 0, sizeof(history));
	accepted_count = 0;
	memset(&state, 0, sizeof(state));
	__u64 version = 100;
	for (int round = 0; round < 4096; round++) {
		c = draw((__u64)round + 1);
		assert(!er_candidate_valid(&c));
		int op = (int)next(3);
		if (op == 1) {
			/* Child birth: fresh RESERVED child inherits the parent. */
			memset(&child, 0, sizeof(child));
			er_snapshot(&work, &child, version);
			assert(!er_inherit(&work, &c, state.rows));
			assert(!er_publish(&child, &work, version));
			check_bound(&child, &c);
			state = child;
		}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
		else if (op == 2) {
			struct er_canonical_view view = {};
			er_snapshot(&view.work, &state, version);
			assert(!er_canonical_stage_prepare(&view, &c, 1));
			assert(!er_canonical_stage_publish(&state, &view,
							   version));
			check_bound(&state, &c);
		}
#endif
		else {
			er_snapshot(&work, &state, version);
			assert(!er_stage_roots(&work, &c, 1));
			assert(!er_publish(&state, &work, version));
			check_bound(&state, &c);
		}
		/* Successful exec: the catalogue accepts new roots while it has
		 * room; a refused activation leaves them unaccepted (prunable). */
		for (__u32 i = 0; i < c.count; i++)
			if (c.active[i].new_uid && next(2))
				(void)activate(c.active[i].uid,
					       c.active[i].epoch);
		version++;
	}
	assert(accepted_count == ACCEPTED_UIDS);
	puts("epoch roles bound: pruning, ER_CAPACITY tightness, 4096-merge churn <= ACCEPTED_UIDS + ER_ACTIVE = ER_SLOTS PASS");
	return 0;
}
