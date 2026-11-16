/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_EXEC_CAPSULE_H
#define ENFORCE_EXEC_SHARED_EXEC_CAPSULE_H
/* Default-off source-only physical-exec capsule (G005-A candidate).
 *
 * Problem: a later same-exec admission (interpreter iteration) may run after
 * the task has migrated to another cgroup. Its source header/TASK can be
 * missing because insertion is fallible. The current route then has the
 * WRONG class. This capsule freezes the ORIGINAL class at first selected
 * policy admission in infallible storage.
 *
 * Storage and identity (two adapters, same state machine):
 *  - ARRAY adapter (host contract, early spikes): capsules live in a
 *    preallocated ARRAY indexed by the INITIAL-namespace TGID; the index is a
 *    lookup key only, and every lookup "creates" (the slot always exists).
 *  - Task-storage adapter (SE_CAP_ABSENT_OK; the verdict object, G019 M4
 *    user decision (ii)): capsule and marker live in BPF task local storage
 *    on the EXECUTING task. SE_CAP_LOOKUP never creates; SE_CAP_CREATE (and
 *    SE_CAP_MARKER_CREATE) create, and only for an exec that can matter
 *    (SE_CAP_MATTERS: the current cgroup has a route-index entry or the task
 *    holds a TASK key) or at the first selected admission. Absent storage is
 *    then "no capsule" (an exec that never mattered), not a fault; a failed
 *    create where one is needed is a capsule fault (degrade: the caller
 *    counts ADMISSION, Strict denies, Audit stays nonblocking but counted).
 *    The storage dies with the task: a missed terminal's FROZEN+PINNED
 *    capsule is retired at lsm/task_free (se_cap_on_free, its own program,
 *    which runs before the kernel frees the task's storage), so no route pin
 *    outlives its task, and a reused task_struct address starts with no
 *    capsule at all.
 *  An admission identifies its exec by the exact task pointer + bprm pointer
 *  (the LSM hook cannot know its sequence); FRESHNESS against task/bprm
 *  address reuse comes from every covered begin unconditionally retiring the
 *  previous capsule, and the nonwrapping sequence binds retire and the route
 *  pin to one exec.
 *
 * HARD loader invariant (part of the coverage proof, not a suggestion):
 * (task-storage adapter: first the lsm/task_free death retire, then)
 * attach fexit/bprm_execve, then fentry/bprm_execve, then
 * fentry/security_bprm_creds_for_exec, then the LSM admission; detach in the
 * exact reverse order. Any other order can leave uncovered frozen capsules
 * whose task/bprm addresses a later uncovered exec could reuse.
 *  - Entry markers live in a second preallocated ARRAY indexed by the
 *    initial-namespace thread ID. A marker proves this bprm_execve call
 *    entered through a trampoline that already carried the terminal fexit.
 *
 * Kernel serialization premise (exact AL2023 6.12.113 / 6.18.56 fs/exec.c,
 * independently audited): security_bprm_creds_for_exec runs after
 * prepare_bprm_creds() took signal->cred_guard_mutex. The mutex is released
 * by setup_new_exec() or by begin_new_exec()'s out_unlock (both after
 * commit_creds, hence after de_thread() left a single thread), or by
 * free_bprm() AFTER bprm_execve() returns on failure. Therefore, when a begin
 * runs, no other exec of the same thread group is between begin and terminal,
 * and the TGID stays allocated while its exec is in flight. Any capsule found
 * non-FREE at begin belongs to a finished exec whose terminal was missed, and
 * may be retired.
 *
 * Coverage premise: with the terminal attached before the entry marker, a
 * call that ran the entry program runs in a trampoline image that also holds
 * the terminal. The per-CPU recursion guard of fentry/fexit can still skip
 * one of them, but only with involuntary preemption (e.g. preempt=full on a
 * PREEMPT_DYNAMIC kernel; AL2023 defaults to PREEMPT_NONE). A skipped
 * terminal leaves a finished exec's capsule (and pin) until the TGID's next
 * begin or admission retires it. Every begin retires, covered or not, so a
 * class can leak only if BOTH that terminal and the next begin of the same
 * thread are skipped AND the new bprm reuses the old address. The loader must
 * record the preemption mode and require zero recursion misses.
 *
 * Interpreter iterations of one exec reuse the same bprm and run before
 * de_thread(), so TGID, task and bprm are stable from begin to the last
 * admission. de_thread()/exchange_tids() does not change the TGID or the
 * executing task pointer.
 *
 * Per-task terminal proof (task-storage adapter): a task runs at most one
 * bprm_execve at a time, and entry, begin, every admission and the terminal
 * of that exec all run in the executing task (de_thread keeps its pointer),
 * so they all reach the same storage. Another thread of the same TGID has
 * its own storage and can never touch this capsule; the cred_guard_mutex
 * premise above is no longer needed for capsule exclusivity (it still
 * orders begin against other threads' execs). A non-FREE capsule found at
 * this task's next begin is a finished exec of THIS task whose terminal was
 * missed, and is retired (as before). A task that dies with a non-FREE
 * capsule had its terminal missed: se_cap_on_free retires it (pin released
 * under the original route lock) before the storage is freed. The only
 * remaining leak window is a skipped task_free program, which leaves the
 * pin and the route's unresolved latch exactly as a failed release does
 * today (publication refused, counted RELEASE_FAULT on any later retire).
 *
 * Locks: the capsule lock guards phase/task/bprm/sequence/flags/class. The
 * embedded owner is guarded ONLY by the original route lock named by its
 * token. Never hold both: BPF forbids nested spin locks.
 *
 * This header never denies, never consults TASK/WORK/policy maps and never
 * records success history. It is not selected by any product image. */
#ifndef ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE
#error "exec capsule requires the source-mode route pin candidate"
#endif
#include "shared_route.h"

#define SE_CAP_FREE 0
#define SE_CAP_OPEN 1 /* covered begin, class not yet frozen */
#define SE_CAP_FROZEN 2 /* original class frozen at first selected admission */
#define SE_CAP_RETIRING 3 /* pin release in progress outside the capsule lock */

#define SE_CAP_F_CHECK 1U /* AT_EXECVE_CHECK: never a successful exec */
#define SE_CAP_F_PINNED \
	2U /* pin intent: set at freeze BEFORE acquiring the
			       * original-route pin; owner.owned under the
			       * route lock remains the only release truth */
#define SE_CAP_F_UNCOVERED \
	4U /* frozen without a covered begin: no terminal
			       * guarantee, so no pin is ever taken */
#define SE_CAP_F_PIN_FAILED 8U /* pin intent abandoned: acquire failed */
#define SE_CAP_F_IDENT \
	16U /* uncovered OWNED freeze: owner.token holds the
			       * original route's identity (no pin, owner.owned
			       * stays 0); later admissions of this exec
			       * re-claim exactly that route and payload */

struct se_exec_capsule {
	struct bpf_spin_lock lock;
	__u32 phase;
	__u64 task, bprm, sequence;
	__u32 flags, execution_class;
	/* Guarded by the ORIGINAL route lock (owner.token.slot), not by lock. */
	struct se_source_mode_owner owner;
};

/* Written and taken only by the thread that owns the index. */
struct se_exec_marker {
	__u64 task, bprm;
};

/* Copy taken under the capsule lock for work outside it. */
struct se_cap_view {
	__u64 task, bprm, sequence;
	__u32 phase, flags, execution_class, slot;
};

/* Admission classification. */
#define SE_CAP_MINE_OPEN 1
#define SE_CAP_MINE_FROZEN 2
#define SE_CAP_UNCOVERED 3 /* FREE: no covered begin observed */
#define SE_CAP_STALE 4 /* another finished exec's capsule; retire first */
#define SE_CAP_BUSY 5 /* RETIRING: violates serialization premise */

/* G019 gap 4 (review H1): admission-order bit ORed into *frozen_class by
 * se_cap_admit when SE_CAP_REPORT_LATER is defined. It is set only for a
 * MINE_FROZEN admission with a valid frozen class: a later bprm_check of
 * the SAME physical exec whose first selected admission already froze the
 * class (a script's interpreter pass). A first admission (MINE_OPEN,
 * UNCOVERED, or a STALE capsule retired at a reused bprm address) never
 * carries it. Callers that compare classes must mask it first. */
#define SE_CAP_LATER (1U << 8)

/* Begin/terminal results. */
#define SE_CAP_OK 0
#define SE_CAP_NEED_RETIRE 1 /* previous finished exec still recorded */
#define SE_CAP_FOREIGN 2 /* not this exec: losing waiter/wrong/duplicate */
#define SE_CAP_FAULT 3

static __attribute__((always_inline)) inline void
se_cap_view_locked(const struct se_exec_capsule *c, struct se_cap_view *v)
{
	v->task = c->task;
	v->bprm = c->bprm;
	v->sequence = c->sequence;
	v->phase = c->phase;
	v->flags = c->flags;
	v->execution_class = c->execution_class;
	v->slot = c->owner.token
			  .slot; /* hint only; revalidated under route lock */
}

static __attribute__((always_inline)) inline int
se_cap_mine(const struct se_exec_capsule *c, __u64 task, __u64 bprm)
{
	return task && bprm && c->task == task && c->bprm == bprm &&
	       c->sequence &&
	       (c->phase == SE_CAP_OPEN || c->phase == SE_CAP_FROZEN);
}

/* Entry marker at fentry/bprm_execve. The terminal fexit is attached BEFORE
 * this entry program, so any call that observed this entry also runs fexit. */
static __attribute__((always_inline)) inline void
se_cap_mark_entry(struct se_exec_marker *m, __u64 task, __u64 bprm)
{
	m->task = task;
	m->bprm = bprm;
}

/* Consume the exact marker. Returns 1 only for this task/bprm. */
static __attribute__((always_inline)) inline int
se_cap_take_marker(struct se_exec_marker *m, __u64 task, __u64 bprm)
{
	if (!task || !bprm || m->task != task || m->bprm != bprm)
		return 0;
	m->task = 0;
	m->bprm = 0;
	return 1;
}

/* Begin at fentry/security_bprm_creds_for_exec, under cred_guard_mutex.
 * Uncovered (no marker) calls never open: their terminal is not guaranteed.
 * A non-FREE capsule is a finished exec (see premise) and must be retired by
 * the caller before this exec opens. */
static __attribute__((always_inline)) inline int
se_cap_begin_locked(struct se_exec_capsule *c, __u64 task, __u64 bprm,
		    __u64 sequence, __u32 is_check, struct se_cap_view *stale)
{
	if (c->phase == SE_CAP_RETIRING)
		return SE_CAP_FAULT;
	/* Retire a finished exec even if this begin then fails: a stale
	 * capsule must never outlive a serialized begin. */
	if (c->phase != SE_CAP_FREE) {
		se_cap_view_locked(c, stale);
		c->phase = SE_CAP_RETIRING;
		return SE_CAP_NEED_RETIRE;
	}
	if (!task || !bprm || !sequence || sequence == ~0ULL)
		return SE_CAP_FAULT;
	c->task = task;
	c->bprm = bprm;
	c->sequence = sequence;
	c->flags = is_check ? SE_CAP_F_CHECK : 0;
	c->execution_class = 0;
	c->phase = SE_CAP_OPEN;
	return SE_CAP_OK;
}

/* Admission classification under the capsule lock. */
static __attribute__((always_inline)) inline int
se_cap_classify_locked(struct se_exec_capsule *c, __u64 task, __u64 bprm,
		       int entry_pending, struct se_cap_view *v)
{
	se_cap_view_locked(c, v);
	/* Defense in depth (review follow-up): a capsule is this exec's only
	 * if THIS exec opened it. Every capsule open consumes the opening
	 * exec's entry marker (covered begin, or the uncovered first selected
	 * admission), so an entry marker still pending for this task/bprm
	 * means the current exec has opened nothing yet: a capsule matching
	 * task/bprm is then an earlier exec at a reused bprm address whose
	 * terminal and retiring begin were both missed. Stale, never mine. */
	if (!entry_pending && se_cap_mine(c, task, bprm))
		return c->phase == SE_CAP_FROZEN ? SE_CAP_MINE_FROZEN :
						   SE_CAP_MINE_OPEN;
	if (c->phase == SE_CAP_FREE)
		return SE_CAP_UNCOVERED;
	if (c->phase == SE_CAP_RETIRING)
		return SE_CAP_BUSY;
	/* Serialized admission of a different exec: stale. Mark for retire. */
	c->phase = SE_CAP_RETIRING;
	return SE_CAP_STALE;
}

/* First selected admission of a covered exec. Freeze BEFORE the caller tries
 * the original-route pin, so a retire always knows which route to inspect. A
 * failed pin acquisition leaves owner.owned clear; later admissions then see
 * a frozen-class fault instead of a current-route class. */
static __attribute__((always_inline)) inline int
se_cap_freeze_locked(struct se_exec_capsule *c, __u64 task, __u64 bprm,
		     __u64 sequence, __u32 execution_class, __u32 pinned)
{
	if (execution_class < 1 || execution_class > 2 ||
	    c->phase != SE_CAP_OPEN || !se_cap_mine(c, task, bprm) ||
	    c->sequence != sequence)
		return SE_CAP_FAULT;
	c->execution_class = execution_class;
	if (pinned)
		c->flags |= SE_CAP_F_PINNED;
	c->phase = SE_CAP_FROZEN;
	return SE_CAP_OK;
}

/* The original-route pin could not be taken. Drop the intent so neither a
 * later admission nor the retire consults a stale owner slot; later
 * admissions of this exec fault with the frozen class. */
static __attribute__((always_inline)) inline int
se_cap_pin_failed_locked(struct se_exec_capsule *c, __u64 sequence)
{
	if (c->phase != SE_CAP_FROZEN || c->sequence != sequence)
		return SE_CAP_FAULT;
	c->flags = (c->flags & ~SE_CAP_F_PINNED) | SE_CAP_F_PIN_FAILED;
	return SE_CAP_OK;
}

/* First selected admission of an exec whose begin was not covered (late
 * attach). The class is still the original class at first policy admission,
 * but no pin is taken: no terminal is guaranteed to release it. */
static __attribute__((always_inline)) inline int se_cap_freeze_uncovered_locked(
	struct se_exec_capsule *c, __u64 task, __u64 bprm, __u64 sequence,
	__u32 execution_class, const struct se_route_claim *ident)
{
	if (execution_class < 1 || execution_class > 2 ||
	    c->phase != SE_CAP_FREE || !task || !bprm || !sequence ||
	    sequence == ~0ULL)
		return SE_CAP_FAULT;
	c->task = task;
	c->bprm = bprm;
	c->sequence = sequence;
	c->flags = SE_CAP_F_UNCOVERED;
	/* Unpinned, so owner.owned is 0 and no route lock reader consults the
	 * owner: the token only records the original route's identity, read
	 * back by later admissions of this same exec (one task, serialized). */
	c->owner.owned = 0;
	c->owner.token = (struct se_source_mode_token){ 0 };
	if (ident && ident->owned &&
	    ident->execution_class == execution_class) {
		c->owner.token.slot = ident->slot;
		c->owner.token.incarnation = ident->incarnation;
		c->owner.token.scope = ident->scope;
		c->owner.token.generation = ident->generation;
		c->owner.token.execution_class = execution_class;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		c->owner.token.record = ident->record & 1;
#endif
		c->flags |= SE_CAP_F_IDENT;
	}
	c->execution_class = execution_class;
	c->phase = SE_CAP_FROZEN;
	return SE_CAP_OK;
}

/* Terminal at fexit/bprm_execve. Only the exact task/bprm owner retires.
 * A losing same-TGID waiter, wrong bprm or duplicate terminal is FOREIGN and
 * changes nothing. *success is 1 only for a frozen non-check exec returning 0. */
static __attribute__((always_inline)) inline int
se_cap_terminal_locked(struct se_exec_capsule *c, __u64 task, __u64 bprm,
		       long retval, struct se_cap_view *v, __u32 *success)
{
	*success = 0;
	if (!se_cap_mine(c, task, bprm))
		return SE_CAP_FOREIGN;
	se_cap_view_locked(c, v);
	*success = !retval && c->phase == SE_CAP_FROZEN &&
		   !(c->flags & SE_CAP_F_CHECK);
	c->phase = SE_CAP_RETIRING;
	return SE_CAP_OK;
}

/* Complete a retire after any pin was released under the route lock. The
 * sequence binds this to the exact retire that set RETIRING. */
static __attribute__((always_inline)) inline int
se_cap_retire_finish_locked(struct se_exec_capsule *c, __u64 sequence)
{
	if (c->phase != SE_CAP_RETIRING || c->sequence != sequence)
		return SE_CAP_FAULT;
	c->phase = SE_CAP_FREE;
	c->task = 0;
	c->bprm = 0;
	c->sequence = 0;
	c->flags = 0;
	c->execution_class = 0;
	return SE_CAP_OK;
}

/* Release the original-route pin owned by a retiring capsule. Called with the
 * ORIGINAL route lock held (route chosen by the owner's token slot, then fully
 * revalidated by the release helper). */
static __attribute__((always_inline)) inline int
se_cap_release_pin_locked(struct se_route_anchor *a, struct se_exec_capsule *c,
			  const struct se_cap_view *v)
{
	if (v->phase != SE_CAP_RETIRING && v->phase != SE_CAP_OPEN &&
	    v->phase != SE_CAP_FROZEN)
		return -1;
	if (!(v->flags & SE_CAP_F_PINNED) || !c->owner.owned)
		return 0;
	struct se_source_mode_token token = c->owner.token;
	if (!se_route_source_pin_release_locked(a, &c->owner, &token, v->task,
						v->sequence))
		return 0;
	/* Unreleasable pin (invariant breach). Keep publication blocked on the
	 * route this owner names: the pin count is never decremented and the
	 * sticky latch has no clear API. Abandon the owner so the TGID slot is
	 * reusable instead of faulting every later exec of that TGID. */
	if (token.slot == a->payload_slot)
		a->unresolved_sources = 1;
	c->owner.owned = 0;
	return -1;
}
/* Adapter. The caller supplies infallible preallocated ARRAY lookups:
 *   SE_CAP_LOOKUP(tgid)        -> struct se_exec_capsule *, 0 if out of range
 *   SE_CAP_MARKER_LOOKUP(pid)  -> struct se_exec_marker *, 0 if out of range
 *   SE_CAP_NEXT_SEQUENCE()     -> nonwrapping u64, 0 on exhaustion
 * plus se_route_admit()'s SE_ROUTE_INDEX_LOOKUP/SE_ROUTE_ANCHOR_LOOKUP and
 * SE_ROUTE_CAPACITY. Optional SE_CAP_STAT(index) counts events. */
#if defined(SE_CAP_LOOKUP) && defined(SE_ROUTE_INDEX_LOOKUP)
#define SE_CAP_STAT_BEGIN 0
#define SE_CAP_STAT_UNCOVERED_BEGIN 1
#define SE_CAP_STAT_STALE_RETIRED 2
#define SE_CAP_STAT_FROZEN 3
#define SE_CAP_STAT_FROZEN_UNCOVERED 4
#define SE_CAP_STAT_PINNED 5
#define SE_CAP_STAT_PIN_FAILED 6
#define SE_CAP_STAT_ORIGINAL_CLAIM 7
#define SE_CAP_STAT_TERMINAL 8
#define SE_CAP_STAT_FOREIGN_TERMINAL 9
#define SE_CAP_STAT_SUCCESS 10
#define SE_CAP_STAT_CHECK_ONLY 11
#define SE_CAP_STAT_RELEASE_FAULT 12
#define SE_CAP_STAT_FAULT 13
#define SE_CAP_STAT_DEATH_RETIRED 14 /* non-FREE capsule retired at task_free */
#define SE_CAP_STATS 15
#ifndef SE_CAP_STAT
#define SE_CAP_STAT(index) \
	do {               \
	} while (0)
#endif
/* ARRAY adapter defaults: every lookup is a creation and every exec
 * matters, so a missing slot is a fault (the original contract). */
#ifndef SE_CAP_CREATE
#define SE_CAP_CREATE(tgid) SE_CAP_LOOKUP(tgid)
#endif
#ifndef SE_CAP_MARKER_CREATE
#define SE_CAP_MARKER_CREATE(pid) SE_CAP_MARKER_LOOKUP(pid)
#endif
#ifndef SE_CAP_MATTERS
#define SE_CAP_MATTERS() 1
#endif
#ifdef SE_CAP_ABSENT_OK
#define SE_CAP_ABSENT_IS_FAULT(needed) (needed)
#else
#define SE_CAP_ABSENT_IS_FAULT(needed) 1
#endif

#if defined(SE_CAP_ENTRY_MARKS_LIVE_CAPSULE) && !defined(SE_CAP_ABSENT_OK)
#error "SE_CAP_ENTRY_MARKS_LIVE_CAPSULE requires the task-storage adapter"
#endif
static __attribute__((always_inline)) inline void
se_cap_on_entry(__u32 pid, __u64 task, __u64 bprm)
{
	int cap_matters = SE_CAP_MATTERS();
#ifdef SE_CAP_ENTRY_MARKS_LIVE_CAPSULE
	/* Review OQ (task-storage adapter, keyed by the current task: the
	 * argument is unused): a capsule still OPEN, FROZEN or RETIRING at an
	 * exec's entry belongs to an earlier exec whose terminal was missed.
	 * Mark this exec even if it does not matter yet, so that if its begin
	 * also misses, its first admission sees the pending marker and retires
	 * that capsule as stale (se_cap_classify_locked), never re-claiming the
	 * earlier exec's route at a reused bprm address. */
	if (!cap_matters) {
		struct se_exec_capsule *live = SE_CAP_LOOKUP(pid);
		cap_matters = live && live->phase != SE_CAP_FREE;
	}
#endif
	struct se_exec_marker *m = cap_matters ? SE_CAP_MARKER_CREATE(pid) :
						 SE_CAP_MARKER_LOOKUP(pid);
	if (m)
		se_cap_mark_entry(m, task, bprm);
	else if (SE_CAP_ABSENT_IS_FAULT(cap_matters))
		SE_CAP_STAT(SE_CAP_STAT_FAULT);
}

/* Release any original-route pin, then free the capsule. A release failure
 * leaves the route pinned (publication stays refused) and is counted. */
static __attribute__((always_inline)) inline int
se_cap_retire(struct se_exec_capsule *c, const struct se_cap_view *v)
{
	int bad = 0;
	if (v->flags & SE_CAP_F_PINNED) {
		__u32 slot = v->slot;
		struct se_route_anchor *a =
			slot < SE_ROUTE_CAPACITY ?
				SE_ROUTE_ANCHOR_LOOKUP(&slot) :
				0;
		if (!a) {
			/* Corrupt owner slot: no route lock can guard it. */
			c->owner.owned = 0;
			bad = 1;
		} else {
			bpf_spin_lock(&a->lock);
			bad = se_cap_release_pin_locked(a, c, v) != 0;
			bpf_spin_unlock(&a->lock);
		}
	}
	bpf_spin_lock(&c->lock);
	if (se_cap_retire_finish_locked(c, v->sequence) != SE_CAP_OK)
		bad = 1;
	bpf_spin_unlock(&c->lock);
	if (bad)
		SE_CAP_STAT(SE_CAP_STAT_RELEASE_FAULT);
	return bad ? -1 : 0;
}

/* fentry/security_bprm_creds_for_exec. Every begin, covered or not, runs
 * under cred_guard_mutex, so a non-FREE capsule is a finished exec and is
 * retired first. Only a covered (marked) begin then opens a capsule. Retiring
 * even without a marker closes the terminal-skip + entry-skip ABA. */
static __attribute__((always_inline)) inline int
se_cap_on_begin(__u32 tgid, __u32 pid, __u64 task, __u64 bprm, __u32 is_check)
{
	struct se_exec_marker *m = SE_CAP_MARKER_LOOKUP(pid);
	struct se_exec_capsule *c = SE_CAP_LOOKUP(tgid);
	int cap_matters = SE_CAP_MATTERS();
	if (!c && cap_matters)
		c = SE_CAP_CREATE(tgid);
#ifdef SE_CAP_ABSENT_OK
	/* No storage: this task never mattered (nothing to retire) and this
	 * exec does not either; or the create failed (a fault). */
	if (!c) {
		if (cap_matters) {
			SE_CAP_STAT(SE_CAP_STAT_FAULT);
			return SE_CAP_FAULT;
		}
		return SE_CAP_FOREIGN;
	}
	int covered = m && se_cap_take_marker(m, task, bprm);
#else
	if (!m || !c) {
		SE_CAP_STAT(SE_CAP_STAT_FAULT);
		return SE_CAP_FAULT;
	}
	int covered = se_cap_take_marker(m, task, bprm);
#endif
	__u64 sequence = covered ? SE_CAP_NEXT_SEQUENCE() : 0;
	struct se_cap_view stale = {};
	bpf_spin_lock(&c->lock);
	int r = SE_CAP_OK;
	if (c->phase == SE_CAP_RETIRING) {
		r = SE_CAP_FAULT;
	} else if (c->phase != SE_CAP_FREE) {
		se_cap_view_locked(c, &stale);
		c->phase = SE_CAP_RETIRING;
		r = SE_CAP_NEED_RETIRE;
	}
	bpf_spin_unlock(&c->lock);
	if (r == SE_CAP_NEED_RETIRE) {
		SE_CAP_STAT(SE_CAP_STAT_STALE_RETIRED);
		(void)se_cap_retire(c, &stale);
	} else if (r == SE_CAP_FAULT) {
		SE_CAP_STAT(SE_CAP_STAT_FAULT);
		return r;
	}
	if (!covered) {
		SE_CAP_STAT(SE_CAP_STAT_UNCOVERED_BEGIN);
		return SE_CAP_FOREIGN;
	}
	bpf_spin_lock(&c->lock);
	r = se_cap_begin_locked(c, task, bprm, sequence, is_check, &stale);
	bpf_spin_unlock(&c->lock);
	if (r == SE_CAP_OK)
		SE_CAP_STAT(SE_CAP_STAT_BEGIN);
	else
		SE_CAP_STAT(SE_CAP_STAT_FAULT);
	return r;
}

static __attribute__((always_inline)) inline void
se_cap_drop_claim(struct se_route_claim *claim)
{
	__u32 slot = claim->slot;
	struct se_route_anchor *a =
		slot < SE_ROUTE_CAPACITY ? SE_ROUTE_ANCHOR_LOOKUP(&slot) : 0;
	if (!a)
		return;
	bpf_spin_lock(&a->lock);
	(void)se_route_release_locked(a, claim);
	bpf_spin_unlock(&a->lock);
}

/* Capsule-internal invariant failure (out-of-range TGID, stuck RETIRING,
 * failed retire, corrupt frozen class). Never expected under the kernel
 * premises, and never a reason to deny an unselected or Audit exec host-wide:
 * degrade through the CURRENT route selection and grant no claim. A selected
 * Strict exec denies (STRICT_FAULT); a selected Audit exec stays nonblocking
 * (AUDIT_FAULT, the caller quarantines); unselected stays unselected. */
static __attribute__((always_inline)) inline int
se_cap_degrade(__u64 cgroup, struct se_route_claim *claim, __u32 *frozen_class)
{
	SE_CAP_STAT(SE_CAP_STAT_FAULT);
	int r = se_route_admit(cgroup, claim);
	if (r == SE_ROUTE_OWNED) {
		__u32 cls = claim->execution_class;
		se_cap_drop_claim(claim);
		r = cls == 2 ? SE_ROUTE_STRICT_FAULT : SE_ROUTE_AUDIT_FAULT;
	}
	*frozen_class = r == SE_ROUTE_AUDIT_FAULT  ? 1 :
			r == SE_ROUTE_STRICT_FAULT ? 2 :
						     0;
	return r;
}

/* LSM bprm_check admission. Returns an SE_ROUTE_* result. When the exec's
 * class is frozen, the claim is on the ORIGINAL route and *frozen_class is the
 * original class; the current cgroup is not consulted. *frozen_class is 0 when
 * the result is unselected. With SE_CAP_REPORT_LATER a frozen re-admission of
 * the same exec also carries SE_CAP_LATER. Every OWNED claim must be released
 * by the caller. */
static __attribute__((always_inline)) inline int
se_cap_admit(__u32 tgid, __u32 pid, __u64 task, __u64 bprm, __u64 cgroup,
	     struct se_route_claim *claim, __u32 *frozen_class)
{
	/* Written and taken only by this thread (no lock). */
	struct se_exec_marker *m = SE_CAP_MARKER_LOOKUP(pid);
	int entry_pending = m && task && bprm && m->task == task &&
			    m->bprm == bprm;
	*frozen_class = 0;
	struct se_exec_capsule *c = SE_CAP_LOOKUP(tgid);
	struct se_cap_view v = {};
	int kind = SE_CAP_UNCOVERED;
	if (!c) {
#ifndef SE_CAP_ABSENT_OK
		return se_cap_degrade(cgroup, claim, frozen_class);
#endif
		/* No storage yet: uncovered. It is created below only if the
		 * current route selects this exec (first selected admission). */
	} else {
		bpf_spin_lock(&c->lock);
		kind = se_cap_classify_locked(c, task, bprm, entry_pending, &v);
		bpf_spin_unlock(&c->lock);
	}
	if (kind == SE_CAP_BUSY || (kind != SE_CAP_UNCOVERED && !c))
		return se_cap_degrade(cgroup, claim, frozen_class);
	if (kind == SE_CAP_STALE && c) {
		SE_CAP_STAT(SE_CAP_STAT_STALE_RETIRED);
		if (se_cap_retire(c, &v))
			return se_cap_degrade(cgroup, claim, frozen_class);
		kind = SE_CAP_UNCOVERED;
	}
	if (kind == SE_CAP_MINE_FROZEN) {
		__u32 cls = v.execution_class;
		*frozen_class = cls;
		if (cls < 1 || cls > 2)
			return se_cap_degrade(cgroup, claim, frozen_class);
#ifdef SE_CAP_REPORT_LATER
		*frozen_class = cls | SE_CAP_LATER;
#endif
		int fault = cls == 1 ? SE_ROUTE_AUDIT_FAULT :
				       SE_ROUTE_STRICT_FAULT;
		if (!(v.flags & SE_CAP_F_PINNED)) {
			/* Uncovered OWNED freeze (review M2): re-claim the
			 * ORIGINAL route by its recorded identity, never the
			 * current route by class (that could mix two
			 * policies of one class). No identity: fault. */
			if (!(v.flags & SE_CAP_F_IDENT))
				return fault;
			__u32 islot = v.slot;
			struct se_route_anchor *ia =
				islot < SE_ROUTE_CAPACITY ?
					SE_ROUTE_ANCHOR_LOOKUP(&islot) :
					0;
			if (!ia)
				return fault;
			bpf_spin_lock(&ia->lock);
			int ir = se_route_claim_ident_locked(
				ia, &c->owner.token, cls, claim);
			bpf_spin_unlock(&ia->lock);
			if (ir == SE_ROUTE_OWNED)
				SE_CAP_STAT(SE_CAP_STAT_ORIGINAL_CLAIM);
			return ir;
		}
		__u32 slot = v.slot;
		struct se_route_anchor *a =
			slot < SE_ROUTE_CAPACITY ?
				SE_ROUTE_ANCHOR_LOOKUP(&slot) :
				0;
		if (!a)
			return fault;
		bpf_spin_lock(&a->lock);
		int r = se_route_claim_source_locked(a, &c->owner, task,
						     v.sequence, cls, claim);
		bpf_spin_unlock(&a->lock);
		if (r == SE_ROUTE_OWNED)
			SE_CAP_STAT(SE_CAP_STAT_ORIGINAL_CLAIM);
		return r;
	}
	int r = se_route_admit(cgroup, claim);
	__u32 cls = r == SE_ROUTE_OWNED	       ? claim->execution_class :
		    r == SE_ROUTE_AUDIT_FAULT  ? 1 :
		    r == SE_ROUTE_STRICT_FAULT ? 2 :
						 0;
	if (!cls)
		return r; /* unselected or invariant: no policy admission */
	*frozen_class = cls;
	int freeze_err;
	if (kind == SE_CAP_MINE_OPEN) {
		/* Pin only an owned claim; a first-admission fault freezes the
		 * class without a payload pin. */
		bpf_spin_lock(&c->lock);
		freeze_err = se_cap_freeze_locked(c, task, bprm, v.sequence,
						  cls, r == SE_ROUTE_OWNED);
		bpf_spin_unlock(&c->lock);
		if (!freeze_err && r == SE_ROUTE_OWNED) {
			__u32 slot = claim->slot;
			struct se_route_anchor *a =
				slot < SE_ROUTE_CAPACITY ?
					SE_ROUTE_ANCHOR_LOOKUP(&slot) :
					0;
			struct se_source_mode_token token = {};
			int pinned = -1;
			if (a) {
				bpf_spin_lock(&a->lock);
				pinned = se_route_source_pin_acquire_locked(
					a, claim, task, v.sequence, &c->owner,
					&token);
				bpf_spin_unlock(&a->lock);
			}
			if (pinned) {
				SE_CAP_STAT(SE_CAP_STAT_PIN_FAILED);
				bpf_spin_lock(&c->lock);
				(void)se_cap_pin_failed_locked(c, v.sequence);
				bpf_spin_unlock(&c->lock);
			} else
				SE_CAP_STAT(SE_CAP_STAT_PINNED);
		}
	} else {
		/* First selected admission without a covered begin: the only
		 * place storage is created at admission (task-storage adapter). */
		if (!c)
			c = SE_CAP_CREATE(tgid);
		__u64 sequence = SE_CAP_NEXT_SEQUENCE();
		if (!c) {
			freeze_err = SE_CAP_FAULT;
		} else {
			bpf_spin_lock(&c->lock);
			freeze_err = se_cap_freeze_uncovered_locked(
				c, task, bprm, sequence, cls,
				r == SE_ROUTE_OWNED ? claim : 0);
			bpf_spin_unlock(&c->lock);
		}
		if (!freeze_err) {
			SE_CAP_STAT(SE_CAP_STAT_FROZEN_UNCOVERED);
			/* This exec opened the capsule: consume its entry
			 * marker, so its later admissions see it as mine. */
			if (entry_pending)
				(void)se_cap_take_marker(m, task, bprm);
		}
	}
	if (freeze_err) {
		/* Capsule-internal failure after a valid current-route admission
		 * (the first selected one, hence the original class): fault with
		 * that class and grant no claim. */
		SE_CAP_STAT(SE_CAP_STAT_FAULT);
		if (claim->owned)
			se_cap_drop_claim(claim);
		return cls == 2 ? SE_ROUTE_STRICT_FAULT : SE_ROUTE_AUDIT_FAULT;
	}
	SE_CAP_STAT(SE_CAP_STAT_FROZEN);
	return r;
}

/* fexit/bprm_execve. Returns 1 for a successful non-check exec whose class was
 * frozen, 0 otherwise (including FOREIGN). This is a source observation only,
 * not a success-history record. */
static __attribute__((always_inline)) inline int
se_cap_on_terminal(__u32 tgid, __u32 pid, __u64 task, __u64 bprm, long retval)
{
	struct se_exec_marker *m = SE_CAP_MARKER_LOOKUP(pid);
	if (m)
		(void)se_cap_take_marker(m, task, bprm);
	struct se_exec_capsule *c = SE_CAP_LOOKUP(tgid);
	if (!c) {
#ifndef SE_CAP_ABSENT_OK
		SE_CAP_STAT(SE_CAP_STAT_FAULT);
#endif
		/* Task-storage adapter: absent means this task never had a
		 * capsule (lookups do not create). A marked entry is NOT
		 * evidence of a lost capsule: a losing same-TGID waiter is
		 * marked and never begins, and an exec that stopped mattering
		 * before begin creates none. A begin-time create miss is
		 * already counted at begin; a missed lookup here leaves a
		 * stale capsule for the next begin, admission or task_free. */
		return 0;
	}
	struct se_cap_view v = {};
	__u32 success = 0;
	bpf_spin_lock(&c->lock);
	int r = se_cap_terminal_locked(c, task, bprm, retval, &v, &success);
	bpf_spin_unlock(&c->lock);
	if (r != SE_CAP_OK) {
		SE_CAP_STAT(SE_CAP_STAT_FOREIGN_TERMINAL);
		return 0;
	}
	(void)se_cap_retire(c, &v);
	SE_CAP_STAT(SE_CAP_STAT_TERMINAL);
	if (v.flags & SE_CAP_F_CHECK)
		SE_CAP_STAT(SE_CAP_STAT_CHECK_ONLY);
	if (success)
		SE_CAP_STAT(SE_CAP_STAT_SUCCESS);
	return success ? 1 : 0;
}

/* lsm/task_free of the task-storage adapter: the dying task's capsule, found
 * by the adapter BEFORE the kernel frees the task's storage. A capsule still
 * OPEN or FROZEN belongs to an exec whose terminal was missed (a finished
 * task has no exec in flight): retire it, releasing any original-route pin
 * under that route's lock. RETIRING is left as is (a retire already faulted
 * and was counted). Returns 1 if a capsule was retired, -1 on a release
 * fault, 0 otherwise. */
static __attribute__((always_inline)) inline int
se_cap_on_free(struct se_exec_capsule *c)
{
	if (!c)
		return 0;
	struct se_cap_view v = {};
	int live = 0;
	bpf_spin_lock(&c->lock);
	if (c->phase == SE_CAP_OPEN || c->phase == SE_CAP_FROZEN) {
		se_cap_view_locked(c, &v);
		c->phase = SE_CAP_RETIRING;
		live = 1;
	}
	bpf_spin_unlock(&c->lock);
	if (!live)
		return 0;
	SE_CAP_STAT(SE_CAP_STAT_DEATH_RETIRED);
	return se_cap_retire(c, &v) ? -1 : 1;
}
#endif
#endif
