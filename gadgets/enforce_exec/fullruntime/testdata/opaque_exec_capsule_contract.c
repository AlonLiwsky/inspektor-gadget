/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Host contract for the default-off source-only physical-exec capsule. It
 * drives the ACTUAL shared_exec_capsule.h adapter and shared_route.h helpers
 * with fixed arrays standing in for the preallocated BPF ARRAY maps. Kernel
 * hook ordering and serialization are premises proved separately on the
 * exact AL2023 kernels; this fixture proves the state machine under them. */
#include <linux/bpf.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static struct bpf_spin_lock *held;
static unsigned lock_errors;
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	if (held)
		lock_errors++; /* nested locks are forbidden in BPF */
	held = lock;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	if (held != lock)
		lock_errors++;
	held = NULL;
}

#define ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE 1
#define SE_ROUTE_CAPACITY 2
#define CAPSULES 64
#define CG_AUDIT 7
#define CG_STRICT 8
#define CG_UNSELECTED 9
struct se_route_anchor;
static __u64 *index_lookup(const __u64 *cgroup);
static struct se_route_anchor *anchor_lookup(const __u32 *slot);
#define SE_ROUTE_INDEX_LOOKUP(key) index_lookup(key)
#define SE_ROUTE_ANCHOR_LOOKUP(key) anchor_lookup(key)

struct se_exec_capsule;
struct se_exec_marker;
static struct se_exec_capsule *capsule_lookup(__u32 tgid);
static struct se_exec_marker *marker_lookup(__u32 pid);
static __u64 next_sequence(void);
static unsigned stats[32];
#define SE_CAP_LOOKUP(tgid) capsule_lookup(tgid)
#define SE_CAP_MARKER_LOOKUP(pid) marker_lookup(pid)
#define SE_CAP_NEXT_SEQUENCE() next_sequence()
#define SE_CAP_STAT(index) (stats[(index)]++)
#include "shared_exec_capsule.h"
#define ERESTARTNOINTR 513 /* kernel-internal errno */

static struct se_route_anchor routes[SE_ROUTE_CAPACITY];
static __u64 locators[SE_ROUTE_CAPACITY];
static __u64 *index_lookup(const __u64 *cgroup)
{
	if (*cgroup == CG_AUDIT)
		return &locators[0];
	if (*cgroup == CG_STRICT)
		return &locators[1];
	return NULL;
}
static struct se_route_anchor *anchor_lookup(const __u32 *slot)
{
	return *slot < SE_ROUTE_CAPACITY ? &routes[*slot] : NULL;
}

static struct se_exec_capsule capsules[CAPSULES];
static struct se_exec_marker markers[CAPSULES];
static __u64 sequence, sequence_limit = ~0ULL - 1;
static struct se_exec_capsule *capsule_lookup(__u32 tgid)
{
	return tgid < CAPSULES ? &capsules[tgid] : NULL;
}
static struct se_exec_marker *marker_lookup(__u32 pid)
{
	return pid < CAPSULES ? &markers[pid] : NULL;
}
static __u64 next_sequence(void)
{
	return sequence < sequence_limit ? ++sequence : 0;
}

static __u32 original, other;

static void reset(void)
{
	memset(routes, 0, sizeof(routes));
	memset(capsules, 0, sizeof(capsules));
	memset(markers, 0, sizeof(markers));
	memset(stats, 0, sizeof(stats));
	sequence = 0;
	sequence_limit = ~0ULL - 1;
	for (__u32 slot = 0; slot < SE_ROUTE_CAPACITY; slot++) {
		routes[slot] = (struct se_route_anchor){
			.incarnation = 1,
			.cgroup_identity = CG_AUDIT + slot,
			.scope = 10 + slot,
			.payload_generation = 13,
			.active_serial = 1,
			.payload_slot = slot,
			.execution_class = slot ? other : original,
			.phase = SE_ROUTE_ACTIVE,
		};
		locators[slot] = se_route_locator(slot, 1);
	}
}

/* Simulated kernel exec of one physical task. */
struct exec {
	__u32 tgid, pid;
	__u64 task, bprm;
};
static void entry(const struct exec *e)
{
	se_cap_on_entry(e->pid, e->task, e->bprm);
}
static int begin(const struct exec *e, __u32 check)
{
	return se_cap_on_begin(e->tgid, e->pid, e->task, e->bprm, check);
}
#ifdef SE_CAP_REPORT_LATER
#define REPORT_LATER 1
#else
#define REPORT_LATER 0
#endif
static int last_later;
/* Returns the verdict class seen by the policy for this admission: 1 Audit,
 * 2 Strict, 0 unselected, 3 audit-fault, 4 strict-fault, 5 invariant. */
static int admit(const struct exec *e, __u64 cgroup)
{
	struct se_route_claim claim = {};
	__u32 frozen = 0;
	int r = se_cap_admit(e->tgid, e->pid, e->task, e->bprm, cgroup, &claim,
			     &frozen);
	/* G019 gap 4: the later-admission bit is reported only when asked
	 * for, and the class comparison always masks it. */
	last_later = !!(frozen & SE_CAP_LATER);
	assert(REPORT_LATER || !last_later);
	frozen &= ~SE_CAP_LATER;
	assert(frozen <= 2);
	assert(!held);
	if (r == SE_ROUTE_OWNED) {
		assert(claim.owned && frozen == claim.execution_class);
		int cls = (int)claim.execution_class;
		se_cap_drop_claim(&claim);
		assert(!claim.owned);
		return cls;
	}
	assert(!claim.owned);
	switch (r) {
	case SE_ROUTE_UNSELECTED:
		return 0;
	case SE_ROUTE_AUDIT_FAULT:
		return 3;
	case SE_ROUTE_STRICT_FAULT:
		return 4;
	default:
		return 5;
	}
}
static int terminal(const struct exec *e, long retval)
{
	return se_cap_on_terminal(e->tgid, e->pid, e->task, e->bprm, retval);
}
static int fault_of(__u32 cls)
{
	return cls == 1 ? 3 : 4;
}
static void quiescent(void)
{
	assert(!held && !lock_errors);
	for (__u32 i = 0; i < SE_ROUTE_CAPACITY; i++)
		assert(!routes[i].early_claims && !routes[i].source_pins &&
		       !routes[i].unresolved_sources);
	for (__u32 i = 0; i < CAPSULES; i++) {
		assert(capsules[i].phase == SE_CAP_FREE);
		assert(!capsules[i].owner.owned);
		assert(!markers[i].task && !markers[i].bprm);
	}
	assert(!stats[SE_CAP_STAT_FAULT] && !stats[SE_CAP_STAT_RELEASE_FAULT]);
}
/* A pinned route refuses withdrawal; publication cannot move its payload. */
static int route_withdrawable(__u32 slot)
{
	struct se_route_anchor a = routes[slot];
	return a.phase == SE_ROUTE_ACTIVE && !a.early_claims &&
	       !a.source_pins && !a.unresolved_sources;
}

static const struct exec A = { .tgid = 20,
			       .pid = 20,
			       .task = 0xa000,
			       .bprm = 0xb000 };

/* Ordinary covered exec with an interpreter iteration in the same scope. */
static void same_scope(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(routes[0].source_pins == 1 && !route_withdrawable(0));
	assert(admit(&A, CG_AUDIT) == (int)original); /* shebang iteration */
	assert(stats[SE_CAP_STAT_ORIGINAL_CLAIM] == 1);
	assert(terminal(&A, 0) == 1);
	assert(stats[SE_CAP_STAT_SUCCESS] == 1 && route_withdrawable(0));
	quiescent();
}

/* The fresh RED: original source header/TASK missing and the task migrated
 * between admissions. The capsule needs no TASK or source header; the second
 * admission claims the ORIGINAL route and sees the ORIGINAL class. */
static void headerless_migrated(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	struct se_route_anchor before = routes[1];
	int later = admit(&A, CG_STRICT);
	if (later != (int)original) {
		fprintf(stderr,
			"RED: migrated admission saw class %d, "
			"original %u\n",
			later, original);
		assert(0);
	}
	/* The current (other) route was never claimed or counted. */
	assert(!memcmp(&before, &routes[1], sizeof(before)));
	assert(stats[SE_CAP_STAT_ORIGINAL_CLAIM] == 1);
	/* Repeated migration back and forth stays original. */
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(admit(&A, CG_UNSELECTED) == (int)original);
	assert(terminal(&A, 0) == 1);
	quiescent();
}

/* Unrelated fresh execs still use their selected route's class: the capsule
 * never leaks one exec's class into another. */
static void fresh_control(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	const struct exec B = {
		.tgid = 21, .pid = 21, .task = 0xa100, .bprm = 0xb100
	};
	entry(&B);
	assert(begin(&B, 0) == SE_CAP_OK);
	assert(admit(&B, CG_STRICT) == (int)other);
	assert(terminal(&B, 0) == 1);
	assert(terminal(&A, 0) == 1);
	/* The same TGID's NEXT exec after migration uses the new route. */
	const struct exec A2 = {
		.tgid = 20, .pid = 20, .task = 0xa000, .bprm = 0xb200
	};
	entry(&A2);
	assert(begin(&A2, 0) == SE_CAP_OK);
	assert(admit(&A2, CG_STRICT) == (int)other);
	assert(terminal(&A2, -ENOEXEC) == 0); /* failed exec: no success */
	assert(stats[SE_CAP_STAT_SUCCESS] == 2);
	quiescent();
}

/* Same-TGID losing waiter: entered bprm_execve, never got cred_guard_mutex,
 * killed by de_thread. Its terminal must not touch the winner's capsule. */
static void losing_waiter(void)
{
	const struct exec win = {
		.tgid = 30, .pid = 31, .task = 0xc100, .bprm = 0xd100
	};
	const struct exec lose = {
		.tgid = 30, .pid = 32, .task = 0xc200, .bprm = 0xd200
	};
	entry(&win);
	entry(&lose);
	assert(begin(&win, 0) == SE_CAP_OK);
	assert(admit(&win, CG_AUDIT) == (int)original);
	struct se_exec_capsule before = capsules[30];
	assert(terminal(&lose, -ERESTARTNOINTR) == 0);
	assert(stats[SE_CAP_STAT_FOREIGN_TERMINAL] == 1);
	assert(!memcmp(&before, &capsules[30], sizeof(before)));
	assert(!markers[32].task); /* loser's own marker cleared */
	assert(admit(&win, CG_STRICT) == (int)original);
	assert(terminal(&win, 0) == 1);
	quiescent();
}

/* Nonleader exec: de_thread/exchange_tids gives the executing task the
 * leader's PID after the last admission. TGID and task are unchanged. */
static void nonleader_dethread(void)
{
	const struct exec before = {
		.tgid = 40, .pid = 43, .task = 0xe300, .bprm = 0xf300
	};
	entry(&before);
	assert(begin(&before, 0) == SE_CAP_OK);
	assert(admit(&before, CG_AUDIT) == (int)original);
	assert(admit(&before, CG_STRICT) == (int)original);
	const struct exec after = {
		.tgid = 40, .pid = 40, .task = 0xe300, .bprm = 0xf300
	};
	assert(terminal(&after, 0) == 1);
	quiescent();
}

/* Wrong bprm, stale and duplicate terminals change nothing. */
static void wrong_and_duplicate_terminal(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	struct se_exec_capsule before = capsules[A.tgid];
	struct exec wrong = A;
	wrong.bprm = 0xbad0;
	assert(terminal(&wrong, 0) == 0);
	wrong = A;
	wrong.task = 0xbad1;
	assert(terminal(&wrong, 0) == 0);
	assert(!memcmp(&before, &capsules[A.tgid], sizeof(before)));
	assert(routes[0].source_pins == 1);
	assert(terminal(&A, 0) == 1);
	assert(terminal(&A, 0) == 0); /* duplicate */
	assert(stats[SE_CAP_STAT_FOREIGN_TERMINAL] == 3);
	assert(stats[SE_CAP_STAT_TERMINAL] == 1);
	quiescent();
}

/* Missed terminal (e.g. detach) then TGID reuse by a new process. The
 * serialized begin proves the old exec finished, releases its original-route
 * pin under that route's lock and opens a fresh sequence. Same task/bprm
 * address reuse (ABA) is also covered. */
static void stale_reuse(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	__u64 old_sequence = capsules[A.tgid].sequence;
	assert(routes[0].source_pins == 1); /* terminal never arrives */
	const struct exec reuse = {
		.tgid = 20, .pid = 20, .task = 0xa000, .bprm = 0xb000
	}; /* ABA addresses */
	entry(&reuse);
	assert(begin(&reuse, 0) == SE_CAP_OK);
	assert(stats[SE_CAP_STAT_STALE_RETIRED] == 1);
	assert(!routes[0].source_pins);
	assert(capsules[A.tgid].phase == SE_CAP_OPEN &&
	       capsules[A.tgid].sequence > old_sequence);
	/* New process is in the other scope: no inherited class. */
	assert(admit(&reuse, CG_STRICT) == (int)other);
	assert(routes[1].source_pins == 1);
	assert(terminal(&reuse, 0) == 1);
	quiescent();
}

/* 6.18 AT_EXECVE_CHECK: begin then return 0 with no admission. Never a
 * successful exec, never freezes, never pins. */
static void check_only(void)
{
	entry(&A);
	assert(begin(&A, 1) == SE_CAP_OK);
	assert(terminal(&A, 0) == 0);
	assert(stats[SE_CAP_STAT_CHECK_ONLY] == 1 &&
	       !stats[SE_CAP_STAT_SUCCESS] && !stats[SE_CAP_STAT_FROZEN]);
	quiescent();
}

/* Late attach: the call entered bprm_execve before the terminal was armed,
 * so no marker; begin refuses. First selected admission still freezes the
 * ORIGINAL class (uncovered, no pin) and records the original route's
 * identity: a re-check (#!) or migrated admission re-claims exactly that
 * route and payload (review M2), never the current route's class; a
 * republish in between faults with the ORIGINAL class. The next covered
 * exec of the TGID retires the stale uncovered capsule. */
static void late_attach(void)
{
	assert(begin(&A, 0) == SE_CAP_FOREIGN);
	assert(stats[SE_CAP_STAT_UNCOVERED_BEGIN] == 1);
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(stats[SE_CAP_STAT_FROZEN_UNCOVERED] == 1);
	assert(!routes[0].source_pins);
	assert(capsules[A.tgid].flags & SE_CAP_F_IDENT);
	assert(admit(&A, CG_AUDIT) == (int)original); /* #! re-check */
	assert(admit(&A, CG_STRICT) == (int)original); /* migrated */
	assert(stats[SE_CAP_STAT_ORIGINAL_CLAIM] == 2 &&
	       !routes[0].source_pins);
	routes[0].payload_generation++; /* republished in between */
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	assert(admit(&A, CG_STRICT) == fault_of(original));
	routes[0].payload_generation--;
	/* Review L2: the anchor's class changed behind an unchanged payload
	 * generation: the ident claim faults with the ORIGINAL class. */
	routes[0].execution_class = other;
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	routes[0].execution_class = original;
	/* No fexit for this call. Next exec of the new image is covered. */
	const struct exec next = {
		.tgid = 20, .pid = 20, .task = 0xa000, .bprm = 0xb400
	};
	entry(&next);
	assert(begin(&next, 0) == SE_CAP_OK);
	assert(stats[SE_CAP_STAT_STALE_RETIRED] == 1);
	assert(admit(&next, CG_STRICT) == (int)other);
	assert(terminal(&next, 0) == 1);
	/* Uncovered admission with a stale covered capsule of a dead TGID
	 * owner: retired before the lazy freeze. */
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original); /* pinned, then lost */
	const struct exec late = {
		.tgid = 20, .pid = 20, .task = 0xa900, .bprm = 0xb900
	};
	assert(admit(&late, CG_STRICT) == (int)other);
	assert(stats[SE_CAP_STAT_STALE_RETIRED] == 2 && !routes[0].source_pins);
	/* Detach stand-in: clear only the uncovered capsule (no pin). */
	assert(capsules[20].flags & SE_CAP_F_UNCOVERED);
	memset(&capsules[20], 0, sizeof(capsules[20]));
	quiescent();
}

/* First admission in an unselected cgroup is not a policy admission and
 * freezes nothing; the first selected admission freezes. */
static void unselected_first(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_UNSELECTED) == 0);
	assert(capsules[A.tgid].phase == SE_CAP_OPEN);
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(admit(&A, CG_STRICT) == (int)original);
	assert(terminal(&A, 0) == 1);
	quiescent();
}

/* First admission faults on its current route (claim counter saturated).
 * The fault class is frozen without a pin; later migrated admissions fault
 * with the ORIGINAL class. */
static void fault_first(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	routes[0].early_claims = ~0U;
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	routes[0].early_claims = 0;
	assert(admit(&A, CG_STRICT) == fault_of(original));
	assert(!routes[0].source_pins && !routes[1].source_pins);
	assert(terminal(&A, 0) == 1);
	quiescent();
}

/* Sequence exhaustion fails closed: no begin and no uncovered freeze. */
static void sequence_exhausted(void)
{
	sequence = sequence_limit;
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_FAULT);
	/* Capsule failure after a valid first admission: that class's fault,
	 * never a host-wide invariant deny. */
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	assert(stats[SE_CAP_STAT_FAULT] == 2);
	assert(capsules[A.tgid].phase == SE_CAP_FREE);
	assert(terminal(&A, 0) == 0);
	stats[SE_CAP_STAT_FAULT] = 0;
	quiescent();
}

/* Out-of-range TGID (pid_max above capacity) degrades through the current
 * route: unselected stays allowed, Audit stays nonblocking (fault), only a
 * selected Strict exec is denied. No claim is ever granted. */
static void out_of_range(void)
{
	const struct exec big = {
		.tgid = CAPSULES, .pid = CAPSULES, .task = 1, .bprm = 2
	};
	entry(&big);
	assert(begin(&big, 0) == SE_CAP_FAULT);
	assert(admit(&big, CG_UNSELECTED) == 0);
	assert(admit(&big, CG_AUDIT) == fault_of(original));
	assert(admit(&big, CG_STRICT) == fault_of(other));
	stats[SE_CAP_STAT_FAULT] = 0;
	quiescent();
}

/* A capsule stuck in RETIRING (violates the serialization premise) must not
 * deny unrelated unselected or Audit execs of that TGID host-wide. */
static void busy_capsule_degrades(void)
{
	capsules[A.tgid].phase = SE_CAP_RETIRING;
	capsules[A.tgid].task = 0xdead;
	capsules[A.tgid].bprm = 0xbeef;
	capsules[A.tgid].sequence = 99;
	assert(admit(&A, CG_UNSELECTED) == 0);
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	assert(admit(&A, CG_STRICT) == fault_of(other));
	memset(&capsules[A.tgid], 0, sizeof(capsules[A.tgid]));
	stats[SE_CAP_STAT_FAULT] = 0;
	quiescent();
}

/* Defense in depth: a check-only begin is never a successful exec even if a
 * later admission froze it (no supported kernel admits a check-only exec). */
static void check_frozen_never_success(void)
{
	entry(&A);
	assert(begin(&A, 1) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(terminal(&A, 0) == 0);
	assert(stats[SE_CAP_STAT_CHECK_ONLY] == 1 &&
	       !stats[SE_CAP_STAT_SUCCESS]);
	quiescent();
}

/* The protected owner, not the capsule copy, authorizes the original claim.
 * A diverged owner sequence (e.g. a leaked earlier pin) or an original route
 * whose class changed behind the barrier faults with the FROZEN class and
 * never with the class of either route. */
static void tampered_owner_or_route(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	capsules[A.tgid].owner.token.source_sequence++;
	assert(admit(&A, CG_STRICT) == fault_of(original));
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	capsules[A.tgid].owner.token.source_sequence--;
	routes[0].execution_class =
		other; /* invariant breach, not publication */
	assert(admit(&A, CG_STRICT) == fault_of(original));
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	/* Terminal release also refuses the breached route. The pin is never
	 * decremented and the route is latched (publication stays refused);
	 * the owner is abandoned so the TGID slot stays usable (review M1). */
	assert(terminal(&A, 0) == 1);
	assert(routes[0].source_pins == 1 &&
	       routes[0].unresolved_sources == 1 &&
	       !capsules[A.tgid].owner.owned &&
	       stats[SE_CAP_STAT_RELEASE_FAULT] == 1);
	routes[0].execution_class = original;
	/* The next exec of the same TGID is fully functional. */
	const struct exec next = {
		.tgid = 20, .pid = 20, .task = 0xa000, .bprm = 0xb500
	};
	entry(&next);
	assert(begin(&next, 0) == SE_CAP_OK);
	assert(admit(&next, CG_AUDIT) == (int)original);
	assert(routes[0].source_pins == 2 && !stats[SE_CAP_STAT_PIN_FAILED]);
	assert(admit(&next, CG_STRICT) == (int)original);
	assert(terminal(&next, 0) == 1);
	assert(routes[0].source_pins == 1 &&
	       stats[SE_CAP_STAT_RELEASE_FAULT] == 1);
	routes[0].source_pins = 0;
	routes[0].unresolved_sources = 0;
	stats[SE_CAP_STAT_RELEASE_FAULT] = 0;
	quiescent();
}

/* Pin acquisition fails (pin counter saturated). The class is still frozen;
 * the stale pin intent is dropped, later admissions fault with the frozen
 * class even without migration, and the terminal never touches a route. */
static void pin_failed(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	routes[0].source_pins = ~0U;
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(stats[SE_CAP_STAT_PIN_FAILED] == 1);
	assert(!(capsules[A.tgid].flags & SE_CAP_F_PINNED) &&
	       (capsules[A.tgid].flags & SE_CAP_F_PIN_FAILED));
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	assert(admit(&A, CG_STRICT) == fault_of(original));
	struct se_route_anchor before = routes[0];
	assert(terminal(&A, 0) == 1);
	assert(!memcmp(&before, &routes[0], sizeof(before)));
	routes[0].source_pins = 0;
	stats[SE_CAP_STAT_PIN_FAILED] = 0;
	quiescent();
}

/* Sequence exhaustion at a begin with a stale capsule: the stale capsule is
 * still retired (review L1), then the begin faults. */
static void stale_then_exhausted(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	sequence = sequence_limit;
	const struct exec next = {
		.tgid = 20, .pid = 20, .task = 0xa000, .bprm = 0xb000
	};
	entry(&next);
	assert(begin(&next, 0) == SE_CAP_FAULT);
	assert(stats[SE_CAP_STAT_STALE_RETIRED] == 1 && !routes[0].source_pins);
	assert(capsules[A.tgid].phase == SE_CAP_FREE);
	assert(terminal(&next, 0) == 0);
	stats[SE_CAP_STAT_FAULT] = 0;
	quiescent();
}

/* Terminal of X1 skipped, then the same thread's next exec X2 loses its
 * entry marker (recursion skip) and reuses X1's bprm address. The unmarked
 * begin still retires X1, so X2 never inherits X1's frozen class. */
static void terminal_and_entry_skipped(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	/* X1 terminal skipped; X2 (same task, same bprm) entry skipped. */
	assert(begin(&A, 0) == SE_CAP_FOREIGN);
	assert(stats[SE_CAP_STAT_STALE_RETIRED] == 1 && !routes[0].source_pins);
	assert(capsules[A.tgid].phase == SE_CAP_FREE);
	/* X2 runs in the other scope: it gets ITS class, not X1's. */
	assert(admit(&A, CG_STRICT) == (int)other);
	assert(capsules[A.tgid].flags & SE_CAP_F_UNCOVERED);
	memset(&capsules[A.tgid], 0, sizeof(capsules[A.tgid]));
	quiescent();
}

/* Review follow-up (defense in depth): X1 froze and pinned, its terminal was
 * missed, then X2 (same task, same bprm address) entered and its retiring
 * begin was skipped too. X2's pending entry marker proves X2 opened nothing:
 * the matching capsule is X1's, stale, never X2's frozen class. */
static void stale_frozen_reused_bprm(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(routes[0].source_pins == 1);
	entry(&A); /* X2 at the same addresses; no begin */
	assert(admit(&A, CG_STRICT) == (int)other);
	assert(stats[SE_CAP_STAT_STALE_RETIRED] == 1 &&
	       !routes[0].source_pins && !markers[A.pid].task);
	assert(admit(&A, CG_STRICT) == (int)other); /* #! re-check: mine */
	assert(terminal(&A, 0) == 1);
	quiescent();
}

/* Documents the counterexample this capsule replaces: the plain current-route
 * path, without capsule authority, returns the wrong class after migration. */
static void legacy_fallback_is_unsafe(void)
{
	struct se_route_claim claim = {};
	assert(se_route_admit(CG_STRICT, &claim) == SE_ROUTE_OWNED);
	assert(claim.execution_class == other && other != original);
	se_cap_drop_claim(&claim);
	quiescent();
}

/* G019 gap 4 (review H1): SE_CAP_LATER marks exactly the later admissions
 * of the SAME physical exec (a #! interpreter pass, also after migration);
 * a first admission, including one at a reused bprm address after a missed
 * terminal (stale capsule retired), never carries it. */
static void later_bit(void)
{
	entry(&A);
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original && !last_later);
	assert(admit(&A, CG_AUDIT) == (int)original &&
	       last_later == REPORT_LATER);
	assert(admit(&A, CG_STRICT) == (int)original &&
	       last_later == REPORT_LATER); /* migrated between passes */
	assert(terminal(&A, 0) == 1);
	entry(&A); /* a new exec at the same addresses */
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(admit(&A, CG_STRICT) == (int)other && !last_later);
	assert(admit(&A, CG_STRICT) == (int)other &&
	       last_later == REPORT_LATER);
	entry(&A); /* its terminal was missed: stale at the next begin */
	assert(begin(&A, 0) == SE_CAP_OK);
	assert(stats[SE_CAP_STAT_STALE_RETIRED] == 1);
	assert(admit(&A, CG_AUDIT) == (int)original && !last_later);
	assert(admit(&A, CG_AUDIT) == (int)original &&
	       last_later == REPORT_LATER);
	assert(terminal(&A, 0) == 1);
	quiescent();
}

int main(int argc, char **argv)
{
	assert(argc == 3);
	original = !strcmp(argv[2], "audit") ? 1 : 2;
	assert(original == 1 || !strcmp(argv[2], "strict"));
	other = original == 1 ? 2 : 1;
	static const struct {
		const char *name;
		void (*run)(void);
	} scenarios[] = {
		{ "same-scope", same_scope },
		{ "headerless-migrated", headerless_migrated },
		{ "fresh-control", fresh_control },
		{ "losing-waiter", losing_waiter },
		{ "nonleader-dethread", nonleader_dethread },
		{ "wrong-duplicate-terminal", wrong_and_duplicate_terminal },
		{ "stale-reuse", stale_reuse },
		{ "check-only", check_only },
		{ "late-attach", late_attach },
		{ "unselected-first", unselected_first },
		{ "fault-first", fault_first },
		{ "sequence-exhausted", sequence_exhausted },
		{ "out-of-range", out_of_range },
		{ "busy-capsule-degrades", busy_capsule_degrades },
		{ "check-frozen-never-success", check_frozen_never_success },
		{ "tampered-owner-or-route", tampered_owner_or_route },
		{ "pin-failed", pin_failed },
		{ "terminal-and-entry-skipped", terminal_and_entry_skipped },
		{ "stale-then-exhausted", stale_then_exhausted },
		{ "stale-frozen-reused-bprm", stale_frozen_reused_bprm },
		{ "legacy-fallback-is-unsafe", legacy_fallback_is_unsafe },
		{ "later-bit", later_bit },
	};
	for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
		if (strcmp(argv[1], "all") &&
		    strcmp(argv[1], scenarios[i].name))
			continue;
		reset();
		scenarios[i].run();
		printf("%s/%s: PASS\n", scenarios[i].name, argv[2]);
	}
	return 0;
}
