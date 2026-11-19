/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Host contract for the TASK-STORAGE adapter of the source-only physical-exec
 * capsule (G019 M4 user decision (ii)). It drives the ACTUAL
 * shared_exec_capsule.h state machine and shared_route.h helpers with a
 * fixture that mimics BPF task local storage: per-task storage that exists
 * only once created (SE_CAP_CREATE / SE_CAP_MARKER_CREATE), a lookup that
 * never creates (SE_CAP_LOOKUP), creation that can fail, storage that dies
 * with its task (after lsm/task_free ran se_cap_on_free), and the "exec can
 * matter" predicate (SE_CAP_MATTERS). The ARRAY adapter keeps its own
 * contract (opaque_exec_capsule_contract.c). */
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
#define TASKS 8
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
static struct se_exec_capsule *capsule_get(int create);
static struct se_exec_marker *marker_get(int create);
static int matters(void);
static __u64 next_sequence(void);
static unsigned stats[32];
#define SE_CAP_ABSENT_OK 1
/* The key is the current task; the TGID/PID arguments are unused. */
#define SE_CAP_LOOKUP(tgid) ((void)(tgid), capsule_get(0))
#define SE_CAP_CREATE(tgid) ((void)(tgid), capsule_get(1))
#define SE_CAP_MARKER_LOOKUP(pid) ((void)(pid), marker_get(0))
#define SE_CAP_MARKER_CREATE(pid) ((void)(pid), marker_get(1))
#define SE_CAP_MATTERS() matters()
#define SE_CAP_NEXT_SEQUENCE() next_sequence()
#define SE_CAP_STAT(index) (stats[(index)]++)
/* The product object's adapter (review OQ). */
#define SE_CAP_ENTRY_MARKS_LIVE_CAPSULE 1
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

/* Task local storage stand-in: one slot per live task pointer. */
static struct {
	__u64 task;
	int has_capsule, has_marker, has_key;
	struct se_exec_capsule capsule;
	struct se_exec_marker marker;
} storage[TASKS];
static __u64 current_task, current_cgroup;
static int create_fails, creates;
static __u64 sequence;

static int slot_of(__u64 task)
{
	for (int i = 0; i < TASKS; i++)
		if (storage[i].task == task)
			return i;
	for (int i = 0; i < TASKS; i++)
		if (!storage[i].task) {
			storage[i].task = task;
			return i;
		}
	assert(0);
	return -1;
}
static struct se_exec_capsule *capsule_get(int create)
{
	int i = slot_of(current_task);
	if (!storage[i].has_capsule) {
		if (!create || create_fails)
			return NULL;
		memset(&storage[i].capsule, 0, sizeof(storage[i].capsule));
		storage[i].has_capsule = 1;
		creates++;
	}
	return &storage[i].capsule;
}
static struct se_exec_marker *marker_get(int create)
{
	int i = slot_of(current_task);
	if (!storage[i].has_marker) {
		if (!create || create_fails)
			return NULL;
		memset(&storage[i].marker, 0, sizeof(storage[i].marker));
		storage[i].has_marker = 1;
		creates++;
	}
	return &storage[i].marker;
}
/* Route-index hit for the current cgroup, or the task holds a TASK key. */
static int matters(void)
{
	return index_lookup(&current_cgroup) != NULL ||
	       storage[slot_of(current_task)].has_key;
}
static __u64 next_sequence(void)
{
	return ++sequence;
}
static struct se_exec_capsule *capsule_of(__u64 task)
{
	int i = slot_of(task);
	return storage[i].has_capsule ? &storage[i].capsule : NULL;
}
/* lsm/task_free (se_cap_on_free on the dying task's storage), then the
 * kernel frees the storage: a later task at the same address starts empty. */
static int task_dies(__u64 task)
{
	int r = se_cap_on_free(capsule_of(task));
	int i = slot_of(task);
	memset(&storage[i], 0, sizeof(storage[i]));
	return r;
}

static __u32 original, other;

static void reset(void)
{
	memset(routes, 0, sizeof(routes));
	memset(storage, 0, sizeof(storage));
	memset(stats, 0, sizeof(stats));
	sequence = 0;
	create_fails = creates = 0;
	current_cgroup = CG_UNSELECTED;
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

struct exec {
	__u32 tgid, pid;
	__u64 task, bprm;
};
/* Every hook runs in the executing task, in its current cgroup. */
static void entry(const struct exec *e, __u64 cgroup)
{
	current_task = e->task;
	current_cgroup = cgroup;
	se_cap_on_entry(e->pid, e->task, e->bprm);
}
static int begin(const struct exec *e, __u64 cgroup)
{
	current_task = e->task;
	current_cgroup = cgroup;
	return se_cap_on_begin(e->tgid, e->pid, e->task, e->bprm, 0);
}
#ifdef SE_CAP_REPORT_LATER
#define REPORT_LATER 1
#else
#define REPORT_LATER 0
#endif
static int last_later;
/* 1 Audit, 2 Strict, 0 unselected, 3 audit-fault, 4 strict-fault, 5 other. */
static int admit(const struct exec *e, __u64 cgroup)
{
	struct se_route_claim claim = {};
	__u32 frozen = 0;
	current_task = e->task;
	current_cgroup = cgroup;
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
		return cls;
	}
	assert(!claim.owned);
	return r == SE_ROUTE_UNSELECTED	  ? 0 :
	       r == SE_ROUTE_AUDIT_FAULT  ? 3 :
	       r == SE_ROUTE_STRICT_FAULT ? 4 :
					    5;
}
static int terminal(const struct exec *e, long retval)
{
	current_task = e->task;
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
	for (int i = 0; i < TASKS; i++) {
		assert(!storage[i].has_capsule ||
		       storage[i].capsule.phase == SE_CAP_FREE);
		assert(!storage[i].has_capsule ||
		       !storage[i].capsule.owner.owned);
		assert(!storage[i].has_marker ||
		       (!storage[i].marker.task && !storage[i].marker.bprm));
	}
	assert(!stats[SE_CAP_STAT_FAULT] && !stats[SE_CAP_STAT_RELEASE_FAULT]);
}

static const struct exec A = { .tgid = 20,
			       .pid = 20,
			       .task = 0xa000,
			       .bprm = 0xb000 };

/* A covered exec in a selected cgroup: storage is created at entry/begin,
 * the original route is pinned, an interpreter iteration after migration
 * keeps the original class, the terminal releases the pin. */
static void selected_covered(void)
{
	entry(&A, CG_AUDIT);
	assert(begin(&A, CG_AUDIT) == SE_CAP_OK && creates == 2);
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(routes[0].source_pins == 1);
	assert(admit(&A, CG_STRICT) == (int)original); /* migrated */
	assert(terminal(&A, 0) == 1 && !routes[0].source_pins);
	quiescent();
}

/* An exec that never matters creates no storage at all, and its terminal
 * is not a fault. */
static void unselected_creates_nothing(void)
{
	entry(&A, CG_UNSELECTED);
	assert(begin(&A, CG_UNSELECTED) == SE_CAP_FOREIGN);
	assert(admit(&A, CG_UNSELECTED) == 0);
	assert(terminal(&A, 0) == 0);
	assert(!creates && !capsule_of(A.task));
	assert(!stats[SE_CAP_STAT_FOREIGN_TERMINAL]);
	quiescent();
}

/* A task holding a TASK key matters even in an unselected cgroup: its
 * covered begin opens a capsule, so a migration into a selected cgroup
 * before the first admission freezes the class WITH a pin. */
static void task_key_matters(void)
{
	storage[slot_of(A.task)].has_key = 1;
	entry(&A, CG_UNSELECTED);
	assert(begin(&A, CG_UNSELECTED) == SE_CAP_OK);
	assert(admit(&A, CG_STRICT) == (int)other);
	assert(routes[1].source_pins == 1);
	assert(admit(&A, CG_AUDIT) == (int)other);
	assert(terminal(&A, 0) == 1);
	quiescent();
}

/* Migration into a selected cgroup by a task that never mattered before
 * its first selected admission: the storage is created at that admission
 * (uncovered: the original class frozen, no pin, the original route's
 * identity recorded). A #! re-check or a migrated admission re-claims the
 * ORIGINAL route (review M2: no false deny of scripts), never the current
 * route's class. */
static void migrate_in_uncovered(void)
{
	entry(&A, CG_UNSELECTED);
	assert(begin(&A, CG_UNSELECTED) == SE_CAP_FOREIGN && !creates);
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(stats[SE_CAP_STAT_FROZEN_UNCOVERED] == 1 &&
	       !routes[0].source_pins);
	assert(admit(&A, CG_AUDIT) == (int)original); /* #! re-check */
	struct se_route_anchor before = routes[1];
	assert(admit(&A, CG_STRICT) == (int)original); /* migrated */
	assert(!memcmp(&before, &routes[1], sizeof(before)));
	assert(stats[SE_CAP_STAT_ORIGINAL_CLAIM] == 2);
	/* No covered terminal for an uncovered exec: a FREE-or-uncovered
	 * capsule is retired by the task's next begin or at its death. */
	assert(terminal(&A, 0) == 1);
	quiescent();
}

/* The begin-time create was skipped (the tracing helper's per-CPU trylock):
 * the exec is uncovered although it mattered; the first selected admission
 * (LSM, non-recursive helper) creates the storage and the #! re-check
 * succeeds by identity. */
static void begin_create_skipped(void)
{
	entry(&A, CG_STRICT);
	create_fails = 1;
	assert(begin(&A, CG_STRICT) == SE_CAP_FAULT);
	create_fails = 0;
	assert(admit(&A, CG_STRICT) == (int)other);
	assert(admit(&A, CG_STRICT) == (int)other); /* binfmt re-check */
	assert(stats[SE_CAP_STAT_ORIGINAL_CLAIM] == 1);
	assert(terminal(&A, 0) == 1);
	stats[SE_CAP_STAT_FAULT] = 0;
	quiescent();
}

/* Identity-bound re-admission fails closed: the original route was
 * republished, withdrawn, or is adopting between the admissions; the first
 * admission was itself a fault (nothing recorded). */
static void identity_mismatch_faults(void)
{
	entry(&A, CG_UNSELECTED);
	assert(begin(&A, CG_UNSELECTED) == SE_CAP_FOREIGN);
	assert(admit(&A, CG_AUDIT) == (int)original);
	routes[0].payload_generation++;
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	routes[0].payload_generation--;
	routes[0].incarnation++;
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	routes[0].incarnation--;
	routes[0].phase = SE_ROUTE_WITHDRAWN;
	assert(admit(&A, CG_STRICT) == fault_of(original));
	routes[0].phase = SE_ROUTE_ACTIVE;
	/* Review L2: the anchor's class changed behind an unchanged payload
	 * generation (invariant breach): the ident claim still faults. */
	routes[0].execution_class = other;
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	routes[0].execution_class = original;
	assert(admit(&A, CG_AUDIT) == (int)original); /* restored identity */
	assert(terminal(&A, 0) == 1);
	/* A faulting first admission records no identity. */
	const struct exec B = {
		.tgid = 21, .pid = 21, .task = 0xa100, .bprm = 0xb100
	};
	entry(&B, CG_UNSELECTED);
	assert(begin(&B, CG_UNSELECTED) == SE_CAP_FOREIGN);
	routes[1].early_claims = ~0U;
	assert(admit(&B, CG_STRICT) == fault_of(other));
	routes[1].early_claims = 0;
	assert(!(capsule_of(B.task)->flags & SE_CAP_F_IDENT));
	assert(admit(&B, CG_STRICT) == fault_of(other));
	assert(terminal(&B, 0) == 1);
	quiescent();
}

/* Storage creation fails where it is needed: the begin is a counted fault;
 * the first selected admission cannot freeze, so it degrades through the
 * current route (Strict fault, Audit fault, unselected allowed). */
static void create_fails_degrades(void)
{
	create_fails = 1;
	entry(&A, CG_STRICT);
	assert(begin(&A, CG_STRICT) == SE_CAP_FAULT);
	assert(stats[SE_CAP_STAT_FAULT] == 2); /* entry marker, begin capsule */
	assert(admit(&A, CG_UNSELECTED) == 0);
	assert(admit(&A, CG_AUDIT) == fault_of(original));
	assert(admit(&A, CG_STRICT) == fault_of(other));
	assert(stats[SE_CAP_STAT_FAULT] == 4); /* + each selected admission */
	assert(terminal(&A, 0) == 0);
	stats[SE_CAP_STAT_FAULT] = 0;
	quiescent();
}

/* The terminal is missed and the task dies: lsm/task_free retires the
 * capsule and releases the original-route pin before the storage is freed;
 * a new task at the same address inherits nothing. */
static void death_retires_pin(void)
{
	entry(&A, CG_AUDIT);
	assert(begin(&A, CG_AUDIT) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(routes[0].source_pins == 1);
	assert(task_dies(A.task) == 1);
	assert(stats[SE_CAP_STAT_DEATH_RETIRED] == 1 && !routes[0].source_pins);
	/* ABA: same task and bprm addresses, a fresh life in the other scope. */
	entry(&A, CG_STRICT);
	assert(begin(&A, CG_STRICT) == SE_CAP_OK);
	assert(!stats[SE_CAP_STAT_STALE_RETIRED]);
	assert(admit(&A, CG_STRICT) == (int)other);
	assert(terminal(&A, 0) == 1);
	quiescent();
}

/* A task that dies with a FREE capsule (or none) retires nothing. */
static void death_after_terminal(void)
{
	entry(&A, CG_AUDIT);
	assert(begin(&A, CG_AUDIT) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(terminal(&A, 0) == 1);
	assert(task_dies(A.task) == 0);
	const struct exec B = { .tgid = 21, .pid = 21, .task = 0xa100 };
	assert(task_dies(B.task) == 0);
	assert(!stats[SE_CAP_STAT_DEATH_RETIRED]);
	quiescent();
}

/* Two threads of one TGID: each has its own storage. A losing waiter's
 * terminal (ERESTARTNOINTR) never touches the winner's capsule; the
 * winner's exec keeps its class through de_thread. */
static void per_task_isolation(void)
{
	const struct exec win = {
		.tgid = 30, .pid = 31, .task = 0xc100, .bprm = 0xd100
	};
	const struct exec lose = {
		.tgid = 30, .pid = 32, .task = 0xc200, .bprm = 0xd200
	};
	entry(&win, CG_AUDIT);
	entry(&lose, CG_AUDIT);
	assert(begin(&win, CG_AUDIT) == SE_CAP_OK);
	assert(admit(&win, CG_AUDIT) == (int)original);
	struct se_exec_capsule before = *capsule_of(win.task);
	assert(terminal(&lose, -ERESTARTNOINTR) == 0);
	assert(!memcmp(&before, capsule_of(win.task), sizeof(before)));
	assert(!capsule_of(lose.task)); /* the loser never began */
	assert(task_dies(lose.task) == 0); /* de_thread kills the loser */
	const struct exec after = {
		.tgid = 30, .pid = 30, .task = 0xc100, .bprm = 0xd100
	}; /* exchange_tids: leader PID, same task */
	assert(admit(&after, CG_STRICT) == (int)original);
	assert(terminal(&after, 0) == 1);
	quiescent();
}

/* Missed terminal, same task execs again: its next begin retires the stale
 * capsule (pin released) before opening a fresh one. */
static void stale_same_task(void)
{
	entry(&A, CG_AUDIT);
	assert(begin(&A, CG_AUDIT) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	const struct exec next = {
		.tgid = 20, .pid = 20, .task = 0xa000, .bprm = 0xb200
	};
	entry(&next, CG_STRICT);
	assert(begin(&next, CG_STRICT) == SE_CAP_OK);
	assert(stats[SE_CAP_STAT_STALE_RETIRED] == 1 && !routes[0].source_pins);
	assert(admit(&next, CG_STRICT) == (int)other);
	assert(terminal(&next, 0) == 1);
	quiescent();
}

/* Review follow-up (defense in depth): X1 froze and pinned, its terminal
 * was missed, then X2 (same task and bprm address) entered and its begin's
 * lookup missed (the tracing helper's trylock). X2's pending entry marker
 * proves X2 opened nothing: X1's capsule is stale, never X2's class. */
static void stale_frozen_reused_bprm(void)
{
	entry(&A, CG_AUDIT);
	assert(begin(&A, CG_AUDIT) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original);
	assert(routes[0].source_pins == 1);
	entry(&A, CG_STRICT); /* X2; its begin missed the storage */
	assert(admit(&A, CG_STRICT) == (int)other);
	assert(!routes[0].source_pins);
	assert(admit(&A, CG_STRICT) == (int)other); /* #! re-check: mine */
	assert(terminal(&A, 0) == 1);
	quiescent();
}

/* Review OQ: X1 froze uncovered with its route identity (IDENT), its
 * terminal was missed; X2 (same task and bprm address) entered while it did
 * not matter yet and its begin missed the storage, then migrated into
 * another selected cgroup. X1's live capsule marks X2's entry anyway, so
 * X2's first admission retires it as stale and admits under X2's current
 * route: never an identity re-claim of X1's route. */
static void stale_ident_reused_bprm(void)
{
	entry(&A, CG_UNSELECTED);
	assert(begin(&A, CG_UNSELECTED) == SE_CAP_FOREIGN);
	assert(admit(&A, CG_AUDIT) == (int)original); /* X1, IDENT */
	assert(capsule_of(A.task)->flags & SE_CAP_F_IDENT);
	entry(&A, CG_UNSELECTED); /* X2; terminal and begin missed */
	assert(storage[slot_of(A.task)].has_marker &&
	       storage[slot_of(A.task)].marker.bprm == A.bprm);
	assert(admit(&A, CG_STRICT) == (int)other);
	assert(stats[SE_CAP_STAT_STALE_RETIRED] == 1 &&
	       stats[SE_CAP_STAT_ORIGINAL_CLAIM] == 0);
	assert(admit(&A, CG_STRICT) == (int)other); /* #! re-check: mine */
	assert(terminal(&A, 0) == 1);
	/* A FREE capsule (a finished exec) marks nothing for an exec that does
	 * not matter. */
	storage[slot_of(A.task)].has_marker = 0;
	entry(&A, CG_UNSELECTED);
	assert(!storage[slot_of(A.task)].has_marker);
	quiescent();
}

/* The exec mattered at entry but migrated out before begin: no capsule is
 * created at begin, the marker is consumed by the terminal. */
static void entry_only(void)
{
	entry(&A, CG_STRICT);
	assert(begin(&A, CG_UNSELECTED) == SE_CAP_FOREIGN);
	assert(admit(&A, CG_UNSELECTED) == 0);
	assert(terminal(&A, 0) == 0);
	quiescent();
}

/* G019 gap 4 (review H1): SE_CAP_LATER on the task-storage adapter. The
 * uncovered freeze (storage created at the first selected admission) and
 * its identity re-claim follow the same rule: only a later admission of the
 * same exec carries the bit, never a first admission after a stale retire. */
static void later_bit(void)
{
	entry(&A, CG_UNSELECTED);
	assert(begin(&A, CG_UNSELECTED) == SE_CAP_FOREIGN);
	assert(admit(&A, CG_AUDIT) == (int)original && !last_later);
	assert(admit(&A, CG_AUDIT) == (int)original &&
	       last_later == REPORT_LATER); /* #! re-check, IDENT re-claim */
	assert(admit(&A, CG_STRICT) == (int)original &&
	       last_later == REPORT_LATER); /* migrated */
	assert(terminal(&A, 0) == 1);
	entry(&A, CG_AUDIT);
	assert(begin(&A, CG_AUDIT) == SE_CAP_OK);
	assert(admit(&A, CG_AUDIT) == (int)original && !last_later);
	entry(&A, CG_STRICT); /* terminal and begin missed: X1 is stale */
	assert(admit(&A, CG_STRICT) == (int)other && !last_later);
	assert(admit(&A, CG_STRICT) == (int)other &&
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
		{ "selected-covered", selected_covered },
		{ "unselected-creates-nothing", unselected_creates_nothing },
		{ "task-key-matters", task_key_matters },
		{ "migrate-in-uncovered", migrate_in_uncovered },
		{ "create-fails-degrades", create_fails_degrades },
		{ "begin-create-skipped", begin_create_skipped },
		{ "identity-mismatch-faults", identity_mismatch_faults },
		{ "death-retires-pin", death_retires_pin },
		{ "death-after-terminal", death_after_terminal },
		{ "per-task-isolation", per_task_isolation },
		{ "stale-same-task", stale_same_task },
		{ "entry-only", entry_only },
		{ "stale-frozen-reused-bprm", stale_frozen_reused_bprm },
		{ "stale-ident-reused-bprm", stale_ident_reused_bprm },
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
