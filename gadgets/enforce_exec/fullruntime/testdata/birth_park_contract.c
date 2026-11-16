/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Host contract for G019 gaps 1 and 2 (full/shared_birth_receipt.h): the
 * cross-generation first-exec qualification truth table
 * (se_birth_receipt_admits) and the birth park (put, take, abandon, stale,
 * latch) driven with the ACTUAL shared_route.h claim helpers. The park
 * fixture mimics BPF task local storage of the forking task: absent until
 * created, creation that can fail. */
#include <linux/bpf.h>
#include <assert.h>
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
#include "shared_route.h"

static struct se_route_anchor routes[SE_ROUTE_CAPACITY];
static struct se_route_anchor *route_of(__u32 slot)
{
	return slot < SE_ROUTE_CAPACITY ? &routes[slot] : NULL;
}
static int release_claim(struct se_route_claim *claim)
{
	struct se_route_anchor *a = route_of(claim->slot);
	if (!a)
		return -1;
	bpf_spin_lock(&a->lock);
	int r = se_route_release_locked(a, claim);
	bpf_spin_unlock(&a->lock);
	return r;
}

struct se_birth_park;
static struct se_birth_park *park_get(int create);
static unsigned stats[8];
#define SE_BIRTH_PARK_LOOKUP(create) park_get(create)
#define SE_BIRTH_PARK_COUNT(index) (stats[(index)]++)
#define SE_BIRTH_CLAIM_RELEASE(claim) release_claim(claim)
#define SE_BIRTH_ROUTE_LOOKUP(slot) route_of(slot)
#include "shared_birth_receipt.h"

static struct se_birth_park park;
static int has_park, create_fails;
static struct se_birth_park *park_get(int create)
{
	if (!has_park) {
		if (!create || create_fails)
			return NULL;
		memset(&park, 0, sizeof(park));
		has_park = 1;
	}
	return &park;
}

static void reset(__u32 execution_class)
{
	memset(routes, 0, sizeof(routes));
	memset(stats, 0, sizeof(stats));
	memset(&park, 0, sizeof(park));
	has_park = create_fails = 0;
	for (__u32 slot = 0; slot < SE_ROUTE_CAPACITY; slot++)
		routes[slot] = (struct se_route_anchor){
			.incarnation = 1,
			.cgroup_identity = 7 + slot,
			.scope = 10 + slot,
			.payload_generation = 13,
			.active_serial = 1,
			.payload_slot = slot,
			.execution_class = execution_class,
			.phase = SE_ROUTE_ACTIVE,
		};
}
/* The source's claim: an early claim on slot 0's route. */
static struct se_route_claim admit(void)
{
	struct se_route_claim c = {};
	struct se_route_anchor *a = &routes[0];
	bpf_spin_lock(&a->lock);
	assert(se_route_claim_locked(a, se_route_locator(0, 1), 7, &c) ==
	       SE_ROUTE_OWNED);
	bpf_spin_unlock(&a->lock);
	return c;
}
static void quiescent(void)
{
	assert(!held && !lock_errors);
	assert(!routes[0].early_claims && !routes[1].early_claims);
	assert(!has_park || !park.owned);
}

/* se_birth_receipt_admits: route identity must match; same generation is
 * exact (serial, record); an older receipt is cross-generation; a newer one
 * is an invariant fault. */
static void admits_truth_table(__u32 cls)
{
	(void)cls;
#define ADMITS(rs, rg, rse, rsl, ri, rr, rc, cs, cg, cse, csl, ci, cr, cc) \
	se_birth_receipt_admits(rs, rg, rse, rsl, ri, rr, rc, cs, cg, cse, \
				csl, ci, cr, cc)
	/* scope gen serial slot inc record class */
	assert(ADMITS(10, 13, 1, 0, 1, 0, 2, 10, 13, 1, 0, 1, 0, 2) == 1);
	assert(ADMITS(10, 13, 1, 0, 1, 0, 1, 10, 13, 1, 0, 1, 0, 1) == 1);
	/* Same generation, another serial or record: not this claim. */
	assert(ADMITS(10, 13, 1, 0, 1, 0, 2, 10, 13, 2, 0, 1, 0, 2) == 0);
	assert(ADMITS(10, 13, 1, 0, 1, 0, 2, 10, 13, 1, 0, 1, 1, 2) == 0);
	/* A revision committed after the birth: cross-generation (2), any
	 * serial and record. */
	assert(ADMITS(10, 13, 1, 0, 1, 0, 2, 10, 14, 2, 0, 1, 1, 2) == 2);
	assert(ADMITS(10, 13, 1, 0, 1, 0, 1, 10, 99, 7, 0, 1, 0, 1) == 2);
	/* A receipt newer than the route: invariant (-1). */
	assert(ADMITS(10, 14, 1, 0, 1, 0, 2, 10, 13, 1, 0, 1, 0, 2) == -1);
	/* Another route identity is never admitted, in any generation. */
	assert(ADMITS(10, 13, 1, 0, 1, 0, 2, 11, 14, 1, 0, 1, 0, 2) == 0);
	assert(ADMITS(10, 13, 1, 0, 1, 0, 2, 10, 14, 1, 1, 1, 0, 2) == 0);
	assert(ADMITS(10, 13, 1, 0, 1, 0, 2, 10, 14, 1, 0, 2, 0, 2) == 0);
	assert(ADMITS(10, 13, 1, 0, 1, 0, 2, 10, 14, 1, 0, 1, 0, 1) == 0);
	/* ... including a newer receipt on another route (not an invariant). */
	assert(ADMITS(10, 14, 1, 0, 1, 0, 2, 10, 13, 1, 0, 2, 0, 2) == 0);
	/* A receipt class outside 1..2, or an empty receipt, never admits. */
	assert(ADMITS(10, 13, 1, 0, 1, 0, 0, 10, 13, 1, 0, 1, 0, 0) == 0);
	assert(ADMITS(10, 13, 1, 0, 1, 0, 3, 10, 13, 1, 0, 1, 0, 3) == 0);
	assert(ADMITS(0, 13, 1, 0, 1, 0, 2, 0, 13, 1, 0, 1, 0, 2) == 0);
	assert(ADMITS(10, 0, 1, 0, 1, 0, 2, 10, 0, 1, 0, 1, 0, 2) == 0);
#undef ADMITS
}

/* Put moves the source's claim (and its early claim) into the park; the
 * target takes it for its child, re-checked under the route lock, and its
 * release ends the early claim. Revisions are refused while parked. */
static void put_take(__u32 cls)
{
	struct se_route_claim c = admit();
	assert(!se_birth_park_put(&c, 0xc1, 0xcc));
	assert(!c.owned && park.owned && routes[0].early_claims == 1);
	assert(stats[SE_BIRTH_PARK_PARKED] == 1);
	struct se_route_claim taken = {};
	__u32 mode = 1;
	assert(se_birth_park_take(0xc1, &taken, &mode) == SE_ROUTE_OWNED);
	/* The park's class is the mode either way (construct sets it again). */
	assert(taken.owned && !park.owned && mode == cls);
	assert(stats[SE_BIRTH_PARK_TAKEN] == 1);
	assert(!release_claim(&taken));
	quiescent();
}

/* A park for another child is never taken (left to its own birth); a target
 * without a park, or whose parked claim is no longer valid, fails closed
 * with the park's class (CONSTRUCT). An invalid parked claim also latches
 * its route (take-latch). */
static void take_failures(__u32 cls)
{
	struct se_route_claim taken = {};
	__u32 mode = 1;
	assert(se_birth_park_take(0xc1, &taken, &mode) == SE_ROUTE_UNSELECTED);
	assert(!taken.owned && mode == 1);
	struct se_route_claim c = admit();
	assert(!se_birth_park_put(&c, 0xc1, 0xcc));
	assert(se_birth_park_take(0xc2, &taken, &mode) == SE_ROUTE_UNSELECTED);
	assert(park.owned && !taken.owned && mode == (cls == 2 ? 2 : 1));
	/* The parked claim went stale (an invariant: the early claim holds
	 * its record): the target never releases a claim not its own. */
	routes[0].payload_generation++;
	mode = 1;
	assert(se_birth_park_take(0xc1, &taken, &mode) == SE_ROUTE_UNSELECTED);
	assert(!park.owned && !taken.owned && mode == (cls == 2 ? 2 : 1));
	assert(stats[SE_BIRTH_PARK_TAKE_FAILED] == 3 &&
	       !stats[SE_BIRTH_PARK_TAKEN]);
	assert(stats[SE_BIRTH_PARK_LATCHED] == 1 &&
	       routes[0].unresolved_sources == 1);
	assert(routes[0].early_claims == 1); /* leaked, not double-released */
	routes[0].early_claims = 0;
	quiescent();
}

/* The target's own parked claim no longer validates: never released, its
 * route latched under the route lock (unresolved_sources) exactly as a
 * failed release in se_birth_park_drop, LATCHED and TAKE_FAILED (the
 * CONSTRUCT) counted once each, the park's class kept. A claim whose route
 * is gone cannot be latched but is counted the same way. Every other route
 * stays unlatched. */
static void take_latch(__u32 cls)
{
	struct se_route_claim c = admit();
	assert(!se_birth_park_put(&c, 0xc1, 0xcc));
	routes[0].incarnation++; /* the claim no longer matches its route */
	struct se_route_claim taken = {};
	__u32 mode = 1;
	assert(se_birth_park_take(0xc1, &taken, &mode) == SE_ROUTE_UNSELECTED);
	assert(!park.owned && !taken.owned && mode == cls);
	assert(routes[0].unresolved_sources == 1 &&
	       !routes[1].unresolved_sources);
	assert(stats[SE_BIRTH_PARK_LATCHED] == 1 &&
	       stats[SE_BIRTH_PARK_TAKE_FAILED] == 1 &&
	       !stats[SE_BIRTH_PARK_TAKEN] && !stats[SE_BIRTH_PARK_ABANDONED] &&
	       !stats[SE_BIRTH_PARK_STALE]);
	assert(routes[0].early_claims == 1); /* never released */
	routes[0].early_claims = 0;
	routes[0].incarnation--;
	routes[0].unresolved_sources = 0;
	/* No route for the parked slot. */
	c = admit();
	assert(!se_birth_park_put(&c, 0xc1, 0xcc));
	park.claim.slot = SE_ROUTE_CAPACITY;
	mode = 1;
	assert(se_birth_park_take(0xc1, &taken, &mode) == SE_ROUTE_UNSELECTED);
	assert(!park.owned && !taken.owned && mode == cls);
	assert(!routes[0].unresolved_sources && !routes[1].unresolved_sources);
	assert(stats[SE_BIRTH_PARK_LATCHED] == 2 &&
	       stats[SE_BIRTH_PARK_TAKE_FAILED] == 2);
	routes[0].early_claims = 0;
	quiescent();
}

/* A failure before construction abandons the park: the claim is released
 * and a Strict park makes the fail-closed mode 2. */
static void abandon(__u32 cls)
{
	__u32 mode = 1;
	se_birth_park_abandon(&mode); /* no park: nothing */
	assert(mode == 1 && !stats[SE_BIRTH_PARK_ABANDONED]);
	struct se_route_claim c = admit();
	assert(!se_birth_park_put(&c, 0xc1, 0xcc));
	se_birth_park_abandon(&mode);
	assert(mode == (cls == 2 ? 2 : 1) &&
	       stats[SE_BIRTH_PARK_ABANDONED] == 1);
	se_birth_park_abandon(&mode); /* already released */
	assert(stats[SE_BIRTH_PARK_ABANDONED] == 1);
	quiescent();
}

/* A park its target never took is released by the task's next put or by
 * its task_free (se_birth_park_drop on the dying task's park): STALE. */
static void stale(__u32 cls)
{
	(void)cls;
	struct se_route_claim c = admit();
	assert(!se_birth_park_put(&c, 0xc1, 0xcc));
	struct se_route_claim d = admit();
	assert(routes[0].early_claims == 2);
	assert(!se_birth_park_put(&d, 0xc2, 0xcc));
	assert(stats[SE_BIRTH_PARK_STALE] == 1 && routes[0].early_claims == 1);
	assert(park.child == 0xc2 && park.owned);
	se_birth_park_drop(&park, SE_BIRTH_PARK_STALE); /* task_free */
	se_birth_park_drop(NULL, SE_BIRTH_PARK_STALE); /* no storage */
	assert(stats[SE_BIRTH_PARK_STALE] == 2);
	quiescent();
}

/* A park whose claim cannot be released latches its route
 * (unresolved_sources) and counts LATCHED, never the release class. */
static void latch(__u32 cls)
{
	(void)cls;
	struct se_route_claim c = admit();
	assert(!se_birth_park_put(&c, 0xc1, 0xcc));
	routes[0].incarnation++; /* the claim no longer matches its route */
	se_birth_park_drop(&park, SE_BIRTH_PARK_STALE);
	assert(!park.owned && routes[0].unresolved_sources == 1);
	assert(stats[SE_BIRTH_PARK_LATCHED] == 1 &&
	       !stats[SE_BIRTH_PARK_STALE]);
	routes[0].early_claims = 0;
	quiescent();
}

/* No storage: the put refuses (the caller keeps and releases its claim). */
static void put_fails(__u32 cls)
{
	(void)cls;
	create_fails = 1;
	struct se_route_claim c = admit();
	assert(se_birth_park_put(&c, 0xc1, 0xcc) == -1);
	assert(c.owned && stats[SE_BIRTH_PARK_PUT_FAILED] == 1);
	assert(!release_claim(&c));
	quiescent();
}

int main(int argc, char **argv)
{
	assert(argc == 3);
	__u32 cls = !strcmp(argv[2], "audit") ? 1 : 2;
	assert(cls == 1 || !strcmp(argv[2], "strict"));
	static const struct {
		const char *name;
		void (*run)(__u32);
	} scenarios[] = {
		{ "admits-truth-table", admits_truth_table },
		{ "put-take", put_take },
		{ "take-failures", take_failures },
		{ "take-latch", take_latch },
		{ "abandon", abandon },
		{ "stale", stale },
		{ "latch", latch },
		{ "put-fails", put_fails },
	};
	for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
		if (strcmp(argv[1], "all") &&
		    strcmp(argv[1], scenarios[i].name))
			continue;
		reset(cls);
		scenarios[i].run(cls);
		printf("%s/%s: PASS\n", scenarios[i].name, argv[2]);
	}
	return 0;
}
