/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Host contract for G019 gap 3 (per-record route holders, product
 * publisher): the ACTUAL shared_route.h / shared_snapshot.h transitions with
 * ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE. A revision commits
 * while the previous record has holders (it becomes RETIRING and keeps
 * them); holders release against their own record; fresh claims always
 * stamp the ACTIVE record; a RETIRING record is dropped only once it has no
 * holder (drop() mirrors real_owner_snapshot_drop's checks and order). */
#include <linux/bpf.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct bpf_spin_lock *held;
static unsigned lock_errors;
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	if (held)
		lock_errors++;
	held = lock;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	if (held != lock)
		lock_errors++;
	held = NULL;
}

#define ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE 1
#define SE_ROUTE_CAPACITY 2
#include "shared_route.h"

#define CGROUP 7
#define SCOPE 31

static struct se_route_anchor a;
static struct se_shared_binding b;
static struct se_shared_object objects[3];
static struct bpf_spin_lock object_authority; /* stands in for the route lock */

static void reset(void)
{
	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	for (__u32 i = 0; i < 3; i++)
		objects[i].state = (struct se_object){
			.slot = i, .generation = 1, .phase = SE_OBJECT_READY
		};
	b.state.scope = SCOPE;
	bpf_spin_lock(&a.lock);
	assert(!se_route_open_locked(&a, CGROUP, SCOPE, 0));
	bpf_spin_unlock(&a.lock);
}
/* Stage object o into record and commit it (first publication or
 * revision). 0 committed, -1 refused (nothing changed but the candidate,
 * which is aborted). */
static int publish(__u32 record, __u32 o)
{
	struct se_pin_ticket h = { .object_slot = o,
				   .object_generation =
					   objects[o].state.generation };
	if (se_snapshot_prepare_locked(&b.state, record, &h, 1, 2))
		return -1;
	struct se_ticket_request r = { .scope = SCOPE,
				       .serial = b.state.records[record].serial,
				       .record = record,
				       .kind = SE_COMMAND_PIN };
	__u32 receipt;
	assert(!se_ticket_command(&object_authority, &b, &objects[o], &r,
				  &receipt));
	assert(!se_snapshot_prepared_locked(&b.state.records[record]));
	bpf_spin_lock(&a.lock);
	int refused = se_route_commit_preflight_locked(
		&a, &b.state, record, b.state.records[record].serial,
		a.admission_serial);
	if (!refused)
		se_route_commit_publish_locked(&a, &b.state, record);
	bpf_spin_unlock(&a.lock);
	if (refused) {
		struct se_snapshot *s = &b.state.records[record];
		assert(!se_snapshot_retire_locked(s));
		r.kind = SE_COMMAND_RELEASE;
		assert(!se_ticket_command(&object_authority, &b, &objects[o],
					  &r, &receipt));
		assert(!se_snapshot_reclaim_locked(s));
	}
	return refused ? -1 : 0;
}
/* real_owner_snapshot_drop: 0 dropped (or FREE), 1 holders remain, -1. */
static int drop(__u32 record)
{
	bpf_spin_lock(&a.lock);
	struct se_snapshot *s = &b.state.records[record];
	__u32 phase = s->phase, count = s->count;
	int holders = s->claims || se_route_rec_held(&a, record);
	struct se_ticket_request r = { .scope = s->scope,
				       .serial = s->serial,
				       .record = record,
				       .kind = SE_COMMAND_RELEASE };
	__u32 o = s->tickets[0].object_slot;
	bpf_spin_unlock(&a.lock);
	if (phase == SE_SNAPSHOT_FREE)
		return 0;
	if (phase != SE_SNAPSHOT_RETIRING || count != 1)
		return -1;
	if (holders)
		return 1;
	__u32 receipt;
	if (se_ticket_command(&object_authority, &b, &objects[o], &r, &receipt))
		return -1;
	bpf_spin_lock(&a.lock);
	int result = se_snapshot_reclaim_locked(s);
	if (!result)
		*SE_ROUTE_REC(&a, record) = (struct se_route_rec){};
	bpf_spin_unlock(&a.lock);
	return result;
}
static int claim(struct se_route_claim *c)
{
	*c = (struct se_route_claim){};
	bpf_spin_lock(&a.lock);
	int r = se_route_claim_locked(&a, se_route_locator(0, a.incarnation),
				      CGROUP, c);
	bpf_spin_unlock(&a.lock);
	return r;
}
static int release(struct se_route_claim *c)
{
	bpf_spin_lock(&a.lock);
	int r = se_route_release_locked(&a, c);
	bpf_spin_unlock(&a.lock);
	return r;
}
static void quiescent(void)
{
	assert(!held && !lock_errors);
	assert(!a.early_claims && !a.source_pins);
	for (__u32 i = 0; i < 2; i++)
		assert(!a.rec[i].early_claims && !a.rec[i].source_pins &&
		       !b.state.records[i].claims);
}
static void first(void)
{
	assert(!publish(0, 0));
	assert(a.rec[0].phase == SE_SNAPSHOT_ACTIVE &&
	       a.rec[0].generation == 1 && a.rec[0].serial == 1);
}

/* A held claim no longer blocks the commit: its record turns RETIRING and
 * keeps the holder (route total and rec[old]); the new record is ACTIVE
 * with no holder; a fresh claim stamps the new record. */
static void commit_while_held(void)
{
	first();
	struct se_route_claim held0;
	assert(claim(&held0) == SE_ROUTE_OWNED && held0.record == 0);
	assert(!publish(1, 1));
	assert(a.active_record == 1 && a.payload_generation == 2);
	assert(a.rec[0].phase == SE_SNAPSHOT_RETIRING &&
	       a.rec[0].early_claims == 1 && a.early_claims == 1);
	assert(a.rec[1].phase == SE_SNAPSHOT_ACTIVE && !a.rec[1].early_claims);
	struct se_route_claim fresh;
	assert(claim(&fresh) == SE_ROUTE_OWNED && fresh.record == 1 &&
	       fresh.generation == 2);
	assert(a.rec[1].early_claims == 1 && a.early_claims == 2);
	/* The held claim is still valid against its RETIRING record. */
	assert(!release(&held0) && !a.rec[0].early_claims);
	assert(!release(&fresh));
	assert(!drop(0) && objects[0].state.pins == 0);
	quiescent();
}

/* The RETIRING record is dropped only once its holders are gone, and a
 * third revision (into that record) is refused meanwhile. Withdrawal is
 * refused while any holder remains. */
static void drop_and_third_revision(void)
{
	first();
	struct se_route_claim held0;
	assert(claim(&held0) == SE_ROUTE_OWNED);
	assert(!publish(1, 1));
	assert(drop(0) == 1 && objects[0].state.pins == 1);
	assert(publish(0, 2) == -1); /* record 0 is still RETIRING */
	bpf_spin_lock(&a.lock);
	assert(se_route_withdraw_locked(&a, &b.state) < 0);
	bpf_spin_unlock(&a.lock);
	assert(!release(&held0));
	assert(!drop(0) && objects[0].state.pins == 0);
	assert(!publish(0, 2) && a.payload_generation == 3 &&
	       a.rec[1].phase == SE_SNAPSHOT_RETIRING);
	assert(!drop(1));
	quiescent();
}

/* A reader of the RETIRING record (a claim already bound to it, moved to a
 * reader by the transfer) holds it: the ticket RELEASE is refused while it
 * reads; once it releases (allowed on RETIRING), the drop goes through. */
static void reader_holds_retiring(void)
{
	first();
	struct se_route_claim c;
	assert(claim(&c) == SE_ROUTE_OWNED);
	assert(!publish(1, 1));
	struct se_reader_owner owner = {};
	struct se_reader_token token = {};
	bpf_spin_lock(&a.lock);
	assert(!se_route_transfer_locked(&a, &b.state, &c, 0xc0, &owner,
					 &token));
	bpf_spin_unlock(&a.lock);
	assert(!c.owned && !a.rec[0].early_claims && token.record == 0 &&
	       b.state.records[0].claims == 1);
	assert(drop(0) == 1);
	struct se_ticket_request r = { .scope = SCOPE,
				       .serial = b.state.records[0].serial,
				       .record = 0,
				       .kind = SE_COMMAND_RELEASE };
	__u32 receipt;
	assert(se_ticket_command(&object_authority, &b, &objects[0], &r,
				 &receipt) < 0 &&
	       objects[0].state.pins == 1);
	/* A fresh reader never lands on the RETIRING record. */
	struct se_reader_owner fresh = {};
	struct se_reader_token fresh_token = {};
	bpf_spin_lock(&a.lock);
	assert(se_reader_acquire_retiring_locked(&b.state, 0, 1, 2, SCOPE, 0xc1,
						 &fresh, &fresh_token) < 0);
	assert(!se_reader_release_locked(&b.state, &owner, &token));
	bpf_spin_unlock(&a.lock);
	assert(!drop(0));
	quiescent();
}

/* A copied claim of a record that was dropped and reused by a later
 * generation is refused (its generation is no longer that record's), as is
 * a forged generation on a live record. */
static void reused_record_refused(void)
{
	first();
	struct se_route_claim c;
	assert(claim(&c) == SE_ROUTE_OWNED);
	struct se_route_claim copy = c;
	assert(!release(&c));
	assert(!publish(1, 1) && !drop(0));
	assert(!publish(0, 2) && !drop(1)); /* record 0 now generation 3 */
	assert(release(&copy) < 0 && !a.early_claims);
	struct se_route_claim live;
	assert(claim(&live) == SE_ROUTE_OWNED && live.record == 0);
	struct se_route_claim forged = live;
	forged.generation = 1;
	assert(release(&forged) < 0);
	assert(!release(&live));
	quiescent();
}

/* A source pin holds its record: the pinned re-claim (claim_source) works
 * on the RETIRING record (and stamps its identity), the identity
 * re-claim (unpinned) only on the ACTIVE one; the pin releases against its
 * RETIRING record; the drop waits for it. */
static void source_pin_on_retiring(void)
{
	first();
	struct se_route_claim c;
	assert(claim(&c) == SE_ROUTE_OWNED);
	struct se_source_mode_owner owner = {};
	struct se_source_mode_token token = {};
	bpf_spin_lock(&a.lock);
	assert(!se_route_source_pin_acquire_locked(&a, &c, 0xa0, 5, &owner,
						   &token));
	bpf_spin_unlock(&a.lock);
	assert(token.record == 0 && a.rec[0].source_pins == 1);
	assert(!release(&c));
	assert(!publish(1, 1));
	assert(drop(0) == 1);
	struct se_route_claim again = {};
	bpf_spin_lock(&a.lock);
	assert(se_route_claim_source_locked(&a, &owner, 0xa0, 5, 2, &again) ==
	       SE_ROUTE_OWNED);
	/* Unpinned identity re-claim of the RETIRING record: refused. */
	struct se_route_claim ident = {};
	assert(se_route_claim_ident_locked(&a, &owner.token, 2, &ident) ==
	       SE_ROUTE_STRICT_FAULT);
	bpf_spin_unlock(&a.lock);
	assert(again.record == 0 && again.generation == 1 &&
	       again.serial == 1 && a.rec[0].early_claims == 1);
	assert(!release(&again));
	bpf_spin_lock(&a.lock);
	assert(!se_route_source_pin_release_locked(&a, &owner, &token, 0xa0,
						   5));
	bpf_spin_unlock(&a.lock);
	assert(!a.rec[0].source_pins && !a.source_pins);
	assert(!drop(0));
	quiescent();
}

/* Saturation: a claim at the ~0U total faults and leaves every count. */
static void saturation(void)
{
	first();
	a.early_claims = (__u32)~0U;
	struct se_route_claim c;
	assert(claim(&c) == SE_ROUTE_STRICT_FAULT && !c.owned &&
	       !a.rec[0].early_claims);
	a.early_claims = 0;
	quiescent();
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	static const struct {
		const char *name;
		void (*run)(void);
	} scenarios[] = {
		{ "commit-while-held", commit_while_held },
		{ "drop-and-third-revision", drop_and_third_revision },
		{ "reader-holds-retiring", reader_holds_retiring },
		{ "reused-record-refused", reused_record_refused },
		{ "source-pin-on-retiring", source_pin_on_retiring },
		{ "saturation", saturation },
	};
	for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
		if (strcmp(argv[1], "all") &&
		    strcmp(argv[1], scenarios[i].name))
			continue;
		reset();
		scenarios[i].run();
		printf("%s: PASS\n", scenarios[i].name);
	}
	return 0;
}
