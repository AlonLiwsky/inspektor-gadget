/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Host contract of full/shared_verdict_event.h (G020 verdict event ABI 1):
 * the actual mapping from facts, decision and receipt metadata to the event
 * bytes. Not a verifier or live-kernel proof (the attached events test is). */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef uint64_t __u64;
/* Only the fact/decision types and fe_lsm_verdict are used. */
#define FM_BLOB_LOOKUP(context, key) \
	((void)(context), (void)(key), (const struct fm_blob *)0)
#include "evaluator.h"
/* A nonzero load epoch, as the agent sets one per load. */
#define SE_VERDICT_LOAD_EPOCH_INIT 0x5e00000000000001ULL
#include "shared_verdict_event.h"

static struct fe_facts facts;
static int cases;

/* Every fact known: /usr/bin/true by /usr/bin/bash. */
static void known_facts(void)
{
	memset(&facts, 0xa5, sizeof(facts));
	facts.target_path.length = 13;
	memset(facts.target_path.bytes, 0, sizeof(facts.target_path.bytes));
	memcpy(facts.target_path.bytes, "/usr/bin/true", 14);
	facts.actor_path.length = 13;
	memcpy(facts.actor_path.bytes, "/usr/bin/bash", 14);
	facts.uid_known = 1;
	facts.ancestors_complete = 1;
	facts.fs_known = FE_TMPFS | FE_MEMFD | FE_DELETED | FE_OVERLAY;
	facts.argv_complete = 1;
	facts.stdin_pipe = 0;
	facts.target_image = 0;
	facts.actor_image = 1;
}

static struct se_verdict_meta meta(__u32 class, __u32 kind)
{
	return (struct se_verdict_meta){
		.generation = 7,
		.cgroup = 0x1234,
		.scope = 0xabcdef,
		.exec_id = 99,
		.task_cookie = 0x7700000001ULL,
		.host_pid = 4242,
		.exec_class = class,
		.pass = kind == SE_VERDICT_FAULT ? SE_VERDICT_PASS_UNKNOWN : 1,
		.kind = kind
	};
}

/* The event, from a buffer full of garbage: every byte is written. */
static struct shared_verdict_event fill(const struct fe_facts *f,
					const struct fe_decision *d,
					struct se_verdict_meta m, int want)
{
	struct shared_verdict_event e;
	memset(&e, 0x5a, sizeof(e));
	assert(se_verdict_event_fill(&e, f, d, &m) == want);
	const unsigned char *raw = (const unsigned char *)&e;
	for (size_t i = 356; i < 360; i++)
		assert(raw[i] == 0); /* padding before task_cookie */
	assert(sizeof(e) == 376);
	assert(e.load_epoch == SE_VERDICT_LOAD_EPOCH_INIT &&
	       e.load_epoch == se_verdict_load_epoch);
	assert(e.generation == m.generation && e.cgroup == m.cgroup &&
	       e.host_pid == m.host_pid && e.exec_class == m.exec_class &&
	       e.scope == m.scope && e.exec_id == m.exec_id &&
	       e.task_cookie == m.task_cookie && e.pass == m.pass);
	assert(e.error <= FE_ROLE_CONFLICT && e.deny <= 1 &&
	       (e.mode == 1 || e.mode == 2) && e.uncertain <= 1);
	/* The event reports the LSM verdict, never another one. */
	if (m.kind == SE_VERDICT_DECISION && d) {
		int error = d->error != FE_OK && d->error != FE_AUDIT_UNKNOWN;
		long verdict = fe_lsm_verdict(m.exec_class, 0, error, d);
		assert((e.deny && e.mode == 2) == (verdict != 0));
	} else
		assert((e.deny && e.mode == 2) ==
		       (fe_lsm_verdict(m.exec_class, 0, 1, 0) != 0));
	cases++;
	return e;
}

static struct fe_decision decision(__u32 deny, __u32 mode, __u32 error)
{
	struct fe_decision d;
	memset(&d, 0, sizeof(d));
	d.deny = deny;
	d.mode = mode;
	d.error = error;
	d.matched_rules[0] = 1ULL << 3;
	return d;
}

static void path_known(const struct shared_verdict_event *e)
{
	assert(!strcmp(e->path, "/usr/bin/true") && e->path_result == 14 &&
	       !(e->facts_unknown & SE_VERDICT_UNKNOWN_TARGET_PATH));
}

int main(void)
{
	struct fe_decision d;
	struct shared_verdict_event e;

	/* Strict allow: no rule denies. */
	known_facts();
	d = decision(0, 2, FE_OK);
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	path_known(&e);
	assert(!e.deny && e.mode == 2 && !e.error && !e.uncertain &&
	       !e.facts_unknown && e.matched_rules[0] == 8 && e.pass == 1);

	/* Strict deny. */
	d = decision(1, 2, FE_OK);
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	assert(e.deny && e.mode == 2 && !e.error && !e.uncertain);

	/* Audit would-deny: mode 1 even for a decision of mode 2. */
	d = decision(1, 1, FE_OK);
	e = fill(&facts, &d, meta(1, SE_VERDICT_DECISION), 0);
	assert(e.deny && e.mode == 1 && !e.error && e.exec_class == 1);
	d = decision(1, 2, FE_OK);
	e = fill(&facts, &d, meta(1, SE_VERDICT_DECISION), 0);
	assert(e.deny && e.mode == 1);

	/* AUDIT_UNKNOWN: error 0, uncertain. */
	d = decision(1, 1, FE_AUDIT_UNKNOWN);
	d.audit_unknown = 1;
	e = fill(&facts, &d, meta(1, SE_VERDICT_DECISION), 0);
	assert(e.deny && e.mode == 1 && e.error == 0 && e.uncertain);
	d = decision(0, 1, FE_AUDIT_UNKNOWN);
	e = fill(&facts, &d, meta(1, SE_VERDICT_DECISION), 0);
	assert(!e.deny && e.error == 0 && e.uncertain);
	/* Uncertainty without the error word (fallback suppression). */
	d = decision(0, 1, FE_OK);
	d.audit_unknown = FE_AUDIT_UNCERTAIN_FALLBACK;
	e = fill(&facts, &d, meta(1, SE_VERDICT_DECISION), 0);
	assert(!e.deny && !e.error && e.uncertain);

	/* Strict UNKNOWN / role conflict: the class verdict, the error kept. */
	d = decision(0, 1, FE_UNKNOWN);
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	assert(e.deny && e.mode == 2 && e.error == FE_UNKNOWN && e.uncertain);
	d = decision(0, 1, FE_ROLE_CONFLICT);
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	assert(e.deny && e.mode == 2 && e.error == FE_ROLE_CONFLICT &&
	       !e.uncertain);
	d = decision(0, 1, FE_ROLE_CONFLICT);
	e = fill(&facts, &d, meta(1, SE_VERDICT_DECISION), 0);
	assert(e.deny && e.mode == 1 && e.error == FE_ROLE_CONFLICT);
	/* Out-of-range errors normalize to FE_INVALID. */
	for (__u32 bad = 5; bad < 9; bad++) {
		d = decision(0, 2, bad);
		e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
		assert(e.deny && e.mode == 2 && e.error == FE_INVALID);
	}
	d = decision(0, 2, 0xffffffffU);
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	assert(e.error == FE_INVALID);

	/* Rule bit 255 (and bit 0) survive. */
	d = decision(1, 2, FE_OK);
	d.matched_rules[0] = 1;
	d.matched_rules[3] = 1ULL << 63;
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	assert(e.matched_rules[0] == 1 && e.matched_rules[1] == 0 &&
	       e.matched_rules[2] == 0 && e.matched_rules[3] == 1ULL << 63);

	/* Path longer than 255 bytes (collector: length 0) and unknown. */
	known_facts();
	facts.target_path.length = 0;
	memset(facts.target_path.bytes, 'x', sizeof(facts.target_path.bytes));
	d = decision(1, 2, FE_OK);
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	assert(e.path_result == -1 && e.path[0] == 0 && e.path[255] == 0 &&
	       e.facts_unknown == SE_VERDICT_UNKNOWN_TARGET_PATH);
	facts.target_path.length = 256; /* malformed: never trusted */
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	assert(e.path_result == -1 && e.path[0] == 0);
	/* 255 bytes exactly: kept, NUL-terminated. */
	facts.target_path.length = 255;
	facts.target_path.bytes[0] = '/';
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	assert(e.path_result == 256 && e.path[0] == '/' && e.path[254] == 'x' &&
	       e.path[255] == 0);
	/* Bytes after the path's NUL are never past the path. */
	known_facts();
	facts.target_path.bytes[13] = 'Z';
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	path_known(&e);

	/* Each fact bit. */
	static const __u32 bits[] = {
		SE_VERDICT_UNKNOWN_UID,	       SE_VERDICT_UNKNOWN_ANCESTORS,
		SE_VERDICT_UNKNOWN_FS,	       SE_VERDICT_UNKNOWN_ARGV,
		SE_VERDICT_UNKNOWN_STDIN,      SE_VERDICT_UNKNOWN_STDIN,
		SE_VERDICT_UNKNOWN_ACTOR_PATH, SE_VERDICT_UNKNOWN_IMAGE,
		SE_VERDICT_UNKNOWN_IMAGE,
	};
	for (int i = 0; i < (int)(sizeof(bits) / sizeof(bits[0])); i++) {
		known_facts();
		switch (i) {
		case 0:
			facts.uid_known = 0;
			break;
		case 1:
			facts.ancestors_complete = 0;
			break;
		case 2:
			facts.fs_known &= ~FE_MEMFD;
			break;
		case 3:
			facts.argv_complete = 0;
			break;
		case 4:
			facts.stdin_pipe = -1;
			break;
		case 5:
			facts.stdin_pipe = 2;
			break;
		case 6:
			facts.actor_path.length = 0;
			break;
		case 7:
			facts.target_image = -1;
			break;
		default:
			facts.actor_image = -1;
		}
		d = decision(0, 2, FE_OK);
		e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
		assert(e.facts_unknown == bits[i]);
	}

	/* Faults (user decision D1): Strict deny=1 mode=2, Audit deny=1
	 * mode=1, error 1 both, no rules, every fact unknown without facts. */
	e = fill(0, 0, meta(2, SE_VERDICT_FAULT), 0);
	assert(e.deny && e.mode == 2 && e.error == FE_INVALID && !e.uncertain &&
	       !e.matched_rules[0] && !e.matched_rules[3] &&
	       e.path_result == -1 && e.path[0] == 0 &&
	       e.facts_unknown == SE_VERDICT_UNKNOWN_ALL &&
	       e.pass == SE_VERDICT_PASS_UNKNOWN);
	e = fill(0, 0, meta(1, SE_VERDICT_FAULT), 0);
	assert(e.deny && e.mode == 1 && e.error == FE_INVALID &&
	       e.exec_class == 1);
	/* A fault ignores a decision it is handed. */
	d = decision(0, 2, FE_OK);
	known_facts();
	e = fill(&facts, &d, meta(2, SE_VERDICT_FAULT), 0);
	assert(e.deny && e.mode == 2 && e.error == FE_INVALID &&
	       !e.matched_rules[0]);
	path_known(&e);
	/* A decision event without a decision: a fault, reported (-1). */
	e = fill(&facts, 0, meta(2, SE_VERDICT_DECISION), -1);
	assert(e.deny && e.mode == 2 && e.error == FE_INVALID);
	/* An unknown class is Strict's fail-closed mode. */
	e = fill(0, 0, meta(0, SE_VERDICT_FAULT), 0);
	assert(e.deny && e.mode == 2);

	/* A fault without a receipt: no exec identity (0). */
	struct se_verdict_meta orphan = meta(2, SE_VERDICT_FAULT);
	orphan.generation = orphan.scope = orphan.exec_id = 0;
	orphan.task_cookie = 0;
	e = fill(0, 0, orphan, 0);
	assert(!e.task_cookie && !e.exec_id && !e.scope && e.deny);
	/* The exec identity of a decision is the receipt's, both fields. */
	d = decision(0, 2, FE_OK);
	e = fill(&facts, &d, meta(2, SE_VERDICT_DECISION), 0);
	assert(e.task_cookie == 0x7700000001ULL && e.exec_id == 99);

	printf("verdict event contract: %d cases\n", cases);
	return 0;
}
