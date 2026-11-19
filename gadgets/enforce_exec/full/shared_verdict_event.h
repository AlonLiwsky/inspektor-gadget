/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_VERDICT_EVENT_H
#define ENFORCE_EXEC_SHARED_VERDICT_EVENT_H
/* G020 shared product verdict event (event ABI "1",
 * fullruntime/shared_verdict_events.go SharedEventABIVersion).
 *
 * One event per evaluated bprm_check pass (a decision), or per fail-closed
 * fault of the exec graph. The prefix up to error is the legacy struct event
 * of full/program.bpf.c byte for byte (names, offsets, sizes; pinned by
 * TestSharedVerdictEventLegacyPrefix); the additive fields follow in the
 * legacy struct's tail padding and beyond.
 *
 * Requires fullpolicy/bpf/evaluator.h (struct fe_facts, struct fe_decision,
 * FE_*). Pure: no helper, map or kernel type; the host contract is
 * fullruntime/testdata/shared_verdict_event.c. */

struct shared_verdict_event {
	__u64 generation, cgroup;
	__u32 deny, mode;
	__s32 path_result;
	__u32 host_pid;
	char path[256];
	__u64 matched_rules[4];
	__u32 error;
	/* Additive (G020). */
	__u32 exec_class; /* 1 Audit, 2 Strict: the binding's static class */
	__u64 scope; /* binding scope cookie of the exec's receipt */
	__u64 exec_id; /* receipt invocation: equal across one exec's passes,
			* a per-TASK sequence (task_cookie qualifies it) */
	__u32 pass; /* 0..5, SE_VERDICT_PASS_UNKNOWN for a fault */
	__u32 uncertain; /* the verdict rests on an UNKNOWN fact */
	__u32 facts_unknown; /* SE_VERDICT_UNKNOWN_* bits */
	/* The exec'ing TASK's identity cookie (receipt cookie; node-wide
	 * sequence of the loaded collection). (task_cookie, exec_id) is unique
	 * per node; host_pid is informational. 0 without a receipt. */
	__u64 task_cookie;
	/* The collection load's epoch (se_verdict_load_epoch): task_cookie
	 * restarts per load, so (load_epoch, task_cookie, exec_id) is the
	 * event key across reloads (review M7). */
	__u64 load_epoch;
};
_Static_assert(__builtin_offsetof(struct shared_verdict_event, path) == 32,
	       "legacy event prefix");
_Static_assert(__builtin_offsetof(struct shared_verdict_event, matched_rules) ==
		       288,
	       "legacy event prefix");
_Static_assert(__builtin_offsetof(struct shared_verdict_event, error) == 320,
	       "legacy event prefix");
_Static_assert(__builtin_offsetof(struct shared_verdict_event, exec_class) ==
		       324,
	       "additive fields start in the legacy tail padding");
_Static_assert(__builtin_offsetof(struct shared_verdict_event, scope) == 328,
	       "verdict event ABI 1");
_Static_assert(__builtin_offsetof(struct shared_verdict_event, facts_unknown) ==
		       352,
	       "verdict event ABI 1");
_Static_assert(__builtin_offsetof(struct shared_verdict_event, task_cookie) ==
		       360,
	       "verdict event ABI 1");
_Static_assert(__builtin_offsetof(struct shared_verdict_event, load_epoch) ==
		       368,
	       "verdict event ABI 1");
_Static_assert(sizeof(struct shared_verdict_event) == 376,
	       "verdict event ABI 1");

/* Per-load epoch: a read-only constant the agent sets to a random nonzero
 * value before every collection load (fullruntime/kernel_matrix.go
 * sharedImageOverlayConstants, operators.NativeConstantsKey; product
 * admission requires it). 0 only in an object loaded without it. */
#ifndef SE_VERDICT_LOAD_EPOCH_INIT
#define SE_VERDICT_LOAD_EPOCH_INIT 0 /* the host contract sets its own */
#endif
const volatile __u64 se_verdict_load_epoch = SE_VERDICT_LOAD_EPOCH_INIT;

/* facts_unknown bits (fullruntime SharedVerdictUnknown*). */
#define SE_VERDICT_UNKNOWN_TARGET_PATH 0x01U
#define SE_VERDICT_UNKNOWN_UID 0x02U
#define SE_VERDICT_UNKNOWN_ANCESTORS 0x04U
#define SE_VERDICT_UNKNOWN_FS 0x08U
#define SE_VERDICT_UNKNOWN_ARGV 0x10U
#define SE_VERDICT_UNKNOWN_STDIN 0x20U
#define SE_VERDICT_UNKNOWN_ACTOR_PATH 0x40U
#define SE_VERDICT_UNKNOWN_IMAGE 0x80U
#define SE_VERDICT_UNKNOWN_ALL 0xffU
#define SE_VERDICT_FS_ALL (FE_TMPFS | FE_MEMFD | FE_DELETED | FE_OVERLAY)
#define SE_VERDICT_PASS_UNKNOWN 0xffffffffU

/* Event kinds of struct se_verdict_meta. */
#define SE_VERDICT_DECISION 0U
#define SE_VERDICT_FAULT 1U

/* What the caller knows beyond the facts and the decision. */
struct se_verdict_meta {
	__u64 generation, cgroup, scope, exec_id, task_cookie;
	__u32 host_pid, exec_class, pass, kind;
};

/* The facts_unknown bitmask of facts (all bits without facts). */
static __attribute__((always_inline)) inline __u32
se_verdict_facts_unknown(const struct fe_facts *f)
{
	if (!f)
		return SE_VERDICT_UNKNOWN_ALL;
	__u32 unknown = 0;
	if (!f->target_path.length || f->target_path.length > 255)
		unknown |= SE_VERDICT_UNKNOWN_TARGET_PATH;
	if (!f->uid_known)
		unknown |= SE_VERDICT_UNKNOWN_UID;
	if (!f->ancestors_complete)
		unknown |= SE_VERDICT_UNKNOWN_ANCESTORS;
	if ((f->fs_known & SE_VERDICT_FS_ALL) != SE_VERDICT_FS_ALL)
		unknown |= SE_VERDICT_UNKNOWN_FS;
	if (!f->argv_complete)
		unknown |= SE_VERDICT_UNKNOWN_ARGV;
	if (f->stdin_pipe < 0 || f->stdin_pipe > 1)
		unknown |= SE_VERDICT_UNKNOWN_STDIN;
	if (!f->actor_path.length || f->actor_path.length > 255)
		unknown |= SE_VERDICT_UNKNOWN_ACTOR_PATH;
	if (f->target_image < 0 || f->actor_image < 0)
		unknown |= SE_VERDICT_UNKNOWN_IMAGE;
	return unknown;
}

/* Fills every byte of e. The verdict is the caller's, computed before the
 * event exists; the event only reports it:
 *   decision, error FE_OK: deny and mode of the decision (mode 1 in an
 *     Audit class: nothing is enforced there);
 *   decision, error FE_AUDIT_UNKNOWN: the same, error 0 and uncertain set;
 *   decision, error FE_INVALID..FE_ROLE_CONFLICT: the fail-closed class
 *     verdict, deny 1 and mode = class (Strict denies, Audit would deny),
 *     with that error (uncertain for FE_UNKNOWN);
 *   decision with any other error: as FE_INVALID;
 *   fault (and a decision without one: returns -1): deny 1, mode = class,
 *     error 1 (FE_INVALID), no matched rules (user decision D1).
 * So (deny && mode == 2) is exactly the LSM denial of a Strict class, and
 * error is always 0..3. */
static __attribute__((always_inline)) inline int
se_verdict_event_fill(struct shared_verdict_event *e, const struct fe_facts *f,
		      const struct fe_decision *d,
		      const struct se_verdict_meta *m)
{
	__builtin_memset(e, 0, sizeof(*e));
	__u32 class_mode = m->exec_class == 1 ? 1 : 2;
	e->generation = m->generation;
	e->cgroup = m->cgroup;
	e->host_pid = m->host_pid;
	e->exec_class = m->exec_class;
	e->scope = m->scope;
	e->exec_id = m->exec_id;
	e->task_cookie = m->task_cookie;
	e->load_epoch = se_verdict_load_epoch;
	e->pass = m->pass;
	e->facts_unknown = se_verdict_facts_unknown(f);
	e->path_result = -1;
	if (f && !(e->facts_unknown & SE_VERDICT_UNKNOWN_TARGET_PATH)) {
		__u32 length = f->target_path.length;
		__builtin_memcpy(e->path, f->target_path.bytes,
				 sizeof(e->path));
		if (length < sizeof(e->path))
			e->path[length] = 0;
		e->path_result = (__s32)length + 1;
	}
	if (m->kind != SE_VERDICT_DECISION || !d) {
		e->deny = 1;
		e->mode = class_mode;
		e->error = FE_INVALID;
		return m->kind == SE_VERDICT_DECISION ? -1 : 0;
	}
	__builtin_memcpy(e->matched_rules, d->matched_rules,
			 sizeof(e->matched_rules));
	__u32 error = d->error;
	if (error == FE_OK || error == FE_AUDIT_UNKNOWN) {
		e->deny = d->deny ? 1 : 0;
		e->mode = class_mode == 2 && d->mode == 2 ? 2 : 1;
		e->uncertain = error == FE_AUDIT_UNKNOWN || d->audit_unknown;
		return 0;
	}
	e->deny = 1;
	e->mode = class_mode;
	e->error = error <= FE_ROLE_CONFLICT ? error : FE_INVALID;
	e->uncertain = error == FE_UNKNOWN;
	return 0;
}
#endif
