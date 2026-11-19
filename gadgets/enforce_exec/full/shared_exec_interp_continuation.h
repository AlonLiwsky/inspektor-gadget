/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_EXEC_INTERP_CONTINUATION_H
#define ENFORCE_EXEC_SHARED_EXEC_INTERP_CONTINUATION_H
/* G019 gap 4 (review H1): the same-bprm script-interpreter continuation.
 *
 * One bprm_execve runs one security_bprm_creds_for_exec and then one
 * search_binary_handler -> security_bprm_check pass per binfmt rewrite:
 * exec_binprm loops depth 0..5 and returns -ELOOP at depth 6 before a
 * seventh pass (fs/exec.c, 6.12 and 6.18). A #! script (binfmt_script) or a
 * binfmt_misc entry sets bprm->interpreter and the next pass checks the
 * interpreter's file with the SAME bprm. Every pass evaluates policy for its
 * own bprm->file; a deny at any pass ends the exec (Strict EPERM, Audit
 * records and allows); every pass's role proposal accumulates into the ONE
 * TASK exec transaction that the exec terminal commits once.
 *
 * Pass 0 is the ordinary reader: it registers the terminal receipt and
 * leaves its proposed evaluation WORK suspended at the terminal stage 3.
 * Pass p >= 1 (the "later" admission of the same physical exec: the
 * capsule's frozen class, SE_CAP_LATER) finds that REGISTERED receipt. These
 * pure predicates decide, in their own frames, whether it is a continuation
 * candidate and whether the resumed WORK is exactly the receipt's proposed
 * terminal WORK. They grant nothing: the continuation program still
 * authenticates the failure frames, classifies and recovers the original
 * reader, and resumes the WORK under exact lexical authority. Any refusal
 * is fail-closed (Strict denies, Audit allows and quarantines) and counted
 * as an interpreter continuation refusal (fail-closed rate GAP [9]). */

/* real_owner_pending_class results. */
#define SE_EXEC_PENDING_NONE 0
#define SE_EXEC_PENDING_RECEIPT 1 /* today's pending quarantine (PENDING [7]) */
#define SE_EXEC_PENDING_CONTINUE 2 /* same-exec interpreter pass candidate */

/* opaque_real_interp_stats cells: continued passes by depth 1..5, then the
 * refusal reasons. Each refusal also counts one GAP [9]. */
#define SE_INTERP_STAT_CONTINUED_FIRST 0 /* + depth - 1, depth 1..5 */
#define SE_INTERP_STAT_FRAME 5 /* receipt/failure-frame tuple mismatch */
#define SE_INTERP_STAT_CLASSIFY 6 /* reader not CONTINUE, or class mismatch */
#define SE_INTERP_STAT_RECOVER 7 /* reader recovery or pinned snapshot */
#define SE_INTERP_STAT_RESUME 8 /* no exact suspended terminal WORK */
#define SE_INTERP_STAT_GRAPH_MISS 9 /* continue/prepare tail call returned */
#define SE_INTERP_STAT_DEPTH 10 /* a pass beyond SE_OWK_EXEC_PASSES - 1 */
#define SE_INTERP_STAT_REBIND 11 /* WORK rebind, suspend or TASK close */
#define SE_INTERP_STATS 12

/* Lock-free classification of the current task's receipt at an OWNED
 * admission. A continuation candidate requires the later-admission bit and
 * an exact REGISTERED receipt of this physical task and this bprm with every
 * identity field nonzero. Anything else that exists is pending: a stale
 * receipt at the same bprm address of an earlier exec reaches only a first
 * admission (no SE_CAP_LATER) and stays pending. */
static __attribute__((always_inline)) inline int
se_exec_receipt_pending_class(const struct se_exec_terminal_receipt *receipt,
			      __u64 physical, __u64 bprm, __u32 later)
{
	if (!receipt)
		return SE_EXEC_PENDING_NONE;
	return later && physical && bprm &&
			       receipt->phase == SE_EXEC_TERMINAL_REGISTERED &&
			       receipt->physical == physical &&
			       receipt->bprm == bprm && !receipt->reserved &&
			       receipt->cookie && receipt->locator &&
			       receipt->invocation && receipt->scope &&
			       receipt->generation ?
		       SE_EXEC_PENDING_CONTINUE :
		       SE_EXEC_PENDING_RECEIPT;
}

/* The pass of a continuation whose WORK was resumed at a terminal-class
 * stage: pass p resumes stage 3p, the previous pass's terminal stage.
 * Returns 1..SE_OWK_EXEC_PASSES - 1, or 0 for a stage that no admissible
 * pass can follow (beyond the exec_binprm depth bound, or not terminal). */
static __attribute__((always_inline)) inline __u32
se_exec_continue_pass(__u32 stage, __u32 passes)
{
	if (!stage || stage % 3U || passes < 2)
		return 0;
	__u32 pass = stage / 3U;
	return pass && pass < passes ? pass : 0;
}

/* Failure-frame authentication of a later pass (needs the
 * ENFORCE_EXEC_POOL_OPAQUE_FAILURE_FINAL_RETURN_PROBE frame types). The
 * outer exec frame is still the only one (depth 1, certain) and was bound
 * to exactly this receipt by pass 0; the handler frame is this pass's own
 * search_binary_handler entry (or the one exec_binprm entry) for the same
 * bprm. */
#define SE_EXEC_CONTINUE_FRAMES_EXACT(rcpt, outer_, handler_, key_, bprm_) \
	((rcpt) && (outer_) && (handler_) && (key_) && (bprm_) &&          \
	 (outer_)->physical == (key_) && (outer_)->depth == 1 &&           \
	 !(outer_)->uncertain && (outer_)->bprm == (bprm_) &&              \
	 (rcpt)->physical == (key_) && (rcpt)->bprm == (bprm_) &&          \
	 (outer_)->cookie == (rcpt)->cookie &&                             \
	 (outer_)->locator == (rcpt)->locator &&                           \
	 (outer_)->invocation == (rcpt)->invocation &&                     \
	 (outer_)->scope == (rcpt)->scope &&                               \
	 (outer_)->generation == (rcpt)->generation && (outer_)->cookie && \
	 (outer_)->locator && (outer_)->invocation && (outer_)->scope &&   \
	 (outer_)->generation && (handler_)->bprm == (bprm_) &&            \
	 (handler_)->depth == 1 && !(handler_)->uncertain)

#ifdef ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_PROPOSE_CANDIDATE_H
/* The resumed current WORK is exactly the receipt's proposed terminal WORK
 * of the frozen class: its last proposal consumed a FINISHED evaluation of
 * this exec transaction (bprm, invocation, generation) of this TASK and
 * scope. A WORK of another exec, an unproposed evaluation, or a WORK of the
 * other class is refused. */
static __attribute__((always_inline)) inline int
se_exec_continue_work_exact(const struct se_invocation *work,
			    const struct se_exec_terminal_receipt *receipt,
			    __u32 mode)
{
	return work && receipt && (mode == 1 || mode == 2) &&
	       work->scope == receipt->scope &&
	       work->observation.stage_cursor.state ==
		       SE_OWK_PROPOSAL_CONSUMED &&
	       work->view.header.generation == receipt->generation &&
	       !work->history.reserved &&
	       work->history.physical_cookie == receipt->cookie &&
	       work->history.scope_cookie == receipt->scope &&
	       work->history.transaction.owned &&
	       work->history.transaction.bprm == receipt->bprm &&
	       work->history.transaction.sequence == receipt->invocation &&
	       work->history.transaction.generation == receipt->generation &&
	       work->history.transaction.execution_class == mode;
}
#endif
#endif
