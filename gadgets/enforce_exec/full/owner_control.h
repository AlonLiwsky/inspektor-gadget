/* SPDX-License-Identifier: GPL-2.0 */
/* Persistent-owner commands. Native owns proc/cgroup pins, frozen admin nonce,
 * closed/drained admission and the two-phase map publication transaction. */
#ifndef FULL_OWNER_CONTROL_H
#define FULL_OWNER_CONTROL_H
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* EO_DISPATCH_TRANSITIONS_BEGIN */
/* These shared transitions require the caller's dispatch_lock. They contain no
 * map lookup, allocation or task locking; storage I/O spans an owned token. */
static __always_inline int eo_dispatch_open_locked(struct eo_dispatch *s,
						   __u64 cookie, __u64 cgroup)
{
	if (!cookie || !cgroup)
		return -1;
	if (s->scope_state)
		return (s->scope_state == EO_SCOPE_INACTIVE ||
			s->scope_state == EO_SCOPE_ACTIVE) &&
				       s->session_cookie == cookie &&
				       s->cgroup == cgroup ?
			       0 :
			       -1;
	/* Fresh ARRAY value only; no reset/reopen of a previous lifetime. */
	if (s->session_cookie || s->cgroup || s->serial || s->last_attempt ||
	    s->active.generation || s->candidate.state || s->integrity_fault)
		return -1;
	s->session_cookie = cookie;
	s->cgroup = cgroup;
	s->serial = 1;
	s->scope_state = EO_SCOPE_INACTIVE;
	return 0;
}
static __always_inline int
eo_dispatch_same(const struct eo_dispatch_descriptor *a,
		 const struct eo_dispatch_descriptor *b)
{
	return a->generation == b->generation &&
	       a->execution_class == b->execution_class &&
	       a->program_bank == b->program_bank && !a->history_reserved &&
	       !b->history_reserved && !a->reserved && !b->reserved &&
	       a->policy_count == b->policy_count &&
	       a->role_writer_mask == b->role_writer_mask;
}
static __always_inline int eo_candidate_owned(const struct eo_dispatch *s,
					      __u64 cookie, __u64 attempt)
{
	return (s->scope_state == EO_SCOPE_INACTIVE ||
		s->scope_state == EO_SCOPE_ACTIVE) &&
	       !s->active.history_reserved && !s->candidate.history_reserved &&
	       cookie && cookie == s->session_cookie && attempt &&
	       attempt == s->candidate.attempt;
}
static __always_inline int eo_dispatch_idle(const struct eo_dispatch *s)
{
	return !s->exec_inflight && !s->fork_inflight && !s->ingress_inflight &&
	       !s->mutation_writers && !s->authority_readers &&
	       !s->bank_readers[0] && !s->bank_readers[1] &&
	       !s->candidate.writers;
}
static __always_inline int eo_candidate_begin_locked(struct eo_dispatch *s,
						     __u64 cookie,
						     __u64 attempt,
						     __u32 entries)
{
	if ((s->scope_state != EO_SCOPE_INACTIVE &&
	     s->scope_state != EO_SCOPE_ACTIVE) ||
	    cookie != s->session_cookie || !cookie || !attempt ||
	    attempt == ~0ULL || attempt <= s->last_attempt || !entries ||
	    entries > 16384 || s->active.program_bank > 1 ||
	    s->active.history_reserved != 0 || s->candidate.writers ||
	    (s->candidate.state != EO_CANDIDATE_NONE &&
	     s->candidate.state != EO_CANDIDATE_ABORTED &&
	     s->candidate.state != EO_CANDIDATE_COMMITTED))
		return -1;
	__u32 bank = s->active.program_bank ^ 1;
	if (s->bank_readers[bank])
		return -1;
	s->candidate = (struct eo_candidate){ .attempt = attempt,
					      .expected = s->active,
					      .state = EO_CANDIDATE_LOADING,
					      .program_bank = bank,
					      .history_reserved = 0,
					      .entries = entries };
	s->last_attempt = attempt;
	return 0;
}
static __always_inline int
eo_candidate_write_begin_locked(struct eo_dispatch *s, __u64 cookie,
				__u64 attempt, __u32 bank,
				struct eo_writer_token *token)
{
	if (token->owned || !eo_candidate_owned(s, cookie, attempt) ||
	    s->candidate.state != EO_CANDIDATE_LOADING ||
	    bank != s->candidate.program_bank || bank > 1 ||
	    bank == s->active.program_bank || s->bank_readers[bank] ||
	    s->candidate.writers || s->candidate.write_sequence == ~0ULL)
		return -1;
	s->candidate.writers = 1;
	s->candidate.write_sequence++;
	*token = (struct eo_writer_token){ cookie, attempt,
					   s->candidate.write_sequence, bank,
					   1 };
	return 0;
}
static __always_inline int
eo_candidate_write_end_locked(struct eo_dispatch *s,
			      struct eo_writer_token *token)
{
	if (!token->owned ||
	    !eo_candidate_owned(s, token->session_cookie, token->attempt) ||
	    token->bank != s->candidate.program_bank ||
	    s->candidate.writers != 1 ||
	    token->sequence != s->candidate.write_sequence)
		return -1;
	s->candidate.writers--;
	token->owned = 0;
	return 0;
}
static __always_inline int eo_candidate_seal_begin_locked(struct eo_dispatch *s,
							  __u64 cookie,
							  __u64 attempt)
{
	if (!eo_candidate_owned(s, cookie, attempt) ||
	    s->candidate.state != EO_CANDIDATE_LOADING || s->candidate.writers)
		return -1;
	s->candidate.state = EO_CANDIDATE_SEALING;
	return 0;
}
static __always_inline int
eo_candidate_seal_finish_locked(struct eo_dispatch *s, __u64 cookie,
				__u64 attempt, __u32 execution_class,
				__u32 policy_count, __u32 role_writer_mask,
				__u32 required_known_mask, int complete)
{
	if (!eo_candidate_owned(s, cookie, attempt) ||
	    s->candidate.state != EO_CANDIDATE_SEALING || s->candidate.writers)
		return -1;
	if (!complete || execution_class < 1 || execution_class > 2 ||
	    !policy_count || policy_count > 8 ||
	    ((role_writer_mask | required_known_mask) >> policy_count)) {
		s->candidate.state = EO_CANDIDATE_ABORTED;
		return -1;
	}
	s->candidate.sealed_class = execution_class;
	s->candidate.sealed_policy_count = policy_count;
	s->candidate.sealed_role_writer_mask = role_writer_mask;
	s->candidate.required_known_mask = required_known_mask;
	s->candidate.state = EO_CANDIDATE_SEALED;
	return 0;
}
static __always_inline int
eo_candidate_abort_locked(struct eo_dispatch *s, __u64 cookie, __u64 attempt)
{
	if (!eo_candidate_owned(s, cookie, attempt) ||
	    s->candidate.state == EO_CANDIDATE_COMMITTED ||
	    s->candidate.state == EO_CANDIDATE_SEALING ||
	    s->candidate.writers || s->candidate.program_bank > 1 ||
	    s->bank_readers[s->candidate.program_bank])
		return -1;
	s->candidate.state = EO_CANDIDATE_ABORTED;
	s->candidate.receipt_serial = 0;
	return 0;
}
static __always_inline int
eo_dispatch_read_begin_locked(struct eo_dispatch *s,
			      struct eo_dispatch_token *token)
{
	if (s->scope_state != EO_SCOPE_ACTIVE || !s->session_cookie ||
	    token->owned || s->active.program_bank > 1 ||
	    s->active.history_reserved != 0 || s->active.execution_class < 1 ||
	    s->active.execution_class > 2 || !s->serial || s->serial == ~0ULL ||
	    s->authority_readers == ~0ULL ||
	    s->bank_readers[s->active.program_bank] == ~0ULL)
		return -1;
	s->serial++;
	s->authority_readers++;
	s->bank_readers[s->active.program_bank]++;
	*token = (struct eo_dispatch_token){ s->session_cookie,
					     s->active.generation,
					     s->active.program_bank, 1 };
	return 0;
}
static __always_inline int
eo_dispatch_read_end_locked(struct eo_dispatch *s,
			    struct eo_dispatch_token *token)
{
	if (!token->owned || token->session_cookie != s->session_cookie ||
	    token->bank > 1 || !s->authority_readers ||
	    !s->bank_readers[token->bank])
		return -1;
	s->authority_readers--;
	s->bank_readers[token->bank]--;
	token->owned = 0;
	return 0;
}
static __always_inline int
eo_candidate_snapshot_locked(struct eo_dispatch *s, __u64 cookie, __u64 attempt)
{
	if (!eo_candidate_owned(s, cookie, attempt) || !eo_dispatch_idle(s) ||
	    (s->candidate.state != EO_CANDIDATE_SEALED &&
	     s->candidate.state != EO_CANDIDATE_STAGING &&
	     s->candidate.state != EO_CANDIDATE_CERTIFIED) ||
	    !eo_dispatch_same(&s->active, &s->candidate.expected) ||
	    !s->serial || s->serial == ~0ULL || s->integrity_fault ||
	    s->candidate.pass_id >= ~0ULL - 1)
		return -1;
	s->candidate.pass_id++;
	s->candidate.pass_start_serial = s->serial;
	s->candidate.receipt_serial = s->serial;
	s->candidate.inventory_count = 0;
	s->candidate.certified_known_mask = 0;
	s->candidate.state = EO_CANDIDATE_STAGING;
	return 0;
}
static __always_inline int
eo_candidate_certify_locked(struct eo_dispatch *s, __u64 cookie, __u64 attempt,
			    __u64 inventory_count, __u32 known_mask)
{
	if (!eo_candidate_owned(s, cookie, attempt) ||
	    s->candidate.state != EO_CANDIDATE_STAGING ||
	    !eo_dispatch_idle(s) ||
	    !eo_dispatch_same(&s->active, &s->candidate.expected) ||
	    s->candidate.receipt_serial != s->serial || s->integrity_fault ||
	    !inventory_count || inventory_count > 4096 ||
	    inventory_count != s->candidate.inventory_count ||
	    (known_mask & ~255U) ||
	    (s->candidate.required_known_mask & ~255U) ||
	    (s->candidate.sealed_class == 2 &&
	     (s->coverage_unknown ||
	      (s->candidate.required_known_mask & ~known_mask))))
		return -1;
	s->candidate.inventory_count = inventory_count;
	s->candidate.certified_known_mask = known_mask;
	s->candidate.state = EO_CANDIDATE_CERTIFIED;
	return 0;
}
/* Called only from the authenticated successful-live-return cgroup mutex hook.
 * Every pointer must be prelooked-up while candidate ownership excludes reuse.
 * The entire validation precedes the first epoch store; there are no helpers,
 * allocations, task locks or fallible checks in the irreversible sequence. */
static __always_inline int eo_candidate_arm_locked(struct eo_dispatch *s,
						   __u64 cookie, __u64 attempt,
						   __u64 *targets[8])
{
	if (!eo_candidate_owned(s, cookie, attempt))
		return -1;
	if (s->candidate.state == EO_CANDIDATE_COMMITTED) {
		const struct eo_dispatch_descriptor committed = {
			.generation = attempt,
			.execution_class = s->candidate.sealed_class,
			.program_bank = s->candidate.program_bank,
			.history_reserved = s->candidate.history_reserved,
			.policy_count = s->candidate.sealed_policy_count,
			.role_writer_mask = s->candidate.sealed_role_writer_mask
		};
		return eo_dispatch_same(&s->active, &committed) ? 0 : -1;
	}
	struct eo_candidate *c = &s->candidate;
	if (c->state != EO_CANDIDATE_CERTIFIED || !eo_dispatch_idle(s) ||
	    !eo_dispatch_same(&s->active, &c->expected) ||
	    c->receipt_serial != s->serial || !s->serial ||
	    s->serial == ~0ULL || s->integrity_fault || !c->inventory_count ||
	    c->program_bank > 1 || c->history_reserved != 0 ||
	    c->program_bank == s->active.program_bank ||
	    s->active.history_reserved || c->sealed_class < 1 ||
	    c->sealed_class > 2 || !c->sealed_policy_count ||
	    c->sealed_policy_count > 8 ||
	    (c->sealed_role_writer_mask >> c->sealed_policy_count) ||
	    c->addition_count > 8 || (c->required_known_mask & ~255U) ||
	    (c->certified_known_mask & ~255U) ||
	    (c->sealed_class == 2 &&
	     (s->coverage_unknown ||
	      (c->required_known_mask & ~c->certified_known_mask))))
		return -1;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= c->addition_count)
			break;
		if (!targets[i] || *targets[i] || !c->additions[i].uid ||
		    c->additions[i].epoch != attempt)
			return -1;
		for (__u32 j = 0; j < 8; j++)
			if (j < i &&
			    (targets[j] == targets[i] ||
			     c->additions[j].uid == c->additions[i].uid))
				return -1;
	}
	/* EO_ARM_IRREVERSIBLE_BEGIN */
	if (c->addition_count > 0)
		*targets[0] = c->additions[0].epoch;
	if (c->addition_count > 1)
		*targets[1] = c->additions[1].epoch;
	if (c->addition_count > 2)
		*targets[2] = c->additions[2].epoch;
	if (c->addition_count > 3)
		*targets[3] = c->additions[3].epoch;
	if (c->addition_count > 4)
		*targets[4] = c->additions[4].epoch;
	if (c->addition_count > 5)
		*targets[5] = c->additions[5].epoch;
	if (c->addition_count > 6)
		*targets[6] = c->additions[6].epoch;
	if (c->addition_count > 7)
		*targets[7] = c->additions[7].epoch;
	s->active = (struct eo_dispatch_descriptor){
		.generation = attempt,
		.execution_class = c->sealed_class,
		.program_bank = c->program_bank,
		.history_reserved = c->history_reserved,
		.policy_count = c->sealed_policy_count,
		.role_writer_mask = c->sealed_role_writer_mask
	};
	s->scope_state = EO_SCOPE_ACTIVE;
	c->state = EO_CANDIDATE_COMMITTED;
	s->serial++;
	/* EO_ARM_IRREVERSIBLE_END */
	return 0;
}

/* The cell pointer is prelooked-up. The sole authenticated admin command owns
 * this writer claim until AFTER the final data/stamp store, then releases once. */
static __always_inline int eo_candidate_write_cell(
	struct eo_dispatch *s, const struct eo_candidate_request *input,
	const unsigned char data[288], struct eo_program_cell *cell)
{
	struct eo_candidate_request request = *input;
	struct eo_writer_token token = {};
	int refused;
	bpf_spin_lock(&s->lock);
	refused = request.reserved || request.index >= 16384 ||
		  eo_candidate_write_begin_locked(s, request.session_cookie,
						  request.attempt, request.bank,
						  &token);
	bpf_spin_unlock(&s->lock);
	if (refused)
		return -1;
	__builtin_memcpy(cell->data, data, sizeof(cell->data));
	cell->attempt = request.attempt;
	bpf_spin_lock(&s->lock);
	refused = eo_candidate_write_end_locked(s, &token);
	bpf_spin_unlock(&s->lock);
	return refused;
}
/* Counter operations use a private invocation claim. Completion must first
 * consume the persistent task/work record using eo_reader_take_locked; copying
 * an external completion identity never copies that authoritative record. */
static __always_inline __u64 *eo_claim_counter(struct eo_dispatch *s,
					       __u32 kind)
{
	if (kind == EO_READER_AUTHORITY || kind == EO_READER_CANDIDATE)
		return &s->authority_readers;
	if (kind == EO_READER_EXEC)
		return &s->exec_inflight;
	if (kind == EO_READER_FORK)
		return &s->fork_inflight;
	if (kind == EO_READER_INGRESS)
		return &s->ingress_inflight;
	if (kind == EO_READER_MUTATION)
		return &s->mutation_writers;
	return 0;
}
static __always_inline int
eo_dispatch_claim_begin_locked(struct eo_dispatch *s,
			       struct eo_reader_claim *local, __u64 sequence,
			       __u32 kind)
{
	if (local->owned || s->scope_state != EO_SCOPE_ACTIVE ||
	    !s->session_cookie || !s->active.generation || s->active.reserved ||
	    s->active.program_bank > 1 || s->active.history_reserved != 0 ||
	    s->active.execution_class < 1 || s->active.execution_class > 2 ||
	    !s->active.policy_count || s->active.policy_count > 8 ||
	    (s->active.role_writer_mask >> s->active.policy_count))
		return -1;
	// Coherent class is available even when the following admission accounting
	// refuses. No task, scratch or other observer allocation precedes this latch.
	*local = (struct eo_reader_claim){ .descriptor = s->active,
					   .session_cookie = s->session_cookie,
					   .sequence = sequence,
					   .kind = kind };
	__u64 *count = eo_claim_counter(s, kind);
	if (!count || !sequence || sequence == ~0ULL || !s->serial ||
	    s->serial == ~0ULL || s->integrity_fault || *count == ~0ULL ||
	    s->bank_readers[s->active.program_bank] == ~0ULL) {
		s->coverage_unknown = 1;
		if (s->serial && s->serial < ~0ULL)
			s->serial++;
		else
			s->integrity_fault |= 1;
		return -1;
	}
	s->serial++;
	(*count)++;
	s->bank_readers[s->active.program_bank]++;
	local->owned = 1;
	return 0;
}
/* task_lock (or exclusive admin work ownership) protects record. No dispatch
 * lock is held here. Claim is transferred exactly once before counter refund. */
static __always_inline int eo_reader_take_locked(struct eo_reader_claim *record,
						 __u64 task_cookie,
						 __u64 expected_cookie,
						 __u64 sequence,
						 struct eo_reader_claim *local)
{
	if (local->owned || !task_cookie || task_cookie != expected_cookie ||
	    !sequence || record->sequence != sequence || record->owned != 1)
		return -1;
	*local = *record;
	record->owned = 0;
	return 0;
}
static __always_inline int
eo_dispatch_claim_end_locked(struct eo_dispatch *s,
			     struct eo_reader_claim *local)
{
	__u64 *count = eo_claim_counter(s, local->kind);
	if (!count || local->owned != 1 || local->descriptor.history_reserved ||
	    local->session_cookie != s->session_cookie ||
	    (local->kind == EO_READER_CANDIDATE ?
		     (s->candidate.state != EO_CANDIDATE_SEALING ||
		      local->descriptor.generation != s->candidate.attempt ||
		      local->descriptor.program_bank !=
			      s->candidate.program_bank ||
		      local->descriptor.history_reserved !=
			      s->candidate.history_reserved) :
		     !eo_dispatch_same(&local->descriptor, &s->active)) ||
	    local->descriptor.program_bank > 1 || !*count ||
	    !s->bank_readers[local->descriptor.program_bank])
		return -1;
	(*count)--;
	s->bank_readers[local->descriptor.program_bank]--;
	local->owned = 0;
	return 0;
}
static __always_inline int
eo_candidate_scan_begin_locked(struct eo_dispatch *s, __u64 cookie,
			       __u64 attempt, struct eo_reader_claim *claim)
{
	if (claim->owned || !eo_candidate_owned(s, cookie, attempt) ||
	    s->candidate.program_bank > 1 ||
	    s->candidate.history_reserved != 0 ||
	    s->candidate.program_bank == s->active.program_bank || !s->serial ||
	    s->serial == ~0ULL || s->authority_readers == ~0ULL ||
	    s->bank_readers[s->candidate.program_bank] == ~0ULL ||
	    eo_candidate_seal_begin_locked(s, cookie, attempt))
		return -1;
	s->serial++;
	s->authority_readers++;
	s->bank_readers[s->candidate.program_bank]++;
	*claim = (struct eo_reader_claim){
		.session_cookie = cookie,
		.sequence = attempt,
		.owned = 1,
		.kind = EO_READER_CANDIDATE,
		.descriptor = { .generation = attempt,
				.program_bank = s->candidate.program_bank,
				.history_reserved =
					s->candidate.history_reserved }
	};
	return 0;
}
/* Admin task staging owns both physical banks until the final task store.
 * The exclusive writer sequence authenticates refund even after copied-token replay.
 * Ordinary admissions remain open and invalidate the snapshot serial. */
static __always_inline int
eo_candidate_stage_begin_locked(struct eo_dispatch *s, __u64 cookie,
				__u64 attempt, struct eo_writer_token *writer,
				struct eo_reader_claim *reader,
				struct eo_dispatch_descriptor *source)
{
	if (writer->owned || reader->owned ||
	    !eo_candidate_owned(s, cookie, attempt) ||
	    s->candidate.state != EO_CANDIDATE_STAGING ||
	    !eo_dispatch_same(&s->active, &s->candidate.expected) ||
	    s->candidate.receipt_serial != s->serial || !s->candidate.pass_id ||
	    !s->candidate.pass_start_serial || !s->serial ||
	    s->serial >= ~0ULL - 1 || s->integrity_fault ||
	    s->candidate.writers || s->candidate.write_sequence == ~0ULL ||
	    s->active.program_bank > 1 || s->active.history_reserved != 0 ||
	    s->candidate.program_bank > 1 ||
	    s->candidate.history_reserved != 0 ||
	    s->candidate.program_bank == s->active.program_bank ||
	    s->bank_readers[s->candidate.program_bank] ||
	    s->bank_readers[s->active.program_bank] == ~0ULL ||
	    s->mutation_writers == ~0ULL || s->authority_readers == ~0ULL)
		return -1;
	s->serial++;
	s->candidate.receipt_serial = s->serial;
	s->candidate.write_sequence++;
	s->candidate.writers = 1;
	s->mutation_writers++;
	s->authority_readers++;
	s->bank_readers[s->active.program_bank]++;
	s->bank_readers[s->candidate.program_bank]++;
	*source = s->active;
	*writer = (struct eo_writer_token){ cookie, attempt,
					    s->candidate.write_sequence,
					    s->candidate.program_bank, 1 };
	*reader = (struct eo_reader_claim){
		.session_cookie = cookie,
		.sequence = s->candidate.write_sequence,
		.owned = 1,
		.kind = EO_READER_CANDIDATE,
		.descriptor = { .generation = attempt,
				.execution_class = s->candidate.sealed_class,
				.program_bank = s->candidate.program_bank,
				.history_reserved =
					s->candidate.history_reserved,
				.policy_count =
					s->candidate.sealed_policy_count,
				.role_writer_mask =
					s->candidate.sealed_role_writer_mask }
	};
	return 0;
}
static __always_inline int
eo_candidate_stage_end_locked(struct eo_dispatch *s,
			      struct eo_writer_token *writer,
			      struct eo_reader_claim *reader,
			      const struct eo_dispatch_descriptor *source)
{
	if (writer->owned != 1 || reader->owned != 1 ||
	    !eo_candidate_owned(s, writer->session_cookie, writer->attempt) ||
	    s->candidate.state != EO_CANDIDATE_STAGING ||
	    s->candidate.writers != 1 ||
	    writer->sequence != s->candidate.write_sequence ||
	    writer->bank > 1 || writer->bank != s->candidate.program_bank ||
	    reader->kind != EO_READER_CANDIDATE ||
	    reader->session_cookie != writer->session_cookie ||
	    reader->sequence != writer->sequence ||
	    reader->descriptor.generation != writer->attempt ||
	    reader->descriptor.program_bank != writer->bank ||
	    reader->descriptor.history_reserved !=
		    s->candidate.history_reserved ||
	    !eo_dispatch_same(source, &s->active) || source->program_bank > 1 ||
	    source->program_bank == writer->bank || !s->mutation_writers ||
	    !s->authority_readers || !s->bank_readers[writer->bank] ||
	    !s->bank_readers[source->program_bank])
		return -1;
	s->candidate.writers = 0;
	s->mutation_writers--;
	s->authority_readers--;
	s->bank_readers[writer->bank]--;
	s->bank_readers[source->program_bank]--;
	writer->owned = 0;
	reader->owned = 0;
	return 0;
}
/* EO_DISPATCH_TRANSITIONS_END */
/* EO_MUTATION_CLAIM_BEGIN */
/* Short-lived stack-owned claim spans eligibility mutations, including initial
 * qualification before activation. No dispatch/task lock nesting. */
static __always_inline int eo_mutation_begin(struct eo_reader_claim *claim)
{
	struct eo_dispatch *s = eo_dispatch_state();
	struct eo_config *c = eo_config();
	if (!s || !c || !c->cookie)
		return -1;
	bpf_spin_lock(&s->lock);
	int invalid = claim->owned || s->session_cookie != c->cookie ||
		      (s->scope_state != EO_SCOPE_ACTIVE &&
		       s->scope_state != EO_SCOPE_INACTIVE) ||
		      !s->serial || s->serial >= ~0ULL - 1 ||
		      s->active.program_bank > 1 ||
		      s->active.history_reserved || s->active.reserved ||
		      s->mutation_writers == ~0ULL ||
		      s->bank_readers[s->active.program_bank] == ~0ULL;
	if (!invalid) {
		s->serial++;
		s->mutation_writers++;
		s->bank_readers[s->active.program_bank]++;
		*claim = (struct eo_reader_claim){ .descriptor = s->active,
						   .session_cookie = c->cookie,
						   .sequence = s->serial,
						   .owned = 1,
						   .kind = EO_READER_MUTATION };
	}
	bpf_spin_unlock(&s->lock);
	return invalid ? -1 : 0;
}
static __always_inline void eo_mutation_end(struct eo_reader_claim *claim)
{
	struct eo_dispatch *s = eo_dispatch_state();
	if (!s)
		return;
	bpf_spin_lock(&s->lock);
	if (eo_dispatch_claim_end_locked(s, claim))
		s->integrity_fault |= 1;
	bpf_spin_unlock(&s->lock);
}

/* EO_MUTATION_CLAIM_END */
/* EO_CANDIDATE_SEAL_BEGIN */
/* Captured once after acquiring the exclusive candidate reader. Every nested
 * reference uses this source, never a mutable active selector or task fallback. */
struct eo_seal_source {
	__u64 attempt;
	__u32 bank;
};
static __always_inline int eo_seal_source_capture(struct eo_work *work,
						  __u64 cookie, __u64 attempt,
						  struct eo_seal_source *source)
{
	const struct eo_config *config = eo_config();
	if (!config || config->abi != EO_ABI || !cookie ||
	    config->cookie != cookie || !attempt || attempt == ~0ULL || !work ||
	    work != eo_borrow_work() || !work->busy ||
	    !eo_current_admin(cookie) || work->reader.owned != 1 ||
	    work->reader.kind != EO_READER_CANDIDATE ||
	    work->reader.session_cookie != cookie ||
	    work->reader.sequence != attempt ||
	    work->reader.descriptor.generation != attempt ||
	    work->reader.descriptor.reserved ||
	    work->reader.descriptor.program_bank > 1 ||
	    work->reader.descriptor.history_reserved != 0)
		return -1;
	*source = (struct eo_seal_source){
		.attempt = attempt, .bank = work->reader.descriptor.program_bank
	};
	return 0;
}

/* Dependency closure is derived only from the complete SEALED image. Policy
 * indices are candidate-local; certification resolves them to exact UID/epoch. */
struct eo_dependency_scan {
	struct eo_seal_source source;
	struct eo_seal_workspace *workspace;
	__u32 policies, roles, enforced_roles, writers, enforced_writers,
		role_writers, role_denies, invalid;
};
/* Structural reference checks use the retained candidate-bank callback, so a
 * missing or stale stamp cannot be hidden by an unrelated counted cell. */
/* Scalar-returning typed-memory validators are global BPF subprograms: their
 * branch states are proved once, not multiplied by every reference callback. */
__noinline int eo_seal_padding(const struct fm_blob *blob, __u32 start)
{
	if (!blob)
		return -1;
	const unsigned char *bytes = (const void *)blob;
	if (start >= 288)
		return 0;
	for (__u32 i = start; i < 288; i++)
		if (bytes[i])
			return -1;
	return 0;
}
__noinline int eo_seal_instruction(const struct fm_blob *code, __u32 count)
{
	if (!code || !count || count > 512 || eo_seal_padding(code, 80))
		return -1;
	const struct fm_instruction *instruction = (const void *)code;
	__u32 ranges = instruction->count;
	switch (instruction->op) {
	case FM_ALT:
		if (instruction->out >= count || instruction->arg >= count ||
		    ranges)
			return -1;
		break;
	case FM_EMPTY_WIDTH:
		if (instruction->out >= count || !instruction->arg ||
		    (instruction->arg & ~(FM_BEGIN_TEXT | FM_END_TEXT)) ||
		    ranges)
			return -1;
		break;
	case FM_NOP:
		if (instruction->out >= count || instruction->arg || ranges)
			return -1;
		break;
	case FM_MATCH:
	case FM_FAIL:
		if (instruction->out || instruction->arg || ranges)
			return -1;
		break;
	case FM_RUNE:
		if (instruction->out >= count || instruction->arg || !ranges ||
		    ranges > 8)
			return -1;
		break;
	default:
		return -1;
	}
	__u32 end = 0;
	for (__u32 i = 0; i < 8; i++) {
		__u32 lo = instruction->ranges[2 * i],
		      hi = instruction->ranges[2 * i + 1];
		if (i < ranges) {
			if (lo > hi || hi > 0x10ffff || (i && lo <= end))
				return -1;
			end = hi;
		} else if (lo || hi)
			return -1;
	}
	return 0;
}
struct eo_instruction_scan {
	struct eo_seal_source source;
	struct eo_seal_workspace *workspace;
	__u32 base, count, invalid;
};
static long eo_seal_instruction_step(__u32 pc, void *opaque)
{
	struct eo_instruction_scan *scan = opaque;
	if (pc >= 512 || pc >= scan->count)
		goto invalid;
	__u32 key = scan->base + pc;
#ifdef __BPF__
	__asm__ __volatile__("" : "+r"(key));
#endif
	if (key >= 16384)
		goto invalid;
	__u32 word = key / 64;
	__u64 bit = 1ULL << (key % 64);
	if (word >= 256)
		goto invalid;
	struct eo_seal_workspace *workspace = scan->workspace;
	if (!(workspace->seen[word] & bit)) {
		if (workspace->instructions >= 8192)
			goto invalid;
		workspace->seen[word] |= bit;
		workspace->instructions++;
	}
	const struct fm_blob *code =
		eo_program_blob(scan->source.bank, key, scan->source.attempt);
	if (!code || eo_seal_instruction(code, scan->count))
		goto invalid;
	return 0;
invalid:
	scan->invalid = 1;
	return 1;
}
static __always_inline int eo_seal_pattern(const struct fm_blob *blob,
					   struct eo_seal_workspace *workspace,
					   struct eo_seal_source source)
{
	const struct fm_pattern *pattern = (const void *)blob;
	if (workspace->patterns >= 1024)
		return -1;
	workspace->patterns++;
	__u32 count = pattern->count, base = pattern->code_base;
	if (!count || count > 512 || pattern->start >= count || !base ||
	    base >= 16384 || count > 16384 - base || eo_seal_padding(blob, 12))
		return -1;
	struct eo_instruction_scan scan = { .source = source,
					    .workspace = workspace,
					    .base = base,
					    .count = count };
	return FE_LOOP(count, eo_seal_instruction_step, &scan) != count ||
			       scan.invalid ?
		       -1 :
		       0;
}
enum eo_seal_value_kind {
	EO_SEAL_PATTERN,
	EO_SEAL_IDENTITY,
	EO_SEAL_UID,
	EO_SEAL_STRING,
	EO_SEAL_FILESYSTEM
};
__noinline int eo_seal_string(const struct fm_blob *blob)
{
	const struct fe_string *string = (const void *)blob;
	__u32 length = string->length;
	if (!length || length > 255)
		return -1;
	__u32 position = 0;
	for (__u32 i = 0; i < 255; i++) {
		if (position >= length)
			break;
		struct fm_decoded decoded = {};
		if (fm_decode_buffer((const void *)string->bytes, length,
				     position, &decoded))
			return -1;
		position += decoded.width;
	}
	if (position != length)
		return -1;
	return eo_seal_padding(blob, 4 + length);
}
struct eo_seal_list_scan {
	struct eo_seal_source source;
	struct eo_seal_workspace *workspace;
	struct fe_list list;
	int kind;
	__u32 invalid;
};
/* Direct global scalar-return boundary: unlike a bpf_loop callback, this
 * typed-memory function is proved independently of each caller's branch state.
 * The caller retains the exclusive workspace and stamped candidate-bank claim
 * across all nested references. No locks are held here. */
__noinline int eo_seal_value(const struct fm_blob *value,
			     struct eo_seal_workspace *workspace, __u32 kind,
			     __u32 bank, __u64 attempt)
{
	if (!value || !workspace || kind > EO_SEAL_FILESYSTEM || bank > 1 ||
	    !attempt || attempt == ~0ULL)
		return -1;
	const struct eo_seal_source source = { .bank = bank,
					       .attempt = attempt };
	if ((kind == EO_SEAL_IDENTITY && !value->words[0]) ||
	    (kind == EO_SEAL_UID && value->words[0] > 0xffffffffULL))
		return -1;
	if (kind == EO_SEAL_IDENTITY || kind == EO_SEAL_UID) {
		for (__u32 word = 1; word < 36; word++)
			if (value->words[word])
				return -1;
	}
	if (kind == EO_SEAL_PATTERN &&
	    eo_seal_pattern(value, workspace, source))
		return -1;
	if ((kind == EO_SEAL_STRING || kind == EO_SEAL_FILESYSTEM) &&
	    eo_seal_string(value))
		return -1;
	if (kind == EO_SEAL_FILESYSTEM) {
		const struct fe_string *string = (const void *)value;
		if (!((string->length == 5 &&
		       !__builtin_memcmp(string->bytes, "tmpfs", 5)) ||
		      (string->length == 5 &&
		       !__builtin_memcmp(string->bytes, "memfd", 5)) ||
		      (string->length == 7 &&
		       !__builtin_memcmp(string->bytes, "deleted", 7)) ||
		      (string->length == 7 &&
		       !__builtin_memcmp(string->bytes, "overlay", 7))))
			return -1;
	}
	return 0;
}
static long eo_seal_list_step(__u32 i, void *opaque)
{
	struct eo_seal_list_scan *scan = opaque;
	if (i >= 256 || i >= scan->list.count || !scan->list.base ||
	    scan->list.base >= 16384 || i >= 16384 - scan->list.base)
		goto invalid;
	const struct fm_blob *value = eo_program_blob(
		scan->source.bank, scan->list.base + i, scan->source.attempt);
	if (!value || eo_seal_value(value, scan->workspace, scan->kind,
				    scan->source.bank, scan->source.attempt))
		goto invalid;
	return 0;
invalid:
	scan->invalid = 1;
	return 1;
}
static __always_inline int eo_seal_list(struct fe_list list, int kind,
					struct eo_seal_workspace *workspace,
					struct eo_seal_source source)
{
	if (!list.count)
		return list.base ? -1 : 0;
	if (!list.base || !fe_list_valid(list))
		return -1;
	struct eo_seal_list_scan scan = { .source = source,
					  .workspace = workspace,
					  .list = list,
					  .kind = kind };
	return FE_LOOP(list.count, eo_seal_list_step, &scan) != list.count ||
			       scan.invalid ?
		       -1 :
		       0;
}
static long eo_dependency_rule(__u32 index, void *opaque)
{
	struct eo_dependency_scan *scan = opaque;
	if (index >= 256)
		return 1;
	const struct fe_rule *rule = (const void *)eo_program_blob(
		scan->source.bank, 9 + index, scan->source.attempt);
	if (!rule || rule->policy >= scan->policies || rule->policy >= 8 ||
	    rule->mode < 1 || rule->mode > 2 || rule->deny > 1 ||
	    (rule->deny && rule->set_role) || rule->reserved ||
	    eo_seal_padding((const void *)rule, 112) ||
	    rule->actor_image < -1 || rule->actor_image > 1 ||
	    rule->target_image < -1 || rule->target_image > 1 ||
	    rule->stdin_pipe < -1 || rule->stdin_pipe > 1 ||
	    rule->ancestor_depth > 16 ||
	    ((!rule->ancestor_depth) != (!rule->ancestor_path.count)) ||
	    eo_seal_list(rule->actor_role, EO_SEAL_IDENTITY, scan->workspace,
			 scan->source) ||
	    eo_seal_list(rule->uid, EO_SEAL_UID, scan->workspace,
			 scan->source) ||
	    eo_seal_list(rule->actor_path, 0, scan->workspace, scan->source) ||
	    eo_seal_list(rule->target_path, 0, scan->workspace, scan->source) ||
	    eo_seal_list(rule->ancestor_path, 0, scan->workspace,
			 scan->source) ||
	    eo_seal_list(rule->container, EO_SEAL_STRING, scan->workspace,
			 scan->source) ||
	    eo_seal_list(rule->fs_type, EO_SEAL_FILESYSTEM, scan->workspace,
			 scan->source) ||
	    eo_seal_list(rule->arg_contains, EO_SEAL_STRING, scan->workspace,
			 scan->source) ||
	    eo_seal_list(rule->arg_prefix, EO_SEAL_STRING, scan->workspace,
			 scan->source)) {
		scan->invalid = 1;
		return 1;
	}
	__u32 bit = 1U << rule->policy;
	if (rule->actor_role.count) {
		scan->roles |= bit;
		if (rule->mode == 2)
			scan->enforced_roles |= bit;
		if (rule->deny)
			scan->role_denies |= bit;
		if (rule->set_role)
			scan->role_writers |= bit;
	}
	if (rule->set_role) {
		scan->writers |= bit;
		if (rule->mode == 2)
			scan->enforced_writers |= bit;
	}
	return 0;
}
static __always_inline int
eo_required_known_mask(__u64 attempt, __u32 *mask,
		       struct eo_seal_workspace *workspace,
		       struct eo_seal_source source)
{
	const struct fe_header *header =
		(const void *)eo_program_blob(source.bank, 0, source.attempt);
	if (!header || !attempt || attempt == ~0ULL ||
	    header->generation != attempt || !header->policies ||
	    header->policies > 8 || header->rules > 256 ||
	    header->rule_base != 9)
		return -1;
	if (eo_seal_padding((const void *)header, 24))
		return -1;
	const struct fm_blob *container =
		eo_program_blob(source.bank, header->container, source.attempt);
	if (!container || eo_seal_string(container))
		return -1;
	__u32 policies = header->policies, rules = header->rules;
	int default_deny = 0, enforced_default_deny = 0;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= policies)
			break;
		const struct fe_policy *policy = (const void *)eo_program_blob(
			source.bank, 1 + i, source.attempt);
		if (!policy || !policy->uid || !policy->root_role ||
		    !policy->root_epoch || policy->root_epoch > attempt ||
		    eo_seal_padding((const void *)policy, 32) ||
		    policy->mode < 1 || policy->mode > 2 ||
		    policy->fallback > 2)
			return -1;
		__u64 uid = policy->uid;
		for (__u32 previous = 0; previous < 8; previous++) {
			if (previous >= i)
				break;
			const struct fe_policy *other =
				(const void *)eo_program_blob(source.bank,
							      1 + previous,
							      source.attempt);
			if (!other || other->uid == uid)
				return -1;
		}
		if (policy->fallback == 2) {
			default_deny = 1;
			if (policy->mode == 2)
				enforced_default_deny = 1;
		}
	}
	for (__u32 i = 0; i < 8; i++) {
		if (i < policies)
			continue;
		const struct fm_blob *unused =
			eo_program_blob(source.bank, 1 + i, source.attempt);
		if (!unused || eo_seal_padding(unused, 0))
			return -1;
	}
	struct eo_dependency_scan scan = { .source = source,
					   .policies = policies,
					   .workspace = workspace };
	if (FE_LOOP(rules, eo_dependency_rule, &scan) < 0 || scan.invalid)
		return -1;
	__u32 required = scan.enforced_roles |
			 (enforced_default_deny ? scan.roles : 0);
	/* Eight possible bit additions, followed by a final fixed-point check. */
	for (int round = 0; round <= 8; round++) {
		__u32 demand = scan.enforced_writers |
			       (required & scan.writers);
		__u32 next = required | (demand & scan.role_writers);
		if (demand) {
			next |= scan.role_denies;
			if (default_deny)
				next |= scan.roles;
		}
		if (next == required) {
			if (required >> policies)
				return -1;
			*mask = required;
			return 0;
		}
		required = next;
	}
	return -1; /* No receipt without a proved bounded fixed point. */
}

struct eo_seal_scan {
	__u64 attempt;
	__u32 bank, count;
};
static long eo_seal_count_step(__u32 key, void *opaque)
{
	struct eo_seal_scan *scan = opaque;
	if (key >= 16384)
		return 1;
	if (eo_program_blob(scan->bank, key, scan->attempt))
		scan->count++;
	return 0;
}
static __noinline int eo_seal_candidate(struct eo_dispatch *dispatch,
					__u64 cookie, __u64 attempt)
{
	struct eo_work *work = eo_get_work();
	if (!work)
		return EO_BAD_STORAGE;
	__u32 zero = 0;
	struct eo_seal_workspace *workspace =
		bpf_map_lookup_elem(&eo_seal_work, &zero);
	if (!workspace || __sync_val_compare_and_swap(&workspace->busy, 0, 1)) {
		eo_put_work(work);
		return EO_BAD_STORAGE;
	}
	workspace->session_cookie = cookie;
	workspace->attempt = attempt;
	workspace->patterns = workspace->instructions = 0;
	/* Volatile bounded stores avoid an unsupported out-of-line BPF memset. */
	for (__u32 i = 0; i < 256; i++)
		((volatile __u64 *)workspace->seen)[i] = 0;
	__u32 entries = 0;
	bpf_spin_lock(&dispatch->lock);
	int refused = eo_candidate_scan_begin_locked(dispatch, cookie, attempt,
						     &work->reader);
	if (!refused)
		entries = dispatch->candidate.entries;
	bpf_spin_unlock(&dispatch->lock);
	if (refused) {
		workspace->session_cookie = workspace->attempt = 0;
		__sync_lock_test_and_set(&workspace->busy, 0);
		eo_put_work(work);
		return EO_RETRY;
	}
	struct eo_seal_source source = {};
	int source_valid =
		!eo_seal_source_capture(work, cookie, attempt, &source);
	struct eo_seal_scan scan = {
		.attempt = attempt, .bank = work->reader.descriptor.program_bank
	};
	int complete = source_valid &&
		       bpf_loop(16384, eo_seal_count_step, &scan, 0) == 16384 &&
		       scan.count == entries;
	__u32 policies = 0, writers = 0, required_known = 0;
	int execution_class =
		complete ? fe_execution_class(0, attempt, &policies, &writers) :
			   -1;
	if (complete && execution_class > 0 &&
	    eo_required_known_mask(attempt, &required_known, workspace, source))
		complete = 0;
	struct eo_reader_claim local = {};
	// The qualified command exclusively owns busy work; take before refund.
	if (eo_reader_take_locked(&work->reader, cookie, cookie, attempt,
				  &local)) {
		/* This invocation still exclusively owns the validator; all its blob
         * references are finished even if the independent read claim is corrupt. */
		workspace->session_cookie = workspace->attempt = 0;
		__sync_lock_test_and_set(&workspace->busy, 0);
		eo_put_work(
			work); /* Ownership guard deliberately retains busy on failure. */
		return EO_BAD_STORAGE;
	}
	bpf_spin_lock(&dispatch->lock);
	refused = eo_dispatch_claim_end_locked(dispatch, &local);
	if (refused)
		dispatch->integrity_fault |= 1;
	else
		refused = eo_candidate_seal_finish_locked(
			dispatch, cookie, attempt,
			execution_class > 0 ? (__u32)execution_class : 0,
			policies, writers, required_known,
			complete && execution_class > 0);
	bpf_spin_unlock(&dispatch->lock);
	work->reader = (struct eo_reader_claim){};
	workspace->session_cookie = workspace->attempt = 0;
	__sync_lock_test_and_set(&workspace->busy, 0);
	eo_put_work(work);
	return refused ? EO_BAD_ROLES : EO_OK;
}
/* EO_CANDIDATE_SEAL_END */

#endif

static __always_inline int eo_control_gate(const struct eo_config *c)
{
	if (c->gate_slot >= 65536)
		return 0;
	__u32 slot = c->gate_slot;
	__u64 *gate = bpf_map_lookup_elem(&eo_gates, &slot);
	return gate && __sync_val_compare_and_swap(gate, 0, 0) == FG_CLOSED;
}
static __always_inline int eo_control_version(struct eo_health *h)
{
	__u64 version =
		__sync_val_compare_and_swap(&h->authority_version, 0, 0);
	if (version >= ER_UNKNOWN - 1) {
		eo_fault(EO_FAULT_VERSION);
		return 0;
	}
	__sync_lock_test_and_set(&h->authority_version, version + 1);
	return 1;
}
static __always_inline int eo_control_movement(int entering)
{
	struct eo_health *h = eo_status();
	if (!h || !h->movement_armed || h->retired || h->movement_fault)
		return 0;
	__u64 sequence =
		__sync_val_compare_and_swap(&h->movement_sequence, 0, 0);
	// Both outer operations are serialized by cgroup_mutex. Unexpected nesting
	// or any potential wrap is permanent failure, never a fresh even sequence.
	if (sequence >= ER_UNKNOWN - 1 || ((sequence & 1) != (!entering))) {
		h->movement_fault = 1;
		eo_fault(EO_FAULT_STATE);
		return 0;
	}
	__sync_fetch_and_add(&h->movement_sequence, 1);
	return 0;
}
SEC("fentry/cgroup_migrate") int BPF_PROG(eo_migrate_enter)
{
	return eo_control_movement(1);
}
SEC("fexit/cgroup_migrate") int BPF_PROG(eo_migrate_exit)
{
	return eo_control_movement(0);
}
SEC("fentry/cgroup_update_dfl_csses") int BPF_PROG(eo_reconfigure_enter)
{
	return eo_control_movement(1);
}
SEC("fexit/cgroup_update_dfl_csses") int BPF_PROG(eo_reconfigure_exit)
{
	return eo_control_movement(0);
}
SEC("fexit/cgroup_kn_lock_live")
int BPF_PROG(eo_movement_arm, struct kernfs_node *kn, bool drain,
	     struct cgroup *result)
{
	__u32 zero = 0;
	struct eo_command *command = bpf_map_lookup_elem(&eo_commands, &zero);
	if (!command || !eo_admin_authorized(command))
		return 0;
	struct eo_health *h = eo_status();
	if (!h || h->retired || h->movement_armed || !result ||
	    (__u64)result >= ~4095ULL)
		return 0;
	// Successful return still owns cgroup_mutex, draining earlier operations
	// whose function entry preceded attachment. Native uses a rejected negative-PID
	// cgroup.procs write and requires the authorized receipt (no hierarchy mutation).
	h->movement_sequence = 0;
	h->movement_fault = 0;
	__sync_lock_test_and_set(&h->movement_armed, 1);
	return 0;
}
static __always_inline int eo_control_root(const struct eo_config *c,
					   const struct eo_command *command,
					   int authorize)
{
	struct task_struct *task = bpf_task_from_pid(c->init_host_pid);
	if (!task)
		return EO_BAD_IDENTITY;
	int result = EO_BAD_IDENTITY;
	struct eo_task *state = eo_lookup_task(task);
	struct eo_anchor *anchor = eo_root();
	struct eo_health *h = eo_status();
	__u64 cgroup = 0;
	if (!anchor || !h || task->pid != task->tgid)
		goto out;
	// Authorization always proves the exact inventoried physical task. A later
	// zero-cookie check proves only continuity of the already-pinned group token:
	// de_thread may replace the leader's task/cookie without replacing that token.
	// Never mint task storage or initialize the anchor from this check path.
	if (authorize && !command->root_cookie)
		goto out;
	if (command->root_cookie &&
	    (!state || state->cookie != command->root_cookie))
		goto out;
	if (BPF_CORE_READ_INTO(&cgroup, task, cgroups, dfl_cgrp, kn, id) ||
	    cgroup != c->cgroup)
		goto out;
	__u64 group = eo_group(task);
	if (!group)
		goto out;
	if (authorize) {
		if (anchor->group) {
			if (anchor->group != group ||
			    anchor->cookie != command->root_cookie)
				goto out;
		} else {
			anchor->group = group;
			anchor->cookie = command->root_cookie;
			h->root_cookie = command->root_cookie;
		}
	}
	h->root_match = anchor->group == group;
	result = h->root_match ? EO_OK : EO_BAD_IDENTITY;
out:
	bpf_task_release(task);
	return result;
}
// kind0 inventories physical identities only; kind1 stages AND validates;
// kind2 validates without adoption or role initialization. Never hold a task
// spinlock while invoking any helper or caller-supplied role operation.
static __noinline int eo_control_inventory(const struct eo_config *c,
					   struct eo_work *w, __u32 mask,
					   int kind)
{
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	if (kind == 1)
		return EO_BAD_ROLES;
#endif
	struct eo_health *h = eo_status();
	if (!h)
		return EO_BAD_STORAGE;
	__u32 valid_roles = 0;
	if (kind) {
		if (!w)
			return EO_BAD_STORAGE;
		valid_roles = w->candidate.count;
		if (valid_roles > ER_ACTIVE)
			return EO_BAD_ROLES;
	}
	h->count = 0;
	if (!h->movement_armed || h->movement_fault)
		return EO_MOVEMENT;
	__u64 sequence =
		__sync_val_compare_and_swap(&h->movement_sequence, 0, 0);
	if (sequence & 1)
		return EO_MOVEMENT;
	struct cgroup *group = bpf_cgroup_from_id(c->cgroup);
	if (!group)
		return EO_BAD_IDENTITY;
	struct bpf_iter_css_task iterator;
	int status = EO_LIMIT;
	if (bpf_iter_css_task_new(&iterator, &group->self, 0)) {
		status = EO_BAD_ITERATOR;
		goto destroy;
	}
	for (__u32 index = 0; index <= EO_TASKS; index++) {
		struct task_struct *task = bpf_iter_css_task_next(&iterator);
		if (!task) {
			status = EO_OK;
			break;
		}
		if (index >= EO_TASKS || index >= c->task_limit)
			break;
		struct eo_task *state = eo_get_task(task);
		if (!state) {
			status = (h->faults & EO_FAULT_CAPACITY) ?
					 EO_LIMIT :
					 EO_BAD_STORAGE;
			break;
		}
		if (kind) {
			if (!w) {
				status = EO_BAD_STORAGE;
				break;
			}
			if (kind == 1 && !eo_lineage(task, state)) {
				status = EO_LINEAGE;
				break;
			}
			if (kind == 1 && eo_stage_task(task, state, w, mask)) {
				status = EO_BAD_ROLES;
				break;
			}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
			if (kind == 3 &&
			    eo_stage_candidate_task(task, state, w, mask) < 0) {
				status = EO_BAD_ROLES;
				break;
			}
			if (kind != 3 && eo_validate_task(state, w)) {
#else
			if (eo_validate_task(state, w)) {
#endif
				status = EO_BAD_ROLES;
				break;
			}
		}
		struct eo_row *row = bpf_map_lookup_elem(&eo_rows, &index);
		if (!row) {
			status = EO_BAD_STORAGE;
			break;
		}
		__u32 flags;
		bpf_spin_lock(&state->lock);
		flags = state->flags;
		bpf_spin_unlock(&state->lock);
		row->cookie = state->cookie;
		row->tid = task->pid;
		row->tgid = task->tgid;
		row->flags = flags;
		row->valid_roles = valid_roles;
		h->count = index + 1;
	}
destroy:
	bpf_iter_css_task_destroy(&iterator);
	bpf_cgroup_release(group);
	if (h->movement_fault ||
	    __sync_val_compare_and_swap(&h->movement_sequence, 0, 0) !=
		    sequence)
		return EO_MOVEMENT;
	if (kind && h->faults)
		return EO_BAD_ROLES;
	if (kind && status == EO_OK) {
		struct eo_phase *phase = eo_phase_state();
		if (!phase)
			return EO_BAD_STORAGE;
		// Record the SAME sequence checked above, never a later reread which could
		// silently bless a migration occurring after the completed inventory.
		phase->validated_movement_sequence = sequence;
	}
	return status;
}
static __always_inline __u64 eo_control_generation(__u32 slot)
{
	const struct fm_blob *blob = eo_blob(slot, 0);
	if (!blob)
		return 0;
	return ((const struct fe_header *)blob)->generation;
}
static __always_inline int eo_control_accepted(__u64 generation)
{
	const struct fm_blob *blob = eo_blob(0, 0);
	if (!blob)
		return 0;
	const struct fe_header *header = (const void *)blob;
	if (header->generation != generation || header->policies > 8)
		return 0;
	__u32 count = header->policies;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= count)
			break;
		blob = eo_blob(0, 1 + i);
		if (!blob)
			return 0;
		const struct fe_policy *policy = (const void *)blob;
		if (!policy->uid || !policy->root_epoch ||
		    policy->root_epoch == ER_UNKNOWN ||
		    eo_accepted_epoch(policy->uid) != policy->root_epoch)
			return 0;
	}
	return 1;
}
static __always_inline int eo_control_receipt(struct eo_health *h,
					      struct eo_phase *phase)
{
	__u64 current =
		__sync_val_compare_and_swap(&h->movement_sequence, 0, 0);
	return h->movement_armed && !h->movement_fault && !(current & 1) &&
	       current == phase->validated_movement_sequence;
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* EO_FRESH_SESSION_BEGIN */
static long eo_count_accepted_epoch(void *map, const void *key, void *value,
				    void *opaque)
{
	(void)map;
	(void)key;
	(void)value;
	__u64 *count = opaque;
	*count = 1;
	return 1;
}
/* Qualified root/authenticated admin and phase.busy precede this call. The
 * development catalogue is UAPI read-only; no kernel epoch writer can exist
 * before OPEN. Prove emptiness outside dispatch_lock, never infer it from a
 * missing task or initialize an existing scope's missing authority version. */
static __noinline int eo_open_fresh_session(struct eo_dispatch *dispatch,
					    const struct eo_config *config,
					    struct eo_health *health,
					    struct eo_phase *phase)
{
	if (!config->cookie || !config->cgroup || health->authority_version ||
	    health->active_generation || health->ready_generation ||
	    health->a_complete || phase->state != EO_IDLE ||
	    phase->committed_generation || phase->candidate_generation ||
	    phase->attempted_generation)
		return EO_RETRY;
	__u64 count = 0;
	long scanned = bpf_for_each_map_elem(
		&eo_epochs, eo_count_accepted_epoch, &count, 0);
	if (scanned < 0 || count || scanned)
		return EO_RETRY;
	int result = EO_RETRY;
	bpf_spin_lock(&dispatch->lock);
	int fresh = !dispatch->scope_state;
	/* Skip the lock/scope word; every remaining authority byte must be fresh. */
	const __u64 *words =
		(const void *)((const unsigned char *)dispatch + 8);
	for (__u32 i = 0; i < (sizeof(*dispatch) - 8) / 8; i++)
		if (words[i])
			fresh = 0;
	if (fresh && !health->authority_version &&
	    !eo_dispatch_open_locked(dispatch, config->cookie,
				     config->cgroup)) {
		health->authority_version = 1;
		result = EO_OK;
	}
	bpf_spin_unlock(&dispatch->lock);
	return result;
}
/* EO_FRESH_SESSION_END */
#endif
SEC("syscall") int eo_command(void *unused)
{
	__u32 zero = 0;
	struct eo_command *input = bpf_map_lookup_elem(&eo_commands, &zero);
	if (!input || !eo_admin_authorized(input))
		return EO_BAD_COMMAND;
	if (!eo_local_types())
		return EO_BAD_CONFIG;
	struct eo_command command = *input;
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	struct eo_phase *phase = eo_phase_state();
	if (!c || !h || !phase)
		return EO_BAD_STORAGE;
	if (__sync_val_compare_and_swap(&phase->busy, 0, 1))
		return EO_RETRY;
	int result = EO_BAD_CONFIG;
	struct eo_work *work = 0;
	if (c->abi != EO_ABI || !c->cookie || !c->cgroup || !c->init_host_pid ||
	    !c->task_limit || c->task_limit > EO_TASKS || c->gate_slot >= 65536)
		goto done;
	result = EO_BAD_COMMAND;
	if (h->retired || phase->state == EO_STOPPED)
		goto done;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	/* EO_CANDIDATE_COMMAND_BEGIN */
	if (command.operation == EO_SESSION_OPEN ||
	    command.operation == EO_CANDIDATE_BEGIN ||
	    command.operation == EO_CANDIDATE_ABORT ||
	    command.operation == EO_CANDIDATE_WRITE ||
	    command.operation == EO_CANDIDATE_SEAL) {
		// Session creation is not adoption authority. Require the separately
		// inventoried/authorized physical root and armed membership observer.
		if (command.operation == EO_SESSION_OPEN &&
		    (!h->movement_armed || h->movement_fault ||
		     eo_control_root(c, &command, 0) != EO_OK)) {
			result = EO_BAD_IDENTITY;
			goto done;
		}
		struct eo_dispatch *dispatch =
			bpf_map_lookup_elem(&eo_dispatch, &zero);
		struct eo_candidate_input *request =
			bpf_map_lookup_elem(&eo_candidate_input, &zero);
		if (!dispatch || !request) {
			result = EO_BAD_STORAGE;
			goto done;
		}
		struct eo_candidate_request candidate = request->request;
		if (candidate.reserved ||
		    candidate.session_cookie != c->cookie ||
		    (command.operation != EO_SESSION_OPEN &&
		     candidate.attempt != command.generation))
			goto done;
		if (command.operation == EO_SESSION_OPEN) {
			result = eo_open_fresh_session(dispatch, c, h, phase);
			goto done;
		}
		/* EO_CANDIDATE_IO_BEGIN */
		if (command.operation == EO_CANDIDATE_SEAL) {
			result = eo_seal_candidate(dispatch,
						   candidate.session_cookie,
						   candidate.attempt);
			goto done;
		}
		if (command.operation == EO_CANDIDATE_WRITE) {
			if (candidate.bank > 1 || candidate.index >= 16384)
				goto done;
			struct eo_program_cell *cell =
				candidate.bank ?
					bpf_map_lookup_elem(&eo_program_bank1,
							    &candidate.index) :
					bpf_map_lookup_elem(&eo_program_bank0,
							    &candidate.index);
			if (!cell) {
				result = EO_BAD_STORAGE;
				goto done;
			}
			result = eo_candidate_write_cell(dispatch, &candidate,
							 request->data, cell) ?
					 EO_RETRY :
					 EO_OK;
			goto done;
		}
		/* EO_CANDIDATE_IO_END */
		int refused;
		bpf_spin_lock(&dispatch->lock);
		if (command.operation == EO_CANDIDATE_BEGIN)
			refused = eo_candidate_begin_locked(
				dispatch, candidate.session_cookie,
				candidate.attempt, candidate.entries);
		else
			refused = eo_candidate_abort_locked(
				dispatch, candidate.session_cookie,
				candidate.attempt);
		bpf_spin_unlock(&dispatch->lock);
		result = refused ? EO_RETRY : EO_OK;
		goto done;
	}
/* EO_CANDIDATE_COMMAND_END */
#endif
	if (command.operation != EO_INVENTORY &&
	    command.operation != EO_ROOT_CHECK && !eo_control_gate(c)) {
		result = EO_RETRY;
		goto done;
	}
	if (command.operation == EO_INVENTORY) {
		result = eo_control_inventory(c, 0, 0, 0);
		goto done;
	}
	if (command.operation == EO_ROOT_AUTHORIZE ||
	    command.operation == EO_ROOT_CHECK) {
		h->root_match = 0;
		result = eo_control_root(
			c, &command, command.operation == EO_ROOT_AUTHORIZE);
		goto done;
	}
	if (command.operation == EO_RETIRE) {
		struct eo_anchor *anchor = eo_root();
		if (!anchor) {
			result = EO_BAD_STORAGE;
			goto done;
		}
		anchor->group = 0;
		anchor->cookie = 0;
		h->root_cookie = 0;
		h->root_match = 0;
		h->ready_generation = 0;
		h->a_complete = 0;
		h->retired = 1;
		phase->state = EO_STOPPED;
		phase->candidate_generation = 0;
		phase->new_uid_mask = 0;
		result = eo_control_version(h) ? EO_OK : EO_BAD_ROLES;
		goto done;
	}
	if (!command.generation || command.generation == ER_UNKNOWN)
		goto done;
	if (command.operation == EO_REATTEST) {
		// Same-generation, read-only physical re-attestation after membership motion.
		// No candidate roots, no UID publication, and no inferred historical lineage.
		if (phase->state != EO_IDLE ||
		    phase->committed_generation != command.generation ||
		    h->active_generation != command.generation ||
		    command.new_uid_mask ||
		    eo_control_generation(0) != command.generation)
			goto done;
		h->ready_generation = 0;
		if (h->faults || h->movement_fault) {
			result = EO_BAD_ROLES;
			goto done;
		}
		work = eo_get_work();
		if (!work) {
			result = EO_BAD_STORAGE;
			goto done;
		}
		if (eo_load_candidate(work, 0, 0) ||
		    work->a_epoch != command.generation) {
			result = EO_BAD_ROLES;
			goto done;
		}
		result = eo_control_inventory(c, work, 0, 2);
		if (result == EO_OK) {
			if (h->pending_births)
				result = EO_RETRY;
			else
				h->ready_generation = command.generation;
		}
		goto done;
	}

	if (command.operation == EO_BOOTSTRAP_A) {
		if (phase->state == EO_IDLE) {
			if (command.generation <= phase->attempted_generation)
				goto done;
			phase->attempted_generation = command.generation;
			phase->candidate_generation = command.generation;
			phase->new_uid_mask = command.new_uid_mask;
			phase->state = EO_STAGING;
			h->a_complete = 0;
			h->ready_generation = 0;
			if (!eo_control_version(h)) {
				result = EO_BAD_ROLES;
				goto done;
			}
		} else if (phase->state != EO_STAGING ||
			   phase->candidate_generation != command.generation ||
			   phase->new_uid_mask != command.new_uid_mask)
			goto done;
		// Any failed retry invalidates the earlier A-complete barrier.
		__sync_lock_test_and_set(&h->a_complete, 0);
	} else if (phase->candidate_generation != command.generation ||
		   (phase->new_uid_mask != command.new_uid_mask &&
		    !(command.operation == EO_VALIDATE &&
		      phase->state == EO_COMMITTED &&
		      command.new_uid_mask == 0)))
		goto done;
	switch (command.operation) {
	case EO_BOOTSTRAP_A:
	case EO_BOOTSTRAP_B:
	case EO_VALIDATE:
		if (command.operation == EO_BOOTSTRAP_B &&
		    (phase->state != EO_STAGING ||
		     __sync_val_compare_and_swap(&h->a_complete, 0, 0) !=
			     command.generation))
			goto done;
		if (command.operation == EO_VALIDATE &&
		    phase->state != EO_VALIDATED &&
		    phase->state != EO_COMMITTED)
			goto done;
		if (command.operation == EO_VALIDATE &&
		    phase->state == EO_COMMITTED && command.new_uid_mask)
			goto done;
		// A failed re-attestation must not leave an earlier readiness receipt live.
		if (command.operation != EO_BOOTSTRAP_A)
			h->ready_generation = 0;
		// Postcommit recovery only re-attests the active accepted roles. It must
		// never revisit staging roots or change the irreversible committed phase.
		__u32 slot = phase->state == EO_COMMITTED ? 0 : 1;
		__u32 mask =
			phase->state == EO_COMMITTED ? 0 : command.new_uid_mask;
		if (eo_control_generation(slot) != command.generation) {
			result = EO_BAD_ROLES;
			goto done;
		}
		if (h->faults || h->movement_fault) {
			result = EO_BAD_ROLES;
			goto done;
		}
		work = eo_get_work();
		if (!work) {
			result = EO_BAD_STORAGE;
			goto done;
		}
		if (eo_load_candidate(work, slot, mask) ||
		    work->a_epoch != command.generation) {
			result = EO_BAD_ROLES;
			goto done;
		}
		result = eo_control_inventory(
			c, work, mask,
			command.operation == EO_VALIDATE ? 2 : 1);
		if (result != EO_OK)
			goto done;
		if (command.operation == EO_BOOTSTRAP_A)
			__sync_lock_test_and_set(&h->a_complete,
						 command.generation);
		else {
			if (phase->state != EO_COMMITTED)
				phase->state = EO_VALIDATED;
			h->ready_generation = command.generation;
		}
		break;
	case EO_PUBLICATION_BEGIN:
		if (phase->state != EO_VALIDATED ||
		    h->ready_generation != command.generation || h->faults)
			goto done;
		if (!eo_control_receipt(h, phase)) {
			h->ready_generation = 0;
			result = EO_MOVEMENT;
			goto done;
		}
		if (!eo_control_version(h)) {
			result = EO_BAD_ROLES;
			goto done;
		}
		phase->state = EO_PUBLISHING;
		result = EO_OK;
		break;
	case EO_PUBLICATION_COMMITTED:
		if (phase->state != EO_PUBLISHING ||
		    !eo_control_accepted(command.generation))
			goto done;
		// Active-slot replacement, not this bookkeeping command, is the irreversible
		// commit. Native appends successful-only kernel history AFTER the swap and
		// holds PUBLISHING until that flush succeeds. Never offer Abort if the active
		// slot already names this generation, including a partial history flush.
		phase->committed_generation = command.generation;
		h->active_generation = command.generation;
		phase->state = EO_COMMITTED;
		result = eo_control_version(h) ? EO_OK : EO_BAD_ROLES;
		if (!eo_control_receipt(h, phase)) {
			h->ready_generation = 0;
			result = EO_MOVEMENT;
		}
		break;
	case EO_BOOTSTRAP_ABORT:
		if ((phase->state != EO_STAGING &&
		     phase->state != EO_VALIDATED &&
		     phase->state != EO_PUBLISHING) ||
		    eo_control_generation(0) == command.generation)
			goto done;
		if (!eo_control_version(h)) {
			result = EO_BAD_ROLES;
			goto done;
		}
		phase->state = EO_IDLE;
		phase->candidate_generation = 0;
		phase->new_uid_mask = 0;
		__sync_lock_test_and_set(&h->a_complete, 0);
		h->ready_generation = h->faults ? 0 : h->active_generation;
		result = EO_OK;
		break;
	case EO_PHASE_CLEAR:
		if (phase->state != EO_COMMITTED ||
		    phase->committed_generation != command.generation ||
		    eo_control_generation(0) != command.generation)
			goto done;
		if (!eo_control_receipt(h, phase)) {
			h->ready_generation = 0;
			result = EO_MOVEMENT;
			goto done;
		}
		if (h->faults || h->pending_births) {
			h->ready_generation = 0;
			result = EO_RETRY;
			goto done;
		}
		if (!eo_control_version(h)) {
			result = EO_BAD_ROLES;
			goto done;
		}
		phase->state = EO_IDLE;
		phase->candidate_generation = 0;
		phase->new_uid_mask = 0;
		__sync_lock_test_and_set(&h->a_complete, 0);
		h->ready_generation = h->faults ? 0 : command.generation;
		result = h->faults ? EO_BAD_ROLES : EO_OK;
		break;
	default:
		break;
	}
done:
	if (work)
		eo_put_work(work);
	h->result = result;
	__sync_lock_test_and_set(&phase->busy, 0);
	return result;
}
#endif
