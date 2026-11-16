/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
struct bpf_spin_lock {
	__u32 val;
};
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	assert(!lock->val);
	lock->val = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	assert(lock->val);
	lock->val = 0;
}
/* ACTUAL_TYPES */
static struct eo_dispatch *copy_dispatch;
static void *dispatch_checked_copy(void *, const void *, size_t);
/* ACTUAL_TRANSITIONS */
static void *dispatch_checked_copy(void *dst, const void *src, size_t size)
{
	assert(copy_dispatch && copy_dispatch->candidate.writers == 1);
	bpf_spin_lock(&copy_dispatch->lock);
	assert(eo_candidate_seal_begin_locked(copy_dispatch, 7, 2));
	bpf_spin_unlock(&copy_dispatch->lock);
	return memcpy(dst, src, size);
}

int main(void)
{
	struct eo_dispatch s = {};
	assert(!eo_dispatch_open_locked(&s, 7, 42));
	assert(!eo_dispatch_open_locked(&s, 7, 42));
	assert(eo_dispatch_open_locked(&s, 8, 42));
	assert(eo_dispatch_open_locked(&s, 7, 43));
	assert(s.serial == 1 && s.active.generation == 0);
	assert(s.scope_state == EO_SCOPE_INACTIVE);
	s.scope_state = 99;
	assert(eo_dispatch_open_locked(&s, 7, 42));
	s.scope_state = EO_SCOPE_INACTIVE;
	s.active = (struct eo_dispatch_descriptor){ .generation = 1,
						    .execution_class = 1,
						    .policy_count = 1,
						    .role_writer_mask = 1 };
	s.scope_state = EO_SCOPE_ACTIVE;
	struct eo_dispatch_descriptor active = s.active;
	assert(!eo_candidate_begin_locked(&s, 7, 2, 16));
	assert(eo_candidate_begin_locked(&s, 7, 3, 16));
	assert(!memcmp(&active, &s.active, sizeof(active)));
	struct eo_program_cell cell = {};
	struct eo_candidate_input input = { .request = { .session_cookie = 7,
							 .attempt = 2,
							 .entries = 16,
							 .index = 3,
							 .bank = 1 } };
	input.data[0] = 91;
	copy_dispatch = &s;
	assert(!eo_candidate_write_cell(&s, &input.request, input.data, &cell));
	assert(cell.attempt == 2 && cell.data[0] == 91 && !s.candidate.writers);
	input.request.attempt = 1;
	assert(eo_candidate_write_cell(&s, &input.request, input.data, &cell));
	assert(cell.attempt == 2 && cell.data[0] == 91);
	struct eo_writer_token writer = {};
	assert(!eo_candidate_write_begin_locked(&s, 7, 2, 1, &writer));
	struct eo_writer_token second_writer = {};
	struct eo_writer_token copied_writer = writer;
	assert(eo_candidate_write_begin_locked(&s, 7, 2, 1, &second_writer));
	assert(eo_candidate_seal_begin_locked(&s, 7, 2));
	assert(!eo_candidate_write_end_locked(&s, &writer));
	assert(eo_candidate_write_end_locked(&s, &writer));
	assert(!eo_candidate_write_begin_locked(&s, 7, 2, 1, &second_writer));
	assert(eo_candidate_write_end_locked(&s, &copied_writer));
	assert(s.candidate.writers == 1);
	assert(eo_candidate_seal_begin_locked(&s, 7, 2));
	assert(!eo_candidate_write_end_locked(&s, &second_writer));

	struct eo_reader_claim scan = {}, scan_release = {};
	assert(!eo_candidate_scan_begin_locked(&s, 7, 2, &scan));
	assert(scan.owned && scan.kind == EO_READER_CANDIDATE &&
	       scan.descriptor.program_bank == 1 && s.bank_readers[1] == 1);

	assert(eo_candidate_write_begin_locked(&s, 7, 2, 1, &writer));
	assert(!eo_reader_take_locked(&scan, 7, 7, 2, &scan_release));
	assert(!eo_dispatch_claim_end_locked(&s, &scan_release));
	assert(!scan.owned && !s.bank_readers[1] && !s.authority_readers);
	assert(!eo_candidate_seal_finish_locked(&s, 7, 2, 1, 1, 1, 0, 1));
	assert(eo_candidate_abort_locked(&s, 8, 2));
	assert(!eo_candidate_snapshot_locked(&s, 7, 2));
	s.candidate.sealed_class = 2;
	s.coverage_unknown = 1;
	assert(eo_candidate_certify_locked(&s, 7, 2, 1, 0));
	s.coverage_unknown = 0;
	s.candidate.required_known_mask = 1;
	assert(eo_candidate_certify_locked(&s, 7, 2, 1, 0));
	s.candidate.required_known_mask = 0;
	s.candidate.sealed_class = 1;
	s.coverage_unknown = 1; /* Audit preserves diagnostic uncertainty. */
	s.candidate.inventory_count =
		1; /* Fixture: one independently staged task. */
	assert(!eo_candidate_certify_locked(&s, 7, 2, 1, 0));
	struct eo_reader_claim overflow = {};
	s.exec_inflight = ~0ULL;
	__u64 old_serial = s.serial;
	assert(eo_dispatch_claim_begin_locked(&s, &overflow, 1,
					      EO_READER_EXEC));
	assert(!overflow.owned && overflow.descriptor.execution_class == 1 &&
	       overflow.descriptor.generation == 1);
	assert(s.serial == old_serial + 1 && s.coverage_unknown &&
	       s.exec_inflight == ~0ULL);
	s.exec_inflight = 0;
	struct eo_reader_claim first = {}, second = {}, released = {};
	assert(!eo_dispatch_claim_begin_locked(&s, &first, 1,
					       EO_READER_AUTHORITY));
	assert(!eo_dispatch_claim_begin_locked(&s, &second, 2,
					       EO_READER_AUTHORITY));
	assert(eo_reader_take_locked(&first, 99, 98, 1, &released));
	assert(!eo_reader_take_locked(&first, 99, 99, 1, &released));
	assert(!eo_dispatch_claim_end_locked(&s, &released));
	assert(eo_reader_take_locked(&first, 99, 99, 1, &released));
	assert(s.authority_readers == 1 && s.bank_readers[0] == 1);
	assert(eo_candidate_snapshot_locked(&s, 7, 2));
	assert(!eo_reader_take_locked(&second, 99, 99, 2, &released));
	assert(!eo_dispatch_claim_end_locked(&s, &released));
	struct eo_dispatch_token reader = {};
	assert(!eo_dispatch_read_begin_locked(&s, &reader));
	__u64 epochs[8] = {};
	__u64 *targets[8];
	for (int i = 0; i < 8; i++)
		targets[i] = &epochs[i];
	assert(eo_candidate_arm_locked(&s, 7, 2, targets));
	assert(!eo_dispatch_read_end_locked(&s, &reader));
	assert(eo_candidate_arm_locked(
		&s, 7, 2, targets)); /* stale serial despite zero readers */
	assert(!eo_candidate_snapshot_locked(&s, 7, 2));
	s.candidate.inventory_count =
		1; /* Fixture: one independently staged task. */
	assert(!eo_candidate_certify_locked(&s, 7, 2, 1, 0));
	s.candidate.addition_count = 8;
	for (int i = 0; i < 8; i++) {
		s.candidate.additions[i].uid = i + 1;
		s.candidate.additions[i].epoch = 2;
	}
	targets[7] = 0;
	assert(eo_candidate_arm_locked(&s, 7, 2, targets));
	for (int i = 0; i < 8; i++)
		assert(epochs[i] == 0);
	assert(!memcmp(&active, &s.active, sizeof(active)));
	targets[7] = &epochs[7];
	assert(!eo_candidate_arm_locked(&s, 7, 2, targets));
	for (int i = 0; i < 8; i++)
		assert(epochs[i] == 2);
	assert(s.active.generation == 2 && s.active.program_bank == 1 &&
	       s.candidate.state == EO_CANDIDATE_COMMITTED);
	assert(!eo_candidate_arm_locked(&s, 7, 2,
					targets)); /* lost ACK reconciliation */
	s.active.execution_class = 2;
	assert(eo_candidate_arm_locked(&s, 7, 2, targets));
	s.active.execution_class = 1;
	assert(eo_candidate_abort_locked(&s, 7, 2));
	assert(!eo_candidate_begin_locked(&s, 7, 3, 16));
	assert(!eo_candidate_abort_locked(&s, 7, 3));
	assert(s.active.generation == 2 && s.session_cookie == 7);

	assert(!eo_candidate_begin_locked(&s, 7, 4, 11));
	assert(!eo_candidate_seal_begin_locked(&s, 7, 4));
	assert(!eo_candidate_seal_finish_locked(&s, 7, 4, 1, 1, 0, 0, 1));
	assert(!eo_candidate_snapshot_locked(&s, 7, 4));
	struct eo_writer_token stage_writer = {};
	struct eo_reader_claim stage_reader = {};
	struct eo_dispatch_descriptor stage_source = {};
	assert(!eo_candidate_stage_begin_locked(&s, 7, 4, &stage_writer,
						&stage_reader, &stage_source));
	assert(s.candidate.writers == 1 && s.mutation_writers == 1 &&
	       s.authority_readers == 1 && s.bank_readers[0] == 1 &&
	       s.bank_readers[1] == 1);
	assert(eo_candidate_abort_locked(&s, 7, 4));
	struct eo_writer_token stale_writer = stage_writer;
	struct eo_reader_claim stale_reader = stage_reader;
	assert(!eo_candidate_stage_end_locked(&s, &stage_writer, &stage_reader,
					      &stage_source));
	assert(!s.candidate.writers && !s.mutation_writers &&
	       !s.authority_readers && !s.bank_readers[0] &&
	       !s.bank_readers[1]);
	assert(!eo_candidate_stage_begin_locked(&s, 7, 4, &stage_writer,
						&stage_reader, &stage_source));
	assert(eo_candidate_stage_end_locked(&s, &stale_writer, &stale_reader,
					     &stage_source));
	assert(s.candidate.writers == 1 && s.mutation_writers == 1);
	struct eo_reader_claim admitted = {};
	assert(!eo_dispatch_claim_begin_locked(&s, &admitted, 91,
					       EO_READER_EXEC));
	assert(!eo_candidate_stage_end_locked(&s, &stage_writer, &stage_reader,
					      &stage_source));
	assert(s.exec_inflight == 1 &&
	       s.bank_readers[s.active.program_bank] == 1);
	assert(!eo_dispatch_claim_end_locked(&s, &admitted));
	assert(eo_candidate_certify_locked(&s, 7, 4, 1, 0));
	assert(!eo_candidate_snapshot_locked(&s, 7, 4));
	s.candidate.inventory_count =
		1; /* Fixture: one independently staged task. */
	assert(!eo_candidate_certify_locked(&s, 7, 4, 1, 0));
	return 0;
}
