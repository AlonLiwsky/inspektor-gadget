/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
struct bpf_spin_lock {
	__u32 val;
};
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define __noinline __attribute__((noinline))
struct fm_blob;
static inline const struct fm_blob *full_lookup_global(unsigned int);
#define FM_BLOB_LOOKUP(ctx, key) full_lookup_global(key)
#define FM_GLOBAL_BLOB_LOOKUP(key) full_lookup_global(key)
#include "evaluator.h"
/* ACTUAL_TYPES */
struct eo_work {
	__u64 busy;
	struct eo_reader_claim reader;
};
struct eo_task {
	struct bpf_spin_lock lock;
	struct {
		__u32 owned;
		__u64 owner_cookie, generation;
		struct eo_reader_claim reader;
	} exec;
};
static struct eo_dispatch dispatch;
static int eo_dispatch, eo_candidate_input;
static struct eo_candidate_input command_input;
static struct eo_seal_workspace seal_workspace;
static int eo_seal_work;
static struct eo_work work;
static struct eo_program_cell cells[2][16384];
static int eo_program_bank0, eo_program_bank1, inject_write, refused_writes,
	faults;
#define EO_FAULT_STATE 8
#define EO_BAD_STORAGE 5
#define EO_RETRY 9
#define EO_BAD_ROLES 8
#define EO_OK 0
static void *bpf_map_lookup_elem(void *map, const __u32 *key)
{
	if (map == &eo_dispatch)
		return &dispatch;
	if (map == &eo_candidate_input)
		return &command_input;
	if (map == &eo_seal_work) {
		assert(!*key);
		return &seal_workspace;
	}
	assert(*key < 16384);
	return &cells[map == &eo_program_bank1 ? 1 : 0][*key];
}
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
static void *bpf_get_current_task_btf(void)
{
	return 0;
}
static struct eo_task *eo_lookup_task(void *unused)
{
	(void)unused;
	return 0;
}
static struct eo_work *eo_borrow_work(void)
{
	return &work;
}
static struct eo_work *eo_get_work(void)
{
	if (work.busy)
		return 0;
	work.busy = 1;
	return &work;
}
static void eo_fault(int bit)
{
	faults |= bit;
}
#define EO_ABI 3
struct eo_config {
	__u64 cookie, cgroup;
	__u32 abi;
};
static struct eo_config config = { .cookie = 7, .abi = 3 };
static int eo_admin, admin_enabled = 1;
static __u64 admin_nonce = 7;
static struct eo_config *eo_config(void)
{
	return &config;
}
static void *bpf_task_storage_get(void *map, void *task, void *value,
				  __u64 flags)
{
	(void)task;
	(void)value;
	assert(map == &eo_admin && !flags);
	return admin_enabled ? &admin_nonce : 0;
}
/* ACTUAL_PHYSICAL_BLOB */
/* ACTUAL_CURRENT_BLOB */
/* ACTUAL_GLOBAL_BLOB */
/* ACTUAL_TRANSITIONS */
/* ACTUAL_PUT_WORK */
static long bpf_loop(__u32 count, long (*callback)(__u32, void *),
		     void *context, __u64 flags)
{
	assert(!flags);
	for (__u32 i = 0; i < count; i++) {
		if (inject_write && i == 1) {
			struct eo_writer_token writer = {};
			assert(work.busy && work.reader.owned &&
			       dispatch.bank_readers[1] == 1);
			assert(eo_candidate_write_begin_locked(&dispatch, 7, 2,
							       1, &writer));
			refused_writes++;
		}
		if (callback(i, context))
			return i + 1;
	}
	return count;
}
static int short_seal_loop;
static long seal_test_loop(unsigned int count,
			   long (*callback)(unsigned int, void *),
			   void *context)
{
	if (short_seal_loop) {
		short_seal_loop = 0;
		return count ? (long)count - 1 : -1;
	}
	return fm_c_loop(count, callback, context);
}
#undef FE_LOOP
#define FE_LOOP(count, callback, context) \
	seal_test_loop(count, callback, context)
/* ACTUAL_SEAL */
struct eo_health {
	__u64 authority_version, active_generation, ready_generation,
		a_complete, movement_armed, movement_fault;
};
struct eo_phase {
	__u64 committed_generation, candidate_generation, attempted_generation;
	__u32 state;
};
#define EO_IDLE 0
static int eo_epochs;
static __u64 accepted_entries;
static long bpf_for_each_map_elem(void *map,
				  long (*callback)(void *, const void *, void *,
						   void *),
				  void *context, __u64 flags)
{
	assert(map == &eo_epochs && !flags && !dispatch.lock.val);
	__u64 key = 11, value = 1;
	if (accepted_entries)
		callback(map, &key, &value, context);
	return accepted_entries ? 1 : 0;
}
/* ACTUAL_FRESH_SESSION */
/* ACTUAL_OPERATIONS */
/* NATIVE_OPERATION_ASSERTS */
#define EO_BAD_IDENTITY 2
#define eo_control_root(c, command, authorize) EO_OK
static int actual_candidate_io(__u32 operation)
{
	struct {
		__u32 operation;
		__u64 generation;
	} command = { operation, 2 };
	command_input =
		(struct eo_candidate_input){ .request = { .session_cookie = 7,
							  .attempt = 2,
							  .entries = 11,
							  .bank = 1,
							  .index = 0 } };
	const struct eo_config *c = &config;
	struct eo_health health = { .movement_armed = 1 }, *h = &health;
	struct eo_phase phase_value = {}, *phase = &phase_value;
	__u32 zero = 0;
	int result = EO_RETRY;
	/* ACTUAL_CANDIDATE_IO */
done:
	return result;
}
static void put(__u32 key, const void *data, size_t size)
{
	struct eo_candidate_input input = { .request = { .session_cookie = 7,
							 .attempt = 2,
							 .entries = 3,
							 .index = key,
							 .bank = 1 } };
	memcpy(input.data, data, size);
	assert(!eo_candidate_write_cell(&dispatch, &input.request, input.data,
					&cells[1][key]));
}
static void reset(int mode)
{
	memset(cells, 0, sizeof(cells));
	memset(&work, 0, sizeof(work));
	memset(&seal_workspace, 0, sizeof(seal_workspace));
	dispatch = (struct eo_dispatch){ .scope_state = EO_SCOPE_ACTIVE,
					 .session_cookie = 7,
					 .cgroup = 42,
					 .serial = 1,
					 .active = { .generation = 1,
						     .execution_class = 1,
						     .policy_count = 1,
						     .role_writer_mask = 1 } };
	inject_write = refused_writes = faults = 0;
	assert(!eo_candidate_begin_locked(&dispatch, 7, 2, 11));
	struct fe_header header = { .generation = 2,
				    .policies = 1,
				    .rules = 1,
				    .rule_base = 9,
				    .container = 16000 };
	struct fe_policy policy = {
		.uid = 1, .root_epoch = 2, .root_role = 10, .mode = 1
	};
	struct fe_rule rule = {
		.policy = 0, .mode = mode, .deny = 0, .set_role = 20
	};
	put(0, &header, sizeof(header));
	put(1, &policy, sizeof(policy));
	put(9, &rule, sizeof(rule));
	struct fm_blob empty = {};
	for (__u32 i = 2; i <= 8; i++)
		put(i, &empty, sizeof(empty));
	struct fe_string container = { .length = 3,
				       .bytes = { 'a', 'p', 'p' } };
	put(16000, &container, sizeof(container));
}
static void retained_seal_source(void)
{
	reset(2);
	work.busy = 1;
	assert(!eo_candidate_scan_begin_locked(&dispatch, 7, 2, &work.reader));
	struct eo_seal_source source = {};
	assert(!eo_seal_source_capture(&work, 7, 2, &source));
	assert(source.bank == 1 && source.attempt == 2);
	dispatch.active.program_bank =
		1; /* A later selector is not the read source. */
	__u32 mask = 0;
	assert(!eo_required_known_mask(2, &mask, &seal_workspace, source));
	struct eo_seal_source wrong = source;
	wrong.bank = 0;
	assert(eo_required_known_mask(2, &mask, &seal_workspace, wrong));
	wrong = source;
	wrong.attempt = 3;
	assert(eo_required_known_mask(2, &mask, &seal_workspace, wrong));

	assert(eo_program_blob(source.bank, 0, source.attempt) ==
	       (void *)cells[1][0].data);
	assert(!eo_program_blob(0, 0, source.attempt));
	assert(!eo_program_blob(source.bank, 0, 3));
	cells[1][0].attempt = 3;
	assert(!eo_program_blob(source.bank, 0, source.attempt));
	cells[1][0].attempt = 2;
	for (int fault = 0; fault < 8; fault++) {
		struct eo_reader_claim saved = work.reader;
		if (fault == 0)
			admin_nonce = 8;
		if (fault == 1)
			work.reader.session_cookie = 8;
		if (fault == 2)
			work.reader.kind = EO_READER_EXEC;
		if (fault == 3)
			work.reader.descriptor.program_bank = 2;
		if (fault == 4)
			work.reader.descriptor.generation = 3;
		if (fault == 5)
			work.reader.sequence = 3;
		if (fault == 6)
			work.busy = 0;
		if (fault == 7)
			work.reader.descriptor.reserved = 1;
		assert(eo_seal_source_capture(&work, 7, 2, &source));
		work.reader = saved;
		work.busy = 1;
		admin_nonce = 7;
	}
}

static void item_boundary_controls(void)
{
	reset(2);
	struct fm_blob value = {};
	struct eo_seal_workspace workspace = {};
	assert(eo_seal_value(0, &workspace, EO_SEAL_UID, 1, 2));
	assert(eo_seal_value(&value, 0, EO_SEAL_UID, 1, 2));
	assert(eo_seal_value(&value, &workspace, 99, 1, 2));
	assert(eo_seal_value(&value, &workspace, EO_SEAL_UID, 2, 2));
	assert(eo_seal_value(&value, &workspace, EO_SEAL_UID, 1, 0));
	assert(eo_seal_value(&value, &workspace, EO_SEAL_IDENTITY, 1, 2));
	value.words[0] = 0xffffffffULL;
	assert(!eo_seal_value(&value, &workspace, EO_SEAL_UID, 1, 2));
	value.words[0]++;
	assert(eo_seal_value(&value, &workspace, EO_SEAL_UID, 1, 2));
	value.words[0] = 1;
	value.words[35] = 1;
	assert(eo_seal_value(&value, &workspace, EO_SEAL_IDENTITY, 1, 2));
	value.words[35] = 0;
	assert(!eo_seal_value(&value, &workspace, EO_SEAL_IDENTITY, 1, 2));
	struct eo_seal_source source = { .bank = 1, .attempt = 2 };
	put(12, &value, sizeof(value));
	short_seal_loop = 1;
	assert(eo_seal_list((struct fe_list){ 12, 1 }, EO_SEAL_IDENTITY,
			    &workspace, source));
	assert(!short_seal_loop);
	assert(!eo_seal_list((struct fe_list){ 12, 1 }, EO_SEAL_IDENTITY,
			     &workspace, source));
	struct fm_pattern pattern = { .code_base = 13, .count = 1, .start = 0 };
	memset(&value, 0, sizeof(value));
	memcpy(&value, &pattern, sizeof(pattern));
	struct fm_instruction instruction = { .op = FM_MATCH };
	put(13, &instruction, sizeof(instruction));
	short_seal_loop = 1;
	assert(eo_seal_value(&value, &workspace, EO_SEAL_PATTERN, 1, 2));
	assert(!short_seal_loop);
	assert(!eo_seal_value(&value, &workspace, EO_SEAL_PATTERN, 1, 2));
}
int main(void)
{
	item_boundary_controls();
	retained_seal_source();
	/* COMPILED_DEPENDENCY_CASES */
	reset(2);
	assert(actual_candidate_io(EO_CANDIDATE_SEAL) == EO_OK);
	assert(dispatch.candidate.state == EO_CANDIDATE_SEALED &&
	       dispatch.candidate.sealed_class == 2);
	reset(2);
	struct eo_program_cell header = cells[1][0];
	assert(actual_candidate_io(EO_CANDIDATE_SEAL) == EO_OK);
	assert(!memcmp(&header, &cells[1][0], sizeof(header)));
	assert(actual_candidate_io(EO_CANDIDATE_ABORT) == EO_OK &&
	       dispatch.candidate.state == EO_CANDIDATE_ABORTED);
	reset(2);
	assert(actual_candidate_io(EO_CANDIDATE_BEGIN) == EO_RETRY &&
	       dispatch.candidate.state == EO_CANDIDATE_LOADING);
	assert(actual_candidate_io(EO_CANDIDATE_WRITE) == EO_OK &&
	       dispatch.candidate.state == EO_CANDIDATE_LOADING);
	assert(cells[1][0].attempt == 2 &&
	       !memcmp(cells[1][0].data, command_input.data, 288));

	for (int mode = 1; mode <= 2; mode++) {
		reset(mode);
		inject_write = 1;
		struct eo_dispatch_descriptor active = dispatch.active;
		assert(eo_seal_candidate(&dispatch, 7, 2) == EO_OK);
		assert(refused_writes == 1 &&
		       dispatch.candidate.state == EO_CANDIDATE_SEALED);
		assert(dispatch.candidate.sealed_class == (__u32)mode &&
		       dispatch.candidate.sealed_policy_count == 1 &&
		       dispatch.candidate.sealed_role_writer_mask == 1);
		assert(!memcmp(&active, &dispatch.active, sizeof(active)));
		assert(!work.busy && !work.reader.owned &&
		       !dispatch.authority_readers &&
		       !dispatch.bank_readers[1]);
	}
	reset(1);
	cells[1][9].attempt = 1;
	assert(eo_seal_candidate(&dispatch, 7, 2) == EO_BAD_ROLES);
	assert(dispatch.candidate.state == EO_CANDIDATE_ABORTED &&
	       !dispatch.candidate.sealed_class);
	assert(!work.busy && !work.reader.owned &&
	       !dispatch.authority_readers && !dispatch.bank_readers[1]);
	reset(0);
	assert(eo_seal_candidate(&dispatch, 7, 2) == EO_BAD_ROLES);
	assert(!work.busy && !work.reader.owned &&
	       !dispatch.authority_readers && !dispatch.bank_readers[1]);
	// Malformed but fully counted input must fail before publishing SEALED.
	for (int malformed = 0; malformed < 9; malformed++) {
		reset(2);
		struct fe_policy policy;
		memcpy(&policy, cells[1][1].data, sizeof(policy));
		struct fe_rule rule;
		memcpy(&rule, cells[1][9].data, sizeof(rule));
		if (malformed == 0) {
			rule.actor_role = (struct fe_list){ 16383, 1 };
			put(9, &rule, sizeof(rule));
		}
		if (malformed == 1) {
			policy.uid = 0;
			put(1, &policy, sizeof(policy));
		}
		if (malformed == 2) {
			policy.root_epoch = 0;
			put(1, &policy, sizeof(policy));
		}
		if (malformed == 3) {
			policy.root_epoch = 3;
			put(1, &policy, sizeof(policy));
		}
		if (malformed == 4) {
			rule.actor_role = (struct fe_list){ 1, 0 };
			put(9, &rule, sizeof(rule));
		}
		if (malformed == 5) {
			rule.actor_image = 2;
			put(9, &rule, sizeof(rule));
		}
		if (malformed == 6) {
			rule.actor_role = (struct fe_list){ 16383, 1 };
			put(9, &rule, sizeof(rule));
			__u64 role = 10;
			put(16383, &role, sizeof(role));
			cells[1][16383].attempt = 1;
		}
		if (malformed == 7) {
			struct fe_header header = { .generation = 2,
						    .policies = 2,
						    .rules = 1,
						    .rule_base = 9,
						    .container = 16000 };
			put(0, &header, sizeof(header));
			put(2, &policy, sizeof(policy));
			dispatch.candidate.entries = 11;
		}
		if (malformed == 8) {
			policy.root_role = 0;
			put(1, &policy, sizeof(policy));
		}
		struct eo_dispatch_descriptor before = dispatch.active;
		assert(eo_seal_candidate(&dispatch, 7, 2) == EO_BAD_ROLES);
		assert(dispatch.candidate.state == EO_CANDIDATE_ABORTED &&
		       !dispatch.candidate.sealed_class &&
		       !dispatch.candidate.required_known_mask);
		assert(!memcmp(&before, &dispatch.active, sizeof(before)) &&
		       !work.busy && !work.reader.owned &&
		       !dispatch.authority_readers &&
		       !dispatch.bank_readers[1]);
	}

	for (int malformed = 0; malformed < 4; malformed++) {
		reset(2);
		struct fe_rule rule;
		memcpy(&rule, cells[1][9].data, sizeof(rule));
		struct fm_blob value = {};
		if (malformed == 0 || malformed == 1) {
			rule.uid = (struct fe_list){ 100, 1 };
			value.words[0] = malformed == 0 ? 0x100000000ULL : 12;
			if (malformed == 1)
				value.words[1] = 1;
		} else {
			rule.arg_contains = (struct fe_list){ 100, 1 };
			struct fe_string string = { .length = 1 };
			string.bytes[0] = malformed == 2 ? 0 : 0xff;
			memcpy(&value, &string, sizeof(string));
		}
		put(9, &rule, sizeof(rule));
		put(100, &value, sizeof(value));
		dispatch.candidate.entries = 12;
		assert(eo_seal_candidate(&dispatch, 7, 2) == EO_BAD_ROLES);
		assert(dispatch.candidate.state == EO_CANDIDATE_ABORTED &&
		       !work.busy && !work.reader.owned &&
		       !dispatch.authority_readers &&
		       !dispatch.bank_readers[1]);
	}

	// A stamped descriptor is not proof that its bytecode exists or is valid.
	for (int malformed = 0; malformed < 3; malformed++) {
		reset(2);
		struct fe_rule rule;
		memcpy(&rule, cells[1][9].data, sizeof(rule));
		rule.actor_path = (struct fe_list){ 100, 1 };
		put(9, &rule, sizeof(rule));
		struct fm_pattern pattern = { .code_base = 101, .count = 1 };
		if (malformed == 1)
			pattern.start = 1;
		put(100, &pattern, sizeof(pattern));
		dispatch.candidate.entries = 12;
		if (malformed == 2) {
			struct fm_instruction instruction = { .op = 99 };
			put(101, &instruction, sizeof(instruction));
			dispatch.candidate.entries = 13;
		}
		assert(eo_seal_candidate(&dispatch, 7, 2) == EO_BAD_ROLES);
		assert(dispatch.candidate.state == EO_CANDIDATE_ABORTED &&
		       !work.busy && !work.reader.owned &&
		       !dispatch.authority_readers &&
		       !dispatch.bank_readers[1]);
	}

	// Distinct instruction keys, not reference count, define the 8192 budget.
	for (int variant = 0; variant < 3; variant++) {
		reset(2);
		__u32 patterns = variant == 0 ? 16 : 17;
		struct fe_rule rule;
		memcpy(&rule, cells[1][9].data, sizeof(rule));
		rule.actor_path = (struct fe_list){ 100, patterns };
		put(9, &rule, sizeof(rule));
		struct fm_instruction instruction = { .op = FM_MATCH };
		for (__u32 i = 0; i < patterns; i++) {
			__u32 base = 1000 + (variant == 2 ? 0 : i * 512);
			struct fm_pattern pattern = { .code_base = base,
						      .count = 512 };
			put(100 + i, &pattern, sizeof(pattern));
			for (__u32 pc = 0; pc < 512; pc++)
				put(base + pc, &instruction,
				    sizeof(instruction));
		}
		dispatch.candidate.entries =
			11 + patterns + (variant == 2 ? 512 : patterns * 512);
		assert(eo_seal_candidate(&dispatch, 7, 2) ==
		       (variant == 1 ? EO_BAD_ROLES : EO_OK));
		assert(!seal_workspace.busy && !seal_workspace.session_cookie &&
		       !seal_workspace.attempt);
		assert(seal_workspace.instructions ==
		       (variant == 2 ? 512 : 8192));
	}
	// Pattern occurrences are counted even when all descriptors share code.
	for (__u32 rules = 4; rules <= 5; rules++) {
		reset(2);
		struct fe_header header = { .generation = 2,
					    .policies = 1,
					    .rules = rules,
					    .rule_base = 9,
					    .container = 16000 };
		put(0, &header, sizeof(header));
		struct fe_rule rule = { .mode = 2,
					.actor_image = -1,
					.target_image = -1,
					.stdin_pipe = -1,
					.actor_path = { 100, 256 } };
		for (__u32 i = 0; i < rules; i++)
			put(9 + i, &rule, sizeof(rule));
		struct fm_pattern pattern = { .code_base = 1000, .count = 1 };
		for (__u32 i = 0; i < 256; i++)
			put(100 + i, &pattern, sizeof(pattern));
		struct fm_instruction instruction = { .op = FM_MATCH };
		put(1000, &instruction, sizeof(instruction));
		dispatch.candidate.entries = 10 + rules + 256 + 1;
		assert(eo_seal_candidate(&dispatch, 7, 2) ==
		       (rules == 4 ? EO_OK : EO_BAD_ROLES));
		assert(seal_workspace.patterns == 1024 && !seal_workspace.busy);
	}
	reset(2);
	seal_workspace.busy = 1;
	seal_workspace.session_cookie = 99;
	seal_workspace.attempt = 88;
	seal_workspace.seen[255] = 42;
	assert(eo_seal_candidate(&dispatch, 7, 2) == EO_BAD_STORAGE);
	assert(seal_workspace.busy == 1 &&
	       seal_workspace.session_cookie == 99 &&
	       seal_workspace.attempt == 88 && seal_workspace.seen[255] == 42);
	assert(!work.busy && dispatch.candidate.state == EO_CANDIDATE_LOADING);

	for (int malformed = 0; malformed < 5; malformed++) {
		reset(2);
		if (malformed < 3) {
			__u32 key = malformed == 0 ? 0 : malformed == 1 ? 1 : 9;
			struct fm_blob blob;
			memcpy(&blob, cells[1][key].data, sizeof(blob));
			blob.words[35] = 1;
			put(key, &blob, sizeof(blob));
		} else if (malformed == 3) {
			struct fe_rule rule;
			memcpy(&rule, cells[1][9].data, sizeof(rule));
			rule.fs_type = (struct fe_list){ 100, 1 };
			put(9, &rule, sizeof(rule));
			struct fe_string string = {
				.length = 3, .bytes = { 'b', 'a', 'd' }
			};
			put(100, &string, sizeof(string));
			dispatch.candidate.entries++;
		} else {
			struct fe_header header;
			memcpy(&header, cells[1][0].data, sizeof(header));
			header.container = 16383;
			put(0, &header, sizeof(header));
		}
		assert(eo_seal_candidate(&dispatch, 7, 2) == EO_BAD_ROLES);
		assert(!seal_workspace.busy && !work.busy);
	}

	dispatch = (struct eo_dispatch){};
	struct eo_health fresh_health = {};
	struct eo_phase fresh_phase = {};
	config.cgroup = 42;
	accepted_entries = 1;
	assert(eo_open_fresh_session(&dispatch, &config, &fresh_health,
				     &fresh_phase) == EO_RETRY);
	assert(!dispatch.scope_state && !fresh_health.authority_version);
	accepted_entries = 0;
	assert(eo_open_fresh_session(&dispatch, &config, &fresh_health,
				     &fresh_phase) == EO_OK);
	assert(dispatch.scope_state == EO_SCOPE_INACTIVE &&
	       fresh_health.authority_version == 1 &&
	       !dispatch.active.generation);
	assert(eo_open_fresh_session(&dispatch, &config, &fresh_health,
				     &fresh_phase) == EO_RETRY);
	fresh_health.authority_version = 0;
	assert(eo_open_fresh_session(&dispatch, &config, &fresh_health,
				     &fresh_phase) == EO_RETRY &&
	       !fresh_health.authority_version);
	dispatch = (struct eo_dispatch){};
	dispatch.candidate.additions[7].uid = 99;
	assert(eo_open_fresh_session(&dispatch, &config, &fresh_health,
				     &fresh_phase) == EO_RETRY &&
	       !fresh_health.authority_version);

	// Last legal instruction key must remain valid without index masking.
	reset(2);
	struct fe_rule edge_rule;
	memcpy(&edge_rule, cells[1][9].data, sizeof(edge_rule));
	edge_rule.actor_path = (struct fe_list){ 100, 1 };
	put(9, &edge_rule, sizeof(edge_rule));
	struct fm_pattern edge_pattern = { .code_base = 16383, .count = 1 };
	put(100, &edge_pattern, sizeof(edge_pattern));
	struct fm_instruction edge_instruction = { .op = FM_MATCH };
	put(16383, &edge_instruction, sizeof(edge_instruction));
	dispatch.candidate.entries = 13;
	assert(eo_seal_candidate(&dispatch, 7, 2) == EO_OK);
	assert(seal_workspace.instructions == 1 &&
	       seal_workspace.seen[255] == (1ULL << 63));
	reset(2);
	put(9, &edge_rule, sizeof(edge_rule));
	edge_pattern.count = 2;
	put(100, &edge_pattern, sizeof(edge_pattern));
	put(16383, &edge_instruction, sizeof(edge_instruction));
	dispatch.candidate.entries = 13;
	assert(eo_seal_candidate(&dispatch, 7, 2) == EO_BAD_ROLES);
	return 0;
}
