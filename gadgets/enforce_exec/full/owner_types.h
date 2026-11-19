/* SPDX-License-Identifier: GPL-2.0 */
/* Persistent-owner shared ABI. Included only by the owner image profile.
 * This file supplies storage/primitives, NOT bootstrap authority or Ready. */
#ifndef FULL_OWNER_TYPES_H
#define FULL_OWNER_TYPES_H
#include "../fullruntime/bpf/gate.h"
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
#define EO_ABI 3U
#else
#define EO_ABI 2U
#endif
#define EO_TASKS 4096U
#define EO_WORKS (EO_TASKS + 1U)
#define EO_VERIFIED 1U
#define EO_QUARANTINED 2U
#define EO_ROOT_GROUP 4U
#define EO_PENDING_BIRTH 8U
#define EO_FAULT_STORAGE 1ULL
#define EO_FAULT_CAPACITY 2ULL
#define EO_FAULT_LINEAGE 4ULL
#define EO_FAULT_STATE 8ULL
#define EO_FAULT_GATE 16ULL
#define EO_FAULT_VERSION 32ULL
#define EO_FAULT_AUTHORITY 64ULL
static __always_inline __u64 eo_accepted_epoch(__u64 uid);
#define ER_ACCEPTED_EPOCH(uid) eo_accepted_epoch(uid)
#include "epoch_roles.h"

#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* EO_DISPATCH_TYPES_BEGIN */
/* dispatch_lock owns this entire record. Lock order is cgroup_mutex ->
 * dispatch_lock; never acquire a task lock or call helpers while it is held. */
struct eo_dispatch_descriptor {
	__u64 generation;
	__u32 execution_class, program_bank, history_reserved, reserved;
	__u32 policy_count, role_writer_mask;
};
enum eo_reader_kind {
	EO_READER_AUTHORITY = 1,
	EO_READER_EXEC,
	EO_READER_FORK,
	EO_READER_INGRESS,
	EO_READER_MUTATION,
	EO_READER_CANDIDATE
};
struct eo_reader_claim {
	struct eo_dispatch_descriptor descriptor;
	__u64 session_cookie, sequence;
	__u32 owned, kind;
};
_Static_assert(sizeof(struct eo_reader_claim) == 56, "reader claim ABI");
enum eo_candidate_state {
	EO_CANDIDATE_NONE = 0,
	EO_CANDIDATE_LOADING,
	EO_CANDIDATE_SEALING,
	EO_CANDIDATE_SEALED,
	EO_CANDIDATE_STAGING,
	EO_CANDIDATE_CERTIFIED,
	EO_CANDIDATE_COMMITTED,
	EO_CANDIDATE_ABORTED
};
struct eo_candidate_addition {
	__u64 uid, epoch;
};
struct eo_candidate {
	__u64 attempt, receipt_serial, inventory_count, writers, write_sequence;
	__u64 pass_id, pass_start_serial;
	struct eo_dispatch_descriptor expected;
	__u32 state, program_bank, history_reserved, sealed_class;
	__u32 entries, required_known_mask, addition_count,
		certified_known_mask;
	__u32 sealed_policy_count, sealed_role_writer_mask;
	struct eo_candidate_addition additions[8];
};
enum eo_scope_state {
	EO_SCOPE_UNINITIALIZED = 0,
	EO_SCOPE_INACTIVE,
	EO_SCOPE_ACTIVE
};
struct eo_dispatch {
	struct bpf_spin_lock lock;
	__u32 scope_state;
	__u64 session_cookie, cgroup, serial, last_attempt;
	struct eo_dispatch_descriptor active;
	__u64 exec_inflight, fork_inflight, ingress_inflight, mutation_writers;
	__u64 authority_readers, bank_readers[2];
	__u64 integrity_fault, coverage_unknown;
	struct eo_candidate candidate;
};
/* Stack-owned borrowed token; copies do not create extra release authority. */
struct eo_writer_token {
	__u64 session_cookie, attempt, sequence;
	__u32 bank, owned;
};
struct eo_dispatch_token {
	__u64 session_cookie, attempt;
	__u32 bank, owned;
};
_Static_assert(sizeof(struct eo_dispatch_descriptor) == 32,
	       "dispatch descriptor ABI");
_Static_assert(sizeof(struct eo_candidate) == 256, "candidate lease ABI");
_Static_assert(sizeof(struct eo_dispatch) == 400, "scope dispatch ABI");
_Static_assert(sizeof(struct eo_dispatch_token) == 24,
	       "borrowed dispatch token ABI");
struct eo_candidate_request {
	__u64 session_cookie, attempt;
	__u32 entries, reserved, index, bank;
};
struct eo_candidate_input {
	struct eo_candidate_request request;
	unsigned char data[288];
};
struct eo_seal_workspace {
	__u64 busy, session_cookie, attempt;
	__u32 patterns, instructions;
	__u64 seen[256];
};
_Static_assert(sizeof(struct eo_seal_workspace) == 2080, "seal workspace ABI");
struct eo_program_cell {
	__u64 attempt;
	unsigned char data[288];
};
_Static_assert(sizeof(struct eo_candidate_request) == 32,
	       "candidate request ABI");
_Static_assert(sizeof(struct eo_candidate_input) == 320, "candidate input ABI");
_Static_assert(sizeof(struct eo_program_cell) == 296, "program cell ABI");
_Static_assert(sizeof(struct eo_writer_token) == 32, "writer token ABI");
/* EO_DISPATCH_TYPES_END */
#endif

struct eo_config {
	__u64 cookie, cgroup;
	__u32 init_host_pid, task_limit, gate_slot, abi;
};
struct eo_command {
	__u64 nonce, generation, root_cookie;
	__u32 operation, new_uid_mask;
};
enum eo_operation {
	EO_INVENTORY = 1,
	EO_ROOT_AUTHORIZE = 2,
	EO_ROOT_CHECK = 3,
	EO_BOOTSTRAP_A = 4,
	EO_BOOTSTRAP_B = 5,
	EO_VALIDATE = 6,
	EO_PUBLICATION_BEGIN = 7,
	EO_PUBLICATION_COMMITTED = 8,
	EO_BOOTSTRAP_ABORT = 9,
	EO_PHASE_CLEAR = 10,
	EO_RETIRE = 11,
	EO_REATTEST = 12,
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	EO_SESSION_OPEN = 13,
	EO_CANDIDATE_BEGIN = 14,
	EO_CANDIDATE_ABORT = 15,
	EO_CANDIDATE_WRITE = 16,
	EO_CANDIDATE_SEAL = 17,
#endif
};
enum eo_result {
	EO_OK = 0,
	EO_BAD_CONFIG = 1,
	EO_BAD_IDENTITY = 2,
	EO_BAD_ITERATOR = 3,
	EO_LIMIT = 4,
	EO_BAD_STORAGE = 5,
	EO_MOVEMENT = 6,
	EO_LINEAGE = 7,
	EO_BAD_ROLES = 8,
	EO_RETRY = 9,
	EO_BAD_COMMAND = 10,
};
struct eo_health {
	__u64 task_credits, work_credits, authority_version, a_complete,
		ready_generation;
	__u64 active_generation, movement_sequence, movement_armed,
		movement_fault;
	// pending_births counts executing observer invocations, NOT unresolved tasks.
	__u64 faults, pending_births, gate_denials, root_cookie;
	__u32 count, result, retired, busy, root_match, padding;
};
enum eo_phase_kind {
	EO_IDLE = 0,
	EO_STAGING = 1,
	EO_VALIDATED = 2,
	EO_PUBLISHING = 3,
	EO_COMMITTED = 4,
	EO_STOPPED = 5
};
struct eo_phase {
	__u64 busy, attempted_generation, candidate_generation;
	__u32 state, new_uid_mask;
	__u64 committed_generation, validated_movement_sequence;
};
struct eo_anchor {
	__u64 group, cookie;
};
struct eo_row {
	__u64 cookie;
	__u32 tid, tgid, flags, valid_roles;
};
struct eo_exec_tx {
	__u64 bprm, cgroup, generation, owner_cookie;
	__u32 owned, slot, suppress, checks;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	/* Owned by the task lock; reset only on a new transaction or matching finish. */
	__u32 execution_class, role_uncertain_mask, role_write_mask;
	__u32 global_deny_unknown, known_deny_seen, policy_count;
	__u32 enforced_write_mask, role_conflict_mask;
#endif
	struct er_row pending[ER_ACTIVE];
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	struct eo_reader_claim reader;
#endif
};
struct eo_fork_tx {
	__u64 child, cgroup, owner_cookie;
	__u32 owned, slot;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	struct eo_reader_claim reader;
#endif
};
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
struct eo_stage_stamp {
	__u64 attempt, pass_id, task_cookie, fact_version, prior_generation,
		pass_start_serial;
	__u32 eligibility_flags, staged_new_uid_mask, required_known_mask,
		reserved;
};
_Static_assert(sizeof(struct eo_stage_stamp) == 64,
	       "canonical stage stamp ABI");
#endif
struct eo_task {
	struct bpf_spin_lock lock;
	__u32 flags;
	__u64 cookie;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	__u64 invocation_sequence;
#endif
	struct er_state committed;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	struct eo_stage_stamp staged;
#endif
	struct eo_exec_tx exec;
	struct eo_fork_tx fork;
};
struct eo_work {
	__u64 busy;
	struct er_work merge;
	struct er_state source;
	struct er_candidate candidate;
	__u64 authority, a_epoch;
	__u32 source_flags, padding;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	struct eo_reader_claim reader;
	struct eo_dispatch_descriptor source_descriptor;
	struct er_canonical_view view;
	struct er_fact_patch patch;
	struct eo_stage_stamp stage_request;

#endif
};
_Static_assert(sizeof(struct eo_config) == 32, "owner config ABI");
_Static_assert(sizeof(struct eo_command) == 32, "owner command ABI");
_Static_assert(sizeof(struct eo_health) == 128, "owner health ABI");
_Static_assert(sizeof(struct eo_phase) == 48, "owner phase ABI");
_Static_assert(sizeof(struct eo_anchor) == 16, "owner anchor ABI");
_Static_assert(sizeof(struct eo_row) == 24, "owner row ABI");
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
_Static_assert(sizeof(struct eo_exec_tx) == 392, "development exec ABI");
_Static_assert(__builtin_offsetof(struct eo_exec_tx, pending) == 80,
	       "development pending ABI");
_Static_assert(sizeof(struct er_state) == 520, "development state ABI");
_Static_assert(sizeof(struct er_work) == 536, "development merge ABI");
_Static_assert(__builtin_offsetof(struct eo_exec_tx, enforced_write_mask) == 72,
	       "development enforced provenance ABI");
_Static_assert(__builtin_offsetof(struct eo_exec_tx, role_conflict_mask) == 76,
	       "development conflict provenance ABI");
_Static_assert(sizeof(struct eo_task) == 1088, "development task ABI");
_Static_assert(sizeof(struct eo_work) == 2648, "development work ABI");
#else
_Static_assert(sizeof(struct eo_exec_tx) == 240, "owner exec ABI");
_Static_assert(sizeof(struct eo_task) == 680, "owner task ABI");
_Static_assert(sizeof(struct eo_work) == 1096, "owner work ABI");
#endif
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
_Static_assert(sizeof(struct eo_fork_tx) == 88, "development fork ABI");
#else
_Static_assert(sizeof(struct eo_fork_tx) == 32, "owner fork ABI");
#endif
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* One permanent scope record; userspace cannot write its lock or authority. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct eo_dispatch);
} eo_dispatch SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct eo_candidate_input);
} eo_candidate_input SEC(".maps");
/* One exclusive validation workspace per Scope, never per task. Physical map
 * allocation/native handle charges remain part of the development resource proof. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct eo_seal_workspace);
} eo_seal_work SEC(".maps");
/* Permanent banks: no native map replacement after session construction. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct eo_program_cell);
} eo_program_bank0 SEC(".maps"), eo_program_bank1 SEC(".maps");

#endif
struct eo_inner {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u8[288]);
};
struct eo_inner eo_template SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, struct eo_inner);
} eo_programs SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
#else
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
#endif
	__type(key, __u64);
	__type(value, __u64);
} eo_epochs SEC(".maps");
// Per-revision observation failures do not erase trusted task roles or poison
// a repaired revision forever. Only one generation can have admitted work at a
// time; old-generation writers drain before publication. LRU eviction therefore
// cannot discard the active generation in favor of later/older writers.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 64);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, __u64);
} eo_generation_faults SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct eo_config);
} eo_configuration SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct eo_command);
} eo_commands SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct eo_health);
} eo_health SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct eo_phase);
} eo_phase SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_WRONLY);
	__type(key, __u32);
	__type(value, struct eo_anchor);
} eo_anchor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, EO_TASKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct eo_row);
} eo_rows SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, __u64);
} eo_gates SEC(".maps");
// TASK_STORAGE containing a spin lock cannot be frozen on the pinned kernel.
// Keep only a frozen physical cookie there. Stateful spin-locked rows live in a
// kernel-writable, UAPI-read-only lifetime hash; rows/credits never recycle.
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} eo_task_ids SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EO_TASKS);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct eo_task);
} eo_tasks SEC(".maps");
// Raw bytes deliberately carry NO spin-lock BTF field: this immutable zero source
// can be frozen, and is only copied into a fresh (NOEXIST) state-hash entry.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u8[sizeof(struct eo_task)]);
} eo_zero_task SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct eo_work);
} eo_work SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} eo_admin SEC(".maps");
// Observed creator PID-object identity is never exported or inferred from PPid.
// Native holds the authorized root proc/PID pin before any births can be observed.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EO_TASKS);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_WRONLY);
	__type(key, __u64);
	__type(value, __u64);
} eo_birth_groups SEC(".maps");

extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;
extern struct cgroup *bpf_cgroup_from_id(__u64 id) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgroup) __ksym;
extern int bpf_iter_css_task_new(struct bpf_iter_css_task *,
				 struct cgroup_subsys_state *,
				 unsigned int) __ksym;
extern struct task_struct *
bpf_iter_css_task_next(struct bpf_iter_css_task *) __ksym;
extern void bpf_iter_css_task_destroy(struct bpf_iter_css_task *) __ksym;
static __always_inline struct eo_config *eo_config(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&eo_configuration, &k);
}
static __always_inline struct eo_health *eo_status(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&eo_health, &k);
}
static __always_inline struct eo_phase *eo_phase_state(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&eo_phase, &k);
}
static __always_inline struct eo_anchor *eo_root(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&eo_anchor, &k);
}
static __always_inline void eo_fault(__u64 bit)
{
	struct eo_health *h = eo_status();
	if (h)
		__sync_fetch_and_or(&h->faults, bit);
}
static __always_inline void eo_data_fault(__u64 generation, __u64 bit)
{
	if (!generation || generation == ER_UNKNOWN) {
		eo_fault(EO_FAULT_STATE);
		return;
	}
	__u64 *value = bpf_map_lookup_elem(&eo_generation_faults, &generation);
	if (!value) {
		bpf_map_update_elem(&eo_generation_faults, &generation, &bit,
				    BPF_NOEXIST);
		value = bpf_map_lookup_elem(&eo_generation_faults, &generation);
	}
	if (!value) {
		eo_fault(EO_FAULT_STORAGE);
		return;
	}
	__sync_fetch_and_or(value, bit);
}
static __always_inline __u64 eo_accepted_epoch(__u64 uid)
{
	struct eo_health *h = eo_status();
	if (!h || !h->authority_version || h->retired)
		return ER_UNKNOWN;
	__u64 *v = bpf_map_lookup_elem(&eo_epochs, &uid);
	return v ? *v : 0;
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
static __always_inline struct eo_dispatch *eo_dispatch_state(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&eo_dispatch, &zero);
}
/* EO_PHYSICAL_BLOB_BEGIN */
static __always_inline const struct fm_blob *
eo_program_blob(__u32 bank, __u32 key, __u64 generation)
{
	if (bank > 1 || key >= 16384 || !generation)
		return 0;
	const struct eo_program_cell *cell =
		bank ? bpf_map_lookup_elem(&eo_program_bank1, &key) :
		       bpf_map_lookup_elem(&eo_program_bank0, &key);
	return cell && cell->attempt == generation ? (const void *)cell->data :
						     0;
}
/* EO_PHYSICAL_BLOB_END */
#endif
static __always_inline const struct fm_blob *eo_blob(__u32 slot, __u32 key)
{
	if (slot > 1 || key >= 16384)
		return 0;
	void *inner = bpf_map_lookup_elem(&eo_programs, &slot);
	if (!inner)
		return 0;
	return bpf_map_lookup_elem(inner, &key);
}
// Credit reservations never recycle, including failed allocation/races. This
// bounds deferred task-storage allocations, not merely the live task count.
static __always_inline __u64 eo_credit(__u64 *counter, __u64 limit)
{
	for (int i = 0; i < 64; i++) {
		__u64 old = __sync_val_compare_and_swap(counter, 0, 0);
		if (old >= limit)
			return 0;
		if (__sync_val_compare_and_swap(counter, old, old + 1) == old)
			return old + 1;
	}
	return 0;
}
static __always_inline struct eo_task *eo_lookup_task(struct task_struct *task)
{
	__u64 *identity = bpf_task_storage_get(&eo_task_ids, task, 0, 0);
	if (!identity)
		return 0;
	__u64 cookie = __sync_val_compare_and_swap(identity, 0, 0);
	if (!cookie)
		return 0;
	return bpf_map_lookup_elem(&eo_tasks, &cookie);
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
static __always_inline struct eo_work *eo_borrow_work(void)
{
	return bpf_task_storage_get(&eo_work, bpf_get_current_task_btf(), 0, 0);
}
/* EO_CURRENT_BLOB_BEGIN */
static __always_inline int eo_current_admin(__u64 cookie)
{
	__u64 *nonce = bpf_task_storage_get(&eo_admin,
					    bpf_get_current_task_btf(), 0, 0);
	return nonce && *nonce == cookie;
}

/* The retained claim, never the mutable active selector, identifies every
 * evaluator callback's bank. Admin SEAL/control owns exclusive work storage. */
static __always_inline const struct fm_blob *eo_current_blob(__u32 key)
{
	struct eo_config *c = eo_config();
	if (!c || !c->cookie || c->abi != EO_ABI)
		return 0;
	struct eo_dispatch_descriptor descriptor = {};
	struct eo_work *w = eo_borrow_work();
	if (w && w->busy && w->reader.owned == 1) {
		if (w->reader.session_cookie != c->cookie ||
		    (w->reader.kind != EO_READER_CANDIDATE &&
		     w->reader.kind != EO_READER_AUTHORITY) ||
		    !eo_current_admin(c->cookie))
			return 0;
		descriptor = w->reader.descriptor;
	} else {
		struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
		if (!s)
			return 0;
		bpf_spin_lock(&s->lock);
		if (s->exec.owned && s->exec.reader.owned == 1 &&
		    s->exec.reader.kind == EO_READER_EXEC &&
		    s->exec.owner_cookie == c->cookie &&
		    s->exec.reader.session_cookie == c->cookie &&
		    s->exec.reader.descriptor.generation == s->exec.generation)
			descriptor = s->exec.reader.descriptor;
		bpf_spin_unlock(&s->lock);
	}
	if (!descriptor.generation || descriptor.reserved ||
	    descriptor.history_reserved)
		return 0;
	return eo_program_blob(descriptor.program_bank, key,
			       descriptor.generation);
}
/* EO_CURRENT_BLOB_END */
#endif
static __always_inline struct eo_task *eo_get_task(struct task_struct *task)
{
	__u64 *identity = bpf_task_storage_get(&eo_task_ids, task, 0, 0);
	if (identity) {
		__u64 cookie = __sync_val_compare_and_swap(identity, 0, 0);
		if (cookie)
			return bpf_map_lookup_elem(&eo_tasks, &cookie);
	}
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || !c->cookie || c->abi != EO_ABI || !c->task_limit ||
	    c->task_limit > EO_TASKS)
		return 0;
	__u64 cookie = eo_credit(&h->task_credits, c->task_limit);
	if (!cookie) {
		eo_fault(EO_FAULT_CAPACITY);
		return 0;
	}
	if (!identity)
		identity = bpf_task_storage_get(&eo_task_ids, task, 0,
						BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!identity) {
		eo_fault(EO_FAULT_STORAGE);
		return 0;
	}
	__u32 zero = 0;
	const void *empty = bpf_map_lookup_elem(&eo_zero_task, &zero);
	if (!empty ||
	    bpf_map_update_elem(&eo_tasks, &cookie, empty, BPF_NOEXIST)) {
		eo_fault(EO_FAULT_STORAGE);
		return 0;
	}
	struct eo_task *s = bpf_map_lookup_elem(&eo_tasks, &cookie);
	if (!s) {
		eo_fault(EO_FAULT_STORAGE);
		return 0;
	}
	s->cookie = cookie;
	// Publish identity only AFTER its complete zero state exists. A losing creator
	// retains its allocated row/credit, never overwrites/recycles the winner.
	__u64 winner = __sync_val_compare_and_swap(identity, 0, cookie);
	if (winner)
		return bpf_map_lookup_elem(&eo_tasks, &winner);
	return s;
}
static __always_inline struct eo_work *eo_get_work(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct eo_work *w = bpf_task_storage_get(&eo_work, task, 0, 0);
	if (!w) {
		struct eo_health *h = eo_status();
		if (!h || !eo_credit(&h->work_credits, EO_WORKS)) {
			eo_fault(EO_FAULT_CAPACITY);
			return 0;
		}
		w = bpf_task_storage_get(&eo_work, task, 0,
					 BPF_LOCAL_STORAGE_GET_F_CREATE);
	}
	if (!w) {
		eo_fault(EO_FAULT_STORAGE);
		return 0;
	}
	if (__sync_val_compare_and_swap(&w->busy, 0, 1)) {
		eo_fault(EO_FAULT_STATE);
		return 0;
	}
	return w;
}
static __always_inline void eo_put_work(struct eo_work *w)
{
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	if (w->reader.owned) {
		eo_fault(EO_FAULT_STATE);
		return;
	}
	w->reader = (struct eo_reader_claim){};
#endif
	__sync_lock_test_and_set(&w->busy, 0);
}
static __always_inline __u64 eo_group(struct task_struct *task)
{
	__u64 group = 0;
	if (BPF_CORE_READ_INTO(&group, task, signal, pids[PIDTYPE_TGID]))
		return 0;
	return group;
}
static __always_inline int eo_admin_authorized(const struct eo_command *command)
{
	struct eo_config *c = eo_config();
	if (!c || c->abi != EO_ABI || !c->cookie || command->nonce != c->cookie)
		return 0;
	__u64 *nonce = bpf_task_storage_get(&eo_admin,
					    bpf_get_current_task_btf(), 0, 0);
	return nonce && *nonce == c->cookie;
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
static __always_inline int eo_mutation_begin(struct eo_reader_claim *claim);
static __always_inline void eo_mutation_end(struct eo_reader_claim *claim);
#endif
// This is the ONLY historical adoption proof: exact pinned init group, or an
// actual observed direct-root birth. Other descendants must already carry a
// kernel-verified creator chain; current ancestry/cgroup membership is not proof.
static __always_inline int eo_lineage(struct task_struct *task,
				      struct eo_task *s)
{
	__u32 flags;
	bpf_spin_lock(&s->lock);
	flags = s->flags;
	bpf_spin_unlock(&s->lock);
	if (flags & EO_QUARANTINED)
		return 0;
	if (flags & EO_VERIFIED)
		return 1;
	struct eo_anchor *a = eo_root();
	if (!a || !a->group)
		return 0;
	__u64 group = eo_group(task), cookie = s->cookie;
	__u64 *creator = bpf_map_lookup_elem(&eo_birth_groups, &cookie);
	int root_group = group && group == a->group;
	if (!root_group && (!creator || *creator != a->group))
		return 0;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	struct eo_reader_claim mutation = {};
	if (eo_mutation_begin(&mutation))
		return 0;
#endif
	int result = 0, overflow = 0;
	bpf_spin_lock(&s->lock);
	if (!(s->flags & EO_QUARANTINED)) {
		if (s->committed.version >= ER_UNKNOWN - 1)
			overflow = 1;
		else if (s->flags & EO_VERIFIED)
			result = 1;
		else {
			s->flags |= EO_VERIFIED;
			if (root_group)
				s->flags |= EO_ROOT_GROUP;
			s->flags &= ~EO_PENDING_BIRTH;
			s->committed.version++;
			result = 1;
		}
	}
	bpf_spin_unlock(&s->lock);
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	eo_mutation_end(&mutation);
#endif
	if (overflow)
		eo_fault(EO_FAULT_VERSION);
	return result;
}
static __always_inline void eo_quarantine(struct eo_task *s)
{
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	struct eo_reader_claim mutation = {};
	if (eo_mutation_begin(&mutation)) {
		eo_fault(EO_FAULT_STATE);
		return;
	}
#endif
	int overflow = 0;
	bpf_spin_lock(&s->lock);
	if (!(s->flags & EO_QUARANTINED)) {
		s->flags |= EO_QUARANTINED;
		if (s->committed.version >= ER_UNKNOWN - 1)
			overflow = 1;
		else
			s->committed.version++;
	}
	bpf_spin_unlock(&s->lock);
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	eo_mutation_end(&mutation);
#endif
	eo_fault(overflow ? EO_FAULT_VERSION : EO_FAULT_LINEAGE);
}
// Force concrete local BTF for custom map values without kernel-target field
// relocations. A custom preserve_access_index annotation would wrongly relocate
// these records against vmlinux. The command entry calls this before any work.
static __always_inline int eo_local_types(void)
{
	return bpf_core_type_id_local(struct eo_config) &&
	       bpf_core_type_id_local(struct eo_command) &&
	       bpf_core_type_id_local(struct eo_health) &&
	       bpf_core_type_id_local(struct eo_phase) &&
	       bpf_core_type_id_local(struct eo_anchor) &&
	       bpf_core_type_id_local(struct eo_row) &&
	       bpf_core_type_id_local(struct eo_task) &&
	       bpf_core_type_id_local(struct eo_work);
}
// Implemented by owner_roles.h; every publication is under its task lock after
// task+authority version validation. No accepted role is initialized from absence.
static __always_inline int eo_stage_task(struct task_struct *, struct eo_task *,
					 struct eo_work *, __u32);
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
static __always_inline int eo_stage_candidate_task(struct task_struct *,
						   struct eo_task *,
						   struct eo_work *, __u32);
#endif
static __always_inline int eo_validate_task(struct eo_task *, struct eo_work *);
static __always_inline int eo_load_candidate(struct eo_work *, __u32, __u32);
struct fe_facts;
struct fe_decision;
// Main LSM adapter contract: begin 0=outside,1=admitted,negative=operational
// denial; generation is the latched original generation when known.
static __always_inline int eo_exec_begin(struct linux_binprm *, __u64 *);
static __always_inline int eo_fill_roles(struct fe_facts *);
static __always_inline int eo_exec_propose(struct linux_binprm *,
					   const struct fe_decision *);
static __always_inline void eo_exec_suppress(void);
#endif
