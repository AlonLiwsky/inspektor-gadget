/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RESOURCE_SHAPE_H
#define RESOURCE_SHAPE_H
#ifndef __VMLINUX_H__
#include <linux/types.h>
#include <linux/bpf.h>
#endif
/* Reuse real evaluator record definitions, not fabricated byte padding. */
#define FM_BLOB_LOOKUP(ctx, key) \
	((void)(ctx), (void)(key), (const struct fm_blob *)0)
#include "../../../fullpolicy/bpf/evaluator.h"
struct rs_role {
	__u64 uid, root_epoch, role;
	__u32 knowledge, reserved;
};
struct rs_bank {
	__u64 stamp, task_cookie, version;
	struct rs_role rows[16];
};
struct rs_descriptor {
	__u64 generation;
	__u32 program_bank, role_bank, mode, reserved;
};
struct rs_lineage {
	__u64 scope_cookie, root_cookie, creator_cookie, creator_group,
		root_group, certificate_serial, origin_epoch;
	__u32 kind, flags;
};
struct rs_authority {
	__u64 uid, epoch, root;
	__u32 new_uid, reserved;
};
struct rs_view {
	__u32 count, reserved;
	struct rs_authority active[8];
};
struct rs_merge {
	__u64 base_version, authority_version;
	int error;
	__u32 prepared;
	struct rs_role rows[16];
};
struct rs_work {
	__u64 busy;
	struct rs_merge merge;
	struct rs_bank source;
	struct rs_view candidate;
	__u64 authority, a_epoch;
	__u32 source_flags, reserved;
};
struct rs_exec {
	struct rs_descriptor descriptor;
	__u64 session_cookie, task_cookie, sequence, bprm, cgroup, base_version;
	__u32 owned, suppress, checks, unknown_mask;
	struct rs_role pending[8];
};
struct rs_fork {
	struct rs_descriptor descriptor;
	__u64 session_cookie, owner_cookie, sequence, child, child_cookie,
		cgroup;
	__u32 owned, flags;
};
struct rs_ingress {
	__u64 child, child_cookie, creator, creator_cookie, nonce, target,
		generation;
	__u32 owned, completion;
};
struct rs_task {
	struct bpf_spin_lock lock;
	__u32 lifecycle;
	__u64 cookie, invocation_sequence;
	__u32 owns_capacity, prefix_flags;
	struct rs_lineage lineage;
	struct rs_bank bank[2];
	struct rs_exec exec;
	struct rs_fork fork;
	struct rs_ingress ingress;
	struct rs_work work;
};
struct rs_observation {
	struct fe_facts facts;
	struct fe_scratch scratch;
	char argument[4097];
};
struct rs_chunk {
	__u64 attempt;
	struct fm_blob data;
};
struct rs_addition {
	__u64 uid, epoch;
};
struct rs_candidate {
	__u64 attempt;
	__u32 state, program_bank, role_bank, mode;
	__u64 writers, sealed_coverage, receipt_serial, inventory_count,
		required_known_mask;
	struct rs_descriptor expected_active;
	struct rs_addition additions[8];
};
struct rs_scope {
	struct bpf_spin_lock lock;
	__u32 integrity_flags;
	__u64 session_cookie, serial, next_task_cookie, last_attempt;
	struct rs_descriptor active;
	__u64 exec_inflight, fork_inflight, ingress_inflight, mutation_writers,
		authority_readers, retained_tasks, capacity_refusals,
		observation_faults, occupied_catalogue, accepted_catalogue;
	struct rs_candidate candidate;
	__u64 control_kn, target_kn, admin_task, initial_barrier, prefix_epoch,
		movement_sequence;
};
struct rs_config {
	__u64 cookie, cgroup, nonce;
	__u32 tid, target_fd, control_fd, task_limit, max_observations, abi;
};
struct rs_command {
	__u64 cookie, attempt, nonce;
	__u32 op, bank, index, length;
	struct fm_blob payload;
};
struct rs_inventory {
	__u64 cookie, version, generation;
	__u32 tid, tgid, flags, known_mask;
};
struct rs_observation_key {
	__u64 task, sequence;
};
#define SIZE(T, N) _Static_assert(sizeof(struct T) == N, #T " shape")
SIZE(rs_role, 32);
SIZE(rs_bank, 536);
SIZE(rs_descriptor, 24);
SIZE(rs_lineage, 64);
SIZE(rs_work, 1368);
SIZE(rs_exec, 344);
SIZE(rs_fork, 80);
SIZE(rs_ingress, 64);
SIZE(rs_task, 3024);
SIZE(rs_observation, 15936);
SIZE(rs_chunk, 296);
SIZE(rs_candidate, 216);
SIZE(rs_scope, 408);
SIZE(rs_config, 48);
SIZE(rs_command, 328);
SIZE(rs_inventory, 40);
#undef SIZE
#endif
