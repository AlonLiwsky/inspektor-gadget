/* SPDX-License-Identifier: GPL-2.0 */
#ifndef GATEA_INGRESS_H
#define GATEA_INGRESS_H
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
#define IN_PIN 1
#define IN_BAD_PIN 2
#define IN_STAGE 3
#define IN_RETURN_TEST 4
#define IN_ABORT 5
#define IN_CANCEL_ARM 6
#define IN_CANCEL_RELEASE 7
#define IN_OVERLAP_ARM 8
#define IN_OVERLAP_ITERATIONS 65536
#define IN_OVERLAP_NS 10000000ULL
#define IN_ARM_BUSY 1
#define IN_ARM_STALE 2
#define IN_ARM_UNCERTAIN 4
#define IN_TOKENS 64
#define IN_AUDIT 0
#define IN_STRICT 1
struct in_config {
	__u64 nonce;
	__u32 tid, target_fd, control_fd, bad_fd, admin_cpu, creator_cpu;
};
struct in_command {
	__u64 nonce, attempt;
	__u32 operation, mode;
};
struct in_state {
	__u32 lock, pinned;
	__u64 admin_task, target_kn, control_kn, target_sb, control_sb;
	__u64 mode, active_attempt, pending_attempt, pending_mode;
	__u64 permission_hits, denials, audit_hits, inspection_errors, arms;
	__u64 last_sb, last_kn, last_tid, last_mask, wrong_control;
	__u64 hook_calls, prior_returns, zero_inputs, cgroup_inodes,
		write_requests, node_matches;
	__u64 observed_magic, observed_sb, observed_kn, observed_mask,
		observed_tid;
	__u64 serial, pending_serial, next_token, ingress_inflight, uncertain;
	__u64 ingress_admitted, ingress_completed, ingress_cancelled,
		unowned_completions;
	__u64 token_failures, arm_refusals, last_arm_reason;
	__u64 last_fact_cookie, last_fact_child, last_fact_kind;
	__u64 test_task, test_nonce, test_armed, signal_requests, signal_errors;
	__u64 overlap_nonce, overlap_ready, overlap_entry, overlap_release,
		overlap_exit, overlap_failed;
	__u64 overlap_used, overlap_creator_cpu, overlap_admin_cpu,
		overlap_child, overlap_cookie, overlap_inflight, overlap_serial,
		overlap_receipt, overlap_reason;
};
#endif
