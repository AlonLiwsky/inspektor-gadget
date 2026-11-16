/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_REAPER_WIRE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_REAPER_WIRE_CANDIDATE_H
/* Candidate-only request/control/receipt ABI shared by typed and opaque
 * owners. Wire reuse does not select either reaper as a product entrypoint. */
#if !defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE)
#error "reaper wire is candidate-only"
#endif
#ifndef offsetof
#define offsetof(T, F) __builtin_offsetof(T, F)
#endif

struct se_pool_request {
	__u32 abi, operation;
	__u64 node_incarnation, admin_generation, reap_sequence;
	__u32 task_budget, work_budget;
	__u64 expected_epoch, reserved0, reserved1;
};
struct se_pool_control {
	struct bpf_spin_lock lock;
	__u32 flags;
	__u64 node_incarnation, last_admin_generation, last_reap_sequence,
		scan_epoch;
	__u32 task_cursor, work_cursor;
	__u64 task_visits, work_visits;
};
struct se_pool_receipt {
	__u32 abi, status;
	__u64 node_incarnation, admin_generation, reap_sequence, epoch_before,
		epoch_after;
	__u32 task_before, task_after, work_before, work_after, task_examined,
		work_examined, task_reclaimed, work_reclaimed, task_pending,
		work_pending, task_faults, work_faults;
	__u64 bytes_zeroed, stages;
	__u32 flags, reserved0;
	__u64 reserved1;
};

#define SE_REAP_SIZE(T, N) _Static_assert(sizeof(struct T) == (N), #T " size")
#define SE_REAP_OFF(T, F, N) \
	_Static_assert(offsetof(struct T, F) == (N), #T "." #F " offset")
SE_REAP_SIZE(se_pool_request, 64);
SE_REAP_OFF(se_pool_request, abi, 0);
SE_REAP_OFF(se_pool_request, operation, 4);
SE_REAP_OFF(se_pool_request, node_incarnation, 8);
SE_REAP_OFF(se_pool_request, admin_generation, 16);
SE_REAP_OFF(se_pool_request, reap_sequence, 24);
SE_REAP_OFF(se_pool_request, task_budget, 32);
SE_REAP_OFF(se_pool_request, work_budget, 36);
SE_REAP_OFF(se_pool_request, expected_epoch, 40);
SE_REAP_OFF(se_pool_request, reserved0, 48);
SE_REAP_OFF(se_pool_request, reserved1, 56);
SE_REAP_SIZE(se_pool_control, 64);
SE_REAP_OFF(se_pool_control, lock, 0);
SE_REAP_OFF(se_pool_control, flags, 4);
SE_REAP_OFF(se_pool_control, node_incarnation, 8);
SE_REAP_OFF(se_pool_control, last_admin_generation, 16);
SE_REAP_OFF(se_pool_control, last_reap_sequence, 24);
SE_REAP_OFF(se_pool_control, scan_epoch, 32);
SE_REAP_OFF(se_pool_control, task_cursor, 40);
SE_REAP_OFF(se_pool_control, work_cursor, 44);
SE_REAP_OFF(se_pool_control, task_visits, 48);
SE_REAP_OFF(se_pool_control, work_visits, 56);
SE_REAP_SIZE(se_pool_receipt, 128);
SE_REAP_OFF(se_pool_receipt, abi, 0);
SE_REAP_OFF(se_pool_receipt, status, 4);
SE_REAP_OFF(se_pool_receipt, node_incarnation, 8);
SE_REAP_OFF(se_pool_receipt, admin_generation, 16);
SE_REAP_OFF(se_pool_receipt, reap_sequence, 24);
SE_REAP_OFF(se_pool_receipt, epoch_before, 32);
SE_REAP_OFF(se_pool_receipt, epoch_after, 40);
SE_REAP_OFF(se_pool_receipt, task_before, 48);
SE_REAP_OFF(se_pool_receipt, task_after, 52);
SE_REAP_OFF(se_pool_receipt, work_before, 56);
SE_REAP_OFF(se_pool_receipt, work_after, 60);
SE_REAP_OFF(se_pool_receipt, task_examined, 64);
SE_REAP_OFF(se_pool_receipt, work_examined, 68);
SE_REAP_OFF(se_pool_receipt, task_reclaimed, 72);
SE_REAP_OFF(se_pool_receipt, work_reclaimed, 76);
SE_REAP_OFF(se_pool_receipt, task_pending, 80);
SE_REAP_OFF(se_pool_receipt, work_pending, 84);
SE_REAP_OFF(se_pool_receipt, task_faults, 88);
SE_REAP_OFF(se_pool_receipt, work_faults, 92);
SE_REAP_OFF(se_pool_receipt, bytes_zeroed, 96);
SE_REAP_OFF(se_pool_receipt, stages, 104);
SE_REAP_OFF(se_pool_receipt, flags, 112);
SE_REAP_OFF(se_pool_receipt, reserved0, 116);
SE_REAP_OFF(se_pool_receipt, reserved1, 120);
_Static_assert(_Alignof(struct se_pool_request) == 8,
	       "se_pool_request alignment");
_Static_assert(_Alignof(struct se_pool_control) == 8,
	       "se_pool_control alignment");
_Static_assert(_Alignof(struct se_pool_receipt) == 8,
	       "se_pool_receipt alignment");
#undef SE_REAP_SIZE
#undef SE_REAP_OFF
#endif
