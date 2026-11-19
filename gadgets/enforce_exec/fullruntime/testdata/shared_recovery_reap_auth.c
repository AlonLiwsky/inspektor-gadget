/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
struct bpf_spin_lock {
	int held;
};
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	assert(!lock->held);
	lock->held = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	assert(lock->held);
	lock->held = 0;
}
struct task_struct {
	int unused;
};
#include "shared_recovery_transition.h"
static struct rm_config config;
static struct rm_control control;
static __u64 current_task;
static __u64 bpf_get_current_task(void)
{
	return current_task;
}
#define SE_RECOVERY_TEST 1
#define SE_RM_CONFIG_LOOKUP(key) ((void)(key), &config)
#define SE_RM_CONTROL_LOOKUP(key) ((void)(key), &control)
#include "shared_recovery_kernel.h"

static void committed_admin(void)
{
	config = (struct rm_config){ .incarnation = 11,
				     .bootstrap_nonce = 13,
				     .abi = RM_ABI,
				     .clone_flags = RM_CLONE_FLAGS };
	control = (struct rm_control){};
	struct rm_grequest register_guardian = { .incarnation = 11,
						 .nonce = 13,
						 .sequence = 1,
						 .operation = RM_REGISTER };
	struct rm_grequest arm = { .incarnation = 11,
				   .nonce = 13,
				   .sequence = 2,
				   .operation = RM_ARM };
	struct rm_arequest ready = { .incarnation = 11,
				     .generation = 1,
				     .sequence = 1,
				     .recovery_epoch = 1,
				     .operation = RM_A_READY };
	struct rm_grequest commit = { .incarnation = 11,
				      .nonce = 13,
				      .sequence = 3,
				      .recovery_epoch = 1,
				      .operation = RM_COMMIT };
	bpf_spin_lock(&control.lock);
	assert(rt_guardian_step(&config, &control, &register_guardian, 100) ==
	       RM_ACCEPT);
	assert(rt_guardian_step(&config, &control, &arm, 100) == RM_ACCEPT);
	assert(rt_rm_alloc(&config, &control, 100, 200, RM_CLONE_FLAGS, 0) ==
	       0);
	assert(rt_admin_step(&config, &control, &ready, 200) == RM_ACCEPT);
	assert(rt_guardian_step(&config, &control, &commit, 100) == RM_ACCEPT);
	assert(rt_rm_cell_valid(&control) &&
	       control.recovery_phase == RM_COMMITTED &&
	       control.admin_generation == 1);
	bpf_spin_unlock(&control.lock);
	current_task = 200;
}

static void normalized_clone_admission(void)
{
	/* On kernel_clone-based kernels the LSM receives CLONE_PARENT only;
	 * the separate SIGCHLD exit_signal is checked by S's exact waiter. */
	struct rm_config c = { .incarnation = 11,
			       .bootstrap_nonce = 13,
			       .abi = RM_ABI,
			       .clone_flags = RM_CLONE_FLAGS };
	struct rm_control s = {};
	struct rm_grequest reg = { .incarnation = 11,
				   .nonce = 13,
				   .sequence = 1,
				   .operation = RM_REGISTER };
	struct rm_grequest arm = { .incarnation = 11,
				   .nonce = 13,
				   .sequence = 2,
				   .operation = RM_ARM };
	assert(rt_guardian_step(&c, &s, &reg, 100) == RM_ACCEPT);
	assert(rt_guardian_step(&c, &s, &arm, 100) == RM_ACCEPT);
	assert(rt_rm_alloc(&c, &s, 100, 200, RM_PREHOOK_INVALID_FLAGS, 0) == 0);
	assert(rt_rm_alloc(&c, &s, 100, 200, RM_U64(0x8800), 0) == 0);
	assert(rt_rm_alloc(&c, &s, 100, 200, RM_U64(0x8001), 0) == 0);
	assert(s.recovery_phase == RM_ARMED && s.candidate_task == 0);
	assert(rt_rm_alloc(&c, &s, 100, 200, RM_LSM_CLONE_FLAGS_NO_SIGNAL, 0) ==
	       0);
	assert(s.recovery_phase == RM_CAPTURED && s.candidate_task == 200);
}

int main(void)
{
	normalized_clone_admission();
	committed_admin();
	struct rm_control before = control;
	assert(se_rm_reap_authorized(11, 1));
	assert(!memcmp(&before, &control, sizeof(control)));
	assert(!se_rm_reap_authorized(11, 0));
	assert(!se_rm_reap_authorized(11, 2));
	assert(!se_rm_reap_authorized(12, 1));
	current_task = 201;
	assert(!se_rm_reap_authorized(11, 1));
	current_task = 200;
	config.incarnation = 12;
	assert(!se_rm_reap_authorized(11, 1));
	config.incarnation = 11;
	struct rm_control admin_closed = control;
	bpf_spin_lock(&control.lock);
	assert(!rt_rm_free(&control, 200));
	bpf_spin_unlock(&control.lock);
	assert(!se_rm_reap_authorized(11, 1));
	control = admin_closed;
	bpf_spin_lock(&control.lock);
	assert(!rt_rm_free(&control, 100));
	bpf_spin_unlock(&control.lock);
	assert(!se_rm_reap_authorized(11, 1));
	puts("actual recovery-cell reaper admission: PASS");
	return 0;
}
