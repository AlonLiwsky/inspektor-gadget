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
static void bpf_spin_lock(struct bpf_spin_lock *l)
{
	assert(!l->val);
	l->val = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *l)
{
	assert(l->val);
	l->val = 0;
}
/* ACTUAL_TYPES */
/* ACTUAL_TRANSITIONS */
struct er_row {
	__u64 uid, epoch, role;
	__u32 knowledge, reserved;
};
/* ACTUAL_EXEC_TYPE */
struct eo_task {
	struct bpf_spin_lock lock;
	__u64 cookie, invocation_sequence;
	struct eo_exec_tx exec;
};
struct eo_work {
	__u64 a_epoch;
};
struct eo_config {
	__u64 cookie, cgroup;
	__u32 abi, gate_slot;
};
struct eo_health {
	__u64 faults;
	__u32 retired;
};
struct fe_header {
	__u64 generation;
	__u32 policies;
};
struct task_struct {
	int unused;
};
struct linux_binprm {
	int unused;
};
#define EO_ABI 3
static struct eo_dispatch dispatch;
static struct eo_task task;
static struct eo_work work;
static struct eo_config config;
static struct eo_health health;
static struct fe_header header;
static struct task_struct physical;
static struct linux_binprm bprm;
static __u64 current_cgroup;
static int fail_task, fail_work, fail_health, fail_header, invalid_roles;
static struct eo_config *eo_config(void)
{
	return &config;
}
static struct eo_health *eo_status(void)
{
	return fail_health ? 0 : &health;
}
static struct task_struct *bpf_get_current_task_btf(void)
{
	return &physical;
}
static __u64 bpf_get_current_cgroup_id(void)
{
	return current_cgroup;
}
static struct eo_dispatch *eo_dispatch_state(void)
{
	return &dispatch;
}
static struct eo_task *eo_lookup_task(struct task_struct *p)
{
	assert(p == &physical);
	return fail_task ? 0 : &task;
}
static struct eo_task *eo_get_task(struct task_struct *p)
{
	assert(dispatch.exec_inflight);
	return eo_lookup_task(p);
}
static const void *eo_program_blob(__u32 bank, __u32 key, __u64 gen)
{
	assert(dispatch.exec_inflight && bank == 0 && key == 0 && gen == 1);
	return fail_header ? 0 : &header;
}
static struct eo_work *eo_get_work(void)
{
	assert(dispatch.exec_inflight);
	return fail_work ? 0 : &work;
}
static int eo_load_candidate(struct eo_work *w, int slot, int mask)
{
	(void)slot;
	(void)mask;
	w->a_epoch = 1;
	return 0;
}
static int eo_validate_exec_task(struct eo_task *s, struct eo_work *w)
{
	(void)s;
	(void)w;
	return invalid_roles;
}
static void eo_put_work(struct eo_work *w)
{
	assert(w == &work);
}
static void eo_data_fault(__u64 gen, __u64 bit)
{
	(void)gen;
	(void)bit;
}
static void eo_clear_pending(struct eo_exec_tx *tx)
{
	memset(tx->pending, 0, sizeof(tx->pending));
}
/* ACTUAL_OBSERVATION_FAULT */
/* ACTUAL_EXEC_ADMISSION */
static void reset(__u32 mode)
{
	memset(&task, 0, sizeof(task));
	task.cookie = 99;
	dispatch = (struct eo_dispatch){ .scope_state = EO_SCOPE_ACTIVE,
					 .session_cookie = 7,
					 .cgroup = 42,
					 .serial = 1,
					 .active = { .generation = 1,
						     .execution_class = mode,
						     .policy_count = 1,
						     .role_writer_mask = 1 } };
	config = (struct eo_config){
		.cookie = 7, .cgroup = 42, .abi = 3, .gate_slot = 8
	};
	health = (struct eo_health){};
	header = (struct fe_header){ .generation = 1, .policies = 1 };
	current_cgroup = 42;
	fail_task = fail_work = fail_health = fail_header = invalid_roles = 0;
}
static void finish(void)
{
	struct eo_reader_claim local = {};
	bpf_spin_lock(&task.lock);
	assert(!eo_reader_take_locked(&task.exec.reader, task.cookie, 99,
				      task.exec.reader.sequence, &local));
	task.exec.owned = 0;
	bpf_spin_unlock(&task.lock);
	eo_release_exec_reader(&local);
	assert(!dispatch.exec_inflight && !dispatch.bank_readers[0]);
}
int main(void)
{
	__u64 generation;
	__u32 mode;
	reset(1);
	dispatch.scope_state = EO_SCOPE_UNINITIALIZED;
	assert(!eo_exec_begin_development(&bprm, &generation, &mode) &&
	       !dispatch.exec_inflight);
	reset(1);
	dispatch.scope_state = EO_SCOPE_INACTIVE;
	assert(!eo_exec_begin_development(&bprm, &generation, &mode) &&
	       !dispatch.exec_inflight);
	reset(1);
	dispatch.scope_state = 99;
	assert(eo_exec_begin_development(&bprm, &generation, &mode) == -1 &&
	       !dispatch.exec_inflight);

	for (__u32 declared = 1; declared <= 2; declared++) {
		for (int fault = 0; fault < 6; fault++) {
			reset(declared);
			if (fault == 0)
				fail_task = 1;
			if (fault == 1)
				fail_health = 1;
			if (fault == 2)
				health.faults = 1;
			if (fault == 3)
				fail_header = 1;
			if (fault == 4)
				dispatch.exec_inflight = ~0ULL;
			if (fault == 5)
				dispatch.integrity_fault = 1;
			assert(eo_exec_begin_development(&bprm, &generation,
							 &mode) == -1);
			assert(mode == declared);
			if (task.exec.owned)
				finish();
			assert(dispatch.exec_inflight ==
			       (fault == 4 ? ~0ULL : 0));
		}
		reset(declared);
		fail_work = 1;
		assert(eo_exec_begin_development(&bprm, &generation, &mode) ==
		       -1);
		assert(mode == declared && task.exec.reader.owned &&
		       dispatch.exec_inflight == 1);
		finish();
		reset(declared);
		invalid_roles = 1;
		assert(eo_exec_begin_development(&bprm, &generation, &mode) ==
			       -1 &&
		       mode == declared);
		finish();
	}
	reset(1);
	assert(eo_exec_begin_development(&bprm, &generation, &mode) == 1 &&
	       mode == 1);
	__u64 sequence = task.exec.reader.sequence;
	current_cgroup = 43;
	assert(eo_exec_begin_development(&bprm, &generation, &mode) == 1 &&
	       mode == 1);
	assert(dispatch.exec_inflight == 1 &&
	       task.exec.reader.sequence == sequence);
	finish();
	reset(2);
	current_cgroup = 43;
	fail_task = 1;
	health.faults = 1;
	assert(eo_exec_begin_development(&bprm, &generation, &mode) == 0);
	assert(dispatch.serial == 1 && !dispatch.exec_inflight);
	return 0;
}
