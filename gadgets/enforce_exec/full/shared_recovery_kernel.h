/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ENFORCE_EXEC_SHARED_RECOVERY_KERNEL_H
#define ENFORCE_EXEC_SHARED_RECOVERY_KERNEL_H
#include "shared_recovery_transition.h"

#ifndef SE_RECOVERY_TEST
#define SE_RM_ARRAY_MAP(name, value_type, flags)  \
	struct {                                  \
		__uint(type, BPF_MAP_TYPE_ARRAY); \
		__uint(max_entries, 1);           \
		__uint(map_flags, flags);         \
		__type(key, __u32);               \
		__type(value, value_type);        \
	} name SEC(".maps")
SE_RM_ARRAY_MAP(se_rm_configuration, struct rm_config, BPF_F_RDONLY_PROG);
SE_RM_ARRAY_MAP(se_rm_guardian_request, struct rm_grequest, BPF_F_RDONLY_PROG);
SE_RM_ARRAY_MAP(se_rm_admin_request, struct rm_arequest, BPF_F_RDONLY_PROG);
SE_RM_ARRAY_MAP(se_rm_control, struct rm_control, BPF_F_RDONLY);
SE_RM_ARRAY_MAP(se_rm_guardian_receipt, struct rm_receipt, BPF_F_RDONLY);
SE_RM_ARRAY_MAP(se_rm_admin_receipt, struct rm_receipt, BPF_F_RDONLY);
#undef SE_RM_ARRAY_MAP
#define SE_RM_CONFIG_LOOKUP(key) bpf_map_lookup_elem(&se_rm_configuration, key)
#define SE_RM_GREQUEST_LOOKUP(key) \
	bpf_map_lookup_elem(&se_rm_guardian_request, key)
#define SE_RM_AREQUEST_LOOKUP(key) \
	bpf_map_lookup_elem(&se_rm_admin_request, key)
#define SE_RM_CONTROL_LOOKUP(key) bpf_map_lookup_elem(&se_rm_control, key)
#define SE_RM_GRECEIPT_LOOKUP(key) \
	bpf_map_lookup_elem(&se_rm_guardian_receipt, key)
#define SE_RM_ARECEIPT_LOOKUP(key) \
	bpf_map_lookup_elem(&se_rm_admin_receipt, key)
#endif

/* TEST_RUN only. The recovered selector must retain loaded handles and skip TC attach. */
#ifndef SE_RECOVERY_TEST
SEC("tc") int se_rm_guardian(struct __sk_buff *skb)
{
	(void)skb;
	__u32 key = 0;
	const struct rm_config *c = SE_RM_CONFIG_LOOKUP(&key);
	const struct rm_grequest *q = SE_RM_GREQUEST_LOOKUP(&key);
	struct rm_control *s = SE_RM_CONTROL_LOOKUP(&key);
	struct rm_receipt *r = SE_RM_GRECEIPT_LOOKUP(&key);
	__u64 task = bpf_get_current_task();
	if (!c || !q || !s || !r)
		return 0;
	struct rm_config local_config = *c;
	struct rm_grequest local_request = *q;
	bpf_spin_lock(&s->lock);
	rt_rm_guardian(&local_config, s, &local_request, task, r);
	bpf_spin_unlock(&s->lock);
	return 0;
}
SEC("tc") int se_rm_administrator(struct __sk_buff *skb)
{
	(void)skb;
	__u32 key = 0;
	const struct rm_config *c = SE_RM_CONFIG_LOOKUP(&key);
	const struct rm_arequest *q = SE_RM_AREQUEST_LOOKUP(&key);
	struct rm_control *s = SE_RM_CONTROL_LOOKUP(&key);
	struct rm_receipt *r = SE_RM_ARECEIPT_LOOKUP(&key);
	__u64 task = bpf_get_current_task();
	if (!c || !q || !s || !r)
		return 0;
	struct rm_config local_config = *c;
	struct rm_arequest local_request = *q;
	bpf_spin_lock(&s->lock);
	rt_rm_admin(&local_config, s, &local_request, task, r);
	bpf_spin_unlock(&s->lock);
	return 0;
}
#endif

/* Runs after prior denial and before every route-dependent return. */
static __always_inline int se_rm_capture(struct task_struct *child,
					 unsigned long clone_flags, int prior)
{
	if (prior)
		return prior;
	__u32 key = 0;
	const struct rm_config *c = SE_RM_CONFIG_LOOKUP(&key);
	struct rm_control *s = SE_RM_CONTROL_LOOKUP(&key);
	__u64 task = bpf_get_current_task();
	if (!c || !s)
		return prior;
	struct rm_config local_config = *c;
	bpf_spin_lock(&s->lock);
	int result = rt_rm_alloc(&local_config, s, task, (__u64)child,
				 clone_flags, prior);
	bpf_spin_unlock(&s->lock);
	return result;
}

/* Only the dying argument and recovery control participate in closure. */
static __always_inline void se_rm_close(struct task_struct *dying)
{
	__u32 key = 0;
	struct rm_control *s = SE_RM_CONTROL_LOOKUP(&key);
	if (!s)
		return;
	bpf_spin_lock(&s->lock);
	rt_rm_free(s, (__u64)dying);
	bpf_spin_unlock(&s->lock);
}

/* Same-invocation physical task; no ticket, request or nonce is authority. */
static __always_inline int se_rm_command_authorized(__u64 node_cookie)
{
	__u32 key = 0;
	const struct rm_config *c = SE_RM_CONFIG_LOOKUP(&key);
	struct rm_control *s = SE_RM_CONTROL_LOOKUP(&key);
	__u64 task = bpf_get_current_task();
	if (!c || !s || !node_cookie || !task)
		return 0;
	struct rm_config local_config = *c;
	if (!rt_rm_config_valid(&local_config) ||
	    local_config.incarnation != node_cookie)
		return 0;
	bpf_spin_lock(&s->lock);
	int authorized =
		rt_rm_cell_valid(s) &&
		s->incarnation == local_config.incarnation &&
		s->terminal == RM_NORMAL && s->guardian_phase == RM_G_ALIVE &&
		s->admin_phase == RM_A_ALIVE &&
		s->recovery_phase == RM_COMMITTED && s->admin_task == task;
	bpf_spin_unlock(&s->lock);
	return authorized;
}

/* Reaper admission must compare the caller's expected generation with the
 * lock-owned physical admin record in THIS invocation. A previous CHECK
 * receipt, request tuple, or node cookie alone is not authorization. This
 * read-only predicate deliberately does not reserve the separate pool BUSY
 * state; the future reaper must take that lock only after releasing this one. */
static __always_inline int se_rm_reap_authorized(__u64 node_cookie,
						 __u64 admin_generation)
{
	__u32 key = 0;
	const struct rm_config *c = SE_RM_CONFIG_LOOKUP(&key);
	struct rm_control *s = SE_RM_CONTROL_LOOKUP(&key);
	__u64 task = bpf_get_current_task();
	if (!c || !s || !node_cookie || !admin_generation || !task)
		return 0;
	struct rm_config local_config = *c;
	if (!rt_rm_config_valid(&local_config) ||
	    local_config.incarnation != node_cookie)
		return 0;
	bpf_spin_lock(&s->lock);
	int authorized =
		rt_rm_cell_valid(s) &&
		s->incarnation == local_config.incarnation &&
		s->terminal == RM_NORMAL && s->guardian_phase == RM_G_ALIVE &&
		s->admin_phase == RM_A_ALIVE &&
		s->recovery_phase == RM_COMMITTED && s->admin_task == task &&
		s->admin_generation == admin_generation;
	bpf_spin_unlock(&s->lock);
	return authorized;
}
#endif
