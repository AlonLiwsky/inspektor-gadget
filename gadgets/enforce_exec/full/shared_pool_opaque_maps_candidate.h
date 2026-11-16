/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_MAPS_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_MAPS_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque TASK maps are candidate-only until selected hooks are migrated"
#endif
#if !defined(SE_OL_TASKS) || !defined(SE_OC_ACCOUNTS) || !defined(SE_OC_QUOTA)
#error "opaque TASK map geometry must be explicit"
#endif
_Static_assert((__u64)SE_OC_ACCOUNTS *SE_OC_QUOTA == SE_OL_TASKS,
	       "opaque TASK account partition");

/* One original-key HASH locator plus fixed TASK and WORK owners. A selected
 * image must use this whole cohort instead of, never beside, the legacy
 * address-keyed TASK/WORK maps. Both zero sources are frozen before attach. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_OL_TASKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, __u64);
} se_opaque_keys SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OL_TASKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} se_opaque_archive SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OL_TASKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_ol_meta);
} se_opaque_meta SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OL_TASKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_pool_task_wire);
} se_opaque_payload SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct se_pool_task_wire);
} se_opaque_payload_zero SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OC_ACCOUNTS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_oc_account);
} se_opaque_accounts SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OL_TASKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_oc_charge);
} se_opaque_charges SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_oc_sequence);
} se_opaque_sequence SEC(".maps");

#if !defined(SE_OWK_ACCOUNTS) || !defined(SE_OWK_QUOTA) || \
	!defined(SE_OWK_WORKS)
#error "opaque WORK map geometry must be explicit"
#endif
_Static_assert(SE_OWK_ACCOUNTS == SE_OC_ACCOUNTS && SE_OWK_QUOTA > 0 &&
		       SE_OWK_QUOTA <= 64 &&
		       (__u64)SE_OWK_ACCOUNTS * SE_OWK_QUOTA == SE_OWK_WORKS,
	       "opaque WORK account partition");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OWK_ACCOUNTS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_owk_account);
} se_opaque_work_accounts SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OWK_WORKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_owk_charge);
} se_opaque_work_charges SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_owk_sequence);
} se_opaque_work_sequence SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OWK_WORKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_owk_meta);
} se_opaque_work_meta SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OWK_WORKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_owk_payload);
} se_opaque_work_payload SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct se_owk_payload);
} se_opaque_work_zero SEC(".maps");
#endif
