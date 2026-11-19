/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_ACCESSORS_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_ACCESSORS_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque map accessors are candidate-only"
#endif
/* Include after shared_pool_opaque_maps_candidate.h and the owner core.
 * These helpers access only the fourteen opaque TASK/WORK maps; route,
 * binding, policy and source authority must be supplied by the caller. */
static struct se_ol_meta *meta_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&se_opaque_meta, &slot);
}
static struct se_oc_account *account_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&se_opaque_accounts, &slot);
}
static struct se_oc_charge *charge_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&se_opaque_charges, &slot);
}
static struct se_oc_sequence *sequence_lookup(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&se_opaque_sequence, &zero);
}
static struct se_owk_account *work_account_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&se_opaque_work_accounts, &slot);
}
static struct se_owk_charge *work_charge_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&se_opaque_work_charges, &slot);
}
static struct se_owk_sequence *work_sequence_lookup(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&se_opaque_work_sequence, &zero);
}
static struct se_owk_meta *work_meta_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&se_opaque_work_meta, &slot);
}
static struct se_owk_payload *work_payload_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&se_opaque_work_payload, &slot);
}
static int work_payload_zero(__u32 slot)
{
	__u32 zero = 0;
	const struct se_owk_payload *empty =
		bpf_map_lookup_elem(&se_opaque_work_zero, &zero);
	return empty ? bpf_map_update_elem(&se_opaque_work_payload, &slot,
					   empty, BPF_ANY) :
		       -1;
}
static void *payload_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&se_opaque_payload, &slot);
}
static int payload_zero(__u32 slot)
{
	__u32 zero = 0;
	const struct se_pool_task_wire *empty =
		bpf_map_lookup_elem(&se_opaque_payload_zero, &zero);
	return empty ? bpf_map_update_elem(&se_opaque_payload, &slot, empty,
					   BPF_ANY) :
		       -1;
}
static const __u64 *opaque_lookup(const void *key)
{
	return bpf_map_lookup_elem(&se_opaque_keys, key);
}
static int archive_copy(__u32 slot, const void *key)
{
	return bpf_map_update_elem(&se_opaque_archive, &slot, key, BPF_ANY);
}
static int archive_zero(__u32 slot)
{
	__u64 zero = 0;
	return bpf_map_update_elem(&se_opaque_archive, &slot, &zero, BPF_ANY);
}
static const __u64 *archive_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&se_opaque_archive, &slot);
}
static int insert_zero(const void *key)
{
	__u64 zero = 0;
	return bpf_map_update_elem(&se_opaque_keys, key, &zero, BPF_NOEXIST) ==
			       0 ?
		       SE_OL_OK :
		       SE_OL_CONTENDED;
}
static __u64 *writer_lookup(const void *key)
{
	return bpf_map_lookup_elem(&se_opaque_keys, key);
}
static int delete_key(const void *key)
{
	return bpf_map_delete_elem(&se_opaque_keys, key) == 0 ? SE_OL_OK :
								SE_OL_CONTENDED;
}

#endif
