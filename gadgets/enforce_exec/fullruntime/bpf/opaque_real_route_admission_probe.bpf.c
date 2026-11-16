// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Isolated, default-inert admission probe. It has NO TASK/WORK lifecycle
 * hooks, and must never be selected as an enforcement image. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#define ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_REAL_ROUTE_ADMISSION_PROBE 1
#define ER_ACCEPTED_EPOCH(uid) (~0ULL)
#include "epoch_roles.h"
#include "shared_pool_opaque_real_control_candidate.h"
/* Never armed by the image or owner. A disposable test controller may set it
 * before a test-run; accidental TC attachment otherwise touches no route. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_real_route_probe_gate SEC(".maps");
SEC("tc") int opaque_real_route_admission_probe(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const __u32 *armed =
		bpf_map_lookup_elem(&opaque_real_route_probe_gate, &zero);
	if (!armed || *armed != 1)
		return 0;
	struct se_route_claim claim = {};
	if (se_route_admit(bpf_get_current_cgroup_id(), &claim) !=
	    SE_ROUTE_OWNED)
		return 0;
	__u32 slot = claim.slot;
	struct se_route_anchor *route = route_lookup(slot);
	if (!route)
		return 0; /* admitted ARRAY contradiction: keep owner fault-held */
	bpf_spin_lock(&route->lock);
	(void)se_route_release_locked(route, &claim);
	bpf_spin_unlock(&route->lock);
	return 0;
}

/* First real-map callback seam only. Exact death may certify empty WORK via
 * se_of_record_death, but this wrapper does not settle exec, native or reader
 * cleanup. The reaper must retain the charge until those source-authenticated
 * receipts exist. This probe is never linked by a product image, and its gate
 * remains zero in load-only qualification. */
SEC("lsm/task_free")
int BPF_PROG(opaque_real_route_final_free_probe, struct task_struct *physical)
{
	__u32 zero = 0;
	const __u32 *armed =
		bpf_map_lookup_elem(&opaque_real_route_probe_gate, &zero);
	if (!armed || *armed != 1)
		return 0;
	struct se_of_lease lease = {};
	if (se_of_record_death(physical, &lease) == SE_OL_OK)
		(void)se_of_release(&lease, physical);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
