/* SPDX-License-Identifier: Apache-2.0 */
/* Synthetic synchronous helper feasibility only, NOT physical-exec ownership. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#ifdef ROUTE_PIN_PUBLICATION_HOOKS
#include <bpf/bpf_tracing.h>
#endif
#if defined(ROUTE_PIN_EXEC_HOOKS) && defined(ROUTE_PIN_PUBLICATION_HOOKS)
#error select only one hook variant
#endif
#ifndef ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE
#error source-pin candidate must be explicitly enabled
#endif
#include "../../full/shared_route.h"
_Static_assert(sizeof(struct se_route_anchor) == 104, "candidate route layout");
struct outcome {
	__u64 calls, acquired, released, failures;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct se_route_anchor);
} routes SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} target SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct outcome);
} outcomes SEC(".maps");
static __always_inline int exercise(__u32 index)
{
	__u32 zero = 0;
	__u64 pid = bpf_get_current_pid_tgid();
	__u64 *wanted = bpf_map_lookup_elem(&target, &zero);
	if (!wanted || !*wanted || *wanted != pid)
		return 0;
	struct se_route_anchor *a = bpf_map_lookup_elem(&routes, &zero);
	struct outcome *o = bpf_map_lookup_elem(&outcomes, &index);
	if (!a || !o)
		return 0;
	struct se_route_claim claim = {};
	struct se_source_mode_owner owner = {};
	struct se_source_mode_token token = {};
	int acquired = -1, released = -1, dropped = -1;
	bpf_spin_lock(&a->lock);
	/* Fixed synthetic identities; no route into the product and no exec claim. */
	if (se_route_claim_locked(a, se_route_locator(0, 1), 7, &claim) ==
	    SE_ROUTE_OWNED) {
		acquired = se_route_source_pin_acquire_locked(a, &claim, 1, 1,
							      &owner, &token);
		if (!acquired)
			released = se_route_source_pin_release_locked(
				a, &owner, &token, 1, 1);
		dropped = se_route_release_locked(a, &claim);
	}
	bpf_spin_unlock(&a->lock);
	__sync_fetch_and_add(&o->calls, 1);
	if (!acquired)
		__sync_fetch_and_add(&o->acquired, 1);
	if (!released)
		__sync_fetch_and_add(&o->released, 1);
	if (acquired || released || dropped)
		__sync_fetch_and_add(&o->failures, 1);
	return 0; /* Ordinary tracing return, never overrides/denies syscall. */
}
#ifdef ROUTE_PIN_EXEC_HOOKS
SEC("fentry/security_bprm_creds_for_exec") int probe_entry(void *ctx)
{
	return exercise(0);
}
SEC("fexit/bprm_execve") int probe_exit(void *ctx)
{
	return exercise(1);
}
#elif defined(ROUTE_PIN_PUBLICATION_HOOKS)
SEC("fentry/cgroup_kn_lock_live")
int BPF_PROG(probe_entry, struct kernfs_node *kn, bool drain)
{
	if (!kn || !drain)
		return 0;
	return exercise(0);
}
SEC("fexit/cgroup_kn_lock_live")
int BPF_PROG(probe_exit, struct kernfs_node *kn, bool drain,
	     struct cgroup *result)
{
	if (!kn || !drain || !result || (__u64)result >= ~4095ULL)
		return 0;
	return exercise(1);
}
#else
SEC("fentry/__x64_sys_getpgid") int probe_entry(void *ctx)
{
	return exercise(0);
}
SEC("fexit/__x64_sys_getpgid") int probe_exit(void *ctx)
{
	return exercise(1);
}
#endif
char LICENSE[] SEC("license") = "GPL";
