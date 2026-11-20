// SPDX-License-Identifier: GPL-2.0
// Qualification-only selective engine. This is NOT the IG product engine.
// The registered owner exclusively holds its unpinned link; release withdraws
// its deny-path rule. This isolates the fence's before-detach ordering.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct backend_binding {
	__u64 denied_inode;
	__u32 mode;
	__u32 pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct backend_binding);
} backend_bind SEC(".maps");

SEC("lsm/bprm_check_security")
long BPF_PROG(backend_check, struct linux_binprm *bprm, int ret)
{
	(void)ret; // Preserve the full-width chained result from ctx below.
	__s64 prior_ret = (__s64)ctx[1];
	if (prior_ret)
		return prior_ret;
	__u64 cgroup = bpf_get_current_cgroup_id();
	struct backend_binding *binding =
		bpf_map_lookup_elem(&backend_bind, &cgroup);
	if (!binding || binding->mode == 1)
		return 0;
	if (binding->mode != 2)
		return -1L;
	__u64 inode = BPF_CORE_READ(bprm, file, f_inode, i_ino);
	if (!inode || inode == binding->denied_inode)
		return -1L;
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
