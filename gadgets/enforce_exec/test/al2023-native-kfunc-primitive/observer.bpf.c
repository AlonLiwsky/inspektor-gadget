// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "argv_wire.h"
extern int ig_capture_pending_argv(struct linux_binprm *bprm, void *output,
				   unsigned int output__sz) __ksym;
struct ig_gate {
	__u64 cgroup;
	__u32 enabled, reserved;
};
struct ig_sample {
	__u64 pid_tgid;
	__s64 prior;
	__u64 bprm, task, pending_p;
	int result;
	__u32 reserved;
	struct ig_argv_result argv;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ig_gate);
} ig_argv_gate SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} ig_argv_seen SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct ig_sample);
} ig_argv_samples SEC(".maps");
SEC("lsm.s/bprm_check_security")
long BPF_PROG(ig_argv_observe, struct linux_binprm *bprm, int prior)
{
	__s64 prior_ret = (__s64)ctx[1];
	__u32 zero = 0;
	const struct ig_gate *gate = bpf_map_lookup_elem(&ig_argv_gate, &zero);
	if (!gate || gate->enabled != 1 || gate->reserved || !gate->cgroup ||
	    bpf_get_current_cgroup_id() != gate->cgroup)
		return prior_ret;
	__u64 *seen = bpf_map_lookup_elem(&ig_argv_seen, &zero);
	if (!seen)
		return prior_ret;
	__u64 index = __sync_fetch_and_add(seen, 1);
	if (index >= 16)
		return prior_ret; /* counter >16 is explicit incomplete evidence */
	__u32 slot = index;
	struct ig_sample *sample = bpf_map_lookup_elem(&ig_argv_samples, &slot);
	if (sample) {
		sample->pid_tgid = bpf_get_current_pid_tgid();
		sample->prior = prior_ret;
		sample->bprm = (__u64)bprm;
		sample->task = (__u64)bpf_get_current_task_btf();
		sample->pending_p = bprm->p;
		sample->result = ig_capture_pending_argv(bprm, &sample->argv,
							 sizeof(sample->argv));
	}
	return prior_ret; /* Observation never adds a denial or policy decision. */
}
char LICENSE[] SEC("license") = "GPL";
