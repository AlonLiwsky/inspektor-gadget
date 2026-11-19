// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../../../stdio.h"
extern int bpf_path_d_path(const struct path *, char *, size_t) __ksym;
struct target {
	__u64 cgroup;
	char path[256];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct target);
} targets SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[256]);
} paths SEC(".maps");
struct result {
	__s32 value;
	__u32 count;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct result);
} results SEC(".maps");
struct compare {
	char *path;
	struct target *target;
	int match;
};
static long compare_path(__u32 i, void *opaque)
{
	struct compare *c = opaque;
	if (i >= 256)
		return 1;
	if (c->path[i] != c->target->path[i]) {
		c->match = 0;
		return 1;
	}
	return c->path[i] == 0;
}
SEC("lsm/bprm_check_security")
int BPF_PROG(check_stdin, struct linux_binprm *bprm, int ret)
{
	if (ret)
		return ret;
	__u32 zero = 0;
	struct target *t = bpf_map_lookup_elem(&targets, &zero);
	if (!t || !t->cgroup || t->cgroup != bpf_get_current_cgroup_id())
		return 0;
	char *path = bpf_map_lookup_elem(&paths, &zero);
	if (!path)
		return -95;
	if (bpf_path_d_path(&bprm->file->f_path, path, 256) <= 0)
		return -95;
	struct compare c = { path, t, 1 };
	if (bpf_loop(256, compare_path, &c, 0) < 0 || !c.match)
		return 0;
	int value = full_stdin_pipe(bpf_get_current_task_btf());
	struct result *r = bpf_map_lookup_elem(&results, &zero);
	if (r) {
		r->value = value;
		__sync_fetch_and_add(&r->count, 1);
	}
	if (value < 0)
		return -95;
	return value ? -1 : 0;
}
char LICENSE[] SEC("license") = "GPL";
