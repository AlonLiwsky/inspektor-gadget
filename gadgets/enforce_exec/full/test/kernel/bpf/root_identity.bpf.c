// SPDX-License-Identifier: GPL-2.0
// Root-group identity ABI proof only. No roles or binding readiness.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} admin SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} identities SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} credit_limit SEC(".maps");
struct command {
	__u64 nonce, cookie, cgroup;
	__u32 operation, host_pid;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct command);
} commands SEC(".maps");
struct result {
	__u64 cookie;
	__u32 status, match;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct result);
} results SEC(".maps");
struct anchor {
	__u64 group, credits;
};
// UAPI reads denied, and native freezes writes before invocation. Raw kernel
// identity never leaves this map; fixture output contains only boolean matches.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_WRONLY);
	__type(key, __u32);
	__type(value, struct anchor);
} anchor SEC(".maps");
SEC("syscall") int root_identity(void *unused)
{
	__u32 zero = 0;
	struct command *c = bpf_map_lookup_elem(&commands, &zero);
	struct result *r = bpf_map_lookup_elem(&results, &zero);
	struct anchor *a = bpf_map_lookup_elem(&anchor, &zero);
	if (!c || !r || !a)
		return 0;
	r->cookie = 0;
	r->match = 0;
	r->status = 1;
	__u64 *nonce =
		bpf_task_storage_get(&admin, bpf_get_current_task_btf(), 0, 0);
	if (!nonce || !*nonce || *nonce != c->nonce)
		return 0;
	if (c->operation == 4) {
		a->group = 0;
		r->status = 0;
		return 0;
	}
	struct task_struct *task = bpf_task_from_pid(c->host_pid);
	if (!task) {
		r->status = 2;
		return 0;
	}
	__u64 cgroup = 0, group = 0;
	if (BPF_CORE_READ_INTO(&cgroup, task, cgroups, dfl_cgrp, kn, id) ||
	    cgroup != c->cgroup) {
		r->status = 3;
		goto out;
	}
	if (BPF_CORE_READ_INTO(&group, task, signal, pids[PIDTYPE_TGID]) ||
	    !group) {
		r->status = 3;
		goto out;
	}
	__u64 *identity = bpf_task_storage_get(&identities, task, 0, 0);
	if (c->operation == 1) {
		if (!identity) {
			__u32 *limit =
				bpf_map_lookup_elem(&credit_limit, &zero);
			if (!limit || !*limit || *limit > 4096 ||
			    a->credits >= *limit) {
				r->status = 7;
				goto out;
			}
			__u64 next = ++a->credits;
			identity = bpf_task_storage_get(
				&identities, task, 0,
				BPF_LOCAL_STORAGE_GET_F_CREATE);
			if (!identity) {
				r->status = 7;
				goto out;
			}
			*identity = next;
		}
		r->cookie = *identity;
		r->status = 0;
		goto out;
	}
	if (!identity || !*identity || *identity != c->cookie) {
		r->status = 4;
		goto out;
	}
	r->cookie = *identity;
	if (c->operation == 2) {
		if (a->group || task->pid != task->tgid) {
			r->status = 5;
			goto out;
		}
		a->group = group;
		r->match = 1;
		r->status = 0;
	} else if (c->operation == 3) {
		r->match = a->group && a->group == group;
		r->status = 0;
	}
out:
	bpf_task_release(task);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
