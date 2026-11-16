// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
// Diagnostic experiment only. Not a production enforcement exemption.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
extern int bpf_path_d_path(struct path *path, char *buf, size_t buf__sz) __ksym;
struct config {
	__u32 mntns;
	__u32 mode;
	__u32 host_mntns;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u64);
	__type(value, struct config);
} targets SEC(".maps");
struct event {
	__u64 cgroup;
	__u32 pid, mntns, expected, mismatch, denied;
	__s32 path_result;
	__u32 userns;
	char path[256];
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 65536);
} events SEC(".maps");
SEC("lsm/bprm_check_security")
long BPF_PROG(mntns_spike, struct linux_binprm *bprm, long ret)
{
	if (ret)
		return ret;
	__u64 cgroup = bpf_get_current_cgroup_id();
	struct config *cfg = bpf_map_lookup_elem(&targets, &cgroup);
	if (!cfg)
		return 0;
	struct task_struct *task = (void *)bpf_get_current_task_btf();
	__u32 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return -1; // Diagnostic overflow must fail the run, not hide events.
	__builtin_memset(e, 0, sizeof(*e));
	e->cgroup = cgroup;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->mntns = mntns;
	e->userns = BPF_CORE_READ(task, cred, user_ns, ns.inum);
	e->expected = cfg->mntns;
	e->mismatch = mntns != cfg->mntns;
	int n = bpf_path_d_path(&bprm->file->f_path, e->path, sizeof(e->path));
	e->path_result = n;
	// Default-deny with the same four directory allows used in Alon's test.
	bool allow = n > 0 &&
		     (__builtin_memcmp(e->path, "/bin/", 5) == 0 ||
		      __builtin_memcmp(e->path, "/sbin/", 6) == 0 ||
		      __builtin_memcmp(e->path, "/usr/bin/", 9) == 0 ||
		      __builtin_memcmp(e->path, "/usr/sbin/", 10) == 0);
	// Mode 1 is the previous unsafe mismatch exemption (negative control).
	// Mode 2 exempts only the separately recorded host namespace, and never
	// exempts a target whose configured namespace is itself the host namespace.
	bool skip = mntns && e->mismatch &&
		    (cfg->mode == 1 || (cfg->mode == 2 && cfg->host_mntns &&
					mntns == cfg->host_mntns));
	e->denied = !skip && !allow;
	bool denied = e->denied;
	bpf_ringbuf_submit(e, 0);
	volatile long result = 0;
	if (denied)
		result = -1;
	return result;
}
char LICENSE[] SEC("license") = "GPL";
