// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define FULL_FS_LIFETIME_MAX 16ULL
#include "../../../filesystem.h"
SEC("lsm/inode_init_security_anon")
int BPF_PROG(fs_track, struct inode *inode, const struct qstr *name,
	     const struct inode *context, int ret)
{
	if (!ret)
		full_fs_mark_memfd(inode, name);
	return ret;
}
struct fs_probe_config {
	__u64 cgroup;
	__u32 enforce, required;
};
struct fs_probe_result {
	__u32 mask, known, count;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fs_probe_config);
} fs_probe_config SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fs_probe_result);
} fs_probe_result SEC(".maps");
SEC("lsm/bprm_check_security")
int BPF_PROG(fs_check, struct linux_binprm *bprm, int ret)
{
	if (ret)
		return ret;
	__u32 zero = 0;
	struct fs_probe_config *c =
		bpf_map_lookup_elem(&fs_probe_config, &zero);
	if (!c || c->cgroup != bpf_get_current_cgroup_id())
		return 0;
	struct full_fs_facts facts = full_file_filesystem(bprm->file);
	struct fs_probe_result *r =
		bpf_map_lookup_elem(&fs_probe_result, &zero);
	if (r) {
		r->mask = facts.mask;
		r->known = facts.known;
		__sync_fetch_and_add(&r->count, 1);
	}
	if (!c->enforce)
		return 0;
	if (facts.mask & facts.known & c->required)
		return -1;
	if ((facts.known & c->required) != c->required)
		return -95;
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
