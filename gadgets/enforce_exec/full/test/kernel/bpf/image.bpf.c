// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
struct origin_key {
	__u64 inode;
	__u32 major, minor;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct origin_key);
	__type(value, __u8);
} origins SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ready SEC(".maps");
static __always_inline int origin_ready(void)
{
	__u32 zero = 0;
	__u32 *r = bpf_map_lookup_elem(&ready, &zero);
	return r && *r;
}
#define ORIGIN_READY() origin_ready()
#define ORIGIN_LOOKUP(key) bpf_map_lookup_elem(&origins, key)
#include "../../../image_origin.h"
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
/* Test-only bounded rendezvous. phase 1 pauses before origin inspection,
 * phase 2 after it. A missed scheduling window is UNKNOWN, never success. */
struct pause_control {
	__u32 when, hold, phase, timedout;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pause_control);
} pause_control SEC(".maps");
static long wait_release(__u32 i, void *opaque)
{
	__u32 zero = 0;
	struct pause_control *c = bpf_map_lookup_elem(&pause_control, &zero);
	if (!c)
		return 1;
	return !*(volatile __u32 *)&c->hold;
}
static __always_inline int rendezvous(__u32 phase)
{
	__u32 zero = 0;
	struct pause_control *c = bpf_map_lookup_elem(&pause_control, &zero);
	if (!c || c->when != phase)
		return 0;
	*(volatile __u32 *)&c->phase = phase;
	if (bpf_loop(1U << 22, wait_release, 0, 0) < 0)
		return -1;
	if (*(volatile __u32 *)&c->hold) {
		c->timedout = 1;
		return -1;
	}
	return 0;
}
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
SEC("lsm.s/bprm_check_security")
int BPF_PROG(check_image, struct linux_binprm *bprm, int ret)
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
	int value = -2;
	if (!rendezvous(1)) {
		value = full_file_image(bprm->file);
		if (rendezvous(2))
			value = -2;
	}
	struct result *r = bpf_map_lookup_elem(&results, &zero);
	if (r) {
		r->value = value;
		__sync_fetch_and_add(&r->count, 1);
	}
	if (value < 0)
		return -95;
	return value ? 0 : -1;
}
char LICENSE[] SEC("license") = "GPL";
