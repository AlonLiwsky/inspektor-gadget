// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Disposable post-copy observation, never argv attribution or policy authority. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct copy_frame {
	__u64 physical, pid_tgid, to, n;
	__u32 depth, uncertain;
};
struct copy_stats {
	__u64 entries, returns, full_copies, overflow, read_errors, incomplete,
		missing;
};
struct copy_sample {
	__u64 pid_tgid, requested;
	__u32 captured;
	__s32 error;
	unsigned char bytes[128];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u64);
} argv_kret_gate SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct copy_stats);
} argv_kret_stats SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct copy_frame);
} argv_kret_frames SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct copy_sample);
} argv_kret_samples SEC(".maps");

SEC("kprobe/_copy_from_user")
int BPF_KPROBE(opaque_argv_copy_enter, void *to, const void *from,
	       unsigned long n)
{
	(void)from;
	__u32 zero = 0;
	const __u64 *gate = bpf_map_lookup_elem(&argv_kret_gate, &zero);
	if (!gate || !*gate || bpf_get_current_cgroup_id() != *gate)
		return 0;
	struct copy_stats *stats = bpf_map_lookup_elem(&argv_kret_stats, &zero);
	if (!stats)
		return 0;
	__sync_fetch_and_add(&stats->entries, 1);
	__u64 key = bpf_get_current_pid_tgid();
	struct copy_frame *old = bpf_map_lookup_elem(&argv_kret_frames, &key);
	if (old) {
		old->uncertain = 1;
		if (old->depth < 8)
			old->depth++;
		else
			__sync_fetch_and_add(&stats->incomplete, 1);
		return 0;
	}
	struct copy_frame frame = { .physical =
					    (__u64)bpf_get_current_task_btf(),
				    .pid_tgid = key,
				    .to = (__u64)to,
				    .n = n,
				    .depth = 1 };
	if (bpf_map_update_elem(&argv_kret_frames, &key, &frame, BPF_NOEXIST))
		__sync_fetch_and_add(&stats->incomplete, 1);
	return 0;
}
SEC("kretprobe/_copy_from_user")
int BPF_KRETPROBE(opaque_argv_copy_return, unsigned long ret)
{
	__u32 zero = 0;
	__u64 key = bpf_get_current_pid_tgid();
	struct copy_stats *stats = bpf_map_lookup_elem(&argv_kret_stats, &zero);
	if (!stats)
		return 0;
	struct copy_frame *frame = bpf_map_lookup_elem(&argv_kret_frames, &key);
	if (!frame) {
		const __u64 *gate = bpf_map_lookup_elem(&argv_kret_gate, &zero);
		if (gate && *gate && bpf_get_current_cgroup_id() == *gate)
			__sync_fetch_and_add(&stats->missing, 1);
		return 0;
	}
	__sync_fetch_and_add(&stats->returns, 1);
	if (frame->depth > 1) {
		frame->depth--;
		return 0;
	}
	if (frame->depth != 1 || frame->uncertain || frame->pid_tgid != key ||
	    frame->physical != (__u64)bpf_get_current_task_btf() ||
	    !frame->to || !frame->n || ret) {
		__sync_fetch_and_add(&stats->incomplete, 1);
		goto done;
	}
	__u64 index = __sync_fetch_and_add(&stats->full_copies, 1);
	if (index >= 128) {
		__sync_fetch_and_add(&stats->overflow, 1);
		goto done;
	}
	__u32 slot = index;
	struct copy_sample *sample =
		bpf_map_lookup_elem(&argv_kret_samples, &slot);
	if (!sample) {
		__sync_fetch_and_add(&stats->incomplete, 1);
		goto done;
	}
	__u32 size = frame->n > 128 ? 128 : frame->n;
	sample->pid_tgid = key;
	sample->requested = frame->n;
	sample->captured = size;
	sample->error =
		bpf_probe_read_kernel(sample->bytes, size, (void *)frame->to);
	if (sample->error)
		__sync_fetch_and_add(&stats->read_errors, 1);
done:
	if (bpf_map_delete_elem(&argv_kret_frames, &key))
		__sync_fetch_and_add(&stats->incomplete, 1);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
