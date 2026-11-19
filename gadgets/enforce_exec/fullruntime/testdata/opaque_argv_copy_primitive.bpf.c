// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Disposable copied-byte observation. No argv attribution or policy authority. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define COPY_SAMPLES 128
#define COPY_BYTES 128
struct copy_stats {
	__u64 calls, full_copies, overflow, read_errors;
};
struct copy_sample {
	__u64 pid_tgid, requested;
	__u32 captured;
	__s32 error;
	unsigned char bytes[COPY_BYTES];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u64);
} argv_copy_gate SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct copy_stats);
} argv_copy_stats SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, COPY_SAMPLES);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct copy_sample);
} argv_copy_samples SEC(".maps");

SEC("fexit/_copy_from_user")
int opaque_argv_copy_primitive(__u64 *ctx)
{
	__u32 zero = 0;
	const __u64 *gate = bpf_map_lookup_elem(&argv_copy_gate, &zero);
	if (!gate || !*gate || bpf_get_current_cgroup_id() != *gate)
		return 0;
	struct copy_stats *stats = bpf_map_lookup_elem(&argv_copy_stats, &zero);
	if (!stats)
		return 0;
	__sync_fetch_and_add(&stats->calls, 1);
	__u64 ret = 0, to = 0, n = 0;
	if (bpf_get_func_ret(ctx, &ret) || ret ||
	    bpf_get_func_arg(ctx, 0, &to) || bpf_get_func_arg(ctx, 2, &n) ||
	    !to || !n)
		return 0;
	__u64 index = __sync_fetch_and_add(&stats->full_copies, 1);
	if (index >= COPY_SAMPLES) {
		__sync_fetch_and_add(&stats->overflow, 1);
		return 0;
	}
	__u32 slot = index;
	struct copy_sample *sample =
		bpf_map_lookup_elem(&argv_copy_samples, &slot);
	if (!sample)
		return 0;
	__u32 size = n > COPY_BYTES ? COPY_BYTES : n;
	sample->pid_tgid = bpf_get_current_pid_tgid();
	sample->requested = n;
	sample->captured = size;
	/* Copy while the caller's kernel destination is still live. Cgroup
	 * scoping is isolation, NOT proof this copy belongs to pending argv. */
	sample->error = bpf_probe_read_kernel(sample->bytes, size, (void *)to);
	if (sample->error)
		__sync_fetch_and_add(&stats->read_errors, 1);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
