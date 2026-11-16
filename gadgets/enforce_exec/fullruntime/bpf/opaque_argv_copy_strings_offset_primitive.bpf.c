// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Default-off, exact-image observer. No policy, verdict or complete argv claim. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct offset_gate {
	__u64 cgroup;
	__u32 profile, reserved;
};
struct offset_stats {
	__u64 seen, full_copies, failed_copies, read_errors, incomplete,
		overflow;
};
struct offset_sample {
	__u64 task, pid_tgid, bprm, pending, destination, requested;
	__u32 captured;
	__s32 error;
	unsigned char bytes[128];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct offset_gate);
} argv_offset_gate SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct offset_stats);
} argv_offset_stats SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct offset_sample);
} argv_offset_samples SEC(".maps");

/* Loader selects only the independently derived post-copy instruction for the
 * exact release + installed image + running BTF identity. Registers and stack
 * locations below are NOT a kernel ABI and must not become a generic fallback. */
SEC("kprobe/copy_strings.isra.0")
int opaque_argv_copy_strings_postcopy(struct pt_regs *ctx)
{
	__u32 zero = 0;
	const struct offset_gate *gate =
		bpf_map_lookup_elem(&argv_offset_gate, &zero);
	if (!gate || !gate->cgroup || gate->reserved ||
	    bpf_get_current_cgroup_id() != gate->cgroup)
		return 0;
	struct offset_stats *stats =
		bpf_map_lookup_elem(&argv_offset_stats, &zero);
	if (!stats)
		return 0;
	__sync_fetch_and_add(&stats->seen, 1);
	if (PT_REGS_RC(ctx)) {
		__sync_fetch_and_add(&stats->failed_copies, 1);
		return 0;
	}
	__u64 destination = 0, length = 0, bprm = 0;
	__u64 stack = PT_REGS_SP(ctx);
	if (gate->profile == 1) {
		/* AL2023 6.12.113-138.209, copy_strings.isra.0+0x180. */
		length = ctx->r15;
		if (bpf_probe_read_kernel(&destination, sizeof(destination),
					  (void *)stack) ||
		    bpf_probe_read_kernel(&bprm, sizeof(bprm),
					  (void *)(stack + 0x10)))
			goto read_error;
	} else if (gate->profile == 2) {
		/* AL2023 6.18.56-125.164, copy_strings.isra.0+0x1ad. */
		destination = ctx->r15;
		if (bpf_probe_read_kernel(&length, sizeof(length),
					  (void *)(stack + 0x10)) ||
		    bpf_probe_read_kernel(&bprm, sizeof(bprm),
					  (void *)(stack + 8)))
			goto read_error;
	} else {
		goto incomplete;
	}
	/* No truncated sample is accepted by this bounded primitive. */
	if (!destination || !bprm || !ctx->bx || !length || length > 128)
		goto incomplete;
	/* Keep the helper size visibly in [1,128] after LLVM's merged range
	 * check. Equality to the original length forbids truncation; the empty
	 * barrier prevents LLVM replacing this bounded scalar with that input. */
	__u32 captured = (__u32)(length - 1);
	asm volatile("" : "+r"(captured));
	captured = (captured & 127U) + 1U;
	if ((__u64)captured != length)
		goto incomplete;
	__u64 index = __sync_fetch_and_add(&stats->full_copies, 1);
	if (index >= 128) {
		__sync_fetch_and_add(&stats->overflow, 1);
		return 0;
	}
	__u32 slot = index;
	struct offset_sample *sample =
		bpf_map_lookup_elem(&argv_offset_samples, &slot);
	if (!sample)
		goto incomplete;
	sample->task = (__u64)bpf_get_current_task_btf();
	sample->pid_tgid = bpf_get_current_pid_tgid();
	sample->bprm = bprm;
	sample->pending = ctx->bx;
	sample->destination = destination;
	sample->requested = length;
	sample->captured = captured;
	sample->error = bpf_probe_read_kernel(sample->bytes, captured,
					      (void *)destination);
	if (sample->error)
		goto read_error;
	return 0;
read_error:
	__sync_fetch_and_add(&stats->read_errors, 1);
	return 0;
incomplete:
	__sync_fetch_and_add(&stats->incomplete, 1);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
