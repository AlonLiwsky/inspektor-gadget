// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Test-only, default-off G020 image classifier probe. Pass-through LSM: it
 * records se_image_classify for execs of one dedicated cgroup and never denies.
 * Not the product object; keys are a writable test map, not the product's
 * kernel-written BPF_F_RDONLY se_image_keys. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shared_image.h"

#define SE_IMAGE_CLASSIFY_EXTERNAL_KEYS
struct se_image_map_key {
	__u64 image_handle;
	struct se_image_key origin;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct se_image_map_key);
	__type(value, __u8);
} se_image_keys SEC(".maps");
#define SE_IMAGE_CLASS_WITNESS_MAP
#include "shared_image_classify.h"

struct probe_config {
	__u64 cgroup, handle;
	__u32 image_dev, armed;
};
struct probe_result {
	__s32 value;
	__u32 count;
	__u32 btf_offset, size_offset;
};
_Static_assert(sizeof(struct probe_config) == 24, "probe config ABI");
_Static_assert(sizeof(struct probe_result) == 16, "probe result ABI");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct probe_config);
} probe_config SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct probe_result);
} probe_results SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(se_image_classify_probe, struct linux_binprm *bprm, int ret)
{
	__u32 zero = 0;
	struct probe_config *cfg = bpf_map_lookup_elem(&probe_config, &zero);
	if (ret || !cfg || !cfg->armed ||
	    bpf_get_current_cgroup_id() != cfg->cgroup)
		return ret;
	struct probe_result *res = bpf_map_lookup_elem(&probe_results, &zero);
	struct se_image_class_witness *w =
		bpf_map_lookup_elem(&se_image_class_witnesses, &zero);
	if (!res)
		return 0;
	res->value =
		se_image_classify(bprm->file, cfg->handle, cfg->image_dev, w);
	se_image_user_path_offset(&res->btf_offset, &res->size_offset);
	__sync_fetch_and_add(&res->count, 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
