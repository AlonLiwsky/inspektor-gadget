/* SPDX-License-Identifier: GPL-2.0 */
/* Map ABI probe, not an exec/lineage/admission test. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
struct ps_inner {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u8[288]);
};
struct ps_inner inner_template SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, struct ps_inner);
} programs SEC(".maps");
static __always_inline int generation(__u32 slot)
{
	void *inner = bpf_map_lookup_elem(&programs, &slot);
	if (!inner)
		return 0;
	__u32 zero = 0;
	__u64 *header = bpf_map_lookup_elem(inner, &zero);
	return header ? *header : 0;
}
SEC("socket") int ps_active(struct __sk_buff *skb)
{
	return generation(0);
}
SEC("socket") int ps_staging(struct __sk_buff *skb)
{
	return generation(1);
}
SEC("socket") int forbidden_delete(struct __sk_buff *skb)
{
	__u32 zero = 0;
	return bpf_map_delete_elem(&programs, &zero);
}
char LICENSE[] SEC("license") = "GPL";
