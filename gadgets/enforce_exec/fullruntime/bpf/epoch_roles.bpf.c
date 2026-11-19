/* SPDX-License-Identifier: GPL-2.0 */
/* No attachment: pure epoch helper parity through BPF_PROG_TEST_RUN. */
typedef unsigned long long __u64;
typedef unsigned int __u32;
#define SEC(name) __attribute__((section(name), used))
#define MAP_UINT(name, value) int(*name)[value]
#define MAP_TYPE(name, value) value *name
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 64);
	MAP_TYPE(key, __u32);
	MAP_TYPE(value, __u64);
} accepted_history SEC(".maps");
static void *(*er_map_lookup)(void *, const void *) = (void *)1;
static __inline __attribute__((always_inline)) __u64 er_test_accepted(__u64 uid)
{
	if (uid >= 64)
		return ~(__u64)0;
	__u32 key = uid;
	__u64 *epoch = er_map_lookup(&accepted_history, &key);
	return epoch ? *epoch : ~(__u64)0;
}
#define ER_ACCEPTED_EPOCH(uid) er_test_accepted(uid)
#include "../../full/epoch_roles.h"
struct er_test_frame {
	struct er_state state;
	struct er_work work;
	struct er_candidate candidate;
	struct er_row source[ER_SLOTS];
	__u64 authority_version;
	__u32 operation;
	int lineage, result;
	__u32 padding;
};
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, __u32);
	MAP_TYPE(value, struct er_test_frame);
} epoch_frame SEC(".maps");
SEC("socket") int epoch_roles_test(void *unused)
{
	(void)unused;
	__u32 key = 0;
	struct er_test_frame *f = er_map_lookup(&epoch_frame, &key);
	if (!f)
		return 99;
	if (f->operation == 1 || f->operation == 2) {
		er_snapshot(&f->work, &f->state, f->authority_version);
		if (f->operation == 1)
			f->result = er_stage_roots(&f->work, &f->candidate,
						   f->lineage);
		else
			f->result =
				er_inherit(&f->work, &f->candidate, f->source);
	} else if (f->operation == 3)
		f->result =
			er_publish(&f->state, &f->work, f->authority_version);
	else
		f->result = ER_INVALID;
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
