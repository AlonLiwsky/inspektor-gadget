// SPDX-License-Identifier: GPL-2.0
// Maximum storage shape only. Synthetic keys do NOT prove task lifetime.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "shape.h"
#include "operations.h"
#define MAP(N, T, K, V, C, F)           \
	struct {                        \
		__uint(type, T);        \
		__uint(max_entries, C); \
		__uint(map_flags, F);   \
		__type(key, K);         \
		__type(value, V);       \
	} N SEC(".maps")
MAP(tasks, BPF_MAP_TYPE_HASH, __u64, struct rs_task, 4096, BPF_F_RDONLY);
MAP(observations, BPF_MAP_TYPE_HASH, struct rs_observation_key,
    struct rs_observation, 1024, BPF_F_RDONLY);
MAP(catalogue, BPF_MAP_TYPE_HASH, __u64, struct rs_addition, 65536,
    BPF_F_RDONLY);
MAP(program0, BPF_MAP_TYPE_ARRAY, __u32, struct rs_chunk, 16384, BPF_F_RDONLY);
MAP(program1, BPF_MAP_TYPE_ARRAY, __u32, struct rs_chunk, 16384, BPF_F_RDONLY);
MAP(scope, BPF_MAP_TYPE_ARRAY, __u32, struct rs_scope, 1, BPF_F_RDONLY);
MAP(config, BPF_MAP_TYPE_ARRAY, __u32, struct rs_config, 1, BPF_F_RDONLY_PROG);
MAP(command, BPF_MAP_TYPE_ARRAY, __u32, struct rs_command, 1,
    BPF_F_RDONLY_PROG);
MAP(inventory, BPF_MAP_TYPE_ARRAY, __u32, struct rs_inventory, 4096,
    BPF_F_RDONLY);
MAP(adminwork, BPF_MAP_TYPE_ARRAY, __u32, struct rs_work, 1, BPF_F_RDONLY);
/* Zero templates deliberately lack spin-lock BTF and may be frozen. */
typedef __u8 zero_task[sizeof(struct rs_task)];
typedef __u8 zero_observation[sizeof(struct rs_observation)];
MAP(zeroTask, BPF_MAP_TYPE_ARRAY, __u32, zero_task, 1, BPF_F_RDONLY_PROG);
MAP(zeroObservation, BPF_MAP_TYPE_ARRAY, __u32, zero_observation, 1,
    BPF_F_RDONLY_PROG);
struct scan_ctx {
	__u64 attempt;
	__u32 bank, bad;
};
static long scan_chunk(__u32 index, void *opaque)
{
	struct scan_ctx *c = opaque;
	struct rs_chunk *p = c->bank ? bpf_map_lookup_elem(&program1, &index) :
				       bpf_map_lookup_elem(&program0, &index);
	if (!p || p->attempt != c->attempt) {
		c->bad = 1;
		return 1;
	}
	return 0;
}
/* All pointers prelooked up; this is primitive shape, NOT the production ARM
 * endpoint, authentication, catalogue reservation exclusion or receipt proof. */
static __noinline int max8(struct rs_scope *s, const struct rs_command *q)
{
	struct rs_addition *p[8];
#pragma unroll
	for (int i = 0; i < 8; i++) {
		__u64 key = q->payload.words[i];
		p[i] = bpf_map_lookup_elem(&catalogue, &key);
		if (!p[i])
			return -2;
	}
	bpf_spin_lock(&s->lock);
	if (s->authority_readers || s->candidate.writers ||
	    s->serial == ~0ULL || s->candidate.attempt != q->attempt) {
		bpf_spin_unlock(&s->lock);
		return -16;
	}
#pragma unroll
	for (int i = 0; i < 8; i++)
		if (p[i]->epoch || !s->candidate.additions[i].epoch ||
		    p[i]->uid != s->candidate.additions[i].uid) {
			bpf_spin_unlock(&s->lock);
			return -22;
		}
	asm volatile(".global rs_commit_begin\nrs_commit_begin:\n%0 = %0;\n"
		     : "+r"(s)
		     :
		     : "memory");
#pragma unroll
	for (int i = 0; i < 8; i++)
		p[i]->epoch = s->candidate.additions[i].epoch;
	s->active.generation = s->candidate.attempt;
	s->active.program_bank = s->candidate.program_bank;
	s->active.role_bank = s->candidate.role_bank;
	s->active.mode = s->candidate.mode;
	s->candidate.state = 6;
	s->serial++;
	asm volatile(".global rs_commit_end\nrs_commit_end:\n%0 = %0;\n"
		     :
		     : "r"(s)
		     : "memory");
	bpf_spin_unlock(&s->lock);
	return 0;
}
/* No loader/authentication claim. Future runs must use BPF_PROG_TEST_RUN only,
 * on separately approved disposable kernels; this object is never attached. */
SEC("syscall") int shape(void *ctx)
{
	(void)ctx;
	__u32 z = 0;
	struct rs_command *q = bpf_map_lookup_elem(&command, &z);
	struct rs_config *c = bpf_map_lookup_elem(&config, &z);
	struct rs_scope *s = bpf_map_lookup_elem(&scope, &z);
	if (!q || !c || !s || !c->nonce || q->nonce != c->nonce)
		return -1;
	__u64 key = q->cookie;
	struct rs_task *t;
	if (q->op == 1) {
		void *v = bpf_map_lookup_elem(&zeroTask, &z);
		if (!v)
			return -2;
		return bpf_map_update_elem(&tasks, &key, v, BPF_NOEXIST);
	}
	if (q->op == 2) {
		t = bpf_map_lookup_elem(&tasks, &key);
		if (!t || !t->owns_capacity || t->cookie != q->attempt)
			return -3;
		return bpf_map_delete_elem(&tasks, &key);
	}
	if (q->op == 3) {
		t = bpf_map_lookup_elem(&tasks, &key);
		if (!t)
			return -2;
		bpf_spin_lock(&t->lock);
		t->cookie = q->attempt;
		t->owns_capacity = 1;
		bpf_spin_unlock(&t->lock);
		return 0;
	}
	if (q->op == 4) {
		struct rs_observation_key k = { key, q->attempt };
		void *v = bpf_map_lookup_elem(&zeroObservation, &z);
		if (!v)
			return -2;
		return bpf_map_update_elem(&observations, &k, v, BPF_NOEXIST);
	}
	if (q->op == 5) {
		struct rs_observation_key k = { key, q->attempt };
		struct rs_observation *o =
			bpf_map_lookup_elem(&observations, &k);
		if (!o)
			return -2;
		o->argument[4096] = 123;
		o->scratch.arg_lengths[63] = 4096;
		o->facts.argv[4095] = 99;
		return 0;
	}
	if (q->op == 6) {
		struct rs_observation_key k = { key, q->attempt };
		return bpf_map_delete_elem(&observations, &k);
	}
	if (q->op == 7) {
		t = bpf_map_lookup_elem(&tasks, &key);
		if (!t)
			return -2;
		struct rs_role r = { .uid = q->payload.words[0],
				     .root_epoch = q->payload.words[1],
				     .role = q->payload.words[2],
				     .knowledge = q->length };
		bpf_spin_lock(&t->lock);
		int result = rs_append(&t->bank[0], &r);
		bpf_spin_unlock(&t->lock);
		return result;
	}
	if (q->op == 8) {
		t = bpf_map_lookup_elem(&tasks, &key);
		if (!t)
			return -2;
		bpf_spin_lock(&t->lock);
		rs_copy(&t->bank[1], &t->bank[0]);
		bpf_spin_unlock(&t->lock);
		return 0;
	}
	if (q->op == 9) {
		if (q->bank > 1 || q->index >= 16384 ||
		    q->bank == s->active.program_bank)
			return -22;
		__u32 index = q->index;
		struct rs_chunk *p =
			q->bank ? bpf_map_lookup_elem(&program1, &index) :
				  bpf_map_lookup_elem(&program0, &index);
		if (!p)
			return -2;
		p->data = q->payload;
		p->attempt = q->attempt;
		return 0;
	}
	if (q->op == 10) {
		if (q->bank > 1 || q->bank == s->active.program_bank)
			return -22;
		struct scan_ctx scan = { .attempt = q->attempt,
					 .bank = q->bank };
		long n = bpf_loop(16384, scan_chunk, &scan, 0);
		return n == 16384 && !scan.bad ? 0 : -22;
	}
	if (q->op == 11) {
		struct rs_addition a = { .uid = key };
		return bpf_map_update_elem(&catalogue, &key, &a, BPF_NOEXIST);
	}
	if (q->op == 12)
		return max8(s, q);
	if (q->op == 13) {
		if (q->bank > 1 || q->bank == s->active.program_bank ||
		    !q->attempt)
			return -22;
		bpf_spin_lock(&s->lock);
		s->candidate.attempt = q->attempt;
		s->candidate.program_bank = q->bank;
		s->candidate.role_bank = q->bank;
		s->candidate.mode = 1;
#pragma unroll
		for (int i = 0; i < 8; i++) {
			s->candidate.additions[i].uid = q->payload.words[i];
			s->candidate.additions[i].epoch = q->attempt + i;
		}
		bpf_spin_unlock(&s->lock);
		return 0;
	}
	return -22;
}
char LICENSE[] SEC("license") = "GPL";
