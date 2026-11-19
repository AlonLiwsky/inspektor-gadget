// SPDX-License-Identifier: GPL-2.0
// Offline ELF/BTF inspection only: no bpf_object__load or kernel-map creation.
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include "shape.h"
#include "operations.h"
#include "program-type.h"
#include "map-contract.h"
struct spec {
	const char *name;
	enum bpf_map_type type;
	unsigned key, value, count, flags;
};
#define RW BPF_F_RDONLY
static const struct spec specs[] = {
	{ "tasks", BPF_MAP_TYPE_HASH, 8, 3024, 4096, RW },
	{ "observations", BPF_MAP_TYPE_HASH, 16, 15936, 1024, RW },
	{ "catalogue", BPF_MAP_TYPE_HASH, 8, 16, 65536, RW },
	{ "program0", BPF_MAP_TYPE_ARRAY, 4, 296, 16384, RW },
	{ "program1", BPF_MAP_TYPE_ARRAY, 4, 296, 16384, RW },
	{ "scope", BPF_MAP_TYPE_ARRAY, 4, 408, 1, RW },
	{ "config", BPF_MAP_TYPE_ARRAY, 4, 48, 1, BPF_F_RDONLY_PROG },
	{ "command", BPF_MAP_TYPE_ARRAY, 4, 328, 1, BPF_F_RDONLY_PROG },
	{ "inventory", BPF_MAP_TYPE_ARRAY, 4, 40, 4096, RW },
	{ "adminwork", BPF_MAP_TYPE_ARRAY, 4, 1368, 1, RW },
	{ "zeroTask", BPF_MAP_TYPE_ARRAY, 4, 3024, 1, BPF_F_RDONLY_PROG },
	{ "zeroObservation", BPF_MAP_TYPE_ARRAY, 4, 15936, 1,
	  BPF_F_RDONLY_PROG },
};
static void layouts(const struct btf *b)
{
#define CHECK(T, N)                                                           \
	do {                                                                  \
		int id = btf__find_by_name_kind(b, #T, BTF_KIND_STRUCT);      \
		assert(id > 0);                                               \
		assert(btf__resolve_size(b, id) == N);                        \
		assert(sizeof(struct T) == N);                                \
		printf("layout %s native=%zu BTF=%d\n", #T, sizeof(struct T), \
		       N);                                                    \
	} while (0)
	CHECK(rs_role, 32);
	CHECK(rs_bank, 536);
	CHECK(rs_descriptor, 24);
	CHECK(rs_lineage, 64);
	CHECK(rs_authority, 32);
	CHECK(rs_view, 264);
	CHECK(rs_merge, 536);
	CHECK(rs_addition, 16);
	CHECK(rs_exec, 344);
	CHECK(rs_fork, 80);
	CHECK(rs_ingress, 64);
	CHECK(rs_work, 1368);
	CHECK(rs_task, 3024);
	CHECK(rs_observation, 15936);
	CHECK(rs_chunk, 296);
	CHECK(rs_candidate, 216);
	CHECK(rs_scope, 408);
	CHECK(rs_config, 48);
	CHECK(rs_command, 328);
	CHECK(rs_inventory, 40);
#undef CHECK
}
int main(int argc, char **argv)
{
	assert(rs_map_access_valid(BPF_F_RDONLY, 0, O_RDONLY));
	assert(rs_map_access_valid(BPF_F_WRONLY, 0, O_WRONLY));
	assert(rs_map_access_valid(BPF_F_RDONLY_PROG, BPF_F_RDONLY_PROG,
				   O_RDWR));
	assert(rs_map_access_valid(
		BPF_F_RDONLY | BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG,
		BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG, O_RDONLY));
	assert(!rs_map_access_valid(BPF_F_RDONLY, 0, O_RDWR));
	assert(!rs_map_access_valid(BPF_F_RDONLY, BPF_F_RDONLY, O_RDONLY));
	assert(!rs_map_access_valid(BPF_F_RDONLY_PROG, 0, O_RDWR));
	assert(!rs_map_access_valid(BPF_F_RDONLY | BPF_F_NO_PREALLOC, 0,
				    O_RDONLY));
	assert(!rs_map_access_valid(0, BPF_F_NO_PREALLOC, O_RDWR));
	assert(!rs_map_access_valid(BPF_F_RDONLY | BPF_F_WRONLY, 0, O_RDONLY));
	assert(!rs_map_access_valid(0, 0, -1));
	puts("PASS FD-only flag stripping; exact remaining flags/access mode enforced, mismatch negatives rejected");
	struct rs_bank a = { .stamp = 23, .task_cookie = 42, .version = 9 },
		       b = {};
	for (unsigned i = 0; i < 16; i++) {
		struct rs_role r = { .uid = i + 1,
				     .root_epoch = 100 + i,
				     .role = i + 4,
				     .knowledge = i != 7 };
		assert(rs_append(&a, &r) == 0);
	}
	struct rs_role extra = {
		.uid = 17, .root_epoch = 222, .role = 19, .knowledge = 1
	};
	struct rs_bank before = a;
	assert(rs_append(&a, &extra) == -28);
	assert(!memcmp(&before, &a, sizeof(a)));
	rs_copy(&b, &a);
	assert(!memcmp(&a, &b, sizeof(a)));
	assert(b.rows[7].knowledge == 0 && b.rows[7].root_epoch == 107);
	puts("PASS native 16 retained rows, UNKNOWN/epoch copy, unchanged 17th refusal (not kernel proof)");
	assert(argc == 2 ||
	       (argc == 3 && !strcmp(argv[2], "--reject-program-type")));
	struct bpf_object *o = bpf_object__open_file(argv[1], NULL);
	assert(o && !libbpf_get_error(o));
	if (argc == 3) {
		assert(!rs_program_type_valid(o));
		puts("PASS negative ELF program type/flags rejected before load");
		bpf_object__close(o);
		return 0;
	}
	assert(rs_program_type_valid(o));
	struct bpf_program *p = bpf_object__find_program_by_name(o, "shape");
	assert(p);
	assert(!bpf_program__set_type(p, BPF_PROG_TYPE_SOCKET_FILTER));
	assert(!rs_program_type_valid(o));
	assert(!bpf_program__set_type(p, BPF_PROG_TYPE_SYSCALL));
	assert(!bpf_program__set_flags(p, BPF_F_ANY_ALIGNMENT));
	assert(!rs_program_type_valid(o));
	assert(!bpf_program__set_flags(p, 0));
	assert(rs_program_type_valid(o));
	puts("PASS open-only program shape: syscall, explicit flags0; negative SOCKET_FILTER and unexpected flags rejected");
	layouts(bpf_object__btf(o));
	unsigned count = 0;
	unsigned long long payload = 0, keys = 0;
	struct bpf_map *m;
	bpf_object__for_each_map(m, o) count++;
	assert(count == sizeof(specs) / sizeof(specs[0]));
	for (unsigned i = 0; i < count; i++) {
		const struct spec *s = &specs[i];
		m = bpf_object__find_map_by_name(o, s->name);
		assert(m);
		assert(bpf_map__type(m) == s->type &&
		       bpf_map__key_size(m) == s->key);
		assert(bpf_map__value_size(m) == s->value &&
		       bpf_map__max_entries(m) == s->count);
		assert(bpf_map__map_flags(m) == s->flags);
		payload += (unsigned long long)s->value * s->count;
		if (s->type == BPF_MAP_TYPE_HASH)
			keys += (unsigned long long)s->key * s->count;
		printf("map %s type=%u key=%u value=%u capacity=%u flags=%u (ELF only, no live mapinfo)\n",
		       s->name, s->type, s->key, s->value, s->count, s->flags);
	}
	assert(payload == 39637624ULL && keys == 573440ULL);
	printf("core payload=%llu HASH keys=%llu; NOT a physical or whole-owner ceiling\n",
	       payload, keys);
	bpf_object__close(o);
	return 0;
}
