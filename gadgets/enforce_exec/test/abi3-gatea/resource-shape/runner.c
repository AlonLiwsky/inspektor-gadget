// SPDX-License-Identifier: GPL-2.0
// NOT invoked by build.sh. Exact disposable-kernel wrapper required.
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "shape.h"
#include "program-type.h"
#include "map-contract.h"
static struct bpf_object *obj;
static int prog;
static __u32 zero;
static __u32 ids[12], program_id;
static struct rs_command q = { .nonce = 0x12345678 };
static int fd(const char *name)
{
	struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
	assert(m);
	return bpf_map__fd(m);
}
static int invoke(unsigned op)
{
	q.op = op;
	assert(!bpf_map_update_elem(fd("command"), &zero, &q, BPF_ANY));
	/* SYSCALL test-run uses no packet/context, matching publication fixture. */
	LIBBPF_OPTS(bpf_test_run_opts, t);
	int e = bpf_prog_test_run_opts(prog, &t);
	if (e)
		fprintf(stderr, "test_run op=%u errno=%d\n", op, errno);
	assert(!e);
	return (int)t.retval;
}
static void read_scope(struct rs_scope *s)
{
	assert(!bpf_map_lookup_elem_flags(fd("scope"), &zero, s, BPF_F_LOCK));
}
static void info(int initial)
{
	struct bpf_map *m;
	unsigned i = 0;
	bpf_object__for_each_map(m, obj)
	{
		struct bpf_map_info v = {};
		__u32 size = sizeof(v);
		assert(i < 12);
		int query = bpf_obj_get_info_by_fd(bpf_map__fd(m), &v, &size);
		int query_errno = errno,
		    fd_flags = fcntl(bpf_map__fd(m), F_GETFL);
		unsigned declared = bpf_map__map_flags(m);
		printf("mapinfo %s id=%u type=%u key=%u value=%u capacity=%u actual_flags=%u declared_flags=%u expected_persistent=%u fd_flags=%d access=%d expected_access=%d query=%d query_errno=%d\n",
		       bpf_map__name(m), v.id, v.type, v.key_size, v.value_size,
		       v.max_entries, v.map_flags, declared,
		       rs_persistent_flags(declared), fd_flags,
		       fd_flags < 0 ? -1 : (fd_flags & O_ACCMODE),
		       rs_fd_mode(declared), query, query_errno);
		assert(!query);
		assert(v.type == bpf_map__type(m) &&
		       v.key_size == bpf_map__key_size(m));
		assert(v.value_size == bpf_map__value_size(m) &&
		       v.max_entries == bpf_map__max_entries(m));
		assert(rs_map_access_valid(declared, v.map_flags, fd_flags));
		if (initial)
			ids[i] = v.id;
		else
			assert(ids[i] == v.id);
		i++;
	}
	assert(i == 12);
}
static void permissions(void)
{
	/* Deliberately out-of-range ARRAY key: even if FD protection regresses,
  * this write cannot touch an entry or any committed state. Pinned syscall.c
  * rejects readonly FDs with EPERM before array bounds are evaluated. */
	__u32 invalid = 4096;
	struct rs_inventory value = {};
	errno = 0;
	int result = bpf_map_update_elem(fd("inventory"), &invalid, &value,
					 BPF_ANY),
	    error = errno;
	printf("readonly_write_probe inventory key=%u result=%d errno=%d expected=%d\n",
	       invalid, result, error, EPERM);
	assert(result == -EPERM && error == EPERM);
	/* RDONLY_PROG is a BPF-access property, not a host FD access mode. */
	struct rs_config before, after;
	assert(!bpf_map_lookup_elem(fd("config"), &zero, &before));
	assert(!bpf_map_update_elem(fd("config"), &zero, &before, BPF_ANY));
	assert(!bpf_map_lookup_elem(fd("config"), &zero, &after));
	assert(!memcmp(&before, &after, sizeof(before)));
	struct rs_command old_command, new_command;
	assert(!bpf_map_lookup_elem(fd("command"), &zero, &old_command));
	assert(!bpf_map_update_elem(fd("command"), &zero, &old_command,
				    BPF_ANY));
	assert(!bpf_map_lookup_elem(fd("command"), &zero, &new_command));
	assert(!memcmp(&old_command, &new_command, sizeof(old_command)));
	puts("PASS readonly owned FD write EPERM; config/command host writes succeed with RDONLY_PROG retained");
}
static void storage(void)
{
	q.attempt = 77;
	for (q.cookie = 1; q.cookie <= 4096; q.cookie++)
		assert(!invoke(1));
	q.cookie = 1;
	assert(invoke(1) == -EEXIST);
	q.cookie = 4097;
	assert(invoke(1) == -E2BIG);
	q.cookie = 1;
	assert(invoke(2) == -3);
	assert(!invoke(3));
	for (unsigned i = 0; i < 16; i++) {
		q.payload.words[0] = i + 1;
		q.payload.words[1] = 100 + i;
		q.payload.words[2] = i + 4;
		q.length = i != 7;
		assert(!invoke(7));
	}
	struct rs_task before, after;
	assert(!bpf_map_lookup_elem_flags(fd("tasks"), &q.cookie, &before,
					  BPF_F_LOCK));
	q.payload.words[0] = 17;
	assert(invoke(7) == -ENOSPC);
	assert(!bpf_map_lookup_elem_flags(fd("tasks"), &q.cookie, &after,
					  BPF_F_LOCK));
	assert(!memcmp(&before, &after, sizeof(before)));
	assert(!invoke(8));
	assert(!bpf_map_lookup_elem_flags(fd("tasks"), &q.cookie, &after,
					  BPF_F_LOCK));
	assert(!memcmp(&after.bank[0], &after.bank[1], sizeof(after.bank[0])));
	assert(after.bank[1].rows[7].knowledge == 0 &&
	       after.bank[1].rows[7].root_epoch == 107);
	q.attempt = 78;
	assert(invoke(2) == -3);
	q.attempt = 77;
	assert(!invoke(2));
	assert(invoke(2) == -3);
	assert(!invoke(1));
	assert(!invoke(3));
	for (q.cookie = 1; q.cookie <= 4096; q.cookie++) {
		assert(!invoke(3));
		assert(!invoke(2));
	}
	for (q.cookie = 1; q.cookie <= 1024; q.cookie++)
		assert(!invoke(4));
	q.cookie = 1;
	assert(invoke(4) == -EEXIST);
	q.cookie = 1025;
	assert(invoke(4) == -E2BIG);
	q.cookie = 1024;
	assert(!invoke(5));
	struct rs_observation o;
	struct rs_observation_key k = { q.cookie, q.attempt };
	assert(!bpf_map_lookup_elem(fd("observations"), &k, &o));
	assert(o.argument[4096] == 123 && o.scratch.arg_lengths[63] == 4096 &&
	       o.facts.argv[4095] == 99);
	assert(!invoke(6));
	assert(invoke(6) == -ENOENT);
	assert(!invoke(4));
	for (q.cookie = 1; q.cookie <= 1024; q.cookie++)
		assert(!invoke(6));
	puts("PASS preallocated full tasks/observations, NOEXIST, owned deletion/refill, 16 rows/UNKNOWN/17th refusal, high offsets");
}
static void cycles(void)
{
	for (unsigned cycle = 0; cycle < 2; cycle++) {
		q.bank = 1 - cycle;
		q.attempt = 1000 + cycle * 100;
		struct rs_scope before, after;
		read_scope(&before);
		const char *active = before.active.program_bank ? "program1" :
								  "program0";
		struct rs_chunk old_first, old_last, current;
		__u32 last = 16383;
		assert(!bpf_map_lookup_elem(fd(active), &zero, &old_first));
		assert(!bpf_map_lookup_elem(fd(active), &last, &old_last));
		for (q.index = 0; q.index < 16384; q.index++) {
			q.payload.words[0] = q.index;
			assert(!invoke(9));
		}
		assert(!invoke(10));
		q.index = 16384;
		assert(invoke(9) == -EINVAL);
		q.index = 16383;
		q.attempt++;
		assert(!invoke(9));
		q.attempt--;
		assert(invoke(10) == -EINVAL);
		read_scope(&after);
		assert(!memcmp(&before.active, &after.active,
			       sizeof(before.active)));
		assert(!bpf_map_lookup_elem(fd(active), &zero, &current));
		assert(!memcmp(&current, &old_first, sizeof(current)));
		assert(!bpf_map_lookup_elem(fd(active), &last, &current));
		assert(!memcmp(&current, &old_last, sizeof(current)));
		assert(!invoke(9));
		assert(!invoke(10));
		for (unsigned i = 0; i < 8; i++) {
			q.cookie = cycle * 8 + i + 1;
			assert(!invoke(11));
			q.payload.words[i] = q.cookie;
		}
		assert(!invoke(13));
		assert(!invoke(12));
		read_scope(&after);
		assert(after.active.generation == q.attempt &&
		       after.active.program_bank == q.bank &&
		       after.candidate.state == 6);
		for (unsigned i = 0; i < 8; i++) {
			struct rs_addition a;
			__u64 key = cycle * 8 + i + 1;
			assert(!bpf_map_lookup_elem(fd("catalogue"), &key, &a));
			assert(a.uid == key && a.epoch == q.attempt + i);
		}
		assert(invoke(12) == -EINVAL);
		info(0);
	}
	for (q.cookie = 17; q.cookie <= 65536; q.cookie++)
		assert(!invoke(11));
	q.cookie = 1;
	assert(invoke(11) == -EEXIST);
	q.cookie = 65537;
	assert(invoke(11) == -E2BIG);
	puts("PASS all 16384 stamps, last stamp/index refusals preserve active content, MAX8, never-deleted full catalogue, fixed IDs over two cycles");
}
int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	const char *consent = getenv("IG_ABI3_RESOURCE_SHAPE_DISPOSABLE");
	if (argc != 2 || !consent || strcmp(consent, "1")) {
		fputs("refusing: exact disposable wrapper required\n", stderr);
		return 2;
	}
	assert(libbpf_num_possible_cpus() > 0 &&
	       libbpf_num_possible_cpus() <= 64);
	printf("possible_cpus=%d (not online)\n", libbpf_num_possible_cpus());
	char *log = calloc(1, 16 * 1024 * 1024);
	assert(log);
	LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_buf = log,
		    .kernel_log_size = 16 * 1024 * 1024, .kernel_log_level = 1);
	obj = bpf_object__open_file(argv[1], &opts);
	assert(obj && !libbpf_get_error(obj));
	if (!rs_program_type_valid(obj)) {
		fputs("refusing before load: expected one shape syscall program with explicit flags0\n",
		      stderr);
		bpf_object__close(obj);
		free(log);
		return 2;
	}
	puts("PROGRAM_TYPE_OK syscall explicit_flags0 (sleepable supplied by libbpf at load)");
	puts("LOAD_BEGIN");
	int e = bpf_object__load(obj);
	fputs(log, stderr);
	free(log);
	if (e) {
		bpf_object__close(obj);
		return 1;
	}
	struct bpf_program *p = bpf_object__find_program_by_name(obj, "shape");
	assert(p);
	prog = bpf_program__fd(p);
	struct bpf_prog_info pi = {};
	__u32 size = sizeof(pi);
	assert(!bpf_obj_get_info_by_fd(prog, &pi, &size));
	program_id = pi.id;
	printf("PROGRAM_ID %u shape\n", program_id);
	struct bpf_map *owned;
	unsigned owned_count = 0;
	bpf_object__for_each_map(owned, obj)
	{
		struct bpf_map_info mi = {};
		__u32 n = sizeof(mi);
		assert(!bpf_obj_get_info_by_fd(bpf_map__fd(owned), &mi, &n));
		printf("MAP_ID %u %s\n", mi.id, bpf_map__name(owned));
		owned_count++;
	}
	assert(owned_count == 12);
	puts("OWNERSHIP_COMPLETE 12 1");
	info(1);
	permissions();
	struct rs_config config = { .nonce = q.nonce };
	assert(!bpf_map_update_elem(fd("config"), &zero, &config, BPF_ANY));
	assert(!bpf_map_freeze(fd("zeroTask")));
	assert(!bpf_map_freeze(fd("zeroObservation")));
	storage();
	cycles();
	bpf_object__close(obj);
	return 0;
}
