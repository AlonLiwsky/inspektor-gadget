// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "nesting.h"
int nest_check_abi(const char *path);
static struct bpf_object *obj;
static struct bpf_link *outer, *inner;
static int pin = -1;
static void cleanup(void)
{
	bpf_link__destroy(outer);
	bpf_link__destroy(inner);
	bpf_object__close(obj);
	if (pin >= 0)
		close(pin);
}
static void require(int ok, const char *what)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", what);
	if (!ok)
		exit(1);
}
static int map(const char *name)
{
	int fd = bpf_object__find_map_fd_by_name(obj, name);
	require(fd >= 0, name);
	return fd;
}
static int init(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, o);
	int fd = bpf_program__fd(
		bpf_object__find_program_by_name(obj, "nest_init"));
	require(!bpf_prog_test_run_opts(fd, &o), "init invocation");
	return (int)o.retval;
}
static struct bpf_link *attach(const char *name)
{
	struct bpf_link *l = bpf_program__attach(
		bpf_object__find_program_by_name(obj, name));
	require(!libbpf_get_error(l), name);
	return l;
}
int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	/* No automatic self-test/load. Runtime requires explicit disposable-host consent. */
	require(argc == 6,
		"usage: runner OBJECT FILE EVIDENCE CAPACITY CASE(normal|audit|strict|boundary-audit|boundary-strict|exhausted)");
	require(geteuid() == 0, "root disposable runner required");
	require(!nest_check_abi("/sys/kernel/btf/vmlinux"),
		"exact live hook and kfunc prototypes before load");
	require(getenv("IG_ABI3_GATE_A_DISPOSABLE") &&
			!strcmp(getenv("IG_ABI3_GATE_A_DISPOSABLE"), "1"),
		"disposable consent");
	const char *kind = argv[5];
	int boundary = !strcmp(kind, "boundary-audit") ||
		       !strcmp(kind, "boundary-strict"),
	    exhausted = !strcmp(kind, "exhausted");
	int strict = !strcmp(kind, "strict") ||
		     !strcmp(kind, "boundary-strict");
	require(!strcmp(kind, "normal") || !strcmp(kind, "audit") || strict ||
			boundary || exhausted,
		"known case");
	unsigned capacity = (unsigned)strtoul(argv[4], NULL, 10);
	require(capacity == 1 || capacity == 2, "bounded capacity");
	require(strcmp(kind, "normal") || capacity == 2,
		"normal has inner capacity");
	pin = open(argv[2], O_RDONLY | O_CLOEXEC);
	require(pin >= 0, "pin readable ordinary file before attachment");
	atexit(cleanup);
	struct nest_config c = { .pid_tgid = ((__u64)getpid() << 32) |
					     (__u32)syscall(SYS_gettid),
				 .fd = pin,
				 .strict = strict,
				 .seed = boundary ? ~0ULL - 1 :
						    (exhausted ? ~0ULL : 0) };
	require(getrandom(&c.nonce, sizeof(c.nonce), 0) == sizeof(c.nonce) &&
			c.nonce,
		"fresh nonce");
	obj = bpf_object__open_file(argv[1], NULL);
	if (libbpf_get_error(obj)) {
		obj = NULL;
		require(0, "open object");
	}
	require(!bpf_map__set_max_entries(
			bpf_object__find_map_by_name(obj, "scratch"), capacity),
		"capacity before load");
	char *logs[3] = {};
	const char *names[3] = {};
	unsigned n = 0;
	struct bpf_program *p;
	bpf_object__for_each_program(p, obj)
	{
		require(n < 3, "bounded programs");
		logs[n] = calloc(1, 8U << 20);
		require(logs[n] != NULL, "log allocation");
		names[n] = bpf_program__name(p);
		require(!bpf_program__set_log_buf(p, logs[n], 8U << 20) &&
				!bpf_program__set_log_level(p, 1),
			"log setup");
		n++;
	}
	int loaded = bpf_object__load(obj);
	char path[4096];
	require(snprintf(path, sizeof(path), "%s/verifier.log", argv[3]) <
			(int)sizeof(path),
		"log path");
	FILE *f = fopen(path, "w");
	require(f != NULL, "verifier log");
	for (unsigned i = 0; i < n; i++) {
		fprintf(f, "=== %s ===\n%s\n", names[i], logs[i]);
		free(logs[i]);
	}
	fclose(f);
	require(!loaded, "load (not established by build)");
	bpf_object__for_each_program(p, obj)
	{
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info);
		require(!bpf_obj_get_info_by_fd(bpf_program__fd(p), &info,
						&len),
			"owned program ID");
		printf("PROGRAM_ID %u %s\n", info.id, bpf_program__name(p));
	}
	__u32 z = 0;
	int config = map("config"), command = map("command"),
	    state = map("state"), scratch = map("scratch");
	struct bpf_map_info mi = {};
	__u32 milen = sizeof(mi);
	require(!bpf_obj_get_info_by_fd(scratch, &mi, &milen) &&
			mi.type == BPF_MAP_TYPE_HASH &&
			mi.max_entries == capacity && mi.map_flags == 0 &&
			mi.key_size == sizeof(struct nest_key),
		"actual scratch HASH capacity and preallocated flags");
	printf("SCRATCH_MAP type=%u entries=%u flags=%u key_size=%u value_size=%u\n",
	       mi.type, mi.max_entries, mi.map_flags, mi.key_size,
	       mi.value_size);
	require(!bpf_map_update_elem(config, &z, &c, BPF_ANY) &&
			!bpf_map_freeze(config),
		"immutable config");
	__u64 wrong = c.nonce ^ 1;
	require(!bpf_map_update_elem(command, &z, &wrong, BPF_ANY) &&
			init() == -22,
		"reject wrong nonce");
	require(!bpf_map_update_elem(command, &z, &c.nonce, BPF_ANY) &&
			!bpf_map_freeze(command) && init() == 0,
		"authenticate and pin exact task/inode before attachment");
	require(init() == -22, "cannot reseed live identity");
	inner = attach("nest_inner");
	outer = attach("nest_outer");
	errno = 0;
	int fd = open(argv[2], O_RDONLY | O_CLOEXEC);
	int error = errno;
	if (fd >= 0)
		close(fd);
	struct nest_state s = {};
	require(!bpf_map_lookup_elem_flags(state, &z, &s, BPF_F_LOCK),
		"read evidence");
	printf("NEST cookie=%llu sequence=%llu outer=%llu inner=%llu inner_sequence=%llu acquired=%llu released=%llu failures=%llu intact=%llu clean=%llu uncertain=%llu errors=%llu helper=%lld open_errno=%d\n",
	       (unsigned long long)s.cookie, (unsigned long long)s.sequence,
	       (unsigned long long)s.outer_hits,
	       (unsigned long long)s.inner_hits,
	       (unsigned long long)s.inner_sequence,
	       (unsigned long long)s.acquired, (unsigned long long)s.released,
	       (unsigned long long)s.failures,
	       (unsigned long long)s.outer_intact,
	       (unsigned long long)s.inner_clean,
	       (unsigned long long)s.uncertain, (unsigned long long)s.errors,
	       (long long)s.helper_result, fd < 0 ? error : 0);
	require(s.cookie == 1 && s.outer_hits == 1 && !s.active && !s.errors,
		"single exact outer invocation");
	int refusal = capacity == 1 || boundary || exhausted;
	printf("INSERTION_ERROR %lld\n", (long long)s.insertion_error);
	require(s.insertion_error ==
			((capacity == 1 && !boundary && !exhausted) ? -E2BIG :
								      0),
		"capacity failure is specifically E2BIG; boundary is not insertion failure");
	require(s.uncertain == (unsigned)refusal &&
			s.failures == (unsigned)refusal,
		"affected uncertainty only");
	if (exhausted)
		require(!s.inner_hits && !s.acquired && !s.released &&
				s.sequence == ~0ULL,
			"exhausted outer cannot wrap/acquire");
	else {
		require(s.order == (refusal ? 0x124567ULL : 0x123567ULL),
			"ordered acquire/inner/release/resume/outer release");
		require(s.inner_hits == 1 && s.outer_intact == 2 &&
				s.inner_clean == 1,
			"genuine inner executes while outer row remains live and unchanged");
		require(s.acquired == (refusal ? 1U : 2U) &&
				s.released == s.acquired,
			"only successful exact acquisitions release");
		require(boundary ? (s.sequence == ~0ULL && !s.inner_sequence) :
				   (s.sequence == 2 && s.inner_sequence == 2 &&
				    s.outer_sequence == 1),
			"distinct nonwrapping invocation identities");
	}
	require(strict && refusal ? (fd < 0 && error == EACCES) : (fd >= 0),
		"audit allows; strict uncertain affected open denies");
	struct nest_key key;
	errno = 0;
	require(bpf_map_get_next_key(scratch, NULL, &key) < 0 &&
			errno == ENOENT,
		"no scratch rows remain");
	return 0;
}
