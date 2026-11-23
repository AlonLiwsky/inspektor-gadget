// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <gadget/macros.h>
#include "stdio.h"
#include "filesystem.h"
struct fm_blob;
static inline const struct fm_blob *full_lookup(void *, unsigned int);
#ifdef ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE
struct fm_global_token;
struct se_policy_view;
static inline struct se_policy_view *
se_pool_view_from_token(const struct fm_global_token *);
static inline const struct fm_blob *
se_pool_blob_from_token(unsigned int, unsigned long long, unsigned int);
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	se_pool_blob_from_token((slot), (cookie), (key))
#elif defined(ENFORCE_EXEC_SHARED_SCALAR_EVAL_CANDIDATE)
struct fm_global_token;
struct se_policy_view;
static inline struct se_policy_view *
se_shared_view_from_token(const struct fm_global_token *);
static inline const struct fm_blob *
se_shared_blob_from_token(unsigned int, unsigned long long, unsigned int);
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	se_shared_blob_from_token((slot), (cookie), (key))
#else
static inline const struct fm_blob *full_lookup_global(unsigned int);
#define FM_GLOBAL_BLOB_LOOKUP(key) full_lookup_global(key)
#endif
#define FM_BLOB_LOOKUP(ctx, key) full_lookup(ctx, key)
#include "evaluator.h"

extern int bpf_copy_from_user_mm_str(void *, __u32, const void *,
				     struct mm_struct *, __u64)
__weak __ksym;
/* The flag is a kfunc argument, not a feature of the build host's BTF.
 * Older stock vmlinux.h files omit its UAPI enum; keep the same value used by
 * modern kernels. A missing kfunc is still an admission failure at load.
 */
#define FE_COPY_PAD_ZEROS (1ULL << 0)
extern int bpf_path_d_path(const struct path *, char *, size_t) __ksym;
extern struct file *bpf_get_task_exe_file(struct task_struct *) __ksym;
extern void bpf_put_file(struct file *) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern struct task_struct *bpf_task_acquire(struct task_struct *) __ksym;
extern void bpf_task_release(struct task_struct *) __ksym;
static __always_inline int origin_ready(void);
static __always_inline int origin_lookup(const void *);
#define ORIGIN_READY() origin_ready()
#define ORIGIN_LOOKUP(key) origin_lookup(key)
#include "image_origin.h"
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
	__type(key, struct full_origin_key);
	__type(value, __u8);
} image_origins SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} image_ready SEC(".maps");
static __always_inline int origin_ready(void)
{
	__u32 zero = 0;
	__u32 *ready = bpf_map_lookup_elem(&image_ready, &zero);
	return ready && *ready == 1;
}
static __always_inline int origin_lookup(const void *key)
{
	return bpf_map_lookup_elem(&image_origins, key) != 0;
}
struct legacy_entry {
	__u64 generation;
	__u32 mode, default_deny, count, deny, prefix, length;
	char path[256];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 129);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct legacy_entry);
} policy SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct fm_blob);
} full_program SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u64);
} bindings SEC(".maps");
// Sticky fault bits are kernel-written and userspace read-only.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} full_faults SEC(".maps");
static __always_inline void fault(__u64 bit)
{
	__u32 zero = 0;
	__u64 *v = bpf_map_lookup_elem(&full_faults, &zero);
	if (v)
		__sync_fetch_and_or(v, bit);
}
struct observation {
	struct fe_facts facts;
	struct fe_scratch evaluator;
	char argument[4097];
};
_Static_assert(sizeof(struct observation) == 15936, "observation ABI");
// A sleepable invocation owns its task-keyed scratch until every exit deletes it.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, struct observation);
} observations SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct observation);
} zero_observation SEC(".maps");
#ifdef ENFORCE_EXEC_TEST_INJECT_ERROR
/* Kernel test harness only, never in an archive: 1 forces an evaluator error,
 * 2 a propose error, after the real evaluation/proposal ran. */
const volatile __u32 enforce_exec_test_inject_error = 0;
#endif
struct event {
	__u64 generation, cgroup;
	__u32 deny, mode;
	__s32 path_result;
	__u32 host_pid;
	char path[256];
	__u64 matched_rules[4];
	__u32 error;
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 262144);
} events SEC(".maps");
GADGET_TRACER(verdict, events, event);
// successful reports, dropped reports, observation failures
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");
static __always_inline void count(__u32 key)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &key);
	if (v)
		(*v)++;
}
static inline const struct fm_blob *full_lookup(void *ctx, unsigned int key)
{
	return bpf_map_lookup_elem(ctx, &key);
}
/* EO_GLOBAL_BLOB_BEGIN */
#if !defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) && \
	!defined(ENFORCE_EXEC_SHARED_SCALAR_EVAL_CANDIDATE)
static inline const struct fm_blob *full_lookup_global(unsigned int key)
{
	return bpf_map_lookup_elem(&full_program, &key);
}
#endif
/* EO_GLOBAL_BLOB_END */
static __always_inline int file_path(struct file *file, struct fe_path *out)
{
	int n = bpf_path_d_path(&file->f_path, (char *)out->bytes,
				sizeof(out->bytes));
	if (n <= 1 || n > 256 || out->bytes[0] != '/')
		return -1;
	out->length = n - 1;
	return n;
}
struct argv_context {
	struct observation *o;
	struct mm_struct *mm;
	__u64 pointer;
	int error;
};
struct copy_context {
	struct observation *o;
	__u32 offset, length;
	int error;
};
static long copy_argument(__u32 i, void *opaque)
{
	struct copy_context *c = opaque;
	if (i >= 4096 || i >= c->length)
		return 1;
	__u64 at = (__u64)c->offset + i;
	asm volatile("" : "+r"(at));
	if (at >= 4096) {
		c->error = 1;
		return 1;
	}
	c->o->facts.argv[at] = c->o->argument[i];
	return 0;
}
static long read_argument(__u32 i, void *opaque)
{
	struct argv_context *c = opaque;
	if (i >= 64 || i >= c->o->facts.argc)
		return 1;
	struct mm_struct *mm = c->mm;
	if (!mm) {
		c->error = 1;
		return 1;
	}
	long n = bpf_copy_from_user_mm_str(c->o->argument, 4097,
					   (void *)c->pointer, mm,
					   FE_COPY_PAD_ZEROS);
	// A full destination may be truncated. Reject rather than match a prefix.
	if (n <= 0 || n >= 4097) {
		c->error = 1;
		return 1;
	}
	__u32 offset = c->o->facts.argv_bytes;
	if (offset > 4096 || n > 4096 - offset) {
		c->error = 1;
		return 1;
	}
	c->o->facts.argv_offsets[i] = offset;
	struct copy_context copy = { c->o, offset, n, 0 };
	if (bpf_loop(4096, copy_argument, &copy, 0) < 0 || copy.error) {
		c->error = 1;
		return 1;
	}
	c->o->facts.argv_bytes = offset + n;
	if (c->pointer + n < c->pointer) {
		c->error = 1;
		return 1;
	}
	c->pointer += n;
	return 0;
}
/* Same observation implementation for legacy and shared callers. Shared image
 * evidence remains UNKNOWN until its generation-qualified image index is wired. */
/* Keep the observation frame separate from the shared ingress/evaluator
 * frame; inlining their combined scratch exceeds the BPF stack limit. */
static __attribute__((noinline)) int full_observe(struct linux_binprm *bprm,
						  struct observation *o)
{
	o->facts.actor_image = -1;
	o->facts.target_image = -1;
	o->facts.stdin_pipe = -1;
	int path_result = -1;
	struct file *target = bprm->file;
	if (target) {
		path_result = file_path(target, &o->facts.target_path);
		o->facts.target_image = full_file_image(target);
	}
	struct task_struct *task = bpf_get_current_task_btf();
	struct full_fs_facts fs = full_file_filesystem(bprm->file);
	o->facts.fs_mask = fs.mask;
	o->facts.fs_known = fs.known;
	o->facts.stdin_pipe = full_stdin_pipe(task);
	bpf_rcu_read_lock();
	const struct cred *cred = task->cred;
	if (cred) {
		o->facts.effective_uid = cred->euid.val;
		o->facts.uid_known = 1;
	}
	bpf_rcu_read_unlock();
	struct file *actor = bpf_get_task_exe_file(task);
	if (actor) {
		file_path(actor, &o->facts.actor_path);
		o->facts.actor_image = full_file_image(actor);
		bpf_put_file(actor);
	}
	// Acquire each parent under RCU before any potentially sleepable operation.
	bpf_rcu_read_lock();
	struct task_struct *parent = bpf_task_acquire(task->real_parent);
	bpf_rcu_read_unlock();
	for (__u32 i = 0; i < 16; i++) {
		if (!parent) {
			o->facts.ancestors_complete = 1;
			break;
		}
		if (BPF_CORE_READ(parent, pid) == 0) {
			o->facts.ancestors_complete = 1;
			bpf_task_release(parent);
			parent = 0;
			break;
		}
		struct file *exe = bpf_get_task_exe_file(parent);
		int valid = -1;
		if (exe) {
			valid = file_path(exe, &o->facts.ancestors[i]);
			bpf_put_file(exe);
		}
		if (valid < 0) {
			bpf_task_release(parent);
			parent = 0;
			break;
		}
		o->facts.ancestor_count = i + 1;
		bpf_rcu_read_lock();
		struct task_struct *next =
			bpf_task_acquire(parent->real_parent);
		bpf_rcu_read_unlock();
		bpf_task_release(parent);
		parent = next;
	}
	if (parent)
		bpf_task_release(parent);
	int argc = bprm->argc;
	if (argc >= 0 && argc <= 64 && bprm->mm) {
		o->facts.argc = argc;
		struct argv_context args = { o, bprm->mm, bprm->p, 0 };
		if (bpf_loop(64, read_argument, &args, 0) >= 0 && !args.error)
			o->facts.argv_complete = 1;
	}
	return path_result;
}
/* Kernel class hook: tracking failures remain diagnostic/unknown and must
 * never deny unrelated memfd creation. Attach before advertising fs capability. */
SEC("lsm/inode_init_security_anon")
int BPF_PROG(enforce_exec_track_memfd, struct inode *inode,
	     const struct qstr *name, const struct inode *context, int ret)
{
	if (!ret)
		full_fs_mark_memfd(inode, name);
	return ret;
}
SEC("lsm.s/bprm_check_security")
int
BPF_PROG(enforce_exec_full, struct linux_binprm *bprm, int ret)
{
	if (ret) {
		return ret;
	}
	__u64 cgroup = bpf_get_current_cgroup_id(),
	      id = bpf_get_current_pid_tgid();
	const __u32 execution_class = 2;
	__u64 *binding = bpf_map_lookup_elem(&bindings, &cgroup);
	if (!binding)
		return 0;
	if (*binding) {
		fault(1);
		return -1;
	} // strict bindings only; never interpret exemptions
	__u32 zero = 0;
	const struct legacy_entry *header = bpf_map_lookup_elem(&policy, &zero);
	if (!header || header->mode != 2 || header->count ||
	    header->default_deny) {
		fault(1);
		return -1;
	}
	__u64 generation = header->generation;
#define FULL_OBSERVATION_FAULT(bit) fault(bit)
	const struct observation *empty =
		bpf_map_lookup_elem(&zero_observation, &zero);
	if (!empty ||
	    bpf_map_update_elem(&observations, &id, empty, BPF_NOEXIST)) {
		FULL_OBSERVATION_FAULT(2);
		count(2);
		return execution_class == 2 ? -1 : 0;
	}
	struct observation *o = bpf_map_lookup_elem(&observations, &id);
	if (!o) {
		bpf_map_delete_elem(&observations, &id);
		FULL_OBSERVATION_FAULT(2);
		count(2);
		return execution_class == 2 ? -1 : 0;
	}
	int path_result = full_observe(bprm, o);
	int error = fe_evaluate(&full_program, &o->facts, &o->evaluator);
	struct fe_decision *d = &o->evaluator.decision;
	if (error) {
		FULL_OBSERVATION_FAULT(4);
		if (!d->error)
			d->error = FE_INVALID;
		count(2);
	}
	/* A fault never trusts the partially merged d->mode: the invocation class
	 * decides (Audit allows, Strict denies), as on the ABI3 and shared paths. */
	int result = (int)fe_lsm_verdict(execution_class, ret, error, d);
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->generation = generation;
		event->cgroup = cgroup;
		/* An error is a would-deny operational error in the binding's class. */
		event->deny = error ? 1 : d->deny;
		event->mode = error ? execution_class : d->mode;
		event->path_result = path_result;
		event->host_pid = id >> 32;
		event->error = d->error;
		__builtin_memcpy(event->path, o->facts.target_path.bytes, 256);
		__builtin_memcpy(event->matched_rules, d->matched_rules, 32);
		bpf_ringbuf_submit(event, 0);
		count(0);
	} else
		count(1);
	bpf_map_delete_elem(&observations, &id);
	return result;
}
char LICENSE[] SEC("license") = "GPL";
