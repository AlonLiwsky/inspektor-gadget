// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
#include "vmlinux.h"
#if defined(ENFORCE_EXEC_SHARED_RECOVERY) &&        \
	(ENFORCE_EXEC_SHARED_RECOVERY != 1 ||       \
	 !defined(ENFORCE_EXEC_ABI3_DEVELOPMENT) || \
	 !defined(ENFORCE_EXEC_SHARED_NODE) ||      \
	 !defined(ENFORCE_EXEC_PERSISTENT_OWNER) || \
	 (defined(ENFORCE_EXEC_POOL_DEVELOPMENT) && \
	  !defined(ENFORCE_EXEC_POOL_REAPER_CANDIDATE)))
#error "recovery requires the explicit shared ABI3 development image; pool needs the reaper candidate gate"
#endif
#if defined(ENFORCE_EXEC_POOL_REAPER_CANDIDATE) &&              \
	(!defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||             \
	 !defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_SHARED_RECOVERY))
#error "reaper candidate needs the combined typed pool and recovery development image"
#endif
#if defined(ENFORCE_EXEC_POOL_DEVELOPMENT) &&       \
	(!defined(ENFORCE_EXEC_ABI3_DEVELOPMENT) || \
	 !defined(ENFORCE_EXEC_SHARED_NODE) ||      \
	 !defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY))
#error "pool ABI is forbidden in default or product image"
#endif
#if defined(ENFORCE_EXEC_SHARED_SCALAR_EVAL_CANDIDATE) && \
	(!defined(ENFORCE_EXEC_SHARED_NODE) ||            \
	 !defined(ENFORCE_EXEC_ABI3_DEVELOPMENT) ||       \
	 defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE))
#error "scalar shared evaluator is an exclusive shared development candidate"
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <gadget/macros.h>
#include "stdio.h"
#ifdef ENFORCE_EXEC_SHARED_NODE
static __always_inline void se_fs_mark_memfd(struct inode *);
static __always_inline int se_fs_known_memfd(struct inode *);
#define FULL_FS_SHARED_MARK(inode) se_fs_mark_memfd(inode)
#define FULL_FS_SHARED_READ(inode) se_fs_known_memfd(inode)
#endif
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
#ifdef ENFORCE_EXEC_SHARED_NODE
struct se_policy_view;
#ifdef ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE
#define SE_POLICY_VIEW(ctx) \
	se_pool_view_from_token((const struct fm_global_token *)(ctx))
#elif defined(ENFORCE_EXEC_SHARED_SCALAR_EVAL_CANDIDATE)
#define SE_POLICY_VIEW(ctx) \
	se_shared_view_from_token((const struct fm_global_token *)(ctx))
#else
static inline struct se_policy_view *full_shared_view(void);
#define SE_POLICY_VIEW(ctx) full_shared_view()
#endif
#include "shared_policy_lookup.h"
struct se_route_anchor;
static inline const __u64 *se_route_index_lookup(const __u64 *);
static inline struct se_route_anchor *se_route_anchor_lookup(const __u32 *);
#define SE_ROUTE_CAPACITY SE_PROFILE_BINDINGS
#define SE_ROUTE_INDEX_LOOKUP(key) se_route_index_lookup(key)
#define SE_ROUTE_ANCHOR_LOOKUP(key) se_route_anchor_lookup(key)
#else
#define FM_BLOB_LOOKUP(ctx, key) full_lookup(ctx, key)
#include "evaluator.h"
#endif
#ifdef ENFORCE_EXEC_SHARED_NODE
#ifndef ENFORCE_EXEC_ABI3_DEVELOPMENT
#error "shared node profile is development-only"
#endif
#ifdef ENFORCE_EXEC_SHARED_RECOVERY
#include "shared_recovery_kernel.h"
#endif
#include "shared_control.h"
#include "shared_inode_kernel.h"
#endif
#if defined(ENFORCE_EXEC_PERSISTENT_OWNER) && !defined(ENFORCE_EXEC_SHARED_NODE)
#include "owner_types.h"
#include "owner_control.h"
#include "owner_roles.h"
#endif

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
/* G020: the shared node never declares the legacy image-origin maps; its
 * from-image facts come from the generation-qualified image index
 * (shared_image_kernel.h) and stay UNKNOWN until that is wired. */
#ifndef ENFORCE_EXEC_SHARED_NODE
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
#endif
#ifndef ENFORCE_EXEC_PERSISTENT_OWNER
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
#endif
struct observation {
	struct fe_facts facts;
	struct fe_scratch evaluator;
	char argument[4097];
};
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
_Static_assert(sizeof(struct observation) == 16008,
	       "development observation ABI");
#else
_Static_assert(sizeof(struct observation) == 15936, "observation ABI");
#endif
// A sleepable invocation owns its task-keyed scratch until every exit deletes it.
#ifndef ENFORCE_EXEC_SHARED_NODE
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
#endif
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
#ifdef ENFORCE_EXEC_SHARED_NODE
	return se_policy_data(full_shared_view(), key);
#elif defined(ENFORCE_EXEC_ABI3_DEVELOPMENT)
	return eo_current_blob(key);
#elif defined(ENFORCE_EXEC_PERSISTENT_OWNER)
	return eo_blob(0, key);
#else
	return bpf_map_lookup_elem(&full_program, &key);
#endif
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
#ifndef ENFORCE_EXEC_SHARED_NODE
		o->facts.target_image = full_file_image(target);
#endif
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
#ifndef ENFORCE_EXEC_SHARED_NODE
		o->facts.actor_image = full_file_image(actor);
#endif
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
#ifdef ENFORCE_EXEC_SHARED_NODE
#define SE_CATALOGUE_FROM_BANK 1
static __always_inline __u64 se_catalogue_epoch(__u64 scope, __u64 uid);
#include "shared_kernel.h"
#ifdef ENFORCE_EXEC_POOL_DEVELOPMENT
#include "shared_pool_work_core.h"
#ifdef ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE
#include "shared_pool_work_semantic_candidate.h"
#include "shared_pool_eval_candidate.h"
static inline const struct fm_blob *
se_pool_blob_from_token(unsigned int slot, unsigned long long cookie,
			unsigned int key)
{
	if (key >= FM_MAX_ENTRIES)
		return 0;
	struct fm_global_token token = { .slot = slot, .cookie = cookie };
	return se_policy_data(se_pool_view_from_token(&token), key);
}
#define SE_POOL_CATALOGUE_EPOCH(scope, uid) se_catalogue_epoch(scope, uid)
#include "shared_pool_catalogue_candidate.h"
#include "shared_pool_inherit_candidate.h"
#endif
#include "shared_pool_task_reap_candidate.h"
#ifdef ENFORCE_EXEC_POOL_REAPER_CANDIDATE
#include "shared_pool_reaper_control_candidate.h"
#include "shared_pool_reaper_visit_candidate.h"
#include "shared_pool_reaper_chunk_candidate.h"
#include "shared_pool_reaper_transport_candidate.h"
#endif
#endif
#include "shared_publication_arm.h"
#endif
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
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
long
#else
int
#endif
BPF_PROG(enforce_exec_full, struct linux_binprm *bprm, int ret)
{
#ifdef ENFORCE_EXEC_SHARED_NODE
	return se_shared_check(bprm, ret);
#else
	if (ret) {
#ifdef ENFORCE_EXEC_PERSISTENT_OWNER
		eo_exec_suppress();
#endif
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
		return fe_lsm_result(ret);
#else
		return ret;
#endif
	}
	__u64 cgroup = bpf_get_current_cgroup_id(),
	      id = bpf_get_current_pid_tgid();
#ifdef ENFORCE_EXEC_PERSISTENT_OWNER
	__u64 generation = 0;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	__u32 execution_class = 2;
	int admitted =
		eo_exec_begin_development(bprm, &generation, &execution_class);
#else
	int admitted = eo_exec_begin(bprm, &generation);
	/* Admission failures happen before the generation is known: unclassified,
	 * so they stay fail-closed for every binding (as ABI3 and the shared node). */
	__u32 execution_class = 2;
#endif
	if (admitted <= 0)
		return admitted < 0 && execution_class == 2 ? -1 : 0;
	struct eo_config *configuration = eo_config();
	if (!configuration) {
		eo_exec_suppress();
		return execution_class == 2 ? -1 : 0;
	}
	cgroup =
		configuration
			->cgroup; // Original binding, including a migrated in-flight exec.
	__u32 zero = 0;
#ifndef ENFORCE_EXEC_ABI3_DEVELOPMENT
	/* Once the generation is known, its policies classify the exec: Audit
	 * (1) never blocks on a later fault; invalid or mixed classes are Strict. */
	__u32 legacy_policies = 0, legacy_writers = 0;
	if (fe_execution_class(0, generation, &legacy_policies,
			       &legacy_writers) == 1)
		execution_class = 1;
#endif
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
#define FULL_OBSERVATION_FAULT(bit) eo_exec_observation_fault(generation, bit)
#else
#define FULL_OBSERVATION_FAULT(bit)             \
	do {                                    \
		eo_data_fault(generation, bit); \
		eo_exec_suppress();             \
	} while (0)
#endif
#else
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
#endif
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
#ifdef ENFORCE_EXEC_PERSISTENT_OWNER
	int error = eo_fill_roles(&o->facts);
	if (!error)
		error = fe_evaluate(0, &o->facts, &o->evaluator);
#ifdef ENFORCE_EXEC_TEST_INJECT_ERROR
	if (enforce_exec_test_inject_error & 1)
		error = 1;
#endif
#else
	int error = fe_evaluate(&full_program, &o->facts, &o->evaluator);
#endif
	struct fe_decision *d = &o->evaluator.decision;
	if (error) {
		FULL_OBSERVATION_FAULT(4);
		if (!d->error)
			d->error = FE_INVALID;
		count(2);
	}
#ifdef ENFORCE_EXEC_PERSISTENT_OWNER
	if (eo_exec_propose(bprm, d)
#ifdef ENFORCE_EXEC_TEST_INJECT_ERROR
	    || (enforce_exec_test_inject_error & 2)
#endif
	) {
		error = 1;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
		eo_exec_observation_fault(generation, 4);
#endif
		if (!d->error)
			d->error = FE_INVALID;
		count(2);
	}
#endif
	/* A fault never trusts the partially merged d->mode: the invocation class
	 * decides (Audit allows, Strict denies), as on the ABI3 and shared paths. */
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	long result = fe_lsm_verdict(execution_class, ret, error, d);
#else
	int result = (int)fe_lsm_verdict(execution_class, ret, error, d);
#endif
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->generation = generation;
		event->cgroup = cgroup;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
		event->deny = d->deny;
		event->mode = d->mode;
#else
		/* An error is a would-deny operational error in the binding's class. */
		event->deny = error ? 1 : d->deny;
		event->mode = error ? execution_class : d->mode;
#endif
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
#endif
}
char LICENSE[] SEC("license") = "GPL";
