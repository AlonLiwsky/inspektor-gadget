/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Host contract of full/shared_pass_facts.h (G020 per-pass exec facts): the
 * actual collector body over stub kfuncs that count every reference, so each
 * acquire/get is released exactly once on every path. Not a verifier or
 * live-kernel proof (the attached facts test is). */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef uint64_t __u64;
/* Only struct fe_facts is used; no blob is ever looked up. */
#define FM_BLOB_LOOKUP(context, key) \
	((void)(context), (void)(key), (const struct fm_blob *)0)
#include "evaluator.h"

#define FULL_FS_TMPFS 1U
#define FULL_FS_MEMFD 2U
#define FULL_FS_DELETED 4U
#define FULL_FS_OVERLAY 8U
struct full_fs_facts {
	__u32 mask, known;
};
struct path {
	int unused;
};
struct file {
	struct path f_path;
	const char *name; /* 0: d_path fails (-EFAULT) */
	int too_long, reachable, refs;
	struct full_fs_facts fs;
	int unlinked;
};
struct task_struct {
	struct task_struct *real_parent;
	int pid, refs, dying;
	struct file *exe;
};
struct linux_binprm {
	struct file *file;
};

static struct task_struct *current;
static int rcu_depth, stdin_value;
/* The task outside the workload (no TASK) and the binding's init. */
static struct task_struct *edge_task, *binding_init;
static __u64 stats[32];
static int file_gets, file_puts, task_acquires, task_releases;
/* Called after every bpf_put_file: the ancestor walk's iteration boundary. */
static void (*on_put)(void);

/* A sibling sharing the fs_struct chroots during the Nth d_path (0: never):
 * the sequence moves by a whole write; chroot_back restores the root (the
 * sequence still moved). */
static int chroot_at_dpath, chroot_back, dpaths;
static __u32 fs_seq;
static int root_state;
static int bpf_path_d_path(struct path *path, char *buf, size_t size)
{
	if (++dpaths == chroot_at_dpath) {
		fs_seq += 2;
		root_state = chroot_back ? 1 : 0;
	}
	struct file *file =
		(struct file *)((char *)path - offsetof(struct file, f_path));
	if (file->too_long)
		return -36;
	if (!file->name)
		return -14;
	size_t n = strlen(file->name) + 1;
	if (n > size)
		return -36;
	memcpy(buf, file->name, n);
	return (int)n;
}
static struct file *bpf_get_task_exe_file(struct task_struct *task)
{
	assert(task == current || task->refs > 0);
	if (!task->exe)
		return 0;
	task->exe->refs++;
	file_gets++;
	return task->exe;
}
static void bpf_put_file(struct file *file)
{
	assert(file->refs > 0);
	file->refs--;
	file_puts++;
	if (on_put)
		on_put();
}
static struct task_struct *bpf_task_acquire(struct task_struct *task)
{
	assert(rcu_depth == 1);
	if (task->dying)
		return 0;
	task->refs++;
	task_acquires++;
	return task;
}
static void bpf_task_release(struct task_struct *task)
{
	assert(task->refs > 0);
	task->refs--;
	task_releases++;
}
static void bpf_rcu_read_lock(void)
{
	assert(rcu_depth == 0);
	rcu_depth++;
}
static void bpf_rcu_read_unlock(void)
{
	assert(rcu_depth == 1);
	rcu_depth--;
}
static struct task_struct *bpf_get_current_task_btf(void)
{
	return current;
}
#define SE_PF_STAT(cell) (stats[(cell)]++)
#define SE_PF_FS(file) ((file)->fs)
#define SE_PF_STDIN(task) ((void)(task), stdin_value)
#define SE_PF_REACHABLE(file) ((file)->reachable)
#define SE_PF_ROOTED(anchor) ((void)(anchor), root_state)
#define SE_PF_UNLINKED(file) ((file)->unlinked)
#define SE_PF_MEMBER(task) ((task) != edge_task)
#define SE_PF_INIT(task, anchor) ((void)(anchor), (task) == binding_init)
/* The fs_struct sequence (odd: a write in flight). */
static __u32 host_fs_seq(void)
{
	return fs_seq;
}
#define SE_PF_FS_SEQ() host_fs_seq()
#define SE_PF_TYPES_ONLY 1
#include "shared_pass_facts.h"
#undef SE_PF_TYPES_ONLY
static __attribute__((unused)) int host_utf8(const __u8 *bytes, __u32 n)
{
	__u32 state = 0;
	for (__u32 i = 0; i < n; i++)
		if (se_pf_utf8_step(&state, bytes[i]))
			return 0;
	return state == 0;
}
#define SE_PF_UTF8(bytes, n) host_utf8(bytes, n)
#include "shared_pass_facts.h"
static const struct se_pf_anchor anchor = { .known = 1 };

static struct fe_facts facts;
static struct linux_binprm bprm;
static struct task_struct idle, init_task, a, b, c, d, self;
static struct file f_target, f_init, f_a, f_b, f_c, f_d, f_self;

static void file_init(struct file *f, const char *name)
{
	memset(f, 0, sizeof(*f));
	f->name = name;
	f->reachable = 1;
}
/* self -> a -> b -> init -> idle (pid 0); c -> d -> init (a subreaper). */
static void world(void)
{
	memset(&idle, 0, sizeof(idle));
	memset(&stats, 0, sizeof(stats));
	file_gets = file_puts = task_acquires = task_releases = 0;
	on_put = 0;
	stdin_value = 1;
	root_state = 1;
	fs_seq = 4;
	chroot_at_dpath = chroot_back = dpaths = 0;
	edge_task = binding_init = 0;
	file_init(&f_target, "/usr/bin/true");
	f_target.fs = (struct full_fs_facts){ 0, 0xd };
	file_init(&f_init, "/usr/lib/systemd/systemd");
	file_init(&f_a, "/usr/bin/a");
	file_init(&f_b, "/usr/bin/b");
	file_init(&f_c, "/usr/bin/c");
	file_init(&f_d, "/usr/bin/d");
	file_init(&f_self, "/usr/bin/self");
	init_task = (struct task_struct){ &idle, 1, 0, 0, &f_init };
	b = (struct task_struct){ &init_task, 20, 0, 0, &f_b };
	a = (struct task_struct){ &b, 30, 0, 0, &f_a };
	d = (struct task_struct){ &init_task, 40, 0, 0, &f_d };
	c = (struct task_struct){ &d, 50, 0, 0, &f_c };
	self = (struct task_struct){ &a, 60, 0, 0, &f_self };
	current = &self;
	bprm.file = &f_target;
}
static void balanced(const char *label)
{
	if (task_acquires != task_releases || file_gets != file_puts ||
	    rcu_depth || a.refs || b.refs || c.refs || d.refs ||
	    init_task.refs || f_a.refs || f_b.refs || f_self.refs) {
		fprintf(stderr,
			"%s: unbalanced acquires %d releases %d gets %d puts %d rcu %d\n",
			label, task_acquires, task_releases, file_gets,
			file_puts, rcu_depth);
		assert(0);
	}
}
static int path_is(const struct fe_path *p, const char *s)
{
	return p->length == strlen(s) && !memcmp(p->bytes, s, p->length);
}
static void collect(const char *label)
{
	assert(se_pass_facts_collect(&bprm, &facts, &anchor) == 0);
	balanced(label);
}
/* Stale state of a previous pass: every owned fact set to a known value. */
static void stale(void)
{
	memset(&facts, 0, sizeof(facts));
	facts.target_path.length = 5;
	memcpy(facts.target_path.bytes, "/old!", 5);
	facts.actor_path.length = 5;
	facts.fs_mask = 1;
	facts.fs_known = 0xf;
	facts.stdin_pipe = 1;
	facts.ancestor_count = 3;
	facts.ancestors_complete = 1;
	facts.actor_image = 1;
	facts.target_image = 0;
}

static void reparent_self_to_c(void)
{
	/* self's parent a dies between iterations: self is reparented to the
	 * subreaper c. The walk holds a, so link 1 is a's parent b. */
	if (file_puts == 2)
		self.real_parent = &c;
}

int main(void)
{
	world();
	collect("normal");
	assert(path_is(&facts.target_path, "/usr/bin/true"));
	assert(path_is(&facts.actor_path, "/usr/bin/self"));
	assert(facts.fs_known == 0xd && facts.fs_mask == 0 &&
	       facts.stdin_pipe == 1);
	assert(facts.ancestor_count == 3 && facts.ancestors_complete == 1);
	assert(path_is(&facts.ancestors[0], "/usr/bin/a"));
	assert(path_is(&facts.ancestors[1], "/usr/bin/b"));
	assert(path_is(&facts.ancestors[2], "/usr/lib/systemd/systemd"));
	assert(stats[SE_PF_PASSES] == 1 && stats[SE_PF_FS_UNKNOWN] == 1);
	for (int i = SE_PF_TARGET_MISSING; i < SE_PF_STATS; i++)
		assert(i == SE_PF_FS_UNKNOWN || !stats[i]);

	/* Per-pass reset: a pass that collects nothing leaves nothing stale
	 * (the interpreter continuation reuses the WORK's facts), image facts
	 * included. */
	world();
	stale();
	bprm.file = 0;
	self.exe = 0;
	stdin_value = -1;
	self.real_parent = &a;
	a.dying = 1;
	collect("stale");
	if (facts.target_path.length || facts.actor_path.length ||
	    facts.fs_known || facts.fs_mask || facts.stdin_pipe != -1 ||
	    facts.ancestor_count || facts.ancestors_complete ||
	    facts.target_image != -1 || facts.actor_image != -1) {
		fprintf(stderr,
			"stale previous-pass fact survived: target %u actor %u fs %#x/%#x stdin %d ancestors %u/%u\n",
			facts.target_path.length, facts.actor_path.length,
			facts.fs_mask, facts.fs_known, facts.stdin_pipe,
			facts.ancestor_count, facts.ancestors_complete);
		return 1;
	}
	assert(stats[SE_PF_TARGET_MISSING] == 1 &&
	       stats[SE_PF_ACTOR_MISSING] == 1 &&
	       stats[SE_PF_STDIN_UNKNOWN] == 1 &&
	       stats[SE_PF_ANCESTOR_UNKNOWN] == 1 &&
	       stats[SE_PF_FS_UNKNOWN] == 1);

	/* Target faults: each UNKNOWN (length 0) with its own reason. */
	struct {
		const char *name;
		int too_long, reachable;
		__u32 cell;
	} target[] = {
		{ "/x", 1, 1, SE_PF_TARGET_TOO_LONG },
		{ 0, 0, 1, SE_PF_TARGET_PATH },
		{ "pipe:[7]", 0, 1, SE_PF_TARGET_PATH },
		{ "/usr/bin/qemu", 0, 0, SE_PF_TARGET_OUTSIDE_ROOT },
		{ "/usr/bin/qemu", 0, -1, SE_PF_TARGET_PATH },
	};
	for (unsigned i = 0; i < sizeof(target) / sizeof(target[0]); i++) {
		world();
		stale();
		f_target.name = target[i].name;
		f_target.too_long = target[i].too_long;
		f_target.reachable = target[i].reachable;
		collect("target fault");
		assert(facts.target_path.length == 0);
		assert(stats[target[i].cell] == 1);
		assert(path_is(&facts.actor_path, "/usr/bin/self"));
	}
	/* A 255-byte path is the longest known one; 256 is too long. */
	static char longest[257];
	world();
	longest[0] = '/';
	memset(longest + 1, 'p', 254);
	f_target.name = longest;
	collect("255 bytes");
	assert(facts.target_path.length == 255);
	world();
	longest[255] = 'p';
	f_target.name = longest;
	collect("256 bytes");
	assert(facts.target_path.length == 0 &&
	       stats[SE_PF_TARGET_TOO_LONG] == 1);

	/* Actor faults. */
	world();
	f_self.reachable = 0;
	collect("actor outside root");
	assert(facts.actor_path.length == 0 &&
	       stats[SE_PF_ACTOR_OUTSIDE_ROOT] == 1);
	world();
	f_self.too_long = 1;
	collect("actor too long");
	assert(facts.actor_path.length == 0 && stats[SE_PF_ACTOR_PATH] == 1);

	/* stdin: only 0 and 1 are known. */
	world();
	stdin_value = 2;
	collect("stdin out of range");
	assert(facts.stdin_pipe == -1 && stats[SE_PF_STDIN_UNKNOWN] == 1);
	world();
	stdin_value = 0;
	collect("stdin not a pipe");
	assert(facts.stdin_pipe == 0 && !stats[SE_PF_STDIN_UNKNOWN]);

	/* Ancestor failures: the whole fact UNKNOWN (count 0, incomplete). */
	for (int mode = 0; mode < 4; mode++) {
		world();
		stale();
		if (mode == 0)
			b.dying = 1; /* acquire of link 1 fails */
		if (mode == 1)
			b.exe = 0; /* link 1 has no exe (kernel thread) */
		if (mode == 2)
			f_b.too_long = 1;
		if (mode == 3)
			f_b.reachable = -1;
		collect("ancestor failure");
		assert(facts.ancestor_count == 0 &&
		       facts.ancestors_complete == 0);
		assert(stats[SE_PF_ANCESTOR_UNKNOWN] == 1);
	}
	/* H1: an ancestor of the workload whose executable is unreachable from
	 * the binding root (or deleted, or not UTF-8) cannot hide the rest of
	 * the chain: the whole fact UNKNOWN. */
	for (int mode = 0; mode < 3; mode++) {
		world();
		if (mode == 0)
			f_b.reachable = 0;
		if (mode == 1)
			f_b.unlinked = 1;
		if (mode == 2)
			f_b.name = "/usr/bin/\xff";
		collect("ancestor hidden");
		assert(facts.ancestor_count == 0 &&
		       facts.ancestors_complete == 0 &&
		       stats[SE_PF_ANCESTOR_UNKNOWN] == 1 &&
		       !stats[SE_PF_ANCESTOR_BOUNDARY]);
	}
	/* The chain ends complete at the edge of the workload (a parent with
	 * no TASK, e.g. the runtime's shim): b is not recorded. */
	world();
	edge_task = &b;
	collect("workload edge");
	assert(facts.ancestor_count == 1 && facts.ancestors_complete == 1 &&
	       stats[SE_PF_ANCESTOR_BOUNDARY] == 1 &&
	       !stats[SE_PF_ANCESTOR_UNKNOWN]);
	/* ... and at the binding's init (the container root process), which is
	 * the last link; its unreachable parent is never looked at. */
	world();
	binding_init = &b;
	f_init.reachable = 0;
	collect("binding init");
	assert(facts.ancestor_count == 2 && facts.ancestors_complete == 1 &&
	       path_is(&facts.ancestors[1], "/usr/bin/b") &&
	       stats[SE_PF_ANCESTOR_BOUNDARY] == 1 &&
	       !stats[SE_PF_ANCESTOR_UNKNOWN]);

	/* H1: a task root other than the binding's anchor (a chroot): every
	 * path fact UNKNOWN, the ancestors too; fs and stdin still known. */
	world();
	stale();
	root_state = 0;
	collect("root mismatch");
	assert(dpaths == 0); /* no path is ever read from a foreign root */
	assert(!facts.target_path.length && !facts.actor_path.length &&
	       !facts.ancestor_count && !facts.ancestors_complete &&
	       facts.fs_known == 0xd && facts.stdin_pipe == 1 &&
	       stats[SE_PF_ROOT_MISMATCH] == 1);
	world();
	root_state = -1;
	collect("no anchor");
	assert(!facts.target_path.length && !facts.actor_path.length &&
	       !facts.ancestors_complete && stats[SE_PF_ROOT_MISMATCH] == 1);

	/* H1 race: a sibling chroots after the root check, during the target's,
	 * the actor's or an ancestor's d_path (dpath 1, 2, 3): every path fact
	 * UNKNOWN, never a spoofed definite path; the same when it chroots back
	 * before the last read (the sequence moved); and a write in flight at
	 * the check (odd sequence). */
	for (int at = 1; at <= 3; at++) {
		for (int back = 0; back < 2; back++) {
			world();
			stale();
			chroot_at_dpath = at;
			chroot_back = back;
			collect("chroot race");
			if (facts.target_path.length ||
			    facts.actor_path.length || facts.ancestor_count ||
			    facts.ancestors_complete ||
			    stats[SE_PF_ROOT_MISMATCH] != 1) {
				fprintf(stderr,
					"chroot race at d_path %d (back %d): target %u actor %u ancestors %u/%u mismatch %llu\n",
					at, back, facts.target_path.length,
					facts.actor_path.length,
					facts.ancestor_count,
					facts.ancestors_complete,
					(unsigned long long)
						stats[SE_PF_ROOT_MISMATCH]);
				return 1;
			}
			assert(facts.fs_known == 0xd && facts.stdin_pipe == 1);
		}
	}
	world();
	fs_seq = 5;
	collect("fs write in flight");
	assert(!facts.target_path.length && !facts.actor_path.length &&
	       !facts.ancestors_complete && stats[SE_PF_ROOT_MISMATCH] == 1);

	/* M1: only valid UTF-8 is a known path. */
	const char *utf8_bad[] = { "/usr/bin/\xff", "/x\xc0\xaf",
				   "/x\xed\xa0\x80", "/x\xf4\x90\x80\x80",
				   "/x\xe2\x82" };
	for (unsigned i = 0; i < sizeof(utf8_bad) / sizeof(utf8_bad[0]); i++) {
		world();
		f_target.name = utf8_bad[i];
		collect("invalid utf-8");
		assert(!facts.target_path.length &&
		       stats[SE_PF_PATH_UTF8] == 1);
	}
	world();
	f_target.name = "/usr/bin/caf\xc3\xa9-\xf0\x9f\x98\x80";
	collect("valid utf-8");
	assert(path_is(&facts.target_path,
		       "/usr/bin/caf\xc3\xa9-\xf0\x9f\x98\x80"));
	world();
	f_self.name = "/usr/bin/\xfe";
	collect("actor invalid utf-8");
	assert(!facts.actor_path.length && stats[SE_PF_PATH_UTF8] == 1);

	/* M2: a deleted actor or target is UNKNOWN. memfd: its own reason. */
	world();
	f_self.unlinked = 1;
	collect("actor deleted");
	assert(!facts.actor_path.length && stats[SE_PF_ACTOR_DELETED] == 1);
	world();
	f_target.unlinked = 1;
	collect("target deleted");
	assert(!facts.target_path.length && stats[SE_PF_TARGET_PATH] == 1 &&
	       path_is(&facts.actor_path, "/usr/bin/self"));
	world();
	f_target.name = "/memfd:x (deleted)";
	f_target.reachable = 2;
	f_target.unlinked = 1; /* a memfd's dentry is never hashed */
	collect("memfd target");
	assert(!facts.target_path.length && stats[SE_PF_TARGET_MEMFD] == 1 &&
	       !stats[SE_PF_TARGET_OUTSIDE_ROOT]);

	/* More than 16 ancestors: the known 16-prefix, incomplete. */
	static struct task_struct deep[20];
	static struct file deep_file[20];
	world();
	for (int i = 0; i < 20; i++) {
		file_init(&deep_file[i], "/usr/bin/deep");
		deep[i] = (struct task_struct){ i + 1 < 20 ? &deep[i + 1] :
							     &init_task,
						100 + i, 0, 0, &deep_file[i] };
	}
	self.real_parent = &deep[0];
	collect("deep");
	for (int i = 0; i < 20; i++)
		assert(!deep[i].refs && !deep_file[i].refs);
	assert(facts.ancestor_count == 16 && facts.ancestors_complete == 0 &&
	       stats[SE_PF_ANCESTOR_TRUNCATED] == 1);
	/* Exactly 16, then pid 0: complete. */
	world();
	for (int i = 0; i < 16; i++)
		deep[i] =
			(struct task_struct){ i + 1 < 16 ? &deep[i + 1] : &idle,
					      100 + i, 0, 0, &deep_file[i] };
	self.real_parent = &deep[0];
	collect("sixteen");
	assert(facts.ancestor_count == 16 && facts.ancestors_complete == 1);

	/* A reparent between two iterations never splices two chains: each link
	 * is the parent of the previous link, read while it was held. */
	world();
	on_put = reparent_self_to_c;
	collect("reparent");
	assert(self.real_parent == &c);
	assert(facts.ancestor_count == 3 && facts.ancestors_complete == 1);
	assert(path_is(&facts.ancestors[0], "/usr/bin/a"));
	assert(path_is(&facts.ancestors[1], "/usr/bin/b"));
	assert(path_is(&facts.ancestors[2], "/usr/lib/systemd/systemd"));
	printf("shared pass facts: ok\n");
	return 0;
}
