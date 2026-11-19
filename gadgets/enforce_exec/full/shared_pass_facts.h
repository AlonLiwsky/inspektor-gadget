/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* G020 per-pass exec facts of the shared product evaluator (design O3).
 *
 * One call per evaluated bprm_check pass (the first pass and every
 * interpreter continuation), from the product prepare frame, writing straight
 * into the WORK's observation facts. The interpreter continuation reuses the
 * WORK, so every fact this collector owns is reset first: a fact the pass
 * cannot collect is UNKNOWN to the evaluator, never the previous pass's.
 *
 * UNKNOWN encodings (fullpolicy/bpf/evaluator.h): a path of length 0; a
 * stdin_pipe outside 0..1; an fs class whose fs_known bit is clear; an
 * ancestor chain with ancestor_count < depth and !ancestors_complete.
 *
 * H1: every path fact is anchored to the binding's root, recorded at Bind
 * (the adopted init's fs root and mount namespace, struct se_pf_anchor),
 * never to the exec'ing task's own root, which CAP_SYS_CHROOT could move:
 * a pass whose task root is not that anchor (or an unknown anchor) has
 * every path fact UNKNOWN (target, actor, ancestors; SE_PF_ROOT_MISMATCH).
 *
 * Paths come from bpf_path_d_path: relative to the exec'ing task's root
 * (the anchored root, checked above), symlinks resolved, never truncated
 * (longer than 255 bytes is -ENAMETOOLONG: UNKNOWN), and valid UTF-8 only
 * (anything else is UNKNOWN, never an evaluator FE_INVALID). d_path does
 * NOT report a file its root cannot reach (it returns the path from that
 * mount namespace's root instead, which looks like an ordinary absolute
 * path), so every path is also walked to the root (SE_PF_REACHABLE): an
 * unreachable file, e.g. a binfmt_misc F-flag interpreter opened outside
 * the container (user decision D5), is UNKNOWN with its own reason; a file
 * of a kernel-internal mount (a memfd) is UNKNOWN with its own reason too.
 * A deleted target, actor or ancestor executable (d_path's " (deleted)")
 * is UNKNOWN (the target's reason SE_PF_TARGET_PATH).
 *
 * The caller defines (BPF: CO-RE readers; host tests: stubs):
 *   SE_PF_STAT(cell)        count one SE_PF_* cell
 *   SE_PF_FS(file)          struct full_fs_facts of the exec file
 *   SE_PF_STDIN(task)       0/1, or -1 when unknown
 *   SE_PF_FS_SEQ()          current's fs_struct root/pwd sequence count (an
 *                           odd value: a write in flight, or unreadable)
 *   SE_PF_ROOTED(anchor)    1 current's root is the anchored binding root,
 *                           0 it is not, -1 unknown (no anchor)
 *   SE_PF_REACHABLE(file)   1 reachable from current's root, 0 not, 2 on a
 *                           kernel-internal mount (memfd), -1 unknown
 *   SE_PF_UNLINKED(file)    1 unlinked (deleted), 0 linked, -1 unknown
 *   SE_PF_MEMBER(task)      1 a task of the enforced workload (it has a
 *                           TASK), 0 not, -1 unknown
 *   SE_PF_INIT(task, anchor) 1 the binding's init (container root process)
 *   SE_PF_UTF8(bytes, n)    1 the n bytes are valid UTF-8, 0 not
 * and provides the kfuncs bpf_path_d_path, bpf_get_task_exe_file,
 * bpf_put_file, bpf_task_acquire, bpf_task_release, bpf_rcu_read_lock,
 * bpf_rcu_read_unlock and bpf_get_current_task_btf. */
/* The pure types (struct se_pf_anchor, se_pf_utf8_step): a caller may
 * include them first with SE_PF_TYPES_ONLY defined, to build its SE_PF_*
 * readers on them, then include the collector. */
#ifndef ENFORCE_EXEC_SHARED_PASS_FACTS_TYPES_H
#define ENFORCE_EXEC_SHARED_PASS_FACTS_TYPES_H
/* The binding's root anchor, recorded at Bind from the adopted init (H1):
 * its fs root (mount id, inode, device) and mount namespace, and the init's
 * identity (tgid, start ticks). known 0: no anchor (every path UNKNOWN). */
struct se_pf_anchor {
	__u64 root_ino, init_start;
	__u32 root_mnt_id, root_dev, mntns, init_tgid, known, reserved;
};

/* One byte of a UTF-8 validation (RFC 3629: no overlong form, no surrogate,
 * at most U+10FFFF). *state is 0 between characters, else the expected
 * continuation bytes (low 3 bits) and the second byte's allowed range
 * (bits 8-15 low, 16-23 high). 1 invalid. Pure, for SE_PF_UTF8. */
static __always_inline int se_pf_utf8_step(__u32 *state, __u8 c)
{
	__u32 st = *state;
	if (st & 7) {
		__u32 lo = (st >> 8) & 0xff, hi = (st >> 16) & 0xff;
		if (c < lo || c > hi)
			return 1;
		*state = (st & 7) - 1 ?
				 ((st & 7) - 1) | (0x80U << 8) | (0xbfU << 16) :
				 0;
		return 0;
	}
	if (c < 0x80)
		return c == 0; /* an embedded NUL is no path byte */
	if (c >= 0xc2 && c <= 0xdf)
		*state = 1 | (0x80U << 8) | (0xbfU << 16);
	else if (c == 0xe0)
		*state = 2 | (0xa0U << 8) | (0xbfU << 16);
	else if ((c >= 0xe1 && c <= 0xec) || c == 0xee || c == 0xef)
		*state = 2 | (0x80U << 8) | (0xbfU << 16);
	else if (c == 0xed)
		*state = 2 | (0x80U << 8) | (0x9fU << 16);
	else if (c == 0xf0)
		*state = 3 | (0x90U << 8) | (0xbfU << 16);
	else if (c >= 0xf1 && c <= 0xf3)
		*state = 3 | (0x80U << 8) | (0xbfU << 16);
	else if (c == 0xf4)
		*state = 3 | (0x80U << 8) | (0x8fU << 16);
	else
		return 1;
	return 0;
}

#endif
#if !defined(SE_PF_TYPES_ONLY) && !defined(ENFORCE_EXEC_SHARED_PASS_FACTS_H)
#define ENFORCE_EXEC_SHARED_PASS_FACTS_H
#if !defined(SE_PF_STAT) || !defined(SE_PF_FS) || !defined(SE_PF_STDIN) || \
	!defined(SE_PF_REACHABLE) || !defined(SE_PF_ROOTED) ||             \
	!defined(SE_PF_UNLINKED) || !defined(SE_PF_MEMBER) ||              \
	!defined(SE_PF_INIT) || !defined(SE_PF_UTF8) || !defined(SE_PF_FS_SEQ)
#error "pass facts need SE_PF_STAT, SE_PF_FS, SE_PF_STDIN, SE_PF_REACHABLE, SE_PF_ROOTED, SE_PF_UNLINKED, SE_PF_MEMBER, SE_PF_INIT, SE_PF_UTF8 and SE_PF_FS_SEQ"
#endif

/* Cells of opaque_real_fact_stats (fullruntime/shared_fact_stats.go). */
enum {
	SE_PF_PASSES = 0, /* passes collected (one per evaluated pass) */
	SE_PF_TARGET_MISSING, /* no exec file */
	SE_PF_TARGET_PATH, /* d_path failed, not absolute, deleted, walk unknown */
	SE_PF_TARGET_TOO_LONG, /* longer than 255 bytes */
	SE_PF_TARGET_OUTSIDE_ROOT, /* D5: not reachable from the binding root */
	SE_PF_ACTOR_MISSING, /* no exe file (kernel thread, exiting mm) */
	SE_PF_ACTOR_PATH, /* d_path failed, too long, or walk unknown */
	SE_PF_ACTOR_OUTSIDE_ROOT,
	SE_PF_FS_UNKNOWN, /* at least one fs class unknown */
	SE_PF_STDIN_UNKNOWN, /* shared files table or failed read */
	SE_PF_ANCESTOR_UNKNOWN, /* the walk failed: ancestor facts UNKNOWN */
	SE_PF_ANCESTOR_BOUNDARY, /* complete at the init or the workload edge */
	SE_PF_ANCESTOR_TRUNCATED, /* more than 16 ancestors (known prefix) */
	SE_PF_ROOT_MISMATCH, /* H1: task root is not the binding's anchor */
	SE_PF_TARGET_MEMFD, /* target on a kernel-internal mount (memfd) */
	SE_PF_PATH_UTF8, /* a target or actor path is not valid UTF-8 */
	SE_PF_ACTOR_DELETED, /* M2: the actor's executable is deleted */
	SE_PF_STATS
};
#define SE_PF_FS_ALL \
	(FULL_FS_TMPFS | FULL_FS_MEMFD | FULL_FS_DELETED | FULL_FS_OVERLAY)
#define SE_PF_ENAMETOOLONG 36

/* Every fact the collector owns, to UNKNOWN. The image facts are reset too:
 * the product's image classifier (its own frame, after this collector) sets
 * them, so a pass it cannot classify never keeps the previous pass's. */
static __always_inline void se_pf_reset(struct fe_facts *facts)
{
	facts->actor_image = -1;
	facts->target_image = -1;
	facts->target_path.length = 0;
	facts->actor_path.length = 0;
	facts->fs_mask = 0;
	facts->fs_known = 0;
	facts->stdin_pipe = -1;
	facts->ancestor_count = 0;
	facts->ancestors_complete = 0;
}

/* Fault cells of one path role (0: that check is not made). */
struct se_pf_cells {
	__u32 path, too_long, outside, internal, utf8, deleted;
};

/* 0, or the SE_PF_* fault cell of this path. The length is set only for an
 * absolute, valid UTF-8 path of <= 255 bytes reachable from the (anchored)
 * root, of a linked file when deleted is checked. */
static __always_inline __u32 se_pf_path(struct file *file, struct fe_path *out,
					const struct se_pf_cells *cells)
{
	out->length = 0;
	int n = bpf_path_d_path(&file->f_path, (char *)out->bytes,
				sizeof(out->bytes));
	if (n == -SE_PF_ENAMETOOLONG || n > 256)
		return cells->too_long;
	if (n <= 1 || out->bytes[0] != '/')
		return cells->path;
	int reachable = SE_PF_REACHABLE(file);
	if (reachable == 0)
		return cells->outside;
	if (reachable == 2)
		return cells->internal;
	if (reachable != 1)
		return cells->path;
	/* After the walk: a memfd is unlinked too, but its reason is its own. */
	if (cells->deleted && SE_PF_UNLINKED(file) != 0)
		return cells->deleted;
	if (!SE_PF_UTF8(out->bytes, n - 1))
		return cells->utf8;
	out->length = n - 1;
	return 0;
}

/* The parent of a task the caller holds (current, or an acquired ancestor),
 * acquired; 0 with *root set at the idle task (pid 0: the chain is complete),
 * 0 alone when it could not be acquired. */
static __always_inline struct task_struct *
se_pf_parent(struct task_struct *task, int *root)
{
	struct task_struct *held = 0;
	bpf_rcu_read_lock();
	struct task_struct *parent = task->real_parent;
	if (parent && parent->pid == 0)
		*root = 1;
	else if (parent)
		held = bpf_task_acquire(parent);
	bpf_rcu_read_unlock();
	return held;
}

/* Up to 16 ancestors, nearest first. Each link is read from the ancestor the
 * walk holds (an acquired reference, released exactly once on every path),
 * so a reparent between two iterations can never splice two chains: link
 * i+1 is always the real parent of the task recorded at link i, read while
 * that task was pinned. Any failure makes the whole ancestor fact UNKNOWN
 * (count 0, incomplete). The chain is complete at the binding's init (the
 * container root process, recorded as the last link), at the edge of the
 * workload (a parent that is no task of the enforced workload, e.g. the
 * runtime's shim of an exec session: its outside part is not this
 * workload's ancestry) or at pid 0. An ancestor of the workload whose
 * executable is unreachable from the binding root, deleted or otherwise
 * unknown fails the walk (H1: it cannot hide the rest of the chain). More
 * than 16 keeps the known prefix, incomplete. */
static __always_inline void se_pf_ancestors(struct task_struct *task,
					    struct fe_facts *facts,
					    const struct se_pf_anchor *anchor)
{
	const struct se_pf_cells cells = {
		SE_PF_ANCESTOR_UNKNOWN, SE_PF_ANCESTOR_UNKNOWN,
		SE_PF_ANCESTOR_UNKNOWN, SE_PF_ANCESTOR_UNKNOWN,
		SE_PF_ANCESTOR_UNKNOWN, SE_PF_ANCESTOR_UNKNOWN
	};
	int root = 0, failed = 0, boundary = 0;
	__u32 count = 0;
	struct task_struct *held = se_pf_parent(task, &root);
	if (!held && !root)
		failed = 1;
#pragma clang loop unroll(disable)
	for (__u32 i = 0; i < 16; i++) {
		if (!held)
			break;
		int member = SE_PF_MEMBER(held);
		if (member == 0) {
			boundary = 1;
			break;
		}
		struct file *exe = member == 1 ? bpf_get_task_exe_file(held) :
						 0;
		__u32 fault = SE_PF_ANCESTOR_UNKNOWN;
		if (exe) {
			fault = se_pf_path(exe, &facts->ancestors[i], &cells);
			bpf_put_file(exe);
		}
		if (fault) {
			failed = 1;
			break;
		}
		count = i + 1;
		if (SE_PF_INIT(held, anchor) == 1) {
			boundary = 1;
			break;
		}
		struct task_struct *next = se_pf_parent(held, &root);
		bpf_task_release(held);
		held = next;
		if (!held && !root) {
			failed = 1;
			break;
		}
	}
	if (held)
		bpf_task_release(held);
	if (failed) {
		facts->ancestor_count = 0;
		facts->ancestors_complete = 0;
		SE_PF_STAT(SE_PF_ANCESTOR_UNKNOWN);
		return;
	}
	facts->ancestor_count = count;
	facts->ancestors_complete = root || boundary;
	if (boundary)
		SE_PF_STAT(SE_PF_ANCESTOR_BOUNDARY);
	else if (!root)
		SE_PF_STAT(SE_PF_ANCESTOR_TRUNCATED);
}

/* Collect one pass's facts into facts (the WORK's observation facts). Every
 * failure leaves its fact UNKNOWN and counts its reason; the return is
 * negative only for invalid arguments (the caller fails the pass closed). */
static __always_inline int
se_pass_facts_collect(struct linux_binprm *bprm, struct fe_facts *facts,
		      const struct se_pf_anchor *anchor)
{
	if (!bprm || !facts || !anchor)
		return -1;
	se_pf_reset(facts);
	SE_PF_STAT(SE_PF_PASSES);
	/* H1: path facts only from the binding's anchored root, and only
	 * while that root holds for the whole collection: d_path and the
	 * reachability walk re-read current->fs->root, which a task sharing
	 * this fs_struct (a thread, CLONE_FS) can chroot at any time until
	 * de_thread. The fs_struct sequence count brackets every path read:
	 * even here, unchanged and still anchored after the last one, else
	 * every path fact is UNKNOWN (also on a mere chdir: fail-closed). */
	__u32 fs_seq = SE_PF_FS_SEQ();
	int rooted = !(fs_seq & 1) && SE_PF_ROOTED(anchor) == 1;
	if (!rooted)
		SE_PF_STAT(SE_PF_ROOT_MISMATCH);
	struct file *target = bprm->file;
	if (target) {
		const struct se_pf_cells cells = {
			SE_PF_TARGET_PATH,	   SE_PF_TARGET_TOO_LONG,
			SE_PF_TARGET_OUTSIDE_ROOT, SE_PF_TARGET_MEMFD,
			SE_PF_PATH_UTF8,	   SE_PF_TARGET_PATH
		};
		__u32 fault = rooted ? se_pf_path(target, &facts->target_path,
						  &cells) :
				       0;
		if (fault)
			SE_PF_STAT(fault);
		struct full_fs_facts fs = SE_PF_FS(target);
		facts->fs_mask = fs.mask & fs.known;
		facts->fs_known = fs.known;
	} else {
		SE_PF_STAT(SE_PF_TARGET_MISSING);
	}
	if (facts->fs_known != SE_PF_FS_ALL)
		SE_PF_STAT(SE_PF_FS_UNKNOWN);
	struct task_struct *task = bpf_get_current_task_btf();
	int stdin_pipe = SE_PF_STDIN(task);
	facts->stdin_pipe = stdin_pipe == 0 || stdin_pipe == 1 ? stdin_pipe :
								 -1;
	if (facts->stdin_pipe < 0)
		SE_PF_STAT(SE_PF_STDIN_UNKNOWN);
	if (!rooted)
		return 0;
	struct file *actor = bpf_get_task_exe_file(task);
	if (actor) {
		const struct se_pf_cells cells = {
			SE_PF_ACTOR_PATH,	  SE_PF_ACTOR_PATH,
			SE_PF_ACTOR_OUTSIDE_ROOT, SE_PF_ACTOR_OUTSIDE_ROOT,
			SE_PF_PATH_UTF8,	  SE_PF_ACTOR_DELETED
		};
		__u32 fault = se_pf_path(actor, &facts->actor_path, &cells);
		bpf_put_file(actor);
		if (fault)
			SE_PF_STAT(fault);
	} else {
		SE_PF_STAT(SE_PF_ACTOR_MISSING);
	}
	se_pf_ancestors(task, facts, anchor);
	/* Close the bracket after the last path read. */
	if (SE_PF_FS_SEQ() != fs_seq || SE_PF_ROOTED(anchor) != 1) {
		facts->target_path.length = 0;
		facts->actor_path.length = 0;
		facts->ancestor_count = 0;
		facts->ancestors_complete = 0;
		SE_PF_STAT(SE_PF_ROOT_MISMATCH);
	}
	return 0;
}
#endif
