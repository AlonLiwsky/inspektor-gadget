/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_EXEC_MAP_H
#define ENFORCE_EXEC_SHARED_EXEC_MAP_H
/* The executable-mapping gate of the shared exec engine (a proposal). Two
 * BPF LSM programs:
 *
 *   em_mmap_file      lsm/mmap_file      a new mapping with PROT_EXEC
 *   em_file_mprotect  lsm/file_mprotect  mprotect that adds PROT_EXEC
 *
 * The exec verdict (bprm_check_security) sees only the program that starts.
 * A dynamic loader started by hand (`ld.so /tmp/x`), LD_PRELOAD and dlopen
 * run code through a mapping, with no exec. This gate judges the mapped FILE
 * by its image provenance (full/shared_image_classify.h), never by a path:
 *
 *   from image (1)      allow
 *   not from image (0)  Strict: deny (-EACCES). Audit: allow and count.
 *   UNKNOWN (-1)        Strict: deny. Audit: allow and count.
 *
 * No path fact is read, so the held-file path provenance question (root
 * anchor, reachability) does not arise here.
 *
 * Coverage is the exec verdict's own route state, read like the root
 * barrier reads it (real_owner_root_barrier_coverage): the ACTIVE route of
 * the current task's exact cgroup. The image identity {handle, overlay dev}
 * is the metadata of that route's ACTIVE snapshot record. The gate takes no
 * claim. It reads the record, classifies, then checks under the route lock
 * that the same serial is still the ACTIVE one: an ACTIVE record holds its
 * image reference (full/shared_image_snapshot.h), so the keys were in
 * se_image_keys for the whole lookup. If the record moved, the result is
 * UNKNOWN.
 *
 * Anonymous executable memory (a JIT) has no file: allowed and counted,
 * unless the binding asks for EM_GATE_DENY_ANON. A private file mapping that
 * was written (vma->anon_vma) and then made executable is the same class.
 *
 * Not done yet (open design items):
 * - the per-binding switch is the map exec_map_gate, keyed by cgroup ID and
 *   written by the test. The product would carry it in the snapshot
 *   metadata, set by the publisher.
 * - verdicts are counters in the same map entry, not verdict events.
 * - no self-test and no fail-closed health class.
 *
 * Requires, before the include: se_image_classify and its maps and
 * constants, se_bindings, SE_ROUTE_CAPACITY, se_opaque_real_route_index and
 * se_opaque_real_route_anchor. */

#define EM_PROT_EXEC 0x4UL
#define EM_VM_EXEC 0x4UL
#define EM_MAP_ANONYMOUS 0x20UL
#define EM_EACCES 13

#define EM_GATE_JUDGE 1U /* judge executable file mappings */
#define EM_GATE_DENY_ANON 2U /* also deny anonymous executable memory */
/* Allow a mapping of the task's own program file (mm->exe_file): the exec
 * verdict allowed that file. Needed only when the policy allows a program
 * that is not from the image. */
#define EM_GATE_EXE_EXEMPT 4U

enum em_cell {
	EM_JUDGED = 0, /* executable mappings judged (file or anonymous) */
	EM_ALLOW_IMAGE, /* file from the image */
	EM_ALLOW_EXE, /* the task's own program file (EM_GATE_EXE_EXEMPT) */
	EM_NOT_IMAGE, /* file not from the image */
	EM_UNKNOWN, /* provenance UNKNOWN (memfd, no index, read fault, race) */
	EM_ANON, /* anonymous executable memory */
	EM_MODIFIED, /* written private file mapping made executable */
	EM_DENIED, /* Strict denials */
	EM_WOULD_DENY, /* Audit: allowed, Strict would deny */
	EM_RACE, /* the snapshot record moved during the lookup */
	EM_MPROTECT, /* judged in file_mprotect (subset of EM_JUDGED) */
	EM_CELLS,
};
struct em_gate {
	__u32 flags, last_hook; /* last_hook: 1 mmap_file, 2 file_mprotect */
	__u64 last_ino; /* inode number of the last denied or would-deny file */
	__u32 last_dev, last_cell;
	__u64 count[EM_CELLS];
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct em_gate);
} exec_map_gate SEC(".maps");
/* Route invariant faults seen by the gate: [0] denied (class unknown or
 * Strict), [1] reserved. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} exec_map_faults SEC(".maps");

struct em_cover {
	__u64 cgroup, serial, handle;
	__u32 slot, incarnation, record, dev, known, reserved;
};

static __always_inline void em_count(struct em_gate *g, __u32 cell)
{
	if (cell < EM_CELLS)
		__sync_fetch_and_add(&g->count[cell], 1);
}

/* 0 not covered, 1 Audit, 2 Strict, 3 route invariant fault. */
static __attribute__((noinline)) int exec_map_cover(struct em_cover *c)
{
	__u64 cgroup = bpf_get_current_cgroup_id();
	if (!cgroup || !c)
		return 0;
	const __u64 *entry = se_opaque_real_route_index(&cgroup);
	if (!entry)
		return 0;
	__u64 loc = __sync_val_compare_and_swap((__u64 *)entry, 0, 0);
	if (!loc)
		return 0;
	__u32 slot = (__u32)loc;
	if (slot >= SE_ROUTE_CAPACITY)
		return 3;
	struct se_route_anchor *a = se_opaque_real_route_anchor(&slot);
	if (!a)
		return 3;
	__u32 class = 0, record = 0, incarnation = 0;
	__u64 serial = 0;
	bpf_spin_lock(&a->lock);
	if ((__u32)loc == a->payload_slot &&
	    (__u32)(loc >> 32) == a->incarnation && a->incarnation &&
	    a->cgroup_identity == cgroup && a->phase == SE_ROUTE_ACTIVE) {
		class = a->execution_class;
		serial = a->active_serial;
		record = a->active_record;
		incarnation = a->incarnation;
		if (class != 1 && class != 2)
			class = 3;
	}
	bpf_spin_unlock(&a->lock);
	if (!class || class == 3)
		return class;
	c->cgroup = cgroup;
	c->serial = serial;
	c->slot = slot;
	c->incarnation = incarnation;
	c->record = record;
	c->handle = 0;
	c->dev = 0;
	c->known = 0;
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &slot);
	if (!binding || !serial || record >= 2)
		return class;
	asm volatile("" : "+r"(record));
	const struct se_snapshot *s = &binding->state.records[record & 1U];
	if (s->serial != serial || s->phase != SE_SNAPSHOT_ACTIVE)
		return class;
	c->handle = s->metadata.image_handle;
	c->dev = s->metadata.image_dev;
	asm volatile("" ::: "memory");
	c->known = s->serial == serial && s->phase == SE_SNAPSHOT_ACTIVE &&
		   c->handle && c->dev;
	return class;
}

/* 1 when the record read by exec_map_cover is still the route's ACTIVE one. */
static __attribute__((noinline)) int exec_map_still(const struct em_cover *c)
{
	if (!c)
		return 0;
	__u32 slot = c->slot;
	__u64 cgroup = c->cgroup, serial = c->serial;
	__u32 incarnation = c->incarnation, record = c->record;
	if (slot >= SE_ROUTE_CAPACITY)
		return 0;
	struct se_route_anchor *a = se_opaque_real_route_anchor(&slot);
	if (!a)
		return 0;
	int still;
	bpf_spin_lock(&a->lock);
	still = a->incarnation == incarnation && a->cgroup_identity == cgroup &&
		a->phase == SE_ROUTE_ACTIVE && a->active_serial == serial &&
		a->active_record == record;
	bpf_spin_unlock(&a->lock);
	return still;
}

static __always_inline struct se_image_class_witness *em_witness(void)
{
#ifdef REAL_OWNER_IMAGE_WITNESS_MAP
	__u32 zero = 0;
	return bpf_map_lookup_elem(&se_image_witness, &zero);
#else
	return 0;
#endif
}

/* The file of a new mapping (mmap): the outer file, as at exec.
 * remap_file_pages passes vma->vm_file, the backing file on overlayfs; it is
 * not handled here (classified as not from the image). */
static __attribute__((noinline)) int em_class_outer(struct file *file,
						    __u64 handle, __u32 dev)
{
	return se_image_classify(file, handle, dev, em_witness());
}

/* The file of an existing mapping (vma->vm_file). On overlayfs that is the
 * REAL backing file (ovl_mmap -> backing_file_mmap -> vma_set_file), not the
 * outer overlay file. A backing file (FMODE_BACKING) carries the outer path
 * it was opened for (backing_file.user_path, P4/P5 of the classifier): that
 * path must be on the container's own overlay. The layer checks are the
 * classifier's own (P6, P7, P11). A file that is not a backing file is
 * classified as it is (tmpfs, a volume: not from image; memfd: UNKNOWN). */
static __attribute__((noinline)) int em_class_vma(struct file *real,
						  __u64 handle, __u32 image_dev)
{
	struct se_image_class_witness *w = em_witness();
	if (!handle)
		return se_image_class_note(w, SE_IMAGE_CLASS_NO_INDEX, -1);
	__u32 offset = se_image_user_path_offset(0, 0);
	__u32 backing = se_image_fmode_backing;
	fmode_t mode = 0;
	if ((backing != SE_IMAGE_FMODE_BACKING_24 &&
	     backing != SE_IMAGE_FMODE_BACKING_25) ||
	    !offset)
		return se_image_class_note(w, SE_IMAGE_CLASS_AUTH, -1);
	if (!real || BPF_CORE_READ_INTO(&mode, real, f_mode))
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	if (!(mode & backing))
		return se_image_classify(real, handle, image_dev, w);
	struct path user_path = {};
	struct super_block *outer_sb = 0;
	unsigned long outer_magic = 0;
	__u32 outer_dev = 0;
	if (bpf_probe_read_kernel(&user_path, sizeof(user_path),
				  (void *)real + offset) ||
	    !user_path.dentry || !user_path.mnt)
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	struct dentry *outer = user_path.dentry;
	if (BPF_CORE_READ_INTO(&outer_sb, outer, d_sb) || !outer_sb ||
	    BPF_CORE_READ_INTO(&outer_magic, outer_sb, s_magic) ||
	    BPF_CORE_READ_INTO(&outer_dev, outer_sb, s_dev))
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	if (outer_magic != SE_IMAGE_OVERLAYFS_SUPER_MAGIC)
		return se_image_class_note(w, SE_IMAGE_CLASS_NOT_OVERLAY, 0);
	if (outer_dev != image_dev)
		return se_image_class_note(w, SE_IMAGE_CLASS_FOREIGN_OVERLAY,
					   0);
	struct inode *real_inode = 0, *root_inode = 0;
	struct super_block *real_sb = 0, *layer_sb = 0;
	struct vfsmount *layer = 0;
	struct dentry *root = 0;
	unsigned long real_magic = 0;
	umode_t real_mode = 0;
	__u32 real_dev = 0;
	__u64 root_ino = 0;
	if (BPF_CORE_READ_INTO(&real_inode, real, f_inode) || !real_inode ||
	    BPF_CORE_READ_INTO(&real_mode, real_inode, i_mode) ||
	    BPF_CORE_READ_INTO(&real_sb, real_inode, i_sb) || !real_sb ||
	    BPF_CORE_READ_INTO(&real_magic, real_sb, s_magic) ||
	    BPF_CORE_READ_INTO(&real_dev, real_sb, s_dev) ||
	    BPF_CORE_READ_INTO(&layer, real, f_path.mnt) || !layer ||
	    BPF_CORE_READ_INTO(&layer_sb, layer, mnt_sb) ||
	    BPF_CORE_READ_INTO(&root, layer, mnt_root) || !root ||
	    BPF_CORE_READ_INTO(&root_inode, root, d_inode) || !root_inode ||
	    BPF_CORE_READ_INTO(&root_ino, root_inode, i_ino))
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	if ((real_mode & SE_IMAGE_S_IFMT) != SE_IMAGE_S_IFREG ||
	    real_magic == SE_IMAGE_OVERLAYFS_SUPER_MAGIC || layer_sb != real_sb)
		return se_image_class_note(w, SE_IMAGE_CLASS_NESTED, -1);
	struct se_image_map_key key = {
		.image_handle = handle,
		.origin = { .inode = root_ino,
			    .major = real_dev >> SE_IMAGE_MINORBITS,
			    .minor = real_dev &
				     ((1U << SE_IMAGE_MINORBITS) - 1) },
	};
	const __u8 *membership = bpf_map_lookup_elem(&se_image_keys, &key);
	if (!membership)
		return se_image_class_note(w, SE_IMAGE_CLASS_UPPER, 0);
	if (*membership != 1)
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	unsigned int mnt_flags = 0;
	if (BPF_CORE_READ_INTO(&mnt_flags, layer, mnt_flags))
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	if (!(mnt_flags & SE_IMAGE_MNT_READONLY))
		return se_image_class_note(w, SE_IMAGE_CLASS_WRITABLE_LAYER,
					   -1);
	return se_image_class_note(w, SE_IMAGE_CLASS_HIT, 1);
}

static __always_inline void em_fault(void)
{
	__u32 zero = 0;
	__u64 *n = bpf_map_lookup_elem(&exec_map_faults, &zero);
	if (n)
		__sync_fetch_and_add(n, 1);
}

/* The verdict of one judged mapping. cell is the reason (EM_NOT_IMAGE,
 * EM_UNKNOWN, EM_ANON or EM_MODIFIED). Returns 0 or -EACCES. */
static __attribute__((noinline)) int em_refuse(struct em_gate *g, int class,
					       __u32 cell, __u32 hook,
					       struct file *file)
{
	if (!g)
		return 0;
	struct inode *inode = 0;
	__u64 ino = 0;
	__u32 dev = 0;
	if (file && !BPF_CORE_READ_INTO(&inode, file, f_inode) && inode) {
		(void)BPF_CORE_READ_INTO(&ino, inode, i_ino);
		(void)BPF_CORE_READ_INTO(&dev, inode, i_sb, s_dev);
	}
	g->last_ino = ino;
	g->last_dev = dev;
	g->last_cell = cell;
	g->last_hook = hook;
	if (class == 2) {
		em_count(g, EM_DENIED);
		return -EM_EACCES;
	}
	em_count(g, EM_WOULD_DENY);
	return 0;
}

/* Common body. file is the mapped file (null: anonymous); vma_file says
 * that it is a vma's file (file_mprotect), modified that the mapping has
 * private written pages. */
static __always_inline int em_judge(struct file *file, int vma_file,
				    int modified, __u32 hook)
{
	struct em_cover c = {};
	int class = exec_map_cover(&c);
	if (!class)
		return 0;
	if (class == 3) {
		/* The class is unknown: fail closed, like the root barrier. */
		em_fault();
		return -EM_EACCES;
	}
	__u64 cgroup = c.cgroup;
	struct em_gate *g = bpf_map_lookup_elem(&exec_map_gate, &cgroup);
	if (!g || !(g->flags & EM_GATE_JUDGE))
		return 0;
	em_count(g, EM_JUDGED);
	if (hook == 2)
		em_count(g, EM_MPROTECT);
	if (!file || modified) {
		em_count(g, file ? EM_MODIFIED : EM_ANON);
		if (g->flags & EM_GATE_DENY_ANON)
			return em_refuse(g, class, file ? EM_MODIFIED : EM_ANON,
					 hook, file);
		return 0;
	}
	if (!vma_file && (g->flags & EM_GATE_EXE_EXEMPT)) {
		struct task_struct *task = bpf_get_current_task_btf();
		struct file *exe = 0;
		struct inode *exe_inode = 0, *inode = 0;
		if (!BPF_CORE_READ_INTO(&exe, task, mm, exe_file) && exe &&
		    !BPF_CORE_READ_INTO(&exe_inode, exe, f_inode) &&
		    !BPF_CORE_READ_INTO(&inode, file, f_inode) && inode &&
		    inode == exe_inode) {
			em_count(g, EM_ALLOW_EXE);
			return 0;
		}
	}
	int image = -1;
	if (c.known)
		image = vma_file ? em_class_vma(file, c.handle, c.dev) :
				   em_class_outer(file, c.handle, c.dev);
	if (!exec_map_still(&c)) {
		em_count(g, EM_RACE);
		image = -1;
	}
	if (image == 1) {
		em_count(g, EM_ALLOW_IMAGE);
		return 0;
	}
	__u32 cell = image == 0 ? EM_NOT_IMAGE : EM_UNKNOWN;
	em_count(g, cell);
	return em_refuse(g, class, cell, hook, file);
}

/* A denial of an earlier LSM program stays; the range check keeps the LSM
 * return range visible to the verifier. */
#define EM_KEEP_DENY(ret)                                           \
	do {                                                        \
		if ((ret) < 0)                                      \
			return (ret) >= -4095 ? (ret) : -EM_EACCES; \
	} while (0)

SEC("lsm/mmap_file")
long BPF_PROG(em_mmap_file, struct file *file, unsigned long reqprot,
	      unsigned long prot, unsigned long flags, int ret)
{
	EM_KEEP_DENY(ret);
	if (!(prot & EM_PROT_EXEC))
		return 0;
	/* An anonymous mapping is told by MAP_ANONYMOUS, not by a null file:
	 * measured on AL2023 6.12.113 and 6.18.56, the verifier takes this hook's file
	 * argument as never null and removes a null check of it (an anonymous
	 * mapping was then classified as a file, UNKNOWN). With MAP_HUGETLB the
	 * kernel passes its own hugetlbfs file: still anonymous memory. */
	if (flags & EM_MAP_ANONYMOUS)
		return em_judge(0, 0, 0, 1);
	return em_judge(file, 0, 0, 1);
}

SEC("lsm/file_mprotect")
long BPF_PROG(em_file_mprotect, struct vm_area_struct *vma,
	      unsigned long reqprot, unsigned long prot, int ret)
{
	EM_KEEP_DENY(ret);
	if (!(prot & EM_PROT_EXEC))
		return 0;
	/* Already executable: judged when it was mapped. */
	if (vma->vm_flags & EM_VM_EXEC)
		return 0;
	struct file *file = vma->vm_file;
	int modified = file && vma->anon_vma;
	return em_judge(file, 1, modified, 2);
}
#endif
