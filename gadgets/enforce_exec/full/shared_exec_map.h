/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_EXEC_MAP_H
#define ENFORCE_EXEC_SHARED_EXEC_MAP_H
/* The executable-mapping gate of the shared exec engine. Two BPF LSM
 * programs:
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
 *   not from image (0)  Strict: deny (-EACCES). Audit: allow, report.
 *   UNKNOWN (-1)        Strict: deny. Audit: allow, report.
 *
 * No path fact is read, so the held-file path provenance question (root
 * anchor, reachability) does not arise here. A path in an event is
 * information only.
 *
 * The switch is the binding's snapshot metadata word exec_map_flags
 * (SE_EXEC_MAP_*, full/shared_snapshot.h): it changes with the policy and the
 * image handle in one publish, and the publisher refuses JUDGE without an
 * image handle.
 *
 * Coverage is the exec verdict's own route state, read like the root barrier
 * reads it (real_owner_root_barrier_coverage): the ACTIVE route of the
 * current task's exact cgroup. The image identity {handle, overlay dev} and
 * the flags are the metadata of that route's ACTIVE snapshot record. The gate
 * takes no claim (lock-read-lock, see exec_map_still).
 *
 * Anonymous memory. These are allowed and counted (EM_ANON), and judged as
 * "not from image" only under SE_EXEC_MAP_DENY_ANON:
 * - a MAP_ANONYMOUS mapping (a JIT);
 * - a file on a kernel-internal shmem or hugetlbfs mount (P12 of the
 *   classifier): memfd, MAP_SHARED|MAP_ANONYMOUS (shmem_zero_setup), SysV
 *   shm (shmat(SHM_EXEC) calls security_mmap_file with the shm file), a
 *   hugetlb memfd;
 * - /dev/zero (character device 1:5): the hook runs before the driver makes
 *   the mapping anonymous.
 * A private file mapping that has an anon_vma (some page of it was written,
 * or it was split from one that was) and is then made executable is the same
 * class (EM_MODIFIED): it may hold the workload's own bytes, like anonymous
 * memory. Its unwritten pages still hold the file's bytes; the class claims
 * no more than "a private mapping with an anon_vma". So the gate stops the loader,
 * LD_PRELOAD and dlopen from mapping a file that is not from the image; code
 * that the workload copies or writes into memory itself is the anonymous
 * class. A file on a user-visible tmpfs (for example /dev/shm, POSIX
 * shm_open) is a file: not from the image.
 *
 * Program-file exemption (SE_EXEC_MAP_EXE_EXEMPT): a mapping of the file
 * that the exec verdict allowed for this process is allowed. The file is the
 * engine's own record (em_exec_record at bprm_committed_creds, on the thread
 * group leader), not mm->exe_file, which userspace can change
 * (PR_SET_MM_EXE_FILE, PR_SET_MM_MAP). It covers both hooks, so text
 * relocations of that program work. A child made by fork without exec has no
 * record of its own: it gets no exemption.
 *
 * Verdicts: one exec_map_event per denied (Strict) or would-deny (Audit)
 * mapping, on its own ring (exec_map_events, the "execmap" datasource) with
 * its own counters, so mapping verdicts never push out exec verdicts.
 * Counters per binding slot: exec_map_counters.
 *
 * Fail closed: a route invariant fault in a covered cgroup denies every
 * executable mapping there, in Audit too, with or without the gate (the class
 * is not known, as for the root barrier). exec_map_faults counts these
 * faults [0] and Strict UNKNOWN results [1] (a classifier fault or a race
 * that the retry did not resolve); both are the node's mapping-gate
 * fail-closed class. An Audit UNKNOWN is counted in exec_map_counters and
 * reported as an event, never as a fault.
 *
 * Self-test: exec_map_probe names one agent thread (a random nonce comm).
 * For that thread only, an uncovered mapping is judged as Strict with no
 * image: a file mapping is denied and marks the probe entry; anonymous
 * memory is allowed. The agent proves both programs at start. The entry can
 * only add denials, to one agent thread.
 *
 * Requires, before the include: se_image_classify and its maps and
 * constants, se_bindings, SE_ROUTE_CAPACITY, se_opaque_real_route_index,
 * se_opaque_real_route_anchor, ROOT_BARRIER_PRIOR, se_verdict_load_epoch,
 * GADGET_TRACER and bpf_path_d_path. */

#define EM_PROT_EXEC 0x4UL
#define EM_VM_EXEC 0x4UL
#define EM_MAP_ANONYMOUS 0x20UL
#define EM_EACCES 13
#define EM_S_IFCHR 0020000U
#define EM_DEV_ZERO ((1U << 20) | 5U) /* MKDEV(1, 5), kernel dev_t */

#define EM_HOOK_MMAP 1U
#define EM_HOOK_MPROTECT 2U

enum em_cell {
	EM_JUDGED = 0, /* executable mappings judged (file or anonymous) */
	EM_ALLOW_IMAGE, /* file from the image */
	EM_ALLOW_EXE, /* the program file of the exec record (EXE_EXEMPT) */
	EM_NOT_IMAGE, /* file not from the image */
	EM_UNKNOWN, /* provenance UNKNOWN (read fault, race) */
	EM_ANON, /* anonymous executable memory (MAP_ANONYMOUS) */
	EM_MODIFIED, /* private file mapping with an anon_vma made executable */
	EM_DENIED, /* Strict denials */
	EM_WOULD_DENY, /* Audit: allowed, Strict would deny */
	EM_RACE, /* the snapshot record moved during the lookup (retried) */
	EM_MPROTECT, /* judged in file_mprotect (subset of EM_JUDGED) */
	EM_SHMEM, /* memfd, shared anonymous, SysV shm, hugetlb (anonymous) */
	EM_DEV_ZERO_CELL, /* /dev/zero (anonymous) */
	EM_CELLS,
};
struct em_counts {
	__u64 count[EM_CELLS];
};
/* Per binding slot, per CPU; the agent sums the CPUs. Monotonic for the
 * slot's lifetime: a reader takes differences. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SE_ROUTE_CAPACITY);
	__type(key, __u32);
	__type(value, struct em_counts);
} exec_map_counters SEC(".maps");
/* Fail-closed class: [0] route invariant faults (denied), [1] UNKNOWN
 * results (a classifier fault, or a race after the retry). */
#define EM_FAULT_ROUTE 0U
#define EM_FAULT_UNKNOWN 1U
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} exec_map_faults SEC(".maps");

/* One event per denied or would-deny mapping. */
struct exec_map_event {
	__u64 generation; /* route generation of the judged snapshot record */
	__u64 scope; /* the binding's scope cookie (se_binding_snapshots.scope) */
	__u64 cgroup;
	__u64 ino; /* inode number of the mapped file (0: anonymous) */
	__u64 load_epoch; /* se_verdict_load_epoch */
	__u32 dev; /* kernel dev_t of the mapped file's superblock */
	__u32 hook; /* 1 mmap_file, 2 file_mprotect */
	__u32 reason; /* enum em_cell: NOT_IMAGE, UNKNOWN, ANON, MODIFIED, ... */
	__u32 exec_class; /* 1 Audit (would deny), 2 Strict (denied) */
	__u32 deny; /* 1 the mapping was refused */
	__u32 host_pid; /* thread group id, information only */
	__u32 slot;
	__u32 reserved;
	char comm[16];
	char path[256]; /* mmap_file only, information only; empty otherwise */
};
_Static_assert(sizeof(struct exec_map_event) == 344, "exec map event wire");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} exec_map_events SEC(".maps");
GADGET_TRACER(execmap, exec_map_events, exec_map_event);
/* submitted, lost (failed reservations) */
#define EM_EVENT_SUBMITTED 0U
#define EM_EVENT_LOST 1U
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} exec_map_event_counters SEC(".maps");

/* The program file that the exec verdict allowed, per thread group (on the
 * group leader). Written at bprm_committed_creds. */
struct em_exe {
	__u64 ino;
	__u32 dev, valid;
};
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct em_exe);
} exec_map_exe SEC(".maps");

/* Self-test probe (see the top). The entry matches the one thread whose
 * name is the nonce (15 random characters): the tid is not compared, so the
 * test works outside the host PID namespace. denied: bit hook of each
 * denial. */
struct em_probe {
	__u32 armed, denied;
	char nonce[16];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct em_probe);
} exec_map_probe SEC(".maps");

/* consistent: the ACTIVE record was read whole (its serial and phase did not
 * change around the reads). Only then are flags, handle and dev the
 * binding's. A record is immutable once PREPARED, so an unchanged serial
 * means unchanged metadata. */
struct em_cover {
	__u64 cgroup, serial, handle, generation, scope;
	__u32 slot, incarnation, record, dev, known, flags, consistent,
		reserved;
};

static __always_inline void em_count(__u32 slot, __u32 cell)
{
	struct em_counts *c = bpf_map_lookup_elem(&exec_map_counters, &slot);
	/* Atomic: a non-sleepable LSM program can still be preempted by
	 * another on the same CPU (preemptible RCU). */
	if (c && cell < EM_CELLS)
		__sync_fetch_and_add(&c->count[cell], 1);
}

static __always_inline void em_fault(__u32 cell)
{
	__u64 *n = bpf_map_lookup_elem(&exec_map_faults, &cell);
	if (n)
		__sync_fetch_and_add(n, 1);
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
	c->flags = 0;
	c->generation = 0;
	c->scope = 0;
	c->consistent = 0;
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &slot);
	/* An ACTIVE route always names a binding, a serial and a record. */
	if (!binding || !serial || record >= 2)
		return 3;
	/* The binding's scope does not change with a publish: set it first,
	 * so an event of a moved record is still attributed. */
	c->scope = binding->state.scope;
	asm volatile("" : "+r"(record));
	const struct se_snapshot *s = &binding->state.records[record & 1U];
	/* A publish can move the route between the anchor read and here: the
	 * record is then not consistent, and the caller retries; it never
	 * reads the flags as "off". */
	if (s->serial != serial || s->phase != SE_SNAPSHOT_ACTIVE)
		return class;
	c->handle = s->metadata.image_handle;
	c->dev = s->metadata.image_dev;
	c->flags = s->metadata.exec_map_flags;
	c->generation = s->generation;
	asm volatile("" ::: "memory");
	c->consistent = s->serial == serial && s->phase == SE_SNAPSHOT_ACTIVE;
	c->known = c->consistent && c->handle && c->dev;
	return class;
}

/* 1 when the record read by exec_map_cover is still the route's ACTIVE one.
 * Lock-read-lock is enough, with no claim: active_serial is never reused in
 * one slot incarnation, so the same incarnation, serial and record at both
 * reads mean that no publish happened in between, and an ACTIVE record holds
 * its image reference (full/shared_image_snapshot.h): the image keys were in
 * se_image_keys for the whole lookup. */
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

/* Anonymous-memory files (see the top): 0 a file, EM_SHMEM or
 * EM_DEV_ZERO_CELL, or -1 on a read fault. */
static __attribute__((noinline)) int em_anon_file(struct file *file)
{
	struct inode *inode = 0;
	struct super_block *sb = 0;
	unsigned long magic = 0;
	umode_t mode = 0;
	__u32 rdev = 0;
	fmode_t fmode = 0;
	__u32 backing = se_image_fmode_backing;
	if (!file || BPF_CORE_READ_INTO(&fmode, file, f_mode))
		return -1;
	/* A backing file (FMODE_BACKING: the real file of an overlayfs
	 * mapping) is a file, whatever its layer: overlayfs opens it on a
	 * private clone of the layer mount, which also has the internal mount
	 * namespace, so a layer on tmpfs would otherwise read as shmem. */
	if ((backing == SE_IMAGE_FMODE_BACKING_24 ||
	     backing == SE_IMAGE_FMODE_BACKING_25) &&
	    (fmode & backing))
		return 0;
	if (BPF_CORE_READ_INTO(&inode, file, f_inode) || !inode ||
	    BPF_CORE_READ_INTO(&mode, inode, i_mode) ||
	    BPF_CORE_READ_INTO(&sb, inode, i_sb) || !sb ||
	    BPF_CORE_READ_INTO(&magic, sb, s_magic))
		return -1;
	if ((mode & SE_IMAGE_S_IFMT) == EM_S_IFCHR) {
		if (BPF_CORE_READ_INTO(&rdev, inode, i_rdev))
			return -1;
		return rdev == EM_DEV_ZERO ? EM_DEV_ZERO_CELL : 0;
	}
	if (magic != SE_IMAGE_TMPFS_MAGIC && magic != SE_IMAGE_HUGETLBFS_MAGIC)
		return 0;
	/* P12: a kern_mount()ed superblock's mount has mnt_ns ERR_PTR(-EINVAL);
	 * a tmpfs mounted by userspace is in a real namespace. */
	struct vfsmount *mnt = 0;
	struct mnt_namespace *ns = 0;
	if (BPF_CORE_READ_INTO(&mnt, file, f_path.mnt) || !mnt)
		return -1;
	struct mount___se_image *m =
		(void *)((char *)mnt -
			 bpf_core_field_offset(struct mount___se_image, mnt));
	if (BPF_CORE_READ_INTO(&ns, m, mnt_ns))
		return -1;
	return (void *)ns == SE_IMAGE_MNT_NS_INTERNAL ? EM_SHMEM : 0;
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
 * classified as it is (tmpfs, a volume: not from image). */
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

/* {dev, ino} of a file; 0 on a read fault. */
static __always_inline int em_file_id(struct file *file, __u32 *dev, __u64 *ino)
{
	struct inode *inode = 0;
	*dev = 0;
	*ino = 0;
	if (!file || BPF_CORE_READ_INTO(&inode, file, f_inode) || !inode ||
	    BPF_CORE_READ_INTO(ino, inode, i_ino) ||
	    BPF_CORE_READ_INTO(dev, inode, i_sb, s_dev))
		return 0;
	return 1;
}

/* bprm_committed_creds: record the program file that the exec verdict
 * allowed, on the new thread group leader (de_thread() has run: current is
 * the leader). The record replaces the one of the previous image. Called
 * from the engine's own bprm_committed_creds program. */
static __always_inline void em_exec_record(struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct em_exe *e = bpf_task_storage_get(&exec_map_exe, task, 0,
						BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!e)
		return;
	__u32 dev = 0;
	__u64 ino = 0;
	int ok = em_file_id(BPF_CORE_READ(bprm, file), &dev, &ino);
	e->valid = 0;
	e->ino = ino;
	e->dev = dev;
	e->valid = ok;
}

/* {dev, ino} of the outer (overlay) file of a vma's file: on overlayfs
 * vma->vm_file is the real backing file, whose user_path is the outer path
 * it was opened for (P4/P5). Any other file is its own identity. */
static __attribute__((noinline)) int em_vma_file_id(struct file *real,
						    __u32 *dev, __u64 *ino)
{
	__u32 offset = se_image_user_path_offset(0, 0);
	__u32 backing = se_image_fmode_backing;
	fmode_t mode = 0;
	if (!real || BPF_CORE_READ_INTO(&mode, real, f_mode))
		return 0;
	if (!(backing == SE_IMAGE_FMODE_BACKING_24 ||
	      backing == SE_IMAGE_FMODE_BACKING_25) ||
	    !offset || !(mode & backing))
		return em_file_id(real, dev, ino);
	struct path user_path = {};
	struct inode *inode = 0;
	*dev = 0;
	*ino = 0;
	if (bpf_probe_read_kernel(&user_path, sizeof(user_path),
				  (void *)real + offset) ||
	    !user_path.dentry ||
	    BPF_CORE_READ_INTO(&inode, user_path.dentry, d_inode) || !inode ||
	    BPF_CORE_READ_INTO(ino, inode, i_ino) ||
	    BPF_CORE_READ_INTO(dev, inode, i_sb, s_dev))
		return 0;
	return 1;
}

/* 1 when file is the program file of the current thread group's record.
 * vma_file: file is a vma's file (file_mprotect). */
static __attribute__((noinline)) int em_is_exe(struct file *file, int vma_file)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_struct *leader = task->group_leader;
	if (!leader)
		return 0;
	struct em_exe *e = bpf_task_storage_get(&exec_map_exe, leader, 0, 0);
	if (!e || !e->valid)
		return 0;
	__u32 dev = 0;
	__u64 ino = 0;
	if (vma_file ? !em_vma_file_id(file, &dev, &ino) :
		       !em_file_id(file, &dev, &ino))
		return 0;
	return ino == e->ino && dev == e->dev;
}

static __always_inline void em_event_count(__u32 key)
{
	__u64 *n = bpf_map_lookup_elem(&exec_map_event_counters, &key);
	if (n)
		__sync_fetch_and_add(n, 1);
}

/* One event for a denied or would-deny mapping. path_file: the outer file
 * of an mmap (trusted hook argument), for the information-only path; 0 for
 * file_mprotect. The verdict never depends on delivery. */
static __attribute__((noinline)) void em_emit(const struct em_cover *c,
					      int class, __u32 cell_hook,
					      struct file *file,
					      struct file *path_file)
{
	/* cell_hook: reason | hook << 8 (BPF calls take five arguments). */
	__u32 cell = cell_hook & 0xff, hook = cell_hook >> 8;
	if (!c)
		return;
	struct exec_map_event *e =
		bpf_ringbuf_reserve(&exec_map_events, sizeof(*e), 0);
	if (!e) {
		em_event_count(EM_EVENT_LOST);
		return;
	}
	e->generation = c->generation;
	e->scope = c->scope;
	e->cgroup = c->cgroup;
	e->load_epoch = se_verdict_load_epoch;
	(void)em_file_id(file, &e->dev, &e->ino);
	e->hook = hook;
	e->reason = cell;
	e->exec_class = class;
	e->deny = class == 2;
	e->host_pid = bpf_get_current_pid_tgid() >> 32;
	e->slot = c->slot;
	e->reserved = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->path[0] = 0;
	if (path_file &&
	    bpf_path_d_path(&path_file->f_path, e->path, sizeof(e->path)) < 0)
		e->path[0] = 0;
	bpf_ringbuf_submit(e, 0);
	em_event_count(EM_EVENT_SUBMITTED);
}

/* The verdict of one judged mapping. cell is the reason. Returns 0 or
 * -EACCES. */
static __always_inline int em_refuse(const struct em_cover *c, int class,
				     __u32 cell, __u32 hook, struct file *file,
				     struct file *path_file)
{
	em_emit(c, class, cell | hook << 8, file, path_file);
	if (class == 2) {
		em_count(c->slot, EM_DENIED);
		return -EM_EACCES;
	}
	em_count(c->slot, EM_WOULD_DENY);
	return 0;
}

/* The self-test probe (see the top): the entry names this thread. */
static __attribute__((noinline)) int em_probe_judge(struct file *file,
						    __u32 hook)
{
	__u32 zero = 0;
	struct em_probe *p = bpf_map_lookup_elem(&exec_map_probe, &zero);
	if (!p || !p->armed || !p->nonce[0])
		return 0;
	char comm[16] = {};
	bpf_get_current_comm(comm, sizeof(comm));
	for (int i = 0; i < 16; i++) {
		if (comm[i] != p->nonce[i])
			return 0;
		if (!comm[i])
			break;
	}
	if (!file || em_anon_file(file))
		return 0;
	__sync_fetch_and_or(&p->denied, 1U << hook);
	return -EM_EACCES;
}

#define EM_RETRY 1

/* One verdict against the record c that exec_map_cover read whole
 * (c->consistent). how: vma_file (bit 0: file is a vma's file, at
 * file_mprotect), modified (bit 1: the mapping has an anon_vma), hook << 8.
 * Returns 0, -EACCES, or EM_RETRY when a publish moved the record during the
 * image lookup: the caller judges again against the new record. */
static __attribute__((noinline)) int em_verdict(struct em_cover *c, int class,
						struct file *file, __u32 how)
{
	int vma_file = how & 1, modified = (how >> 1) & 1;
	__u32 hook = how >> 8;
	if (!c || !(c->flags & SE_EXEC_MAP_JUDGE))
		return 0;
	__u32 slot = c->slot;
	struct file *path_file = vma_file ? 0 : file;
	em_count(slot, EM_JUDGED);
	if (hook == EM_HOOK_MPROTECT)
		em_count(slot, EM_MPROTECT);
	int anon = file ? em_anon_file(file) : EM_ANON;
	if (anon < 0) {
		em_count(slot, EM_UNKNOWN);
		if (class == 2)
			em_fault(EM_FAULT_UNKNOWN);
		return em_refuse(c, class, EM_UNKNOWN, hook, file, path_file);
	}
	if (anon > 0 || modified) {
		__u32 cell = modified && !anon ? EM_MODIFIED : (__u32)anon;
		em_count(slot, cell);
		if (c->flags & SE_EXEC_MAP_DENY_ANON)
			return em_refuse(c, class, cell, hook, file, path_file);
		return 0;
	}
	if ((c->flags & SE_EXEC_MAP_EXE_EXEMPT) && em_is_exe(file, vma_file)) {
		em_count(slot, EM_ALLOW_EXE);
		return 0;
	}
	int image = -1;
	if (c->known)
		image = vma_file ? em_class_vma(file, c->handle, c->dev) :
				   em_class_outer(file, c->handle, c->dev);
	if (!exec_map_still(c))
		return EM_RETRY;
	if (image == 1) {
		em_count(slot, EM_ALLOW_IMAGE);
		return 0;
	}
	__u32 cell = image == 0 ? EM_NOT_IMAGE : EM_UNKNOWN;
	em_count(slot, cell);
	/* Fail-closed class: Strict UNKNOWN only. An Audit UNKNOWN denies
	 * nothing; it is counted (EM_UNKNOWN) and reported, never NotReady. */
	if (cell == EM_UNKNOWN && class == 2)
		em_fault(EM_FAULT_UNKNOWN);
	return em_refuse(c, class, cell, hook, file, path_file);
}

/* Common body. file is the mapped file (null: MAP_ANONYMOUS); vma_file says
 * that it is a vma's file (file_mprotect); modified that the mapping has an
 * anon_vma. A publish that moves the record during a lookup gets one more
 * full verdict against the new ACTIVE record (all of its flags): a publish
 * must not break a mapping that both records allow. A second move is
 * UNKNOWN. */
static __always_inline int em_judge(struct file *file, int vma_file,
				    int modified, __u32 hook)
{
	__u32 how = (vma_file ? 1U : 0U) | (modified ? 2U : 0U) | hook << 8;
	struct em_cover c = {};
	int class = exec_map_cover(&c);
	if (!class)
		return em_probe_judge(file, hook);
	int retried = 0;
	if (class != 3 && !c.consistent) {
		/* A publish moved the record before it was read: read the new
		 * ACTIVE record once more. */
		em_count(c.slot, EM_RACE);
		retried = 1;
		class = exec_map_cover(&c);
		if (!class)
			return 0;
	}
	if (class == 3) {
		/* The class is unknown: fail closed, like the root barrier,
		 * with or without the gate. */
		em_fault(EM_FAULT_ROUTE);
		return -EM_EACCES;
	}
	if (c.consistent) {
		int r = em_verdict(&c, class, file, how);
		if (r != EM_RETRY)
			return r;
		if (!retried) {
			em_count(c.slot, EM_RACE);
			class = exec_map_cover(&c);
			if (!class)
				return 0;
			if (class == 3) {
				em_fault(EM_FAULT_ROUTE);
				return -EM_EACCES;
			}
			if (c.consistent) {
				r = em_verdict(&c, class, file, how);
				if (r != EM_RETRY)
					return r;
			}
		}
	}
	/* Two publishes in one lookup: whether the gate is on, or the image
	 * fact, is not known. UNKNOWN: Strict denies, Audit reports. */
	em_count(c.slot, EM_UNKNOWN);
	if (class == 2)
		em_fault(EM_FAULT_UNKNOWN);
	return em_refuse(&c, class, EM_UNKNOWN, hook, file,
			 vma_file ? 0 : file);
}

/* A denial of an earlier LSM program stays. The prior verdict is the context
 * word after the hook's arguments (ROOT_BARRIER_PRIOR); the range check keeps
 * the LSM return range visible to the verifier. */
#define EM_KEEP_DENY(prior)                                                    \
	do {                                                                   \
		__s64 em_prior = (prior);                                      \
		if (em_prior)                                                  \
			return em_prior < 0 && em_prior >= -4095 ? em_prior :  \
								   -EM_EACCES; \
	} while (0)

SEC("lsm/mmap_file")
long BPF_PROG(em_mmap_file, struct file *file, unsigned long reqprot,
	      unsigned long prot, unsigned long flags)
{
	EM_KEEP_DENY(ROOT_BARRIER_PRIOR(4));
	if (!(prot & EM_PROT_EXEC))
		return 0;
	/* An anonymous mapping is told by MAP_ANONYMOUS, not by a null file:
	 * measured on AL2023 6.12.113 and 6.18.56, the verifier takes this
	 * hook's file argument as never null and removes a null check of it
	 * (an anonymous mapping was then classified as a file, UNKNOWN). A
	 * kernel caller that passes NULL without MAP_ANONYMOUS
	 * (load_elf_binary under MMAP_PAGE_ZERO) then reads as a file with a
	 * read fault: Strict denies it (fails closed, rare). With MAP_HUGETLB
	 * the kernel passes its own hugetlbfs file: still anonymous memory. */
	if (flags & EM_MAP_ANONYMOUS)
		return em_judge(0, 0, 0, EM_HOOK_MMAP);
	return em_judge(file, 0, 0, EM_HOOK_MMAP);
}

SEC("lsm/file_mprotect")
long BPF_PROG(em_file_mprotect, struct vm_area_struct *vma,
	      unsigned long reqprot, unsigned long prot)
{
	EM_KEEP_DENY(ROOT_BARRIER_PRIOR(3));
	if (!(prot & EM_PROT_EXEC))
		return 0;
	/* Already executable: judged when it was mapped. */
	if (vma->vm_flags & EM_VM_EXEC)
		return 0;
	struct file *file = vma->vm_file;
	int modified = file && vma->anon_vma;
	return em_judge(file, 1, modified, EM_HOOK_MPROTECT);
}
#endif
