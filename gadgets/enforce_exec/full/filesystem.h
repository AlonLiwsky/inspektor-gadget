/* SPDX-License-Identifier: GPL-2.0 */
/* Per-class facts for the validated Linux memfd/LSM matrix. No path/name-based
 * inference. fs_known is a BIT MASK, not an all-or-nothing boolean.
 *
 * Attach full_fs_mark_memfd at inode_init_security_anon before admitting
 * policies. Inode storage is freed by the kernel with the inode, avoiding
 * pointer/dev+ino ABA. Credits bound all lifetime allocations and never recycle.
 * Unmarked shmem/hugetlb files remain MEMFD-unknown, including pre-attachment
 * files and any tracking-budget/allocation failures. Creation is never denied.
 */
#ifndef FULL_FILESYSTEM_H
#define FULL_FILESYSTEM_H
#define FULL_FS_TMPFS 1U
#define FULL_FS_MEMFD 2U
#define FULL_FS_DELETED 4U
#define FULL_FS_OVERLAY 8U
#ifndef FULL_FS_LIFETIME_MAX
#define FULL_FS_LIFETIME_MAX 65536ULL
#endif
struct full_fs_marker {
	__u64 memfd;
};
struct full_fs_diagnostics {
	__u64 credits, faults;
};
struct full_fs_facts {
	__u32 mask, known;
};
#ifndef FULL_FS_SHARED_MARK
struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct full_fs_marker);
} fs_inode_origins SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct full_fs_diagnostics);
} fs_diagnostics SEC(".maps");

#endif

static __always_inline void full_fs_mark_memfd(struct inode *inode,
					       const struct qstr *class)
{
#ifndef FULL_FS_SHARED_MARK
	__u32 zero = 0;
	struct full_fs_diagnostics *d =
		bpf_map_lookup_elem(&fs_diagnostics, &zero);
	if (!d)
		return;
#endif
	__u32 length = 0;
	const unsigned char *name = 0;
	unsigned char bytes[7] = {};
	if (!class || BPF_CORE_READ_INTO(&length, class, len) ||
	    BPF_CORE_READ_INTO(&name, class, name) || !name) {
#ifndef FULL_FS_SHARED_MARK
		__sync_fetch_and_or(&d->faults, 2);
#endif
		return;
	}
	if (length != 7)
		return;
	if (bpf_probe_read_kernel(bytes, sizeof(bytes), name)) {
#ifndef FULL_FS_SHARED_MARK
		__sync_fetch_and_or(&d->faults, 2);
#endif
		return;
	}
	/* This is the kernel's security class QSTR(MEMFD_ANON_NAME), NOT the
  * user-controlled memfd filename. The pinned memfd_alloc_file uses this
  * class for both ordinary and MFD_HUGETLB files. */
	if (bytes[0] != '[' || bytes[1] != 'm' || bytes[2] != 'e' ||
	    bytes[3] != 'm' || bytes[4] != 'f' || bytes[5] != 'd' ||
	    bytes[6] != ']')
		return;
#ifdef FULL_FS_SHARED_MARK
	FULL_FS_SHARED_MARK(inode);
#else
	if (bpf_inode_storage_get(&fs_inode_origins, inode, 0, 0))
		return;
	int reserved = 0;
#pragma clang loop unroll(disable)
	for (int i = 0; i < 64; i++) {
		__u64 old = __sync_val_compare_and_swap(&d->credits, 0, 0);
		if (old >= FULL_FS_LIFETIME_MAX)
			break;
		if (__sync_val_compare_and_swap(&d->credits, old, old + 1) ==
		    old) {
			reserved = 1;
			break;
		}
	}
	if (!reserved) {
		__sync_fetch_and_or(&d->faults, 1);
		return;
	}
	struct full_fs_marker *marker = bpf_inode_storage_get(
		&fs_inode_origins, inode, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!marker) {
		__sync_fetch_and_or(&d->faults, 4);
		return;
	}
	marker->memfd = 1;
#endif
}

/* file must be a verifier-trusted, live exec file (not a probed raw file ptr).
 * Individual failed reads leave only the affected classes unknown.
 * deleted follows d_unlinked: unhashed dentry which is not its own parent.
 */
static __always_inline struct full_fs_facts
full_file_filesystem(struct file *file)
{
	struct full_fs_facts out = {};
	if (!file)
		return out;
	struct inode *inode = file->f_inode;
	if (!inode)
		return out;
	struct super_block *sb = 0;
	unsigned long magic = 0;
	if (!BPF_CORE_READ_INTO(&sb, inode, i_sb) && sb &&
	    !BPF_CORE_READ_INTO(&magic, sb, s_magic)) {
		out.known |= FULL_FS_TMPFS | FULL_FS_OVERLAY;
		if (magic == 0x01021994UL)
			out.mask |= FULL_FS_TMPFS;
		if (magic == 0x794c7630UL)
			out.mask |= FULL_FS_OVERLAY;
		/* memfd_alloc_file's only backing types in the validated kernel matrix. */
		if (magic != 0x01021994UL && magic != 0x958458f6UL)
			out.known |= FULL_FS_MEMFD;
	}
#ifdef FULL_FS_SHARED_READ
	if (FULL_FS_SHARED_READ(inode)) {
#else
	struct full_fs_marker *marker =
		bpf_inode_storage_get(&fs_inode_origins, inode, 0, 0);
	if (marker && marker->memfd == 1) {
#endif
		out.known |= FULL_FS_MEMFD;
		out.mask |= FULL_FS_MEMFD;
	}
	struct dentry *dentry = 0, *parent = 0;
	struct hlist_bl_node **pprev = 0;
	if (!BPF_CORE_READ_INTO(&dentry, file, f_path.dentry) && dentry &&
	    !BPF_CORE_READ_INTO(&parent, dentry, d_parent) && parent &&
	    !BPF_CORE_READ_INTO(&pprev, dentry, d_hash.pprev)) {
		out.known |= FULL_FS_DELETED;
		if (!pprev && parent != dentry)
			out.mask |= FULL_FS_DELETED;
	}
	return out;
}
#endif
