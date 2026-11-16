/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_IMAGE_CLASSIFY_H
#define ENFORCE_EXEC_SHARED_IMAGE_CLASSIFY_H
#include "shared_image.h"

/* G020 kernel "from image" classifier. Pure read-side adapter: no lock, no
 * snapshot/reader authority, no map mutation. The caller (O3 per-pass facts)
 * owns the snapshot reference that pins {handle, image_dev} and its
 * se_image_keys generation through the LAST lookup made here.
 *
 * An exec file is "from image" iff it is a regular file on the container's
 * own overlay (outer superblock dev == image_dev) whose authenticated backing
 * real file lives in a LOWER layer whose layer root {ino, dev} the publisher
 * inserted for this handle. Upper files, copy-ups, memfds, host files and
 * foreign overlays are NOT from image (0). Anything unverifiable is UNKNOWN
 * (-1), never 1.
 *
 * Premises, exact AL2023 sources (g020-ksrc/{6.12/linux-6.12.113,
 * 6.18/linux-6.18.56}):
 * P1 6.12 fs/overlayfs/file.c:170 `file->private_data = realfile;` (ovl_open):
 *    private_data IS the real struct file.
 * P2 6.18 fs/overlayfs/file.c:92-95 `struct ovl_file { struct file *realfile;
 *    struct file *upperfile; }` and :232 `file->private_data = of;`: private_data
 *    is struct ovl_file *, realfile is its FIRST field (offset 0). ovl_file is
 *    module-private (absent from vmlinux BTF), hence no CO-RE: the layout is a
 *    rodata constant set by Go from the exact kernel matrix (kernel_matrix.go).
 * P3 Both: ovl_open_realfile -> backing_file_open (fs/backing-file.c:33-55):
 *    alloc_empty_backing_file sets FMODE_BACKING (6.12 fs/file_table.c:313,
 *    6.18 :339; include/linux/fs.h 6.12:175 / 6.18:177, 1 << 24).
 * P4 backing-file.c:37,46 user_path = file_user_path(user_file); for the
 *    non-backing outer overlay file that is &outer->f_path (fs.h 6.12:2814,
 *    6.18:2922). So user_path == {outer f_path.mnt, outer f_path.dentry}.
 * P5 struct backing_file { struct file file; struct path user_path; ... }
 *    (6.12 file_table.c:46; 6.18 :47, user_path in a union with bf_freeptr,
 *    used by the slab only while the object is FREE). Present in vmlinux BTF on
 *    both kernels; its CO-RE offset must equal round_up(sizeof(struct file), 8)
 *    or the classification is refused.
 * P6 backing-file.c:47 vfs_open(real_path, f): real f_path = realpath, whose
 *    mnt is the layer mount (fs/overlayfs/util.c 6.12:251,272 / 6.18:264,285,
 *    upper 6.12:241 / 6.18:254).
 * P7 Layer mounts are clone_private_mount(&l->path) (overlayfs/super.c
 *    6.12:1043 / 6.18:1097; upper 6.12:496 / 6.18:524) = clone_mnt(old,
 *    path->dentry, CL_PRIVATE) (fs/namespace.c 6.12:2304 / 6.18:2402): the
 *    layer mount's mnt_root IS the layer directory dentry.
 * P8 Overlay sb->s_magic = OVERLAYFS_SUPER_MAGIC (overlayfs/super.c 6.12:1450 /
 *    6.18:1537).
 * P9 ovl_mmap maps exactly this realfile (overlayfs/file.c 6.12:426 /
 *    6.18:482), so the classified file is the one whose pages are executed.
 *    A later copy-up never rewrites private_data/realfile; open_exec's
 *    deny_write_access makes such a copy-up content-identical.
 * P10 exec always opens a fresh file (fs/exec.c do_open_execat -> do_filp_open,
 *    also for AT_EMPTY_PATH): realfile reflects the lower/upper state at THIS
 *    exec's open; the outer file pins outer->realfile through bprm lifetime.
 * P11 Lower layer mounts get `mnt->mnt_flags |= MNT_READONLY | MNT_NOATIME;`
 *    after clone_private_mount (overlayfs/super.c 6.12:1055 / 6.18:1109); the
 *    upper clone (6.12:496 / 6.18:524) is never read-only (a read-only upper
 *    is refused via __mnt_is_readonly at 6.12:481 / 6.18:509). MNT_READONLY =
 *    0x40 (include/linux/mount.h). Private clones are in no namespace and
 *    cannot be remounted, so an indexed layer mount WITHOUT MNT_READONLY is
 *    not a lower layer (e.g. an upper dir wrongly indexed): UNKNOWN, never 1.
 * P12 memfd_create files live on a kernel-internal tmpfs/hugetlbfs mount:
 *    shmem_init `shm_mnt = kern_mount(&shmem_fs_type)` (mm/shmem.c) and the
 *    hugetlbfs kern_mount (fs/hugetlbfs/inode.c), both through kern_mount
 *    (fs/namespace.c 6.12:5698-5705 / 6.18:6081-6084) which sets
 *    `real_mount(mnt)->mnt_ns = MNT_NS_INTERNAL`, MNT_NS_INTERNAL =
 *    ERR_PTR(-EINVAL) = (void *)-22 (fs/mount.h; mm/shmem.c and fs/mount.h are
 *    NOT in g020-ksrc: verified live on both kernels by the memfd case of
 *    TestSharedImageClassifyAttached, not from source). struct vfsmount mnt is
 *    a member of struct mount (fs/mount.h, in vmlinux BTF; CO-RE container_of).
 *    A user-mounted tmpfs sits in a real mnt_namespace, so it is not matched.
 */

#if !defined(ENFORCE_EXEC_SHARED_IMAGE_KERNEL_H) && \
	!defined(SE_IMAGE_CLASSIFY_EXTERNAL_KEYS)
#error "include shared_image_kernel.h (se_image_keys) or provide test keys"
#endif
_Static_assert(sizeof(struct se_image_map_key) == 24,
	       "se_image_keys key layout (shared_image_kernel.h)");

#define SE_IMAGE_OVERLAYFS_SUPER_MAGIC 0x794c7630UL
#define SE_IMAGE_FMODE_BACKING (1U << 24)
#define SE_IMAGE_S_IFMT 0170000U
#define SE_IMAGE_S_IFREG 0100000U
#define SE_IMAGE_MINORBITS 20
#define SE_IMAGE_MNT_READONLY 0x40U /* P11 */
#define SE_IMAGE_TMPFS_MAGIC 0x01021994UL
#define SE_IMAGE_HUGETLBFS_MAGIC 0x958458f6UL
#define SE_IMAGE_MNT_NS_INTERNAL ((void *)-22L) /* P12 */

/* Overlay private_data layout; MUST match kernel_matrix.go. UNSET refuses. */
#define SE_IMAGE_OVL_LAYOUT_UNSET 0
#define SE_IMAGE_OVL_LAYOUT_REALFILE 1 /* 6.12: private_data = realfile */
#define SE_IMAGE_OVL_LAYOUT_OVL_FILE 2 /* 6.18: private_data = ovl_file */
const volatile __u32 se_image_ovl_layout = SE_IMAGE_OVL_LAYOUT_UNSET;

/* Witness slots. Classifier reasons first; command-side slots reserved for the
 * publisher/PREPARE path and never written by se_image_classify. */
enum se_image_class_reason {
	SE_IMAGE_CLASS_HIT = 0, /* 1: lower layer root indexed for handle */
	SE_IMAGE_CLASS_UPPER, /* 0: authenticated, layer root not indexed */
	SE_IMAGE_CLASS_NOT_OVERLAY, /* 0: outer file not on overlayfs */
	SE_IMAGE_CLASS_FOREIGN_OVERLAY, /* 0: overlay, s_dev != image_dev */
	SE_IMAGE_CLASS_NO_INDEX, /* -1: handle 0 */
	SE_IMAGE_CLASS_AUTH, /* -1: real file not authenticated */
	SE_IMAGE_CLASS_NESTED, /* -1: real not regular/nested/sb mismatch */
	SE_IMAGE_CLASS_READ_FAULT, /* -1: kernel read failed */
	SE_IMAGE_CLASS_INSERT_UNCERTAIN, /* command side, reserved */
	SE_IMAGE_CLASS_DELETE_UNCERTAIN, /* command side, reserved */
	SE_IMAGE_CLASS_PREPARE_REFUSED, /* command side, reserved */
	SE_IMAGE_CLASS_WRITABLE_LAYER, /* -1: indexed layer mount not MNT_READONLY */
	SE_IMAGE_CLASS_MEMFD, /* -1: memfd (internal tmpfs/hugetlbfs mount) */
	SE_IMAGE_CLASS_SLOTS,
};
struct se_image_class_witness {
	__u64 count[SE_IMAGE_CLASS_SLOTS];
};
_Static_assert(sizeof(struct se_image_class_witness) == 104,
	       "image class witness ABI");

#ifdef SE_IMAGE_CLASS_WITNESS_MAP
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_image_class_witness);
} se_image_class_witnesses SEC(".maps");
#endif

struct mount___se_image {
	struct vfsmount mnt;
	struct mnt_namespace *mnt_ns;
} __attribute__((preserve_access_index));

struct backing_file___se_image {
	struct file file;
	struct path user_path;
} __attribute__((preserve_access_index));

/* Offset of backing_file.user_path. BTF (P5) and round_up(sizeof(struct
 * file), 8) must agree; 0 refuses. Without the BTF type only the fallback. */
static __always_inline __u32 se_image_user_path_offset(__u32 *btf_offset,
						       __u32 *size_offset)
{
	__u32 fallback = ((__u32)bpf_core_type_size(struct file) + 7U) & ~7U;
	__u32 btf = 0;
	if (bpf_core_type_exists(struct backing_file___se_image) &&
	    bpf_core_field_exists(struct backing_file___se_image, user_path))
		btf = bpf_core_field_offset(struct backing_file___se_image,
					    user_path);
	if (btf_offset)
		*btf_offset = btf;
	if (size_offset)
		*size_offset = fallback;
	if (!fallback || (btf && btf != fallback))
		return 0;
	return fallback;
}

static __always_inline int se_image_class_note(struct se_image_class_witness *w,
					       __u32 reason, int result)
{
	if (w && reason < SE_IMAGE_CLASS_SLOTS)
		__sync_fetch_and_add(&w->count[reason], 1);
	return result;
}

/* Return 1 from image, 0 not from image, -1 UNKNOWN. outer is the exec file
 * (bprm->file), pinned by the caller; image_dev is the kernel dev_t of the
 * container overlay superblock and handle the snapshot's image handle. */
static __always_inline int se_image_classify(struct file *outer, __u64 handle,
					     __u32 image_dev,
					     struct se_image_class_witness *w)
{
	if (!handle)
		return se_image_class_note(w, SE_IMAGE_CLASS_NO_INDEX, -1);
	struct inode *inode = 0;
	struct super_block *sb = 0;
	unsigned long magic = 0;
	__u32 dev = 0;
	if (!outer || BPF_CORE_READ_INTO(&inode, outer, f_inode) || !inode ||
	    BPF_CORE_READ_INTO(&sb, inode, i_sb) || !sb ||
	    BPF_CORE_READ_INTO(&magic, sb, s_magic) ||
	    BPF_CORE_READ_INTO(&dev, sb, s_dev))
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	if (magic != SE_IMAGE_OVERLAYFS_SUPER_MAGIC) {
		if (magic == SE_IMAGE_TMPFS_MAGIC ||
		    magic == SE_IMAGE_HUGETLBFS_MAGIC) {
			struct vfsmount *omnt = 0;
			struct mnt_namespace *ns = 0;
			if (BPF_CORE_READ_INTO(&omnt, outer, f_path.mnt) ||
			    !omnt)
				return se_image_class_note(
					w, SE_IMAGE_CLASS_READ_FAULT, -1);
			struct mount___se_image *m =
				(void *)((char *)omnt -
					 bpf_core_field_offset(
						 struct mount___se_image, mnt));
			if (BPF_CORE_READ_INTO(&ns, m, mnt_ns))
				return se_image_class_note(
					w, SE_IMAGE_CLASS_READ_FAULT, -1);
			if ((void *)ns == SE_IMAGE_MNT_NS_INTERNAL)
				return se_image_class_note(
					w, SE_IMAGE_CLASS_MEMFD, -1);
		}
		return se_image_class_note(w, SE_IMAGE_CLASS_NOT_OVERLAY, 0);
	}
	if (dev != image_dev)
		return se_image_class_note(w, SE_IMAGE_CLASS_FOREIGN_OVERLAY,
					   0);

	/* Resolve (P1/P2). */
	__u32 layout = se_image_ovl_layout;
	__u32 offset = se_image_user_path_offset(0, 0);
	if ((layout != SE_IMAGE_OVL_LAYOUT_REALFILE &&
	     layout != SE_IMAGE_OVL_LAYOUT_OVL_FILE) ||
	    !offset)
		return se_image_class_note(w, SE_IMAGE_CLASS_AUTH, -1);
	void *private = 0;
	struct file *real = 0;
	if (BPF_CORE_READ_INTO(&private, outer, private_data) || !private)
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	if (layout == SE_IMAGE_OVL_LAYOUT_REALFILE)
		real = private;
	else if (bpf_probe_read_kernel(&real, sizeof(real), private))
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	if (!real)
		return se_image_class_note(w, SE_IMAGE_CLASS_AUTH, -1);

	/* Authenticate (P3-P5): a backing file opened FOR this outer path. */
	fmode_t mode = 0;
	struct path outer_path = {}, user_path = {};
	if (BPF_CORE_READ_INTO(&mode, real, f_mode) ||
	    bpf_core_read(&outer_path, sizeof(outer_path), &outer->f_path))
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	if (!(mode & SE_IMAGE_FMODE_BACKING))
		return se_image_class_note(w, SE_IMAGE_CLASS_AUTH, -1);
	if (bpf_probe_read_kernel(&user_path, sizeof(user_path),
				  (void *)real + offset))
		return se_image_class_note(w, SE_IMAGE_CLASS_READ_FAULT, -1);
	if (!outer_path.mnt || !outer_path.dentry ||
	    user_path.mnt != outer_path.mnt ||
	    user_path.dentry != outer_path.dentry)
		return se_image_class_note(w, SE_IMAGE_CLASS_AUTH, -1);

	/* Real inode on a non-overlay layer superblock (P6/P7). */
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
#endif
