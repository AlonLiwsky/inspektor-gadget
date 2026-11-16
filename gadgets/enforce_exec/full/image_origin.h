/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 The Inspektor Gadget authors */
#ifndef ENFORCE_EXEC_IMAGE_ORIGIN_H
#define ENFORCE_EXEC_IMAGE_ORIGIN_H
/*
 * SPIKE, pinned Linux 6b4b543fa18757297ac756a6fe6e64f506b7844a.
 * Caller supplies ORIGIN_READY() and ORIGIN_LOOKUP(key). Ready certifies a
 * complete immutable index of ALL regular lower files, not just executable
 * files, and a validated root/mount matrix: immutable host-directory lowers,
 * no redirect/data-only layers or nested overlay, built-in overlay BTF.
 * Missing index entry means false ONLY under that contract. No upper-dentry
 * heuristic. This is not production owner/index validation.
 *
 * The trusted outer exec file pins ovl_file and its realfile until release.
 * Probe reads of that backing file are allowed; it is NEVER passed to a kfunc.
 * ovl_file.realfile is the originally opened mmap backing; read paths can
 * switch to upperfile after copy-up. If current and opened identities differ,
 * refuse as UNKNOWN rather than classifying a possibly different executable.
 */
struct full_origin_key {
	__u64 inode;
	__u32 major, minor;
};
struct ovl_file___sandbox {
	struct file *realfile;
} __attribute__((preserve_access_index));
extern struct inode *bpf_real_data_inode(struct file *file) __weak __ksym;

static __always_inline int full_origin_inode(struct inode *inode,
					     struct full_origin_key *key,
					     unsigned long *magic)
{
	struct super_block *sb = 0;
	__u32 dev = 0;
	unsigned short mode = 0;
	if (!inode || BPF_CORE_READ_INTO(&sb, inode, i_sb) || !sb ||
	    BPF_CORE_READ_INTO(&dev, sb, s_dev) ||
	    BPF_CORE_READ_INTO(magic, sb, s_magic) ||
	    BPF_CORE_READ_INTO(&key->inode, inode, i_ino) ||
	    BPF_CORE_READ_INTO(&mode, inode, i_mode) ||
	    (mode & 0xf000U) != 0x8000U)
		return -1;
	key->major = dev >> 20;
	key->minor = dev & ((1U << 20) - 1);
	return 0;
}

static __always_inline int full_file_image(struct file *file)
{
	if (!ORIGIN_READY() || !bpf_ksym_exists(bpf_real_data_inode))
		return -1;
	struct inode *outer = 0;
	struct full_origin_key outerkey = {}, current = {};
	unsigned long magic = 0, current_magic = 0;
	if (!file || BPF_CORE_READ_INTO(&outer, file, f_inode) ||
	    full_origin_inode(outer, &outerkey, &magic))
		return -1;
	struct inode *data = bpf_real_data_inode(file);
	if (full_origin_inode(data, &current, &current_magic) ||
	    current_magic == 0x794c7630UL)
		return -1;
	if (magic == 0x794c7630UL) {
		if (!bpf_core_type_exists(struct ovl_file___sandbox) ||
		    !bpf_core_field_exists(struct ovl_file___sandbox, realfile))
			return -1;
		struct ovl_file___sandbox *of = 0;
		struct file *backing = 0;
		struct inode *opened = 0;
		struct full_origin_key openedkey = {};
		unsigned long opened_magic = 0;
		if (BPF_CORE_READ_INTO(&of, file, private_data) || !of ||
		    BPF_CORE_READ_INTO(&backing, of, realfile) || !backing ||
		    BPF_CORE_READ_INTO(&opened, backing, f_inode) ||
		    full_origin_inode(opened, &openedkey, &opened_magic) ||
		    opened_magic == 0x794c7630UL ||
		    openedkey.inode != current.inode ||
		    openedkey.major != current.major ||
		    openedkey.minor != current.minor)
			return -1;
	}
	return ORIGIN_LOOKUP(&current) ? 1 : 0;
}
#endif
