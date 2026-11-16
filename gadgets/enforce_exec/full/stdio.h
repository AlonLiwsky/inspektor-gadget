/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 The Inspektor Gadget authors */
#ifndef ENFORCE_EXEC_STDIO_H
#define ENFORCE_EXEC_STDIO_H

/* Restricted post-exec stdin classification, not a general fget replacement.
 * The sole current files owner may borrow its descriptor as __fget_light does.
 * On x86 an aligned READ_ONCE plus compiler barrier implements acquire ordering.
 * Every operation after proving ownership is nonsleeping. Shared tables, failed
 * reads and unvalidated architectures return UNKNOWN (-1), never false.
 *
 * CLOEXEC FD0 will not survive standard exec. Named FIFO and anonymous pipe both
 * satisfy S_IFIFO. This needs the documented kernel/LSM matrix and live proof;
 * it does not promise safe arbitrary shared-CLONE_FILES inspection.
 */
static __always_inline int full_stdin_pipe(struct task_struct *task)
{
#ifndef __TARGET_ARCH_x86
	return -1;
#else
	struct files_struct *files = 0;
	if (BPF_CORE_READ_INTO(&files, task, files) || !files)
		return -1;
	int owners = 0;
	if (BPF_CORE_READ_INTO(&owners, files, count.counter) || owners != 1)
		return -1;
	asm volatile("" ::: "memory");

	struct fdtable *table = 0;
	unsigned int max_fds = 0;
	if (BPF_CORE_READ_INTO(&table, files, fdt) || !table ||
	    BPF_CORE_READ_INTO(&max_fds, table, max_fds) || !max_fds)
		return -1;
	unsigned long *close_on_exec = 0, close_mask = 0;
	if (BPF_CORE_READ_INTO(&close_on_exec, table, close_on_exec) ||
	    !close_on_exec ||
	    bpf_probe_read_kernel(&close_mask, sizeof(close_mask),
				  close_on_exec))
		return -1;
	int result = 0;
	if (!(close_mask & 1UL)) {
		struct file **descriptors = 0;
		struct file *file = 0;
		if (BPF_CORE_READ_INTO(&descriptors, table, fd) ||
		    !descriptors ||
		    bpf_probe_read_kernel(&file, sizeof(file), descriptors))
			return -1;
		if (file) {
			struct inode *inode = 0;
			unsigned short mode = 0;
			if (BPF_CORE_READ_INTO(&inode, file, f_inode) ||
			    !inode || BPF_CORE_READ_INTO(&mode, inode, i_mode))
				return -1;
			result = (mode & 0xf000U) ==
				 0x1000U; /* S_IFMT / S_IFIFO */
		}
	}
	asm volatile("" ::: "memory");
	if (BPF_CORE_READ_INTO(&owners, files, count.counter) || owners != 1)
		return -1;
	return result;
#endif
}
#endif
