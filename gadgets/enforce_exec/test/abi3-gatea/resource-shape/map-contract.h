/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RESOURCE_SHAPE_MAP_CONTRACT_H
#define RESOURCE_SHAPE_MAP_CONTRACT_H
#include <fcntl.h>
#include <linux/bpf.h>
/* Pinned syscall.c bpf_map_flags_retain_permanent() strips only FD access
 * flags. RDONLY_PROG/NO_PREALLOC/etc remain object flags, never masked away. */
static unsigned rs_persistent_flags(unsigned declared)
{
	return declared & ~(BPF_F_RDONLY | BPF_F_WRONLY);
}
static int rs_fd_mode(unsigned declared)
{
	if ((declared & (BPF_F_RDONLY | BPF_F_WRONLY)) ==
	    (BPF_F_RDONLY | BPF_F_WRONLY))
		return -1;
	if (declared & BPF_F_RDONLY)
		return O_RDONLY;
	if (declared & BPF_F_WRONLY)
		return O_WRONLY;
	return O_RDWR;
}
static int rs_map_access_valid(unsigned declared, unsigned actual, int fd_flags)
{
	return rs_fd_mode(declared) >= 0 && fd_flags >= 0 &&
	       actual == rs_persistent_flags(declared) &&
	       (fd_flags & O_ACCMODE) == rs_fd_mode(declared);
}
#endif
