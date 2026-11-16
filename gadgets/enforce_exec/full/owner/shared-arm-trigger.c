/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>
#include "shared-arm-trigger.h"

int se_arm_s_open_trigger_fd(int dir_fd, uint64_t expected_cgroup_id)
{
	if (!expected_cgroup_id) {
		errno = EINVAL;
		return -1;
	}
	struct statfs fs;
	struct stat dir_st;
	if (fstatfs(dir_fd, &fs) || fstat(dir_fd, &dir_st))
		return -1;
	if ((unsigned long)fs.f_type != CGROUP2_SUPER_MAGIC ||
	    !S_ISDIR(dir_st.st_mode)) {
		errno = EOPNOTSUPP;
		return -1;
	}
	if (sizeof(dir_st.st_ino) != sizeof(expected_cgroup_id) ||
	    (uint64_t)dir_st.st_ino != expected_cgroup_id) {
		errno = EINVAL;
		return -1;
	}
	int fd = openat(dir_fd, "cgroup.subtree_control",
			O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	struct stat st;
	if (fstatfs(fd, &fs) || fstat(fd, &st))
		goto fail;
	if ((unsigned long)fs.f_type != CGROUP2_SUPER_MAGIC ||
	    !S_ISREG(st.st_mode) || st.st_dev != dir_st.st_dev) {
		errno = EOPNOTSUPP;
		goto fail;
	}
	return fd;
fail: {
	int saved = errno;
	close(fd);
	errno = saved;
	return -1;
}
}

int se_arm_a_trigger_fd(int fd, struct se_arm_trigger_result *result)
{
	if (!result)
		return -1;
	result->written = -1;
	result->error_number = 0;
	ssize_t written = write(fd, "\n", 1);
	result->written = written;
	if (written < 0)
		result->error_number = errno;
	return written == 1 ? 0 : -1;
}
