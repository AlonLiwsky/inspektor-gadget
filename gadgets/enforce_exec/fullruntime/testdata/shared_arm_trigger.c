/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>
#include "shared-arm-trigger.h"

int main(void)
{
	char path[] = "/tmp/se-arm-trigger-XXXXXX";
	char *dir = mkdtemp(path);
	assert(dir);
	int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(dir_fd >= 0);
	errno = 0;
	assert(se_arm_s_open_trigger_fd(dir_fd, 1) == -1 &&
	       errno == EOPNOTSUPP);
	assert(!close(dir_fd));
	assert(!rmdir(dir));
	errno = 0;
	assert(se_arm_s_open_trigger_fd(-1, 1) == -1 && errno == EBADF);
	errno = 0;
	assert(se_arm_s_open_trigger_fd(-1, 0) == -1 && errno == EINVAL);
	/* Read-only local probe: never write the host's cgroup filesystem. */
	int cg_dir = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cg_dir >= 0) {
		struct statfs fs;
		struct stat st;
		if (!fstatfs(cg_dir, &fs) &&
		    (unsigned long)fs.f_type == CGROUP2_SUPER_MAGIC &&
		    !fstat(cg_dir, &st) && (uint64_t)st.st_ino < UINT64_MAX) {
			errno = 0;
			assert(se_arm_s_open_trigger_fd(
				       cg_dir, (uint64_t)st.st_ino + 1) == -1 &&
			       errno == EINVAL);
		}
		assert(!close(cg_dir));
	}
	int fds[2];
	assert(!pipe(fds));
	struct se_arm_trigger_result result = {};
	assert(!se_arm_a_trigger_fd(fds[1], &result));
	assert(result.written == 1 && !result.error_number);
	char byte = 0;
	assert(read(fds[0], &byte, 1) == 1 && byte == '\n');
	assert(!close(fds[1]));
	assert(se_arm_a_trigger_fd(fds[1], &result));
	assert(result.written == -1 && result.error_number == EBADF);
	assert(!close(fds[0]));
	return 0;
}
