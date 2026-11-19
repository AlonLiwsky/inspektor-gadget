/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_ARM_TRIGGER_H
#define ENFORCE_EXEC_SHARED_ARM_TRIGGER_H

#include <stdint.h>
#include <sys/types.h>

struct se_arm_trigger_result {
	ssize_t written;
	int error_number;
};

/* S-side constructor: dir_fd is a separately trusted cgroup directory. Its
 * inode must match the saved exact cgroup ID on the admitted amd64 kernels.
 * Returns a CLOEXEC writable cgroup.subtree_control fd, or -1. */
int se_arm_s_open_trigger_fd(int dir_fd, uint64_t expected_cgroup_id);

/* A-side primitive only. fd must be S-verified and pre-opened on an exact
 * cgroup-v2 cgroup.subtree_control file. This performs one write, no retry;
 * failure or short write remains ambiguous until S reconciles the receipt. */
int se_arm_a_trigger_fd(int fd, struct se_arm_trigger_result *result);

#endif
