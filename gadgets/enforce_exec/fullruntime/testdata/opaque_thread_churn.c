/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* One real pthread birth/join per process. The supervisor execs this helper
 * after moving an uncharged shell into the isolated cgroup, so only the
 * pthread's task_alloc consumes an opaque TASK credit. */
#include <pthread.h>

static void *run(void *opaque)
{
	int *observed = opaque;
	*observed = 1;
	return 0;
}

int main(void)
{
	pthread_t thread;
	int observed = 0;
	if (pthread_create(&thread, 0, run, &observed))
		return 1;
	if (pthread_join(thread, 0))
		return 2;
	return observed == 1 ? 0 : 3;
}
