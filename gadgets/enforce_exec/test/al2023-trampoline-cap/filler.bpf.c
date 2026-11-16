// SPDX-License-Identifier: GPL-2.0
/* Test-only no-op trampoline fillers for the G009 cap probe. The runner
 * retargets each program (AttachTo) and loads one instance per link. None of
 * them can deny: the LSM filler returns 0. A BPF LSM program only runs when
 * every earlier fmod_ret program on the trampoline returned 0, so 0 is also
 * the prior result. fentry/fexit return values are ignored by the kernel. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("lsm/bprm_check_security")
int filler_lsm(void *ctx)
{
	return 0;
}

SEC("fentry/bprm_execve")
int filler_fentry(void *ctx)
{
	return 0;
}

SEC("fexit/bprm_execve")
int filler_fexit(void *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
