// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
#include "../../../program.bpf.c"

// Test-only companion: demonstrate correct BPF-LSM return-value chaining.
SEC("lsm/bprm_check_security")
long BPF_PROG(preserve_previous, struct linux_binprm *bprm, long ret)
{
	return ret;
}
