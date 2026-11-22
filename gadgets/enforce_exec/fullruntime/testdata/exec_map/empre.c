// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

/* A library that prints EMPRE-LOADED when it is loaded
 * (TestSharedNodeExecMapAttached). */
#include <unistd.h>
__attribute__((constructor)) static void empre_init(void)
{
	(void)!write(1, "EMPRE-LOADED\n", 13);
}
