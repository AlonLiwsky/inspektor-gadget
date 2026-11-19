/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RESOURCE_SHAPE_PROGRAM_TYPE_H
#define RESOURCE_SHAPE_PROGRAM_TYPE_H
#include <string.h>
#include <bpf/libbpf.h>
/* Open-only contract shared by checker and runner. Never coerces program type
 * or flags to hide a wrongly classified ELF. At open, explicit flags are zero;
 * libbpf v1.7 SEC_SLEEPABLE adds BPF_F_SLEEPABLE to load opts later. */
static int rs_program_type_valid(const struct bpf_object *object)
{
	struct bpf_program *program;
	unsigned count = 0;
	bpf_object__for_each_program(program, object)
	{
		count++;
		if (strcmp(bpf_program__name(program), "shape") ||
		    strcmp(bpf_program__section_name(program), "syscall") ||
		    bpf_program__type(program) != BPF_PROG_TYPE_SYSCALL ||
		    bpf_program__flags(program) != 0)
			return 0;
	}
	return count == 1;
}
#endif
