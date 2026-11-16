/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 The Inspektor Gadget authors */
/* BPF_PROG_TEST_RUN only: this program is never attached. */
#include "gate.h"
#define SEC(name) __attribute__((section(name), used))
#define MAP_UINT(name, value) int(*name)[value]
#define MAP_TYPE(name, value) value *name
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 65536);
	MAP_UINT(map_flags, 1024); /* BPF_F_MMAPABLE */
	MAP_TYPE(key, unsigned int);
	MAP_TYPE(value, fg_u64);
} gate_words SEC(".maps");
struct gate_command {
	unsigned int slot, operation;
};
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, unsigned int);
	MAP_TYPE(value, struct gate_command);
} commands SEC(".maps");
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, unsigned int);
	MAP_TYPE(value, fg_u64);
} release_faults SEC(".maps");
static void *(*map_lookup)(void *, const void *) = (void *)1;
SEC("socket") int gate_test(void *unused)
{
	(void)unused;
	unsigned int zero = 0;
	struct gate_command *command = map_lookup(&commands, &zero);
	if (!command)
		return 99;
	unsigned int slot = command->slot;
	fg_u64 *word = map_lookup(&gate_words, &slot);
	int result;
	if (command->operation == 0)
		result = fg_enter(word);
	else if (command->operation == 1)
		result = fg_leave(word);
	else if (command->operation == 2 || command->operation == 3) {
		fg_u64 *faults = map_lookup(&release_faults, &zero);
		result = fg_leave_owned(word, command->operation == 2, faults);
	} else
		return 99;
	return result + 1;
}
char LICENSE[] SEC("license") = "GPL";
