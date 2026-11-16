/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
struct bpf_spin_lock {
	__u32 val;
};
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
/* ACTUAL_TYPES */
struct fm_blob {
	unsigned char bytes[288];
};
struct eo_task {
	struct bpf_spin_lock lock;
	struct {
		__u32 owned;
		__u64 owner_cookie, generation;
		struct eo_reader_claim reader;
	} exec;
};
struct eo_work {
	__u64 busy;
	struct eo_reader_claim reader;
};
static struct eo_task task;
static struct eo_work work;
static struct eo_dispatch dispatch;
static struct eo_program_cell cells[2][4];
static int eo_program_bank0, eo_program_bank1, lookups, missing_task;
static void *bpf_map_lookup_elem(void *map, const __u32 *key)
{
	lookups++;
	assert(*key < 4);
	return &cells[map == &eo_program_bank1 ? 1 : 0][*key];
}
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	assert(!lock->val);
	lock->val = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	assert(lock->val);
	lock->val = 0;
}
static void *bpf_get_current_task_btf(void)
{
	return &task;
}
static struct eo_task *eo_lookup_task(void *unused)
{
	(void)unused;
	return missing_task ? 0 : &task;
}
static struct eo_work *eo_borrow_work(void)
{
	return &work;
}
#define EO_ABI 3
struct eo_config {
	__u64 cookie;
	__u32 abi;
};
static struct eo_config config = { .cookie = 7, .abi = 3 };
static int eo_admin, admin_enabled = 1;
static __u64 admin_nonce = 7;
static struct eo_config *eo_config(void)
{
	return &config;
}
static void *bpf_task_storage_get(void *map, void *task, void *value,
				  __u64 flags)
{
	(void)task;
	(void)value;
	assert(map == &eo_admin && !flags);
	return admin_enabled ? &admin_nonce : 0;
}
/* ACTUAL_PHYSICAL_BLOB */
/* ACTUAL_CURRENT_BLOB */
/* ACTUAL_GLOBAL_BLOB */
int main(void)
{
	cells[0][0].attempt = 7;
	cells[0][0].data[0] = 11;
	cells[1][0].attempt = 8;
	cells[1][0].data[0] = 22;
	task.exec.owned = task.exec.reader.owned = 1;
	task.exec.reader.kind = EO_READER_EXEC;
	task.exec.reader.session_cookie = 7;
	task.exec.owner_cookie = 7;
	task.exec.generation = 7;
	task.exec.reader.descriptor =
		(struct eo_dispatch_descriptor){ .generation = 7,
						 .program_bank = 0 };
	dispatch.active.program_bank =
		1; // Mutable selector is deliberately different.
	assert(full_lookup_global(0)->bytes[0] == 11 &&
	       dispatch.active.program_bank == 1);
	work.busy = work.reader.owned = 1;
	work.reader.kind = EO_READER_CANDIDATE;
	work.reader.session_cookie = 7;
	work.reader.descriptor =
		(struct eo_dispatch_descriptor){ .generation = 8,
						 .program_bank = 1 };
	assert(full_lookup_global(0)->bytes[0] == 22);
	admin_enabled = 0;
	assert(!full_lookup_global(0));
	admin_enabled = 1;
	admin_nonce = 8;
	assert(!full_lookup_global(0));
	admin_nonce = 7;
	work.reader.kind = EO_READER_EXEC;
	assert(!full_lookup_global(0));
	work.reader.kind = EO_READER_CANDIDATE;
	work.reader.session_cookie = 8;
	assert(!full_lookup_global(0));
	work.reader.session_cookie = 7;
	missing_task = 1;
	assert(full_lookup_global(0)->bytes[0] == 22);
	missing_task = 0;
	work.busy = 0;
	assert(full_lookup_global(0)->bytes[0] == 11);
	work.busy = 1;
	work.reader.descriptor.generation = 9;
	assert(!full_lookup_global(0));
	work.reader.descriptor.generation = 8;
	cells[1][0].attempt = 7;
	assert(!full_lookup_global(0));
	cells[1][0].attempt = 8;
	int before = lookups;
	assert(!full_lookup_global(16384) && lookups == before);
	work.reader.descriptor.program_bank = 2;
	assert(!full_lookup_global(0) && lookups == before);
	work.reader.owned = 0;
	task.exec.owned = 0;
	assert(!full_lookup_global(0)); // No fallback to mutable active bank.
	return 0;
}
