// SPDX-License-Identifier: GPL-2.0
/* Isolated observer-only feasibility module; no policy/verdict/native registry. */
#include <linux/binfmts.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include "argv_wire.h"

static int ig_argv_fail(struct ig_argv_result *out, int error,
			unsigned int status)
{
	memset(out, 0, sizeof(*out));
	out->abi = IG_ARGV_ABI;
	out->status = status;
	out->error = error;
	return error;
}

__bpf_kfunc_start_defs();
__bpf_kfunc int ig_capture_pending_argv(struct linux_binprm *bprm, void *output,
					unsigned int output__sz)
{
	struct ig_argv_result *out = output;
	struct mm_struct *mm;
	unsigned long start;
	struct ig_argv_cursor cursor = {};
	int argc;

	if (output__sz != sizeof(*out))
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->abi = IG_ARGV_ABI;
	/* LSM trusted bprm is live for this synchronous callback. Do not accept
	 * a committed/current mm or retain any pointer after the call. */
	if (!bprm || !current->in_execve || !bprm->mm ||
	    bprm->mm == current->mm)
		return ig_argv_fail(out, -EINVAL, IG_ARGV_UNKNOWN);
	mm = bprm->mm;
	start = bprm->p;
	argc = bprm->argc;
	if (argc < 0)
		return ig_argv_fail(out, -EINVAL, IG_ARGV_UNKNOWN);
	if (argc > IG_ARGV_MAX_ARGS)
		return ig_argv_fail(out, -E2BIG, IG_ARGV_OVERSIZED);
	cursor.argc = argc;
	while (cursor.strings < cursor.argc) {
		struct page *page = NULL;
		const unsigned char *mapping;
		unsigned long address, offset;
		unsigned int available, i;
		int locked = 1, copied = 0;
		long count;

		if (cursor.bytes == IG_ARGV_MAX_BYTES)
			return ig_argv_fail(out, -E2BIG, IG_ARGV_OVERSIZED);
		if (start > ULONG_MAX - cursor.bytes)
			return ig_argv_fail(out, -EOVERFLOW, IG_ARGV_UNKNOWN);
		address = start + cursor.bytes;
		offset = offset_in_page(address);
		available = min_t(unsigned int, PAGE_SIZE - offset,
				  IG_ARGV_MAX_BYTES - cursor.bytes);
		/* No external rendezvous or blocking mmap-lock acquisition. GUP is
		 * sleepable even with NOFAULT; this is not a latency guarantee. */
		if (!mmap_read_trylock(mm))
			return ig_argv_fail(out, -EAGAIN, IG_ARGV_UNKNOWN);
		count = get_user_pages_remote(mm, address & PAGE_MASK, 1,
					      FOLL_NOFAULT | FOLL_NOWAIT, &page,
					      &locked);
		if (locked)
			mmap_read_unlock(mm);
		if (count != 1)
			return ig_argv_fail(out,
					    count < 0 ? (int)count : -EFAULT,
					    IG_ARGV_UNKNOWN);
		mapping = kmap_local_page(page);
		for (i = 0; i < available; i++) {
			copied = ig_argv_append(out, &cursor,
						mapping[offset + i]);
			if (copied)
				break;
		}
		kunmap_local(mapping);
		put_page(page);
		if (copied < 0)
			return ig_argv_fail(out, -E2BIG, IG_ARGV_OVERSIZED);
	}
	out->argc = cursor.argc;
	out->bytes = cursor.bytes;
	out->status = IG_ARGV_KNOWN;
	out->complete = 1;
	return 0;
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ig_argv_kfunc_ids)
BTF_ID_FLAGS(func, ig_capture_pending_argv, KF_SLEEPABLE | KF_TRUSTED_ARGS)
BTF_KFUNCS_END(ig_argv_kfunc_ids)
static const struct btf_kfunc_id_set ig_argv_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &ig_argv_kfunc_ids,
};
static int __init ig_argv_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &ig_argv_kfunc_set);
}
static void __exit ig_argv_exit(void)
{
}
module_init(ig_argv_init);
module_exit(ig_argv_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Isolated AL2023 pending argv observer feasibility kfunc");
