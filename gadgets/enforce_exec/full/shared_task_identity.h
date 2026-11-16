/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_TASK_IDENTITY_H
#define ENFORCE_EXEC_SHARED_TASK_IDENTITY_H

/* Include after shared_exec.h. Production storage is a PRIVATE preallocated
 * non-LRU HASH: physical task address u64 -> se_task_state (960 bytes).
 * ZERO_TEMPLATE returns a frozen ARRAY[1] opaque 960-byte ZERO value with no
 * BTF spin-lock field. Never put a 960-byte initializer on the BPF stack or
 * pass a spin-lock-typed map value as a raw update buffer.
 *
 * Birth is called only for an unpublished child in actual task_alloc. The
 * failed child cannot escape the callback; its real lifetime covers LAST use.
 * Death is called only from matched actual task_free, AFTER parent-owned exec
 * abort/reader release. Neither sched_exit nor a native address command is
 * authority to delete. Bootstrap of existing tasks needs a DIFFERENT trusted,
 * serialized admission path; it must not reuse collision-as-birth semantics.
 *
 * The caller proves exclusive birth/death/cleanup on this physical key and a
 * live task reference through LAST borrowed row access. Map helpers NEVER run
 * under row lock. HASH delete is NOT a compare-and-delete: exactness follows
 * from this lifecycle exclusion and the sole authorized writer set, not CAS.
 * Reader ownership uses the route lock; the death checks below are refusal
 * guards AFTER caller quiescence, not synchronization via the wrong row lock.
 *
 * RESERVE(slot,scope,&cookie) succeeds with ONE unique nonwrapping cookie and
 * charge. REFUND(slot,scope,cookie) is synchronous/infallible for that owned
 * tuple: its original fixed account is pinned until LAST refund, including
 * after binding removal. No current-cgroup lookup or fallible lookup after
 * deletion is allowed. Parent owns quotas, cookie allocation and diagnostics.
 * Successful NOEXIST + private non-LRU HASH + key exclusion guarantees lookup
 * remains present. Violation returns FATAL_CHARGED: no false refund/recovery;
 * parent quarantines and retains the orphan reservation until node cleanup.
 */
#define SE_TASK_ID_OK 0
#define SE_TASK_ID_INVALID (-1)
#define SE_TASK_ID_QUOTA (-2)
#define SE_TASK_ID_COLLISION (-3)
#define SE_TASK_ID_INSERT_FAILED (-4)
#define SE_TASK_ID_DELETE_FAILED (-5)
#define SE_TASK_ID_BUSY (-6)
#define SE_TASK_ID_FATAL_CHARGED (-7)
#ifndef SE_TASK_LOOKUP
#define SE_TASK_LOOKUP(key) bpf_map_lookup_elem(&se_tasks, &(key))
#endif
#ifndef SE_TASK_INSERT_NOEXIST
#define SE_TASK_INSERT_NOEXIST(key, zero) \
	bpf_map_update_elem(&se_tasks, &(key), zero, BPF_NOEXIST)
#endif
#ifndef SE_TASK_DELETE
#define SE_TASK_DELETE(key) bpf_map_delete_elem(&se_tasks, &(key))
#endif
#ifndef SE_TASK_ZERO_TEMPLATE
#error "provide the parent-accounted frozen opaque zero ARRAY template"
#endif
#ifndef SE_TASK_RESERVE
#error "provide generation-qualified task quota/cookie reservation"
#endif
#ifndef SE_TASK_REFUND
#error "provide synchronous infallible owned-task refund"
#endif
_Static_assert(sizeof(struct se_task_state) == 960, "task identity wire");

static inline void se_task_quarantine(struct se_task_state *task)
{
	bpf_spin_lock(&task->lock);
	task->flags = (task->flags & ~SE_TASK_LIVE) | SE_TASK_QUARANTINED;
	bpf_spin_unlock(&task->lock);
}
static inline int se_task_birth(__u64 address, __u32 slot, __u64 scope)
{
	if (!address || !scope || scope == ~0ULL)
		return SE_TASK_ID_INVALID;
	struct se_task_state *task = SE_TASK_LOOKUP(address);
	if (task) {
		se_task_quarantine(task);
		return SE_TASK_ID_COLLISION; /* never adopt/relabel an existing row */
	}
	const void *zero_template_value = SE_TASK_ZERO_TEMPLATE();
	if (!zero_template_value)
		return SE_TASK_ID_INVALID;
	__u64 cookie = 0;
	if (SE_TASK_RESERVE(slot, scope, &cookie))
		return SE_TASK_ID_QUOTA;
	if (!cookie || cookie == ~0ULL)
		return SE_TASK_ID_FATAL_CHARGED;
	if (SE_TASK_INSERT_NOEXIST(address, zero_template_value)) {
		SE_TASK_REFUND(slot, scope,
			       cookie); /* only this unsuccessful attempt */
		task = SE_TASK_LOOKUP(address);
		if (task) {
			se_task_quarantine(task);
			return SE_TASK_ID_COLLISION;
		}
		return SE_TASK_ID_INSERT_FAILED;
	}
	task = SE_TASK_LOOKUP(address);
	if (!task)
		return SE_TASK_ID_FATAL_CHARGED;
	/* The zero row is inaccessible as LIVE while its immutable identity is
	 * initialized. This is not qualification or role/ledger bootstrap. */
	bpf_spin_lock(&task->lock);
	task->physical_cookie = cookie;
	task->scope_cookie = scope;
	task->scope_slot = slot;
	task->identity_reserved = 0;
	task->eligibility_version = 1;
	task->flags = SE_TASK_LIVE; /* publish LIVE LAST, never VERIFIED */
	bpf_spin_unlock(&task->lock);
	return SE_TASK_ID_OK;
}
static inline int se_task_death(__u64 address)
{
	if (!address)
		return SE_TASK_ID_INVALID;
	struct se_task_state *task = SE_TASK_LOOKUP(address);
	if (!task)
		return SE_TASK_ID_OK; /* no record/charge owned for this death */
	bpf_spin_lock(&task->lock);
	task->flags = (task->flags & ~SE_TASK_LIVE) | SE_TASK_QUARANTINED;
	if (task->exec.owned || task->reader.owned || task->reader_invocation) {
		bpf_spin_unlock(&task->lock);
		return SE_TASK_ID_BUSY;
	}
	/* Copy BEFORE deletion. No row pointer is read after the unlock below. */
	__u64 cookie = task->physical_cookie, scope = task->scope_cookie;
	__u32 slot = task->scope_slot, reserved = task->identity_reserved;
	bpf_spin_unlock(&task->lock);
	if (!cookie || cookie == ~0ULL || !scope || scope == ~0ULL || reserved)
		return SE_TASK_ID_FATAL_CHARGED;
	if (SE_TASK_DELETE(address))
		return SE_TASK_ID_DELETE_FAILED; /* quarantined row stays charged */
	SE_TASK_REFUND(slot, scope, cookie);
	return SE_TASK_ID_OK;
}
#endif
