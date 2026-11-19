/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ENFORCE_EXEC_SHARED_INODE_FACTS_H
#define ENFORCE_EXEC_SHARED_INODE_FACTS_H

/* Positive MEMFD evidence only. This helper does NOT authenticate inode birth,
 * death, or the kernel's MEMFD security class. The adapter must do so.
 *
 * Adapter contract:
 * - fixed preallocated rows/accounts; serialize an inode address through the
 *   LAST callback/row access of each operation, including failed-delete retries;
 * - do NOT hold a BPF spin lock across map helpers: this header supplies neither
 *   that illegal locking strategy nor an implemented kernel serialization seam;
 * - lookup pointers remain stable through the operation; insert is NOEXIST;
 * - delete_exact checks the entire identity atomically with removal. Only OK
 *   means definitively removed; any uncertainty retains the invalid charged row;
 * - account identity/limit stay pinned through the operation and while charged.
 *   Binding removal marks the account retired, never reuses its slot/generation
 *   until all rows/operations retire. Refund targets the ORIGINAL account;
 *   retired is atomically published; already-admitted pinned operations may
 *   finish charging after retirement, so used==0 alone cannot authorize reuse;
 * - reads hold a live bprm.file and an authenticated matching birth cookie;
 * - retirement proves matched physical inode death, not binding removal, an
 *   address-only event, a guessed cookie, or an RCU-delay credit timer.
 * These obligations are not discharged by the userspace actual-header tests.
 */
#define SE_INODE_OK 0
#define SE_INODE_MISSING 1
#define SE_INODE_CONFLICT 2
#define SE_INODE_STORAGE_ERROR (-1)
#define SE_INODE_QUOTA_ERROR (-2)
#define SE_INODE_INVALID (-3)

struct se_inode_identity {
	__u64 inode_address, birth_cookie, charge_scope_cookie,
		charge_generation;
	__u32 charge_slot, reserved;
};
struct se_inode_row {
	struct se_inode_identity identity;
	__u32 valid_memfd;
};
struct se_inode_quota {
	__u64 scope_cookie, generation;
	__u32 limit, used, retired;
};
struct se_inode_fact {
	__u32 known_memfd, memfd;
};

/* Callback domains: lookup/account => OK, MISSING, STORAGE_ERROR;
 * insert => OK, CONFLICT, STORAGE_ERROR;
 * delete => OK, MISSING, CONFLICT, STORAGE_ERROR. Non-OK never refunds a row.
 * Failure of insert must mean this attempt inserted NO row; ambiguous storage
 * outcomes need adapter reconciliation before returning to this helper.
 */
static inline int se_inode_lookup(__u64 address, struct se_inode_row **row);
static inline int se_inode_insert(const struct se_inode_row *row);
static inline int
se_inode_delete_exact(const struct se_inode_identity *identity);
static inline int se_inode_account(const struct se_inode_identity *identity,
				   struct se_inode_quota **account);

static inline int se_inode_identity_valid(const struct se_inode_identity *i)
{
	return !i->reserved && i->inode_address && i->birth_cookie &&
	       i->birth_cookie != ~0ULL && i->charge_scope_cookie &&
	       i->charge_scope_cookie != ~0ULL && i->charge_generation &&
	       i->charge_generation != ~0ULL;
}
static inline int se_inode_identity_equal(const struct se_inode_identity *a,
					  const struct se_inode_identity *b)
{
	return a->inode_address == b->inode_address &&
	       a->birth_cookie == b->birth_cookie &&
	       a->charge_scope_cookie == b->charge_scope_cookie &&
	       a->charge_generation == b->charge_generation &&
	       a->charge_slot == b->charge_slot && a->reserved == b->reserved;
}
static inline int se_inode_quota_matches(const struct se_inode_quota *q,
					 const struct se_inode_identity *i)
{
	return q && q->scope_cookie == i->charge_scope_cookie &&
	       q->generation == i->charge_generation;
}
static inline int se_inode_charge(struct se_inode_quota *q)
{
	if (__sync_fetch_and_add(&q->retired, 0) || !q->limit)
		return SE_INODE_QUOTA_ERROR;
	for (int attempt = 0; attempt < 64; attempt++) {
		__u32 used = __sync_fetch_and_add(&q->used, 0);
		if (used >= q->limit)
			break;
		if (__sync_val_compare_and_swap(&q->used, used, used + 1) ==
		    used)
			return SE_INODE_OK;
	}
	return SE_INODE_QUOTA_ERROR;
}
/* The caller owns precisely one charge and pins account identity. No competing
 * operation may refund that charge. Other independent refunds are atomic. */
static inline void se_inode_refund(struct se_inode_quota *q)
{
	__sync_fetch_and_sub(&q->used, 1);
}

/* Invoke ONLY for authenticated positive MEMFD creation evidence. A duplicate
 * exact record consumes no credit; a collision cannot adopt another charge. */
static inline int se_inode_mark_memfd(const struct se_inode_identity *identity)
{
	if (!se_inode_identity_valid(identity))
		return SE_INODE_INVALID;
	struct se_inode_row *existing = 0;
	int result = se_inode_lookup(identity->inode_address, &existing);
	if (result == SE_INODE_OK) {
		if (!existing ||
		    !se_inode_identity_equal(&existing->identity, identity))
			return SE_INODE_CONFLICT;
		return existing->valid_memfd == 1 ? SE_INODE_OK :
						    SE_INODE_INVALID;
	}
	if (result != SE_INODE_MISSING)
		return result;
	struct se_inode_quota *q = 0;
	result = se_inode_account(identity, &q);
	if (result != SE_INODE_OK)
		return result;
	if (!se_inode_quota_matches(q, identity))
		return SE_INODE_CONFLICT;
	result = se_inode_charge(q);
	if (result != SE_INODE_OK)
		return result;
	struct se_inode_row row = { .identity = *identity, .valid_memfd = 1 };
	result = se_inode_insert(&row);
	if (result != SE_INODE_OK)
		se_inode_refund(
			q); /* this failed attempt only, not an existing row */
	return result;
}

/* Ownership is not transferred when another binding executes the same file.
 * A positive physical fact can be read while its original account is retired. */
static inline int se_inode_read_memfd(__u64 address, __u64 birth_cookie,
				      struct se_inode_fact *out)
{
	*out = (struct se_inode_fact){};
	if (!address || !birth_cookie || birth_cookie == ~0ULL)
		return SE_INODE_INVALID;
	struct se_inode_row *row = 0;
	int result = se_inode_lookup(address, &row);
	if (result != SE_INODE_OK)
		return result;
	if (!row || !se_inode_identity_valid(&row->identity) ||
	    row->identity.inode_address != address ||
	    row->identity.birth_cookie != birth_cookie)
		return SE_INODE_CONFLICT;
	if (row->valid_memfd != 1)
		return SE_INODE_INVALID;
	*out = (struct se_inode_fact){ .known_memfd = 1, .memfd = 1 };
	return SE_INODE_OK;
}

/* The adapter, not this function, authenticates death. Invalidate BEFORE any
 * fallible cleanup, and refund only the exact successfully removed row. */
static inline int se_inode_retire_dead(const struct se_inode_identity *identity)
{
	if (!se_inode_identity_valid(identity))
		return SE_INODE_INVALID;
	struct se_inode_row *row = 0;
	int result = se_inode_lookup(identity->inode_address, &row);
	if (result != SE_INODE_OK)
		return result;
	if (!row || !se_inode_identity_equal(&row->identity, identity))
		return SE_INODE_CONFLICT;
	row->valid_memfd = 0;
	struct se_inode_quota *q = 0;
	result = se_inode_account(identity, &q);
	if (result != SE_INODE_OK)
		return result;
	if (!se_inode_quota_matches(q, identity) ||
	    !__sync_fetch_and_add(&q->used, 0))
		return SE_INODE_CONFLICT;
	result = se_inode_delete_exact(identity);
	if (result == SE_INODE_OK)
		se_inode_refund(q);
	return result;
}
#endif
