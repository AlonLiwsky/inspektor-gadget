/* SPDX-License-Identifier: GPL-2.0 */
/* Caller serializes this transaction with its task-state lock. */
#ifndef FULL_TRANSACTION_H
#define FULL_TRANSACTION_H
struct fr_transaction {
	__u64 bprm, cgroup, generation;
	__u32 slot, owned, suppress, checks;
	struct fr_entry pending[FR_ACTIVE];
};
static __always_inline int fr_propose(struct fr_transaction *tx, __u64 uid,
				      __u64 roles)
{
	if (!uid || !roles)
		return 0;
#pragma clang loop unroll(disable)
	for (int i = 0; i < FR_ACTIVE; i++) {
		if (tx->pending[i].uid == uid) {
			if (tx->pending[i].roles != roles) {
				tx->suppress = 1;
				return -1;
			}
			return 0;
		}
		if (!tx->pending[i].uid) {
			tx->pending[i].uid = uid;
			tx->pending[i].roles = roles;
			return 0;
		}
	}
	tx->suppress = 1;
	return -1;
}
/* Clear pending before count release, including denied/audit execs. */
static __always_inline void fr_clear_pending(struct fr_transaction *tx)
{
#pragma clang loop unroll(disable)
	for (int i = 0; i < FR_ACTIVE; i++) {
		tx->pending[i].uid = 0;
		tx->pending[i].roles = 0;
	}
}
#endif
