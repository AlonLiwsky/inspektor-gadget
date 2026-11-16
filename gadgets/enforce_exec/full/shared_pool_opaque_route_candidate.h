/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_ROUTE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_ROUTE_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque route/account adapter is candidate-only"
#endif
#ifndef SE_OC_ROUTE_LOOKUP
#error "provide fixed original-route ARRAY lookup"
#endif
#ifndef SE_OC_AFTER_RECYCLE_ACCOUNT_CHECK
#define SE_OC_AFTER_RECYCLE_ACCOUNT_CHECK() ((void)0)
#endif

/* Include after the actual route and opaque charge headers. A live original-
 * route claim pins the route against withdrawal/recycle while the exact
 * account charges TASK. That account bitmap is the ONLY opaque TASK credit;
 * no second route counter or cross-lock refund is created. The selected
 * image must route every opaque constructor through this adapter and every
 * route recycle through se_oc_route_recycle below. */
static __attribute__((noinline)) int
se_oc_reserve_route_claim(const struct se_route_claim *claim,
			  struct se_oc_reservation *reservation)
{
	if (!claim || !reservation || !claim->owned || claim->reserved ||
	    claim->slot >= SE_OC_ACCOUNTS || reservation->held ||
	    reservation->terminal || reservation->account ||
	    reservation->charge || reservation->meta)
		return SE_OL_CORRUPT;
	__u32 slot = claim->slot;
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	if (!route)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&route->lock);
	int valid = se_route_claim_valid(route, claim);
	/* Neither legacy TASK nor legacy WORK may share this route with the
	 * opaque account. A WORK can outlive its TASK, so checking only the
	 * legacy TASK counter permits a mixed-owner transition. */
	int mixed_or_faulted = route->tasks_used || route->scratch_used ||
			       route->reserved;
	bpf_spin_unlock(&route->lock);
	if (!valid)
		return SE_OL_STALE;
	if (mixed_or_faulted)
		return SE_OL_CORRUPT;
	int result = se_oc_bind_account(slot, claim->scope, claim->incarnation);
	if (result != SE_OL_OK)
		return result;
	return se_oc_reserve_any(slot, claim->scope, claim->incarnation,
				 reservation);
}

/* Route withdrawal blocks new claims; existing claims pin early_claims until
 * their account transactions finish. Thus an exact zero account count is
 * monotonic while the original route remains WITHDRAWN with no claims. Take
 * that account observation outside the route lock, then revalidate the route
 * under its lock before the normal recycle transition. No nested locks and
 * no helper under either lock. A stale/replaced account never authorizes
 * recycling its old route. The selected control path must use this adapter,
 * not se_route_recycle_locked directly. */
static __attribute__((noinline)) int
se_oc_route_recycle(__u32 slot, const struct se_binding_snapshots *snapshots)
{
	if (slot >= SE_OC_ACCOUNTS || !snapshots)
		return SE_OL_CORRUPT;
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	struct se_oc_account *account = SE_OC_ACCOUNT_LOOKUP(slot);
	if (!route || !account)
		return SE_OL_CORRUPT;
	__u64 scope;
	__u32 incarnation;
	bpf_spin_lock(&route->lock);
	int withdraw_ready = route->phase == SE_ROUTE_WITHDRAWN &&
			     !route->early_claims &&
			     route->payload_slot == slot && route->scope &&
			     route->incarnation && !route->reserved;
	scope = route->scope;
	incarnation = route->incarnation;
	bpf_spin_unlock(&route->lock);
	if (!withdraw_ready)
		return SE_OL_STALE;
	bpf_spin_lock(&account->lock);
	int healthy = !account->fault && !account->reserved &&
		      account->used <= SE_OC_QUOTA &&
		      se_oc_bitmap_count(account) == account->used &&
		      ((!account->scope && !account->incarnation) ||
		       (account->scope == scope &&
			account->incarnation == incarnation));
	int occupied = account->used != 0;
	bpf_spin_unlock(&account->lock);
	if (!healthy)
		return SE_OL_CORRUPT;
	if (occupied)
		return SE_OL_CONTENDED;
	SE_OC_AFTER_RECYCLE_ACCOUNT_CHECK();
	bpf_spin_lock(&route->lock);
	int exact = route->phase == SE_ROUTE_WITHDRAWN &&
		    !route->early_claims && route->payload_slot == slot &&
		    route->scope == scope &&
		    route->incarnation == incarnation && !route->reserved;
	int result = exact ? se_route_recycle_locked(route, snapshots) : -1;
	bpf_spin_unlock(&route->lock);
	return result ? SE_OL_STALE : SE_OL_OK;
}
#endif
