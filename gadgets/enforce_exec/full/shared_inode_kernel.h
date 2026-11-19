/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_INODE_KERNEL_H
#define ENFORCE_EXEC_SHARED_INODE_KERNEL_H
#include "shared_inode_facts.h"
#ifndef SE_PROFILE_INODE_FACTS
#error "shared inode pool and quota must be explicit"
#endif
_Static_assert(SE_PROFILE_INODE_FACTS > 0 && SE_PROFILE_INODE_QUOTA > 0 &&
		       (0ULL + SE_PROFILE_BINDINGS) * SE_PROFILE_INODE_QUOTA <=
			       SE_PROFILE_INODE_FACTS,
	       "inode reservations exceed fixed pool");
struct se_inode_account_state {
	struct bpf_spin_lock lock;
	__u32 reserved;
	struct se_inode_quota quota;
	__u64 next_birth;
};
_Static_assert(sizeof(struct se_inode_identity) == 40, "inode identity ABI");
_Static_assert(sizeof(struct se_inode_row) == 48, "inode row ABI");
_Static_assert(sizeof(struct se_inode_account_state) == 48,
	       "inode account ABI");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_PROFILE_INODE_FACTS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct se_inode_row);
} se_inode_facts SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_BINDINGS + 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_inode_account_state);
} se_inode_accounts SEC(".maps");
static inline int se_inode_lookup(__u64 address, struct se_inode_row **row)
{
	*row = bpf_map_lookup_elem(&se_inode_facts, &address);
	return *row ? SE_INODE_OK : SE_INODE_MISSING;
}
static inline int se_inode_account(const struct se_inode_identity *id,
				   struct se_inode_quota **out)
{
	*out = 0;
	if (id->charge_slot > SE_PROFILE_BINDINGS)
		return SE_INODE_INVALID;
	struct se_inode_account_state *a =
		bpf_map_lookup_elem(&se_inode_accounts, &id->charge_slot);
	if (!a)
		return SE_INODE_STORAGE_ERROR;
	if (a->reserved || a->quota.scope_cookie != id->charge_scope_cookie ||
	    a->quota.generation != id->charge_generation)
		return SE_INODE_CONFLICT;
	*out = &a->quota;
	return SE_INODE_OK;
}
static inline int se_inode_insert(const struct se_inode_row *row)
{
	return bpf_map_update_elem(&se_inode_facts,
				   &row->identity.inode_address, row,
				   BPF_NOEXIST) ?
		       SE_INODE_STORAGE_ERROR :
		       SE_INODE_OK;
}
/* Matched final physical death excludes every live-file reader and new birth
 * at this address until return. No administrative deletion/retry exists. This
 * lifetime exclusion, NOT a nonexistent map compare-delete, makes the exact
 * lookup+delete indivisible with respect to another identity for this key. */
static inline int se_inode_delete_exact(const struct se_inode_identity *id)
{
	struct se_inode_row *row =
		bpf_map_lookup_elem(&se_inode_facts, &id->inode_address);
	if (!row)
		return SE_INODE_MISSING;
	if (!se_inode_identity_equal(&row->identity, id))
		return SE_INODE_CONFLICT;
	return bpf_map_delete_elem(&se_inode_facts, &id->inode_address) ?
		       SE_INODE_STORAGE_ERROR :
		       SE_INODE_OK;
}
static __always_inline void
se_inode_route_unref(const struct se_inode_identity *id)
{
	if (id->charge_slot == SE_PROFILE_BINDINGS)
		return; /* permanent unbound account */
	struct se_route_anchor *r =
		bpf_map_lookup_elem(&se_routes, &id->charge_slot);
	if (!r)
		return; /* admitted ARRAY invariant; never invent a refund */
	bpf_spin_lock(&r->lock);
	if (r->scope == id->charge_scope_cookie &&
	    r->incarnation == id->charge_generation && r->inode_refs)
		r->inode_refs--;
	else
		r->inode_reserved = 1;
	bpf_spin_unlock(&r->lock);
}
static __always_inline void se_inode_early_release(struct se_route_claim *claim)
{
	if (!claim->owned)
		return;
	struct se_route_anchor *r =
		bpf_map_lookup_elem(&se_routes, &claim->slot);
	if (!r)
		return;
	bpf_spin_lock(&r->lock);
	se_route_release_locked(r, claim);
	bpf_spin_unlock(&r->lock);
}
/* Birth is called only after the existing decoder authenticated the kernel
 * [memfd] security class, before this newly allocated inode is published. */
static __always_inline void se_fs_mark_memfd(struct inode *inode)
{
	__u64 address = (__u64)inode;
	if (!address)
		return;
	struct se_inode_row *existing =
		bpf_map_lookup_elem(&se_inode_facts, &address);
	if (existing) {
		existing->valid_memfd = 0;
		return;
	} /* stale/collision: never adopt */
	struct se_route_claim claim = {};
	int admission = se_route_admit(bpf_get_current_cgroup_id(), &claim);
	if (admission != SE_ROUTE_OWNED && admission != SE_ROUTE_UNSELECTED)
		return;
	__u32 slot = claim.owned ? claim.slot : SE_PROFILE_BINDINGS;
	struct se_inode_account_state *a =
		bpf_map_lookup_elem(&se_inode_accounts, &slot);
	if (!a) {
		se_inode_early_release(&claim);
		return;
	}
	struct se_inode_identity id = { .inode_address = address,
					.charge_slot = slot };
	if (claim.owned) {
		struct se_route_anchor *r =
			bpf_map_lookup_elem(&se_routes, &slot);
		if (!r) {
			se_inode_early_release(&claim);
			return;
		}
		bpf_spin_lock(&r->lock);
		int invalid = r->scope != claim.scope ||
			      r->incarnation != claim.incarnation ||
			      r->inode_reserved || r->inode_refs == ~0U;
		if (!invalid) {
			if (a->quota.scope_cookie != r->scope ||
			    a->quota.generation != r->incarnation) {
				/* Previous account can be reused only after ALL rows and operations left.
     * The original route incarnation cannot recycle while inode_refs != 0. */
				if (r->inode_refs || a->quota.used)
					invalid = 1;
				else {
					a->quota = (struct se_inode_quota){
						.scope_cookie = r->scope,
						.generation = r->incarnation,
						.limit = SE_PROFILE_INODE_QUOTA
					};
					a->next_birth = 0;
					a->reserved = 0;
				}
			}
			if (!invalid) {
				r->inode_refs++;
				id.charge_scope_cookie = r->scope;
				id.charge_generation = r->incarnation;
			}
		}
		bpf_spin_unlock(&r->lock);
		se_inode_early_release(&claim);
		if (invalid)
			return;
	} else {
		__u32 zero = 0;
		const struct se_node_config *config =
			bpf_map_lookup_elem(&se_configuration, &zero);
		if (!se_profile_matches(config))
			return;
		bpf_spin_lock(&a->lock);
		if (!a->quota.scope_cookie && !a->quota.used)
			a->quota = (struct se_inode_quota){
				.scope_cookie = config->node_cookie,
				.generation = 1,
				.limit = SE_PROFILE_INODE_FACTS -
					 (0ULL + SE_PROFILE_BINDINGS) *
						 SE_PROFILE_INODE_QUOTA
			};
		id.charge_scope_cookie = a->quota.scope_cookie;
		id.charge_generation = a->quota.generation;
		bpf_spin_unlock(&a->lock);
	}
	bpf_spin_lock(&a->lock);
	if (a->next_birth < ~0ULL - 1)
		id.birth_cookie = ++a->next_birth;
	bpf_spin_unlock(&a->lock);
	if (!id.birth_cookie || se_inode_mark_memfd(&id) != SE_INODE_OK)
		se_inode_route_unref(&id);
	/* On success the operation's route ref becomes the retained row's ref,
  * without a zero-count interval. No policy generation is used as account ID. */
}
/* Only the live bprm.file decoder calls this. Its file->dentry->inode reference
 * excludes matched inode_free and address reuse through the LAST lookup. */
static __always_inline int se_fs_known_memfd(struct inode *inode)
{
	__u64 address = (__u64)inode;
	struct se_inode_row *row =
		bpf_map_lookup_elem(&se_inode_facts, &address);
	if (!row || row->valid_memfd != 1)
		return 0;
	__u64 birth = row->identity.birth_cookie;
	struct se_inode_fact fact = {};
	return se_inode_read_memfd(address, birth, &fact) == SE_INODE_OK &&
	       fact.known_memfd && fact.memfd;
}
SEC("lsm/inode_free_security")
int BPF_PROG(se_inode_free, struct inode *inode)
{
	/* Dying argument is identity only: never dereference or acquire it. */
	__u64 address = (__u64)inode;
	struct se_inode_row *row =
		bpf_map_lookup_elem(&se_inode_facts, &address);
	if (!row || row->valid_memfd != 1)
		return 0;
	struct se_inode_identity id = row->identity;
	if (se_inode_retire_dead(&id) == SE_INODE_OK)
		se_inode_route_unref(&id);
	/* Failed delete stays invalid+charged. Later address-only death is NOT a
  * retry receipt and must not refund or delete a different physical inode. */
	return 0;
}
#endif
