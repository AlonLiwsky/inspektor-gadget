/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_REAL_CONTROL_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_REAL_CONTROL_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE) || \
	!defined(ENFORCE_EXEC_ABI3_DEVELOPMENT) ||          \
	!defined(FULL_EPOCH_ROLES_H)
#error "real-control opaque owner requires the explicit candidate and epoch wire"
#endif
#if !defined(SE_PROFILE_BINDINGS) || !defined(SE_PROFILE_TASKS) ||         \
	!defined(SE_PROFILE_TASK_QUOTA) || !defined(SE_PROFILE_SCRATCH) || \
	!defined(SE_PROFILE_SCRATCH_QUOTA)
#error "real-control opaque owner requires explicit TASK/WORK profile"
#endif
#if !defined(SE_CATALOGUE_FROM_BANK) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_ROUTE_ADMISSION_PROBE)
#error "real-control opaque owner requires map-backed catalogue; the admission probe is not an enforcement image"
#endif
/* One original route/binding/control cohort and one opaque TASK/WORK owner.
 * This is only a composition adapter: callers must still provide real source
 * callbacks, publication, cleanup, native admission and a complete Ready
 * proof. Never select the admission probe as an enforcement image. */
#define SE_OL_TASKS SE_PROFILE_TASKS
#define SE_OC_ACCOUNTS SE_PROFILE_BINDINGS
#define SE_OC_QUOTA SE_PROFILE_TASK_QUOTA
#define SE_OWK_ACCOUNTS SE_PROFILE_BINDINGS
#define SE_OWK_QUOTA SE_PROFILE_SCRATCH_QUOTA
#define SE_OWK_WORKS SE_PROFILE_SCRATCH
_Static_assert(SE_PROFILE_BINDINGS == SE_OC_ACCOUNTS &&
		       SE_PROFILE_TASKS == SE_OL_TASKS &&
		       SE_PROFILE_TASK_QUOTA == SE_OC_QUOTA &&
		       SE_PROFILE_SCRATCH == SE_OWK_WORKS &&
		       SE_PROFILE_SCRATCH_QUOTA == SE_OWK_QUOTA,
	       "real-control opaque owner must match the shared profile");

struct se_route_anchor;
static inline const __u64 *se_opaque_real_route_index(const __u64 *);
static inline struct se_route_anchor *
se_opaque_real_route_anchor(const __u32 *);
#define SE_ROUTE_CAPACITY SE_PROFILE_BINDINGS
#define SE_ROUTE_INDEX_LOOKUP(key) se_opaque_real_route_index(key)
#define SE_ROUTE_ANCHOR_LOOKUP(key) se_opaque_real_route_anchor(key)
#include "shared_pool_opaque_core_candidate.h"
#include "shared_control.h"
#include "shared_pool_opaque_exec_reader_candidate.h"
#include "shared_policy_physical_kernel.h"
#include "shared_publication_arm.h"
#include "shared_pool_opaque_accessors_candidate.h"

static inline const __u64 *se_opaque_real_route_index(const __u64 *key)
{
	return bpf_map_lookup_elem(&se_route_index, key);
}
static inline struct se_route_anchor *
se_opaque_real_route_anchor(const __u32 *key)
{
	return bpf_map_lookup_elem(&se_routes, key);
}
static struct se_route_anchor *route_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&se_routes, &slot);
}
#endif
