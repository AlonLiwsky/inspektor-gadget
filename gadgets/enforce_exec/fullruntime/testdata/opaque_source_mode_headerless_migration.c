/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Actual route-helper counterexample, not a physical-source implementation.
 * Source-header insertion failed, so the original lexical claim can only
 * latch its route. A later same-exec callback has migrated to another cgroup
 * and has neither a source header nor a reader receipt. This is the current
 * route fallback in real_owner_reader_begin_core, not authority to reconstruct
 * the original class. Do not make this pass by changing ordinary admission:
 * unrelated fresh execs must still use their selected route's class. */
#define ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE 1
#define SE_OC_ACCOUNTS 2
#define SE_OL_TASKS 8
#define main opaque_locator_fixture_main
#include "../../full/test/host/opaque_locator_candidate.c"
#undef main

static struct se_route_claim admit(__u32 slot)
{
	struct se_route_claim claim = {};
	struct se_route_anchor *route = &routes[slot];
	bpf_spin_lock(&route->lock);
	assert(se_route_claim_locked(route, se_route_locator(slot, 1),
				     route->cgroup_identity,
				     &claim) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&route->lock);
	return claim;
}

static void release(struct se_route_claim *claim)
{
	struct se_route_anchor *route = &routes[claim->slot];
	bpf_spin_lock(&route->lock);
	assert(!se_route_release_locked(route, claim));
	bpf_spin_unlock(&route->lock);
}

int main(int argc, char **argv)
{
	assert(argc == 3);
	__u32 original = !strcmp(argv[2], "audit") ? 1 : 2;
	assert(original == 1 || !strcmp(argv[2], "strict"));
	int migrated = !strcmp(argv[1], "headerless-migrated");
	assert(migrated || !strcmp(argv[1], "headerless-same-scope"));
	for (__u32 slot = 0; slot < 2; slot++) {
		routes[slot] = (struct se_route_anchor){
			.incarnation = 1,
			.cgroup_identity = 7 + slot,
			.scope = 10 + slot,
			.payload_generation = 13,
			.active_serial = 1,
			.payload_slot = slot,
			.execution_class = slot ? (original == 1 ? 2 : 1) :
						  original,
			.phase = SE_ROUTE_ACTIVE,
		};
	}
	struct se_route_claim first = admit(0);
	/* Exercise the actual proposed fallback for failed source-header
	 * insertion. No source owner or token was published and no test-side
	 * replacement is supplied to the later admission. */
	bpf_spin_lock(&routes[0].lock);
	assert(!se_route_source_latch_locked(&routes[0], &first));
	bpf_spin_unlock(&routes[0].lock);
	release(&first);
	assert(routes[0].unresolved_sources == 1);
	assert(!routes[0].source_pins && !routes[0].early_claims);
	struct se_route_anchor original_before = routes[0];
	struct se_route_claim later = admit(migrated ? 1 : 0);
	__u32 observed = later.execution_class;
	release(&later);
	assert(routes[0].unresolved_sources == 1);
	assert(!held && !lock_errors);
	if (migrated)
		assert(!memcmp(&original_before, &routes[0],
			       sizeof(original_before)));
	if (observed != original) {
		fprintf(stderr,
			"RED: source-header insertion failure plus cgroup "
			"migration lost original class=%u; current-route fallback "
			"class=%u (%s) while original route remains latched\n",
			original, observed,
			original == 1 ? "Audit can be blocked" :
					"Strict can be allowed");
		return 1;
	}
	assert(observed == original);
	puts("headerless original-source class contract: PASS");
	return 0;
}
