/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POLICY_PHYSICAL_KERNEL_H
#define ENFORCE_EXEC_SHARED_POLICY_PHYSICAL_KERNEL_H
#ifndef ENFORCE_EXEC_SHARED_CONTROL_H
#error "physical policy lookup requires fixed shared control maps"
#endif
#ifndef ENFORCE_EXEC_SHARED_POLICY_LOOKUP_H
#error "physical policy lookup requires the shared policy view"
#endif
/* The caller retains the exact HELD snapshot ticket and reader/early claim
 * through its last use. This resolver only checks immutable fixed-object
 * identity and bounds; it does not acquire that authority. */
static inline const struct fm_blob *
se_policy_physical(void *context, fm_u32 slot, fm_u64 generation, fm_u32 key)
{
	if (context || slot >= SE_PROFILE_OBJECTS)
		return 0;
	const struct se_shared_object *object =
		bpf_map_lookup_elem(&se_objects, &slot);
	if (!object || object->state.generation != generation ||
	    !object->state.pins ||
	    (object->state.phase != SE_OBJECT_READY &&
	     object->state.phase != SE_OBJECT_RETIRING) ||
	    key >= object->state.length)
		return 0;
	const struct se_node_config *config;
	__u32 zero = 0, kind = 0, base = 0;
	config = bpf_map_lookup_elem(&se_configuration, &zero);
	if (!se_profile_matches(config) ||
	    se_object_range(config, slot, &kind, &base) ||
	    key >= se_object_capacity(kind))
		return 0;
	__u32 at = base + key;
	return bpf_map_lookup_elem(&se_arena, &at);
}
#endif
