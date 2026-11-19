/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POLICY_PREPARE_H
#define ENFORCE_EXEC_SHARED_POLICY_PREPARE_H
#ifndef SE_OBJECT_LOOKUP
#error "policy preparation requires the selected fixed-object lookup"
#endif

/* Build a retained snapshot view in caller-owned WORK storage. This has no
 * TASK or WORK allocation authority: the caller must hold the exact reader
 * and WORK ticket through its last use of the view. Include after the shared
 * control maps and shared_policy_lookup.h. */
static __always_inline int
se_prepare_policy_view(struct se_policy_view *view, __u64 scope,
		       const struct se_snapshot *snapshot, __u64 generation)
{
	if (!view)
		return -1;
	/* Re-preparation failure cannot leave an earlier WORK view usable. */
	view->ready = 0;
	/* The view owns these refs for the complete WORK lifetime. Use its fixed
	 * storage as the prepare input as well: se_policy_prepare copies each
	 * ref to the same index only after reading it, avoiding a 192-byte BPF
	 * stack array on the attached exec path. */
	struct se_policy_ref *refs = view->refs;
	/* A retained reader may observe RETIRING after admission, but a record
	 * without its exact scope/generation and live claim is not a source. */
	if (!snapshot || snapshot->scope != scope ||
	    snapshot->generation != generation || !snapshot->serial ||
	    !snapshot->claims ||
	    (snapshot->phase != SE_SNAPSHOT_ACTIVE &&
	     snapshot->phase != SE_SNAPSHOT_RETIRING) ||
	    snapshot->count > 8 || !snapshot->count ||
	    !se_snapshot_metadata_valid(&snapshot->metadata, snapshot->count,
					generation))
		return -1;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= snapshot->count)
			break;
		const struct se_pin_ticket *ticket = &snapshot->tickets[i];
		if (ticket->phase != SE_TICKET_HELD || ticket->scope != scope ||
		    ticket->snapshot_serial != snapshot->serial ||
		    ticket->position != i)
			return -1;
		__u32 slot = ticket->object_slot;
		const struct se_shared_object *object = SE_OBJECT_LOOKUP(&slot);
		if (!object ||
		    object->state.generation != ticket->object_generation ||
		    !object->state.pins)
			return -1;
		refs[i] = (struct se_policy_ref){
			.generation = ticket->object_generation,
			.root_epoch = snapshot->metadata.root_epochs[i],
			.slot = slot,
			.entries = object->state.length
		};
	}
	if (se_policy_prepare(view, 0, scope, generation,
			      (const struct fe_string *)&snapshot->metadata
				      .container_length,
			      refs, snapshot->count))
		return -1;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= snapshot->count)
			break;
		if (view->policies[i].uid !=
		    snapshot->metadata.policy_uids[i]) {
			view->ready = 0;
			return -1;
		}
	}
	return 0;
}
#endif
