// SPDX-License-Identifier: GPL-2.0
// Unattached staged-evaluator lifecycle probe. Never select as an exec gadget.
#include "evaluator_stage_probe.bpf.c"

SEC("socket") int evaluator_stage_begin_probe(void *unused)
{
	(void)unused;
	fm_u32 zero = 0;
	const struct fe_facts *facts = map_lookup(&stage_facts, &zero);
	struct fe_scratch *scratch = map_lookup(&stage_scratch, &zero);
	struct fe_stage_cursor *cursor = map_lookup(&stage_cursor, &zero);
	if (!facts || !scratch || !cursor)
		return 0;
	return fe_stage_begin(&stage_blobs, facts, scratch, cursor) + 1;
}

SEC("socket") int evaluator_stage_finish_probe(void *unused)
{
	(void)unused;
	fm_u32 zero = 0;
	struct fe_scratch *scratch = map_lookup(&stage_scratch, &zero);
	struct fe_stage_cursor *cursor = map_lookup(&stage_cursor, &zero);
	if (!scratch || !cursor)
		return 0;
	return fe_stage_finish(&stage_blobs, scratch, cursor) + 1;
}
