// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestProductPublisherSourcePins pins the G019 M4 product publisher's BPF
// source (ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE):
//   - B1: the adoption marker extends only the source-pinned route (104 ->
//     112 B, pinned in the product header), the protocol (88 B) and
//     non-product layouts are unchanged; while adopting, both claim paths
//     fault (Strict deny, Audit allow) and count the attempt, saturating;
//   - B2: every product command authenticates through one helper: the
//     compiled profile, the caller's se_admin nonce, the request's nonce and
//     node cookie, and a strictly increasing sequence consumed exactly once
//     (compare-and-swap) in the product receipt map; a refusal changes
//     nothing; no se_command, se_commands or se_receipts dependency.
func TestProductPublisherSourcePins(t *testing.T) {
	read := func(path string) string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	route := squashSpace(read("../full/shared_route.h"))
	verdict := squashSpace(read("bpf/opaque_real_owner_child_candidate.bpf.c"))
	header := read("bpf/opaque_real_owner_product_publisher.h")
	product := squashSpace(header)
	snapshotSrc := squashSpace(read("../full/shared_snapshot.h"))
	for _, pin := range []struct{ name, source, text string }{
		// Revision deadlock fix (step 0): a committed revision drops the
		// previous (RETIRING) record at once, best effort, so its object
		// unpins without waiting for the slot's next revision; a record with
		// reader claims is never dropped (drop and RELEASE both check).
		{
			"revision drops the previous record after commit", product,
			"(void)real_owner_snapshot_drop(slot, record ^ 1);\n\treturn OPAQUE_REAL_CMD_OK;\nundo:\n\tif (epoch == 1)",
		},
		// G019 gap 3: readers and the record's route holders, checked
		// under the route lock before any ticket release (1: holders
		// remain, retryable).
		{"drop refuses a held record", product, "__u32 held = s->claims || se_route_rec_held(route, record);"},
		// The binding's catalogue is write-once per (scope, UID) (G019 gap
		// 3: a RETIRING reader evaluates against it after a commit).
		{"epoch cell accepts only an equal epoch", product, "(cell->epoch == 0 || cell->epoch == epoch);"},
		{"commit preflight checks the epoch cell", product, "!real_owner_epoch_cell_ready(cell, route->scope, uid, epoch) ||"},
		{"epoch index inserted once", product, "if (bpf_map_update_elem(&se_epoch_index, &key, &bank, BPF_NOEXIST)) {\n" +
			"\t\thave = bpf_map_lookup_elem(&se_epoch_index, &key);\n\t\treturn have && *have == bank ? 0 : -1;"},
		{"cells cleared only with both records FREE", product, "int clear = route->phase == SE_ROUTE_FREE && !route->early_claims &&\n" +
			"\t\t    !b->records[0].phase && !b->records[1].phase &&"},
		{"revision keeps the root epoch", product, "__u64 active_epoch = b->records[b->active_record & 1]\n\t\t\t\t\t     .metadata.root_epochs[0];\n" +
			"\t\tif (active_uid != request_uid ||\n\t\t    active_epoch != request_epoch ||\n" +
			"\t\t    route->execution_class != r->execution_class) {"},
		// pub-load: a load through ctx+offsetof(metadata) is refused
		// ("dereference of modified ctx ptr"): every metadata copy and the
		// revision's identity reads are fixed-offset loads on a fresh copy
		// of the ctx register.
		{"ctx loads on the unmodified ctx", product, "const struct opaque_real_route_publish_request *c = r;\n" +
			"\tasm volatile(\"\" : \"+r\"(c));\n\treturn *(const __u64 *)((const char *)c + offset);"},
		{"first publication copies the metadata by words", product, "real_owner_metadata_copy_locked(&b->records[0].metadata, r);"},
		{"revision copies the metadata by words", product, "real_owner_metadata_copy_locked(&candidate->metadata, r);"},
		{"revision reads its identity once", product, "__u64 request_uid = REAL_OWNER_REQUEST_UID(r);\n\t__u64 request_epoch = REAL_OWNER_REQUEST_EPOCH(r);"},
		{"drop reports holders", product, "if (phase != SE_SNAPSHOT_RETIRING || count != 1)\n\t\treturn -1;\n\tif (held)\n\t\treturn 1;"},
		{
			"RELEASE refuses a held record", snapshotSrc,
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n" +
				"\tif (kind == SE_COMMAND_RELEASE && s->claims)\n\t\treturn -1;\n#endif\n\ts->commands = 1;",
		},
		{"route marker fields", route, "finish requires to be 0. Both under the route lock. */\n" +
			"\t__u32 adopting, adopting_faults;\n\t/* G019 gap 3: holders per snapshot record (se_route_rec). */\n" +
			"\tstruct se_route_rec rec[2];\n#endif\n};"},
		{
			"marker only on the source-pinned route", route,
			"#if defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) && \\\n" +
				"\t!defined(ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE)\n" +
				"#error \"the product publisher's route marker extends the source-pinned route\"\n#endif",
		},
		{
			"claim faults while adopting", route,
			"return SE_ROUTE_INVARIANT_FAULT; /* inadmissible class invariant violation */\n" +
				"#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n" +
				"\t/* Adoption in progress: no fork or exec of this cgroup is admitted, and\n" +
				"\t * each attempt fails the adoption (saturating: it never wraps to 0). */\n" +
				"\tif (a->adopting) {\n\t\tif (a->adopting_faults != (__u32)~0U)\n\t\t\ta->adopting_faults++;\n" +
				"\t\treturn a->execution_class == 1 ? SE_ROUTE_AUDIT_FAULT :\n\t\t\t\t\t\t SE_ROUTE_STRICT_FAULT;\n\t}\n#endif\n" +
				"\tif (c->owned || a->reserved",
		},
		{
			"source claim faults while adopting", route,
			"\t * pins); a pinned claim during adoption is a fault all the same. */\n" +
				"\tif (a->adopting) {\n\t\tif (a->adopting_faults != (__u32)~0U)\n\t\t\ta->adopting_faults++;\n" +
				"\t\treturn frozen_class == 1 ? SE_ROUTE_AUDIT_FAULT :\n\t\t\t\t\t   SE_ROUTE_STRICT_FAULT;\n\t}\n#endif\n" +
				"\tconst struct se_source_mode_token *t = &owner->token;",
		},
		{
			"product composition", verdict,
			"#if defined(ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE) && \\\n" +
				"\t(!defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE) || \\\n" +
				"\t !defined(ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE) || \\\n" +
				"\t !defined(ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE) || \\\n" +
				"\t !defined(ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE))\n#error",
		},
		{
			"header included last", verdict,
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n" +
				"#include \"opaque_real_owner_product_publisher.h\"\n#endif\n" +
				"char LICENSE[] SEC(\"license\") = \"GPL\";",
		},
		{
			"product anchor size", product,
			"_Static_assert(sizeof(struct se_route_anchor) == 176,",
		},
		{
			"authentication", product,
			"if (!h || !se_profile_matches(config) || !receipt ||\n" +
				"\t    h->node_cookie != config->node_cookie || !h->sequence ||\n" +
				"\t    h->sequence == ~0ULL)\n\t\treturn 0;\n" +
				"#ifdef ENFORCE_EXEC_SHARED_RECOVERY\n\tif (!se_rm_command_authorized(config->node_cookie))\n\t\treturn 0;\n#else\n" +
				"\tconst __u64 *admin = SE_ADMIN_LOOKUP();\n" +
				"\tif (!admin || *admin != config->nonce || h->nonce != config->nonce)\n\t\treturn 0;\n#endif\n" +
				"\t__u64 node = receipt->node_cookie, seen = receipt->sequence;\n" +
				"\tif ((node && node != config->node_cookie) || h->sequence <= seen ||\n" +
				"\t    __sync_val_compare_and_swap(&receipt->sequence, seen,\n\t\t\t\t\th->sequence) != seen)\n\t\treturn 0;",
		},
		{
			"receipt map", product,
			"__uint(type, BPF_MAP_TYPE_ARRAY);\n\t__uint(max_entries, 1);\n\t__uint(map_flags, BPF_F_RDONLY);\n" +
				"\t__type(key, __u32);\n\t__type(value, struct opaque_real_cmd_receipt);\n} opaque_real_cmd_receipt SEC(\".maps\");",
		},
		{
			"return codes", product,
			"#define OPAQUE_REAL_CMD_OK 0\n#define OPAQUE_REAL_CMD_RETRY 1",
		},
	} {
		if !strings.Contains(pin.source, squashSpace(pin.text)) {
			t.Errorf("%s: pin missing: %q", pin.name, pin.text)
		}
	}
	// B3-B5 pins.
	for _, pin := range []struct{ name, text string }{
		{"stage size class from the profile", "if (!config || r->reserved || slot >= config->objects ||\n" +
			"\t    se_object_range(config, slot, &size_class, &base))"},
		{"first publication sets the marker in the commit block", "se_route_commit_publish_locked(route, b, real_owner_record(record));\n" +
			"\tif (first) {\n\t\troute->adopting = 1;\n\t\troute->adopting_faults = 0;\n\t}"},
		{"revision only when not adopting", "route->payload_slot != r->slot || route->adopting != 0 ||"},
		{"recycle through the WORK-aware adapter", "int result = se_owk_route_recycle(slot, &binding->state);"},
		{"recycle clears the marker on the FREE route", "int clear = route->phase == SE_ROUTE_FREE && !route->early_claims &&\n" +
			"\t\t    !b->records[0].phase && !b->records[1].phase &&\n\t\t    !b->active_serial && !b->inflight;\n" +
			"\tif (clear) {\n\t\troute->adopting = 0;\n\t\troute->adopting_faults = 0;"},
		// L-2/L-3: a FREE route only repeats the idempotent cleanup; a
		// cleanup that cannot run is its own code, never success.
		{"recycle idempotent on FREE", "if (!free) {\n\t\tint result = se_owk_route_recycle(slot, &binding->state);"},
		{"recycle unclean code", "return real_owner_recycle_clean(slot) ? OPAQUE_REAL_RECYCLE_UNCLEAN :\n\t\t\t\t\t\tOPAQUE_REAL_CMD_OK;"},
		{"cleanup uses the publication's scope", "scope = state->scope;"},
		{"css iterator flags 0", "bpf_iter_css_task_new(&it, &group->self, 0) == 0;"},
		{"identity in clock ticks", "#define OPAQUE_REAL_TICK_NS (1000000000ULL / 100) /* USER_HZ */"},
		{"identity refuses exiting tasks", "(flags & OPAQUE_REAL_PF_EXITING) ||\n" +
			"\t    BPF_CORE_READ_INTO(&cgroup, task, cgroups, dfl_cgrp, kn, id) ||"},
		{"leader start ticks", "start / OPAQUE_REAL_TICK_NS != state->init_start_ticks)"},
		{"the adoption claim requires the marker", "if (a->phase == SE_ROUTE_ACTIVE && a->adopting == 1 &&"},
		{"qualify mirrors the birth checks", "if (!owner.lease.meta->cleanup_error && directory &&\n" +
			"\t\t    *directory == owner.lease.locator &&\n\t\t    t->physical_cookie == owner.lease.cookie &&\n" +
			"\t\t    t->flags == SE_TASK_LIVE && t->scope_cookie == scope &&\n" +
			"\t\t    t->scope_slot == slot && t->committed.version &&\n" +
			"\t\t    !t->exec.owned && !t->reader.owned && !t->next_invocation) {"},
		{"unrecordable adopted TASK is quarantined", "(void)real_owner_birth_quarantine((__u64)task, cookie,\n\t\t\t\t\t\t\t  locator);"},
		{"finish: exact set, locator, nobody exiting", "if (unreadable || (flags & OPAQUE_REAL_PF_EXITING) || !want ||\n" +
			"\t\t    !have || *have != want->locator)"},
		{"finish: count rule", "if (!started || state->bad || !state->iterated ||\n\t    state->iterated != state->adopted || !state->scope) {"},
		// H1: the binding's root anchor is recorded before adopting clears.
		{"finish: root anchor", "root->scope = state->scope;\n\tbpf_spin_lock(&state->lock);\n\t__u32 incarnation = state->incarnation;"},
		{"finish: no faulted claim, then the marker cleared", "!route->adopting_faults && route->incarnation == incarnation &&"},
		// Code 4: last_cgroup is never cleared (recycle keeps it).
		{"code 4 on any binding's last cgroup", "if (!state || state->last_cgroup == cgroup)\n\t\t\treturn 1;"},
		// Undo paths (first publication): locator only if ours, the epoch
		// index only if created here, the candidate aborted, then FREE.
		{"undo: locator", "if (indexed) {\n\t\tconst __u64 *have = bpf_map_lookup_elem(&se_route_index, &cgroup);\n" +
			"\t\tif (have && *have == locator)\n\t\t\tbpf_map_delete_elem(&se_route_index, &cgroup);\n\t}"},
		{"undo: epoch index", "if (epoch == 1)\n\t\tse_arm_rollback_one(scope, r->metadata.policy_uids[0], 1, cell);"},
		{"undo: candidate", "if (real_owner_snapshot_abort(slot, record, serial))\n\t\treturn OPAQUE_REAL_CMD_INVARIANT;"},
		{"undo: open", "if (reopened) {\n\t\treal_owner_binding_clear_locked(b);\n\t\troute->cgroup_identity = 0;\n" +
			"\t\troute->scope = 0;\n\t\troute->payload_slot = 0;\n\t\troute->phase = SE_ROUTE_FREE;\n\t}"},
		{"revision undo keeps last-good", "return real_owner_snapshot_abort(slot, record, serial) ?\n" +
			"\t\t       OPAQUE_REAL_CMD_INVARIANT :\n\t\t       code;"},
		// The VM injector's three points, diagnostic only.
		{"injector refused in the product", "#if defined(SE_PRODUCT_NO_TEST_RUN) && !defined(SE_PRODUCT_DIAGNOSTIC_TWIN)\n" +
			"#error \"the publication fault injector is diagnostic only\"\n#endif"},
		{"init role is the staged object's root role", "return p && uid && role && p->uid == uid && p->root_role == role &&\n" +
			"\t       !p->root_epoch && p->mode == execution_class;"},
		{"revision keeps the policy UID (L-6), the root epoch and the class", "__u64 active_uid =\n" +
			"\t\t\tb->records[b->active_record & 1].metadata.policy_uids[0];\n"},
		{"init role checked after pin and seal", "if (!real_owner_root_role_matches(r->object_slot, r->object_generation,\n" +
			"\t\t\t\t\t  r->metadata.policy_uids[0],\n\t\t\t\t\t  r->init_role, r->execution_class)) {\n" +
			"\t\tcode = OPAQUE_REAL_CMD_REFUSED;\n\t\tgoto undo;\n\t}"},
		{"injector: pin and seal", "r->execution_class) ||\n\t    SE_PUBLISH_FAULT(1))\n\t\tgoto undo;"},
		{"injector: epoch bind", "if (epoch < 0 || SE_PUBLISH_FAULT(2))\n\t\tgoto undo;"},
		{"injector: after the locator insert", "indexed = 1;\n\tif (SE_PUBLISH_FAULT(3))\n\t\tgoto undo;"},
		// Recycle cleanup (deviation 4): binding, epoch cells and index of
		// the scope, the slot's adopted set, the state but last_cgroup.
		{"recycle: epoch cells of the scope", "if (!cell || !scope || cell->scope != scope)\n\t\t\tcontinue;"},
		{"recycle: epoch index", "if (have && *have == bank)\n\t\t\tbpf_map_delete_elem(&se_epoch_index, &key);\n" +
			"\t\tcell->scope = 0;\n\t\tcell->uid = 0;\n\t\tcell->epoch = 0;"},
		{"recycle: adopted set", "bpf_for_each_map_elem(&opaque_real_adopted, real_owner_adopted_clear,\n\t\t\t      &slot, 0);"},
		// A missed quarantine entry is reported (1), never success.
		{"quarantine: a missed entry is not success", "return walk.missed ? OPAQUE_REAL_CMD_RETRY : OPAQUE_REAL_CMD_OK;"},
		// I-3: gone (no TASK key at the address) is not missed.
		{"quarantine: gone vs missed", "if (!bpf_map_lookup_elem(&se_opaque_keys, &physical))\n\t\twalk->gone++;\n" +
			"\telse if (real_owner_birth_quarantine(key->task, value->cookie,\n\t\t\t\t\t     value->locator))\n" +
			"\t\twalk->missed++;\n\telse\n\t\twalk->marked++;"},
		{"quarantine: gone reported", "state->gone = walk.gone;"},
		// Verify: an exiting task is refused and counted apart (the agent
		// maps bad == exiting to AdoptionThreadExited); any other mismatch
		// is still bad and refused.
		{"verify counts exiting tasks of the init only", "__u32 tgid = 0;\n\t\t\tif (!BPF_CORE_READ_INTO(&tgid, task, tgid) &&\n" +
			"\t\t\t    tgid == state->init_tgid)\n\t\t\t\t__sync_fetch_and_add(&state->exiting, 1);\n" +
			"\t\t\t__sync_fetch_and_add(&state->bad, 1);\n" +
			"\t\t} else if (real_owner_adopt_identity(task, state, &leader)) {\n\t\t\t__sync_fetch_and_add(&state->bad, 1);\n\t\t}"},
		{"finish counts exiting tasks of the init only", "if (!unreadable && (flags & OPAQUE_REAL_PF_EXITING)) {\n" +
			"\t\t\t/* As in verify: only the init's own exiting threads\n\t\t\t * count as exiting; any exiting task is bad. */\n" +
			"\t\t\t__u32 tgid = 0;\n\t\t\tif (!BPF_CORE_READ_INTO(&tgid, task, tgid) &&\n" +
			"\t\t\t    tgid == state->init_tgid)\n\t\t\t\t__sync_fetch_and_add(&state->exiting, 1);\n\t\t}"},
		{"verify still refuses on any bad task", "if (!started || state->bad || !state->iterated ||\n" +
			"\t    state->iterated > SE_PROFILE_TASK_QUOTA || state->leaders != 1) {"},
		// M-5: every TASK that may exist after a charge is recorded.
		{"adopt_task records an unopenable published TASK", "if (directory) {\n\t\t\t\tcookie = 0;\n\t\t\t\tlocator = *directory;\n\t\t\t\tqualified = 1;"},
		{"adopt_publish reports a failed release as possibly published", "return status == SE_OL_OK && !released ? 0 : 1;"},
		// L-4: per-slot cap on the shared adopted set.
		{"adopted set per-slot cap", "if (recorded >= SE_PROFILE_TASK_QUOTA ||\n\t\t    bpf_map_update_elem(&opaque_real_adopted, &key, &value,\n\t\t\t\t\tBPF_NOEXIST)) {"},
		{"adopt_state wire", "_Static_assert(sizeof(struct opaque_real_adopt_state) == 120,"},
		{"quarantine through the birth quarantine", "if (real_owner_birth_quarantine(key->task, value->cookie,\n\t\t\t\t\tvalue->locator))"},
	} {
		if !strings.Contains(product, squashSpace(pin.text)) {
			t.Errorf("%s: pin missing: %q", pin.name, pin.text)
		}
	}
	// Recycle clears every adoption field except last_cgroup.
	recycle := product[strings.Index(product, squashSpace("real_owner_recycle_clean(__u32 slot)")):]
	if strings.Contains(recycle, "last_cgroup") {
		t.Error("recycle must keep last_cgroup (code 4 survives recycle)")
	}
	if strings.Count(product, squashSpace("state->last_cgroup = cgroup;")) != 1 {
		t.Error("last_cgroup is written only by a successful first publication")
	}
	// B6 (U2): ENTRY [11] and 12 cells only with the product publisher; the
	// reader's failed open is ENTRY only without any TASK key, else [8];
	// the reader's own begin refusal is [8]; both claim sites count
	// attempts; non-product objects keep 11 classes and the old reader.
	for _, pin := range []string{
		"#define REAL_OWNER_RATE_WORK_RETRY 10\n#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n" +
			"#define REAL_OWNER_RATE_ENTRY 11\n#define REAL_OWNER_RATE_ADMISSION 12\n#define REAL_OWNER_RATE_CLASSES 13\n#else\n#define REAL_OWNER_RATE_CLASSES 11\n#endif",
		"SE_RATE_ATTEMPT(1);\n\tint good = 0;\n\tif (!terminal_fault && !pending_terminal) {\n" +
			"\t\tgood = !SE_FC_EXEC_OPEN_PARENT_FAULT(key) &&\n\t\t       real_owner_child_open_parent(&owner) == SE_OL_OK;\n\t\tif (!good)\n\t\t\tSE_FAIL_CLOSED_RATE(\n" +
			"\t\t\t\tbpf_map_lookup_elem(&se_opaque_keys, &key) ?\n\t\t\t\t\tREAL_OWNER_RATE_OPEN_PARENT :\n" +
			"\t\t\t\t\tREAL_OWNER_RATE_ENTRY);\n\t}\n#else\n\tint good = !terminal_fault && !pending_terminal &&\n" +
			"\t\t   real_owner_child_open_parent(&owner) == SE_OL_OK;\n#endif",
		"if (!opened)\n\t\t\tSE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_OPEN_PARENT);\n#endif",
		"*mode_out = claim.execution_class;\n#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n\tSE_RATE_ATTEMPT(0);\n#endif",
		// The test-only extended injectors in the pinned conditions are
		// no fault outside ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_EXT_DIAGNOSTIC
		// (and that flag is refused in a product object).
		"#else\n#define SE_FC_EXEC_OPEN_PARENT_FAULT(key) 0\n#define SE_FC_EXEC_ADMISSION_FAULT(later) 0\n" +
			"#define SE_FC_BIRTH_ADMISSION_FAULT() 0\n#define SE_FC_TARGET_ADMISSION_FAULT() 0\n" +
			"#define SE_FC_READER_BEGIN_FAULT() 0\n#endif\n",
	} {
		if !strings.Contains(verdict, squashSpace(pin)) {
			t.Errorf("B6 pin missing: %q", pin)
		}
	}
	if strings.Count(verdict, "REAL_OWNER_RATE_ENTRY") != 2 {
		t.Error("ENTRY is attributed at exactly one site (the reader's failed open without a TASK key)")
	}
	// G019 M4 ADMISSION [12]: every exec admission fault before the reader
	// opens (Strict, Audit and invariant faults from se_cap_admit or
	// se_route_admit, and the frozen-class mismatch) is a counted attempt
	// plus ADMISSION; UNSELECTED is not; Audit still allows.
	for _, pin := range []string{
		"(void)real_owner_child_release_claim(&claim);\n#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n" +
			"\t\tSE_RATE_ATTEMPT(1);\n\t\tSE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_ADMISSION);\n#endif\n\t\treturn frozen_class == 2 ? 1 : 0;\n\t}",
		"if (admission != SE_ROUTE_OWNED) {\n#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n" +
			"/* G019 M4: every admission fault is a counted attempt and a\n\t\t * counted ADMISSION; Audit faults too (never silent). */\n" +
			"if (admission == SE_ROUTE_STRICT_FAULT ||\n\t\t    admission == SE_ROUTE_AUDIT_FAULT ||\n\t\t    admission == SE_ROUTE_INVARIANT_FAULT) {\n" +
			"\t\t\tSE_RATE_ATTEMPT(1);\n\t\t\tSE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_ADMISSION);\n\t\t}\n#endif\n" +
			"\t\treturn admission == SE_ROUTE_STRICT_FAULT ||\n\t\t\t\t       admission == SE_ROUTE_INVARIANT_FAULT ?\n\t\t\t       1 :\n\t\t\t       0;\n\t}",
	} {
		if !strings.Contains(verdict, squashSpace(pin)) {
			t.Errorf("ADMISSION pin missing: %q", pin)
		}
	}
	// The fork source's admission faults count a birth attempt plus
	// ADMISSION; the target's re-admission fault counts ADMISSION too
	// (design 13.20, review L1) against the source's attempt, a non-fault
	// target re-admission stays CONSTRUCT [5]: one class per attempt.
	if pin := "int admission = se_route_admit(bpf_get_current_cgroup_id(), &claim);\n" +
		// The test-only birth admission injector (0 outside the EXT flag):
		// its claim is released before anything is parked, then it takes
		// the same fault path.
		"/* Test-only birth admission fault: the claim is released here, before\n\t * anything is parked, and the fork takes the admission-fault path. */\n" +
		"\tif (admission == SE_ROUTE_OWNED && SE_FC_BIRTH_ADMISSION_FAULT()) {\n\t\t(void)real_owner_child_release_claim(&claim);\n" +
		"\t\tadmission = claim.execution_class == 2 ? SE_ROUTE_STRICT_FAULT :\n\t\t\t\t\t\t\t SE_ROUTE_AUDIT_FAULT;\n\t}\n" +
		"\tif (admission != SE_ROUTE_OWNED) {\n" +
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n" +
		"/* G019 M4: a fork admission fault (adopting, reserved,\n\t\t * saturated or invariant route) is a counted attempt and a\n\t\t * counted ADMISSION, Audit too; outside Total. */\n" +
		"if (admission == SE_ROUTE_STRICT_FAULT ||\n\t\t    admission == SE_ROUTE_AUDIT_FAULT ||\n\t\t    admission == SE_ROUTE_INVARIANT_FAULT) {\n" +
		"\t\t\tSE_RATE_ATTEMPT(0);\n\t\t\tSE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_ADMISSION);\n\t\t}\n#endif\n" +
		"\t\t*mode_out = admission == SE_ROUTE_STRICT_FAULT ||"; !strings.Contains(verdict, squashSpace(pin)) {
		t.Errorf("fork ADMISSION pin missing: %q", pin)
	}
	if strings.Count(verdict, "REAL_OWNER_RATE_ADMISSION") != 5 || strings.Count(verdict, "SE_RATE_ATTEMPT(1)") != 4 ||
		strings.Count(verdict, "SE_RATE_ATTEMPT(0)") != 2 {
		t.Error("ADMISSION is attributed at exactly the two exec admission-fault returns, the fork source's (each with its attempt) and the fork target's (the source's attempt)")
	}
	// G019 gap 4: an interpreter pass is its own exec attempt (the fourth
	// SE_RATE_ATTEMPT(1)), counted before its claim is released and the
	// continuation dispatched; its refusals count GAP against it.
	if pin := "if (pending_class == SE_EXEC_PENDING_CONTINUE) {\n#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n" +
		"\t\tSE_RATE_ATTEMPT(1); /* every pass is one exec attempt */\n#endif\n" +
		"\t\tint unreleased = real_owner_child_release_claim(&claim) != 0;\n" +
		"\t\treturn 16 | (unreleased ? 32 : 0) | (mode == 2 ? 1 : 0);\n\t}"; !strings.Contains(verdict, squashSpace(pin)) {
		t.Errorf("interpreter pass attempt pin missing: %q", pin)
	}
	if !strings.Contains(verdict, squashSpace("} else {\n#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n"+
		"/* G019 13.20: a target admission fault is ADMISSION (its birth\n\t\t * attempt was counted by the source), anything else CONSTRUCT:\n\t\t * exactly one class per attempt. */\n"+
		"SE_FAIL_CLOSED_RATE(admission == SE_ROUTE_STRICT_FAULT || admission == SE_ROUTE_AUDIT_FAULT || admission == SE_ROUTE_INVARIANT_FAULT ? REAL_OWNER_RATE_ADMISSION : REAL_OWNER_RATE_CONSTRUCT);\n"+
		"#else\n\t\tSE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_CONSTRUCT);\n#endif")) {
		t.Error("the target's re-admission fault is ADMISSION, a non-fault CONSTRUCT (one class per attempt)")
	}
	// QUARANTINED is OR-ed in, LIVE kept, cleanup_error never written; the
	// int result exists only under the product publisher.
	if !strings.Contains(verdict, squashSpace("#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n"+
		"#define SE_BIRTH_QUARANTINE_T int\n#define SE_BIRTH_QUARANTINE_RETURN(marked) return (marked) ? 0 : 1\n#else\n"+
		"#define SE_BIRTH_QUARANTINE_T void\n#define SE_BIRTH_QUARANTINE_RETURN(marked) return\n#endif")) ||
		!strings.Contains(verdict, squashSpace("task->flags |= SE_TASK_QUARANTINED;")) {
		t.Error("birth quarantine: int result under the flag, QUARANTINED OR-ed in")
	}
	quarantine := verdict[strings.Index(verdict, "real_owner_birth_quarantine(__u64key,__u64cookie,__u64locator)"):]
	quarantine = quarantine[:strings.Index(quarantine, "SE_BIRTH_QUARANTINE_RETURN(marked);}")]
	if strings.Contains(quarantine, "cleanup_error") || strings.Contains(quarantine, "SE_TASK_LIVE") {
		t.Error("birth quarantine must not write cleanup_error or clear LIVE")
	}
	// No map helper and no BPF-to-BPF call inside any spin-locked region
	// of the product publisher (lock, validate, unlock, update, relock).
	for rest := header; ; {
		i := strings.Index(rest, "bpf_spin_lock(")
		if i < 0 {
			break
		}
		rest = rest[i+len("bpf_spin_lock("):]
		j := strings.Index(rest, "bpf_spin_unlock(")
		if j < 0 {
			t.Fatal("unbalanced bpf_spin_lock in the product publisher")
		}
		region := rest[:j]
		for _, call := range []string{"bpf_map_", "se_ticket_command", "se_owk_", "se_oc_", "bpf_for_each", "bpf_task_", "bpf_cgroup_"} {
			if strings.Contains(region, call) {
				t.Errorf("locked region calls %s: %q", call, region)
			}
		}
		// Only the always-inline *_locked helpers of this header.
		for _, f := range strings.FieldsFunc(region, func(r rune) bool {
			return r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9')
		}) {
			if strings.HasPrefix(f, "real_owner_") && !strings.HasSuffix(f, "_locked") && f != "real_owner_record" {
				t.Errorf("locked region calls %s", f)
			}
		}
	}
	for _, helper := range []string{"real_owner_commit_locked", "real_owner_binding_clear_locked"} {
		if !strings.Contains(product, squashSpace("static __always_inline")+"int\n"+helper) &&
			!strings.Contains(product, squashSpace("static __always_inline void\n"+helper)) &&
			!strings.Contains(product, squashSpace("static __always_inline int\n"+helper)) {
			t.Errorf("%s must be always_inline (it runs under the route lock)", helper)
		}
	}
	// Review M1: a revision checks the staged object's prefix like a first
	// publication, and keeps the route's class.
	for _, pin := range []string{
		"/* Review M1: a revision's staged object is checked exactly like a first\n" +
			"\t * publication's (UID, root role, class, zero epoch). */\n" +
			"\tif (!real_owner_root_role_matches(r->object_slot, r->object_generation,\n" +
			"\t\t\t\t\t  request_uid, r->init_role,\n\t\t\t\t\t  r->execution_class)) {\n" +
			"\t\tcode = OPAQUE_REAL_CMD_REFUSED;\n\t\tgoto undo;\n\t}",
		"(!first && s->execution_class != route->execution_class) ||",
		"static __always_inline __u32 real_owner_record(__u32 record)\n{\n" +
			"\tasm volatile(\"\" : \"+r\"(record));\n\treturn record & 1;\n}",
	} {
		if !strings.Contains(product, squashSpace(pin)) {
			t.Errorf("M1 pin missing: %q", pin)
		}
	}
	if strings.Count(product, squashSpace("real_owner_root_role_matches(r->object_slot, r->object_generation,")) != 2 {
		t.Error("the staged-object prefix check runs in both the first publication and the revision")
	}
	for _, pin := range []string{
		"if (record >= 2)\n\t\treturn OPAQUE_REAL_CMD_INVARIANT;\n\trecord = real_owner_record(record);",
		"route->execution_class != r->execution_class) {",
		"bpf_spin_lock(&state->lock);\n\tint role_kept = state->init_role == r->init_role;\n" +
			"\tbpf_spin_unlock(&state->lock);\n\tif (!role_kept)\n\t\treturn OPAQUE_REAL_CMD_REFUSED;",
		"if (a->phase == SE_ROUTE_ACTIVE && a->adopting == 1 &&\n\t    a->active_record < 2 &&",
	} {
		if !strings.Contains(product, squashSpace(pin)) {
			t.Errorf("M1 follow-up pin missing: %q", pin)
		}
	}
	// The verifier refused route_publish when a spilled u32 record index came
	// back unbounded after bpf_spin_lock: every records[] index of the
	// publisher is a literal, a fresh masked map field, or re-bounded at use.
	allowed := map[string]bool{
		"0": true, "1": true, "real_owner_record(record)": true,
		"b->active_record & 1": true, "claim.record & 1": true,
	}
	// commit_locked's one bare records[record], right after its re-bound,
	// is checked exactly below; every other index is scanned.
	rebound := "record = real_owner_record(record);\n\tconst struct se_snapshot *s = &b->records[record];"
	for rest := strings.Replace(header, rebound, "", 1); ; {
		i := strings.Index(rest, "records[")
		if i < 0 {
			break
		}
		rest = rest[i+len("records["):]
		j := strings.Index(rest, "]")
		if index := rest[:j]; index != "" && !allowed[index] {
			t.Errorf("records[%s]: index not proven bounded at its use", index)
		}
	}
	// The one bare records[record] is commit_locked's, immediately after
	// its re-bound (review: the scan must not allow it anywhere else).
	if strings.Count(product, "records[record]") != 1 ||
		!strings.Contains(header, rebound) {
		t.Error("the only bare records[record] is commit_locked's, right after its re-bound")
	}
	// Review M1 item 6: se_ticket_command (full/shared_snapshot.h) ends its
	// snapshot command on every path after a successful begin, so a failed
	// pin or release can never leave a stray `commands` count that would
	// block retire/reclaim (and so withdraw and recycle) forever: no return
	// between the begin's own failure check and the end call.
	snapshot := read("../full/shared_snapshot.h")
	ticket := snapshot[strings.Index(snapshot, "static inline int se_ticket_command("):]
	ticket = ticket[:strings.Index(ticket, "\n}\n")]
	begin := strings.Index(ticket, "se_snapshot_command_begin_locked(")
	end := strings.Index(ticket, "se_snapshot_command_end_locked(")
	beginFail := "bpf_spin_unlock(authority_lock);\n\tif (result)\n\t\treturn result;"
	if begin < 0 || end < begin || strings.Count(ticket, "se_snapshot_command_end_locked(") != 1 {
		t.Fatal("se_ticket_command: one begin, then exactly one end")
	}
	held := ticket[begin:end]
	if f := strings.Index(held, beginFail); f < 0 || strings.Contains(held[f+len(beginFail):], "return") ||
		strings.Contains(held[f+len(beginFail):], "goto") {
		t.Error("se_ticket_command: a return or goto between the begin's failure check and the command end")
	}
	// CO-RE read widths: BPF_CORE_READ_INTO reads sizeof(*dst) bytes, so a
	// destination wider than its field also reads the next field (chain13:
	// a __u64 for the 4-byte ns_common.inum refused every adoption). Every
	// read's destination is declared with its field's exact width.
	// Keyed by the full field path after the source (review: no last-field
	// collisions across structures).
	fieldWidth := map[string]string{
		"tgid": "__u32", "pid": "__u32", "flags": "__u32",
		"nsproxy,mnt_ns,ns.inum": "__u32",
		"cgroups,dfl_cgrp,kn,id": "__u64", "start_boottime": "__u64",
	}
	reads := regexp.MustCompile(`BPF_CORE_READ_INTO\(&(\w+),\s*\w+,\s*([^)]*)\)`).FindAllStringSubmatchIndex(header, -1)
	if len(reads) == 0 {
		t.Fatal("no CO-RE read found in the product publisher")
	}
	// Every read must match the checked shape (an &local destination and a
	// plain source): a cast source, a field or pointer destination would
	// otherwise escape the width check.
	if n := strings.Count(header, "BPF_CORE_READ_INTO("); n != len(reads) {
		t.Errorf("%d BPF_CORE_READ_INTO calls, %d in the checked shape", n, len(reads))
	}
	for _, m := range reads {
		dst, path := header[m[2]:m[3]], header[m[4]:m[5]]
		field := strings.Join(strings.Fields(path), "")
		want, known := fieldWidth[field]
		if !known {
			t.Errorf("CO-RE read of %q into %s: field width not in the pinned table", field, dst)
			continue
		}
		decls := regexp.MustCompile(`(__u32|__u64)[^;()]*\b`+dst+`\b[^;()]*;`).FindAllStringSubmatch(header[:m[0]], -1)
		if len(decls) == 0 || decls[len(decls)-1][1] != want {
			t.Errorf("CO-RE read of %q into %s: destination is not %s", field, dst, want)
		}
	}
	if !strings.Contains(product, squashSpace("BPF_CORE_READ_INTO(&inum, task, nsproxy, mnt_ns, ns.inum)")) {
		t.Error("the mount namespace inode is read into the __u32 inum")
	}
	// Arming (fail-open fix): a product object arms only from the
	// authenticated configuration, and publish and verify refuse on an
	// unarmed image.
	for _, pin := range []string{
		"#if defined(SE_PRODUCT_NO_TEST_RUN) && \\\n\t!defined(ENFORCE_EXEC_POOL_OPAQUE_NATIVE_CONFIG_GATE_CANDIDATE)\n" +
			"#error \"the product object arms only from the authenticated node configuration (NATIVE_CONFIG_GATE)\"\n#endif",
	} {
		if !strings.Contains(verdict, squashSpace(pin)) {
			t.Errorf("arming pin missing: %q", pin)
		}
	}
	for _, cmd := range []string{"opaque_real_route_publish", "opaque_real_adopt_verify"} {
		body := product[strings.Index(product, squashSpace("int "+cmd+"(")):]
		if !strings.HasPrefix(body[strings.Index(body, "{"):], squashSpace("{\n\tif (!r || !real_owner_cmd_authenticate(&r->header))\n"+
			"\t\treturn OPAQUE_REAL_CMD_AUTH;\n\tif (!real_owner_image_configured())\n\t\treturn OPAQUE_REAL_CMD_UNARMED;")) {
			t.Errorf("%s must refuse on an unarmed image right after authentication", cmd)
		}
	}
	// Every tail-call site of an armed product object fails closed on an
	// empty slot: the task_alloc constructor counts [2] and Strict denies;
	// each verdict-graph site counts [2] (SE_GRAPH_MISS, product publisher
	// only) and then takes its static class verdict (Strict -1).
	for _, pin := range []string{
		"bpf_tail_call(ctx, &opaque_real_owner_child_targets, 0);\n" +
			"\t/* Missing target is not a successful child constructor. An audit route\n" +
			"\t * remains nonblocking; strict enforcement denies. */\n" +
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n\tse_birth_park_abandon(&mode);\n#endif\n" +
			"\treal_owner_child_missing_target();\n\tif (mode == 2)\n\t\treturn -1;",
		"SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_MISSING_TARGET);\n\tif (se_ol_task_open(&parent_key, &parent) == SE_OL_OK) {",
		"#define SE_GRAPH_MISS() SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_MISSING_TARGET)",
		"bpf_tail_call(ctx, &opaque_real_stage_strict, 0);\n\t\tSE_GRAPH_MISS();\n\t}",
		"bpf_tail_call(ctx, &opaque_real_prepare_strict, 0);\n\t\tSE_GRAPH_MISS();\n\t}",
		"&opaque_real_rule_strict,\n\t\t\t\t\t\t      0);\n\t\t\t\tSE_GRAPH_MISS();\n\t\t\t}",
		"bpf_tail_call(ctx, &opaque_real_finish_strict, 0);\n\t}\n\tSE_GRAPH_MISS();",
		"bpf_tail_call(ctx, &opaque_real_policy_audit,\n\t\t\t\t\t      0);\n\t\t\tSE_GRAPH_MISS();",
		// The static class verdicts after a miss: Strict never allows.
		"if (execution_class != 2 || error || !decision)\n\t\treturn -1;",
	} {
		src := verdict
		if strings.HasPrefix(pin, "if (execution_class") {
			src = squashSpace(read("../fullpolicy/bpf/evaluator.h"))
		}
		if !strings.Contains(src, squashSpace(pin)) {
			t.Errorf("tail-call miss pin missing: %q", pin)
		}
	}
	if n := strings.Count(verdict, "SE_GRAPH_MISS();"); n != 5 {
		t.Errorf("SE_GRAPH_MISS at %d sites, want the 5 verdict-graph sites", n)
	}
	// The init-tgid filter on exiting tasks exists exactly twice (verify and
	// finish), so removing either copy fails even if the other's text
	// still matches.
	if n := strings.Count(product, squashSpace("if (!BPF_CORE_READ_INTO(&tgid, task, tgid) &&\n\t    tgid == state->init_tgid)\n\t\t__sync_fetch_and_add(&state->exiting, 1);")); n != 2 {
		t.Errorf("init-tgid exiting filter present %d times, want 2 (verify and finish)", n)
	}
	// The protocol and test-host layouts keep the 88-byte route.
	for _, path := range []string{"testdata/shared_control.c", "../full/test/host/pool_work_core_candidate.c"} {
		if !strings.Contains(read(path), "_Static_assert(sizeof(struct se_route_anchor) == 88") {
			t.Errorf("%s: protocol route layout pin (88 B) missing", path)
		}
	}
	for _, forbidden := range []string{"se_command", "se_commands", "se_receipts", "SE_COMMAND_LOOKUP", "SE_RECEIPT_LOOKUP"} {
		if strings.Contains(header, forbidden+"(") || strings.Contains(header, "&"+forbidden) {
			t.Errorf("product publisher depends on the protocol %s", forbidden)
		}
	}
}
