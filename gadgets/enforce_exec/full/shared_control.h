/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ENFORCE_EXEC_SHARED_CONTROL_H
#define ENFORCE_EXEC_SHARED_CONTROL_H
#include "shared_route.h"

/* Mandatory explicit image geometry, validated again by native pre-allocation
 * admission. There are no inferred shared-profile defaults. */
#ifndef SE_PROFILE_BINDINGS
#error "shared image requires explicit binding count"
#endif
#ifndef SE_PROFILE_SLOTS_256
#error "shared image requires all four explicit object-slot counts"
#endif
#ifndef SE_PROFILE_SLOTS_1024
#error "shared image requires all four explicit object-slot counts"
#endif
#ifndef SE_PROFILE_SLOTS_4096
#error "shared image requires all four explicit object-slot counts"
#endif
#ifndef SE_PROFILE_SLOTS_16384
#error "shared image requires all four explicit object-slot counts"
#endif
/* Validate each literal BEFORE aggregation: signed negative counts must not
 * cancel positive capacities through unsigned arithmetic. */
#define SE_SLOT_DOMAIN(value) \
	((value) >= 0 && (0ULL + (value)) <= 0xffffffffULL)
_Static_assert(SE_SLOT_DOMAIN(SE_PROFILE_SLOTS_256), "256 slot count domain");
_Static_assert(SE_SLOT_DOMAIN(SE_PROFILE_SLOTS_1024), "1024 slot count domain");
_Static_assert(SE_SLOT_DOMAIN(SE_PROFILE_SLOTS_4096), "4096 slot count domain");
_Static_assert(SE_SLOT_DOMAIN(SE_PROFILE_SLOTS_16384),
	       "16384 slot count domain");
#define SE_PROFILE_OBJECTS                                     \
	(0ULL + SE_PROFILE_SLOTS_256 + SE_PROFILE_SLOTS_1024 + \
	 SE_PROFILE_SLOTS_4096 + SE_PROFILE_SLOTS_16384)
#define SE_PROFILE_CELLS                                                   \
	(256ULL * SE_PROFILE_SLOTS_256 + 1024ULL * SE_PROFILE_SLOTS_1024 + \
	 4096ULL * SE_PROFILE_SLOTS_4096 + 16384ULL * SE_PROFILE_SLOTS_16384)
_Static_assert(SE_PROFILE_BINDINGS > 0 && SE_PROFILE_BINDINGS <= 0xffffffffU,
	       "binding profile domain");
_Static_assert(SE_PROFILE_OBJECTS > 0 && SE_PROFILE_OBJECTS <= 0xffffffffU,
	       "object profile domain");
_Static_assert(SE_PROFILE_CELLS > 0 && SE_PROFILE_CELLS <= 0xffffffffU,
	       "arena profile domain");
struct se_node_config {
	__u64 node_cookie, nonce;
	__u32 abi, profile_version, bindings, objects, cells, slots[4],
		reserved;
};
struct se_arena_cell {
	__u64 words[36];
};
enum se_operation {
	SE_OBJECT_BEGIN = 1,
	SE_OBJECT_WRITE,
	SE_OBJECT_FINALIZE,
	SE_OBJECT_ABORT,
	SE_OBJECT_RETIRE,
	SE_OBJECT_RECLAIM,
	SE_BINDING_OPEN,
	SE_SNAPSHOT_PREPARE,
	SE_SNAPSHOT_PIN,
	SE_SNAPSHOT_SEAL,
	SE_SNAPSHOT_ABORT,
	SE_SNAPSHOT_RELEASE,
	SE_SNAPSHOT_RECLAIM,
	SE_OBJECT_INSPECT,
	SE_SNAPSHOT_INSPECT,
	SE_NODE_INSPECT
};
struct se_control_command {
	__u64 node_cookie, nonce, sequence, generation, attempt, scope, serial,
		cgroup_identity;
	__u32 operation, object, binding, record, index, count, execution_class,
		reserved;
	struct se_pin_ticket handles[8];
	struct se_arena_cell value;
	struct se_snapshot_metadata metadata;
};
struct se_control_receipt {
	__u64 node_cookie, sequence, generation, serial;
	__u32 operation, status, value, reserved;
};
_Static_assert(sizeof(struct se_node_config) == 56, "shared config wire");
_Static_assert(sizeof(struct se_control_command) == 1112,
	       "shared command wire");
_Static_assert(sizeof(struct se_control_receipt) == 48, "shared receipt wire");
_Static_assert(sizeof(struct se_arena_cell) == 288, "shared arena cell wire");
#ifndef SE_CONTROL_TEST
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct se_node_config);
} se_configuration SEC(".maps");
#ifndef ENFORCE_EXEC_SHARED_RECOVERY
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} se_admin SEC(".maps");
#endif
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_WRONLY);
	__type(key, __u32);
	__type(value, struct se_control_command);
} se_commands SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_control_receipt);
} se_receipts SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_OBJECTS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_shared_object);
} se_objects SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_BINDINGS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_shared_binding);
} se_bindings SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_BINDINGS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_route_anchor);
} se_routes SEC(".maps");
/* Locator only; preallocated, not an authority lock or copied class. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_PROFILE_BINDINGS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, __u64);
} se_route_index SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_CELLS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_arena_cell);
} se_arena SEC(".maps");
#define SE_CONFIG_LOOKUP(key) bpf_map_lookup_elem(&se_configuration, key)
#define SE_COMMAND_LOOKUP(key) bpf_map_lookup_elem(&se_commands, key)
#define SE_RECEIPT_LOOKUP(key) bpf_map_lookup_elem(&se_receipts, key)
#ifndef ENFORCE_EXEC_SHARED_RECOVERY
#define SE_ADMIN_LOOKUP() \
	bpf_task_storage_get(&se_admin, bpf_get_current_task_btf(), 0, 0)
#endif
#define SE_OBJECT_LOOKUP(key) bpf_map_lookup_elem(&se_objects, key)
#define SE_ROUTE_LOOKUP(key) bpf_map_lookup_elem(&se_routes, key)
#define SE_BINDING_LOOKUP(key) bpf_map_lookup_elem(&se_bindings, key)
#define SE_CELL_LOOKUP(key) bpf_map_lookup_elem(&se_arena, key)
#endif
#ifndef SE_AFTER_CELL_STORE
#define SE_AFTER_CELL_STORE(object) \
	do {                        \
	} while (0)
#endif
static inline int se_profile_matches(const struct se_node_config *c)
{
	return c && c->node_cookie && c->nonce && c->abi == 3 &&
	       c->profile_version == 1 && !c->reserved &&
	       c->bindings == SE_PROFILE_BINDINGS &&
	       c->objects == SE_PROFILE_OBJECTS &&
	       c->cells == SE_PROFILE_CELLS &&
	       c->slots[0] == SE_PROFILE_SLOTS_256 &&
	       c->slots[1] == SE_PROFILE_SLOTS_1024 &&
	       c->slots[2] == SE_PROFILE_SLOTS_4096 &&
	       c->slots[3] == SE_PROFILE_SLOTS_16384;
}
#ifdef SE_OBJECT_RANGE_INLINE_DIAGNOSTIC
__attribute__((always_inline))
#endif
static inline int
se_object_range(const struct se_node_config *c, __u32 slot, __u32 *size_class,
		__u32 *base)
{
	__u64 offset = 0;
	__u32 index = slot;
	for (__u32 i = 0; i < 4; i++) {
		__u32 capacity = se_object_capacity(i);
		if (index < c->slots[i]) {
			*size_class = i;
			*base = (__u32)(offset + (__u64)index * capacity);
			return 0;
		}
		index -= c->slots[i];
		offset += (__u64)c->slots[i] * capacity;
	}
	return -1;
}
/* The recovered physical-admin lookup uses only the node cookie as input and
 * relooks its own maps. Keep its lock frame out of the command interpreter's
 * call chain on older kernels; never pass a borrowed map-value pointer into
 * this subprogram. */
#ifdef ENFORCE_EXEC_SHARED_RECOVERY
static __attribute__((noinline)) int
se_command_recovery_authorized(__u64 node_cookie)
{
	return se_rm_command_authorized(node_cookie);
}
#endif

/* Protocol-only mode uses the pinned native admin task storage. Recovered
 * mode admits only the committed live physical admin under the recovery lock.
 * The trusted host protocol serializes complete command-map writes and runs.
 * Publication remains in se_publication_arm after cgroup_kn_lock_live. */
/* Stock Rocky 4.18 refuses spinlocks in the syscall program type. Probe a
 * non-sleepable TEST_RUN-only endpoint in the unselected real-map candidate;
 * selected-image transport/resources must be revised before adopting it. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
SEC("tc")
#else
SEC("syscall")
#endif
int se_command(void *unused)
{
	(void)unused;
	__u32 zero = 0;
	const struct se_node_config *config = SE_CONFIG_LOOKUP(&zero);
	const struct se_control_command *input = SE_COMMAND_LOOKUP(&zero);
#ifdef ENFORCE_EXEC_SHARED_RECOVERY
	if (!se_profile_matches(config) || !input ||
	    input->node_cookie != config->node_cookie || input->reserved ||
	    !se_command_recovery_authorized(config->node_cookie))
		return 1;
#else
	const __u64 *admin = SE_ADMIN_LOOKUP();
	if (!se_profile_matches(config) || !input || !admin ||
	    *admin != config->nonce || input->nonce != config->nonce ||
	    input->node_cookie != config->node_cookie || input->reserved)
		return 1;
#endif
	struct se_control_receipt *receipt = SE_RECEIPT_LOOKUP(&zero);
	if (!receipt ||
	    (receipt->node_cookie &&
	     receipt->node_cookie != config->node_cookie) ||
	    !input->sequence || input->sequence == ~0ULL ||
	    input->sequence <= receipt->sequence)
		return 1;
	/* The actual thread is single-flight. Failed authenticated calls consume their
  * sequence too; lost acknowledgements reconcile this exact node/sequence. */
	*receipt =
		(struct se_control_receipt){ .node_cookie = config->node_cookie,
					     .sequence = input->sequence,
					     .operation = input->operation,
					     .status = 1 };
	/* Read-only node handshake is independent of object class/initialization. */
	if (input->operation == SE_NODE_INSPECT) {
		receipt->value = config->profile_version;
		receipt->status = 0;
		return 0;
	}
	int result = -1;
	if ((input->operation >= SE_OBJECT_BEGIN &&
	     input->operation <= SE_OBJECT_RECLAIM) ||
	    input->operation == SE_OBJECT_INSPECT) {
		__u32 slot = input->object, size_class = 0, base = 0;
		if (slot >= config->objects ||
		    se_object_range(config, slot, &size_class, &base))
			return 1;
		struct se_shared_object *object = SE_OBJECT_LOOKUP(&slot);
		if (!object)
			return 1;
		if (input->operation == SE_OBJECT_WRITE) {
			if (input->index >= se_object_capacity(size_class))
				return 1;
			__u32 key = base + input->index;
			struct se_arena_cell *cell = SE_CELL_LOOKUP(&key);
			if (!cell)
				return 1;
			struct se_write_claim claim = {};
			bpf_spin_lock(&object->lock);
			if (object->state.slot == slot &&
			    object->state.size_class == size_class)
				result = se_object_write_begin_locked(
					&object->state, input->generation,
					input->attempt, input->index, &claim);
			bpf_spin_unlock(&object->lock);
			if (result)
				return 1;
			__builtin_memcpy(cell, &input->value, sizeof(*cell));
			SE_AFTER_CELL_STORE(object);
			bpf_spin_lock(&object->lock);
			result = se_object_write_finish_locked(&object->state,
							       &claim);
			bpf_spin_unlock(&object->lock);
		} else {
			bpf_spin_lock(&object->lock);
			struct se_object *s = &object->state;
			if (input->operation == SE_OBJECT_BEGIN &&
			    s->generation == input->generation &&
			    s->phase == SE_OBJECT_FREE && !s->pins &&
			    !s->commands && !s->writer_sequence &&
			    !s->reserved && input->attempt &&
			    input->attempt != ~0ULL && input->count &&
			    input->count <= se_object_capacity(size_class) &&
			    s->generation < ~0ULL - 1) {
				s->slot = slot;
				s->size_class = size_class;
				result = se_object_begin_locked(
					s, input->attempt, input->count);
			} else if (s->slot == slot &&
				   s->size_class == size_class) {
				switch (input->operation) {
				case SE_OBJECT_FINALIZE:
					result = se_object_finalize_locked(
						s, input->generation,
						input->attempt, input->count,
						input->execution_class);
					break;
				case SE_OBJECT_ABORT:
					result = se_object_abort_locked(
						s, input->generation,
						input->attempt);
					break;
				case SE_OBJECT_RETIRE:
					result = se_object_retire_locked(
						s, input->generation);
					break;
				case SE_OBJECT_RECLAIM:
					result = se_object_reclaim_locked(
						s, input->generation);
					break;
				case SE_OBJECT_INSPECT:
					result =
						s->generation ==
								input->generation ?
							0 :
							-1;
					break;
				}
			}
			if (!result) {
				receipt->generation = s->generation;
				receipt->value = s->phase;
			}
			bpf_spin_unlock(&object->lock);
		}
	} else {
		__u32 key = input->binding;
		if (key >= config->bindings)
			return 1;
		struct se_shared_binding *binding = SE_BINDING_LOOKUP(&key);
		struct se_route_anchor *route = SE_ROUTE_LOOKUP(&key);
		if (!binding || !route)
			return 1;
		if (input->operation == SE_SNAPSHOT_PIN ||
		    input->operation == SE_SNAPSHOT_RELEASE ||
		    input->operation == SE_SNAPSHOT_INSPECT) {
			__u32 slot = input->object;
			if (slot >= config->objects)
				return 1;
			struct se_shared_object *object =
				SE_OBJECT_LOOKUP(&slot);
			if (!object)
				return 1;
			struct se_ticket_request request = {
				.scope = input->scope,
				.serial = input->serial,
				.record = input->record,
				.position = input->index,
				.kind = input->operation == SE_SNAPSHOT_PIN ?
						SE_COMMAND_PIN :
					input->operation ==
							SE_SNAPSHOT_RELEASE ?
						SE_COMMAND_RELEASE :
						SE_COMMAND_INSPECT
			};
			__u32 value = 0;
			result = se_ticket_command(&route->lock, binding,
						   object, &request, &value);
			if (!result)
				receipt->value = value;
		} else {
			__u32 record = input->record;
			if (record >= 2)
				return 1;
			struct se_pin_ticket handles[8] = {};
			if (input->operation == SE_SNAPSHOT_PREPARE) {
				if (!input->count || input->count > 8 ||
				    input->generation >= ~0ULL - 1 ||
				    !se_snapshot_metadata_valid(
					    &input->metadata, input->count,
					    input->generation + 1))
					return 1;
					/* Literal slot offsets: older verifiers cannot prove a
				 * variable stack cursor remains inside handles[8]. */
#ifdef __clang__
#pragma unroll
#endif
				for (__u32 i = 0; i < 8; i++) {
					if (i >= input->count)
						continue;
					handles[i] = input->handles[i];
					if (handles[i].object_slot >=
					    config->objects)
						return 1;
				}
			}
			bpf_spin_lock(&route->lock);
			struct se_binding_snapshots *b = &binding->state;
			if (input->operation == SE_BINDING_OPEN &&
			    input->scope == input->sequence && input->scope &&
			    input->scope != ~0ULL && !b->scope &&
			    !b->next_serial && !b->next_command &&
			    !b->generation && !b->active_serial &&
			    !b->inflight && !b->records[0].phase &&
			    !b->records[1].phase &&
			    !se_route_open_locked(route, input->cgroup_identity,
						  input->scope, key)) {
				b->scope = input->scope;
				result = 0;
			} else if (route->scope == input->scope &&
				   b->scope == input->scope && input->scope) {
				struct se_snapshot *s = &b->records[record];
				if (input->operation == SE_SNAPSHOT_PREPARE &&
				    b->generation == input->generation &&
				    b->next_serial == input->serial) {
					result = se_snapshot_prepare_locked(
						b, record, handles,
						input->count,
						input->execution_class);
					if (!result)
						b->records[record].metadata =
							input->metadata;
				} else if (s->serial == input->serial &&
					   s->scope == input->scope) {
					switch (input->operation) {
					case SE_SNAPSHOT_SEAL:
						result =
							se_snapshot_prepared_locked(
								s);
						break;
					case SE_SNAPSHOT_ABORT:
						if (s->phase ==
							    SE_SNAPSHOT_PREPARING ||
						    s->phase ==
							    SE_SNAPSHOT_PREPARED)
							result =
								se_snapshot_retire_locked(
									s);
						break;
					case SE_SNAPSHOT_RECLAIM:
						result =
							se_snapshot_reclaim_locked(
								s);
						break;
					}
				}
			}
			if (!result) {
				receipt->serial = b->records[record].serial;
				receipt->value = b->records[record].phase;
			}
			bpf_spin_unlock(&route->lock);
		}
	}
	receipt->status = result ? 1 : 0;
	return result ? 1 : 0;
}
#endif
