#ifndef ENFORCE_EXEC_SHARED_POOL_ABI_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_ABI_CANDIDATE_H
/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* ABI prerequisite only. No product hook reads or writes these maps. */
#if !defined(ENFORCE_EXEC_ABI3_DEVELOPMENT) || \
	!defined(ENFORCE_EXEC_SHARED_NODE) ||  \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY)
#error "fixed pool ABI requires shared ABI3 and explicit candidate-only build"
#endif

#ifndef offsetof
#define offsetof(T, F) __builtin_offsetof(T, F)
#endif
#include "shared_pool_task_wire.h"
#include "shared_pool_reaper_wire_candidate.h"
/* Exact reviewed host ABI, adapted to actual BTF spinlock. */
struct se_pool_task_meta {
	struct bpf_spin_lock lock;
	__u32 phase;
	__u64 cookie, physical_address, account_scope;
	__u32 slot, account_slot, account_incarnation, active_leases;
	__u32 work_refs, native_refs, cleanup_done, flags, directory_holds,
		reserved0;
	__u64 next_work_sequence, current_work_cookie;
	__u32 current_work_slot, current_work_owned, cleanup_error, reserved1;
	__u64 last_reap_sequence, reserved2, reserved3;
};
struct se_pool_work_meta {
	struct bpf_spin_lock lock;
	__u32 phase;
	__u64 cookie, owner_task_cookie, owner_task_address, account_scope,
		invocation_sequence;
	__u32 owner_task_slot, account_slot, account_incarnation, active_leases,
		owner_ref_held, cleanup_done;
	__u64 last_reap_sequence;
};
struct se_pool_charge {
	__u64 current_cookie, last_returned_cookie, account_scope;
	__u32 account_incarnation, state;
};
struct se_pool_way {
	__u64 address, cookie;
	__u32 slot, reserved;
};
struct se_pool_directory {
	struct bpf_spin_lock lock;
	__u32 reserved;
	struct se_pool_way ways[16];
};
struct se_pool_bitmap_header {
	_Alignas(8) __u32 task_hint;
	__u32 work_hint, reserved0, reserved1;
};
#define SIZE(T, N) _Static_assert(sizeof(struct T) == (N), #T " size")
#define OFF(T, F, N) \
	_Static_assert(offsetof(struct T, F) == (N), #T "." #F " offset")
SIZE(bpf_spin_lock, 4);
SIZE(se_pool_task_meta, 128);
OFF(se_pool_task_meta, lock, 0);
OFF(se_pool_task_meta, phase, 4);
OFF(se_pool_task_meta, cookie, 8);
OFF(se_pool_task_meta, physical_address, 16);
OFF(se_pool_task_meta, account_scope, 24);
OFF(se_pool_task_meta, slot, 32);
OFF(se_pool_task_meta, account_slot, 36);
OFF(se_pool_task_meta, account_incarnation, 40);
OFF(se_pool_task_meta, active_leases, 44);
OFF(se_pool_task_meta, work_refs, 48);
OFF(se_pool_task_meta, native_refs, 52);
OFF(se_pool_task_meta, cleanup_done, 56);
OFF(se_pool_task_meta, flags, 60);
OFF(se_pool_task_meta, directory_holds, 64);
OFF(se_pool_task_meta, reserved0, 68);
OFF(se_pool_task_meta, next_work_sequence, 72);
OFF(se_pool_task_meta, current_work_cookie, 80);
OFF(se_pool_task_meta, current_work_slot, 88);
OFF(se_pool_task_meta, current_work_owned, 92);
OFF(se_pool_task_meta, cleanup_error, 96);
OFF(se_pool_task_meta, reserved1, 100);
OFF(se_pool_task_meta, last_reap_sequence, 104);
OFF(se_pool_task_meta, reserved2, 112);
OFF(se_pool_task_meta, reserved3, 120);
SIZE(se_pool_work_meta, 80);
OFF(se_pool_work_meta, lock, 0);
OFF(se_pool_work_meta, phase, 4);
OFF(se_pool_work_meta, cookie, 8);
OFF(se_pool_work_meta, owner_task_cookie, 16);
OFF(se_pool_work_meta, owner_task_address, 24);
OFF(se_pool_work_meta, account_scope, 32);
OFF(se_pool_work_meta, invocation_sequence, 40);
OFF(se_pool_work_meta, owner_task_slot, 48);
OFF(se_pool_work_meta, account_slot, 52);
OFF(se_pool_work_meta, account_incarnation, 56);
OFF(se_pool_work_meta, active_leases, 60);
OFF(se_pool_work_meta, owner_ref_held, 64);
OFF(se_pool_work_meta, cleanup_done, 68);
OFF(se_pool_work_meta, last_reap_sequence, 72);
SIZE(se_pool_charge, 32);
OFF(se_pool_charge, current_cookie, 0);
OFF(se_pool_charge, last_returned_cookie, 8);
OFF(se_pool_charge, account_scope, 16);
OFF(se_pool_charge, account_incarnation, 24);
OFF(se_pool_charge, state, 28);
SIZE(se_pool_way, 24);
OFF(se_pool_way, address, 0);
OFF(se_pool_way, cookie, 8);
OFF(se_pool_way, slot, 16);
OFF(se_pool_way, reserved, 20);
SIZE(se_pool_directory, 392);
OFF(se_pool_directory, lock, 0);
OFF(se_pool_directory, reserved, 4);
OFF(se_pool_directory, ways, 8);
SIZE(se_pool_bitmap_header, 16);
OFF(se_pool_bitmap_header, task_hint, 0);
OFF(se_pool_bitmap_header, work_hint, 4);
OFF(se_pool_bitmap_header, reserved0, 8);
OFF(se_pool_bitmap_header, reserved1, 12);
_Static_assert(_Alignof(struct se_pool_bitmap_header) == 8, "bitmap alignment");
_Static_assert(_Alignof(struct se_pool_task_meta) == 8, "task alignment");
_Static_assert(_Alignof(struct se_pool_work_meta) == 8, "work alignment");
_Static_assert(_Alignof(struct se_pool_charge) == 8,
	       "se_pool_charge alignment");
_Static_assert(_Alignof(struct se_pool_directory) == 8,
	       "se_pool_directory alignment");

/* The semantic task state retains its old field offsets; its former spinlock
 * is wire-reserved here. The metadata lock above is the only task pool lock.
 * The work payload likewise contains no pool metadata lock. Neither semantic
 * representation is selected by any hook in this candidate. */
#ifdef ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE
#include "shared_pool_epoch_cache_wire.h"
SIZE(se_pool_epoch_cache, 272);
struct se_pool_task_payload {
	union {
		struct se_pool_task_wire wire;
		struct {
			struct se_task_state semantic;
			__u8 reserved_extension[1280 -
						sizeof(struct se_task_state)];
		};
	};
};
struct se_pool_work_payload {
	struct se_invocation semantic;
	struct se_pool_epoch_cache catalogue;
};
#else
struct se_pool_task_payload {
	__u32 reserved_lock;
	__u32 flags;
	__u64 physical_cookie, scope_cookie, eligibility_version,
		next_invocation;
	__u32 scope_slot, identity_reserved;
	struct er_state committed;
	struct se_task_stage staged;
	struct se_reader_owner reader;
	__u64 reader_invocation;
	struct se_exec_transaction exec;
	__u8 reserved_extension[1280 - sizeof(struct se_task_state)];
};
struct se_pool_work_payload {
	__u64 scope, cookie, sequence;
	__u32 slot, reserved;
	struct se_policy_view view;
	struct se_exec_work history;
	struct er_work inherited;
	struct observation observation;
	__u8 reserved_extension[19456 - sizeof(struct se_invocation)];
};
#endif
SIZE(se_pool_task_payload, 1280);
#ifdef ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE
OFF(se_pool_task_payload, semantic, 0);
OFF(se_pool_task_payload, wire, 0);
OFF(se_pool_task_payload, wire.identity, 0);
OFF(se_pool_task_payload, wire.bytes, 48);
_Static_assert(offsetof(struct se_pool_task_payload, semantic.flags) ==
			       offsetof(struct se_pool_task_payload,
					wire.identity.flags) &&
		       offsetof(struct se_pool_task_payload,
				semantic.physical_cookie) ==
			       offsetof(struct se_pool_task_payload,
					wire.identity.physical_cookie) &&
		       offsetof(struct se_pool_task_payload,
				semantic.scope_cookie) ==
			       offsetof(struct se_pool_task_payload,
					wire.identity.scope_cookie) &&
		       offsetof(struct se_pool_task_payload,
				semantic.eligibility_version) ==
			       offsetof(struct se_pool_task_payload,
					wire.identity.eligibility_version) &&
		       offsetof(struct se_pool_task_payload,
				semantic.next_invocation) ==
			       offsetof(struct se_pool_task_payload,
					wire.identity.next_invocation) &&
		       offsetof(struct se_pool_task_payload,
				semantic.scope_slot) ==
			       offsetof(struct se_pool_task_payload,
					wire.identity.scope_slot) &&
		       offsetof(struct se_pool_task_payload,
				semantic.identity_reserved) ==
			       offsetof(struct se_pool_task_payload,
					wire.identity.identity_reserved),
	       "opaque identity and typed TASK semantic must overlay exactly");
/* The opaque-key lexical handle checks this exact 48-byte identity prefix
 * before exposing any TASK semantic bytes. Keep the candidate bridge honest
 * if the selected task wire layout or LIVE bit changes. */
_Static_assert(offsetof(struct se_task_state, committed) == 48,
	       "opaque TASK identity prefix contract");
#ifdef SE_TASK_LIVE
_Static_assert(SE_TASK_LIVE == 4U, "opaque TASK LIVE bit contract");
#endif
OFF(se_pool_task_payload, semantic.reserved_lock, 0);
OFF(se_pool_task_payload, semantic.flags, 4);
OFF(se_pool_task_payload, semantic.physical_cookie, 8);
OFF(se_pool_task_payload, semantic.scope_cookie, 16);
OFF(se_pool_task_payload, semantic.eligibility_version, 24);
OFF(se_pool_task_payload, semantic.next_invocation, 32);
OFF(se_pool_task_payload, semantic.scope_slot, 40);
OFF(se_pool_task_payload, semantic.identity_reserved, 44);
OFF(se_pool_task_payload, semantic.committed, 48);
OFF(se_pool_task_payload, semantic.staged, 568);
OFF(se_pool_task_payload, semantic.reader, 632);
OFF(se_pool_task_payload, semantic.reader_invocation, 680);
OFF(se_pool_task_payload, semantic.exec, 688);
OFF(se_pool_task_payload, reserved_extension, 960);
SIZE(se_pool_work_payload, 19456);
OFF(se_pool_work_payload, semantic, 0);
OFF(se_pool_work_payload, semantic.scope, 0);
OFF(se_pool_work_payload, semantic.cookie, 8);
OFF(se_pool_work_payload, semantic.sequence, 16);
OFF(se_pool_work_payload, semantic.slot, 24);
OFF(se_pool_work_payload, semantic.reserved, 28);
OFF(se_pool_work_payload, semantic.view, 32);
OFF(se_pool_work_payload, semantic.history, 936);
OFF(se_pool_work_payload, semantic.inherited, 2640);
OFF(se_pool_work_payload, semantic.observation, 3176);
OFF(se_pool_work_payload, catalogue, 19184);
#else
OFF(se_pool_task_payload, reserved_lock, 0);
OFF(se_pool_task_payload, flags, 4);
OFF(se_pool_task_payload, physical_cookie, 8);
OFF(se_pool_task_payload, scope_cookie, 16);
OFF(se_pool_task_payload, eligibility_version, 24);
OFF(se_pool_task_payload, next_invocation, 32);
OFF(se_pool_task_payload, scope_slot, 40);
OFF(se_pool_task_payload, identity_reserved, 44);
OFF(se_pool_task_payload, committed, 48);
OFF(se_pool_task_payload, staged, 568);
OFF(se_pool_task_payload, reader, 632);
OFF(se_pool_task_payload, reader_invocation, 680);
OFF(se_pool_task_payload, exec, 688);
OFF(se_pool_task_payload, reserved_extension, 960);
SIZE(se_pool_work_payload, 19456);
OFF(se_pool_work_payload, scope, 0);
OFF(se_pool_work_payload, cookie, 8);
OFF(se_pool_work_payload, sequence, 16);
OFF(se_pool_work_payload, slot, 24);
OFF(se_pool_work_payload, reserved, 28);
OFF(se_pool_work_payload, view, 32);
OFF(se_pool_work_payload, history, 936);
OFF(se_pool_work_payload, inherited, 2640);
OFF(se_pool_work_payload, observation, 3176);
OFF(se_pool_work_payload, reserved_extension, 19184);
#endif
_Static_assert(_Alignof(struct se_pool_task_payload) == 8 &&
		       _Alignof(struct se_pool_work_payload) == 8,
	       "payload alignment");
_Static_assert(sizeof(struct se_invocation) == 19184,
	       "existing work semantic size");
_Static_assert(sizeof(struct se_task_state) == 960,
	       "existing task semantic size");

#ifndef SE_PROFILE_TASKS
#error "pool task capacity is required"
#endif
#ifndef SE_PROFILE_SCRATCH
#error "pool work capacity is required"
#endif
#ifndef SE_PROFILE_BINDINGS
#error "pool account count is required"
#endif
#ifndef SE_PROFILE_TASK_QUOTA
#error "pool task partition is required"
#endif
#ifndef SE_PROFILE_SCRATCH_QUOTA
#error "pool work partition is required"
#endif
#define SE_POOL_T SE_PROFILE_TASKS
#define SE_POOL_W SE_PROFILE_SCRATCH
#define SE_POOL_B SE_PROFILE_BINDINGS
#define SE_POOL_QT SE_PROFILE_TASK_QUOTA
#define SE_POOL_QW SE_PROFILE_SCRATCH_QUOTA
#define SE_POOL_CEIL(a, b) (((a) + (b) - 1u) / (b))
#define SE_POOL_BUCKET_NEED SE_POOL_CEIL(SE_POOL_T, 4u)
#if SE_POOL_BUCKET_NEED <= 1u
#define SE_POOL_D 1u
#elif SE_POOL_BUCKET_NEED <= 2u
#define SE_POOL_D 2u
#elif SE_POOL_BUCKET_NEED <= 4u
#define SE_POOL_D 4u
#elif SE_POOL_BUCKET_NEED <= 8u
#define SE_POOL_D 8u
#elif SE_POOL_BUCKET_NEED <= 16u
#define SE_POOL_D 16u
#elif SE_POOL_BUCKET_NEED <= 32u
#define SE_POOL_D 32u
#elif SE_POOL_BUCKET_NEED <= 64u
#define SE_POOL_D 64u
#elif SE_POOL_BUCKET_NEED <= 128u
#define SE_POOL_D 128u
#elif SE_POOL_BUCKET_NEED <= 256u
#define SE_POOL_D 256u
#elif SE_POOL_BUCKET_NEED <= 512u
#define SE_POOL_D 512u
#elif SE_POOL_BUCKET_NEED <= 1024u
#define SE_POOL_D 1024u
#elif SE_POOL_BUCKET_NEED <= 2048u
#define SE_POOL_D 2048u
#elif SE_POOL_BUCKET_NEED <= 4096u
#define SE_POOL_D 4096u
#elif SE_POOL_BUCKET_NEED <= 8192u
#define SE_POOL_D 8192u
#elif SE_POOL_BUCKET_NEED <= 16384u
#define SE_POOL_D 16384u
#elif SE_POOL_BUCKET_NEED <= 32768u
#define SE_POOL_D 32768u
#elif SE_POOL_BUCKET_NEED <= 65536u
#define SE_POOL_D 65536u
#elif SE_POOL_BUCKET_NEED <= 131072u
#define SE_POOL_D 131072u
#elif SE_POOL_BUCKET_NEED <= 262144u
#define SE_POOL_D 262144u
#elif SE_POOL_BUCKET_NEED <= 524288u
#define SE_POOL_D 524288u
#elif SE_POOL_BUCKET_NEED <= 1048576u
#define SE_POOL_D 1048576u
#elif SE_POOL_BUCKET_NEED <= 2097152u
#define SE_POOL_D 2097152u
#elif SE_POOL_BUCKET_NEED <= 4194304u
#define SE_POOL_D 4194304u
#elif SE_POOL_BUCKET_NEED <= 8388608u
#define SE_POOL_D 8388608u
#elif SE_POOL_BUCKET_NEED <= 16777216u
#define SE_POOL_D 16777216u
#elif SE_POOL_BUCKET_NEED <= 33554432u
#define SE_POOL_D 33554432u
#elif SE_POOL_BUCKET_NEED <= 67108864u
#define SE_POOL_D 67108864u
#elif SE_POOL_BUCKET_NEED <= 134217728u
#define SE_POOL_D 134217728u
#elif SE_POOL_BUCKET_NEED <= 268435456u
#define SE_POOL_D 268435456u
#elif SE_POOL_BUCKET_NEED <= 536870912u
#define SE_POOL_D 536870912u
#elif SE_POOL_BUCKET_NEED <= 1073741824u
#define SE_POOL_D 1073741824u
#else
#error "pool directory exceeds addressable capacity"
#endif
#define SE_POOL_TASK_WORDS SE_POOL_CEIL(SE_POOL_QT, 64u)
#define SE_POOL_WORK_WORDS SE_POOL_CEIL(SE_POOL_QW, 64u)
struct se_pool_bitmap {
	struct se_pool_bitmap_header header;
	__u64 words[SE_POOL_TASK_WORDS + SE_POOL_WORK_WORDS];
};
struct se_pool_sequence {
	struct bpf_spin_lock lock;
	__u32 reserved;
	__u64 next;
};
SIZE(se_pool_sequence, 16);
OFF(se_pool_sequence, lock, 0);
OFF(se_pool_sequence, reserved, 4);
OFF(se_pool_sequence, next, 8);
_Static_assert(sizeof(struct se_pool_bitmap) ==
		       16 + 8 * (SE_POOL_TASK_WORDS + SE_POOL_WORK_WORDS),
	       "bitmap formula");
_Static_assert(__builtin_offsetof(struct se_pool_bitmap, words) == 16,
	       "bitmap words");
_Static_assert(SE_POOL_T > 0 && SE_POOL_W > 0 && SE_POOL_B > 0 &&
		       SE_POOL_QT > 0 && SE_POOL_QW > 0,
	       "pool nonzero");
_Static_assert((__u64)SE_POOL_B *SE_POOL_QT <= SE_POOL_T &&
		       (__u64)SE_POOL_B * SE_POOL_QW <= SE_POOL_W,
	       "partition capacity");
_Static_assert((SE_POOL_D & (SE_POOL_D - 1u)) == 0 &&
		       SE_POOL_D >= SE_POOL_BUCKET_NEED,
	       "directory power of two");
_Static_assert((__u64)SE_POOL_T + SE_POOL_W <= 0xffffffffULL, "charge entries");

#define SE_POOL_ARRAY(name, V, count, flags)      \
	struct {                                  \
		__uint(type, BPF_MAP_TYPE_ARRAY); \
		__uint(max_entries, count);       \
		__uint(map_flags, flags);         \
		__type(key, __u32);               \
		__type(value, V);                 \
	} name SEC(".maps")
/* Kernel-owned pool state is userspace-readonly at creation. Spinlock-bearing
 * ARRAY values cannot rely on BPF_MAP_FREEZE on the tested kernels. */
SE_POOL_ARRAY(se_pool_task_meta, struct se_pool_task_meta, SE_POOL_T,
	      BPF_F_RDONLY);
SE_POOL_ARRAY(se_pool_task_payload, struct se_pool_task_payload, SE_POOL_T,
	      BPF_F_RDONLY);
SE_POOL_ARRAY(se_pool_work_meta, struct se_pool_work_meta, SE_POOL_W,
	      BPF_F_RDONLY);
SE_POOL_ARRAY(se_pool_work_payload, struct se_pool_work_payload, SE_POOL_W,
	      BPF_F_RDONLY);
SE_POOL_ARRAY(se_pool_charges, struct se_pool_charge, SE_POOL_T + SE_POOL_W,
	      BPF_F_RDONLY);
SE_POOL_ARRAY(se_pool_directory, struct se_pool_directory, SE_POOL_D,
	      BPF_F_RDONLY);
SE_POOL_ARRAY(se_pool_bitmaps, struct se_pool_bitmap, SE_POOL_B, BPF_F_RDONLY);
SE_POOL_ARRAY(se_pool_task_zero, struct se_pool_task_payload, 1,
	      BPF_F_RDONLY_PROG);
SE_POOL_ARRAY(se_pool_work_zero, struct se_pool_work_payload, 1,
	      BPF_F_RDONLY_PROG);
SE_POOL_ARRAY(se_pool_sequence, struct se_pool_sequence, 1, BPF_F_RDONLY);
SE_POOL_ARRAY(se_pool_reap_request, struct se_pool_request, 1,
	      BPF_F_RDONLY_PROG);
SE_POOL_ARRAY(se_pool_reap_control, struct se_pool_control, 1, BPF_F_RDONLY);
SE_POOL_ARRAY(se_pool_reap_receipt, struct se_pool_receipt, 1, BPF_F_RDONLY);
#undef SE_POOL_ARRAY
#undef SIZE
#undef OFF
#endif
