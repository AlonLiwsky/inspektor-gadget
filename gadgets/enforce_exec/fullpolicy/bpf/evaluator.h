/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 The Inspektor Gadget authors */
#ifndef ENFORCE_EXEC_FULLPOLICY_EVALUATOR_H
#define ENFORCE_EXEC_FULLPOLICY_EVALUATOR_H
#include "matcher.h"
#if defined(FM_GLOBAL_BLOB_LOOKUP) || defined(FM_GLOBAL_SCALAR_BLOB_LOOKUP)
#define FE_GLOBAL_MATCHER 1
#endif
/* Ordinary BPF images retain ABI2 behavior. Host oracle fixtures exercise the
 * development semantics; they do not authorize live selection. */
#if defined(ENFORCE_EXEC_ABI3_DEVELOPMENT) || !defined(__bpf__)
#define FE_AUDIT_ISOLATION 1
#endif
#define FE_INLINE static __attribute__((always_inline)) inline
/* Same-register signed errno clamp proved by the Gate-A ingress fixture.
 * A valid prior LSM denial is preserved; malformed nonzero input cannot allow.
 * Keep the return type long: an int return can lose the verifier's signed bound. */
FE_INLINE long fe_lsm_result(int prior)
{
	long result = prior;
#ifdef __BPF__
	__asm__ __volatile__("%[value] <<= 32;\n"
			     "%[value] s>>= 32;\n"
			     "if %[value] s> 0 goto 1f;\n"
			     "if %[value] s>= -4095 goto 2f;\n"
			     "1: %[value] = -1;\n"
			     "2:\n"
			     : [value] "+r"(result));
#else
	if (result < -4095 || result > 0)
		result = -1;
#endif
	return result;
}

#if defined(FE_BOUNDED_LOOP_CANDIDATE)
#define FE_LOOP(count, callback, context) \
	FM_BOUND_LOOP(count, callback, context)
#elif defined(__bpf__)
#define FE_LOOP(count, callback, context) \
	fm_bpf_loop(count, callback, context, 0)
#else
#define FE_LOOP(count, callback, context) fm_c_loop(count, callback, context)
#endif

/* This evaluator consumes authoritative facts only. It neither observes tasks
 * nor bootstraps roles. The caller owns private scratch for the entire call;
 * per-CPU storage is unsafe across sleepable operations. Blobs must be immutable.
 * argv is a canonical NUL-separated vector, with offsets into argv_bytes.
 */
struct fe_path {
	fm_u32 length;
	fm_u8 bytes[256];
};
struct fe_role {
	fm_u64 policy_uid, role;
};
struct fe_facts {
	struct fe_path actor_path, target_path;
	int actor_image, target_image;
	fm_u32 effective_uid, uid_known;
	struct fe_path ancestors[16];
	fm_u32 ancestor_count, ancestors_complete;
	struct fe_role roles[8];
	fm_u32 role_count, fs_mask,
		fs_known; /* fs_known: per-class FE_* mask */
	fm_u8 argv[4096];
	fm_u32 argc, argv_offsets[64], argv_bytes, argv_complete;
	int stdin_pipe;
};
enum { FE_TMPFS = 1, FE_MEMFD = 2, FE_DELETED = 4, FE_OVERLAY = 8 };
enum {
	FE_OK = 0,
	FE_INVALID = 1,
	FE_UNKNOWN = 2,
	FE_ROLE_CONFLICT = 3,
	FE_AUDIT_UNKNOWN = 4
};
/* Upper bit cancels earlier interpreter-check proposals as well as this call. */
#define FE_AUDIT_DIAGNOSTIC_MASK 0xffU
#define FE_ROLE_UNCERTAIN_SHIFT 8
#define FE_ROLE_WRITE_SHIFT 16
#define FE_AUDIT_UNCERTAIN_FALLBACK (1U << 30)
#define FE_AUDIT_GLOBAL_SUPPRESS (1U << 31)
#define FE_UNCERTAINTY_VALID_MASK \
	(0x00ffffffU | FE_AUDIT_UNCERTAIN_FALLBACK | FE_AUDIT_GLOBAL_SUPPRESS)
#define FE_ROLE_UNCERTAIN(word) (((word) >> FE_ROLE_UNCERTAIN_SHIFT) & 0xffU)
#define FE_ROLE_WRITES(word) (((word) >> FE_ROLE_WRITE_SHIFT) & 0xffU)
struct fe_decision {
	fm_u32 deny, mode;
	fm_u64 matched_rules[4], proposed_roles[8];
	fm_u32 error, audit_unknown;
#ifdef FE_AUDIT_ISOLATION
	fm_u32 enforced_writes, role_conflicts;
	/* Comparison only: never grant or export these when proposals are uncertain. */
	fm_u64 known_role_witnesses[8];
#endif
};
/* Immutable invocation class governs faults, never a partially merged mode.
 * A known audit deny remains nonblocking even in an enforcement-capable union. */
FE_INLINE long fe_lsm_verdict(fm_u32 execution_class, int prior, int error,
			      const struct fe_decision *decision)
{
	if (prior)
		return fe_lsm_result(prior);
	if (execution_class == 1)
		return 0;
	if (execution_class != 2 || error || !decision)
		return -1;
	return decision->deny && decision->mode == 2 ? -1 : 0;
}
struct fe_scratch {
	struct fm_scratch matcher;
	struct fe_decision decision;
	fm_u32 arg_lengths[64];
};
_Static_assert(sizeof(struct fe_facts) == 9216, "facts ABI");
#ifdef FE_AUDIT_ISOLATION
_Static_assert(sizeof(struct fe_decision) == 184, "development decision ABI");
_Static_assert(__builtin_offsetof(struct fe_decision, known_role_witnesses) ==
		       120,
	       "comparison-only witness ABI");
_Static_assert(__builtin_offsetof(struct fe_decision, enforced_writes) == 112,
	       "enforced provenance ABI");
_Static_assert(__builtin_offsetof(struct fe_decision, role_conflicts) == 116,
	       "conflict provenance ABI");
_Static_assert(sizeof(struct fe_scratch) == 2688,
	       "development evaluator scratch ABI");
#else
_Static_assert(sizeof(struct fe_decision) == 112, "decision ABI");
_Static_assert(sizeof(struct fe_scratch) == 2616, "evaluator scratch ABI");
#endif
_Static_assert(__builtin_offsetof(struct fe_decision, error) == 104,
	       "error ABI");
_Static_assert(__builtin_offsetof(struct fe_decision, audit_unknown) == 108,
	       "uncertainty uses decision padding");
struct fe_header {
	fm_u64 generation;
	fm_u32 policies, rule_base, rules, container;
};
/* root_epoch is owner metadata used by trusted role-fact acquisition; the
 * evaluator never bootstraps a missing role from it. */
struct fe_policy {
	fm_u64 uid, root_role;
	fm_u32 fallback, mode;
	fm_u64 root_epoch;
};
_Static_assert(sizeof(struct fe_policy) == 32, "policy prefix ABI");
struct fe_list {
	fm_u32 base, count;
};
struct fe_rule {
	fm_u32 policy, mode, deny;
	int actor_image, target_image, stdin_pipe;
	fm_u32 ancestor_depth, reserved;
	fm_u64 set_role;
	struct fe_list actor_path, target_path, ancestor_path, actor_role, uid,
		container, fs_type, arg_contains, arg_prefix;
};
struct fe_string {
	fm_u32 length;
	fm_u8 bytes[256];
};
_Static_assert(sizeof(struct fe_rule) == 112, "rule prefix ABI");
_Static_assert(sizeof(struct fe_header) == 24, "header prefix ABI");

FE_INLINE const struct fm_blob *fe_blob(void *ctx, fm_u32 key)
{
	if (key >= FM_MAX_ENTRIES)
		return 0;
#ifdef FE_GLOBAL_MATCHER
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	const struct fm_global_token *token = ctx;
	if (!token || token->reserved || !token->cookie)
		return 0;
	return FM_GLOBAL_SCALAR_BLOB_LOOKUP(token->slot, token->cookie, key);
#else
	(void)ctx;
	return FM_GLOBAL_BLOB_LOOKUP(key);
#endif
#else
	return FM_BLOB_LOOKUP(ctx, key);
#endif
}
/* Typed structural lookups keep scope-neutral object-local data keys separate
 * from the whole policy-set index space. Defaults preserve the legacy image.
 * Only the shared rule accessor may select an object; data/matcher lookups
 * retain that immutable selection through the complete rule evaluation. */
#ifndef FE_HEADER_LOOKUP
#define FE_HEADER_LOOKUP(ctx) ((const struct fe_header *)fe_blob((ctx), 0))
#endif
#ifndef FE_POLICY_LOOKUP
#define FE_POLICY_LOOKUP(ctx, index) \
	((const struct fe_policy *)fe_blob((ctx), 1 + (index)))
#endif
#ifndef FE_RULE_LOOKUP
#define FE_RULE_LOOKUP(ctx, index) \
	((const struct fe_rule *)fe_blob((ctx), 9 + (index)))
#endif
#ifndef FE_CONTAINER_LOOKUP
FE_INLINE const struct fe_string *fe_container_lookup(void *ctx)
{
	const struct fe_header *h = FE_HEADER_LOOKUP(ctx);
	return h ? (const struct fe_string *)fe_blob(ctx, h->container) : 0;
}
#define FE_CONTAINER_LOOKUP(ctx) fe_container_lookup(ctx)
#endif
/* Full immutable-program classification, independent of facts or match order.
 * The owner latches this only while holding the admitted program read lease. */
struct fe_class_context {
	void *blob_context;
	fm_u32 policies, execution_class, invalid, role_writers;
};
static long fe_class_rule(fm_u32 i, void *opaque)
{
	struct fe_class_context *c = opaque;
	if (i >= 256) {
		c->invalid = 1;
		return 1;
	}
	const struct fe_rule *r = FE_RULE_LOOKUP(c->blob_context, i);
	if (!r || r->policy >= c->policies || r->mode < 1 || r->mode > 2) {
		c->invalid = 1;
		return 1;
	}
	if (r->mode > c->execution_class)
		c->execution_class = r->mode;
	if (r->set_role)
		c->role_writers |= 1U << r->policy;
	return 0;
}
FE_INLINE int fe_execution_class(void *blob_context, fm_u64 generation,
				 fm_u32 *policies, fm_u32 *role_writers)
{
	const struct fe_header *h = FE_HEADER_LOOKUP(blob_context);
	if (!h || h->generation != generation || !h->policies ||
	    h->policies > 8 || h->rules > 256 || h->rule_base != 9)
		return -1;
	struct fe_class_context c = { blob_context, h->policies, 1, 0, 0 };
	for (fm_u32 i = 0; i < 8; i++) {
		if (i >= h->policies)
			break;
		const struct fe_policy *p = FE_POLICY_LOOKUP(blob_context, i);
		if (!p || p->mode < 1 || p->mode > 2)
			return -1;
		if (p->mode > c.execution_class)
			c.execution_class = p->mode;
	}
	if (FE_LOOP(h->rules, fe_class_rule, &c) < 0 || c.invalid)
		return -1;
	*policies = h->policies;
	*role_writers = c.role_writers;
	return c.execution_class;
}
FE_INLINE int fe_list_valid(struct fe_list list)
{
	return list.count <= 256 && list.base < FM_MAX_ENTRIES &&
	       list.count <= FM_MAX_ENTRIES - list.base;
}
struct fe_bytes_context {
	const fm_u8 *left, *right;
	fm_u32 length;
	int equal;
};
static long fe_bytes_step(fm_u32 i, void *opaque)
{
	struct fe_bytes_context *c = opaque;
	if (i >= 255 || i >= c->length)
		return 1;
	if (c->left[i] != c->right[i]) {
		c->equal = 0;
		return 1;
	}
	return 0;
}
FE_INLINE
int fe_bytes_equal(const fm_u8 *a, const fm_u8 *b, fm_u32 length)
{
	if (!a || !b || length > 255)
		return -1;
#if defined(__bpf__) && defined(FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC)
	/* Keep the physical byte bound visible to older verifiers. The generic
	 * 512-step loop loses its correlation with a 255-byte map string. */
	for (fm_u32 i = 0; i < 255; i++) {
		if (i >= length)
			break;
		if (a[i] != b[i])
			return 0;
	}
	return 1;
#else
	struct fe_bytes_context c = { a, b, length, 1 };
	if (FE_LOOP(length, fe_bytes_step, &c) < 0)
		return -1;
	return c.equal;
#endif
}
struct fe_path_check {
	const struct fe_path *path;
	fm_u32 offset;
	int error;
};
static long fe_path_byte(fm_u32 i, void *opaque)
{
	(void)i;
	struct fe_path_check *c = opaque;
	if (c->offset >= c->path->length)
		return 1;
	fm_u32 rune = 0, width = 0;
	if (fm_decode(c->path->bytes, c->path->length, c->offset, &rune,
		      &width)) {
		c->error = 1;
		return 1;
	}
	c->offset += width;
	return 0;
}
#if defined(__bpf__) && defined(FE_BOUNDED_LOOP_CANDIDATE)
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_path_valid(const struct fe_path *path)
{
	if (!path || path->length > 255)
		return 0;
	struct fe_path_check c = { path, 0, 0 };
	if (FE_LOOP(255, fe_path_byte, &c) < 0)
		return 0;
	return !c.error && c.offset == path->length;
}
struct fe_paths_check {
	const struct fe_facts *facts;
	int error;
};
static long fe_ancestor_valid(fm_u32 i, void *opaque)
{
	struct fe_paths_check *c = opaque;
	if (i >= 16 || i >= c->facts->ancestor_count)
		return 1;
	if (!fe_path_valid(&c->facts->ancestors[i])) {
		c->error = 1;
		return 1;
	}
	return 0;
}
/* Validate the full vector before matching, including arguments not consulted
 * by a successful alternative. Zero lengths are valid empty arguments. */
struct fe_argv_check {
	const struct fe_facts *facts;
	struct fe_scratch *scratch;
	fm_u32 block, argument, start;
	int error;
};
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
#define FE_ARGV_BLOCK_BYTES 16U
#define FE_ARGV_BLOCKS (4096U / FE_ARGV_BLOCK_BYTES)
#else
#define FE_ARGV_BLOCK_BYTES 256U
#define FE_ARGV_BLOCKS 16U
#endif
static long fe_argv_byte(fm_u32 i, void *opaque)
{
	struct fe_argv_check *c = opaque;
	fm_u64 offset = (fm_u64)c->block * FE_ARGV_BLOCK_BYTES + i;
	if (i >= FE_ARGV_BLOCK_BYTES || offset >= 4096 ||
	    offset >= c->facts->argv_bytes)
		return 1;
	if (c->facts->argv[offset])
		return 0;
	fm_u32 arg = c->argument;
	if (arg >= 64 || arg >= c->facts->argc ||
	    c->facts->argv_offsets[arg] != c->start) {
		c->error = 1;
		return 1;
	}
	c->scratch->arg_lengths[arg] = offset - c->start;
	c->argument++;
	c->start = offset + 1;
	return 0;
}
#if !defined(FE_BOUNDED_LOOP_CANDIDATE)
static long fe_argv_block(fm_u32 i, void *opaque)
{
	struct fe_argv_check *c = opaque;
	if (i >= 16 || c->error)
		return 1;
	c->block = i;
	if (FE_LOOP(256, fe_argv_byte, c) < 0)
		c->error = 1;
	return c->error ? 1 : 0;
}
#else
struct fe_argv_scan_state {
	fm_u32 argument, start;
	int error;
};
/* The verifier must not expand all 4,096 data-dependent byte branches in one
 * subprogram. Transfer only scalar state across 256-byte compartments. */
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_argv_scan_block(const struct fe_facts *f, struct fe_scratch *s,
		       fm_u32 block, struct fe_argv_scan_state *state)
{
	if (!f || !s || !state || block >= FE_ARGV_BLOCKS || state->error)
		return -1;
	struct fe_argv_check c = {
		.facts = f,
		.scratch = s,
		.block = block,
		.argument = state->argument,
		.start = state->start,
	};
	if (FE_LOOP(FE_ARGV_BLOCK_BYTES, fe_argv_byte, &c) < 0 || c.error)
		state->error = 1;
	state->argument = c.argument;
	state->start = c.start;
	return state->error ? -1 : 0;
}
#endif
/* Independently verify the4096-byte scan; do not expand its nested callbacks
 * under every rule/predicate state. Both arguments are bounded typed memory. */
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_argv_valid(const struct fe_facts *f, struct fe_scratch *s)
{
	if (!f || !s || !f->argv_complete || f->argc > 64 ||
	    f->argv_bytes > 4096)
		return 0;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
	struct fe_argv_scan_state state = {};
	for (fm_u32 block = 0; block < FE_ARGV_BLOCKS; block++) {
		if (fe_argv_scan_block(f, s, block, &state) < 0)
			return 0;
	}
	return !state.error && state.argument == f->argc &&
	       state.start == f->argv_bytes;
#else
	struct fe_argv_check c = { .facts = f, .scratch = s };
	if (FE_LOOP(16, fe_argv_block, &c) < 0)
		return 0;
	return !c.error && c.argument == f->argc && c.start == f->argv_bytes;
#endif
}
enum { FE_PATH, FE_VALUE, FE_STRING, FE_FS, FE_ARG_EXACT, FE_ARG_PREFIX };
struct fe_match_context {
	void *blob_context;
	const struct fe_facts *facts;
	struct fe_scratch *scratch;
	struct fe_list list;
	const struct fe_path *path;
	const struct fe_string *string;
	fm_u32 string_key;
	fm_u32 path_selector;
	fm_u64 value;
	fm_u32 kind;
	int result;
};
#if defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FE_GLOBAL_MATCHER)
/* Reacquire both frozen policy strings inside this verifier compartment.
 * Passing a readonly map-value pointer to a noinline BPF subprogram makes
 * the verifier treat it as writable despite C const qualification. */
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_bytes_equal_keys(
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	fm_u32 slot, fm_u64 cookie,
#endif
	fm_u32 left_key, fm_u32 right_key, fm_u32 length)
{
	if (length > 255 || left_key >= FM_MAX_ENTRIES ||
	    right_key >= FM_MAX_ENTRIES)
		return -1;
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	struct fm_global_token token = { .slot = slot, .cookie = cookie };
	void *ctx = &token;
#else
	void *ctx = 0;
#endif
	const struct fe_string *left = (const void *)fe_blob(ctx, left_key);
	const struct fe_string *right = (const void *)fe_blob(ctx, right_key);
	if (!left || !right || left->length < length || right->length < length)
		return -1;
	return fe_bytes_equal(left->bytes, right->bytes, length);
}
#endif
#if !(defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FE_GLOBAL_MATCHER))
struct fe_argument_bytes {
	const struct fe_facts *facts;
	const struct fe_string *value;
	fm_u32 offset, length;
	int equal;
};
static long fe_argument_byte(fm_u32 i, void *opaque)
{
	struct fe_argument_bytes *c = opaque;
	if (i >= 255 || i >= c->length)
		return 1;
	fm_u64 offset = (fm_u64)c->offset + i;
	__asm__ __volatile__("" : "+r"(offset));
	if (offset >= 4096) {
		c->equal = -1;
		return 1;
	}
	if (c->facts->argv[offset] != c->value->bytes[i]) {
		c->equal = 0;
		return 1;
	}
	return 0;
}
struct fe_arg_context {
	const struct fe_facts *facts;
	struct fe_scratch *scratch;
	const struct fe_string *value;
	fm_u32 kind;
	int result;
};
static long fe_arg_step(fm_u32 i, void *opaque)
{
	struct fe_arg_context *c = opaque;
	const struct fe_facts *f = c->facts;
	if (i >= 64 || i >= f->argc)
		return 1;
	fm_u32 len = c->value->length, offset = f->argv_offsets[i];
	fm_u32 actual = c->scratch->arg_lengths[i];
	if (len > actual || (c->kind == FE_ARG_EXACT && len != actual))
		return 0;
	if (offset >= 4096 || len > 4096 - offset || len > 255) {
		c->result = -1;
		return 1;
	}
	struct fe_argument_bytes bytes = { f, c->value, offset, len, 1 };
	if (FE_LOOP(255, fe_argument_byte, &bytes) < 0)
		bytes.equal = -1;
	if (bytes.equal) {
		c->result = bytes.equal;
		return 1;
	}
	return 0;
}
#endif
#if defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FE_GLOBAL_MATCHER)
struct fe_arg_request {
	fm_u64 cookie;
	fm_u32 slot, string_key, kind;
};
/* Resolve immutable string data inside the typed global boundary; never pass
 * a readonly blob pointer from the caller. One argument is checked in full. */
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_arg_one_global(const struct fe_facts *facts,
		      const struct fe_scratch *scratch,
		      const struct fe_arg_request *request, fm_u32 argument)
{
	if (!facts || !scratch || !request || facts->argc > 64 ||
	    request->string_key >= FM_MAX_ENTRIES ||
	    (request->kind != FE_ARG_EXACT && request->kind != FE_ARG_PREFIX))
		return -1;
	__asm__ __volatile__("" : "+r"(argument));
	if (argument >= 64 || argument >= facts->argc)
		return 0;
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	struct fm_global_token token = {
		.slot = request->slot,
		.cookie = request->cookie,
	};
	void *context = &token;
#else
	void *context = 0;
#endif
	const struct fe_string *value =
		(const struct fe_string *)fe_blob(context, request->string_key);
	if (!value || value->length > 255)
		return -1;
	fm_u32 length = value->length;
	fm_u32 offset = facts->argv_offsets[argument];
	fm_u32 actual = scratch->arg_lengths[argument];
	if (length > actual ||
	    (request->kind == FE_ARG_EXACT && length != actual))
		return 0;
	if (offset >= 4096 || length > 4096 - offset)
		return -1;
	for (fm_u32 i = 0; i < 255; i++) {
		if (i >= length)
			break;
		fm_u64 position = (fm_u64)offset + i;
		__asm__ __volatile__("" : "+r"(position));
		if (position >= 4096)
			return -1;
		if (facts->argv[position] != value->bytes[i])
			return 0;
	}
	return 1;
}
#endif
/* Keep the64-argument scan independent of rule/list verifier state. The byte
 * callback indexes the full argv array with an explicit absolute bound: an
 * interior argv pointer is not falsely advertised as256 readable bytes. */
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_match_arguments(const struct fe_facts *facts, struct fe_scratch *scratch,
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
		       fm_u32 string_key, fm_u32 kind,
		       const struct fm_global_token *token)
#elif defined(FE_GLOBAL_MATCHER)
		       fm_u32 string_key, fm_u32 kind)
#else
		       const struct fe_string *value, fm_u32 kind)
#endif
{
#ifdef FE_GLOBAL_MATCHER
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	const struct fe_string *value =
		(const struct fe_string *)fe_blob((void *)token, string_key);
#else
	const struct fe_string *value =
		(const struct fe_string *)fe_blob(0, string_key);
#endif
#endif
	if (!facts || !scratch || !value || facts->argc > 64 ||
	    value->length > 255 ||
	    (kind != FE_ARG_EXACT && kind != FE_ARG_PREFIX))
		return -1;
#if defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FE_GLOBAL_MATCHER)
	struct fe_arg_request request = {
		.string_key = string_key,
		.kind = kind,
	};
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	if (!token || token->reserved || !token->cookie)
		return -1;
	request.slot = token->slot;
	request.cookie = token->cookie;
#endif
	for (fm_u32 i = 0; i < 64; i++) {
		if (i >= facts->argc)
			break;
		int result = fe_arg_one_global(facts, scratch, &request, i);
		if (result)
			return result;
	}
	return 0;
#else
	struct fe_arg_context c = { facts, scratch, value, kind, 0 };
	if (FE_LOOP(64, fe_arg_step, &c) < 0)
		return -1;
	return c.result;
#endif
}
FE_INLINE fm_u32 fe_fs_bit(const struct fe_string *s)
{
	if (s->length == 5 && s->bytes[0] == 't' && s->bytes[1] == 'm' &&
	    s->bytes[2] == 'p' && s->bytes[3] == 'f' && s->bytes[4] == 's')
		return FE_TMPFS;
	if (s->length == 5 && s->bytes[0] == 'm' && s->bytes[1] == 'e' &&
	    s->bytes[2] == 'm' && s->bytes[3] == 'f' && s->bytes[4] == 'd')
		return FE_MEMFD;
	if (s->length == 7 && s->bytes[0] == 'd' && s->bytes[1] == 'e' &&
	    s->bytes[2] == 'l' && s->bytes[3] == 'e' && s->bytes[4] == 't' &&
	    s->bytes[5] == 'e' && s->bytes[6] == 'd')
		return FE_DELETED;
	if (s->length == 7 && s->bytes[0] == 'o' && s->bytes[1] == 'v' &&
	    s->bytes[2] == 'e' && s->bytes[3] == 'r' && s->bytes[4] == 'l' &&
	    s->bytes[5] == 'a' && s->bytes[6] == 'y')
		return FE_OVERLAY;
	return 0;
}
#if defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FE_GLOBAL_MATCHER)
/* No map-value or nested stack pointers cross this global verifier boundary.
 * The caller owns the immutable WORK lease; each alternative reacquires its
 * blob using the same scalar selection. A selector is 0=actor, 1=target,
 * 2..17=ancestor index. */
struct fe_alt_request {
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
	/* The retained WORK carries the exact scalar token and request together;
	 * nested matcher calls borrow it without a callback-local token copy. */
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
	struct fm_work_run_request matcher;
#else
	struct fm_global_token token;
#endif
	fm_u64 value;
	fm_u32 kind, path_selector, string_key;
#else
	fm_u64 cookie, value;
	fm_u32 slot, kind, path_selector, string_key;
#endif
};
#if defined(FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC) && \
	!defined(FM_WORK_RUN_STATE_DIAGNOSTIC)
_Static_assert(sizeof(struct fe_alt_request) == 40,
	       "staged alternative request contains scalar identity only");
#elif defined(FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC) && \
	defined(FM_WORK_RUN_STATE_DIAGNOSTIC)
_Static_assert(sizeof(struct fe_alt_request) == 72 &&
		       __builtin_offsetof(struct fe_alt_request, matcher) == 0,
	       "WORK matcher request must retain scalar token prefix and state");
#endif
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_match_alternative(const struct fe_facts *facts,
			 struct fe_scratch *scratch,
			 struct fe_alt_request *request, fm_u32 key)
{
	if (!facts || !scratch || !request || key >= FM_MAX_ENTRIES)
		return -1;
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
	const struct fm_global_token *token = &request->matcher.token;
#else
	const struct fm_global_token *token = &request->token;
#endif
#else
	struct fm_global_token token = {
		.slot = request->slot,
		.cookie = request->cookie,
	};
	const struct fm_global_token *token_ptr = &token;
#endif
	void *context = (void *)
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
			&request->matcher;
#else
		token;
#endif
#else
		token_ptr;
#endif
#else
	void *context = 0;
#endif
	const struct fm_blob *blob = fe_blob(context, key);
	if (!blob)
		return -1;
	if (request->kind == FE_PATH) {
		const struct fe_path *path = 0;
		if (request->path_selector == 0)
			path = &facts->actor_path;
		else if (request->path_selector == 1)
			path = &facts->target_path;
		else if (request->path_selector >= 2) {
			fm_u32 ancestor = request->path_selector - 2;
			__asm__ __volatile__("" : "+r"(ancestor));
			if (ancestor < 16 && ancestor < facts->ancestor_count)
				path = &facts->ancestors[ancestor];
		}
		if (!path || !path->length)
			return -1;
		return fm_match_key(context, key, path->bytes, path->length,
				    &scratch->matcher);
	}
	if (request->kind == FE_VALUE)
		return blob->words[0] == request->value;
	const struct fe_string *string = (const void *)blob;
	if (string->length > 255)
		return -1;
	if (request->kind == FE_STRING) {
		const struct fe_string *container =
			(const void *)fe_blob(context, request->string_key);
		if (!container || container->length > 255)
			return -1;
		if (string->length != container->length)
			return 0;
		return fe_bytes_equal_keys(
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
			request->matcher.token.slot,
			request->matcher.token.cookie,
#else
			request->token.slot, request->token.cookie,
#endif
#else
			request->slot, request->cookie,
#endif
#endif
			key, request->string_key, string->length);
	}
	if (request->kind == FE_FS) {
		fm_u32 bit = fe_fs_bit(string);
		return bit && (facts->fs_known & bit) ?
			       !!(facts->fs_mask & bit) :
			       -1;
	}
	if (request->kind != FE_ARG_EXACT && request->kind != FE_ARG_PREFIX)
		return -1;
	return fe_match_arguments(facts, scratch, key, request->kind
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
				  ,
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
				  token
#else
				  token_ptr
#endif
#endif
	);
}
/* Reuse the independently checked alternative across the complete 256-entry
 * list. The request carries only scalar selection; no readonly blob pointer
 * crosses a global-function boundary. */
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_match_list_global(const struct fe_facts *facts,
			 struct fe_scratch *scratch,
			 struct fe_alt_request *request,
			 fm_u32 base, fm_u32 count)
{
	struct fe_list list = { .base = base, .count = count };
	if (!facts || !scratch || !request || !fe_list_valid(list))
		return -1;
	if (!count)
		return 1;
	int unknown_fs = 0;
	for (fm_u32 i = 0; i < 256; i++) {
		if (i >= count)
			break;
		int result =
			fe_match_alternative(facts, scratch, request, base + i);
		if (request->kind == FE_FS && result < 0) {
			unknown_fs = 1;
			continue;
		}
		if (result)
			return result;
	}
	return unknown_fs ? -1 : 0;
}
#endif
#if !(defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FE_GLOBAL_MATCHER))
#if defined(__bpf__) && defined(FE_BOUNDED_LOOP_CANDIDATE)
static
	__attribute__((noinline))
#else
static
#endif
	long
	fe_match_step(fm_u32 i, void *opaque)
{
	struct fe_match_context *c = opaque;
	if (i >= 256 || i >= c->list.count)
		return 1;
#if defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FE_GLOBAL_MATCHER)
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	if (!c->blob_context) {
		c->result = -1;
		return 1;
	}
#endif
	struct fe_alt_request request = {
		.kind = c->kind,
		.path_selector = c->path_selector,
		.string_key = c->string_key,
		.value = c->value,
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
		.slot = ((const struct fm_global_token *)c->blob_context)->slot,
		.cookie = ((const struct fm_global_token *)c->blob_context)
				  ->cookie,
#endif
	};
	int result = fe_match_alternative(c->facts, c->scratch, &request,
					  c->list.base + i);
#else
	const struct fm_blob *blob = fe_blob(c->blob_context, c->list.base + i);
	if (!blob) {
		c->result = -1;
		return 1;
	}
	int result = 0;
	if (c->kind == FE_PATH) {
		if (!c->path) {
			c->result = -1;
			return 1;
		}
		result = fm_match_key(c->blob_context, c->list.base + i,
				      c->path->bytes, c->path->length,
				      &c->scratch->matcher);
	} else if (c->kind == FE_VALUE) {
		result = blob->words[0] == c->value;
	} else {
		const struct fe_string *s = (const struct fe_string *)blob;
		if (s->length > 255) {
			c->result = -1;
			return 1;
		}
		if (c->kind == FE_STRING) {
			if (!c->string) {
				c->result = -1;
				return 1;
			}
			if (s->length == c->string->length)
#if defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FE_GLOBAL_MATCHER)
				result = fe_bytes_equal_keys(
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
					((const struct fm_global_token *)
						 c->blob_context)
						->slot,
					((const struct fm_global_token *)
						 c->blob_context)
						->cookie,
#endif
					c->list.base + i, c->string_key,
					s->length);
#else
				result = fe_bytes_equal(
					s->bytes, c->string->bytes, s->length);
#endif
		} else if (c->kind == FE_FS) {
			fm_u32 bit = fe_fs_bit(s);
			result = bit && (c->facts->fs_known & bit) ?
					 !!(c->facts->fs_mask & bit) :
					 -1;
		} else {
#ifdef FE_GLOBAL_MATCHER
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
			result = fe_match_arguments(
				c->facts, c->scratch, c->list.base + i, c->kind,
				(const struct fm_global_token *)c->blob_context);
#else
			result = fe_match_arguments(c->facts, c->scratch,
						    c->list.base + i, c->kind);
#endif
#else
			result = fe_match_arguments(c->facts, c->scratch, s,
						    c->kind);
#endif
		}
	}
#endif
	if (c->kind == FE_FS && result < 0) {
		c->result =
			-1; /* keep looking for a known-positive OR alternative */
		return 0;
	}
	if (result) {
		c->result = result;
		return 1;
	}
	return 0;
}
FE_INLINE
int fe_match_scalar(struct fe_match_context *c, fm_u32 base, fm_u32 count,
		    fm_u32 kind)
{
	struct fe_list list = { .base = base, .count = count };
	if (!c || !fe_list_valid(list))
		return -1;
	if (!list.count)
		return 1;
	c->list = list;
	c->kind = kind;
	c->result = 0;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
	for (fm_u32 i = 0; i < list.count; i++) {
		long step = fe_match_step(i, c);
		if (step != 0 && step != 1)
			return -1;
		if (step)
			break;
	}
#else
	if (FE_LOOP(list.count, fe_match_step, c) < 0)
		return -1;
#endif
	return c->result;
}
FE_INLINE int fe_match(struct fe_match_context *c, struct fe_list list,
		       fm_u32 kind)
{
	return fe_match_scalar(c, list.base, list.count, kind);
}
#endif
#if !(defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FE_GLOBAL_MATCHER))
struct fe_ancestor_context {
	void *blob_context;
	const struct fe_facts *facts;
	struct fe_scratch *scratch;
	struct fe_list list;
	fm_u32 depth;
	int result;
};
static long fe_ancestor_step(fm_u32 i, void *opaque)
{
	struct fe_ancestor_context *c = opaque;
	if (i >= 16 || i >= c->depth || i >= c->facts->ancestor_count)
		return 1;
	struct fe_match_context match = {
		.blob_context = c->blob_context,
		.facts = c->facts,
		.scratch = c->scratch,
		.path = &c->facts->ancestors[i],
		.path_selector = 2 + i,
	};
	if (!match.path->length) {
		c->result = -1;
		return 1;
	}
	int result = fe_match(&match, c->list, FE_PATH);
	if (result) {
		c->result = result;
		return 1;
	}
	return 0;
}
#endif
struct fe_eval_context {
	void *blob_context;
	const struct fe_facts *facts;
	struct fe_scratch *scratch;
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
	/* The staged caller retains this scalar-only request in its WORK-owned
	 * post-capture workspace. No BPF pointer is stored across a tail call. */
	struct fe_alt_request *alt_request;
#endif
/* Guarded staged-tail-call stack cut: the policy header is re-read through
 * the same pinned immutable view for each rule rather than retained here. */
#ifndef FE_STAGE_RELOOKUP_HEADER_CANDIDATE
	const struct fe_header *header;
#endif
	fm_u32 matched, allow_mode, deny_mode, uncertain_deny, enforced_grants,
		role_conflicts;
#ifdef FE_AUDIT_ISOLATION
	fm_u32 uncertain_allow;
#endif
};
/* Resolve all eight policy-local role records in an independent verifier
 * compartment. Absence is unknown, never an implicit root-role bootstrap. */
#ifdef __bpf__
__attribute__((noinline))
#else
FE_INLINE
#endif
int fe_resolve_role(const struct fe_facts *facts, fm_u64 policy_uid, fm_u64 *role)
{
	if (!facts || !role || facts->role_count > 8)
		return -1;
	fm_u64 found = 0;
	for (fm_u32 i = 0; i < 8; i++) {
		if (i >= facts->role_count)
			break;
		fm_u32 role_index = i;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
		__asm__ __volatile__("" : "+r"(role_index));
		if (role_index >= 8)
			return -1;
#endif
		if (facts->roles[role_index].policy_uid != policy_uid)
			continue;
		fm_u64 candidate = facts->roles[role_index].role;
		if (found && found != candidate)
			return -1;
		found = candidate;
	}
	if (!found)
		return -1;
	*role = found;
	return 0;
}

#ifndef FE_GLOBAL_MATCHER
struct fe_predicate_context {
	struct fe_eval_context *evaluation;
	const struct fe_rule *rule;
	const struct fe_policy *policy;
	struct fe_match_context match;
	int result;
};
/* One predicate per helper callback prevents the verifier from multiplying
 * matcher states across nine sequential list callsites. Field order remains the
 * oracle's order: an unknown fact is an error only when actually consulted. */
static long fe_predicate_step(fm_u32 index, void *opaque)
{
	struct fe_predicate_context *pc = opaque;
	struct fe_eval_context *e = pc->evaluation;
	const struct fe_rule *r = pc->rule;
	const struct fe_facts *f = e->facts;
	struct fe_match_context *c = &pc->match;
	struct fe_list list = {};
	fm_u32 kind = FE_VALUE;
	int result = 1;
	switch (index) {
	case 0:
	case 1:
		if (index == 0) {
			list = r->actor_path;
			c->path = &f->actor_path;
		} else {
			list = r->target_path;
			c->path = &f->target_path;
		}
		if (list.count && !c->path->length)
			goto unknown;
		kind = FE_PATH;
		break;
	case 2:
		list = r->actor_role;
		if (list.count &&
		    fe_resolve_role(f, pc->policy->uid, &c->value) < 0)
			goto unknown;
		break;
	case 3:
		list = r->container;
		kind = FE_STRING;
		if (list.count) {
			c->string = FE_CONTAINER_LOOKUP(e->blob_context);
			if (!c->string || !c->string->length ||
			    c->string->length > 255)
				goto unknown;
		}
		break;
	case 4:
		list = r->uid;
		if (list.count && !f->uid_known)
			goto unknown;
		c->value = f->effective_uid;
		break;
	case 5:
		if (r->actor_image == -1)
			return 0;
		if (f->actor_image < 0 || f->actor_image > 1)
			goto unknown;
		result = r->actor_image == f->actor_image;
		goto done;
	case 6:
		if (r->target_image == -1)
			return 0;
		if (f->target_image < 0 || f->target_image > 1)
			goto unknown;
		result = r->target_image == f->target_image;
		goto done;
	case 7:
		list = r->fs_type;
		kind = FE_FS;
		break;
	case 8: {
		if (!r->ancestor_path.count)
			return 0;
		if (!r->ancestor_depth || r->ancestor_depth > 16)
			goto unknown;
		struct fe_ancestor_context a = {
			.blob_context = e->blob_context,
			.facts = f,
			.scratch = e->scratch,
			.list = r->ancestor_path,
			.depth = r->ancestor_depth,
		};
		if (FE_LOOP(16, fe_ancestor_step, &a) < 0)
			goto unknown;
		result = a.result;
		if (!result && f->ancestor_count < r->ancestor_depth &&
		    !f->ancestors_complete)
			goto unknown;
		goto done;
	}
	case 9:
		if ((r->arg_contains.count || r->arg_prefix.count) &&
		    !fe_argv_valid(f, e->scratch))
			goto unknown;
		list = r->arg_contains;
		kind = FE_ARG_EXACT;
		break;
	case 10:
		list = r->arg_prefix;
		kind = FE_ARG_PREFIX;
		break;
	case 11:
		if (r->stdin_pipe == -1)
			return 0;
		if (f->stdin_pipe < 0 || f->stdin_pipe > 1)
			goto unknown;
		result = r->stdin_pipe == f->stdin_pipe;
		goto done;
	default:
		goto unknown;
	}
	result = fe_match(c, list, kind);
done:
	if (result != 1) {
		pc->result = result;
		return 1;
	}
	return 0;
unknown:
	pc->result = -1;
	return 1;
}
#endif
#ifdef FE_GLOBAL_MATCHER
/* Verify the complete ordered conjunction once with typed arguments. Direct
 * field sequencing removes the predicate callback frame, so ancestry plus the
 * separately verified matcher remains within eight BPF frames. */
#if defined(__bpf__) && defined(FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC)
FE_INLINE
#else
__attribute__((noinline))
#endif
int fe_rule_match_global(const struct fe_facts *f, struct fe_scratch *scratch,
			 fm_u32 rule_key,
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
			 fm_u64 policy_uid, const struct fm_global_token *token
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
			 ,
			 struct fe_alt_request *request)
#else
)
#endif
#else
						   fm_u64 policy_uid)
#endif
{
	void *blob_context = 0;
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	blob_context = (void *)token;
#endif
	/* Fetch immutable data inside this compartment. Global memory arguments
     * are treated as writable by the verifier even when declared const. */
	if (rule_key < 9 || rule_key >= 265)
		return -1;
	const struct fe_rule *r = FE_RULE_LOOKUP(blob_context, rule_key - 9);
	if (!f || !scratch || !r || f->ancestor_count > 16 ||
	    f->role_count > 8 || r->actor_image < -1 || r->actor_image > 1 ||
	    r->target_image < -1 || r->target_image > 1 || r->stdin_pipe < -1 ||
	    r->stdin_pipe > 1)
		return -1;
	const struct fe_header *header = FE_HEADER_LOOKUP(blob_context);
	if (!header)
		return -1;
	int result;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
	if (!request)
		return -1;
	*request = (struct fe_alt_request){};
#else
	struct fe_alt_request local_request = {};
	struct fe_alt_request *request = &local_request;
#endif
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	if (!token || token->reserved || !token->cookie)
		return -1;
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
	request->matcher.token = *token;
#else
	request->token = *token;
#endif
#else
	request->slot = token->slot;
	request->cookie = token->cookie;
#endif
#endif
#define FE_TEST(list, predicate)                                          \
	do {                                                              \
		request->kind = (predicate);                              \
		result = fe_match_list_global(f, scratch, request,        \
					      (list).base, (list).count); \
		if (result != 1)                                          \
			return result;                                    \
	} while (0)
#else
	struct fe_match_context c = {
		.blob_context = blob_context,
		.facts = f,
		.scratch = scratch,
	};
#define FE_TEST(list, kind)                            \
	do {                                           \
		c.blob_context = blob_context;         \
		c.facts = f;                           \
		c.scratch = scratch;                   \
		result = fe_match(&c, (list), (kind)); \
		if (result != 1)                       \
			return result;                 \
	} while (0)
#endif
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
	request->path_selector = 0;
	if (r->actor_path.count && !f->actor_path.length)
		return -1;
#else
	c.path = &f->actor_path;
	c.path_selector = 0;
	if (r->actor_path.count && !c.path->length)
		return -1;
#endif
	FE_TEST(r->actor_path, FE_PATH);
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
	request->path_selector = 1;
	if (r->target_path.count && !f->target_path.length)
		return -1;
#else
	c.path = &f->target_path;
	c.path_selector = 1;
	if (r->target_path.count && !c.path->length)
		return -1;
#endif
	FE_TEST(r->target_path, FE_PATH);
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
	if (r->actor_role.count &&
	    fe_resolve_role(f, policy_uid, &request->value) < 0)
#else
	if (r->actor_role.count && fe_resolve_role(f, policy_uid, &c.value) < 0)
#endif
		return -1;
	FE_TEST(r->actor_role, FE_VALUE);
	if (r->container.count) {
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
		const struct fe_string *container =
			FE_CONTAINER_LOOKUP(blob_context);
		request->string_key = header->container;
		if (!container || !container->length || container->length > 255)
			return -1;
#else
		c.string = FE_CONTAINER_LOOKUP(blob_context);
		c.string_key = header->container;
		if (!c.string || !c.string->length || c.string->length > 255)
			return -1;
#endif
	}
	FE_TEST(r->container, FE_STRING);
	if (r->uid.count && !f->uid_known)
		return -1;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
	request->value = f->effective_uid;
#else
	c.value = f->effective_uid;
#endif
	FE_TEST(r->uid, FE_VALUE);
	if (r->actor_image != -1) {
		if (f->actor_image < 0 || f->actor_image > 1)
			return -1;
		if (r->actor_image != f->actor_image)
			return 0;
	}
	if (r->target_image != -1) {
		if (f->target_image < 0 || f->target_image > 1)
			return -1;
		if (r->target_image != f->target_image)
			return 0;
	}
	FE_TEST(r->fs_type, FE_FS);
	if (r->ancestor_path.count) {
		if (!r->ancestor_depth || r->ancestor_depth > 16)
			return -1;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
		int found = 0;
		for (fm_u32 i = 0; i < 16; i++) {
			if (i >= r->ancestor_depth || i >= f->ancestor_count)
				break;
			if (!f->ancestors[i].length)
				return -1;
			request->path_selector = 2 + i;
			request->kind = FE_PATH;
			result = fe_match_list_global(f, scratch, request,
						      r->ancestor_path.base,
						      r->ancestor_path.count);
			if (result < 0)
				return -1;
			if (result == 1) {
				found = 1;
				break;
			}
		}
		if (!found) {
			if (f->ancestor_count < r->ancestor_depth &&
			    !f->ancestors_complete)
				return -1;
			return 0;
		}
#else
		c.blob_context = blob_context;
		c.facts = f;
		c.scratch = scratch;
		struct fe_ancestor_context a = {
			.blob_context = blob_context,
			.facts = f,
			.scratch = scratch,
			.list = r->ancestor_path,
			.depth = r->ancestor_depth,
		};
		if (FE_LOOP(16, fe_ancestor_step, &a) < 0)
			return -1;
		if (a.result != 1) {
			if (a.result < 0 ||
			    (f->ancestor_count < r->ancestor_depth &&
			     !f->ancestors_complete))
				return -1;
			return 0;
		}
#endif
	}
	if ((r->arg_contains.count || r->arg_prefix.count) &&
	    !fe_argv_valid(f, scratch))
		return -1;
	FE_TEST(r->arg_contains, FE_ARG_EXACT);
	FE_TEST(r->arg_prefix, FE_ARG_PREFIX);
	if (r->stdin_pipe != -1) {
		if (f->stdin_pipe < 0 || f->stdin_pipe > 1)
			return -1;
		if (r->stdin_pipe != f->stdin_pipe)
			return 0;
	}
#undef FE_TEST
	return 1;
}
#endif
FE_INLINE int fe_rule_match(struct fe_eval_context *e, const struct fe_rule *r,
			    const struct fe_policy *p, fm_u32 rule_key)
{
#ifdef FE_GLOBAL_MATCHER
	(void)r;
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	return fe_rule_match_global(
		e->facts, e->scratch, rule_key, p->uid,
		(const struct fm_global_token *)e->blob_context
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
		,
		e->alt_request
#endif
	);
#else
	return fe_rule_match_global(e->facts, e->scratch, rule_key, p->uid);
#endif
#else
	(void)rule_key;
	struct fe_predicate_context c = {
		.evaluation = e,
		.rule = r,
		.policy = p,
		.result = 1,
		.match = { .blob_context = e->blob_context,
			   .facts = e->facts,
			   .scratch = e->scratch },
	};
	if (FE_LOOP(12, fe_predicate_step, &c) < 0)
		return -1;
	return c.result;
#endif
}
#ifdef FE_RULE_STEP_INLINE_DIAGNOSTIC
__attribute__((always_inline))
#endif
static long
fe_rule_step(fm_u32 i, void *opaque)
{
	struct fe_eval_context *e = opaque;
	struct fe_decision *d = &e->scratch->decision;
#ifdef FE_STAGE_RELOOKUP_HEADER_CANDIDATE
	const struct fe_header *header = FE_HEADER_LOOKUP(e->blob_context);
	if (!header) {
		d->error = FE_INVALID;
		return 1;
	}
#else
	const struct fe_header *header = e->header;
#endif
	if (i >= 256 || i >= header->rules)
		return 1;
	const struct fe_rule *r = FE_RULE_LOOKUP(e->blob_context, i);
	if (!r || r->policy >= 8 || r->policy >= header->policies ||
	    r->mode < 1 || r->mode > 2 || r->deny > 1 || r->actor_image < -1 ||
	    r->actor_image > 1 || r->target_image < -1 || r->target_image > 1 ||
	    r->stdin_pipe < -1 || r->stdin_pipe > 1) {
		d->error = FE_INVALID;
		return 1;
	}
	const struct fe_policy *p =
		FE_POLICY_LOOKUP(e->blob_context, r->policy);
	if (!p) {
		d->error = FE_INVALID;
		return 1;
	}
	int match = fe_rule_match(e, r, p, header->rule_base + i);
	if (match < 0) {
#ifdef FE_AUDIT_ISOLATION
		if (r->mode == 1) {
			d->audit_unknown |= 1U << r->policy;
			if (r->set_role)
				d->audit_unknown |=
					(1U << (r->policy +
						FE_ROLE_UNCERTAIN_SHIFT)) |
					(1U
					 << (r->policy + FE_ROLE_WRITE_SHIFT));
			if (!d->error)
				d->error = FE_AUDIT_UNKNOWN;
			if (r->deny) {
				e->uncertain_deny = 1;
				d->audit_unknown |= FE_AUDIT_GLOBAL_SUPPRESS;
			} else
				e->uncertain_allow = 1;
		} else {
			d->error = FE_UNKNOWN;
		}
		return 0;
#else
		d->error = FE_UNKNOWN;
		return 1;
#endif
	}
	if (!match)
		return 0;
	e->matched = 1;
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
	fm_u32 matched_word = (i >> 6) & 3U;
	__asm__ __volatile__("" : "+r"(matched_word));
	if (matched_word >= 4) {
		d->error = FE_INVALID;
		return 1;
	}
	d->matched_rules[matched_word] |= (fm_u64)1 << (i & 63);
#else
	d->matched_rules[(i >> 6) & 3] |= (fm_u64)1 << (i & 63);
#endif
	if (r->deny) {
		d->deny = 1;
		if (r->mode > e->deny_mode)
			e->deny_mode = r->mode;
	} else {
		if (r->mode > e->allow_mode)
			e->allow_mode = r->mode;
		fm_u32 index = r->policy;
		if (index >= 8) {
			d->error = FE_INVALID;
			return 1;
		}
		if (r->set_role) {
#ifdef FE_AUDIT_ISOLATION
			if (!d->known_role_witnesses[index])
				d->known_role_witnesses[index] = r->set_role;
#endif
			d->audit_unknown |= 1U << (index + FE_ROLE_WRITE_SHIFT);
			if (r->mode == 2) {
				e->enforced_grants |= 1U << index;
#ifdef FE_AUDIT_ISOLATION
				d->enforced_writes |= 1U << index;
#endif
			}
			if ((e->role_conflicts & (1U << index)) ||
			    (d->proposed_roles[index] &&
			     d->proposed_roles[index] != r->set_role)) {
				e->role_conflicts |= 1U << index;
#ifdef FE_AUDIT_ISOLATION
				d->role_conflicts |= 1U << index;
#endif
#ifdef FE_AUDIT_ISOLATION
				if (!(e->enforced_grants & (1U << index))) {
					d->audit_unknown |=
						(1U << index) |
						(1U
						 << (index +
						     FE_ROLE_UNCERTAIN_SHIFT));
					if (!d->error)
						d->error = FE_AUDIT_UNKNOWN;
					return 0;
				}
#endif
				d->error = FE_ROLE_CONFLICT;
				return 1;
			}
			d->proposed_roles[index] = r->set_role;
		}
	}
	return 0;
}
FE_INLINE int fe_evaluate(void *blob_context, const struct fe_facts *f,
			  struct fe_scratch *s)
{
	/* Clear outputs even on malformed input and poisoned/reused scratch. The
     * matcher and argument lengths initialize their own consumed scratch. */
	s->decision.deny = 0;
	s->decision.mode = 1;
	s->decision.error = 0;
	s->decision.audit_unknown = 0;
#ifdef FE_AUDIT_ISOLATION
	s->decision.enforced_writes = 0;
	s->decision.role_conflicts = 0;
	for (fm_u32 i = 0; i < 8; i++)
		s->decision.known_role_witnesses[i] = 0;
#endif
	for (fm_u32 i = 0; i < 4; i++)
		s->decision.matched_rules[i] = 0;
	for (fm_u32 i = 0; i < 8; i++)
		s->decision.proposed_roles[i] = 0;
	const struct fe_header *h = FE_HEADER_LOOKUP(blob_context);
	if (!h || !h->policies || h->policies > 8 || h->rules > 256 ||
	    h->rule_base != 9 || h->container >= FM_MAX_ENTRIES ||
	    f->ancestor_count > 16 || f->role_count > 8 ||
	    !fe_path_valid(&f->actor_path) || !fe_path_valid(&f->target_path)) {
		s->decision.error = FE_INVALID;
		return -1;
	}
	struct fe_paths_check paths = { f, 0 };
	if (FE_LOOP(16, fe_ancestor_valid, &paths) < 0 || paths.error) {
		s->decision.error = FE_INVALID;
		return -1;
	}
	struct fe_eval_context e = { .blob_context = blob_context,
				     .facts = f,
				     .scratch = s,
#ifndef FE_STAGE_RELOOKUP_HEADER_CANDIDATE
				     .header = h,
#endif
				     .allow_mode = 1,
				     .deny_mode = 1 };
	if (FE_LOOP(h->rules, fe_rule_step, &e) < 0)
		s->decision.error = FE_INVALID;
#ifdef FE_AUDIT_ISOLATION
	if (s->decision.error && s->decision.error != FE_UNKNOWN &&
	    s->decision.error != FE_AUDIT_UNKNOWN) {
#else
	if (s->decision.error) {
#endif
		for (fm_u32 i = 0; i < 8; i++)
			s->decision.proposed_roles[i] = 0;
		return -1;
	}
	if (!e.matched) {
		for (fm_u32 i = 0; i < 8; i++) {
			if (i >= h->policies)
				break;
			const struct fe_policy *p =
				FE_POLICY_LOOKUP(blob_context, i);
			if (!p || p->fallback > 2 || p->mode < 1 ||
			    p->mode > 2) {
				s->decision.error = FE_INVALID;
				return -1;
			}
			if (p->fallback == 2) {
				s->decision.deny = 1;
				if (p->mode > e.deny_mode)
					e.deny_mode = p->mode;
			} else if (p->fallback == 1 && p->mode > e.allow_mode)
				e.allow_mode = p->mode;
		}
	}
#ifdef FE_AUDIT_ISOLATION
	if (!e.matched && e.uncertain_allow && s->decision.deny &&
	    e.deny_mode == 1) {
		e.uncertain_deny = 1;
		s->decision.audit_unknown |= FE_AUDIT_UNCERTAIN_FALLBACK |
					     FE_AUDIT_GLOBAL_SUPPRESS;
	}
#endif
	s->decision.mode = s->decision.deny ? e.deny_mode : e.allow_mode;
	for (fm_u32 i = 0; i < 8; i++) {
		if (s->decision.deny || e.uncertain_deny ||
		    s->decision.error == FE_UNKNOWN ||
		    (FE_ROLE_UNCERTAIN(s->decision.audit_unknown) & (1U << i)))
			s->decision.proposed_roles[i] = 0;
	}
	return s->decision.error && s->decision.error != FE_AUDIT_UNKNOWN ? -1 :
									    0;
}
#endif
