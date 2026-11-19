/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 The Inspektor Gadget authors */
#ifndef ENFORCE_EXEC_FULLPOLICY_MATCHER_H
#define ENFORCE_EXEC_FULLPOLICY_MATCHER_H

/* Standalone bounded Thompson NFA interpreter. No allocation, recursion or libc.
 * BPF builds use bpf_loop; ordinary C uses a bounded callback shim. The caller supplies FM_BLOB_LOOKUP(context, uint32_key),
 * returning a const struct fm_blob * or NULL, and private scratch per execution.
 * A per-CPU scratch value is not safe across sleepable BPF operations.
 *
 * Layouts match fullpolicy/kernel.go. Values and instruction PCs use the fixed
 * little-endian ABI; PCs are relative to pattern.code_base. Input is a complete,
 * already-authoritative path byte string, not a syscall-entry pointer snapshot.
 */
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "fullpolicy blob ABI requires a little-endian target"
#endif
#ifndef FM_BLOB_LOOKUP
#error "define FM_BLOB_LOOKUP(context, key) before including matcher.h"
#endif
#define FM_INLINE static __attribute__((always_inline)) inline
#define FM_MAX_STATES 512
#define FM_MAX_BYTES 255
#define FM_MAX_ENTRIES 16384
#define FM_MAX_RANGES 8
#if defined(FM_GLOBAL_BLOB_LOOKUP) || defined(FM_GLOBAL_SCALAR_BLOB_LOOKUP)
#define FM_GLOBAL_MATCHER 1
#endif

typedef unsigned char fm_u8;
typedef unsigned int fm_u32;
typedef unsigned long long fm_u64;
/* Only scalar WORK identity crosses the global matcher ABI. The caller holds
 * the exact WORK ticket through the last nested instruction callback. Keep
 * the wire available to candidate producers even before scalar lookup is
 * selected; defining this type does not enable a lookup mode. */
struct fm_global_token {
	fm_u32 slot, reserved;
	fm_u64 cookie;
};
struct fm_blob {
	fm_u64 words[36];
};
struct fm_pattern {
	fm_u32 code_base, start, count;
	fm_u8 padding[276];
};
struct fm_instruction {
	fm_u32 op, out, arg, count;
	fm_u32 ranges[2 * FM_MAX_RANGES];
	fm_u8 padding[208];
};
struct fm_scratch {
	fm_u64 seeds[8], next[8], seen[8];
	fm_u32 queue[FM_MAX_STATES];
	fm_u32 head, tail;
};
_Static_assert(sizeof(struct fm_blob) == 288, "blob layout");
_Static_assert(sizeof(struct fm_pattern) == 288, "pattern layout");
_Static_assert(sizeof(struct fm_instruction) == 288, "instruction layout");

enum {
	FM_ALT = 0,
	FM_EMPTY_WIDTH = 3,
	FM_MATCH = 4,
	FM_FAIL = 5,
	FM_NOP = 6,
	FM_RUNE = 7,
	FM_BEGIN_TEXT = 4,
	FM_END_TEXT = 8,
};

/* Decode exactly one canonical UTF-8 rune. NUL is not a valid path byte even
 * though it is valid UTF-8. Incomplete, overlong, surrogate and out-of-range
 * encodings are errors, never replacement characters or truncated matches.
 */
struct fm_utf8_buffer {
	fm_u8 bytes[256];
};
struct fm_decoded {
	fm_u32 rune, width;
};
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
/* Diagnostic only: scalar matcher progress lives in the already retained
 * WORK request. No verifier pointer or borrowed map value is stored here. */
struct fm_work_run_request {
	struct fm_global_token token;
	struct {
		fm_u32 code_base, count, length, position;
		int result;
		struct fm_decoded decoded;
	} state;
};
_Static_assert(sizeof(struct fm_work_run_request) == 48,
	       "WORK matcher progress contains only fixed-width scalar state");
#endif
/* BPF callers supply a full256-byte buffer (fe_path.bytes / matcher_input.bytes).
 * The typed memory argument lets the verifier prove decoding once, independent
 * of nested interpreter callbacks. Actual reads stay strictly within length. */
#ifdef __bpf__
__attribute__((noinline))
#else
FM_INLINE
#endif
int fm_decode_buffer(const struct fm_utf8_buffer *buffer, fm_u32 length,
                     fm_u32 position, struct fm_decoded *decoded)
{
	if (!buffer || !decoded || length > FM_MAX_BYTES ||
	    position >= length || position >= FM_MAX_BYTES)
		return -1;
	const fm_u8 *input = buffer->bytes;
	fm_u32 first = input[position];
	fm_u32 value, size;
	if (first > 0 && first < 0x80) {
		value = first;
		size = 1;
	} else if (first >= 0xc2 && first <= 0xdf) {
		value = first & 0x1f;
		size = 2;
	} else if (first >= 0xe0 && first <= 0xef) {
		value = first & 0x0f;
		size = 3;
	} else if (first >= 0xf0 && first <= 0xf4) {
		value = first & 0x07;
		size = 4;
	} else {
		return -1;
	}
	if (size > length - position)
		return -1;
	for (fm_u32 i = 1; i < 4; i++) {
		if (i >= size)
			break;
		fm_u64 offset = (fm_u64)position + i;
		/* Keep the checked scalar and pointer offset identical. Otherwise LLVM
         * may precompute input+position and add i after checking position+i,
         * losing the combined bound in the BPF verifier. */
		__asm__ __volatile__("" : "+r"(offset));
		if (offset >= length || offset >= FM_MAX_BYTES)
			return -1;
		fm_u32 byte = input[offset];
		if ((byte & 0xc0) != 0x80)
			return -1;
		value = (value << 6) | (byte & 0x3f);
	}
	if ((size == 2 && value < 0x80) || (size == 3 && value < 0x800) ||
	    (size == 4 && value < 0x10000) || value > 0x10ffff ||
	    (value >= 0xd800 && value <= 0xdfff))
		return -1;
	decoded->rune = value;
	decoded->width = size;
	return 0;
}
FM_INLINE int fm_decode(const fm_u8 *input, fm_u32 length, fm_u32 position,
			fm_u32 *rune, fm_u32 *width)
{
	struct fm_decoded decoded = {};
	int result = fm_decode_buffer((const struct fm_utf8_buffer *)input,
				      length, position, &decoded);
	if (result < 0)
		return result;
	*rune = decoded.rune;
	*width = decoded.width;
	return 0;
}

FM_INLINE int fm_enqueue_inline(struct fm_scratch *scratch, fm_u32 pc,
				fm_u32 count)
{
	if (!scratch || !count || count > FM_MAX_STATES || pc >= count ||
	    pc >= FM_MAX_STATES)
		return -1;
	fm_u32 word = pc >> 6;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
	/* Keep the checked word used for the dynamic memory offset identical in
	 * the generated BPF, independent of the earlier pc/count relation. */
	__asm__ __volatile__("" : "+r"(word));
	if (word >= 8)
		return -1;
#endif
	fm_u64 mask = 1ULL << (pc & 63);
	if (scratch->seen[word] & mask)
		return 0;
	fm_u32 tail = scratch->tail;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
	__asm__ __volatile__("" : "+r"(tail));
#endif
	if (tail >= FM_MAX_STATES)
		return -1;
	scratch->seen[word] |= mask;
	scratch->queue[tail] = pc;
	scratch->tail = tail + 1;
	return 0;
}
/* Seed callbacks use an independently verified typed-memory queue helper. The
 * opcode helper inlines this implementation to stay within BPF call depth. */
#ifdef __bpf__
__attribute__((noinline))
#else
FM_INLINE
#endif
int fm_enqueue(struct fm_scratch *scratch, fm_u32 pc, fm_u32 count)
{
	return fm_enqueue_inline(scratch, pc, count);
}

/* bpf_loop keeps callback verification independent of the runtime iteration
 * count. Plain C executes the same callbacks through a bounded local shim. */
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
/* Exact Rocky 4.18 accepts ordinary bounded loops but not helper 181. This
 * candidate keeps the callback's 0/1/error contract without an indirect
 * function-pointer call. Verifier acceptance of the full matcher is separate
 * from the isolated loop premise. Never select this macro by default. */
#define FM_BOUND_LOOP(count, callback, context)                             \
	({                                                                  \
		fm_u32 _fm_count = (count);                                 \
		long _fm_result = _fm_count;                                \
		if (_fm_count > FM_MAX_STATES)                              \
			_fm_result = -1;                                    \
		else                                                        \
			for (fm_u32 _fm_i = 0; _fm_i < FM_MAX_STATES;       \
			     _fm_i++) {                                     \
				if (_fm_i >= _fm_count)                     \
					break;                              \
				long _fm_step = callback(_fm_i, (context)); \
				if (_fm_step == 1) {                        \
					_fm_result = _fm_i + 1;             \
					break;                              \
				}                                           \
				if (_fm_step != 0) {                        \
					_fm_result = -1;                    \
					break;                              \
				}                                           \
			}                                                   \
		_fm_result;                                                 \
	})
#define FM_LOOP(count, callback, context) \
	FM_BOUND_LOOP(count, callback, context)
#elif defined(__bpf__)
static long (*fm_bpf_loop)(fm_u32, void *, void *, fm_u64) = (void *)181;
#define FM_LOOP(count, callback, context) \
	fm_bpf_loop(count, callback, context, 0)
#else
FM_INLINE long fm_c_loop(fm_u32 count, long (*callback)(fm_u32, void *),
			 void *context)
{
	if (count > FM_MAX_STATES)
		return -1;
	for (fm_u32 i = 0; i < FM_MAX_STATES; i++) {
		if (i >= count)
			return count;
		long result = callback(i, context);
		if (result == 1)
			return i + 1;
		if (result != 0)
			return -1;
	}
	return count;
}
#define FM_LOOP(count, callback, context) fm_c_loop(count, callback, context)
#endif

struct fm_step_context {
	void *context;
	struct fm_scratch *scratch;
	fm_u32 code_base, count, rune;
	int at_begin, at_end, matched, error;
};
FM_INLINE long fm_failure(struct fm_step_context *ctx)
{
	ctx->error = 1;
	return 1;
}
#if !(defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FM_GLOBAL_MATCHER))
#if defined(__bpf__) && defined(FE_BOUNDED_LOOP_CANDIDATE)
static
	__attribute__((noinline))
#else
static
#endif
	long
	fm_seed_callback(fm_u32 pc, void *data)
{
	struct fm_step_context *ctx = data;
	if (pc >= ctx->count || pc >= FM_MAX_STATES)
		return 1;
	if (ctx->scratch->seeds[pc >> 6] & (1ULL << (pc & 63))) {
#ifdef FM_GLOBAL_MATCHER
		if (fm_enqueue_inline(ctx->scratch, pc, ctx->count) < 0)
#else
		if (fm_enqueue(ctx->scratch, pc, ctx->count) < 0)
#endif
			return fm_failure(ctx);
	}
	return 0;
}
#endif

#if defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FM_GLOBAL_MATCHER)
/* Each bit is consumed exactly once in ascending PC order. Avoid verifying
 * 512 independent seed-bit branches in one caller. */
#ifdef __bpf__
__attribute__((noinline))
#else
FM_INLINE
#endif
int fm_seed_word(struct fm_scratch *scratch, fm_u32 count, fm_u32 word)
{
	if (!scratch || !count || count > FM_MAX_STATES || word >= 8)
		return -1;
	fm_u64 bits = scratch->seeds[word];
	for (fm_u32 i = 0; i < 64; i++) {
		if (!bits)
			break;
		fm_u32 pc = word * 64 + __builtin_ctzll(bits);
		if (pc >= count)
			break;
		if (fm_enqueue_inline(scratch, pc, count) < 0)
			return -1;
		bits &= bits - 1;
	}
	return 0;
}
#endif

struct fm_instruction_state {
	fm_u32 count, rune;
	int at_begin, at_end;
};
/* Globally verify the pure opcode transition once, instead of multiplying its
 * branch states across rules, predicates, ancestors and path characters. All
 * arguments are typed bounded memory; the map lookup stays in the callback.
 * Inline queue/range operations avoid exceeding eight frames on ancestry paths.
 */
#if defined(__bpf__) && !defined(FM_GLOBAL_MATCHER)
__attribute__((noinline))
#else
FM_INLINE
#endif
int fm_apply_instruction(struct fm_scratch *scratch,
                         const struct fm_instruction *inst,
                         const struct fm_instruction_state *state)
{
	if (!scratch || !inst || !state || !state->count ||
	    state->count > FM_MAX_STATES)
		return -1;
	fm_u32 count = state->count;
	if (inst->op != FM_RUNE && inst->count != 0)
		return -1;
	switch (inst->op) {
	case FM_ALT:
		if (fm_enqueue_inline(scratch, inst->out, count) < 0 ||
		    fm_enqueue_inline(scratch, inst->arg, count) < 0)
			return -1;
		break;
	case FM_EMPTY_WIDTH:
		if (inst->arg & ~(FM_BEGIN_TEXT | FM_END_TEXT))
			return -1;
		if (inst->out >= count)
			return -1;
		if ((!(inst->arg & FM_BEGIN_TEXT) || state->at_begin) &&
		    (!(inst->arg & FM_END_TEXT) || state->at_end)) {
			if (fm_enqueue_inline(scratch, inst->out, count) < 0)
				return -1;
		}
		break;
	case FM_NOP:
		if (fm_enqueue_inline(scratch, inst->out, count) < 0)
			return -1;
		break;
	case FM_MATCH:
		return state->at_end ? 1 : 0;
	case FM_FAIL:
		break;
	case FM_RUNE: {
		if (!inst->count || inst->count > FM_MAX_RANGES || inst->arg ||
		    inst->out >= count || inst->out >= FM_MAX_STATES)
			return -1;
		int consumes = 0;
		/* This small loop is verified once inside the global function. Every
         * range is validated, even after a positive match. Larger interpreter
         * loops continue to use bpf_loop callbacks. */
		for (fm_u32 i = 0; i < FM_MAX_RANGES; i++) {
			if (i >= inst->count)
				break;
			fm_u32 lo_index = 2 * i, hi_index = lo_index + 1;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
			__asm__ __volatile__(""
					     : "+r"(lo_index), "+r"(hi_index));
			if (lo_index >= 2 * FM_MAX_RANGES ||
			    hi_index >= 2 * FM_MAX_RANGES)
				return -1;
#endif
			fm_u32 lo = inst->ranges[lo_index],
			       hi = inst->ranges[hi_index];
			if (lo > hi || hi > 0x10ffff)
				return -1;
			if (!state->at_end && state->rune >= lo &&
			    state->rune <= hi)
				consumes = 1;
		}
		if (consumes) {
			fm_u32 out = inst->out;
			__asm__ __volatile__("" : "+r"(out));
			if (out >= count || out >= FM_MAX_STATES)
				return -1;
			fm_u32 word = out >> 6;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
			__asm__ __volatile__("" : "+r"(word));
			if (word >= 8)
				return -1;
#endif
			scratch->next[word] |= 1ULL << (out & 63);
		}
		break;
	}
	default:
		return -1;
	}
	return 0;
}

/* Exactly one workqueue step. Each PC is enqueued once, so epsilon cycles
 * terminate within512 callbacks without verifier path expansion per iteration. */
#if defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FM_GLOBAL_MATCHER)
struct fm_instruction_request {
	fm_u64 cookie;
	fm_u32 slot, code_base, count, rune;
	int at_begin, at_end;
};
/* The ordinary-loop candidate cannot expand a full opcode transition under
 * every queue iteration. Pass scalar state only; resolve immutable blobs in
 * this independently verified compartment. Return 2 when the queue drains. */
#ifdef __bpf__
__attribute__((noinline))
#else
FM_INLINE
#endif
int fm_instruction_step(struct fm_scratch *scratch,
			const struct fm_instruction_request *request)
{
	if (!scratch || !request || !request->count ||
	    request->count > FM_MAX_STATES ||
	    request->code_base >= FM_MAX_ENTRIES)
		return -1;
	if (scratch->head >= scratch->tail)
		return 2;
	fm_u32 head = scratch->head;
	__asm__ __volatile__("" : "+r"(head));
	if (head >= FM_MAX_STATES)
		return -1;
	fm_u32 pc = scratch->queue[head];
	scratch->head = head + 1;
	if (pc >= request->count || pc >= FM_MAX_STATES ||
	    pc >= FM_MAX_ENTRIES - request->code_base)
		return -1;
	fm_u32 key = request->code_base + pc;
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	if (!request->cookie)
		return -1;
	const struct fm_blob *blob = FM_GLOBAL_SCALAR_BLOB_LOOKUP(
		request->slot, request->cookie, key);
#else
	const struct fm_blob *blob = FM_GLOBAL_BLOB_LOOKUP(key);
#endif
	if (!blob)
		return -1;
	struct fm_instruction_state state = {
		.count = request->count,
		.rune = request->rune,
		.at_begin = request->at_begin,
		.at_end = request->at_end,
	};
	return fm_apply_instruction(
		scratch, (const struct fm_instruction *)blob, &state);
}
/* At most eight windows cover all 512 unique PCs. A window returns bit 0 for
 * a match and bit 1 when the queue has drained; errors remain negative. */
#if defined(__bpf__) && !defined(FM_STAGE_INLINE_INSTRUCTION_WINDOW)
__attribute__((noinline))
#else
FM_INLINE
#endif
int fm_instruction_window(struct fm_scratch *scratch,
			  const struct fm_instruction_request *request)
{
	if (!scratch || !request)
		return -1;
	int matched = 0;
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
#pragma unroll
#endif
	for (fm_u32 i = 0; i < 64; i++) {
		int result = fm_instruction_step(scratch, request);
		if (result < 0)
			return -1;
		if (result == 2)
			return 2 | matched;
		if (result == 1)
			matched = 1;
	}
	return matched;
}
#endif
#if !(defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FM_GLOBAL_MATCHER))
#if defined(__bpf__) && defined(FE_BOUNDED_LOOP_CANDIDATE)
static
	__attribute__((noinline))
#else
static
#endif
	long
	fm_instruction_callback(fm_u32 index, void *data)
{
	(void)index;
	struct fm_step_context *ctx = data;
	struct fm_scratch *scratch = ctx->scratch;
	fm_u32 count = ctx->count;
	if (scratch->head >= scratch->tail)
		return 1;
	if (scratch->head >= FM_MAX_STATES)
		return fm_failure(ctx);
	fm_u32 pc = scratch->queue[scratch->head++];
	if (pc >= count || pc >= FM_MAX_STATES)
		return fm_failure(ctx);
	fm_u32 key = ctx->code_base + pc;
	if (key >= FM_MAX_ENTRIES)
		return fm_failure(ctx);
#ifdef FM_GLOBAL_MATCHER
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	const struct fm_global_token *token = ctx->context;
	if (!token || token->reserved || !token->cookie)
		return fm_failure(ctx);
	const struct fm_blob *blob =
		FM_GLOBAL_SCALAR_BLOB_LOOKUP(token->slot, token->cookie, key);
#else
	const struct fm_blob *blob = FM_GLOBAL_BLOB_LOOKUP(key);
#endif
#else
	const struct fm_blob *blob = FM_BLOB_LOOKUP(ctx->context, key);
#endif
	if (!blob)
		return fm_failure(ctx);
	struct fm_instruction_state state = {
		.count = count,
		.rune = ctx->rune,
		.at_begin = ctx->at_begin,
		.at_end = ctx->at_end,
	};
	int result = fm_apply_instruction(
		scratch, (const struct fm_instruction *)blob, &state);
	if (result < 0)
		return fm_failure(ctx);
	if (result)
		ctx->matched = 1;
	return 0;
}
#endif

#if defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FM_GLOBAL_MATCHER)
/* One full rune transition is an independent verifier unit. All carried
 * fields are scalars; scratch remains WORK-owned and the frozen program is
 * reacquired by scalar key/cookie for every instruction. */
#ifdef __bpf__
__attribute__((noinline))
#else
FM_INLINE
#endif
int fm_step_global(struct fm_scratch *scratch,
		   const struct fm_instruction_request *request)
{
	if (!scratch || !request || !request->count ||
	    request->count > FM_MAX_STATES)
		return -1;
	scratch->head = scratch->tail = 0;
	for (fm_u32 i = 0; i < 8; i++) {
		scratch->next[i] = 0;
		scratch->seen[i] = 0;
	}
	for (fm_u32 word = 0; word < 8; word++) {
		if (fm_seed_word(scratch, request->count, word) < 0)
			return -1;
	}
	int matched = 0;
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
#pragma unroll
#endif
	for (fm_u32 window = 0; window < 8; window++) {
		int result = fm_instruction_window(scratch, request);
		if (result < 0)
			return -1;
		if (result & 1)
			matched = 1;
		if (result & 2)
			break;
	}
	if (scratch->head != scratch->tail)
		return -1;
	return matched;
}
#endif
FM_INLINE int fm_step(void *context, fm_u32 code_base, fm_u32 count,
		      fm_u32 rune, int at_begin, int at_end,
		      struct fm_scratch *scratch)
{
	if (!scratch || !count || count > FM_MAX_STATES)
		return -1;
#if defined(FE_BOUNDED_LOOP_CANDIDATE) && defined(FM_GLOBAL_MATCHER)
	struct fm_instruction_request request = {
		.code_base = code_base,
		.count = count,
		.rune = rune,
		.at_begin = at_begin,
		.at_end = at_end,
	};
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
	const struct fm_global_token *token = context;
	if (!token || token->reserved || !token->cookie)
		return -1;
	request.slot = token->slot;
	request.cookie = token->cookie;
#else
	(void)context;
#endif
	return fm_step_global(scratch, &request);
#else
	scratch->head = scratch->tail = 0;
	for (fm_u32 i = 0; i < 8; i++) {
		scratch->next[i] = 0;
		scratch->seen[i] = 0;
	}
	struct fm_step_context ctx = {
		.context = context,
		.scratch = scratch,
		.code_base = code_base,
		.count = count,
		.rune = rune,
		.at_begin = at_begin,
		.at_end = at_end,
	};
#ifdef FE_BOUNDED_LOOP_CANDIDATE
	if (FM_LOOP(count, fm_seed_callback, &ctx) < 0 || ctx.error)
		return -1;
	if (FM_LOOP(count, fm_instruction_callback, &ctx) < 0 || ctx.error ||
	    scratch->head != scratch->tail)
		return -1;
#else
	if (FM_LOOP(FM_MAX_STATES, fm_seed_callback, &ctx) < 0 || ctx.error)
		return -1;
	if (FM_LOOP(FM_MAX_STATES, fm_instruction_callback, &ctx) < 0 ||
	    ctx.error || scratch->head != scratch->tail)
		return -1;
#endif
	return ctx.matched;
#endif
}

struct fm_run_context {
#ifndef FM_WORK_RUN_STATE_DIAGNOSTIC
	void *context;
#endif
	const fm_u8 *input;
	struct fm_scratch *scratch;
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
	struct fm_work_run_request *run;
#else
	fm_u32 code_base, count, length, position;
	int result;
#if defined(__bpf__) && defined(FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC)
	/* Keep the decoder output in the caller-owned context: the separate
	 * callback need not reserve another stack slot across fm_step. */
	struct fm_decoded decoded;
#endif
#endif
};
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
#define FM_CTX(ctx, field) ((ctx)->run->state.field)
#else
#define FM_CTX(ctx, field) ((ctx)->field)
#endif
#if defined(__bpf__) && defined(FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC)
__attribute__((noinline))
#endif
static long
fm_rune_callback(fm_u32 index, void *data)
{
	(void)index;
	struct fm_run_context *ctx = data;
	int at_end = FM_CTX(ctx, position) == FM_CTX(ctx, length);
#if defined(__bpf__) && defined(FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC)
	FM_CTX(ctx, decoded).rune = 0;
	FM_CTX(ctx, decoded).width = 0;
	if (!at_end &&
	    fm_decode_buffer((const struct fm_utf8_buffer *)ctx->input,
			     FM_CTX(ctx, length), FM_CTX(ctx, position),
			     &FM_CTX(ctx, decoded)) < 0) {
		FM_CTX(ctx, result) = -1;
		return 1;
	}
	int result = fm_step(
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
		ctx->run,
#else
		ctx->context,
#endif
		FM_CTX(ctx, code_base), FM_CTX(ctx, count),
		FM_CTX(ctx, decoded).rune, FM_CTX(ctx, position) == 0, at_end,
		ctx->scratch);
#else
	fm_u32 rune = 0, width = 0;
	if (!at_end && fm_decode(ctx->input, FM_CTX(ctx, length),
				 FM_CTX(ctx, position), &rune, &width) < 0) {
		FM_CTX(ctx, result) = -1;
		return 1;
	}
	int result = fm_step(
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
		ctx->run,
#else
		ctx->context,
#endif
		FM_CTX(ctx, code_base), FM_CTX(ctx, count), rune,
		FM_CTX(ctx, position) == 0, at_end, ctx->scratch);
#endif
	if (result < 0 || at_end) {
		FM_CTX(ctx, result) = result;
		return 1;
	}
#if defined(__bpf__) && defined(FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC)
	FM_CTX(ctx, position) += FM_CTX(ctx, decoded).width;
#else
	FM_CTX(ctx, position) += width;
#endif
	for (fm_u32 i = 0; i < 8; i++)
		ctx->scratch->seeds[i] = ctx->scratch->next[i];
	return 0;
}

/* Return1 for a whole-string match,0 for no match,-1 for malformed/unavailable
 * data or exceeded bounds. An error must never be interpreted as false by an
 * enforcement caller. Each call resets working state before use, so scratch
 * can be reused after a previous match, mismatch or error.
 */
FM_INLINE int fm_match_inline(void *context, const struct fm_pattern *pattern,
			      const fm_u8 *input, fm_u32 length,
			      struct fm_scratch *scratch)
{
	if (!pattern || !input || !scratch || length > FM_MAX_BYTES)
		return -1;
	/* Cache descriptor scalars once. The program map must be frozen, but loop
     * bounds should not depend on repeated loads through a map-value pointer. */
	fm_u32 count = pattern->count, start = pattern->start;
	fm_u32 code_base = pattern->code_base;
	if (!count || count > FM_MAX_STATES || start >= count || !code_base ||
	    code_base >= FM_MAX_ENTRIES || count > FM_MAX_ENTRIES - code_base)
		return -1;
	for (fm_u32 i = 0; i < 8; i++)
		scratch->seeds[i] = 0;
	fm_u32 start_word = start >> 6;
#if defined(FE_BOUNDED_LOOP_CANDIDATE)
	__asm__ __volatile__("" : "+r"(start_word));
	if (start_word >= 8)
		return -1;
#endif
	scratch->seeds[start_word] = 1ULL << (start & 63);
	struct fm_run_context ctx = {
#ifndef FM_WORK_RUN_STATE_DIAGNOSTIC
		.context = context,
#endif
		.input = input,
		.scratch = scratch,
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
		.run = (struct fm_work_run_request *)context,
#else
		.code_base = code_base,
		.count = count,
		.length = length,
		.result = -1,
#endif
	};
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
	if (!ctx.run)
		return -1;
	ctx.run->state.code_base = code_base;
	ctx.run->state.count = count;
	ctx.run->state.length = length;
	ctx.run->state.position = 0;
	ctx.run->state.result = -1;
	ctx.run->state.decoded = (struct fm_decoded){};
#endif
#if defined(__bpf__) && defined(FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC)
	/* Keep this 256-step UTF-8 bound independent of the generic 512-step
	 * interpreter loop on kernels without bpf_loop. */
	for (fm_u64 remaining = FM_MAX_BYTES + 1; remaining; remaining--) {
		long step = fm_rune_callback(
			(fm_u32)(FM_MAX_BYTES + 1 - remaining), &ctx);
		if (step == 1)
			break;
		if (step != 0)
			return -1;
	}
#else
	if (FM_LOOP(FM_MAX_BYTES + 1, fm_rune_callback, &ctx) < 0)
		return -1;
#endif
	return FM_CTX(&ctx, result);
}
#ifdef FM_GLOBAL_MATCHER
/* Fixed-map BPF programs can independently verify the entire matcher. The
 * accessor resolves the program's immutable blob map without passing an opaque
 * map pointer through the global-function ABI. All memory arguments are typed.
 */
__attribute__((noinline)) int
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
fm_match_global(fm_u32 pattern_key, const struct fm_utf8_buffer *input,
		fm_u32 length, struct fm_scratch *scratch,
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
		struct fm_work_run_request *run)
#else
		const struct fm_global_token *token)
#endif
#else
fm_match_global(fm_u32 pattern_key, const struct fm_utf8_buffer *input,
		fm_u32 length, struct fm_scratch *scratch)
#endif
{
	if (!input || pattern_key >= FM_MAX_ENTRIES)
		return -1;
		/* Readonly map values must not cross the global memory-argument ABI: C
     * const does not mark BTF memory arguments readonly. Resolve by scalar key. */
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
	const struct fm_global_token *token = run ? &run->token : 0;
#endif
	if (!token || token->reserved || !token->cookie)
		return -1;
	const struct fm_pattern *pattern =
		(const struct fm_pattern *)FM_GLOBAL_SCALAR_BLOB_LOOKUP(
			token->slot, token->cookie, pattern_key);
	return fm_match_inline((void *)
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
				       run,
#else
				       token,
#endif
			       pattern, input->bytes, length, scratch);
#else
	const struct fm_pattern *pattern =
		(const struct fm_pattern *)FM_GLOBAL_BLOB_LOOKUP(pattern_key);
	return fm_match_inline(0, pattern, input->bytes, length, scratch);
#endif
}
#endif
FM_INLINE int fm_match(void *context, const struct fm_pattern *pattern,
		       const fm_u8 *input, fm_u32 length,
		       struct fm_scratch *scratch)
{
	return fm_match_inline(context, pattern, input, length, scratch);
}
/* Fixed-map BPF callers use this key boundary so the immutable pattern stays
 * inside the global function, not a falsely writable memory argument. */
FM_INLINE int fm_match_key(void *context, fm_u32 key, const fm_u8 *input,
			   fm_u32 length, struct fm_scratch *scratch)
{
	if (key >= FM_MAX_ENTRIES)
		return -1;
#ifdef FM_GLOBAL_MATCHER
#ifdef FM_GLOBAL_SCALAR_BLOB_LOOKUP
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
	struct fm_work_run_request *run = context;
	const struct fm_global_token *token = run ? &run->token : 0;
#else
	const struct fm_global_token *token = context;
#endif
	if (!token || token->reserved || !token->cookie)
		return -1;
	return fm_match_global(key, (const struct fm_utf8_buffer *)input,
			       length, scratch,
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
			       run);
#else
			       token);
#endif
#else
	(void)context;
	return fm_match_global(key, (const struct fm_utf8_buffer *)input,
			       length, scratch);
#endif
#else
	const struct fm_pattern *pattern =
		(const struct fm_pattern *)FM_BLOB_LOOKUP(context, key);
	return fm_match_inline(context, pattern, input, length, scratch);
#endif
}
#undef FM_GLOBAL_MATCHER
#undef FM_LOOP
#undef FM_INLINE
#undef FM_CTX
#endif
