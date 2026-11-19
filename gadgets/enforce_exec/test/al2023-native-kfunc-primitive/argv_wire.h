/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IG_ARGV_KFUNC_WIRE_H
#define IG_ARGV_KFUNC_WIRE_H
#define IG_ARGV_ABI 1U
#define IG_ARGV_MAX_ARGS 64U
#define IG_ARGV_MAX_BYTES 4096U
#define IG_ARGV_UNKNOWN 0U
#define IG_ARGV_KNOWN 1U
#define IG_ARGV_OVERSIZED 2U
struct ig_argv_result {
	unsigned int abi, status, argc, bytes, complete;
	int error;
	unsigned int offsets[IG_ARGV_MAX_ARGS];
	unsigned char data[IG_ARGV_MAX_BYTES];
};
_Static_assert(sizeof(struct ig_argv_result) == 4376, "argv wire size");
/* Private stack state, never aliased with caller-visible output. */
struct ig_argv_cursor {
	unsigned int argc, bytes, strings;
};
/* Output is write-only: concurrent output changes cannot control addressing or
 * progress. Return 1 on final NUL, 0 for more bytes, -1 on bound exhaustion. */
static inline int ig_argv_append(struct ig_argv_result *out,
				 struct ig_argv_cursor *cursor,
				 unsigned char byte)
{
	if (!cursor->argc || cursor->argc > IG_ARGV_MAX_ARGS ||
	    cursor->strings >= cursor->argc ||
	    cursor->bytes >= IG_ARGV_MAX_BYTES)
		return -1;
	out->data[cursor->bytes++] = byte;
	if (!byte) {
		++cursor->strings;
		if (cursor->strings == cursor->argc)
			return 1;
		out->offsets[cursor->strings] = cursor->bytes;
	}
	return cursor->bytes == IG_ARGV_MAX_BYTES ? -1 : 0;
}
#endif
