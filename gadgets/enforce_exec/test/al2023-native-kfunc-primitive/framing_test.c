// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "argv_wire.h"
static struct ig_argv_result out;
int main(void)
{
	struct ig_argv_cursor cursor;
	memset(&out, 0, sizeof(out));
	cursor = (struct ig_argv_cursor){ .argc = 2 };
	assert(ig_argv_append(&out, &cursor, 0) == 0);
	assert(ig_argv_append(&out, &cursor, 0xff) == 0);
	assert(ig_argv_append(&out, &cursor, 0) == 1);
	assert(cursor.bytes == 3 && out.offsets[1] == 1 && cursor.strings == 2);
	memset(&out, 0, sizeof(out));
	cursor = (struct ig_argv_cursor){ .argc = 64 };
	for (unsigned int i = 0; i < 64; i++)
		assert(ig_argv_append(&out, &cursor, 0) == (i == 63));
	memset(&out, 0, sizeof(out));
	cursor = (struct ig_argv_cursor){ .argc = 1 };
	for (unsigned int i = 0; i < 4095; i++)
		assert(ig_argv_append(&out, &cursor, 'x') == 0);
	assert(ig_argv_append(&out, &cursor, 0) == 1 && cursor.bytes == 4096);
	assert(ig_argv_append(&out, &cursor, 0) == -1);
	memset(&out, 0, sizeof(out));
	cursor = (struct ig_argv_cursor){ .argc = 1 };
	for (unsigned int i = 0; i < 4095; i++)
		assert(ig_argv_append(&out, &cursor, 'x') == 0);
	assert(ig_argv_append(&out, &cursor, 'x') == -1);
	memset(&out, 0, sizeof(out));
	cursor = (struct ig_argv_cursor){ .argc = 65 };
	assert(ig_argv_append(&out, &cursor, 0) == -1);
	/* Perturb every shared metadata field before each write. Neither bounds
	 * nor progress may depend on caller-mutable output metadata. */
	memset(&out, 0, sizeof(out));
	cursor = (struct ig_argv_cursor){ .argc = 64 };
	for (unsigned int i = 0; i < 64; i++) {
		out.argc = out.bytes = out.complete = out.status = ~0U;
		assert(ig_argv_append(&out, &cursor, 0) == (i == 63));
	}
	assert(cursor.bytes == 64 && cursor.strings == 64);
	assert(ig_argv_append(&out, &cursor, 0) == -1);
	cursor = (struct ig_argv_cursor){ .argc = 1 };
	for (unsigned int i = 0; i < 4096; i++) {
		out.argc = 0;
		out.bytes = ~0U;
		assert(ig_argv_append(&out, &cursor, 'x') ==
		       (i == 4095 ? -1 : 0));
	}
	assert(cursor.bytes == 4096 && cursor.strings == 0);
	assert(ig_argv_append(&out, &cursor, 0) == -1);
	puts("framing boundaries PASS (not kernel acquisition proof)");
}
