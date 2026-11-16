/* SPDX-License-Identifier: Apache-2.0 */
/* Plain userspace oracle harness; libc/allocation are outside matcher.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fm_blob;
struct fixture {
	struct fm_blob *entries;
	unsigned int count;
};
static const struct fm_blob *lookup(void *, unsigned int);
#define FM_BLOB_LOOKUP(context, key) lookup(context, key)
#if defined(FM_CANDIDATE_GLOBAL_TEST) || defined(FM_WORK_RUN_STATE_DIAGNOSTIC)
static struct fixture *current_fixture;
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
static const struct fm_blob *lookup_scalar(unsigned int, unsigned long long,
					   unsigned int);
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	lookup_scalar((slot), (cookie), (key))
#else
#define FM_GLOBAL_BLOB_LOOKUP(key) lookup(current_fixture, key)
#endif
#endif
#include "../bpf/matcher.h"

static const struct fm_blob *lookup(void *context, unsigned int key)
{
	struct fixture *fixture = context;
	return key < fixture->count ? &fixture->entries[key] : NULL;
}
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
static const struct fm_blob *
lookup_scalar(unsigned int slot, unsigned long long cookie, unsigned int key)
{
	return slot == 0 && cookie == 101 ? lookup(current_fixture, key) : NULL;
}
#endif
int main(int argc, char **argv)
{
	if (argc != 4)
		return 2;
	FILE *file = fopen(argv[1], "rb");
	if (!file || fseek(file, 0, SEEK_END))
		return 2;
	long bytes = ftell(file);
	if (bytes <= 0 || bytes % sizeof(struct fm_blob) ||
	    bytes / sizeof(struct fm_blob) > FM_MAX_ENTRIES ||
	    fseek(file, 0, SEEK_SET))
		return 2;
	struct fixture fixture = { .count = bytes / sizeof(struct fm_blob) };
#if defined(FM_CANDIDATE_GLOBAL_TEST) || defined(FM_WORK_RUN_STATE_DIAGNOSTIC)
	current_fixture = &fixture;
#endif
	fixture.entries = calloc(fixture.count, sizeof(struct fm_blob));
	struct fm_scratch *scratch = calloc(1, sizeof(*scratch));
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
	struct fm_work_run_request run = {
		.token = { .slot = 0, .cookie = 101 },
	};
#endif
	if (!fixture.entries || !scratch ||
	    fread(fixture.entries, sizeof(struct fm_blob), fixture.count,
		  file) != fixture.count)
		return 2;
	fclose(file);
	unsigned int pattern_key = strtoul(argv[2], NULL, 10);
	if (pattern_key >= fixture.count)
		return 2;
	unsigned char input[1024];
	size_t hex_length = strlen(argv[3]);
	if (hex_length % 2 || hex_length / 2 > sizeof(input))
		return 2;
	for (size_t i = 0; i < hex_length / 2; i++) {
		unsigned int byte;
		if (sscanf(argv[3] + 2 * i, "%2x", &byte) != 1)
			return 2;
		input[i] = byte;
	}
	/* Poison scratch to catch dependence on calloc/previous invocation state. */
	memset(scratch, 0xa5, sizeof(*scratch));
	int result =
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
		fm_match_key(&run, pattern_key, input, hex_length / 2, scratch);
#elif defined(FM_CANDIDATE_GLOBAL_TEST)
		fm_match_key(&fixture, pattern_key, input, hex_length / 2,
			     scratch);
#else
		fm_match(
			&fixture,
			(const struct fm_pattern *)&fixture.entries[pattern_key],
			input, hex_length / 2, scratch);
#endif
	/* Reusing scratch after an error or match must produce the same answer. */
	int again =
#ifdef FM_WORK_RUN_STATE_DIAGNOSTIC
		fm_match_key(&run, pattern_key, input, hex_length / 2, scratch);
#elif defined(FM_CANDIDATE_GLOBAL_TEST)
		fm_match_key(&fixture, pattern_key, input, hex_length / 2,
			     scratch);
#else
		fm_match(
			&fixture,
			(const struct fm_pattern *)&fixture.entries[pattern_key],
			input, hex_length / 2, scratch);
#endif
	if (result != again)
		return 3;
	printf("%d\n", result);
	free(scratch);
	free(fixture.entries);
	return 0;
}
