// SPDX-License-Identifier: GPL-2.0
// Compile/ABI harness only; production header is included unchanged.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
struct fm_blob;
static inline const struct fm_blob *owner_test_lookup(void *, unsigned int);
#define FM_BLOB_LOOKUP(context, key) owner_test_lookup(context, key)
#include "../../../../fullpolicy/bpf/evaluator.h"
#include "../../../owner_types.h"
#include "../../../owner_control.h"
#include "../../../owner_roles.h"
static inline const struct fm_blob *owner_test_lookup(void *context,
						      unsigned int key)
{
	return bpf_map_lookup_elem(context, &key);
}
char LICENSE[] SEC("license") = "GPL";
