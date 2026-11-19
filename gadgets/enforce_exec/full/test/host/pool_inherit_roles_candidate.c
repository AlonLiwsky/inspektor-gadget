/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Pure child role publication shared by HASH and future pool adapters. */
#include <linux/bpf.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
static __u64 test_epoch(__u64 uid)
{
	return uid ? 1 : 0;
}
#define ER_ACCEPTED_EPOCH(uid) test_epoch(uid)
#include "epoch_roles.h"
#include "shared_inherit_roles.h"

static void projection(struct er_work *work)
{
	memset(work, 0, sizeof(*work));
	work->rows[0] = er_known_row(17, 2, 3);
	work->rows[7] = er_known_row(23, 4, 5);
	work->rows[15] = er_known_row(29, 6, 7);
}

int main(void)
{
	struct er_work work;
	projection(&work);
	struct er_state child = {};
	assert(se_child_roles_publish(&child, &work) == 0);
	assert(child.version == 1 &&
	       !memcmp(child.rows, work.rows, sizeof(child.rows)));
	struct er_state before = child;
	assert(se_child_roles_publish(&child, &work) == -1);
	assert(!memcmp(&child, &before, sizeof(child)));

	const unsigned positions[] = { 0, 7, 15 };
	for (unsigned i = 0; i < sizeof(positions) / sizeof(positions[0]);
	     i++) {
		for (unsigned field = 1; field <= 5; field++) {
			child = (struct er_state){};
			struct er_row *row = &child.rows[positions[i]];
			switch (field) {
			case 1:
				row->uid = 1;
				break;
			case 2:
				row->epoch = 1;
				break;
			case 3:
				row->role = 1;
				break;
			case 4:
				row->knowledge = 1;
				break;
			case 5:
				row->reserved = 1;
				break;
			}
			before = child;
			assert(se_child_roles_publish(&child, &work) == -1);
			assert(!memcmp(&child, &before, sizeof(child)));
		}
	}
	child = (struct er_state){ .version = 2 };
	before = child;
	assert(se_child_roles_publish(&child, &work) == -1);
	assert(!memcmp(&child, &before, sizeof(child)));
	assert(se_child_roles_publish(0, &work) == -1);
	assert(se_child_roles_publish(&child, 0) == -1);
	puts("pool inheritance role publication candidate OK");
	return 0;
}
