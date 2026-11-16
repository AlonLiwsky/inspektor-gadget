// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
#include "shared_inode_facts.h"

/* Deliberately tiny fixed pools. These callbacks model serialized operations;
 * they are not a proof of kernel serialization or matched physical death. */
#define ROWS 3
static struct se_inode_row rows[ROWS];
static struct se_inode_quota quotas[2];
static int lookup_error, account_error, insert_error, delete_error,
	account_wrong;
static unsigned inserts, deletes;
static struct se_inode_identity id(__u64 address, __u64 birth, unsigned owner)
{
	return (struct se_inode_identity){ address,
					   birth,
					   quotas[owner].scope_cookie,
					   quotas[owner].generation,
					   owner,
					   0 };
}
static inline int se_inode_lookup(__u64 address, struct se_inode_row **out)
{
	*out = 0;
	if (lookup_error)
		return SE_INODE_STORAGE_ERROR;
	for (unsigned i = 0; i < ROWS; i++) {
		if (rows[i].identity.inode_address == address) {
			*out = &rows[i];
			return SE_INODE_OK;
		}
	}
	return SE_INODE_MISSING;
}
static inline int se_inode_account(const struct se_inode_identity *identity,
				   struct se_inode_quota **out)
{
	*out = 0;
	if (account_error)
		return SE_INODE_STORAGE_ERROR;
	if (account_wrong) {
		*out = &quotas[1];
		return SE_INODE_OK;
	}
	for (unsigned i = 0; i < 2; i++) {
		if (i == identity->charge_slot &&
		    quotas[i].scope_cookie == identity->charge_scope_cookie &&
		    quotas[i].generation == identity->charge_generation) {
			*out = &quotas[i];
			return SE_INODE_OK;
		}
	}
	return SE_INODE_MISSING;
}
static inline int se_inode_insert(const struct se_inode_row *row)
{
	inserts++;
	if (insert_error)
		return insert_error;
	for (unsigned i = 0; i < ROWS; i++) {
		if (rows[i].identity.inode_address ==
		    row->identity.inode_address)
			return SE_INODE_CONFLICT;
	}
	for (unsigned i = 0; i < ROWS; i++) {
		if (!rows[i].identity.inode_address) {
			rows[i] = *row;
			return SE_INODE_OK;
		}
	}
	return SE_INODE_STORAGE_ERROR;
}
static inline int
se_inode_delete_exact(const struct se_inode_identity *identity)
{
	deletes++;
	if (delete_error)
		return delete_error;
	for (unsigned i = 0; i < ROWS; i++) {
		if (rows[i].identity.inode_address != identity->inode_address)
			continue;
		if (!se_inode_identity_equal(&rows[i].identity, identity))
			return SE_INODE_CONFLICT;
		rows[i] = (struct se_inode_row){};
		return SE_INODE_OK;
	}
	return SE_INODE_MISSING;
}
static void unknown(__u64 address, __u64 birth)
{
	struct se_inode_fact fact = { 1, 1 };
	assert(se_inode_read_memfd(address, birth, &fact) != SE_INODE_OK);
	assert(!fact.known_memfd && !fact.memfd);
}
static void known(__u64 address, __u64 birth)
{
	struct se_inode_fact fact = {};
	assert(se_inode_read_memfd(address, birth, &fact) == SE_INODE_OK);
	assert(fact.known_memfd == 1 && fact.memfd == 1);
}
static void reset(void)
{
	memset(rows, 0, sizeof(rows));
	quotas[0] = (struct se_inode_quota){ .scope_cookie = 10,
					     .generation = 7,
					     .limit = 2 };
	quotas[1] = (struct se_inode_quota){ .scope_cookie = 20,
					     .generation = 8,
					     .limit = 2 };
	lookup_error = account_error = insert_error = delete_error =
		account_wrong = 0;
	inserts = deletes = 0;
}
static void identity_and_errors(void)
{
	reset();
	struct se_inode_identity a = id(100, 1, 0), other = id(100, 1, 1);
	unknown(100, 1);
	unknown(0, 1);
	unknown(100, 0);
	struct se_inode_identity invalid = a;
	invalid.birth_cookie = 0;
	assert(se_inode_mark_memfd(&invalid) == SE_INODE_INVALID);
	assert(!quotas[0].used && !inserts);
	lookup_error = 1;
	assert(se_inode_mark_memfd(&a) == SE_INODE_STORAGE_ERROR);
	lookup_error = 0;
	account_error = 1;
	assert(se_inode_mark_memfd(&a) == SE_INODE_STORAGE_ERROR);
	account_error = 0;
	account_wrong = 1;
	assert(se_inode_mark_memfd(&a) == SE_INODE_CONFLICT);
	assert(!quotas[0].used && !quotas[1].used);
	account_wrong = 0;
	struct se_inode_identity missing_account = a;
	missing_account.charge_generation++;
	assert(se_inode_mark_memfd(&missing_account) == SE_INODE_MISSING);
	for (int error = SE_INODE_STORAGE_ERROR; error <= SE_INODE_CONFLICT;
	     error++) {
		if (error != SE_INODE_STORAGE_ERROR &&
		    error != SE_INODE_CONFLICT)
			continue;
		insert_error = error;
		assert(se_inode_mark_memfd(&a) == error);
		assert(!quotas[0].used);
		unknown(100, 1);
	}
	insert_error = 0;
	assert(!se_inode_mark_memfd(&a));
	unsigned calls = inserts;
	assert(!se_inode_mark_memfd(&a) && inserts == calls &&
	       quotas[0].used == 1);
	assert(se_inode_mark_memfd(&other) == SE_INODE_CONFLICT);
	assert(!quotas[1].used && quotas[0].used == 1);
	struct se_inode_identity failed_attempt = id(200, 9, 0);
	insert_error = SE_INODE_CONFLICT;
	assert(se_inode_mark_memfd(&failed_attempt) == SE_INODE_CONFLICT);
	assert(quotas[0].used == 1);
	known(100, 1);
	insert_error = 0;
	assert(se_inode_retire_dead(&other) == SE_INODE_CONFLICT && !deletes);
	other = a;
	other.birth_cookie++;
	assert(se_inode_mark_memfd(&other) == SE_INODE_CONFLICT);
	assert(se_inode_retire_dead(&other) == SE_INODE_CONFLICT && !deletes);
	unknown(100, 2);
	known(100, 1);
	lookup_error = 1;
	unknown(100, 1);
	lookup_error = 0;
	account_error = 1;
	assert(se_inode_retire_dead(&a) == SE_INODE_STORAGE_ERROR);
	assert(quotas[0].used == 1 && !deletes);
	unknown(100, 1);
	account_error = 0;
	assert(!se_inode_retire_dead(&a) && !quotas[0].used);
	assert(se_inode_retire_dead(&a) == SE_INODE_MISSING && !quotas[0].used);
}
static void failed_delete_and_aba(void)
{
	reset();
	struct se_inode_identity a = id(100, 1, 0);
	assert(!se_inode_mark_memfd(&a));
	int errors[] = { SE_INODE_STORAGE_ERROR, SE_INODE_CONFLICT,
			 SE_INODE_MISSING };
	for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		delete_error = errors[i];
		assert(se_inode_retire_dead(&a) == errors[i]);
		assert(quotas[0].used == 1);
		unknown(100, 1);
		assert(se_inode_mark_memfd(&a) == SE_INODE_INVALID);
	}
	delete_error = 0;
	assert(!se_inode_retire_dead(&a) && !quotas[0].used);
	struct se_inode_identity replacement = id(100, 2, 1);
	assert(!se_inode_mark_memfd(&replacement));
	unsigned calls = deletes;
	assert(se_inode_retire_dead(&a) == SE_INODE_CONFLICT &&
	       calls == deletes);
	assert(!quotas[0].used && quotas[1].used == 1);
	known(100, 2);
	struct se_inode_identity stale_charge = replacement;
	stale_charge.charge_generation--;
	assert(se_inode_retire_dead(&stale_charge) == SE_INODE_CONFLICT);
	known(100, 2);
	assert(!se_inode_retire_dead(&replacement) && !quotas[1].used);
}
static void retired_account_and_capacity(void)
{
	reset();
	struct se_inode_identity a = id(100, 1, 0), b = id(101, 2, 0);
	struct se_inode_identity c = id(102, 3, 1), d = id(103, 4, 1);
	assert(!se_inode_mark_memfd(&a) && !se_inode_mark_memfd(&b));
	struct se_inode_identity excess = id(104, 5, 0);
	assert(se_inode_mark_memfd(&excess) == SE_INODE_QUOTA_ERROR);
	assert(!se_inode_mark_memfd(
		&c)); /* Neighbor's reservation still works. */
	assert(se_inode_mark_memfd(&d) == SE_INODE_STORAGE_ERROR);
	assert(quotas[0].used == 2 &&
	       quotas[1].used == 1); /* refund attempt only */
	quotas[0].retired = 1; /* binding gone; shared physical files survive */
	known(100, 1);
	known(101, 2); /* another binding can execute them */
	assert(!se_inode_retire_dead(&a) && quotas[0].used == 1);
	assert(!se_inode_mark_memfd(&d) && quotas[1].used == 2);
	assert(se_inode_mark_memfd(&excess) == SE_INODE_QUOTA_ERROR);
	assert(!se_inode_retire_dead(&b) && !quotas[0].used);
	/* Reuse the account only after its old rows/operations have drained. */
	quotas[0].generation++;
	quotas[0].retired = 0;
	struct se_inode_identity fresh = id(100, 6, 0);
	assert(!se_inode_mark_memfd(&fresh));
	assert(se_inode_retire_dead(&a) == SE_INODE_CONFLICT &&
	       quotas[0].used == 1);
	known(100, 6);
	assert(!se_inode_retire_dead(&fresh));
	assert(!se_inode_retire_dead(&c));
	assert(!se_inode_retire_dead(&d));
	assert(!quotas[0].used && !quotas[1].used);
}
static void cumulative_recovery(void)
{
	reset();
	/* More than the old lifetime ceiling, with only THREE backing rows. */
	for (__u64 birth = 1; birth <= 100000; birth++) {
		unsigned owner = birth & 1;
		struct se_inode_identity current = id(100, birth, owner);
		assert(!se_inode_mark_memfd(&current));
		known(100, birth);
		assert(quotas[owner].used == 1 && !quotas[owner ^ 1].used);
		assert(!se_inode_retire_dead(&current));
		assert(!quotas[0].used && !quotas[1].used);
		unknown(100, birth);
	}
}
int main(void)
{
	identity_and_errors();
	failed_delete_and_aba();
	retired_account_and_capacity();
	cumulative_recovery();
	puts("shared inode facts: exact charge/refund, invalid charged retries, identity fencing, retired account and 100000 bounded-pool reuse cycles passed");
}
