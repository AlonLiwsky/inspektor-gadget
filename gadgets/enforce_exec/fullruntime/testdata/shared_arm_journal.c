/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "shared-arm-journal.h"

struct fixture_ctx {
	struct se_arm_journal *journal;
	int writes, triggers, proofs;
};

static int journal_append(void *ctx, enum se_arm_journal_phase phase,
			  const struct se_arm_request *request,
			  const struct se_arm_receipt *receipt)
{
	struct fixture_ctx *fixture = ctx;
	return se_arm_journal_append(fixture->journal, phase, request, receipt);
}

static int write_request(void *ctx, const struct se_arm_request *request)
{
	struct fixture_ctx *fixture = ctx;
	assert(request->node_cookie == 4 && request->sequence == 8);
	assert(fixture->journal->phase == SE_ARM_TX_PREPARED);
	fixture->writes++;
	return 0;
}

static int trigger_a(void *ctx, __u64 sequence)
{
	struct fixture_ctx *fixture = ctx;
	assert(fixture->writes == 1 && sequence == 8);
	assert(fixture->journal->phase == SE_ARM_TX_WRITTEN);
	fixture->triggers++;
	return 0;
}

static int state_proof(void *ctx, const struct se_arm_request *request,
		       const struct se_arm_receipt *receipt)
{
	struct fixture_ctx *fixture = ctx;
	assert(request->sequence == receipt->sequence);
	assert(fixture->journal->phase == SE_ARM_TX_WRITTEN ||
	       fixture->journal->phase == SE_ARM_TX_PREPARED);
	fixture->proofs++;
	return 0;
}

static struct se_arm_request request(void)
{
	struct se_arm_request req = {};
	req.node_cookie = 4;
	req.sequence = 8;
	req.scope = 9;
	req.serial = 3;
	req.expected_generation = 2;
	req.operation = SE_ARM_COMMIT;
	req.count = 1;
	return req;
}

static struct se_arm_receipt receipt(void)
{
	return (struct se_arm_receipt){ .node_cookie = 4,
					.sequence = 8,
					.generation = 3,
					.serial = 3,
					.operation = SE_ARM_COMMIT };
}

static void external_mutation_holds(int replace)
{
	char dir[] = "/tmp/se-arm-journal-mutation-XXXXXX";
	assert(mkdtemp(dir));
	int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(dir_fd >= 0);
	struct se_arm_journal journal = {};
	assert(!se_arm_journal_create_at(dir_fd, 4, &journal));
	struct se_arm_request req = request();
	assert(!se_arm_journal_append(&journal, SE_ARM_J_PREPARED, &req, 0));
	if (replace) {
		assert(!unlinkat(dir_fd, "arm.journal", 0));
		int other = openat(dir_fd, "arm.journal",
				   O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
				   0600);
		assert(other >= 0 && !close(other));
	} else {
		assert(!ftruncate(journal.fd, 0));
	}
	assert(se_arm_journal_append(&journal, SE_ARM_J_WRITTEN, &req, 0));
	assert(journal.poisoned && journal.phase == SE_ARM_TX_PREPARED);
	struct se_arm_transaction tx = {};
	assert(se_arm_journal_restore_hold(&journal, &tx));
	assert(!se_arm_journal_close(&journal));
	assert(!unlinkat(dir_fd, "arm.journal", 0));
	assert(!close(dir_fd));
	assert(!rmdir(dir));
}

int main(void)
{
	external_mutation_holds(0);
	external_mutation_holds(1);
	char dir[] = "/tmp/se-arm-journal-XXXXXX";
	assert(mkdtemp(dir));
	int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(dir_fd >= 0);
	struct se_arm_journal journal = {};
	errno = 0;
	assert(se_arm_journal_open_at(dir_fd, 4, &journal) && errno == ENOENT);
	assert(!se_arm_journal_create_at(dir_fd, 4, &journal));
	assert(journal.initialized && journal.phase == SE_ARM_TX_EMPTY);
	struct se_arm_journal second = {};
	errno = 0;
	assert(se_arm_journal_create_at(dir_fd, 4, &second) && errno == EEXIST);
	assert(se_arm_journal_open_at(dir_fd, 4,
				      &second)); /* exclusive writer */
	assert(!second.initialized);
	struct se_arm_transaction tx = {};
	assert(!se_arm_tx_init(&tx, 4));
	struct fixture_ctx fixture = { .journal = &journal };
	struct se_arm_tx_ops ops = { .ctx = &fixture,
				     .journal = journal_append,
				     .write_request = write_request,
				     .trigger_a = trigger_a,
				     .state_proof = state_proof };
	struct se_arm_request req = request();
	assert(!se_arm_tx_stage(&tx, &req, &ops));
	assert(fixture.writes == 1 && tx.phase == SE_ARM_TX_WRITTEN);
	assert(journal.phase == SE_ARM_TX_WRITTEN);
	assert(!se_arm_tx_permit(&tx, &ops));
	assert(fixture.triggers == 1 && tx.phase == SE_ARM_TX_PERMITTED);
	struct se_arm_receipt got = receipt();
	struct se_arm_receipt bad = got;
	bad.generation++;
	assert(se_arm_journal_append(&journal, SE_ARM_J_RESOLVED, &req, &bad));
	assert(journal.phase == SE_ARM_TX_WRITTEN);
	assert(se_arm_tx_reconcile(&tx, &bad, &ops));
	assert(fixture.proofs == 0);
	assert(!se_arm_tx_reconcile(&tx, &got, &ops));
	assert(fixture.proofs == 1);
	assert(journal.phase == SE_ARM_TX_EMPTY && journal.last_sequence == 8);
	assert(tx.phase == SE_ARM_TX_EMPTY && tx.last_sequence == 8);
	assert(se_arm_journal_append(&journal, SE_ARM_J_PREPARED, &req, 0));
	assert(!se_arm_journal_close(&journal));
	journal = (struct se_arm_journal){};
	assert(!se_arm_journal_open_at(dir_fd, 4, &journal));
	assert(journal.phase == SE_ARM_TX_EMPTY && journal.last_sequence == 8);
	struct se_arm_transaction restored = {};
	assert(!se_arm_journal_restore_hold(&journal, &restored));
	assert(restored.phase == SE_ARM_TX_EMPTY &&
	       restored.last_sequence == 8);
	assert(se_arm_tx_stage(&restored, &req, &ops)); /* replay denied */
	/* An unresolved WRITTEN record is recovered as a hold, not skipped. */
	req.sequence = 9;
	assert(!se_arm_journal_append(&journal, SE_ARM_J_PREPARED, &req, 0));
	assert(!se_arm_journal_append(&journal, SE_ARM_J_WRITTEN, &req, 0));
	assert(!se_arm_journal_close(&journal));
	journal = (struct se_arm_journal){};
	assert(!se_arm_journal_open_at(dir_fd, 4, &journal));
	assert(journal.phase == SE_ARM_TX_WRITTEN &&
	       journal.pending.sequence == 9 && journal.last_sequence == 8);
	restored = (struct se_arm_transaction){};
	assert(!se_arm_journal_restore_hold(&journal, &restored));
	assert(restored.phase == SE_ARM_TX_PERMITTED &&
	       restored.request.sequence == 9 && restored.last_sequence == 8);
	assert(se_arm_tx_permit(&restored, &ops)); /* no A replay */
	assert(se_arm_tx_stage(&restored, &req, &ops)); /* no next arm */
	got.sequence = 9;
	assert(!se_arm_tx_reconcile(&restored, &got, &ops));
	assert(journal.last_sequence == 9 && journal.phase == SE_ARM_TX_EMPTY);
	/* PREPARED can be the last durable record if WRITTEN's fsync was
	 * interrupted. It also becomes HOLD, but exact proof may resolve it. */
	req.sequence = 10;
	assert(!se_arm_journal_append(&journal, SE_ARM_J_PREPARED, &req, 0));
	assert(!se_arm_journal_close(&journal));
	journal = (struct se_arm_journal){};
	assert(!se_arm_journal_open_at(dir_fd, 4, &journal));
	assert(journal.phase == SE_ARM_TX_PREPARED &&
	       journal.pending.sequence == 10 && journal.last_sequence == 9);
	restored = (struct se_arm_transaction){};
	assert(!se_arm_journal_restore_hold(&journal, &restored));
	assert(restored.phase == SE_ARM_TX_PERMITTED &&
	       se_arm_tx_permit(&restored, &ops)); /* no A replay */
	got.sequence = 10;
	assert(!se_arm_tx_reconcile(&restored, &got, &ops));
	assert(journal.phase == SE_ARM_TX_EMPTY && journal.last_sequence == 10);
	assert(!se_arm_journal_close(&journal));
	journal = (struct se_arm_journal){};
	errno = 0;
	assert(se_arm_journal_open_at(dir_fd, 5, &journal) && errno == EBADMSG);
	assert(!journal.initialized);
	/* Checksum corruption is terminal, including when record boundaries fit. */
	int fd = openat(dir_fd, "arm.journal", O_RDWR | O_CLOEXEC);
	assert(fd >= 0);
	unsigned char original;
	assert(pread(fd, &original, 1, 32) == 1);
	unsigned char changed = original ^ 1;
	assert(pwrite(fd, &changed, 1, 32) == 1);
	assert(!fsync(fd));
	journal = (struct se_arm_journal){};
	errno = 0;
	assert(se_arm_journal_open_at(dir_fd, 4, &journal) && errno == EBADMSG);
	assert(!journal.initialized);
	assert(pwrite(fd, &original, 1, 32) == 1);
	assert(!fsync(fd));
	assert(!close(fd));
	/* A torn tail is never skipped or truncated on restart. */
	fd = openat(dir_fd, "arm.journal", O_WRONLY | O_APPEND | O_CLOEXEC);
	assert(fd >= 0 && write(fd, "x", 1) == 1);
	assert(!close(fd));
	journal = (struct se_arm_journal){};
	errno = 0;
	assert(se_arm_journal_open_at(dir_fd, 4, &journal) && errno == EBADMSG);
	assert(!journal.initialized);
	assert(!unlinkat(dir_fd, "arm.journal", 0));
	/* Symlinks cannot redirect the journal writer. */
	assert(!symlinkat("/dev/null", dir_fd, "arm.journal"));
	journal = (struct se_arm_journal){};
	assert(se_arm_journal_open_at(dir_fd, 4, &journal));
	assert(!unlinkat(dir_fd, "arm.journal", 0));
	/* Restart cannot silently bootstrap a fresh empty sequence ledger. */
	journal = (struct se_arm_journal){};
	errno = 0;
	assert(se_arm_journal_open_at(dir_fd, 4, &journal) && errno == ENOENT);
	assert(!close(dir_fd));
	assert(!rmdir(dir));
	return 0;
}
