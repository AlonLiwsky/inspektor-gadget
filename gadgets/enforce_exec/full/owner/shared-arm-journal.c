/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include "shared-arm-journal.h"

#define SE_ARM_J_MAGIC 0x5341524dU
#define SE_ARM_J_VERSION 1U
#define SE_ARM_J_NAME "arm.journal"

/* Native amd64-only disk format. A torn tail or invalid checksum is a hard
 * recovery HOLD; no truncation, skip or guess is permitted. */
struct se_arm_journal_record {
	uint32_t magic, version, phase, reserved;
	uint64_t node_cookie, sequence;
	struct se_arm_request request;
	struct se_arm_receipt receipt;
	uint32_t crc32, tail_reserved;
};
_Static_assert(sizeof(struct se_arm_journal_record) == 264, "arm journal wire");
_Static_assert(offsetof(struct se_arm_journal_record, crc32) == 256,
	       "arm journal checksum offset");

static uint32_t se_arm_crc32(const void *bytes, size_t length)
{
	const unsigned char *p = bytes;
	uint32_t crc = ~0U;
	for (size_t i = 0; i < length; i++) {
		crc ^= p[i];
		for (unsigned int bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ (0xedb88320U & -(crc & 1U));
	}
	return ~crc;
}

static int se_arm_journal_padding_zero(const struct se_arm_request *request)
{
	const unsigned char *bytes = (const unsigned char *)request;
	for (size_t i = offsetof(struct se_arm_request, bank_index) +
			sizeof(request->bank_index);
	     i < offsetof(struct se_arm_request, epochs); i++)
		if (bytes[i])
			return 0;
	return 1;
}

static int se_arm_journal_apply(struct se_arm_journal *j,
				const struct se_arm_journal_record *r)
{
	if (r->magic != SE_ARM_J_MAGIC || r->version != SE_ARM_J_VERSION ||
	    r->reserved || r->tail_reserved ||
	    r->crc32 != se_arm_crc32(r, offsetof(struct se_arm_journal_record,
						 crc32)) ||
	    r->node_cookie != j->node_cookie ||
	    r->request.node_cookie != j->node_cookie ||
	    r->request.sequence != r->sequence || !r->sequence ||
	    r->sequence == UINT64_MAX || r->request.reserved ||
	    !se_arm_journal_padding_zero(&r->request) ||
	    r->request.operation < SE_ARM_COMMIT ||
	    r->request.operation > SE_ARM_BIND)
		return -1;
	switch (r->phase) {
	case SE_ARM_J_PREPARED:
		if (j->phase != SE_ARM_TX_EMPTY ||
		    r->sequence <= j->last_sequence ||
		    memcmp(&r->receipt, &(struct se_arm_receipt){},
			   sizeof(r->receipt)))
			return -1;
		j->pending = r->request;
		j->phase = SE_ARM_TX_PREPARED;
		return 0;
	case SE_ARM_J_WRITTEN:
		if (j->phase != SE_ARM_TX_PREPARED ||
		    memcmp(&j->pending, &r->request, sizeof(r->request)) ||
		    memcmp(&r->receipt, &(struct se_arm_receipt){},
			   sizeof(r->receipt)))
			return -1;
		j->phase = SE_ARM_TX_WRITTEN;
		return 0;
	case SE_ARM_J_RESOLVED:
		/* A crash after WRITTEN's write but before its fsync may leave
		 * only PREPARED durable even if A ran. Never retrigger A; allow
		 * recovery solely after exact receipt and locked state proof. */
		if ((j->phase != SE_ARM_TX_PREPARED &&
		     j->phase != SE_ARM_TX_WRITTEN) ||
		    memcmp(&j->pending, &r->request, sizeof(r->request)) ||
		    !se_arm_tx_receipt_matches(&r->request, &r->receipt))
			return -1;
		j->last_sequence = r->sequence;
		memset(&j->pending, 0, sizeof(j->pending));
		j->phase = SE_ARM_TX_EMPTY;
		return 0;
	default:
		return -1;
	}
}

static int se_arm_journal_scan(struct se_arm_journal *j)
{
	struct stat st;
	if (fstat(j->fd, &st) || st.st_size < 0 ||
	    st.st_size % (off_t)sizeof(struct se_arm_journal_record))
		return -1;
	for (off_t offset = 0; offset < st.st_size;
	     offset += sizeof(struct se_arm_journal_record)) {
		struct se_arm_journal_record record;
		if (pread(j->fd, &record, sizeof(record), offset) !=
			    sizeof(record) ||
		    se_arm_journal_apply(j, &record))
			return -1;
	}
	return 0;
}

static int se_arm_journal_file_unchanged(struct se_arm_journal *j);

static int se_arm_journal_open_internal(int trusted_dir_fd, __u64 node_cookie,
					struct se_arm_journal *journal,
					int create)
{
	if (!journal || journal->initialized || !node_cookie ||
	    sizeof(void *) != 8 || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__) {
		errno = EINVAL;
		return -1;
	}
	struct stat dir_st;
	if (fstat(trusted_dir_fd, &dir_st))
		return -1;
	if (!S_ISDIR(dir_st.st_mode) || dir_st.st_uid != geteuid() ||
	    (dir_st.st_mode & 022)) {
		errno = EACCES;
		return -1;
	}
	int flags = O_RDWR | O_APPEND | O_CLOEXEC | O_NOFOLLOW;
	if (create)
		flags |= O_CREAT | O_EXCL;
	int fd = openat(trusted_dir_fd, SE_ARM_J_NAME, flags, 0600);
	if (fd < 0)
		return -1;
	struct stat st;
	if (fstat(fd, &st))
		goto fail;
	if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
	    st.st_nlink != 1 || (st.st_mode & 077) ||
	    st.st_dev != dir_st.st_dev) {
		errno = EACCES;
		goto fail;
	}
	if (flock(fd, LOCK_EX | LOCK_NB))
		goto fail;
	if (create && fsync(trusted_dir_fd))
		goto fail;
	int owned_dir_fd = fcntl(trusted_dir_fd, F_DUPFD_CLOEXEC, 0);
	if (owned_dir_fd < 0)
		goto fail;
	*journal = (struct se_arm_journal){ .fd = fd,
					    .dir_fd = owned_dir_fd,
					    .node_cookie = node_cookie,
					    .device = st.st_dev,
					    .inode = st.st_ino,
					    .size = st.st_size,
					    .initialized = 1 };
	if (se_arm_journal_scan(journal) ||
	    se_arm_journal_file_unchanged(journal)) {
		errno = EBADMSG;
		*journal = (struct se_arm_journal){};
		close(owned_dir_fd);
		goto fail;
	}
	return 0;
fail: {
	int saved = errno;
	close(fd);
	errno = saved;
	return -1;
}
}

static int se_arm_journal_file_unchanged(struct se_arm_journal *j)
{
	struct stat fd_st, path_st, dir_st;
	if (fstat(j->fd, &fd_st) || fstat(j->dir_fd, &dir_st) ||
	    fstatat(j->dir_fd, SE_ARM_J_NAME, &path_st, AT_SYMLINK_NOFOLLOW) ||
	    !S_ISDIR(dir_st.st_mode) || dir_st.st_uid != geteuid() ||
	    (dir_st.st_mode & 022) || !S_ISREG(fd_st.st_mode) ||
	    !S_ISREG(path_st.st_mode) || fd_st.st_uid != geteuid() ||
	    path_st.st_uid != geteuid() || (fd_st.st_mode & 077) ||
	    (path_st.st_mode & 077) || fd_st.st_dev != j->device ||
	    fd_st.st_ino != j->inode || path_st.st_dev != j->device ||
	    path_st.st_ino != j->inode || fd_st.st_nlink != 1 ||
	    path_st.st_nlink != 1 || fd_st.st_size != j->size ||
	    path_st.st_size != j->size)
		return -1;
	return 0;
}

int se_arm_journal_create_at(int trusted_dir_fd, __u64 node_cookie,
			     struct se_arm_journal *journal)
{
	return se_arm_journal_open_internal(trusted_dir_fd, node_cookie,
					    journal, 1);
}

int se_arm_journal_open_at(int trusted_dir_fd, __u64 node_cookie,
			   struct se_arm_journal *journal)
{
	return se_arm_journal_open_internal(trusted_dir_fd, node_cookie,
					    journal, 0);
}

int se_arm_journal_append(void *ctx, enum se_arm_journal_phase phase,
			  const struct se_arm_request *request,
			  const struct se_arm_receipt *receipt)
{
	struct se_arm_journal *j = ctx;
	if (!j || !j->initialized || j->poisoned || !request ||
	    ((phase == SE_ARM_J_RESOLVED) != (receipt != 0)))
		return -1;
	if (se_arm_journal_file_unchanged(j) ||
	    j->size > INT64_MAX - (off_t)sizeof(struct se_arm_journal_record)) {
		j->poisoned = 1;
		return -1;
	}
	struct se_arm_journal_record record = {
		.magic = SE_ARM_J_MAGIC,
		.version = SE_ARM_J_VERSION,
		.phase = phase,
		.node_cookie = j->node_cookie,
		.sequence = request->sequence,
	};
	memcpy(&record.request, request, sizeof(record.request));
	if (receipt)
		record.receipt = *receipt;
	record.crc32 = se_arm_crc32(
		&record, offsetof(struct se_arm_journal_record, crc32));
	struct se_arm_journal next = *j;
	if (se_arm_journal_apply(&next, &record))
		return -1;
	if (write(j->fd, &record, sizeof(record)) != sizeof(record) ||
	    fsync(j->fd)) {
		j->poisoned = 1;
		return -1;
	}
	j->size += sizeof(record);
	if (se_arm_journal_file_unchanged(j)) {
		j->poisoned = 1;
		return -1;
	}
	next.size = j->size;
	*j = next;
	return 0;
}

int se_arm_journal_restore_hold(const struct se_arm_journal *journal,
				struct se_arm_transaction *tx)
{
	if (!journal || !journal->initialized || journal->poisoned || !tx ||
	    tx->node_cookie || tx->last_sequence || tx->request.sequence ||
	    tx->phase || !journal->node_cookie ||
	    (journal->phase != SE_ARM_TX_EMPTY &&
	     journal->phase != SE_ARM_TX_PREPARED &&
	     journal->phase != SE_ARM_TX_WRITTEN))
		return -1;
	if (journal->phase == SE_ARM_TX_EMPTY) {
		if (journal->pending.sequence)
			return -1;
	} else if (journal->pending.node_cookie != journal->node_cookie ||
		   journal->pending.sequence <= journal->last_sequence)
		return -1;
	tx->node_cookie = journal->node_cookie;
	tx->last_sequence = journal->last_sequence;
	if (journal->phase != SE_ARM_TX_EMPTY) {
		memcpy(&tx->request, &journal->pending, sizeof(tx->request));
		tx->phase = SE_ARM_TX_PERMITTED;
	}
	return 0;
}

int se_arm_journal_close(struct se_arm_journal *journal)
{
	if (!journal || !journal->initialized)
		return -1;
	int fd = journal->fd;
	int dir_fd = journal->dir_fd;
	journal->initialized = 0;
	journal->fd = -1;
	journal->dir_fd = -1;
	int err = close(fd);
	if (close(dir_fd))
		err = -1;
	return err;
}
