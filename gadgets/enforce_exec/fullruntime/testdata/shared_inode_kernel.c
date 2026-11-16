/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
struct bpf_spin_lock {
	int held;
};
static int locks;
static void bpf_spin_lock(struct bpf_spin_lock *l)
{
	assert(!locks && !l->held);
	locks = l->held = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *l)
{
	assert(locks && l->held);
	locks = l->held = 0;
}
#define SEC(x)
#define __uint(n, v) int n
#define __type(n, t) t *n
#define BPF_PROG(n, ...) n(__VA_ARGS__)
#define BPF_NOEXIST 1
#define SE_PROFILE_BINDINGS 2
#define SE_PROFILE_SLOTS_256 2
#define SE_PROFILE_SLOTS_1024 0
#define SE_PROFILE_SLOTS_4096 0
#define SE_PROFILE_SLOTS_16384 0
#define SE_PROFILE_INODE_FACTS 4
#define SE_PROFILE_INODE_QUOTA 1
struct super_block {
	unsigned long s_magic;
};
struct inode {
	struct super_block *i_sb;
};
struct hlist_bl_node {
	int unused;
};
struct dentry {
	struct dentry *d_parent;
	struct {
		struct hlist_bl_node **pprev;
	} d_hash;
};
struct file {
	struct inode *f_inode;
	struct {
		struct dentry *dentry;
	} f_path;
};
struct qstr {
	__u32 len;
	const unsigned char *name;
};
#define BPF_CORE_READ_INTO(out, src, field) (*(out) = (src)->field, 0)
static int bpf_probe_read_kernel(void *out, unsigned long n, const void *src)
{
	memcpy(out, src, n);
	return 0;
}
static __u64 cgroup = 7;
static void *bpf_map_lookup_elem(void *, const void *);
static int bpf_map_update_elem(void *, const void *, const void *, int);
static int bpf_map_delete_elem(void *, const void *);
static void *bpf_task_storage_get(void *m, void *t, void *v, int f)
{
	(void)m;
	(void)t;
	(void)v;
	(void)f;
	return 0;
}
static void *bpf_get_current_task_btf(void)
{
	return 0;
}
static __u64 bpf_get_current_cgroup_id(void)
{
	return cgroup;
}
struct se_route_anchor;
static inline const __u64 *se_route_index_lookup(const __u64 *);
static inline struct se_route_anchor *se_route_anchor_lookup(const __u32 *);
#define SE_ROUTE_CAPACITY 2
#define SE_ROUTE_INDEX_LOOKUP(k) se_route_index_lookup(k)
#define SE_ROUTE_ANCHOR_LOOKUP(k) se_route_anchor_lookup(k)
#include "shared_control.h"
#include "shared_inode_kernel.h"
#define FULL_FS_SHARED_MARK(inode) se_fs_mark_memfd(inode)
#define FULL_FS_SHARED_READ(inode) se_fs_known_memfd(inode)
#include "filesystem.h"
static struct se_route_anchor routes[2];
static struct se_inode_account_state accounts[3];
static struct se_inode_row rows[4];
static __u64 locators[2];
static int delete_failed;
static struct se_node_config config = { .node_cookie = 99,
					.nonce = 2,
					.abi = 3,
					.profile_version = 1,
					.bindings = 2,
					.objects = 2,
					.cells = 512,
					.slots = { 2, 0, 0, 0 } };
static void *bpf_map_lookup_elem(void *map, const void *key)
{
	assert(!locks);
	if (map == &se_inode_facts) {
		for (int i = 0; i < 4; i++)
			if (rows[i].identity.inode_address == *(__u64 *)key)
				return &rows[i];
		return 0;
	}
	if (map == &se_inode_accounts) {
		__u32 k = *(__u32 *)key;
		return k < 3 ? &accounts[k] : 0;
	}
	if (map == &se_routes) {
		__u32 k = *(__u32 *)key;
		return k < 2 ? &routes[k] : 0;
	}
	if (map == &se_route_index) {
		__u64 k = *(__u64 *)key;
		return k == 7 ? &locators[0] : k == 8 ? &locators[1] : 0;
	}
	if (map == &se_configuration)
		return &config;
	return 0;
}
static int bpf_map_update_elem(void *map, const void *key, const void *value,
			       int flags)
{
	assert(!locks && map == &se_inode_facts && flags == BPF_NOEXIST);
	if (bpf_map_lookup_elem(map, key))
		return -1;
	for (int i = 0; i < 4; i++)
		if (!rows[i].identity.inode_address) {
			memcpy(&rows[i], value, sizeof(rows[i]));
			return 0;
		}
	return -1;
}
static int bpf_map_delete_elem(void *map, const void *key)
{
	assert(!locks && map == &se_inode_facts);
	if (delete_failed)
		return -1;
	struct se_inode_row *row = bpf_map_lookup_elem(map, key);
	if (!row)
		return -1;
	memset(row, 0, sizeof(*row));
	return 0;
}
static inline const __u64 *se_route_index_lookup(const __u64 *k)
{
	return bpf_map_lookup_elem(&se_route_index, k);
}
static inline struct se_route_anchor *se_route_anchor_lookup(const __u32 *k)
{
	return bpf_map_lookup_elem(&se_routes, k);
}
static void reset(void)
{
	memset(routes, 0, sizeof(routes));
	memset(accounts, 0, sizeof(accounts));
	memset(rows, 0, sizeof(rows));
	delete_failed = 0;
	cgroup = 7;
	for (unsigned i = 0; i < 2; i++) {
		routes[i] =
			(struct se_route_anchor){ .incarnation = 1,
						  .cgroup_identity = 7 + i,
						  .scope = 11 + i,
						  .payload_generation = 20,
						  .active_serial = 1,
						  .payload_slot = i,
						  .execution_class = 1,
						  .phase = SE_ROUTE_ACTIVE };
		locators[i] = se_route_locator(i, 1);
	}
}
static void decoder(void)
{
	reset();
	struct super_block sb = { .s_magic = 0x01021994UL };
	struct inode inode = { .i_sb = &sb };
	struct dentry parent = {}, dentry = { .d_parent = &parent };
	struct file file = { .f_inode = &inode,
			     .f_path = { .dentry = &dentry } };
	struct full_fs_facts facts = full_file_filesystem(&file);
	assert((facts.mask & FULL_FS_TMPFS) && !(facts.known & FULL_FS_MEMFD));
	struct qstr user = { .len = 7,
			     .name = (const unsigned char *)"userfd!" };
	full_fs_mark_memfd(&inode, &user);
	assert(!se_fs_known_memfd(&inode));
	struct qstr kernel = { .len = 7,
			       .name = (const unsigned char *)"[memfd]" };
	full_fs_mark_memfd(&inode, &kernel);
	facts = full_file_filesystem(&file);
	assert((facts.known & FULL_FS_MEMFD) && (facts.mask & FULL_FS_MEMFD) &&
	       (facts.mask & FULL_FS_DELETED));
	se_inode_free(&inode);
	facts = full_file_filesystem(&file);
	assert(!(facts.known & FULL_FS_MEMFD));
	sb.s_magic = 0x958458f6UL;
	facts = full_file_filesystem(&file);
	assert(!(facts.known & FULL_FS_MEMFD));
	sb.s_magic = 0x794c7630UL;
	facts = full_file_filesystem(&file);
	assert((facts.known & FULL_FS_MEMFD) && !(facts.mask & FULL_FS_MEMFD) &&
	       (facts.mask & FULL_FS_OVERLAY));
}
int main(void)
{
	struct inode a = {}, b = {}, c = {}, d = {}, e = {};
	decoder();
	reset();
	for (int i = 0; i < 10000; i++) {
		se_fs_mark_memfd(&a);
		assert(se_fs_known_memfd(&a));
		assert(routes[0].inode_refs == 1 &&
		       accounts[0].quota.used == 1);
		se_inode_free(&a);
		assert(!se_fs_known_memfd(&a) && !routes[0].inode_refs &&
		       !accounts[0].quota.used);
	}
	se_fs_mark_memfd(&a);
	se_fs_mark_memfd(&b);
	assert(se_fs_known_memfd(&a) && !se_fs_known_memfd(&b));
	cgroup = 8;
	se_fs_mark_memfd(&b);
	assert(se_fs_known_memfd(&b) && accounts[1].quota.used == 1);
	cgroup = 9;
	se_fs_mark_memfd(&c);
	se_fs_mark_memfd(&d);
	se_fs_mark_memfd(&e);
	assert(se_fs_known_memfd(&c) && se_fs_known_memfd(&d) &&
	       !se_fs_known_memfd(&e));
	routes[0].phase = SE_ROUTE_WITHDRAWN;
	locators[0] = 0;
	assert(se_fs_known_memfd(&a));
	se_inode_free(&a);
	assert(!accounts[0].quota.used && !routes[0].inode_refs &&
	       accounts[1].quota.used == 1);
	se_inode_free(&b);
	se_inode_free(&c);
	se_inode_free(&d);
	assert(!accounts[2].quota.used);
	reset();
	se_fs_mark_memfd(&a);
	delete_failed = 1;
	se_inode_free(&a);
	assert(!se_fs_known_memfd(&a) && accounts[0].quota.used == 1 &&
	       routes[0].inode_refs == 1);
	delete_failed = 0;
	se_fs_mark_memfd(&a);
	se_inode_free(&a);
	assert(!se_fs_known_memfd(&a) && accounts[0].quota.used == 1 &&
	       routes[0].inode_refs == 1);
	puts("actual shared inode hook bodies: fixed pool, quotas, original refund, failure quarantine passed");
	return 0;
}
