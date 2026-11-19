// SPDX-License-Identifier: GPL-2.0
/* Default-off, test-only exact-kernel fixture for the source-only physical-exec
 * capsule (full/shared_exec_capsule.h). Hooks are the intended product hooks,
 * but the LSM program is PASS-THROUGH: it returns the prior result unchanged,
 * never denies, never consults TASK/WORK/policy maps and never records success
 * history. It only observes which class each admission would use. Not selected
 * by any product image; maps are private and never pinned. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE 1
#define SE_ROUTE_CAPACITY 2
struct se_route_anchor;
struct se_exec_capsule;
struct se_exec_marker;
static __always_inline __u64 *fixture_locator(const __u64 *cgroup);
static __always_inline struct se_route_anchor *
fixture_anchor(const __u32 *slot);
static __always_inline struct se_exec_capsule *fixture_capsule(__u32 tgid);
static __always_inline struct se_exec_marker *fixture_marker(__u32 pid);
static __always_inline __u64 fixture_sequence(void);
static __always_inline void fixture_stat(__u32 index);
#define SE_ROUTE_INDEX_LOOKUP(key) fixture_locator(key)
#define SE_ROUTE_ANCHOR_LOOKUP(key) fixture_anchor(key)
#define SE_CAP_LOOKUP(tgid) fixture_capsule(tgid)
#define SE_CAP_MARKER_LOOKUP(pid) fixture_marker(pid)
#define SE_CAP_NEXT_SEQUENCE() fixture_sequence()
#define SE_CAP_STAT(index) fixture_stat(index)
#include "../../full/shared_exec_capsule.h"

_Static_assert(sizeof(struct se_route_anchor) == 104, "route layout");
_Static_assert(sizeof(struct se_exec_capsule) == 104, "capsule layout");
_Static_assert(sizeof(struct se_exec_marker) == 16, "marker layout");
/* Offsets hard-coded by runner/main.go. */
_Static_assert(__builtin_offsetof(struct se_route_anchor, execution_class) ==
		       56,
	       "class");
_Static_assert(__builtin_offsetof(struct se_route_anchor, phase) == 60,
	       "phase");
_Static_assert(__builtin_offsetof(struct se_route_anchor, early_claims) == 64,
	       "early");
_Static_assert(__builtin_offsetof(struct se_route_anchor, source_pins) == 96,
	       "pins");
_Static_assert(__builtin_offsetof(struct se_route_anchor, unresolved_sources) ==
		       100,
	       "latch");
_Static_assert(__builtin_offsetof(struct se_exec_capsule, phase) == 4,
	       "capsule phase");
_Static_assert(__builtin_offsetof(struct se_exec_capsule, owner) +
			       __builtin_offsetof(struct se_source_mode_owner,
						  owned) ==
		       96,
	       "owned");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_ROUTE_CAPACITY);
	__type(key, __u32);
	__type(value, struct se_route_anchor);
} routes SEC(".maps");
/* cgroup v2 id -> route locator. Written only by the runner before attach. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_ROUTE_CAPACITY);
	__type(key, __u64);
	__type(value, __u64);
} locators SEC(".maps");
/* max_entries is replaced by the runner with the guest pid_max. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct se_exec_capsule);
} capsules SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct se_exec_marker);
} markers SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sequence SEC(".maps");
struct capsule_stats {
	__u64 events[SE_CAP_STATS];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct capsule_stats);
} stats SEC(".maps");

#define OBSERVATIONS 8
struct admission {
	__u64 cgroup, sequence;
	__s32 result;
	__u32 frozen, current_class, pid;
};
struct observation {
	__u32 count, reserved;
	struct admission admissions[OBSERVATIONS];
};
/* Selected/frozen admissions per initial-namespace TGID, for the runner. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct observation);
} observations SEC(".maps");

static __always_inline __u64 *fixture_locator(const __u64 *cgroup)
{
	return bpf_map_lookup_elem(&locators, cgroup);
}
static __always_inline struct se_route_anchor *fixture_anchor(const __u32 *slot)
{
	return bpf_map_lookup_elem(&routes, slot);
}
static __always_inline struct se_exec_capsule *fixture_capsule(__u32 tgid)
{
	return bpf_map_lookup_elem(&capsules, &tgid);
}
static __always_inline struct se_exec_marker *fixture_marker(__u32 pid)
{
	return bpf_map_lookup_elem(&markers, &pid);
}
static __always_inline __u64 fixture_sequence(void)
{
	__u32 zero = 0;
	__u64 *next = bpf_map_lookup_elem(&sequence, &zero);
	if (!next)
		return 0;
	__u64 value = __sync_fetch_and_add(next, 1) + 1;
	return value && value < ~0ULL - 1 ? value : 0;
}
static __always_inline void fixture_stat(__u32 index)
{
	__u32 zero = 0;
	struct capsule_stats *s = bpf_map_lookup_elem(&stats, &zero);
	if (s && index < SE_CAP_STATS)
		__sync_fetch_and_add(&s->events[index], 1);
}

static __always_inline __u32 current_class(__u64 cgroup)
{
	__u64 *locator = bpf_map_lookup_elem(&locators, &cgroup);
	if (!locator)
		return 0;
	__u32 slot = (__u32)*locator;
	struct se_route_anchor *a = bpf_map_lookup_elem(&routes, &slot);
	return a ? a->execution_class : 0; /* unlocked diagnostic read only */
}

/* Attached FIRST by the runner: every call that later observes the entry
 * program below returns through this terminal. */
SEC("fexit/bprm_execve")
int BPF_PROG(capsule_terminal, struct linux_binprm *bprm, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	(void)se_cap_on_terminal(id >> 32, (__u32)id,
				 (__u64)bpf_get_current_task_btf(), (__u64)bprm,
				 ret);
	return 0;
}

SEC("fentry/bprm_execve")
int BPF_PROG(capsule_entry, struct linux_binprm *bprm)
{
	__u64 id = bpf_get_current_pid_tgid();
	se_cap_on_entry((__u32)id, (__u64)bpf_get_current_task_btf(),
			(__u64)bprm);
	return 0;
}

/* AT_EXECVE_CHECK (6.14+) is absent from 6.12 BTF; CO-RE resolves it. */
struct linux_binprm___check {
	unsigned int is_check : 1;
} __attribute__((preserve_access_index));

SEC("fentry/security_bprm_creds_for_exec")
int BPF_PROG(capsule_begin, struct linux_binprm *bprm)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 is_check = 0;
	struct linux_binprm___check *checked = (void *)bprm;
	if (bpf_core_field_exists(checked->is_check))
		is_check = BPF_CORE_READ_BITFIELD_PROBED(checked, is_check);
	(void)se_cap_on_begin(id >> 32, (__u32)id,
			      (__u64)bpf_get_current_task_btf(), (__u64)bprm,
			      is_check);
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(capsule_admit, struct linux_binprm *bprm, int prior)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u64 task = (__u64)bpf_get_current_task_btf();
	__u64 cgroup = bpf_get_current_cgroup_id();
	struct se_route_claim claim = {};
	__u32 frozen = 0;
	int result = se_cap_admit(tgid, (__u32)id, task, (__u64)bprm, cgroup,
				  &claim, &frozen);
	if (claim.owned)
		se_cap_drop_claim(&claim);
	if (result != SE_ROUTE_UNSELECTED || frozen) {
		struct observation *o =
			bpf_map_lookup_elem(&observations, &tgid);
		if (!o) {
			struct observation empty = {};
			(void)bpf_map_update_elem(&observations, &tgid, &empty,
						  BPF_NOEXIST);
			o = bpf_map_lookup_elem(&observations, &tgid);
		}
		if (o) {
			__u32 n = o->count;
			if (n < OBSERVATIONS) {
				struct se_exec_capsule *c =
					fixture_capsule(tgid);
				o->admissions[n].cgroup = cgroup;
				o->admissions[n].sequence = c ? c->sequence : 0;
				o->admissions[n].result = result;
				o->admissions[n].frozen = frozen;
				o->admissions[n].current_class =
					current_class(cgroup);
				o->admissions[n].pid = (__u32)id;
			}
			o->count = n + 1;
		}
	}
	return prior; /* pass-through: this fixture never denies */
}

char LICENSE[] SEC("license") = "GPL";
