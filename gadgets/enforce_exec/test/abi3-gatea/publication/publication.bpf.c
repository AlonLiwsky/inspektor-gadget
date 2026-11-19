// SPDX-License-Identifier: GPL-2.0
// Test-only real-content publication primitive, NOT a full policy evaluator.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "publication.h"
struct scope {
	struct bpf_spin_lock lock;
	PC_STATE_FIELDS;
};
struct task {
	struct bpf_spin_lock lock;
	__u32 slot;
	__u64 cookie, writer_attempt, reader_attempt, reader_bank, reader_mode;
	struct pc_history history[2];
};
_Static_assert(sizeof(struct scope) == sizeof(struct pc_stats), "state ABI");
/* Reviewed fixture payload sizes, NOT kernel allocation/RSS accounting. */
_Static_assert(sizeof(struct scope) == 312 && sizeof(struct task) == 208,
	       "fixture state/task payload");
_Static_assert(sizeof(struct pc_program) == 208 &&
		       sizeof(struct pc_command) == 120,
	       "fixture program/command payload");
_Static_assert(sizeof(struct pc_catalogue) == 16 &&
		       sizeof(struct pc_config) == 24,
	       "fixture catalogue/config payload");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct pc_config);
} config SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PC_TASKS);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct pc_command);
} commands SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct scope);
} state SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct pc_program);
} programs SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PC_UIDS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct pc_catalogue);
} catalogue SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PC_TASKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct task);
} tasks SEC(".maps");
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
static __always_inline struct task *self(void)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	return bpf_map_lookup_elem(&tasks, &key);
}
/* All map pointers used below have fixed ARRAY or never-deleted HASH lifetime.
 * Task addresses are only used by their still-live native thread. No task-row
 * deletion/reuse or complete lineage qualification is claimed by this fixture. */
static __noinline int pin_control(__u32 fd, __u64 *node)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct fdtable *table = 0;
	struct file **fds = 0, *file = 0;
	struct inode *inode = 0;
	struct super_block *sb = 0;
	struct kernfs_node *kn = 0;
	char *name = 0;
	__u32 limit = 0, flags = 0;
	unsigned long magic = 0;
	int error = -22;
	if (fd >= 1024)
		return error;
	bpf_rcu_read_lock();
	if (BPF_CORE_READ_INTO(&table, t, files, fdt) || !table)
		goto done;
	if (BPF_CORE_READ_INTO(&limit, table, max_fds) || fd >= limit)
		goto done;
	if (BPF_CORE_READ_INTO(&fds, table, fd) || !fds)
		goto done;
	if (bpf_probe_read_kernel(&file, sizeof(file), &fds[fd]) || !file)
		goto done;
	if (BPF_CORE_READ_INTO(&flags, file, f_flags) || !(flags & 0x200000))
		goto done;
	if (BPF_CORE_READ_INTO(&inode, file, f_inode) || !inode)
		goto done;
	if (BPF_CORE_READ_INTO(&sb, inode, i_sb) || !sb ||
	    BPF_CORE_READ_INTO(&magic, sb, s_magic) || magic != 0x63677270)
		goto done;
	if (BPF_CORE_READ_INTO(&kn, inode, i_private) || !kn ||
	    BPF_CORE_READ_INTO(&name, kn, name) || !name)
		goto done;
	char text[13] = {};
	if (bpf_probe_read_kernel_str(text, sizeof(text), name) != 13 ||
	    __builtin_memcmp(text, "cgroup.procs", 13))
		goto done;
	*node = (__u64)kn;
	error = 0;
done:
	bpf_rcu_read_unlock();
	return error;
}
static __always_inline void reader_put(struct scope *s)
{
	bpf_spin_lock(&s->lock);
	if (s->readers)
		s->readers--;
	else
		s->incoherent++;
	bpf_spin_unlock(&s->lock);
}
static __always_inline void reader_get_locked(struct scope *s)
{
	s->readers++;
	if (s->readers > s->max_readers)
		s->max_readers = s->readers;
}
static __noinline int register_task(struct scope *s, const struct pc_command *q)
{
	if (q->slot >= PC_TASKS)
		return -22;
	struct task fresh = { .slot = q->slot };
	int result = -16;
	bpf_spin_lock(&s->lock);
	if (s->pinned && !s->active_attempt && !s->attempt &&
	    !(s->registered_mask & (1ULL << q->slot)) &&
	    s->next_cookie != ~0ULL) {
		fresh.cookie = ++s->next_cookie;
		s->registrations++;
		s->registered_mask |= 1ULL << q->slot;
		result = 0;
	}
	bpf_spin_unlock(&s->lock);
	if (result)
		return result;
	__u64 key = (__u64)bpf_get_current_task_btf();
	result = bpf_map_update_elem(&tasks, &key, &fresh, BPF_NOEXIST);
	bpf_spin_lock(&s->lock);
	s->registrations--;
	if (result)
		s->registered_mask &= ~(1ULL << q->slot);
	bpf_spin_unlock(&s->lock);
	return result;
}
static __noinline int reserve_uid(struct scope *s, __u64 uid)
{
	struct pc_catalogue fresh = { .uid = uid };
	int result = bpf_map_update_elem(&catalogue, &uid, &fresh, BPF_NOEXIST);
	if (result && result != -17)
		return -28;
	if (!result) {
		bpf_spin_lock(&s->lock);
		s->reserved++;
		bpf_spin_unlock(&s->lock);
	}
	return 0;
}
static __always_inline __u64 candidate_uid(const struct pc_command *q, int i)
{
	return i == 0 ? q->uid0 : i == 1 ? q->uid1 : q->extra_uids[i - 2];
}
static __noinline int begin(struct scope *s, const struct pc_command *q)
{
	if (!q->attempt || !q->uid0 || !q->uid1 || q->uid0 == q->uid1 ||
	    q->bank > 1 || q->mode > 1)
		return -22;
#pragma unroll
	for (int i = 0; i < PC_ADDITIONS; i++) {
		if (!candidate_uid(q, i))
			return -22;
#pragma unroll
		for (int j = 0; j < PC_ADDITIONS; j++)
			if (i != j &&
			    candidate_uid(q, i) == candidate_uid(q, j))
				return -22;
	}
	int result = -16;
	bpf_spin_lock(&s->lock);
	if (s->registered_mask == PC_ALL_TASKS && !s->registrations &&
	    !s->readers && !s->writers &&
	    (s->phase == PC_NONE || s->phase == PC_ABORTED ||
	     s->phase == PC_COMMITTED) &&
	    q->attempt > s->last_attempt &&
	    (!s->active_attempt || q->bank != s->active_bank)) {
		s->last_attempt = q->attempt;
		s->attempt = q->attempt;
		s->bank = q->bank;
		s->mode = q->mode;
		s->uid0 = q->uid0;
		s->uid1 = q->uid1;
		s->expected_active = s->active_attempt;
		s->phase = PC_LOADING;
		s->receipt_attempt = 0;
		s->staged_mask = 0;
		/* Reserve operations hold authority ownership until all eight finish. */
		reader_get_locked(s);
		result = 0;
	}
	bpf_spin_unlock(&s->lock);
	if (result)
		return result;
#pragma unroll
	for (int i = 0; i < PC_ADDITIONS; i++)
		if (!result)
			result = reserve_uid(s, candidate_uid(q, i));
	bpf_spin_lock(&s->lock);
	s->readers--;
	if (result) {
		s->phase = PC_ABORTED;
		s->refused++;
	}
	bpf_spin_unlock(&s->lock);
	return result;
}
static __noinline int write_begin(struct scope *s, struct task *t,
				  const struct pc_command *q)
{
	__u64 held;
	bpf_spin_lock(&t->lock);
	held = t->writer_attempt;
	bpf_spin_unlock(&t->lock);
	if (held)
		return -16;
	int result = -1;
	bpf_spin_lock(&s->lock);
	if (s->phase == PC_LOADING && s->attempt == q->attempt &&
	    s->bank == q->bank && !s->writers) {
		s->writers++;
		reader_get_locked(s);
		result = 0;
	}
	bpf_spin_unlock(&s->lock);
	if (!result) {
		bpf_spin_lock(&t->lock);
		t->writer_attempt = q->attempt;
		bpf_spin_unlock(&t->lock);
	}
	return result;
}
static __noinline int write_end(struct scope *s, struct task *t,
				const struct pc_command *q)
{
	if (q->bank > 1)
		return -22;
	__u32 bank = q->bank;
	struct pc_program *p = bpf_map_lookup_elem(&programs, &bank);
	struct pc_catalogue *a = bpf_map_lookup_elem(&catalogue, &q->uid0),
			    *b = bpf_map_lookup_elem(&catalogue, &q->uid1);
	__u64 owned;
	bpf_spin_lock(&t->lock);
	owned = t->writer_attempt;
	bpf_spin_unlock(&t->lock);
	if (!owned || owned != q->attempt)
		return -1;
	int valid = 0;
	bpf_spin_lock(&s->lock);
	valid = p && a && b && s->phase == PC_LOADING &&
		s->attempt == q->attempt && s->bank == q->bank &&
		s->mode == q->mode && s->uid0 == q->uid0 &&
		s->uid1 == q->uid1 && s->writers == 1;
	bpf_spin_unlock(&s->lock);
	if (valid) {
		struct pc_program staged = { .stamp = q->bad_stamp ? 0 :
								     q->attempt,
					     .count = 2,
					     .mode = q->mode };
		staged.rules[0] = (struct pc_rule){ q->uid0,
						    a->accepted_epoch ?
							    a->accepted_epoch :
							    q->attempt,
						    1,
						    q->arg0,
						    q->deny_bits & 1,
						    0 };
		staged.rules[1] = (struct pc_rule){ q->uid1,
						    b->accepted_epoch ?
							    b->accepted_epoch :
							    q->attempt,
						    2,
						    q->arg1,
						    (q->deny_bits >> 1) & 1,
						    0 };
#pragma unroll
		for (int i = 0; i < PC_ADDITIONS; i++) {
			__u64 uid = candidate_uid(q, i);
			struct pc_catalogue *entry =
				bpf_map_lookup_elem(&catalogue, &uid);
			if (!entry) {
				valid = 0;
				break;
			}
			staged.additions[i] = (struct pc_epoch){
				uid, entry->accepted_epoch ?
					     entry->accepted_epoch :
					     q->attempt
			};
		}
		if (valid)
			*p = staged;
	}
	bpf_spin_lock(&t->lock);
	t->writer_attempt = 0;
	bpf_spin_unlock(&t->lock);
	bpf_spin_lock(&s->lock);
	s->writers--;
	s->readers--;
	bpf_spin_unlock(&s->lock);
	return valid ? 0 : -22;
}
static __noinline int seal(struct scope *s, const struct pc_command *q)
{
	if (q->bank > 1)
		return -22;
	__u32 bank = q->bank;
	struct pc_program *p = bpf_map_lookup_elem(&programs, &bank);
	if (!p)
		return -2;
	int result = -16;
	bpf_spin_lock(&s->lock);
	if (s->phase == PC_LOADING && s->attempt == q->attempt &&
	    s->bank == q->bank && !s->writers) {
		s->phase = PC_SEALING;
		reader_get_locked(s);
		result = 0;
	}
	bpf_spin_unlock(&s->lock);
	if (result)
		return result;
	/* SEALING excludes every writer throughout this complete content scan. */
	int valid = p->stamp == q->attempt && p->count == 2 &&
		    p->mode == q->mode && p->mode <= PC_STRICT &&
		    p->rules[0].uid == q->uid0 && p->rules[1].uid == q->uid1 &&
		    q->uid0 != q->uid1 && p->rules[0].epoch &&
		    p->rules[1].epoch && p->rules[0].role == 1 &&
		    p->rules[1].role == 2 && p->rules[0].deny <= 1 &&
		    p->rules[1].deny <= 1;
#pragma unroll
	for (int i = 0; i < PC_ADDITIONS; i++) {
		if (p->additions[i].uid != candidate_uid(q, i) ||
		    !p->additions[i].epoch)
			valid = 0;
#pragma unroll
		for (int j = 0; j < PC_ADDITIONS; j++)
			if (i != j &&
			    p->additions[i].uid == p->additions[j].uid)
				valid = 0;
	}
	if (p->additions[0].epoch != p->rules[0].epoch ||
	    p->additions[1].epoch != p->rules[1].epoch)
		valid = 0;
	bpf_spin_lock(&s->lock);
	s->readers--;
	if (valid && s->uid0 == q->uid0 && s->uid1 == q->uid1 &&
	    s->mode == q->mode) {
		s->phase = PC_SEALED;
		result = 0;
	} else {
		s->phase = PC_LOADING;
		result = -22;
	}
	bpf_spin_unlock(&s->lock);
	return result;
}
static __noinline int snapshot(struct scope *s, const struct pc_command *q)
{
	int result = -11;
	bpf_spin_lock(&s->lock);
	if ((s->phase == PC_SEALED || s->phase == PC_STAGING ||
	     s->phase == PC_CERTIFIED) &&
	    s->attempt == q->attempt && !s->readers && !s->writers &&
	    s->serial != ~0ULL) {
		s->phase = PC_STAGING;
		s->receipt_serial = s->serial;
		s->receipt_attempt = 0;
		s->staged_mask = 0;
		result = 0;
	}
	bpf_spin_unlock(&s->lock);
	return result;
}
static __noinline int stage_task(struct scope *s, struct task *t,
				 const struct pc_command *q)
{
	if (q->bank > 1)
		return -22;
	__u32 bank = q->bank;
	struct pc_program *p = bpf_map_lookup_elem(&programs, &bank);
	if (!p)
		return -2;
	/* The lookup received &bank: re-establish the range of the actual stack
  * reload, not just q->bank. The compiler barrier preserves this verifier
  * guard; reject invalid values before acquiring any reader credit. */
	asm volatile("" : "+r"(bank));
	if (bank > 1)
		return -22;
	struct pc_history *target = &t->history[bank];
	asm volatile("" : "+r"(target));
	__u64 old_bank = 0, old_attempt = 0;
	int result = -11;
	bpf_spin_lock(&s->lock);
	if (s->phase == PC_STAGING && s->attempt == q->attempt &&
	    s->bank == q->bank && s->serial == s->receipt_serial) {
		old_bank = s->active_bank;
		old_attempt = s->active_attempt;
		reader_get_locked(s);
		result = 0;
	}
	bpf_spin_unlock(&s->lock);
	if (result)
		return result;
	if (old_bank > 1) {
		reader_put(s);
		return -22;
	}
	struct pc_history next = { .stamp = q->attempt };
	__u32 slot;
	bpf_spin_lock(&t->lock);
	next.cookie = t->cookie;
	slot = t->slot;
/* Preserve same-UID history. Only new fixture UIDs receive explicit roots. */
#pragma unroll
	for (int i = 0; i < 2; i++) {
		struct pc_rule *rule = &p->rules[i];
		struct pc_role *out = &next.roles[i];
		int found = 0;
		if (old_attempt) {
#pragma unroll
			for (int j = 0; j < 2; j++) {
				if (t->history[old_bank].roles[j].uid ==
				    rule->uid) {
					*out = t->history[old_bank].roles[j];
					found = 1;
				}
			}
		}
		if (!found)
			*out = (struct pc_role){ rule->uid, rule->epoch, 1,
						 rule->role, 1 };
		if (q->unknown_mask & (1U << i))
			out->known = 0; // Test-only candidate uncertainty.
	}
	*target = next;
	bpf_spin_unlock(&t->lock);
	int known = next.roles[0].known && next.roles[1].known;
	bpf_spin_lock(&s->lock);
	s->readers--;
	if (slot < PC_TASKS)
		s->staged_mask &= ~(1ULL << slot);
	if (s->serial == s->receipt_serial && slot < PC_TASKS &&
	    (s->mode == PC_AUDIT || known))
		s->staged_mask |= 1ULL << slot;
	else
		result = -11;
	bpf_spin_unlock(&s->lock);
	return result;
}
static __noinline int certify(struct scope *s, const struct pc_command *q)
{
	int result = -11;
	bpf_spin_lock(&s->lock);
	if (s->phase == PC_STAGING && s->attempt == q->attempt &&
	    s->expected_active == s->active_attempt &&
	    s->staged_mask == PC_ALL_TASKS && s->serial == s->receipt_serial &&
	    !s->readers && !s->writers) {
		s->phase = PC_CERTIFIED;
		s->receipt_attempt = q->attempt;
		result = 0;
	}
	bpf_spin_unlock(&s->lock);
	return result;
}
static __noinline int read_begin(struct scope *s, struct task *t)
{
	__u64 owned;
	bpf_spin_lock(&t->lock);
	owned = t->reader_attempt;
	bpf_spin_unlock(&t->lock);
	if (owned)
		return -16;
	__u64 attempt = 0, bank = 0, mode = 0;
	int result = -11;
	bpf_spin_lock(&s->lock);
	if (s->active_attempt && s->serial != ~0ULL) {
		attempt = s->active_attempt;
		bank = s->active_bank;
		mode = s->active_mode;
		reader_get_locked(s);
		s->serial++;
		result = 0;
	}
	bpf_spin_unlock(&s->lock);
	if (result)
		return result;
	bpf_spin_lock(&t->lock);
	t->reader_attempt = attempt;
	t->reader_bank = bank;
	t->reader_mode = mode;
	bpf_spin_unlock(&t->lock);
	return 0;
}
static __noinline int read_end(struct scope *s, struct task *t,
			       const struct pc_command *q)
{
	__u64 attempt, bank, mode, cookie;
	struct pc_history h = {};
	bpf_spin_lock(&t->lock);
	attempt = t->reader_attempt;
	bank = t->reader_bank;
	mode = t->reader_mode;
	cookie = t->cookie;
	if (attempt && bank < 2)
		h = t->history[bank];
	bpf_spin_unlock(&t->lock);
	if (!attempt)
		return -1;
	__u32 key = bank;
	struct pc_program *p = bank < 2 ? bpf_map_lookup_elem(&programs, &key) :
					  0;
	struct pc_catalogue *a = 0, *b = 0;
	if (p) {
		a = bpf_map_lookup_elem(&catalogue, &p->rules[0].uid);
		b = bpf_map_lookup_elem(&catalogue, &p->rules[1].uid);
	}
	int valid = p && a && b && p->stamp == attempt && p->mode == mode &&
		    p->count == 2 && h.stamp == attempt && h.cookie == cookie &&
		    h.roles[0].uid == p->rules[0].uid &&
		    h.roles[1].uid == p->rules[1].uid &&
		    h.roles[0].epoch == p->rules[0].epoch &&
		    h.roles[1].epoch == p->rules[1].epoch &&
		    a->accepted_epoch == h.roles[0].epoch &&
		    b->accepted_epoch == h.roles[1].epoch;
	int deny = 0;
	if (valid) {
#pragma unroll
		for (int i = 0; i < 2; i++) {
			if (!h.roles[i].known) {
				if (mode == PC_STRICT)
					deny = 1;
			} else if (q->arg0 == p->rules[i].arg &&
				   h.roles[i].role == p->rules[i].role &&
				   p->rules[i].deny)
				deny = 1;
		}
	}
	bpf_spin_lock(&t->lock);
	t->reader_attempt = 0;
	bpf_spin_unlock(&t->lock);
	bpf_spin_lock(&s->lock);
	s->readers--;
	if (s->serial != ~0ULL)
		s->serial++;
	else
		s->incoherent++;
	s->evals++;
	if (!valid)
		s->incoherent++;
	if (deny) {
		if (mode == PC_STRICT)
			s->denials++;
		else
			s->audit_denials++;
	}
	bpf_spin_unlock(&s->lock);
	return mode == PC_STRICT && (!valid || deny) ? -1 : 0;
}
static __noinline int query(struct scope *s, const struct pc_command *q)
{
	bpf_spin_lock(&s->lock);
	reader_get_locked(s);
	bpf_spin_unlock(&s->lock);
	struct pc_catalogue *a = bpf_map_lookup_elem(&catalogue, &q->uid0),
			    *b = bpf_map_lookup_elem(&catalogue, &q->uid1);
	bpf_spin_lock(&s->lock);
	s->query0 = a ? a->accepted_epoch : ~0ULL;
	s->query1 = b ? b->accepted_epoch : ~0ULL;
	s->query_attempt = s->active_attempt;
	s->query_bank = s->active_bank;
	s->query_mode = s->active_mode;
	s->readers--;
	bpf_spin_unlock(&s->lock);
	return 0;
}
SEC("syscall") int pc_command(void *unused)
{
	__u32 zero = 0, tid = (__u32)bpf_get_current_pid_tgid();
	struct pc_config *c = bpf_map_lookup_elem(&config, &zero);
	struct scope *s = bpf_map_lookup_elem(&state, &zero);
	struct pc_command *input = bpf_map_lookup_elem(&commands, &tid);
	if (!c || !s || !input)
		return -1;
	struct pc_command q = *input;
	if (!c->nonce || q.nonce != c->nonce ||
	    (__u32)(bpf_get_current_pid_tgid() >> 32) != c->tgid)
		return -1;
	int admin = tid == c->admin_tid;
	if (q.op == PC_PIN) {
		if (!admin)
			return -1;
		__u64 kn = 0;
		if (pin_control(c->control_fd, &kn))
			return -22;
		__u64 task = (__u64)bpf_get_current_task_btf();
		int result = -17;
		bpf_spin_lock(&s->lock);
		if (!s->pinned) {
			s->pinned = 1;
			s->admin_task = task;
			s->control_kn = kn;
			s->serial = 1;
			result = 0;
		}
		bpf_spin_unlock(&s->lock);
		return result;
	}
	if (admin) {
		__u64 task = (__u64)bpf_get_current_task_btf();
		bpf_spin_lock(&s->lock);
		admin = s->pinned && s->admin_task == task;
		bpf_spin_unlock(&s->lock);
	}
	if (q.op == PC_REGISTER)
		return register_task(s, &q);
	struct task *t = self();
	if (!t)
		return -2;
	if (q.op == PC_WRITE_BEGIN)
		return write_begin(s, t, &q);
	if (q.op == PC_WRITE_END)
		return write_end(s, t, &q);
	if (q.op == PC_STAGE)
		return stage_task(s, t, &q);
	if (q.op == PC_READ_BEGIN)
		return read_begin(s, t);
	if (q.op == PC_READ_END)
		return read_end(s, t, &q);
	if (q.op == PC_EVAL) {
		int result = read_begin(s, t);
		return result ? result : read_end(s, t, &q);
	}
	if (!admin)
		return -1;
	if (q.op == PC_BEGIN)
		return begin(s, &q);
	if (q.op == PC_SEAL)
		return seal(s, &q);
	if (q.op == PC_SNAPSHOT)
		return snapshot(s, &q);
	if (q.op == PC_CERTIFY)
		return certify(s, &q);
	if (q.op == PC_QUERY)
		return query(s, &q);
	if (q.op == PC_ARM)
		return -95; // Only the mutex-held fexit may commit.
	if (q.op == PC_ABORT) {
		int result = -16;
		bpf_spin_lock(&s->lock);
		if (q.attempt == s->active_attempt)
			result = -114;
		else if (q.attempt == s->attempt && !s->writers &&
			 !s->readers && s->phase != PC_SEALING) {
			s->phase = PC_ABORTED;
			s->receipt_attempt = 0;
			result = 0;
		}
		bpf_spin_unlock(&s->lock);
		return result;
	}
	return -22;
}
SEC("fexit/cgroup_kn_lock_live")
int BPF_PROG(pc_arm, struct kernfs_node *kn, bool drain, struct cgroup *live)
{
	if (!live || (__u64)live >= ~4095ULL)
		return 0;
	__u32 zero = 0, tid = (__u32)bpf_get_current_pid_tgid();
	struct pc_config *c = bpf_map_lookup_elem(&config, &zero);
	struct scope *s = bpf_map_lookup_elem(&state, &zero);
	struct pc_command *input = bpf_map_lookup_elem(&commands, &tid);
	if (!c || !s || !input || tid != c->admin_tid)
		return 0;
	struct pc_command q = *input;
	if (q.op != PC_ARM || !c->nonce || q.nonce != c->nonce || q.bank > 1)
		return 0;
	__u64 task = (__u64)bpf_get_current_task_btf();
	__u32 bank = q.bank;
	struct pc_program *p = bpf_map_lookup_elem(&programs, &bank);
	/* Stable never-deleted entries: all helpers finish BEFORE the shared lock. */
	struct pc_catalogue *a = bpf_map_lookup_elem(&catalogue, &q.uid0),
			    *b = bpf_map_lookup_elem(&catalogue, &q.uid1);
	struct pc_catalogue *extra0 =
		bpf_map_lookup_elem(&catalogue, &q.extra_uids[0]);
	struct pc_catalogue *extra1 =
		bpf_map_lookup_elem(&catalogue, &q.extra_uids[1]);
	struct pc_catalogue *extra2 =
		bpf_map_lookup_elem(&catalogue, &q.extra_uids[2]);
	struct pc_catalogue *extra3 =
		bpf_map_lookup_elem(&catalogue, &q.extra_uids[3]);
	struct pc_catalogue *extra4 =
		bpf_map_lookup_elem(&catalogue, &q.extra_uids[4]);
	struct pc_catalogue *extra5 =
		bpf_map_lookup_elem(&catalogue, &q.extra_uids[5]);
	bpf_spin_lock(&s->lock);
	s->arm_result = -11;
	if (!p || !a || !b || !extra0 || !extra1 || !extra2 || !extra3 ||
	    !extra4 || !extra5 || !s->pinned || s->admin_task != task ||
	    s->control_kn != (__u64)kn || s->phase != PC_CERTIFIED ||
	    s->attempt != q.attempt || s->bank != q.bank || s->mode != q.mode ||
	    s->uid0 != q.uid0 || s->uid1 != q.uid1 || q.uid0 == q.uid1 ||
	    s->receipt_attempt != q.attempt || s->receipt_serial != s->serial ||
	    s->serial == ~0ULL || s->expected_active != s->active_attempt ||
	    s->staged_mask != PC_ALL_TASKS || s->readers || s->writers ||
	    s->registrations || p->stamp != q.attempt || p->count != 2 ||
	    p->mode != q.mode || a->uid != q.uid0 || b->uid != q.uid1 ||
	    p->rules[0].uid != q.uid0 || p->rules[1].uid != q.uid1 ||
	    !p->rules[0].epoch || !p->rules[1].epoch ||
	    (a->accepted_epoch && a->accepted_epoch != p->rules[0].epoch) ||
	    (b->accepted_epoch && b->accepted_epoch != p->rules[1].epoch) ||
	    p->additions[0].uid != q.uid0 || !p->additions[0].epoch ||
	    a->uid != q.uid0 ||
	    (a->accepted_epoch && a->accepted_epoch != p->additions[0].epoch) ||
	    p->additions[1].uid != q.uid1 || !p->additions[1].epoch ||
	    b->uid != q.uid1 ||
	    (b->accepted_epoch && b->accepted_epoch != p->additions[1].epoch) ||
	    p->additions[2].uid != q.extra_uids[0] || !p->additions[2].epoch ||
	    extra0->uid != q.extra_uids[0] ||
	    (extra0->accepted_epoch &&
	     extra0->accepted_epoch != p->additions[2].epoch) ||
	    p->additions[3].uid != q.extra_uids[1] || !p->additions[3].epoch ||
	    extra1->uid != q.extra_uids[1] ||
	    (extra1->accepted_epoch &&
	     extra1->accepted_epoch != p->additions[3].epoch) ||
	    p->additions[4].uid != q.extra_uids[2] || !p->additions[4].epoch ||
	    extra2->uid != q.extra_uids[2] ||
	    (extra2->accepted_epoch &&
	     extra2->accepted_epoch != p->additions[4].epoch) ||
	    p->additions[5].uid != q.extra_uids[3] || !p->additions[5].epoch ||
	    extra3->uid != q.extra_uids[3] ||
	    (extra3->accepted_epoch &&
	     extra3->accepted_epoch != p->additions[5].epoch) ||
	    p->additions[6].uid != q.extra_uids[4] || !p->additions[6].epoch ||
	    extra4->uid != q.extra_uids[4] ||
	    (extra4->accepted_epoch &&
	     extra4->accepted_epoch != p->additions[6].epoch) ||
	    p->additions[7].uid != q.extra_uids[5] || !p->additions[7].epoch ||
	    extra5->uid != q.extra_uids[5] ||
	    (extra5->accepted_epoch &&
	     extra5->accepted_epoch != p->additions[7].epoch) ||
	    p->additions[0].epoch != p->rules[0].epoch ||
	    p->additions[1].epoch != p->rules[1].epoch) {
		s->arm_refused++;
		bpf_spin_unlock(&s->lock);
		return 0;
	}
	__u64 new_accepted =
		(!a->accepted_epoch) + (!b->accepted_epoch) +
		(!extra0->accepted_epoch) + (!extra1->accepted_epoch) +
		(!extra2->accepted_epoch) + (!extra3->accepted_epoch) +
		(!extra4->accepted_epoch) + (!extra5->accepted_epoch);
	/* Force precomputed metrics before the first irreversible store. The named
  * NOTYPE labels let build.sh inspect the emitted commit block, not just C.
  * Each marker emits a self-move of an initialized operand so Clang does not
  * give its inline-asm line and the following C line the same BTF offset. */
	asm volatile(".globl pc_commit_begin\npc_commit_begin:\n%0 = %0;\n"
		     : "+r"(new_accepted)
		     :
		     : "memory");
	/* COMMIT: no helper, nested lock, loop, or fallible branch after first store. */
	a->accepted_epoch = p->rules[0].epoch;
	b->accepted_epoch = p->rules[1].epoch;
	extra0->accepted_epoch = p->additions[2].epoch;
	extra1->accepted_epoch = p->additions[3].epoch;
	extra2->accepted_epoch = p->additions[4].epoch;
	extra3->accepted_epoch = p->additions[5].epoch;
	extra4->accepted_epoch = p->additions[6].epoch;
	extra5->accepted_epoch = p->additions[7].epoch;

	s->active_bank = q.bank;
	s->active_mode = q.mode;
	s->active_attempt = q.attempt;
	s->phase = PC_COMMITTED;
	s->receipt_attempt = q.attempt;
	s->serial++;
	s->accepted += new_accepted;
	s->arms++;
	s->arm_result = 0;
	asm volatile(".globl pc_commit_end\npc_commit_end:\n%0 = %0;\n"
		     :
		     : "r"(s)
		     : "memory");
	bpf_spin_unlock(&s->lock);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
