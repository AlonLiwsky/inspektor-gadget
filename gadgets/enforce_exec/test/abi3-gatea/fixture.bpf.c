// SPDX-License-Identifier: GPL-2.0
// Test-only feasibility primitives. NOT the production authority protocol.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "fixture.h"
struct row {
	struct bpf_spin_lock lock;
	__u32 live;
	__u64 cookie, child, child_cookie, scratch, birth_bank, birth_attempt;
	struct ga_bank history[2];
};
struct control {
	struct bpf_spin_lock lock;
	__u32 seeded;
	__u64 serial, next_cookie, inflight, retained, births, frees;
	__u64 refused, failures, faults, taint, scratch_collisions;
	__u64 last_key, last_cookie, last_free_cookie;
	__u64 active_attempt, active_bank, active_program, receipt_serial,
		receipt_attempt;
	__u64 ready, inventory, held, armed;
	struct ga_bank catalogue[2];
};
_Static_assert(sizeof(struct control) == sizeof(struct ga_stats), "stats ABI");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, GA_LIMIT);
	__type(key, __u64);
	__type(value, struct row);
} tasks SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct control);
} state SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ga_config);
} config SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ga_command);
} commands SEC(".maps");
// Fixed immutable payload bank: proves coherent selection, not an evaluator.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u64);
} programs SEC(".maps");
/* Tag the pointee type: a trailing declaration attribute emits no kptr BTF. */
struct held_ref {
	struct task_struct __kptr *task;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct held_ref);
} refs SEC(".maps");
extern struct task_struct *bpf_task_acquire(struct task_struct *) __ksym;
extern void bpf_task_release(struct task_struct *) __ksym;
extern struct cgroup *bpf_cgroup_from_id(__u64) __ksym;
extern void bpf_cgroup_release(struct cgroup *) __ksym;
extern int bpf_iter_css_task_new(struct bpf_iter_css_task *,
				 struct cgroup_subsys_state *,
				 unsigned int) __ksym;
extern struct task_struct *
bpf_iter_css_task_next(struct bpf_iter_css_task *) __ksym;
extern void bpf_iter_css_task_destroy(struct bpf_iter_css_task *) __ksym;
static __always_inline struct control *ctl(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&state, &z);
}
static __always_inline struct ga_config *cfg(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&config, &z);
}
static __always_inline struct row *current_row(void)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	return bpf_map_lookup_elem(&tasks, &key);
}
static __always_inline void finish(struct control *s)
{
	bpf_spin_lock(&s->lock);
	if (s->inflight)
		s->inflight--;
	else
		s->faults++;
	if (s->serial == ~0ULL)
		s->faults++;
	else
		s->serial++;
	bpf_spin_unlock(&s->lock);
}
SEC("lsm.s/task_alloc")
int BPF_PROG(ga_alloc, struct task_struct *child, __u64 flags, int ret)
{
	if (ret)
		return ret;
	struct row *p = current_row();
	struct control *s = ctl();
	struct ga_config *c = cfg();
	if (!p || !s || !c)
		return ret;
	__u64 collision;
	bpf_spin_lock(&p->lock);
	collision = p->scratch || p->child;
	bpf_spin_unlock(&p->lock);
	if (collision) {
		bpf_spin_lock(&s->lock);
		s->scratch_collisions++;
		s->taint++;
		bpf_spin_unlock(&s->lock);
		return c->strict ? -11 : ret;
	}
	struct row fresh = {};
	__u64 key = (__u64)child;
	bpf_spin_lock(&s->lock);
	if (s->next_cookie == ~0ULL || s->serial == ~0ULL ||
	    s->retained >= GA_LIMIT) {
		s->refused++;
		// Audit admitted an untracked child: coverage is no longer certifiable.
		// Strict refusal happened before reservation and loses no child coverage.
		if (!c->strict)
			s->taint++;
	} else {
		fresh.cookie = ++s->next_cookie;
		s->serial++;
		s->inflight++;
		s->retained++;
		fresh.birth_bank = s->active_bank;
		fresh.birth_attempt = s->active_attempt;
	}
	bpf_spin_unlock(&s->lock);
	if (!fresh.cookie)
		return c->strict ? -11 : ret;
	bpf_spin_lock(&p->lock);
	fresh.history[0] = p->history[0];
	fresh.history[1] = p->history[1];
	bpf_spin_unlock(&p->lock);
	if (bpf_map_update_elem(&tasks, &key, &fresh, BPF_NOEXIST)) {
		bpf_spin_lock(&s->lock);
		s->retained--;
		s->refused++;
		s->taint++;
		bpf_spin_unlock(&s->lock);
		finish(s);
		return c->strict ? -11 : ret;
	}
	bpf_spin_lock(&p->lock);
	p->child = key;
	p->child_cookie = fresh.cookie;
	bpf_spin_unlock(&p->lock);
	bpf_spin_lock(&s->lock);
	s->last_key = key;
	s->last_cookie = fresh.cookie;
	bpf_spin_unlock(&s->lock);
	return ret;
}
// Attach BEFORE ga_alloc: the pinned trampoline prepends links, so this runs
// after allocation and proves later LSM denial uses task_free rollback.
SEC("lsm.s/task_alloc")
int BPF_PROG(ga_later, struct task_struct *child, __u64 flags, int ret)
{
	struct ga_config *c = cfg();
	if (ret || !c || !c->reject_later || !current_row())
		return ret;
	return -13;
}
SEC("tp_btf/task_newtask")
int BPF_PROG(ga_new, struct task_struct *child, __u64 flags)
{
	struct row *p = current_row();
	struct control *s = ctl();
	struct ga_config *c = cfg();
	if (!p || !s || !c)
		return 0;
	__u64 key = (__u64)child, owned = 0, cookie = 0;
	bpf_spin_lock(&p->lock);
	if (p->child == key) {
		owned = 1;
		cookie = p->child_cookie;
		p->child = 0;
		p->child_cookie = 0;
	}
	bpf_spin_unlock(&p->lock);
	if (!owned)
		return 0; // Audit tracking refusal is deliberately nonblocking.
	struct row *r = bpf_map_lookup_elem(&tasks, &key);
	int valid = 0;
	if (r) {
		bpf_spin_lock(&r->lock);
		if (r->cookie == cookie && r->birth_bank < 2 &&
		    r->history[r->birth_bank].generation == r->birth_attempt) {
			r->live = 1;
			valid = 1;
		}
		bpf_spin_unlock(&r->lock);
	}
	bpf_spin_lock(&s->lock);
	if (valid)
		s->births++;
	else
		s->faults++;
	bpf_spin_unlock(&s->lock);
	if (c->hold_child) {
		__u32 z = 0;
		struct held_ref *h = bpf_map_lookup_elem(&refs, &z);
		struct task_struct *t = bpf_task_acquire(child);
		if (t) {
			if (h) {
				struct task_struct *old =
					bpf_kptr_xchg(&h->task, t);
				if (old)
					bpf_task_release(old);
			} else
				bpf_task_release(t);
		}
	}
	finish(s);
	return 0;
}
SEC("fexit/copy_process")
int BPF_PROG(ga_failed, struct pid *pid, int trace, int node,
	     struct kernel_clone_args *args, struct task_struct *result)
{
	if ((__u64)result < ~4094ULL)
		return 0;
	struct row *p = current_row();
	struct control *s = ctl();
	if (!p || !s)
		return 0;
	int owned = 0;
	bpf_spin_lock(&p->lock);
	if (p->child) {
		owned = 1;
		p->child = 0;
		p->child_cookie = 0;
	}
	bpf_spin_unlock(&p->lock);
	// Child cleanup may already have run. Never look up/dereference its row here.
	if (owned) {
		bpf_spin_lock(&s->lock);
		s->failures++;
		bpf_spin_unlock(&s->lock);
		finish(s);
	}
	return 0;
}
SEC("lsm/task_free")
int BPF_PROG(ga_free, struct task_struct *task)
{
	__u64 key = (__u64)task;
	struct row *r = bpf_map_lookup_elem(&tasks, &key);
	struct control *s = ctl();
	if (!r || !s)
		return 0;
	__u64 cookie;
	bpf_spin_lock(&r->lock);
	cookie = r->cookie;
	bpf_spin_unlock(&r->lock);
	bpf_spin_lock(&s->lock);
	if (s->serial == ~0ULL)
		s->faults++;
	else
		s->serial++;
	bpf_spin_unlock(&s->lock);
	int err = bpf_map_delete_elem(&tasks,
				      &key); // no map helper under spinlock
	bpf_spin_lock(&s->lock);
	if (err || !s->retained)
		s->faults++;
	else {
		s->retained--;
		s->frees++;
		s->last_free_cookie = cookie;
	}
	bpf_spin_unlock(&s->lock);
	return 0;
}
static __noinline int inventory(struct control *s, int stage, __u64 attempt,
				__u32 flags)
{
	__u64 receipt, bank, active, attempted;
	int result = 0;
	__u32 count = 0;
	bpf_spin_lock(&s->lock);
	receipt = s->serial;
	active = s->active_bank;
	attempted = s->active_attempt;
	bank = active ^ 1;
	s->ready = 0;
	if (s->serial == ~0ULL || s->inflight || s->faults || s->taint)
		result = -11;
	bpf_spin_unlock(&s->lock);
	if (result || active > 1 || bank > 1)
		return -11;
	__u32 program_key = bank;
	__u64 *program = bpf_map_lookup_elem(&programs, &program_key);
	if (!program || *program != 100 + bank)
		return -22;
	struct cgroup *group = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!group)
		return -2;
	struct bpf_iter_css_task it;
	// ITER_NEW owns verifier state even when creation fails. Destroy is safe
	// after invalid flags/allocation failure and must precede cgroup release.
	result = bpf_iter_css_task_new(&it, &group->self, flags);
	if (result)
		goto destroy;
	for (int i = 0; i <= GA_LIMIT; i++) {
		struct task_struct *t = bpf_iter_css_task_next(&it);
		if (!t)
			break;
		if (i == GA_LIMIT) {
			result = -7;
			break;
		}
		__u64 key = (__u64)t;
		struct row *r = bpf_map_lookup_elem(&tasks, &key);
		if (!r) {
			result = -2;
			break;
		}
		bpf_spin_lock(&r->lock);
		if (!r->cookie || !r->live ||
		    r->history[active].generation != attempted ||
		    r->history[active].uid != 1 ||
		    r->history[active].epoch != 1 ||
		    r->history[active].role != 7)
			result = -22;
		if (stage && bank < 2)
			r->history[bank] = (struct ga_bank){ attempt, 1, 1, 7 };
		bpf_spin_unlock(&r->lock);
		count++;
		// No row pointer retained beyond iterator_next: it owns the task reference.
	}
destroy:
	bpf_iter_css_task_destroy(&it);
	bpf_cgroup_release(group);
	bpf_spin_lock(&s->lock);
	s->inventory = count;
	if (s->serial != receipt || s->inflight || s->faults || s->taint)
		result = -11;
	if (!result && stage && bank < 2) {
		s->catalogue[bank] = (struct ga_bank){ attempt, 1, 1, 7 };
		s->receipt_serial = receipt;
		s->receipt_attempt = attempt;
		s->ready = 1;
	}
	bpf_spin_unlock(&s->lock);
	return result;
}
SEC("syscall") int ga_command(void *unused)
{
	__u32 z = 0;
	struct ga_config *c = cfg();
	struct control *s = ctl();
	struct ga_command *cmd = bpf_map_lookup_elem(&commands, &z);
	if (!c || !s || !cmd ||
	    c->admin_pid != bpf_get_current_pid_tgid() >> 32)
		return -1;
	if (cmd->operation == GA_SEED) {
		// Authenticated one-shot initialization only. Profiles inject initial
		// boundaries, never reset/recycle a live serial, cookie or accepted row.
		if (cmd->attempt > 4)
			return -22;
		int seeded;
		bpf_spin_lock(&s->lock);
		seeded = s->seeded;
		if (!seeded)
			s->seeded = 1;
		bpf_spin_unlock(&s->lock);
		if (seeded)
			return -17;
		__u64 key = (__u64)bpf_get_current_task_btf();
		struct row r = { .live = 1, .cookie = 1 };
		r.history[0] = (struct ga_bank){ 1, 1, 1, 7 };
		if (bpf_map_update_elem(&tasks, &key, &r, BPF_NOEXIST))
			return -17;
		bpf_spin_lock(&s->lock);
		s->next_cookie = cmd->attempt == 1 ? ~0ULL :
				 cmd->attempt == 2 ? ~1ULL :
						     1;
		s->retained = 1;
		s->serial = cmd->attempt == 3 ? ~0ULL :
			    cmd->attempt == 4 ? ~1ULL :
						1;
		s->active_attempt = 1;
		s->active_program = 100;
		s->catalogue[0] = r.history[0];
		bpf_spin_unlock(&s->lock);
		return 0;
	}
	if (cmd->operation == GA_RELEASE_TASK) {
		struct held_ref *h = bpf_map_lookup_elem(&refs, &z);
		if (!h)
			return -2;
		struct task_struct *t = bpf_kptr_xchg(&h->task, 0);
		if (t)
			bpf_task_release(t);
		return 0;
	}
	if (cmd->operation == GA_INVENTORY || cmd->operation == GA_STAGE ||
	    cmd->operation == GA_ITERATOR_ERROR)
		return inventory(s, cmd->operation == GA_STAGE, cmd->attempt,
				 cmd->operation == GA_ITERATOR_ERROR ? ~0U : 0);
	if (cmd->operation == GA_ARM) {
		int result = -11;
		bpf_spin_lock(&s->lock);
		if (s->serial != ~0ULL && s->ready &&
		    s->receipt_attempt == cmd->attempt &&
		    s->receipt_serial == s->serial && !s->inflight &&
		    !s->faults && !s->taint) {
			s->active_bank ^= 1;
			s->active_program = 100 + s->active_bank;
			s->active_attempt = cmd->attempt;
			s->ready = 0;
			s->armed++;
			result = 0;
		}
		bpf_spin_unlock(&s->lock);
		return result;
	}
	struct row *r = current_row();
	if (!r)
		return -2;
	int result = 0;
	bpf_spin_lock(&r->lock);
	if (cmd->operation == GA_HOLD_SCRATCH) {
		if (r->scratch)
			result = -16;
		else
			r->scratch = cmd->attempt;
	} else if (cmd->operation == GA_FREE_SCRATCH) {
		if (r->scratch != cmd->attempt)
			result = -1;
		else
			r->scratch = 0;
	} else
		result = -22;
	bpf_spin_unlock(&r->lock);
	return result;
}
char LICENSE[] SEC("license") = "GPL";
