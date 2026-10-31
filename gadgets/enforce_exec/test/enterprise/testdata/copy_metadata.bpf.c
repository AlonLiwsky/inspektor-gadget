// SPDX-License-Identifier: GPL-2.0-only
// Report-only experiment. No LSM program, no payload reads, no result changes.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct mm_struct;
struct linux_binprm {
 struct mm_struct *mm;
 unsigned long p;
 int argc;
} __attribute__((preserve_access_index));

struct config { __u64 deadline, ns_dev, ns_ino; };
struct counters { __u64 records, attempts, calls, faults; };
struct frame { __u64 call, to, n; };
struct pending {
 __u64 task, bprm, attempt, depth;
 struct frame frame[8];
};
// All fields are 64-bit to keep the offline representation padding-free.
struct record {
 __u64 kind, pid_tgid, ns_pid_tgid, task, attempt, call, depth, to, n, remaining;
 __u64 bprm, mm, p, argc, stack_bytes, unknown;
 __u64 stack[16];
};
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,4); __type(key,__u32); __type(value,__u32); } owned SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,4); __type(key,__u32); __type(value,struct pending); } pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct config); __uint(map_flags,BPF_F_RDONLY_PROG); } config SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct counters); } counters SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,4096); __type(key,__u32); __type(value,struct record); } records SEC(".maps");

static __always_inline struct pending *current(struct counters **counts)
{
 __u32 zero=0;
 struct config *cfg=bpf_map_lookup_elem(&config,&zero);
 if (!cfg || !cfg->ns_dev || !cfg->ns_ino) return 0;
 struct bpf_pidns_info local={};
 // This helper checks current's ACTIVE namespace identity first. Never look up
 // a namespace-local userspace PID using the initial-namespace task ID.
 if (bpf_get_ns_current_pid_tgid(cfg->ns_dev,cfg->ns_ino,&local,sizeof(local))) return 0;
 __u32 tgid=local.tgid;
 __u32 *slot=bpf_map_lookup_elem(&owned,&tgid);
 if (!slot || *slot>=4) return 0;
 struct counters *c=bpf_map_lookup_elem(&counters,&zero);
 if (!c) return 0;
 if (local.pid!=tgid || !cfg->deadline || bpf_ktime_get_ns()>cfg->deadline) {
  __sync_fetch_and_add(&c->faults,1); return 0;
 }
 *counts=c;
 return bpf_map_lookup_elem(&pending,slot);
}

static __always_inline struct record *reserve(struct counters *c, struct pending *s, __u64 kind)
{
 __u64 seq=__sync_fetch_and_add(&c->records,1);
 if (seq>=4096) { __sync_fetch_and_add(&c->faults,1); return 0; }
 __u32 key=seq;
 struct record *r=bpf_map_lookup_elem(&records,&key);
 if (!r) { __sync_fetch_and_add(&c->faults,1); return 0; }
 // Each slot is written once. Array values start zeroed; no ring/reuse race.
 r->kind=kind; r->pid_tgid=bpf_get_current_pid_tgid();
 __u32 zero=0;
 struct config *cfg=bpf_map_lookup_elem(&config,&zero);
 struct bpf_pidns_info local={};
 if (!cfg || bpf_get_ns_current_pid_tgid(cfg->ns_dev,cfg->ns_ino,&local,sizeof(local))) {
  r->unknown=16; __sync_fetch_and_add(&c->faults,1); return 0;
 }
 r->ns_pid_tgid=((__u64)local.tgid<<32)|local.pid;
 r->task=bpf_get_current_task(); r->attempt=s->attempt;
 r->bprm=s->bprm;
 return r;
}

SEC("fexit/security_bprm_creds_for_exec")
int BPF_PROG(start, struct linux_binprm *bprm, int ret)
{
 struct counters *c=0; struct pending *s=current(&c);
 if (!s || ret) return 0;
 if (s->attempt) { __sync_fetch_and_add(&c->faults,1); return 0; }
 __u64 attempt=__sync_fetch_and_add(&c->attempts,1)+1;
 if (attempt>16) { __sync_fetch_and_add(&c->faults,1); return 0; }
 s->task=bpf_get_current_task(); s->bprm=(__u64)bprm; s->attempt=attempt; s->depth=0;
 struct record *r=reserve(c,s,3);
 if (r) {
  // Only live typed argument dereferences, never pointers retrieved from maps.
  if (bpf_core_read(&r->mm,sizeof(r->mm),&bprm->mm) ||
      bpf_core_read(&r->p,sizeof(r->p),&bprm->p)) { r->unknown=1; __sync_fetch_and_add(&c->faults,1); }
  int argc=0;
  if (bpf_core_read(&argc,sizeof(argc),&bprm->argc)) { r->unknown=1; __sync_fetch_and_add(&c->faults,1); }
  r->argc=argc;
 }
 return 0;
}

SEC("fentry/_copy_from_user")
int BPF_PROG(copy_enter, void *to, const void *from, unsigned long n)
{
 struct counters *c=0; struct pending *s=current(&c);
 if (!s || !s->attempt) return 0;
 // Keep the checked full-width scalar through indexing; do not reload map depth.
 __u64 depth=s->depth;
 if (s->task!=bpf_get_current_task() || depth>=8) { __sync_fetch_and_add(&c->faults,1); return 0; }
 struct frame *f=&s->frame[depth];
 f->call=__sync_fetch_and_add(&c->calls,1)+1; f->to=(__u64)to; f->n=n;
 s->depth=depth+1;
 struct record *r=reserve(c,s,1);
 if (r) {
  r->call=f->call; r->depth=depth+1; r->to=f->to; r->n=n;
  // UNKNOWN_DIRECT_ORIGIN stays set. Stack contents are diagnostic candidates,
  // never proof from an ancestor match. No user or destination contents read.
  r->unknown=2;
  long bytes=bpf_get_stack(ctx,r->stack,sizeof(r->stack),0);
  if (bytes<=0 || bytes>=sizeof(r->stack) || bytes%8) { r->unknown|=4; __sync_fetch_and_add(&c->faults,1); }
  r->stack_bytes=bytes;
 }
 return 0;
}

SEC("fexit/_copy_from_user")
int BPF_PROG(copy_exit, void *to, const void *from, unsigned long n, unsigned long remaining)
{
 struct counters *c=0; struct pending *s=current(&c);
 if (!s || !s->attempt) return 0;
 // Validate before subtraction: invalid depth must fault, never wrap or mask.
 __u64 depth=s->depth;
 if (s->task!=bpf_get_current_task() || !depth || depth>8) { __sync_fetch_and_add(&c->faults,1); return 0; }
 depth-=1;
 struct frame *f=&s->frame[depth];
 struct record *r=reserve(c,s,2);
 if (r) {
  r->call=f->call; r->depth=depth+1; r->to=(__u64)to; r->n=n; r->remaining=remaining; r->unknown=2;
  if (f->to!=(__u64)to || f->n!=n || remaining) { r->unknown|=8; __sync_fetch_and_add(&c->faults,1); }
 }
 s->depth=depth;
 return 0;
}

SEC("fentry/security_bprm_check")
int BPF_PROG(check, struct linux_binprm *bprm)
{
 struct counters *c=0; struct pending *s=current(&c);
 if (!s || !s->attempt) return 0;
 if (s->task!=bpf_get_current_task() || s->bprm!=(__u64)bprm || s->depth) { __sync_fetch_and_add(&c->faults,1); return 0; }
 struct record *r=reserve(c,s,4);
 if (r) {
  int argc=0;
  if (bpf_core_read(&r->mm,sizeof(r->mm),&bprm->mm) || bpf_core_read(&r->p,sizeof(r->p),&bprm->p) || bpf_core_read(&argc,sizeof(argc),&bprm->argc)) { r->unknown=1; __sync_fetch_and_add(&c->faults,1); }
  r->argc=argc;
 }
 return 0;
}

SEC("fentry/free_bprm")
int BPF_PROG(finish, struct linux_binprm *bprm)
{
 struct counters *c=0; struct pending *s=current(&c);
 if (!s || !s->attempt) return 0;
 if (s->task!=bpf_get_current_task() || s->bprm!=(__u64)bprm || s->depth) { __sync_fetch_and_add(&c->faults,1); return 0; }
 reserve(c,s,5);
 s->attempt=0; s->depth=0; s->task=0; s->bprm=0;
 return 0;
}
char LICENSE[] SEC("license")="GPL";
