// SPDX-License-Identifier: GPL-2.0-only
// Report-only experiment. No LSM program, no payload reads, no result changes.
#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct mm_struct;
struct linux_binprm {
 struct mm_struct *mm;
 unsigned long p;
 int argc;
} __attribute__((preserve_access_index));

// Canonical amd64 function ABI, not a syscall-wrapper ABI. These UAPI names
// map to authenticated vendor pt_regs di/si/dx/ax offsets checked in Go BTF.
#if !defined(__TARGET_ARCH_x86)
#error "A0 canonical copy adapters require amd64"
#endif
_Static_assert(sizeof(unsigned long)==8 && sizeof(struct pt_regs)==168,"amd64 pt_regs layout");
_Static_assert(__builtin_offsetof(struct pt_regs,rdi)==112 && sizeof(((struct pt_regs *)0)->rdi)==8,"di layout");
_Static_assert(__builtin_offsetof(struct pt_regs,rsi)==104 && sizeof(((struct pt_regs *)0)->rsi)==8,"si layout");
_Static_assert(__builtin_offsetof(struct pt_regs,rdx)==96 && sizeof(((struct pt_regs *)0)->rdx)==8,"dx layout");
_Static_assert(__builtin_offsetof(struct pt_regs,rax)==80 && sizeof(((struct pt_regs *)0)->rax)==8,"ax layout");
struct a0_copy_args { __u64 to, from, n; };
static __always_inline struct a0_copy_args copy_entry_args(struct pt_regs *ctx)
{
 return (struct a0_copy_args){PT_REGS_PARM1(ctx),PT_REGS_PARM2(ctx),PT_REGS_PARM3(ctx)};
}
static __always_inline __u64 copy_return_value(struct pt_regs *ctx)
{
 return PT_REGS_RC(ctx);
}
// Permanent uncertainty bits: direct origin, candidate-only LIFO, unknown
// return-instance loss. Return To/N are entry snapshots, not fresh arguments.
#define A0_COPY_UNKNOWN (2 | 32 | 64)
#define A0_RETURN_UNKNOWN (A0_COPY_UNKNOWN | 128)

struct config { __u64 deadline, ns_dev, ns_ino; };
struct counters { __u64 records, attempts, calls, faults; };
struct frame { __u64 call, to, n; };
struct pending {
 __u64 task, bprm, attempt, depth;
};
// All fields are 64-bit to keep the offline representation padding-free.
struct record {
 __u64 kind, pid_tgid, ns_pid_tgid, task, attempt, call, depth, to, n, remaining;
 __u64 bprm, mm, p, argc, stack_bytes, unknown;
 __u64 stack[16];
};
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,4); __type(key,__u32); __type(value,__u32); } owned SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,4); __type(key,__u32); __type(value,struct pending); } pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,32); __type(key,__u32); __type(value,struct frame); } frames SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct config); __uint(map_flags,BPF_F_RDONLY_PROG); } config SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct counters); } counters SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,4096); __type(key,__u32); __type(value,struct record); } records SEC(".maps");

static __always_inline struct pending *current(struct counters **counts, __u32 *owned_slot)
{
 __u32 zero=0;
 struct config *cfg=bpf_map_lookup_elem(&config,&zero);
 if (!cfg || !cfg->ns_dev || !cfg->ns_ino) return 0;
 struct bpf_pidns_info local={};
 // This helper checks current's ACTIVE namespace identity first. Never look up
 // a namespace-local userspace PID using the initial-namespace task ID.
 if (bpf_get_ns_current_pid_tgid(cfg->ns_dev,cfg->ns_ino,&local,sizeof(local))) return 0;
 __u32 tgid=local.tgid;
 __u32 *slot_ptr=bpf_map_lookup_elem(&owned,&tgid);
 if (!slot_ptr) return 0;
 __u32 slot=*slot_ptr;
 if (slot>=4) return 0;
 struct counters *c=bpf_map_lookup_elem(&counters,&zero);
 if (!c) return 0;
 if (local.pid!=tgid || !cfg->deadline || bpf_ktime_get_ns()>cfg->deadline) {
  __sync_fetch_and_add(&c->faults,1); return 0;
 }
 *counts=c;
 *owned_slot=slot;
 return bpf_map_lookup_elem(&pending,&slot);
}

// Bound the key before narrowing. Each map value is one complete frame,
// so accessing its fields never requires an inner-array pointer offset.
static __always_inline struct frame *frame_at(__u32 slot, __u64 index)
{
 if (slot>=4 || index>=8) return 0;
 __u32 key=slot*8+(__u32)index;
 return bpf_map_lookup_elem(&frames,&key);
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
 struct counters *c=0; __u32 slot=0; struct pending *s=current(&c,&slot);
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

SEC("kprobe/_copy_from_user")
int copy_enter(struct pt_regs *ctx)
{
 struct a0_copy_args args=copy_entry_args(ctx);
 __u64 to=args.to, n=args.n;
 struct counters *c=0; __u32 slot=0; struct pending *s=current(&c,&slot);
 if (!s || !s->attempt) return 0;
 // Keep the checked full-width scalar through indexing; do not reload map depth.
 __u64 depth=s->depth;
 if (s->task!=bpf_get_current_task() || depth>=8) { __sync_fetch_and_add(&c->faults,1); return 0; }
 struct frame *f=frame_at(slot,depth);
 if (!f) { __sync_fetch_and_add(&c->faults,1); return 0; }
 f->call=__sync_fetch_and_add(&c->calls,1)+1; f->to=(__u64)to; f->n=n;
 s->depth=depth+1;
 struct record *r=reserve(c,s,1);
 if (r) {
  r->call=f->call; r->depth=depth+1; r->to=f->to; r->n=n;
  // UNKNOWN_DIRECT_ORIGIN stays set. Stack contents are diagnostic candidates,
  // never proof from an ancestor match. No user or destination contents read.
  r->unknown=A0_COPY_UNKNOWN;
  long bytes=bpf_get_stack(ctx,r->stack,sizeof(r->stack),0);
  if (bytes<=0 || bytes>=sizeof(r->stack) || bytes%8) { r->unknown|=4; __sync_fetch_and_add(&c->faults,1); }
  r->stack_bytes=bytes;
 }
 return 0;
}

SEC("kretprobe/_copy_from_user")
int copy_exit(struct pt_regs *ctx)
{
 __u64 remaining=copy_return_value(ctx);
 struct counters *c=0; __u32 slot=0; struct pending *s=current(&c,&slot);
 if (!s || !s->attempt) return 0;
 // Validate before subtraction: invalid depth must fault, never wrap or mask.
 __u64 depth=s->depth;
 if (s->task!=bpf_get_current_task() || !depth || depth>8) { __sync_fetch_and_add(&c->faults,1); return 0; }
 depth-=1;
 struct frame *f=frame_at(slot,depth);
 if (!f) { __sync_fetch_and_add(&c->faults,1); return 0; }
 struct record *r=reserve(c,s,2);
 if (r) {
  // To/N are retained ENTRY SNAPSHOTS. No return argument-register reads
  // or tautological fresh-argument comparison can establish call identity.
  r->call=f->call; r->depth=depth+1; r->to=f->to; r->n=f->n; r->remaining=remaining; r->unknown=A0_RETURN_UNKNOWN;
  if (remaining) { r->unknown|=8; __sync_fetch_and_add(&c->faults,1); }
 }
 s->depth=depth;
 return 0;
}

SEC("fentry/security_bprm_check")
int BPF_PROG(check, struct linux_binprm *bprm)
{
 struct counters *c=0; __u32 slot=0; struct pending *s=current(&c,&slot);
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
 struct counters *c=0; __u32 slot=0; struct pending *s=current(&c,&slot);
 if (!s || !s->attempt) return 0;
 if (s->task!=bpf_get_current_task() || s->bprm!=(__u64)bprm || s->depth) { __sync_fetch_and_add(&c->faults,1); return 0; }
 reserve(c,s,5);
 s->attempt=0; s->depth=0; s->task=0; s->bprm=0;
 return 0;
}
char LICENSE[] SEC("license")="GPL";
