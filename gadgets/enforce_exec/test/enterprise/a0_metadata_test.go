// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package enterprise_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

func TestA0DefaultGuard(t *testing.T) {
	for _, value := range []string{"", "0", "true", " 1", "1\n"} {
		if a0Enabled(value) {
			t.Errorf("%q unexpectedly enabled operations", value)
		}
	}
	if !a0Enabled("1") {
		t.Fatal("explicit opt-in not recognized")
	}
}

func TestA0Bounds(t *testing.T) {
	valid := a0Bounds{Tasks: 4, Attempts: 16, Depth: 8, Records: 4096, CPUs: 64, Duration: 30 * time.Second}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*a0Bounds){
		"tasks": func(b *a0Bounds) { b.Tasks++ }, "attempts": func(b *a0Bounds) { b.Attempts++ },
		"depth": func(b *a0Bounds) { b.Depth++ }, "records": func(b *a0Bounds) { b.Records++ },
		"cpus": func(b *a0Bounds) { b.CPUs++ }, "payload": func(b *a0Bounds) { b.PayloadBytes = 1 },
		"duration": func(b *a0Bounds) { b.Duration++ }, "zero duration": func(b *a0Bounds) { b.Duration = 0 },
		"negative tasks": func(b *a0Bounds) { b.Tasks = -1 }, "zero attempts": func(b *a0Bounds) { b.Attempts = 0 },
		"zero depth": func(b *a0Bounds) { b.Depth = 0 }, "zero records": func(b *a0Bounds) { b.Records = 0 }, "zero cpus": func(b *a0Bounds) { b.CPUs = 0 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b := valid
			change(&b)
			if b.validate() == nil {
				t.Fatal("unsafe bound accepted")
			}
		})
	}
}

func TestA0StructuralSuccessNeverProvesProvenance(t *testing.T) {
	for _, valid := range []bool{false, true} {
		r := offlineReport(valid)
		if r.KernelProbe != "NOT_RUN" || r.Completeness != "NOT_READY" {
			t.Fatalf("offline result overclaimed: %+v", r)
		}
	}
}

func nativeSample() []nativeRecord {
	base := nativeRecord{PIDTGID: 7<<32 | 7, NamespacePIDTGID: 7<<32 | 7, Task: 10, Attempt: 1, Bprm: 20, MM: 30, P: 40, Argc: 2}
	start := base
	start.Kind = 3
	entry := base
	entry.Kind = 1
	entry.Call = 1
	entry.Depth = 1
	entry.To = 100
	entry.N = 16
	entry.Unknown = copyCandidateUnknown
	entry.StackBytes = 16
	entry.Stack[0] = 101
	entry.Stack[1] = 102
	ret := entry
	ret.Kind = 2
	ret.Unknown = returnSnapshotUnknown
	ret.StackBytes = 0
	ret.Stack = [16]uint64{}
	check := base
	check.Kind = 4
	finish := base
	finish.Kind = 5
	return []nativeRecord{start, entry, ret, check, finish}
}

func TestA0NativeRecordLayout(t *testing.T) {
	// The record contains only fixed metadata scalars, no argv/source/destination
	// byte payload. Stack words are bounded kernel-address diagnostics.
	if size := binary.Size(nativeRecord{}); size != 32*8 {
		t.Fatalf("native metadata size: %d", size)
	}
	if size := binary.Size(nativeCounters{}); size != 4*8 {
		t.Fatalf("counter size: %d", size)
	}
}

func TestA0NativePairUncertainty(t *testing.T) {
	if err := validateNativeRecords(nativeSample(), 7); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]nativeRecord) []nativeRecord{
		"empty":                     func(r []nativeRecord) []nativeRecord { return nil },
		"missing start":             func(r []nativeRecord) []nativeRecord { return r[1:] },
		"missing retirement":        func(r []nativeRecord) []nativeRecord { return r[:4] },
		"missing check":             func(r []nativeRecord) []nativeRecord { return append(r[:3], r[4]) },
		"missing return":            func(r []nativeRecord) []nativeRecord { return append(r[:2], r[3:]...) },
		"missing entry":             func(r []nativeRecord) []nativeRecord { return append(r[:1], r[2:]...) },
		"no copies":                 func(r []nativeRecord) []nativeRecord { return []nativeRecord{r[0], r[3], r[4]} },
		"foreign task":              func(r []nativeRecord) []nativeRecord { r[1].NamespacePIDTGID++; return r },
		"stale task pointer":        func(r []nativeRecord) []nativeRecord { r[1].Task++; return r },
		"stale bprm pointer":        func(r []nativeRecord) []nativeRecord { r[1].Bprm++; return r },
		"wrong attempt":             func(r []nativeRecord) []nativeRecord { r[1].Attempt++; return r },
		"zero attempt":              func(r []nativeRecord) []nativeRecord { r[1].Attempt = 0; return r },
		"zero destination":          func(r []nativeRecord) []nativeRecord { r[1].To = 0; return r },
		"zero requested size":       func(r []nativeRecord) []nativeRecord { r[1].N = 0; return r },
		"partial copy":              func(r []nativeRecord) []nativeRecord { r[2].Remaining = 1; return r },
		"wrong destination":         func(r []nativeRecord) []nativeRecord { r[2].To++; return r },
		"wrong size":                func(r []nativeRecord) []nativeRecord { r[2].N++; return r },
		"wrong call":                func(r []nativeRecord) []nativeRecord { r[2].Call++; return r },
		"wrong depth":               func(r []nativeRecord) []nativeRecord { r[2].Depth++; return r },
		"missing stack":             func(r []nativeRecord) []nativeRecord { r[1].StackBytes = 0; return r },
		"possibly truncated stack":  func(r []nativeRecord) []nativeRecord { r[1].StackBytes = 128; return r },
		"malformed stack length":    func(r []nativeRecord) []nativeRecord { r[1].StackBytes = 15; return r },
		"unknown copy flags":        func(r []nativeRecord) []nativeRecord { r[1].Unknown = 6; return r },
		"claimed direct provenance": func(r []nativeRecord) []nativeRecord { r[1].Unknown = 0; return r },
		"uncertain start":           func(r []nativeRecord) []nativeRecord { r[0].Unknown = 1; return r },
		"uncertain check":           func(r []nativeRecord) []nativeRecord { r[3].Unknown = 1; return r },
		"uncertain retire":          func(r []nativeRecord) []nativeRecord { r[4].Unknown = 1; return r },
		"duplicate start":           func(r []nativeRecord) []nativeRecord { return append(r[:1], r...) },
		"record after retire":       func(r []nativeRecord) []nativeRecord { return append(r, r[3]) },
		"unknown kind":              func(r []nativeRecord) []nativeRecord { r[3].Kind = 99; return r },
		"excess records":            func(r []nativeRecord) []nativeRecord { return make([]nativeRecord, maxRecords+1) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			if validateNativeRecords(change(nativeSample()), 7) == nil {
				t.Fatal("uncertain metadata accepted")
			}
		})
	}
}

func TestA0NativeNestedPairs(t *testing.T) {
	base := nativeSample()
	records := []nativeRecord{base[0]}
	for depth := uint64(1); depth <= maxDepth; depth++ {
		r := base[1]
		r.Depth = depth
		r.Call = depth
		records = append(records, r)
	}
	for depth := uint64(maxDepth); depth > 0; depth-- {
		r := base[2]
		r.Depth = depth
		r.Call = depth
		records = append(records, r)
	}
	records = append(records, base[3:]...)
	if err := validateNativeRecords(records, 7); err != nil {
		t.Fatal(err)
	}
	bad := append([]nativeRecord(nil), records...)
	bad[8].Depth = 9
	if validateNativeRecords(bad, 7) == nil {
		t.Fatal("excess depth accepted")
	}
	bad = append([]nativeRecord(nil), records...)
	bad[9], bad[10] = bad[10], bad[9]
	if validateNativeRecords(bad, 7) == nil {
		t.Fatal("non-LIFO return accepted")
	}
	bad = append([]nativeRecord(nil), records...)
	bad[2].Call = 1
	if validateNativeRecords(bad, 7) == nil {
		t.Fatal("reused call ID accepted")
	}
}

func TestA0BTFTypedScalars(t *testing.T) {
	ul := &btf.Int{Name: "long unsigned int", Size: 8, Encoding: btf.Unsigned}
	si := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	if !unsignedLong(ul) || !signedInt(si) {
		t.Fatal("correct scalar prototypes rejected")
	}
	if unsignedLong(si) || signedInt(ul) || unsignedLong(&btf.Int{Size: 4}) {
		t.Fatal("wrong width or sign accepted")
	}
	voidPtr := &btf.Pointer{Target: &btf.Const{Type: &btf.Void{}}}
	bprmPtr := &btf.Pointer{Target: &btf.Struct{Name: "linux_binprm"}}
	if !pointerTo(voidPtr, "void") || !pointerTo(bprmPtr, "linux_binprm") {
		t.Fatal("correct pointer prototypes rejected")
	}
	if pointerTo(voidPtr, "linux_binprm") || pointerTo(bprmPtr, "void") || pointerTo(si, "void") {
		t.Fatal("wrong pointer target accepted")
	}
}

func TestA0CleanupOrdersStopBeforeIdentityRelease(t *testing.T) {
	for _, fail := range []string{"", "detach", "unregister", "release"} {
		t.Run(fail, func(t *testing.T) {
			var order []string
			step := func(name string) func() error {
				return func() error {
					order = append(order, name)
					if name == fail {
						return errors.New("injected " + name)
					}
					return nil
				}
			}
			retained, err := orderedA0Cleanup(a0CleanupSteps{detach: step("detach"), unregister: step("unregister"), release: step("release"), quarantine: func(error) { order = append(order, "quarantine") }})
			want := []string{"detach", "unregister", "release"}
			if fail == "detach" {
				want = []string{"detach", "quarantine"}
			}
			if !reflect.DeepEqual(order, want) {
				t.Fatalf("cleanup order %v, want %v", order, want)
			}
			if retained != (fail == "detach") || (err != nil) != (fail != "") {
				t.Fatalf("retained=%v err=%v", retained, err)
			}
		})
	}
}

func TestA0HelperDoesNotInheritEnvironment(t *testing.T) {
	t.Setenv("LD_PRELOAD", "untrusted.so")
	t.Setenv("LD_AUDIT", "untrusted-audit.so")
	child := ownedA0Command("/not-executed", nil, nil)
	if child.Env == nil || len(child.Env) != 0 {
		t.Fatalf("helper environment must be explicitly empty: %v", child.Env)
	}
	if child.Process != nil {
		t.Fatal("construction started a subprocess")
	}
}

func TestA0NamespaceAnchorRefusesAmbiguity(t *testing.T) {
	valid := func(proc int64, root uint64, fs int64, typ int, linked, opened, dev uint64) error {
		return validateA0NamespaceFacts(proc, root, fs, typ, linked, opened, dev)
	}
	// No assumption that this inode denotes the initial namespace: real nested
	// namespaces are acceptable only with the bound kernel namespace-aware helper.
	if err := valid(unix.PROC_SUPER_MAGIC, 1, unix.NSFS_MAGIC, unix.CLONE_NEWPID, 101, 101, 4); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"fake proc":            valid(0, 1, unix.NSFS_MAGIC, unix.CLONE_NEWPID, 101, 101, 4),
		"bound subtree":        valid(unix.PROC_SUPER_MAGIC, 99, unix.NSFS_MAGIC, unix.CLONE_NEWPID, 101, 101, 4),
		"fake nsfs":            valid(unix.PROC_SUPER_MAGIC, 1, 0, unix.CLONE_NEWPID, 101, 101, 4),
		"wrong namespace type": valid(unix.PROC_SUPER_MAGIC, 1, unix.NSFS_MAGIC, unix.CLONE_NEWNET, 101, 101, 4),
		"substituted nsfd":     valid(unix.PROC_SUPER_MAGIC, 1, unix.NSFS_MAGIC, unix.CLONE_NEWPID, 101, 102, 4),
		"unknown inode":        valid(unix.PROC_SUPER_MAGIC, 1, unix.NSFS_MAGIC, unix.CLONE_NEWPID, 0, 0, 4),
		"unknown device":       valid(unix.PROC_SUPER_MAGIC, 1, unix.NSFS_MAGIC, unix.CLONE_NEWPID, 101, 101, 0),
	} {
		t.Run(name, func(t *testing.T) {
			if err == nil {
				t.Fatal("ambiguous anchor accepted")
			}
		})
	}
}

func TestA0NamespaceLinkParser(t *testing.T) {
	if ino, err := parsePIDNamespaceLink("pid:[101]"); err != nil || ino != 101 {
		t.Fatalf("valid namespace link: %d %v", ino, err)
	}
	for _, value := range []string{"", "pid:[0]", "pid:[01]", "pid:[+1]", "pid:[-1]", "pid:[1]extra", "net:[1]", "pid:[18446744073709551616]"} {
		if _, err := parsePIDNamespaceLink(value); err == nil {
			t.Errorf("malformed anchor accepted: %q", value)
		}
	}
}

func TestA0NamespaceLocalIdentityDoesNotUseHostPID(t *testing.T) {
	records := nativeSample()
	for i := range records {
		records[i].PIDTGID = 9000<<32 | 9000
	}
	if err := validateNativeRecords(records, 7); err != nil {
		t.Fatalf("properly namespaced local PID rejected: %v", err)
	}
	for i := range records {
		records[i].PIDTGID = 7<<32 | 7
		records[i].NamespacePIDTGID = 9000<<32 | 9000
	}
	if validateNativeRecords(records, 7) == nil {
		t.Fatal("host PID collision authorized a different namespace-local task")
	}
}

func TestA0ChildNamespaceHandshake(t *testing.T) {
	if err := validateA0ChildIdentity(7, 6, 7, 6); err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][4]uint32{{8, 6, 7, 6}, {7, 8, 7, 6}, {0, 6, 0, 6}, {7, 0, 7, 0}} {
		if validateA0ChildIdentity(ids[0], ids[1], ids[2], ids[3]) == nil {
			t.Fatalf("ambiguous child identity accepted: %v", ids)
		}
	}
}

func TestA0NativeRejectsGoTestDeadline(t *testing.T) {
	if validateA0NativeDeadline(true) == nil {
		t.Fatal("test timeout could defeat native quarantine")
	}
	if err := validateA0NativeDeadline(false); err != nil {
		t.Fatal(err)
	}
}

type a0ErrorThenNilCloser struct{ calls int }

func (c *a0ErrorThenNilCloser) Close() error {
	c.calls++
	if c.calls == 1 {
		return errors.New("injected close uncertainty after disown")
	}
	return nil
}

func TestA0FirstDetachErrorCannotBeClearedByNilRetry(t *testing.T) {
	closer := &a0ErrorThenNilCloser{}
	owner := &a0NativeOwner{links: []io.Closer{closer}}
	first := owner.detach()
	if first == nil {
		t.Fatal("first uncertain close accepted")
	}
	if second := owner.detach(); !errors.Is(second, first) {
		t.Fatalf("first detach uncertainty lost: %v", second)
	}
	var order []string
	retained, err := orderedA0Cleanup(a0CleanupSteps{
		detach:     owner.detach,
		unregister: func() error { order = append(order, "unregister"); return nil },
		release:    func() error { order = append(order, "kill/wait/reap/release"); return nil },
		quarantine: func(error) { order = append(order, "quarantine") },
	})
	if !retained || err == nil || !reflect.DeepEqual(order, []string{"quarantine"}) {
		t.Fatalf("uncertainty released ownership: retained=%v err=%v order=%v", retained, err, order)
	}
	if closer.calls != 1 || len(owner.links) != 1 || owner.links[0] != closer {
		t.Fatalf("retried uncertain close or dropped retained link: calls=%d links=%d", closer.calls, len(owner.links))
	}
	// Demonstrate the fake really models a false-success retry; owner never calls it.
	if err := closer.Close(); err != nil {
		t.Fatal("fake did not implement error-then-nil behavior")
	}
}

// a0CSection extracts production C, rather than a Go model of its indexing.
func a0CSection(t *testing.T, source, start, end string) string {
	t.Helper()
	_, rest, ok := strings.Cut(source, start)
	if !ok {
		t.Fatalf("missing C section start %q", start)
	}
	body, _, ok := strings.Cut(rest, end)
	if !ok {
		t.Fatalf("missing C section end %q", end)
	}
	return start + body
}

func a0CopySource(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("testdata/copy_metadata.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	return string(source)
}

func TestA0CopyDepthSingleValidatedCapture(t *testing.T) {
	source := a0CopySource(t)
	for _, callback := range []struct{ start, end, guard, operation string }{
		{"int copy_enter(", `SEC("kretprobe/_copy_from_user")`, "depth>=8", "frame_at(slot,depth)"},
		{"int copy_exit(", `SEC("fentry/security_bprm_check")`, "!depth || depth>8", "frame_at(slot,depth)"},
	} {
		body := a0CSection(t, source, callback.start, callback.end)
		// One full-width map load and one final store. Checking map memory and
		// then reloading it for arithmetic loses the checked scalar identity.
		if strings.Count(body, "s->depth") != 2 {
			t.Errorf("%s must read depth once and write it once", callback.start)
		}
		capture := strings.Index(body, "__u64 depth=s->depth;")
		guard := strings.Index(body, callback.guard)
		index := strings.Index(body, callback.operation)
		if capture < 0 || guard <= capture || index <= guard {
			t.Errorf("%s must validate the captured 64-bit depth before indexing", callback.start)
		}
	}
}

func TestA0CopyDepthCRegression(t *testing.T) {
	if !a0Enabled(os.Getenv(a0Flag)) {
		t.Skip("A0 pure C regression disabled")
	}
	clang := os.Getenv("IG_ENTERPRISE_A0_CLANG")
	if !filepath.IsAbs(clang) {
		t.Fatal("absolute trusted IG_ENTERPRISE_A0_CLANG required")
	}
	source := a0CopySource(t)

	adapters := a0CSection(t, source, "// Canonical amd64 function ABI,", "struct config {")
	types := a0CSection(t, source, "struct config {", "struct { __uint")
	lookup := a0CSection(t, source, "static __always_inline struct pending *current(", "static __always_inline struct record *reserve(")
	callbacks := a0CSection(t, source, `SEC("kprobe/_copy_from_user")`, `SEC("fentry/security_bprm_check")`)
	// Actual production identity/slot lookup and copy callbacks, with userspace
	// map/helper stubs only. This does not load BPF or execute exec_target.
	harness := `
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <linux/bpf.h>
#include <asm/ptrace.h>
// Include the real installed register macros. Rename only syscall helper
// declarations so the actual callback code can call deterministic test stubs.
#define bpf_map_lookup_elem unused_header_map_lookup
#define bpf_get_ns_current_pid_tgid unused_header_pidns
#define bpf_ktime_get_ns unused_header_time
#define bpf_get_current_task unused_header_task
#define bpf_get_stack unused_header_stack
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#undef bpf_map_lookup_elem
#undef bpf_get_ns_current_pid_tgid
#undef bpf_ktime_get_ns
#undef bpf_get_current_task
#undef bpf_get_stack
` + adapters + types + `
static int owned, pending, config, counters, frames;
static struct pending states[4];
static struct frame frame_values[32];
static struct config settings={1000,1,2};
static struct counters counts;
static struct record observed;
static __u32 active, owned_slot, last_frame_key;
static unsigned frame_lookups;
static int fail_frames, change_slot;
static long stack_result=16;
#define state states[active]
static int bpf_get_ns_current_pid_tgid(__u64 dev,__u64 ino,struct bpf_pidns_info *p,unsigned long size) {
 assert(dev==1 && ino==2); p->pid=42+active; p->tgid=p->pid; return 0;
}
static __u64 bpf_ktime_get_ns(void) { return 1; }
static void *bpf_map_lookup_elem(void *map,const void *keyptr) {
 __u32 key=*(const __u32 *)keyptr;
 if (map==&config) { assert(key==0); return &settings; }
 if (map==&owned) { assert(key==42+active); return &owned_slot; }
 if (map==&counters) { assert(key==0); if(change_slot) owned_slot=3; return &counts; }
 if (map==&pending) { assert(key<4); return &states[key]; }
 assert(map==&frames && key<32); frame_lookups++; last_frame_key=key;
 return fail_frames ? 0 : &frame_values[key];
}
static __u64 bpf_get_current_task(void) { return 7; }
static long bpf_get_stack(void *ctx, void *stack, unsigned long size, int flags) { return stack_result; }
static struct record *reserve(struct counters *c, struct pending *s, __u64 kind) {
 memset(&observed,0,sizeof(observed)); observed.kind=kind; c->records++; return &observed;
}
` + lookup + callbacks + `
static void enter(void *ctx,void *to,const void *from,unsigned long n) {
 struct pt_regs regs={.rdi=(uintptr_t)to,.rsi=(uintptr_t)from,.rdx=n,.rax=0xaabbccdd11223344ULL};
 copy_enter(&regs);
}
static void leave(void *ctx,void *to,const void *from,unsigned long n,unsigned long remaining) {
 struct pt_regs regs={.rdi=(uintptr_t)to,.rsi=0x9988776655443322ULL,.rdx=n,.rax=remaining};
 copy_exit(&regs);
}
static void reset(__u32 slot,__u64 depth) {
 memset(states,0,sizeof(states)); memset(frame_values,0,sizeof(frame_values));
 memset(&counts,0,sizeof(counts)); memset(&observed,0,sizeof(observed));
 active=owned_slot=slot; fail_frames=change_slot=0; frame_lookups=0; stack_result=16;
 for (unsigned owner=0;owner<4;owner++) {
  states[owner].task=7; states[owner].attempt=1; states[owner].depth=depth;
 }
}
static void expect_unchanged(struct pending *before,struct frame *prior) {
 assert(memcmp(states,before,sizeof(states))==0);
 assert(memcmp(frame_values,prior,sizeof(frame_values))==0);
}
int main(void) {
 // Exercise actual installed PT_REGS macros via the production adapters.
 struct pt_regs regs={.rdi=0x1122334455667788ULL,.rsi=0x2233445566778899ULL,
  .rdx=0x33445566778899aaULL,.rax=0x445566778899aabbULL};
 struct a0_copy_args args=copy_entry_args(&regs);
 assert(args.to==regs.rdi && args.from==regs.rsi && args.n==regs.rdx);
 assert(copy_return_value(&regs)==regs.rax);
 reset(0,0);
 copy_enter(&regs);
 regs.rdi=0xdeadbeefdeadbeefULL;regs.rsi=0xbadbadbadbadbadULL;regs.rdx=0x9999999999999999ULL;
 regs.rax=0x1122334455667788ULL;
 copy_exit(&regs);
 assert(observed.to==args.to && observed.n==args.n && observed.remaining==regs.rax);
 assert(observed.unknown==(A0_RETURN_UNKNOWN|8) && counts.faults==1);

 _Static_assert(sizeof(struct pending)==32,"pending no longer holds frames");
 _Static_assert(sizeof(struct frame)==24,"frame payload changed");
 reset(0,0);
 struct frame zero={};
 for (__u32 i=0;i<32;i++) assert(memcmp(&frame_values[i],&zero,sizeof(zero))==0);
 const __u64 depths[]={0,1,2,3,4,5,6,7,8,9,UINT64_MAX,UINT64_C(1)<<32};
 for (__u32 owner=0;owner<4;owner++) {
  for (unsigned i=0;i<sizeof(depths)/sizeof(depths[0]);i++) {
   __u64 depth=depths[i];
   reset(owner,depth);
   struct pending before[4]; struct frame prior[32];
   memcpy(before,states,sizeof(states)); memcpy(prior,frame_values,sizeof(frame_values));
   enter(0,(void *)100,0,16);
   if (depth>=8) {
    assert(counts.faults==1 && counts.calls==0 && counts.records==0 && frame_lookups==0);
    expect_unchanged(before,prior);
   } else {
    assert(counts.faults==0 && counts.calls==1 && counts.records==1);
    assert(state.depth==depth+1 && observed.depth==depth+1 && observed.unknown==A0_COPY_UNKNOWN);
    assert(last_frame_key==owner*8+depth && frame_lookups==1);
    assert(frame_values[last_frame_key].call==observed.call && frame_values[last_frame_key].to==100);
    for (__u32 k=0;k<32;k++) if(k!=last_frame_key) assert(memcmp(&frame_values[k],&prior[k],sizeof(zero))==0);
   }
   reset(owner,depth);
   if(depth && depth<=8) frame_values[owner*8+depth-1]=(struct frame){depth,100,16};
   memcpy(before,states,sizeof(states)); memcpy(prior,frame_values,sizeof(frame_values));
   leave(0,(void *)100,0,16,0);
   if (!depth || depth>8) {
    assert(counts.faults==1 && counts.records==0 && frame_lookups==0);
    expect_unchanged(before,prior);
   } else {
    assert(counts.faults==0 && counts.records==1 && state.depth==depth-1);
    assert(last_frame_key==owner*8+depth-1 && observed.call==depth && observed.depth==depth && observed.unknown==A0_RETURN_UNKNOWN);
   }
  }
 }
 // Interleave all owners while independently filling and draining eight slots.
 reset(0,0);
 for (__u64 depth=0;depth<8;depth++) for(__u32 owner=0;owner<4;owner++) {
  active=owned_slot=owner;
  enter(0,(void *)(uintptr_t)(100+owner*8+depth),0,16+depth);
  assert(state.depth==depth+1);
 }
 for (__u64 depth=8;depth>0;depth--) for(__u32 owner=0;owner<4;owner++) {
  active=owned_slot=owner;
  leave(0,(void *)(uintptr_t)(100+owner*8+depth-1),0,16+depth-1,0);
  assert(state.depth==depth-1 && observed.call==(depth-1)*4+owner+1);
  assert(observed.depth==depth && observed.unknown==A0_RETURN_UNKNOWN);
 }
 assert(counts.calls==32 && counts.records==64 && counts.faults==0);
 // Invalid authenticated-slot map values are refused by actual current().
 const __u32 invalid_slots[]={4,UINT32_MAX};
 for (unsigned i=0;i<2;i++) {
  reset(0,1); owned_slot=invalid_slots[i];
  struct pending before[4]; struct frame prior[32];
  memcpy(before,states,sizeof(states)); memcpy(prior,frame_values,sizeof(frame_values));
  enter(0,(void *)100,0,16); leave(0,(void *)100,0,16,0);
  assert(counts.calls==0 && counts.records==0 && frame_lookups==0);
  expect_unchanged(before,prior);
 }
 // Mutate the owned-map value AFTER capture: both lookups still use original slot.
 reset(1,0); change_slot=1; enter(0,(void *)100,0,16);
 assert(last_frame_key==8 && states[1].depth==1 && states[3].depth==0);
 // Missing frame value must fault before call ID/frame/depth mutation.
 for(int exiting=0;exiting<2;exiting++) {
  reset(2,exiting ? 1 : 0); fail_frames=1;
  struct pending before[4]; struct frame prior[32];
  memcpy(before,states,sizeof(states)); memcpy(prior,frame_values,sizeof(frame_values));
  if(exiting) leave(0,(void *)100,0,16,0); else enter(0,(void *)100,0,16);
  assert(counts.faults==1 && counts.calls==0 && counts.records==0 && frame_lookups==1);
  expect_unchanged(before,prior);
 }
 const long bad_stack[]={-1,0,15,128};
 for(unsigned i=0;i<4;i++) {
  reset(0,0); stack_result=bad_stack[i]; enter(0,(void *)100,0,16);
  assert(counts.faults==1 && observed.unknown==(A0_COPY_UNKNOWN|4) && state.depth==1);
 }
 reset(0,1); state.task=8;
 struct pending before[4]; struct frame prior[32];
 memcpy(before,states,sizeof(states)); memcpy(prior,frame_values,sizeof(frame_values));
 enter(0,(void *)100,0,16); leave(0,(void *)100,0,16,0);
 assert(counts.faults==2 && counts.records==0 && frame_lookups==0); expect_unchanged(before,prior);
 for(unsigned fault=0;fault<3;fault++) {
  reset(0,1); frame_values[0]=(struct frame){1,100,16};
  leave(0,(void *)(uintptr_t)(fault==0 ? 101 : 100),0,fault==1 ? 17 : 16,fault==2);
  assert(counts.faults==(fault==2) && observed.unknown==(A0_RETURN_UNKNOWN|(fault==2 ? 8 : 0)) && state.depth==0);
 }
 return 0;
}
`

	harness += fmt.Sprintf("\n_Static_assert(A0_COPY_UNKNOWN==%d, \"entry uncertainty wire bits\");\n_Static_assert(A0_RETURN_UNKNOWN==%d, \"return uncertainty wire bits\");\n", copyCandidateUnknown, returnSnapshotUnknown)
	dir := t.TempDir()
	input, binary := filepath.Join(dir, "depth.c"), filepath.Join(dir, "depth")
	if err := os.WriteFile(input, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()
	for _, args := range [][]string{
		{"-std=c11", "-D__TARGET_ARCH_x86", "-O2", "-Wall", "-Werror", "-fsanitize=undefined,bounds", "-fno-sanitize-recover=all", input, "-o", binary},
		nil,
	} {
		command := clang
		if args == nil {
			command = binary
		}
		if output, err := exec.CommandContext(ctx, command, args...).CombinedOutput(); err != nil {
			t.Fatalf("pure C depth regression: %v: %s", err, output)
		}
	}
}

func TestA0FrameMapLayout(t *testing.T) {
	if !a0Enabled(os.Getenv(a0Flag)) {
		t.Skip("A0 offline map layout disabled")
	}
	object, _ := compileA0(t)
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Programs) != 5 {
		t.Fatalf("program count = %d", len(spec.Programs))
	}
	for _, hook := range a0AttachmentPlan() {
		p := spec.Programs[hook.Name]
		if p == nil || p.Type != hook.ProgramType {
			t.Fatalf("%s wrong compiled type: %+v", hook.Name, p)
		}
	}
	if len(spec.Maps) != 6 {
		t.Fatalf("map count = %d, want six", len(spec.Maps))
	}
	for name, want := range map[string]struct{ entries, size uint32 }{
		"frames": {32, 24}, "pending": {4, 32},
	} {
		m := spec.Maps[name]
		if m == nil || m.Type != ebpf.Array || m.KeySize != 4 || m.ValueSize != want.size || m.MaxEntries != want.entries {
			t.Fatalf("%s unexpected map layout: %+v", name, m)
		}
	}
}

type a0AttachTestCloser struct {
	index int
	order *[]int
	calls int
	fail  bool
}

func (c *a0AttachTestCloser) Close() error {
	c.calls++
	*c.order = append(*c.order, c.index)
	if c.fail && c.calls == 1 {
		return fmt.Errorf("close %d", c.index)
	}
	return nil
}

func TestA0MixedAttachFailureQuarantinesAllAvailableReferences(t *testing.T) {
	for failed := 0; failed < 5; failed++ {
		for _, anomaly := range []string{"error", "handle-and-error", "nil", "typed-nil"} {
			for mask := 0; mask < (1 << (failed + 1)); mask++ {
				t.Run(fmt.Sprintf("%d/%s/%d", failed, anomaly, mask), func(t *testing.T) {
					var order []int
					collection := &ebpf.Collection{}
					ns := &a0Namespace{}
					owner := &a0NativeOwner{collection: collection, namespace: ns}
					var handles []*a0AttachTestCloser
					calls := 0
					err := attachA0Plan(owner, func(spec a0AttachSpec) (io.Closer, error) {
						i := calls
						calls++
						if i > failed {
							t.Fatal("attachment continued after failure")
						}
						h := &a0AttachTestCloser{index: i, order: &order, fail: mask&(1<<i) != 0}
						if i == failed {
							switch anomaly {
							case "error":
								return nil, errors.New("attach")
							case "nil":
								return nil, nil
							case "typed-nil":
								var absent *a0AttachTestCloser
								return absent, nil
							case "handle-and-error":
								handles = append(handles, h)
								return h, errors.New("attach")
							}
						}
						handles = append(handles, h)
						return h, nil
					})
					if err == nil || calls != failed+1 || owner.attachErr == nil {
						t.Fatal("attachment uncertainty lost")
					}
					operations := 0
					retained, cleanupErr := orderedA0Cleanup(a0CleanupSteps{
						detach:     owner.detach,
						unregister: func() error { operations++; return nil },
						release:    func() error { operations++; return nil },
						quarantine: func(error) {},
					})
					if !retained || cleanupErr == nil || operations != 0 {
						t.Fatal("uncertain attachment released resources")
					}
					if owner.collection != collection || owner.namespace != ns || len(owner.links) != len(handles) || owner.child != nil || owner.registered != 0 || owner.timer != nil {
						t.Fatal("available references lost")
					}
					for i, h := range handles {
						if h.fail && !strings.Contains(cleanupErr.Error(), fmt.Sprintf("close %d", i)) {
							t.Fatal("close error lost")
						}
						if h.calls != 1 || order[len(handles)-1-i] != i {
							t.Fatal("not exactly one reverse close pass")
						}
					}
					first := owner.detachErr
					if !errors.Is(owner.detach(), first) {
						t.Fatal("nil retry cleared uncertainty")
					}
					for _, h := range handles {
						if h.calls != 1 {
							t.Fatal("close retried")
						}
					}
				})
			}
		}
	}
}

func TestA0MixedAttachPlanExactContract(t *testing.T) {
	plan := a0AttachmentPlan()
	wantNames := []string{"start", "copy_enter", "copy_exit", "check", "finish"}
	for i, s := range plan {
		if s.Return != (i == 2) {
			t.Fatal("wrong entry/return attachment kind")
		}
		if s.Options.Cookie != 0 || s.Options.TraceFSPrefix != "" {
			t.Fatal("unexpected attachment option")
		}
		if s.Name != wantNames[i] {
			t.Fatal("attachment order changed")
		}
		if i == 1 || i == 2 {
			if s.ProgramType != ebpf.Kprobe || s.Symbol != "_copy_from_user" || !s.Options.ExactSymbol || s.Options.Offset != 0 {
				t.Fatal("noncanonical copy hook")
			}
			wantMax := 0
			if i == 2 {
				wantMax = 128
			}
			if s.Options.RetprobeMaxActive != wantMax {
				t.Fatal("return capacity changed")
			}
		} else if s.ProgramType != ebpf.Tracing || s.Symbol != "" {
			t.Fatal("typed lifecycle changed")
		}
	}
	var order []int
	o := &a0NativeOwner{}
	n := 0
	if err := attachA0Plan(o, func(a0AttachSpec) (io.Closer, error) {
		h := &a0AttachTestCloser{index: n, order: &order}
		n++
		return h, nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 5 || o.detach() != nil || len(o.links) != 0 {
		t.Fatal("complete attachment teardown failed")
	}
}

func TestA0AuthenticatedRegisterLayout(t *testing.T) {
	newRegs := func() *btf.Struct {
		u := &btf.Int{Name: "long unsigned int", Size: 8, Encoding: btf.Unsigned}
		return &btf.Struct{Name: "pt_regs", Size: 168, Members: []btf.Member{
			{Name: "di", Type: u, Offset: 112 * 8},
			{Name: "si", Type: u, Offset: 104 * 8},
			{Name: "dx", Type: u, Offset: 96 * 8},
			{Name: "ax", Type: u, Offset: 80 * 8},
		}}
	}
	if err := validateA0RegisterLayout(newRegs()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*btf.Struct){
		"size":       func(r *btf.Struct) { r.Size = 160 },
		"offset":     func(r *btf.Struct) { r.Members[0].Offset = 104 * 8 },
		"missing":    func(r *btf.Struct) { r.Members = r.Members[:3] },
		"wrong name": func(r *btf.Struct) { r.Members[0].Name = "rdi" },
		"narrow":     func(r *btf.Struct) { r.Members[0].Type = &btf.Int{Size: 4, Encoding: btf.Unsigned} },
		"signed":     func(r *btf.Struct) { r.Members[0].Type = &btf.Int{Size: 8, Encoding: btf.Signed} },
		"bitfield":   func(r *btf.Struct) { r.Members[0].BitfieldSize = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRegs()
			change(r)
			if validateA0RegisterLayout(r) == nil {
				t.Fatal("ambiguous ABI accepted")
			}
		})
	}
	if validateA0RegisterLayout(nil) == nil {
		t.Fatal("missing ABI accepted")
	}
}

func TestA0CandidatePairingNeverClaimsLosslessness(t *testing.T) {
	for _, name := range []string{"balanced", "missing return", "duplicate return", "foreign task", "missing snapshot flag", "foreign capacity pressure", "profile zero wrong counter", "profile unavailable", "profile ambiguous"} {
		t.Run(name, func(t *testing.T) {
			records := nativeSample()
			switch name {
			case "missing return":
				records = append(records[:2], records[3:]...)
			case "duplicate return":
				records = append(records[:3], records[2:]...)
			case "foreign task":
				records[2].Task++
			case "missing snapshot flag":
				records[2].Unknown = copyCandidateUnknown
			}
			valid := validateNativeRecords(records, 7) == nil
			if name == "missing return" || name == "duplicate return" || name == "foreign task" || name == "missing snapshot flag" {
				if valid {
					t.Fatal("malformed pair accepted")
				}
			}
			// Diagnostics/pressure are not inputs that can establish losslessness.
			report := offlineReport(valid)
			if report.Pairing != "LIFO_candidate" || report.ReturnArguments != "entry_snapshot" ||
				report.ReturnInstanceLoss != "UNKNOWN" || report.Completeness != "NOT_READY" ||
				report.CopyEntry != "canonical_kprobe" || report.CopyReturn != "canonical_kretprobe" || report.RetprobeMaxActive != 128 {
				t.Fatalf("observation overclaimed: %+v", report)
			}
		})
	}
}

func TestA0AttachmentPrecedesEveryActivationStep(t *testing.T) {
	data, err := os.ReadFile("copy_completion_feasibility_test.go")
	if err != nil {
		t.Fatal(err)
	}
	body := a0CSection(t, string(data), "func runA0(", "func validateNativeRecords(")
	attachment := strings.Index(body, "if err := attachA0Plan(")
	refusal := strings.Index(body, `t.Fatalf("NOT_READY: mixed attachment:`)
	if attachment < 0 || refusal < attachment {
		t.Fatal("missing fatal attachment barrier")
	}
	for _, step := range []string{`Maps["config"].Put`, `Maps["config"].Freeze`, "ownedA0Command(", "child.Start()", `Maps["owned"].Put`, "gateWrite.Write("} {
		if strings.Index(body, step) <= refusal {
			t.Fatalf("%s occurs before fatal attach barrier", step)
		}
	}
}
