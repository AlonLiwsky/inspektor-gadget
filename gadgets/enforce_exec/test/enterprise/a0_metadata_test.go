// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package enterprise_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
	entry.Unknown = 2
	entry.StackBytes = 16
	entry.Stack[0] = 101
	entry.Stack[1] = 102
	ret := entry
	ret.Kind = 2
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
	for _, callback := range []struct{ start, end, guard string }{
		{"int BPF_PROG(copy_enter,", `SEC("fexit/_copy_from_user")`, "depth>=8"},
		{"int BPF_PROG(copy_exit,", `SEC("fentry/security_bprm_check")`, "!depth || depth>8"},
	} {
		body := a0CSection(t, source, callback.start, callback.end)
		// One full-width map load and one final store. Checking map memory and
		// then reloading it for arithmetic loses the checked scalar identity.
		if strings.Count(body, "s->depth") != 2 {
			t.Errorf("%s must read depth once and write it once", callback.start)
		}
		capture := strings.Index(body, "__u64 depth=s->depth;")
		guard := strings.Index(body, callback.guard)
		index := strings.Index(body, "&s->frame[depth]")
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
	types := a0CSection(t, source, "struct config {", "struct { __uint")
	callbacks := a0CSection(t, source, `SEC("fentry/_copy_from_user")`, `SEC("fentry/security_bprm_check")`)
	// Ordinary process memory only: no kernel helpers, maps, attachments,
	// namespace operations, or synthetic exec_target are invoked.
	harness := `
#include <stdint.h>
#include <assert.h>
#include <string.h>
typedef uint64_t __u64;
#define SEC(name)
#define BPF_PROG(name, ...) name(void *ctx, __VA_ARGS__)
` + types + `
static struct pending state;
static struct counters counts;
static struct record observed;
static struct pending *current(struct counters **c) { *c=&counts; return &state; }
static __u64 bpf_get_current_task(void) { return 7; }
static long bpf_get_stack(void *ctx, void *stack, unsigned long size, int flags) { return 16; }
static struct record *reserve(struct counters *c, struct pending *s, __u64 kind) {
 memset(&observed,0,sizeof(observed)); observed.kind=kind; c->records++; return &observed;
}
` + callbacks + `
static void reset(__u64 depth) {
 memset(&state,0,sizeof(state)); memset(&counts,0,sizeof(counts));
 memset(&observed,0,sizeof(observed)); state.task=7; state.attempt=1; state.depth=depth;
 for (unsigned i=0;i<8;i++) state.frame[i]=(struct frame){i+1,100+i,16+i};
}
int main(void) {
 const __u64 depths[]={0,1,7,8,9,UINT64_MAX,UINT64_C(1)<<32};
 for (unsigned i=0;i<sizeof(depths)/sizeof(depths[0]);i++) {
  __u64 depth=depths[i];
  reset(depth);
  struct pending before=state;
  copy_enter(0,(void *)100,0,16);
  if (depth>=8) {
   assert(counts.faults==1 && counts.calls==0 && counts.records==0);
   assert(memcmp(&before,&state,sizeof(state))==0);
  } else {
   assert(counts.faults==0 && counts.calls==1 && counts.records==1);
   assert(state.depth==depth+1 && observed.depth==depth+1 && observed.unknown==2);
   assert(state.frame[depth].call==observed.call && state.frame[depth].to==100);
  }
  reset(depth); before=state;
  if (!depth || depth>8) {
   copy_exit(0,(void *)100,0,16,0);
   assert(counts.faults==1 && counts.records==0);
   assert(memcmp(&before,&state,sizeof(state))==0);
  } else {
   copy_exit(0,(void *)(uintptr_t)(100+depth-1),0,16+depth-1,0);
   assert(counts.faults==0 && counts.records==1 && state.depth==depth-1);
   assert(observed.call==depth && observed.depth==depth && observed.unknown==2);
  }
 }
 reset(0);
 for (__u64 i=0;i<8;i++) copy_enter(0,(void *)(uintptr_t)(100+i),0,16+i);
 assert(state.depth==8 && counts.faults==0);
 for (__u64 i=8;i>0;i--) {
  copy_exit(0,(void *)(uintptr_t)(100+i-1),0,16+i-1,0);
  assert(state.depth==i-1 && observed.call==i && observed.depth==i && observed.unknown==2);
 }
 assert(counts.calls==8 && counts.records==16 && counts.faults==0);
 reset(1); state.task=8;
 struct pending before=state;
 copy_enter(0,(void *)100,0,16); copy_exit(0,(void *)100,0,16,0);
 assert(counts.faults==2 && counts.records==0 && memcmp(&before,&state,sizeof(state))==0);
 reset(1); copy_exit(0,(void *)101,0,16,0);
 assert(counts.faults==1 && observed.unknown==10 && state.depth==0);
 reset(1); copy_exit(0,(void *)100,0,17,0);
 assert(counts.faults==1 && observed.unknown==10);
 reset(1); copy_exit(0,(void *)100,0,16,1);
 assert(counts.faults==1 && observed.unknown==10);
 return 0;
}
`
	dir := t.TempDir()
	input, binary := filepath.Join(dir, "depth.c"), filepath.Join(dir, "depth")
	if err := os.WriteFile(input, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()
	for _, args := range [][]string{
		{"-std=c11", "-O2", "-Wall", "-Werror", "-fsanitize=undefined,bounds", "-fno-sanitize-recover=all", input, "-o", binary},
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
