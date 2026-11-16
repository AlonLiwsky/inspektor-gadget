// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func testGate(t *testing.T) (*Gate, *uint64) {
	t.Helper()
	word := new(uint64)
	g, err := NewGateWord(word)
	if err != nil {
		t.Fatal(err)
	}
	return g, word
}

func requireState(t *testing.T, g *Gate, closed bool, count uint64) {
	t.Helper()
	c, n, err := g.State()
	if err != nil || c != closed || n != count {
		t.Fatalf("state=(%v,%d,%v), want(%v,%d)", c, n, err, closed, count)
	}
}

func TestGateAdmissionAndPublication(t *testing.T) {
	g, _ := testGate(t)
	if err := g.Enter(); err != nil {
		t.Fatal(err)
	}
	requireState(t, g, false, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ready := make(chan *UpdateLease, 1)
	failed := make(chan error, 1)
	go func() {
		l, err := g.BeginUpdate(ctx)
		if err != nil {
			failed <- err
			return
		}
		ready <- l
	}()
	for {
		closed, _, err := g.State()
		if err != nil {
			t.Fatal(err)
		}
		if closed {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
			runtime.Gosched()
		}
	}
	if err := g.Enter(); !errors.Is(err, ErrGateBusy) {
		t.Fatalf("closed admission=%v", err)
	}
	if _, err := g.BeginUpdate(ctx); !errors.Is(err, ErrGateBusy) {
		t.Fatalf("publisher takeover=%v", err)
	}
	var committed atomic.Bool
	committed.Store(true) // represents the task's role commit before release
	if err := g.Leave(); err != nil {
		t.Fatal(err)
	}
	var lease *UpdateLease
	select {
	case lease = <-ready:
	case err := <-failed:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !committed.Load() {
		t.Fatal("publication preceded commit")
	}
	requireState(t, g, true, 0)
	if err := lease.Reopen(); err != nil {
		t.Fatal(err)
	}
	requireState(t, g, false, 0)
	next, err := g.BeginUpdate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Reopen(); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale publisher reopened current closure: %v", err)
	}
	requireState(t, g, true, 0)
	if err := next.Reopen(); err != nil {
		t.Fatal(err)
	}
}

func TestGateTimeoutPreservesAdmission(t *testing.T) {
	g, _ := testGate(t)
	if err := g.Enter(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	if _, err := g.BeginUpdate(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout=%v", err)
	}
	requireState(t, g, false, 1)
	if err := g.Leave(); err != nil {
		t.Fatal(err)
	}
	l, err := g.BeginUpdate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Retire(); err != nil {
		t.Fatal(err)
	}
	requireState(t, g, true, 0)
	if err = g.Enter(); !errors.Is(err, ErrGateRetired) {
		t.Fatalf("retired enter=%v", err)
	}
	if _, err = g.BeginUpdate(t.Context()); !errors.Is(err, ErrGateRetired) {
		t.Fatal(err)
	}
}

func TestGateLimitsAndForeignClosure(t *testing.T) {
	g, word := testGate(t)
	if err := g.Leave(); !errors.Is(err, ErrGateUnderflow) {
		t.Fatal(err)
	}
	for range MaxAdmittedExecs {
		if err := g.Enter(); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Enter(); !errors.Is(err, ErrGateCapacity) {
		t.Fatal(err)
	}
	requireState(t, g, false, MaxAdmittedExecs)
	for range MaxAdmittedExecs {
		if err := g.Leave(); err != nil {
			t.Fatal(err)
		}
	}
	atomic.StoreUint64(word, GateClosed) // test a foreign publisher before ownership
	if _, err := g.BeginUpdate(t.Context()); !errors.Is(err, ErrGateBusy) {
		t.Fatal(err)
	}
	requireState(t, g, true, 0)
	atomic.StoreUint64(word, MaxAdmittedExecs+1) // corruption injection, never production
	if err := g.Enter(); !errors.Is(err, ErrGateCorrupt) {
		t.Fatal(err)
	}
	if err := g.Leave(); !errors.Is(err, ErrGateCorrupt) {
		t.Fatal(err)
	}
	if _, err := g.BeginUpdate(t.Context()); !errors.Is(err, ErrGateCorrupt) {
		t.Fatal(err)
	}
	if _, _, err := g.State(); !errors.Is(err, ErrGateCorrupt) {
		t.Fatal(err)
	}
}

func TestGateConstructor(t *testing.T) {
	if _, err := NewGateWord(nil); err == nil {
		t.Fatal("nil accepted")
	}
	bytes := make([]byte, 24)
	base := uintptr(unsafe.Pointer(&bytes[0]))
	off := int((8-base%8)%8) + 1
	if _, err := NewGateWord((*uint64)(unsafe.Pointer(&bytes[off]))); err == nil {
		t.Fatal("misaligned accepted")
	}
	value := uint64(MaxAdmittedExecs + 1)
	if _, err := NewGateWord(&value); !errors.Is(err, ErrGateCorrupt) {
		t.Fatal(err)
	}
	if _, err := NewGateMap(nil); err == nil {
		t.Fatal("nil map accepted")
	}
}

func TestGateConcurrentAdmission(t *testing.T) {
	g, _ := testGate(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var workers sync.WaitGroup
	var taskWrites atomic.Uint64
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 1000 {
				for {
					if ctx.Err() != nil {
						return
					}
					err := g.Enter()
					if err == nil {
						break
					}
					if !errors.Is(err, ErrGateBusy) {
						t.Error(err)
						return
					}
					runtime.Gosched()
				}
				taskWrites.Add(1)
				for {
					err := g.Leave()
					if err == nil {
						break
					}
					if !errors.Is(err, ErrGateBusy) {
						t.Error(err)
						return
					}
				}
			}
		}()
	}
	for range 100 {
		l, err := g.BeginUpdate(ctx)
		if errors.Is(err, ErrGateBusy) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		requireState(t, g, true, 0)
		before := taskWrites.Load()
		runtime.Gosched()
		if taskWrites.Load() != before {
			t.Fatal("task commit during drained closure")
		}
		if err = l.Reopen(); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	requireState(t, g, false, 0)
	if taskWrites.Load() != 8000 {
		t.Fatalf("lost task commits: %d", taskWrites.Load())
	}
}

func newHeapGateMap() *GateMap {
	return &GateMap{memory: &gateMemory{}, words: make([]uint64, MaxLifetimeSlots)}
}

func TestGateSlotBudgetsAndRetirement(t *testing.T) {
	m := newHeapGateMap()
	gates := make([]*Gate, 0, MaxConcurrentBindings)
	for i := range MaxConcurrentBindings {
		slot, g, err := m.Allocate()
		if err != nil || slot != uint32(i) {
			t.Fatalf("allocate %d: %d %v", i, slot, err)
		}
		gates = append(gates, g)
	}
	if _, _, err := m.Allocate(); !errors.Is(err, ErrSlotCapacity) {
		t.Fatal(err)
	}
	if err := m.Close(); !errors.Is(err, ErrGateBusy) {
		t.Fatal(err)
	}
	lease, err := gates[0].BeginUpdate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); !errors.Is(err, ErrGateBusy) {
		t.Fatal("unmapped publisher lease")
	}
	if err = lease.Retire(); err != nil {
		t.Fatal(err)
	}
	slot, g, err := m.Allocate()
	if err != nil || slot != MaxConcurrentBindings {
		t.Fatalf("slot reused: %d %v", slot, err)
	}
	gates = append(gates, g)
	if err = gates[0].Enter(); !errors.Is(err, ErrGateRetired) {
		t.Fatal(err)
	}
	for _, g := range gates[1:] {
		l, err := g.BeginUpdate(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err = l.Retire(); err != nil {
			t.Fatal(err)
		}
	}
	m.next = MaxLifetimeSlots // simulate exhausted monotonic cursor, never reset it
	if _, _, err = m.Allocate(); !errors.Is(err, ErrSlotCapacity) {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.Allocate(); !errors.Is(err, ErrGateClosed) {
		t.Fatal(err)
	}
	if _, _, err = gates[0].State(); !errors.Is(err, ErrGateClosed) {
		t.Fatal(err)
	}
}

func TestGateBPFCompiles(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang unavailable")
	}
	out, err := exec.Command(clang, "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-c", "bpf/gate_test.bpf.c", "-o", filepath.Join(t.TempDir(), "gate.o")).CombinedOutput()
	if err != nil {
		t.Fatalf("compile gate BPF: %v\n%s", err, out)
	}
}

func TestCanceledBeginDoesNotCloseAdmission(t *testing.T) {
	g, _ := testGate(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := g.BeginUpdate(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	requireState(t, g, false, 0)
}

func TestStaleRetirementCannotRetireCurrentLease(t *testing.T) {
	g, _ := testGate(t)
	old, err := g.BeginUpdate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = old.Reopen(); err != nil {
		t.Fatal(err)
	}
	current, err := g.BeginUpdate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = old.Retire(); !errors.Is(err, ErrStaleLease) {
		t.Fatal(err)
	}
	if g.retired.Load() {
		t.Fatal("stale lease retired current owner")
	}
	requireState(t, g, true, 0)
	if err = current.Reopen(); err != nil {
		t.Fatal(err)
	}
}

func TestUnexpectedLeaseStateFailsClosed(t *testing.T) {
	g, word := testGate(t)
	lease, err := g.BeginUpdate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	atomic.StoreUint64(word, GateClosed|1) // inject a protocol violation
	if err = lease.Reopen(); !errors.Is(err, ErrGateCorrupt) {
		t.Fatal(err)
	}
	requireState(t, g, true, 1)
	if _, err = g.BeginUpdate(t.Context()); !errors.Is(err, ErrGateBusy) {
		t.Fatal("foreign closure taken over")
	}
}

// Exercise the actual C helper without privileged BPF execution. The caller's
// ownership lock is released before the final shared gate decrement.
func TestGateOwnedRelease(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	root, err := filepath.Abs("bpf")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	source := filepath.Join(tmp, "owned.c")
	binary := filepath.Join(tmp, "owned")
	if err := os.WriteFile(source, []byte(`
#include <assert.h>
#include <pthread.h>
#include "gate.h"
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned int owned=1;
static fg_u64 word=FG_CLOSED|1, faults=0;
static int committed=0;
static void *complete(void *unused){
 (void)unused;
 pthread_mutex_lock(&lock);
 unsigned int claim=owned;
 if(claim){committed=1;owned=0;}
 pthread_mutex_unlock(&lock);
 assert(fg_leave_owned(&word,claim,&faults)==FG_OK);
 return 0;
}
int main(void){
 pthread_t threads[32];
 for(int i=0;i<32;i++)assert(!pthread_create(&threads[i],0,complete,0));
 for(int i=0;i<32;i++)assert(!pthread_join(threads[i],0));
 assert(committed&&word==FG_CLOSED&&!faults);
 assert(fg_leave_owned(&word,0,&faults)==FG_OK&&word==FG_CLOSED);
 assert(fg_leave_owned(&word,1,&faults)==FG_UNDERFLOW);
 assert(faults&&word==FG_CLOSED);
 /* Existing faults are NOT evidence that a valid claimed count is corrupt.
  * Drain exact owners without repairing faults or reopening admission. */
 word=FG_CLOSED|2;faults=4;
 assert(fg_leave_owned(&word,1,&faults)==FG_OK&&word==(FG_CLOSED|1)&&faults==4);
 assert(fg_leave_owned(&word,0,&faults)==FG_OK&&word==(FG_CLOSED|1)&&faults==4);
 assert(fg_leave_owned(&word,1,&faults)==FG_OK&&word==FG_CLOSED&&faults==4);
 assert(fg_leave_owned(&word,1,&faults)==FG_UNDERFLOW&&word==FG_CLOSED&&faults==5);
 faults=0;word=FG_CLOSED|(FG_MAX_ADMITTED+1ULL);
 assert(fg_leave_owned(&word,1,&faults)==FG_CORRUPT&&faults);
 assert(word==(FG_CLOSED|(FG_MAX_ADMITTED+1ULL)));
 return 0;
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-O2", "-pthread", "-I"+root, source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("owned release: %v %s", err, out)
	}
}

// A lease copied by value must share its one-shot authority. In particular an
// old copy cannot reopen OR retire a later publisher's closure.
func TestCopiedUpdateLeaseCannotTakeOverLaterPublisher(t *testing.T) {
	for _, retire := range []bool{false, true} {
		t.Run(map[bool]string{false: "reopen", true: "retire"}[retire], func(t *testing.T) {
			g, _ := testGate(t)
			old, err := g.BeginUpdate(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			copied := *old
			if err = old.Reopen(); err != nil {
				t.Fatal(err)
			}
			current, err := g.BeginUpdate(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if retire {
				err = copied.Retire()
			} else {
				err = copied.Reopen()
			}
			if !errors.Is(err, ErrStaleLease) {
				t.Fatalf("copied stale lease stole new publication: %v", err)
			}
			requireState(t, g, true, 0)
			if err = current.Reopen(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
