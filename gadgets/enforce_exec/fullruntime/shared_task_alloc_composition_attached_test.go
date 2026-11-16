// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// VM only: the product fork transaction next to a second,
// independent lsm/task_alloc program that denies the fork, in both attach
// orders (modelled on TestTaskAllocComposition from
// kubescape/inspektor-gadget#26). BPF LSM programs on
// one hook run as fmod_ret: the first nonzero return skips the rest. In one
// order the denier runs first and the product source never runs; in the
// other the product source parks its claim and the target constructs the
// child TASK inside task_alloc, then the denier refuses the fork, and
// security_task_alloc calls security_task_free, so the product task_free
// must release everything. In both orders, for a Strict and an Audit
// binding:
//   - the denied fork fails with EPERM;
//   - TASK/WORK credits return to the post-adoption baseline, no exec
//     terminal receipt is left, the route holds no early claim, and every
//     birth park is taken or abandoned (none stale, latched or failed);
//   - no fail-closed rate counts a fault, and no account is faulted;
//   - the next fork of the same parent succeeds and settles.
//
// The product source must run in exactly one of the two orders (it is
// logged which), so both paths are covered. Whether it ran is read from a
// class-independent signal: opaque_real_attempts[0], which counts every
// OWNED birth claim of the source, Audit and Strict alike (the birth park
// is class-independent too). Where it ran, the target must have taken the
// parked claim (birth park Taken), i.e. the child TASK was constructed
// before the denier refused the fork. The fail-closed witness must stay
// Healthy throughout.
//
// Environment: as TestSharedNodeFailClosedInjectAttached, with the product
// object (g19pkg128) in IG_SHARED_M4_OBJECT:
//
//	IG_SHARED_M4_OBJECT, IG_SHARED_M4_CGROUP_ROOT (ig15-g019-m4-*),
//	IG_SHARED_M4_HANDLER_SYMBOL, IG_SHARED_FC_HELPER
func TestSharedNodeTaskAllocCompositionAttached(t *testing.T) {
	if os.Getenv("IG_SHARED_M4_OBJECT") == "" || os.Getenv("IG_SHARED_M4_CGROUP_ROOT") == "" {
		t.Skip("set IG_SHARED_M4_OBJECT and IG_SHARED_M4_CGROUP_ROOT on an isolated exact-kernel VM")
	}
	cfg := sharedFCConfig{helper: os.Getenv("IG_SHARED_FC_HELPER"), interval: 200 * time.Millisecond}
	if cfg.helper == "" {
		t.Fatal("IG_SHARED_FC_HELPER (the static testdata/opaque_real_live_exec_parent.c build) is required")
	}
	for _, class := range []struct {
		name  string
		class int
	}{{"strict", 2}, {"audit", 1}} {
		t.Run(class.name, func(t *testing.T) {
			ran := map[string]bool{}
			for _, order := range []string{"denier attached first", "denier attached last"} {
				t.Run(order, func(t *testing.T) {
					ran[order] = sharedTaskAllocComposition(t, cfg, class.class, order == "denier attached first")
				})
			}
			if t.Failed() {
				return
			}
			first, last := ran["denier attached first"], ran["denier attached last"]
			t.Logf("product source ran before the denier: first-attached order %v, last-attached order %v", first, last)
			if first == last {
				t.Fatalf("the product source ran in %v of both orders; want exactly one order to exercise the constructed-then-denied child", first)
			}
		})
	}
}

// sharedTaskAllocDenier is an independent lsm/task_alloc program: it denies
// (-EPERM) every fork whose current cgroup is the one armed in its map
// (value[0]; 0 disarms), and counts its denials (value[1]).
func sharedTaskAllocDenier(t *testing.T) (*ebpf.Map, link.Link) {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "ig_ta_denier", Type: ebpf.Array, KeySize: 4, ValueSize: 16, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "ig_ta_deny_fork", Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: "task_alloc", License: "GPL",
		Instructions: asm.Instructions{
			asm.FnGetCurrentCgroupId.Call(),
			asm.Mov.Reg(asm.R6, asm.R0),
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "allow"),
			asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
			asm.JEq.Imm(asm.R1, 0, "allow"),
			asm.JNE.Reg(asm.R1, asm.R6, "allow"),
			asm.Add.Imm(asm.R0, 8),
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.Mov.Imm(asm.R0, -int32(unix.EPERM)),
			asm.Return(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("allow"),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatalf("load the denying task_alloc program: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		t.Fatalf("attach the denying task_alloc program: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return m, l
}

func sharedTaskAllocDenierSet(t *testing.T, m *ebpf.Map, cgroup uint64) uint64 {
	t.Helper()
	var value [2]uint64
	if err := m.Lookup(uint32(0), &value); err != nil {
		t.Fatal(err)
	}
	value[0] = cgroup
	if err := m.Update(uint32(0), value, ebpf.UpdateExist); err != nil {
		t.Fatal(err)
	}
	return value[1]
}

// sharedTaskAllocComposition runs one order and reports whether the product
// source parked a birth for the denied fork (it ran before the denier).
func sharedTaskAllocComposition(t *testing.T, cfg sharedFCConfig, class int, denierFirst bool) bool {
	var denier *ebpf.Map
	if denierFirst {
		denier, _ = sharedTaskAllocDenier(t)
	}
	f := sharedFCStart(t, cfg, "taskalloc", class, nil)
	if !denierFirst {
		denier, _ = sharedTaskAllocDenier(t)
	}
	cgroup := f.helper.ino
	route := f.slot(cgroup)
	parkBefore, err := f.node.BirthParkHealth()
	if err != nil {
		t.Fatalf("object has no birth park: %v", err)
	}
	witnessBefore := sharedM4ReadWitness(t, f.gc)
	f.requireHealth("before the denied fork", SharedFailClosedHealthy)

	// The denied fork.
	sharedTaskAllocDenierSet(t, denier, cgroup)
	exits := f.helper.round(t, "FORKN:%d:0\n", 1)
	denials := sharedTaskAllocDenierSet(t, denier, 0)
	if len(exits) != 1 || exits[0].pid != -1 || exits[0].code != int(unix.EPERM) {
		t.Fatalf("denied fork: %+v, want FORKED:-1:%d (EPERM)", exits, unix.EPERM)
	}
	if denials != 1 {
		t.Fatalf("the denier counted %d denials, want 1", denials)
	}
	f.settle("denied fork")
	park := sharedTaskAllocParkSettled(t, f, parkBefore)
	sharedTaskAllocNoClaim(t, f, route)
	sharedTaskAllocNoFault(t, f, witnessBefore, "denied fork")
	witnessDenied := sharedM4ReadWitness(t, f.gc)
	births := witnessDenied.attempts[0] - witnessBefore.attempts[0]
	sourceRan := births != 0
	t.Logf("class %d denier first %v: denied fork: birth attempts +%d, birth park delta %+v", class, denierFirst, births, park)
	switch {
	case births > 1:
		t.Fatalf("denied fork: %d birth attempts, want at most 1", births)
	case sourceRan && (park.Parked != 1 || park.Taken != 1):
		t.Fatalf("product source ran but the target did not take its park (delta %+v): no constructed child to clean up", park)
	case !sourceRan && park.Parked != 0:
		t.Fatalf("birth park %+v without a counted birth attempt", park)
	}
	f.requireHealth("after the denied fork", SharedFailClosedHealthy)

	// The next fork of the same parent succeeds and settles.
	exits = f.helper.round(t, "FORKN:%d:0\n", 1)
	if len(exits) != 1 || exits[0].pid <= 0 || exits[0].code != 0 {
		t.Fatalf("next fork: %+v, want a child that execs and exits 0", exits)
	}
	f.settle("next fork")
	sharedTaskAllocParkSettled(t, f, parkBefore)
	sharedTaskAllocNoClaim(t, f, route)
	sharedTaskAllocNoFault(t, f, witnessBefore, "next fork")
	f.requireHealth("after the next fork", SharedFailClosedHealthy)
	t.Logf("class %d denier first %v: denied fork EPERM, TASK/WORK %d/%d at baseline, next fork ok", class, denierFirst, f.tasks, f.works)
	return sourceRan
}

// slot returns the route slot of the binding of cgroup.
func (f *sharedFCEnv) slot(cgroup uint64) uint32 {
	f.t.Helper()
	f.node.mu.Lock()
	s := f.node.bindings[cgroup]
	f.node.mu.Unlock()
	if s == nil {
		f.t.Fatalf("cgroup %d is not bound", cgroup)
	}
	return s.Inspect().RouteSlot
}

// sharedTaskAllocParkSettled waits until every park since before is taken or
// abandoned, with none stale, latched, put-failed or take-failed.
func sharedTaskAllocParkSettled(t *testing.T, f *sharedFCEnv, before SharedBirthParkHealth) SharedBirthParkHealth {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		now, err := f.node.BirthParkHealth()
		if err != nil {
			t.Fatal(err)
		}
		d := SharedBirthParkHealth{
			Parked: now.Parked - before.Parked, Taken: now.Taken - before.Taken, Abandoned: now.Abandoned - before.Abandoned,
			Stale: now.Stale - before.Stale, PutFailed: now.PutFailed - before.PutFailed, Latched: now.Latched - before.Latched,
			TakeFailed: now.TakeFailed - before.TakeFailed, CrossGeneration: now.CrossGeneration - before.CrossGeneration,
		}
		if d.Stale != 0 || d.PutFailed != 0 || d.Latched != 0 || d.TakeFailed != 0 {
			t.Fatalf("birth park %+v: a park went stale, latched or failed", d)
		}
		if d.Parked == d.Taken+d.Abandoned {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("birth park %+v: a parked claim was never taken or abandoned", d)
		}
	}
}

// sharedTaskAllocNoClaim requires the route to hold no early claim.
func sharedTaskAllocNoClaim(t *testing.T, f *sharedFCEnv, slot uint32) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		r := f.anchor(slot)
		claims := r.EarlyClaims + r.Rec[0].EarlyClaims + r.Rec[1].EarlyClaims
		if claims == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("route %d holds %d early claim(s) after the fork settled: %+v", slot, claims, r)
		}
	}
}

// sharedTaskAllocNoFault requires no fail-closed rate to have counted.
func sharedTaskAllocNoFault(t *testing.T, f *sharedFCEnv, before sharedM4Witness, label string) {
	t.Helper()
	after := sharedM4ReadWitness(t, f.gc)
	for i := range after.rates {
		if after.rates[i] != before.rates[i] {
			t.Fatalf("%s: fail-closed rate [%d] +%d, want no fault", label, i, after.rates[i]-before.rates[i])
		}
	}
	f.accounts() // fails on a faulted TASK or WORK account
}
