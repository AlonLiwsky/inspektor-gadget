// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package nativeattach

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func lsm(hook string) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: hook}
}

func tracing(fn string, at ebpf.AttachType) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{Type: ebpf.Tracing, AttachType: at, AttachTo: fn}
}

func TestOrderLifecycleMovementDecision(t *testing.T) {
	programs := map[string]*ebpf.ProgramSpec{
		"a_check":     lsm("bprm_check_security"),
		"b_begin":     tracing("security_bprm_creds_for_exec", ebpf.AttachTraceFEntry),
		"c_entry":     tracing("bprm_execve", ebpf.AttachTraceFEntry),
		"d_terminal":  tracing("bprm_execve", ebpf.AttachTraceFExit),
		"e_migrate":   tracing("cgroup_migrate", ebpf.AttachTraceFEntry),
		"f_newtask":   tracing("task_newtask", ebpf.AttachTraceRawTp),
		"g_alloc":     lsm("task_alloc"),
		"h_free":      lsm("task_free"),
		"i_alloc":     lsm("task_alloc"),
		"j_command":   {Type: ebpf.Syscall},
		"k_publisher": lsm("task_prctl"),
		"l_exit":      tracing("sched_process_exit", ebpf.AttachTraceRawTp),
		"m_exec":      tracing("sched_process_exec", ebpf.AttachTraceRawTp),
	}
	want := []string{"h_free", "l_exit", "g_alloc", "i_alloc", "e_migrate", "f_newtask", "j_command", "k_publisher", "m_exec", "d_terminal", "c_entry", "b_begin", "a_check"}
	for range 20 { // map order is random; the result must not be
		if got := Order(programs); !reflect.DeepEqual(got, want) {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

type fakeLink struct {
	link.Link
	id     int
	closed *[]int
}

func (l *fakeLink) Close() error { *l.closed = append(*l.closed, l.id); return nil }

func TestAttachRollbackAtEveryPosition(t *testing.T) {
	const n = 5
	for fail := 0; fail < n; fail++ {
		for _, cause := range []error{unix.E2BIG, unix.EBUSY} {
			t.Run(fmt.Sprintf("fail=%d/%v", fail, cause), func(t *testing.T) {
				var closed []int
				steps := make([]Step, n)
				for k := range steps {
					steps[k] = Step{Name: fmt.Sprint("p", k), Target: fmt.Sprint("t", k)}
				}
				links, err := Attach(steps, func(k int) (link.Link, error) {
					if k == fail {
						return nil, fmt.Errorf("attach: %w", cause)
					}
					if k == 1 {
						return nil, nil // a step that attaches nothing
					}
					return &fakeLink{id: k, closed: &closed}, nil
				}, func(l link.Link) { _ = l.Close() })
				if links != nil || err == nil {
					t.Fatal("failed transaction returned links")
				}
				var want []int
				attached := 0
				for k := fail - 1; k >= 0; k-- {
					if k != 1 {
						want = append(want, k)
						attached++
					}
				}
				if !reflect.DeepEqual(closed, want) {
					t.Fatalf("closed %v, want reverse %v", closed, want)
				}
				var capErr *ErrAttachCapacity
				if isCap := errors.As(err, &capErr); isCap != errors.Is(cause, unix.E2BIG) {
					t.Fatalf("typed capacity error %v for %v", err, cause)
				}
				if !errors.Is(err, cause) {
					t.Fatalf("%v does not wrap %v", err, cause)
				}
				if capErr != nil && (capErr.Target != steps[fail].Target || capErr.Attached != attached) {
					t.Fatalf("capacity error %+v, want target %s attached %d", capErr, steps[fail].Target, attached)
				}
			})
		}
	}
	var closed []int
	links, err := Attach([]Step{{Name: "a"}, {Name: "b"}}, func(k int) (link.Link, error) {
		return &fakeLink{id: k, closed: &closed}, nil
	}, func(l link.Link) { _ = l.Close() })
	if err != nil || len(links) != 2 || len(closed) != 0 {
		t.Fatal("successful transaction closed links")
	}
}

func TestCheckCapacityMath(t *testing.T) {
	const target = "bpf_lsm_bprm_check_security"
	need := map[string]int{target: 3, "bprm_execve": 3}
	for _, tc := range []struct {
		existing, reserve int
		ok                bool
	}{
		{0, DefaultReservePerHook, true},
		{TrampolineLinkCap - 3 - DefaultReservePerHook, DefaultReservePerHook, true},      // exactly need+R free
		{TrampolineLinkCap - 3 - DefaultReservePerHook + 1, DefaultReservePerHook, false}, // one short
		{TrampolineLinkCap - 3, 0, true},
		{TrampolineLinkCap - 2, 0, false},
		{TrampolineLinkCap + 5, 0, false}, // overfull never reads as free
	} {
		err := CheckCapacity(need, map[string]int{target: tc.existing}, tc.reserve)
		if (err == nil) != tc.ok {
			t.Fatalf("existing=%d reserve=%d: %v", tc.existing, tc.reserve, err)
		}
		var capErr *ErrAttachCapacity
		if err != nil && (!errors.As(err, &capErr) || capErr.Target != target || capErr.Attached != 0 || !errors.Is(err, unix.E2BIG)) {
			t.Fatalf("untyped or wrong refusal: %v", err)
		}
	}
	var capErr *ErrAttachCapacity
	if err := CheckCapacity(map[string]int{"x": MaxFamilyLinksPerHook + 1}, nil, 0); !errors.As(err, &capErr) || capErr.Target != "x" {
		t.Fatalf("family above K accepted: %v", err)
	}
	if err := CheckCapacity(map[string]int{"x": MaxFamilyLinksPerHook}, nil, DefaultReservePerHook); err != nil {
		t.Fatal(err)
	}
	for _, reserve := range []int{-1, TrampolineLinkCap - MaxFamilyLinksPerHook + 1} {
		if CheckCapacity(nil, nil, reserve) == nil {
			t.Fatalf("invalid reserve %d accepted", reserve)
		}
	}
}

func TestCheckPresentNamesTarget(t *testing.T) {
	expected := []Expected{{"a", "task_free", 10, 100}, {"b", "bprm_check_security", 11, 101}}
	live := map[uint32]uint32{10: 100, 11: 101}
	lookup := func(id uint32) (uint32, error) {
		p, ok := live[id]
		if !ok {
			return 0, unix.ENOENT
		}
		return p, nil
	}
	if err := CheckPresent(expected, lookup); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(){
		"missing":  func() { delete(live, 11) },
		"replaced": func() { live[11] = 999 },
	} {
		live = map[uint32]uint32{10: 100, 11: 101}
		mutate()
		var notReady *ErrNotReady
		if err := CheckPresent(expected, lookup); !errors.As(err, &notReady) || notReady.Target != "bprm_check_security" || notReady.Name != "b" {
			t.Fatalf("%s: stale Ready or unnamed target: %v", name, err)
		}
	}
}
