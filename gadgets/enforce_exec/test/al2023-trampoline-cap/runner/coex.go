// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

// G009 retry, coexistence and hold modes. Synthetic no-op fillers only.
// Test only; not product enforcement or Ready.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"slices"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

// waitGone polls until none of the fillers' link IDs remains.
func (fl *fillers) waitGone() error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		ids, err := linkIDs()
		if err != nil {
			return err
		}
		left := slices.DeleteFunc(ids, func(id uint32) bool { _, ok := fl.ids[id]; return !ok })
		if len(left) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("leftover filler links: %v", left)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// retryCase pre-fills target so the hint refuses, starts the family through
// nativeattach.Retry and frees the fillers after freeAfter (never when
// freeAfter is 0; the context is then canceled after cancelAfter). Every
// NotReady state must name target with none of our links present.
func retryCase(f *family, filler *ebpf.CollectionSpec, kernel *btf.Spec, target string, reserve int, freeAfter, cancelAfter time.Duration) (string, error) {
	fl, err := fill(filler, kernel, target, f.need[target]+reserve-1)
	if err != nil {
		return "", err
	}
	nFillers := len(fl.links)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	freed := make(chan struct{}, 1)
	start := time.Now()
	go func() {
		if freeAfter == 0 {
			time.Sleep(cancelAfter)
			cancel()
			freed <- struct{}{}
			return
		}
		time.Sleep(freeAfter)
		fl.close()
		freed <- struct{}{}
	}()
	notReady, ready := 0, 0
	var stateErr error
	var links []link.Link
	var expected []nativeattach.Expected
	err = nativeattach.Retry{
		Initial: 200 * time.Millisecond, Max: 2 * time.Second,
		State: func(err error) {
			if err == nil {
				ready++
				return
			}
			notReady++
			if e := expectCapacity(err, target); e != nil {
				stateErr = errors.Join(stateErr, e)
			}
			if left, e := f.ours(); e != nil || len(left) != 0 {
				stateErr = errors.Join(stateErr, fmt.Errorf("partial hook set while NotReady: %v", left), e)
			}
		},
	}.Run(ctx, func() error {
		var err error
		links, expected, err = f.start(reserve, true)
		return err
	})
	<-freed
	elapsed := time.Since(start)
	if freeAfter == 0 {
		// Cancel case: refused, no link of ours, fillers untouched.
		defer fl.close()
		if err == nil {
			nativeattach.Rollback(links, func(l link.Link) { _ = l.Close() })
			return "", fmt.Errorf("canceled retry attached")
		}
		if !errors.Is(err, context.Canceled) || expectCapacity(err, target) != nil {
			return "", fmt.Errorf("canceled retry: want context.Canceled and ErrAttachCapacity, got %w", err)
		}
		if err := errors.Join(stateErr, f.waitNoneOurs(), fl.unchanged()); err != nil {
			return "", err
		}
		if notReady == 0 || ready != 0 {
			return "", fmt.Errorf("states notready=%d ready=%d", notReady, ready)
		}
		return fmt.Sprintf("case=cancel fillers=%d notready=%d ready=0 elapsed=%s err=%q", nFillers, notReady, elapsed.Round(time.Millisecond), err.Error()), nil
	}
	if err != nil {
		return "", fmt.Errorf("retry did not attach: %w", err)
	}
	present := nativeattach.CheckPresent(expected, nativeattach.LookupLink)
	nativeattach.Rollback(links, func(l link.Link) { _ = l.Close() })
	if err := errors.Join(stateErr, present, f.waitNoneOurs(), fl.waitGone()); err != nil {
		return "", err
	}
	if notReady == 0 || ready != 1 || len(links) != len(candidateAttachSet) {
		return "", fmt.Errorf("states notready=%d ready=%d links=%d", notReady, ready, len(links))
	}
	return fmt.Sprintf("case=freed fillers=%d freed_after=%s notready=%d ready=1 attached=%d elapsed=%s",
		nFillers, freeAfter, notReady, len(links), elapsed.Round(time.Millisecond)), nil
}

func liveRetry(filler *ebpf.CollectionSpec, candidate, target string, reserve int, freeAfter time.Duration) error {
	release, kernel, f, err := liveFamily(candidate, reserve)
	if err != nil {
		return err
	}
	defer f.coll.Close()
	if f.need[target] == 0 {
		return fmt.Errorf("candidate attaches nothing on %s", target)
	}
	detail, err := retryCase(f, filler, kernel, target, reserve, freeAfter, 0)
	if err != nil {
		return fmt.Errorf("retry case: %w", err)
	}
	fmt.Printf("RETRY kernel=%s target=%s %s leftover=0\n", release, target, detail)
	detail, err = retryCase(f, filler, kernel, target, reserve, 0, 2*time.Second)
	if err != nil {
		return fmt.Errorf("cancel case: %w", err)
	}
	fmt.Printf("RETRY kernel=%s target=%s %s leftover=0 fillers_unchanged=true\n", release, target, detail)
	fmt.Println("PASS: automatic retry; NOT product enforcement or Ready")
	return nil
}

func liveFamily(candidate string, reserve int) (string, *btf.Spec, *family, error) {
	release, err := kernelCheck()
	if err != nil {
		return "", nil, nil, err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return "", nil, nil, err
	}
	f, err := loadFamily(candidate, kernel, candidateAttachSet)
	if err != nil {
		return "", nil, nil, err
	}
	fmt.Printf("kernel %s candidate links per hook (K): %v reserve=%d\n", release, f.need, reserve)
	return release, kernel, f, nil
}

// coexFillers is F for one hook: 0, 10, 20, then the reserve boundary
// (cap - R - K - preexisting, the last F at which the family attaches) and
// one past it.
func coexFillers(k, reserve, preexisting int) []int {
	boundary := nativeattach.TrampolineLinkCap - reserve - k - preexisting
	var out []int
	for _, n := range []int{0, 10, 20, boundary, boundary + 1} {
		if n >= 0 && preexisting+n <= nativeattach.TrampolineLinkCap && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

func liveCoex(filler *ebpf.CollectionSpec, candidate string, reserve int) error {
	release, kernel, f, err := liveFamily(candidate, reserve)
	if err != nil {
		return err
	}
	defer f.coll.Close()
	failed := 0
	for _, target := range slices.Sorted(maps.Keys(f.need)) {
		k := f.need[target]
		existing, err := nativeattach.CountLinks([]string{target})
		if err != nil {
			return err
		}
		pre := existing[target]
		for _, n := range coexFillers(k, reserve, pre) {
			want := "attach"
			if pre+n+k+reserve > nativeattach.TrampolineLinkCap {
				want = "refuse"
			}
			got, detail, err := coexCase(f, filler, kernel, target, n, pre, reserve)
			if err != nil {
				failed++
				fmt.Printf("FAIL COEX target=%s F=%d: %v\n", target, n, err)
				continue
			}
			if got != want {
				failed++
			}
			fmt.Printf("COEX kernel=%s target=%s K=%d R=%d F=%d preexisting=%d expected=%s result=%s %s leftover=0 fillers_unchanged=true\n",
				release, target, k, reserve, n, pre, want, got, detail)
		}
	}
	if failed != 0 {
		return fmt.Errorf("%d coexistence case(s) failed", failed)
	}
	fmt.Println("PASS: coexistence matrix with no-op fillers; NOT product enforcement or Ready")
	return nil
}

func coexCase(f *family, filler *ebpf.CollectionSpec, kernel *btf.Spec, target string, n, pre, reserve int) (string, string, error) {
	fl, err := fill(filler, kernel, target, nativeattach.TrampolineLinkCap-pre-n)
	if err != nil {
		return "", "", err
	}
	defer fl.close()
	if len(fl.links) != n {
		return "", "", fmt.Errorf("attached %d fillers, want %d", len(fl.links), n)
	}
	links, expected, err := f.start(reserve, true)
	got, detail := "attach", fmt.Sprintf("attached=%d", len(links))
	if err == nil {
		err = nativeattach.CheckPresent(expected, nativeattach.LookupLink)
		nativeattach.Rollback(links, func(l link.Link) { _ = l.Close() })
		if err != nil {
			return "", "", err
		}
	} else {
		if e := expectCapacity(err, target); e != nil {
			return "", "", e
		}
		got, detail = "refuse", fmt.Sprintf("err=%q", err.Error())
	}
	if err := errors.Join(f.waitNoneOurs(), fl.unchanged()); err != nil {
		return "", "", err
	}
	fl.close()
	return got, detail, fl.waitGone()
}

// liveHold pre-attaches, on every hook of the candidate's attach set, the
// largest F at which the family still attaches with reserve R, and holds
// them until SIGTERM/SIGINT or timeout. It is the filler pre-step of the
// functional smoke (the attached verdict test runs meanwhile). On release
// every filler must still be on its program and then disappear.
func liveHold(filler *ebpf.CollectionSpec, candidate string, reserve int, timeout time.Duration) error {
	release, err := kernelCheck()
	if err != nil {
		return err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpec(candidate)
	if err != nil {
		return err
	}
	need := map[string]int{}
	for _, name := range candidateAttachSet {
		p := spec.Programs[name]
		if p == nil {
			return fmt.Errorf("candidate lacks %s", name)
		}
		need[nativeattach.TrampolineTarget(p)]++
	}
	var held []*fillers
	defer func() {
		for _, fl := range held {
			fl.close()
		}
	}()
	for _, target := range slices.Sorted(maps.Keys(need)) {
		existing, err := nativeattach.CountLinks([]string{target})
		if err != nil {
			return err
		}
		n := nativeattach.TrampolineLinkCap - reserve - need[target] - existing[target]
		fl, err := fill(filler, kernel, target, nativeattach.TrampolineLinkCap-existing[target]-n)
		if err != nil {
			return err
		}
		held = append(held, fl)
		fmt.Printf("HOLD kernel=%s target=%s K=%d R=%d F=%d preexisting=%d\n", release, target, need[target], reserve, len(fl.links), existing[target])
	}
	fmt.Println("HOLDING")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, unix.SIGTERM, unix.SIGINT)
	select {
	case s := <-sig:
		fmt.Printf("HOLD release on %s\n", s)
	case <-time.After(timeout):
		fmt.Println("HOLD release on timeout")
	}
	for _, fl := range held {
		if err := fl.unchanged(); err != nil {
			return fmt.Errorf("filler changed while held: %w", err)
		}
	}
	for _, fl := range held {
		fl.close()
		if err := fl.waitGone(); err != nil {
			return err
		}
	}
	held = nil
	fmt.Printf("HOLD kernel=%s released leftover=0 fillers_unchanged=true\n", release)
	fmt.Println("PASS: fillers held and released; NOT product enforcement or Ready")
	return nil
}
