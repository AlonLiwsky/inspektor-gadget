// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// TestSharedNodeBirthParkAttached (G019 gaps 1 and 2, VM only): births
// straddling revisions of their own binding, under Strict (A) and Audit (B).
// Each binding runs STREAMS concurrent fork+exec loops in its adopted init
// while its policy is revised every 50 ms (same UID, root role and verdicts);
// with the per-record holders (G019 gap 3) at least half of the revisions
// must commit without a retryable refusal (the distribution is logged).
// With the birth park every child is constructed under its source's claim
// (the parked early claim holds its record, ACTIVE -> RETIRING, blocking
// only the withdrawal and reuse of that record until the target took it)
// and a child born before a revision qualifies under the later generation,
// so the run must count:
//   - parked == taken + abandoned, no stale, failed take or latched park
//     (BirthParkHealth), and at least one parked birth;
//   - no CONSTRUCT [5] and no QUALIFY [6] fail-closed refusal;
//   - every churn exec allowed (root is allowed by both policies) unless
//     KILL=1, which SIGKILLs forking parents and children mid-straddle;
//   - quiesce: no leaked park (a final revision commits at once, Ready
//     carries no birth-park fault).
//
// Environment: IG_SHARED_BIRTH_PARK_OBJECT (a product object, or with
// SPIN=1 the birth-park spin twin g19pkgparkf128: the product object at
// q(128,32) plus -DSE_PRODUCT_DIAGNOSTIC_TWIN=1, the publication fault
// injector and ENFORCE_EXEC_POOL_OPAQUE_BIRTH_PARK_SPIN_DIAGNOSTIC, so the
// product publisher binds and publishes on it; its widened straddle
// window keeps parked claims held across commits),
// IG_SHARED_BIRTH_PARK_CGROUP_A/_B (dedicated ig15-g019-park-* cgroups),
// IG_SHARED_BIRTH_PARK_STREAMS (3 or 8, default 3),
// IG_SHARED_BIRTH_PARK_SECONDS (default 10), IG_SHARED_BIRTH_PARK_KILL=1,
// IG_SHARED_BIRTH_PARK_SPIN=1.
func TestSharedNodeBirthParkAttached(t *testing.T) {
	object := os.Getenv("IG_SHARED_BIRTH_PARK_OBJECT")
	if object == "" {
		t.Skip("set IG_SHARED_BIRTH_PARK_OBJECT on an isolated exact-kernel VM")
	}
	cgroupA, cgroupB := os.Getenv("IG_SHARED_BIRTH_PARK_CGROUP_A"), os.Getenv("IG_SHARED_BIRTH_PARK_CGROUP_B")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(cgroupA), "ig15-g019-park-") || !strings.HasPrefix(filepath.Base(cgroupB), "ig15-g019-park-") || cgroupA == cgroupB {
		t.Fatal("root and two dedicated ig15-g019-park-* cgroups required")
	}
	streams := 3
	if raw := os.Getenv("IG_SHARED_BIRTH_PARK_STREAMS"); raw != "" {
		var err error
		if streams, err = strconv.Atoi(raw); err != nil || (streams != 3 && streams != 8) {
			t.Fatalf("invalid IG_SHARED_BIRTH_PARK_STREAMS %q (3 or 8)", raw)
		}
	}
	duration := 10 * time.Second
	if raw := os.Getenv("IG_SHARED_BIRTH_PARK_SECONDS"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds < 1 || seconds > 600 {
			t.Fatalf("invalid IG_SHARED_BIRTH_PARK_SECONDS %q", raw)
		}
		duration = time.Duration(seconds) * time.Second
	}
	kill, spin := os.Getenv("IG_SHARED_BIRTH_PARK_KILL") == "1", os.Getenv("IG_SHARED_BIRTH_PARK_SPIN") == "1"
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	if spin {
		spec, err := ebpf.LoadCollectionSpec(object)
		if err != nil {
			t.Fatal(err)
		}
		_, admin := spec.Maps["se_admin"]
		_, twin := spec.Maps["opaque_real_publish_fault"]
		if !admin || !twin {
			t.Fatalf("SPIN=1 needs the product diagnostic twin (se_admin %v, opaque_real_publish_fault %v): g19pkgparkf128", admin, twin)
		}
	}
	node, gc, ctx := startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
	if _, err := node.BirthParkHealth(); err != nil {
		t.Fatalf("object %s has no birth park: %v", object, err)
	}
	ia, ib := startSharedPipeInit(t, cgroupA, "ig15-g019-park-init-a"), startSharedPipeInit(t, cgroupB, "ig15-g019-park-init-b")
	type binding struct {
		name    string
		init    *sharedPipeInit
		session *BindingSession
		mode    fullpolicy.Mode
	}
	bindings := []*binding{{name: "A", init: ia, mode: fullpolicy.Enforce}, {name: "B", init: ib, mode: fullpolicy.Audit}}
	policy := func(b *binding, revision int) SharedBindingPolicy {
		return SharedBindingPolicy{Source: sharedM4Policy("park-"+b.name, strconv.Itoa(revision), b.mode, fullpolicy.Deny), Container: strings.ToLower(b.name)}
	}
	for _, b := range bindings {
		s, err := node.Bind(ctx, SharedBindingConfig{CgroupID: b.init.ino, InitHostPID: uint32(b.init.cmd.Process.Pid), Acquire: b.init.acquire})
		if err != nil {
			t.Fatalf("Bind %s: %v", b.name, err)
		}
		b.session = s
		if _, err := s.Publish(ctx, policy(b, 1)); err != nil {
			t.Fatalf("publish %s (adoption): %v", b.name, err)
		}
	}
	parkBefore, err := node.BirthParkHealth()
	if err != nil {
		t.Fatal(err)
	}
	witnessBefore := sharedM4ReadWitness(t, gc)

	// Churn: STREAMS concurrent fork+exec loops per binding; with KILL,
	// each round also SIGKILLs a forking subshell and a child mid-flight.
	line := fmt.Sprintf("for s in $(seq %d); do (for i in $(seq 20); do /bin/true; done) & done; wait", streams)
	if kill {
		line = fmt.Sprintf("for s in $(seq %d); do (for i in $(seq 20); do /bin/true; done) & done; "+
			"(for i in $(seq 50); do /bin/true & done; wait) & p=$!; /bin/sleep 0.00$((RANDOM %% 9 + 1)); kill -9 $p; "+
			"/bin/sleep 5 & kill -9 $!; wait", streams)
	}
	runCtx, stop := context.WithTimeout(ctx, duration)
	defer stop()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var bad []string
	rounds, revisions, retried := map[string]int{}, map[string]int{}, map[string]int{}
	// G019 gap 3: retryable refusals per committed revision (the
	// distribution; with per-record holders the common case is none).
	perRevision := map[int]int{}
	for _, b := range bindings {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for runCtx.Err() == nil {
				out, code, err := b.init.run(runCtx, line)
				if runCtx.Err() != nil {
					return
				}
				mu.Lock()
				rounds[b.name]++
				if !kill && (err != nil || code != 0) {
					bad = append(bad, fmt.Sprintf("%s: %q %d %v", b.name, out, code, err))
				}
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for revision := 2; ; revision++ {
				select {
				case <-runCtx.Done():
					return
				case <-ticker.C:
				}
				for attempt := 0; runCtx.Err() == nil; attempt++ {
					_, err := b.session.Publish(ctx, policy(b, revision))
					mu.Lock()
					switch {
					case err == nil:
						revisions[b.name]++
						perRevision[attempt]++
					case strings.Contains(err.Error(), "retryable") && attempt < 200:
						retried[b.name]++
					default:
						bad = append(bad, fmt.Sprintf("%s revision %d: %v", b.name, revision, err))
					}
					mu.Unlock()
					if err == nil || !strings.Contains(err.Error(), "retryable") || attempt >= 200 {
						break
					}
					time.Sleep(2 * time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	t.Logf("birth park: streams=%d kill=%v spin=%v rounds %v revisions %v retryable refusals %v; retryable refusals per committed revision %v", streams, kill, spin, rounds, revisions, retried, perRevision)
	if len(bad) != 0 {
		t.Fatalf("churn/revision failures: %v", bad)
	}
	for _, b := range bindings {
		if rounds[b.name] == 0 || revisions[b.name] < 2 {
			t.Fatalf("%s: %d churn rounds, %d revisions: the straddle was not exercised", b.name, rounds[b.name], revisions[b.name])
		}
	}
	// G019 gap 3: a held record (a parked birth claim, a reader, a pin)
	// no longer blocks the commit, so most revisions commit at their first
	// attempt, the SPIN twin's widened straddle included (before gap 3 it
	// measured ~1.7 retryable refusals per revision).
	if committed := revisions["A"] + revisions["B"]; 2*perRevision[0] < committed {
		t.Fatalf("only %d of %d revisions committed without a retryable refusal (distribution %v)", perRevision[0], committed, perRevision)
	}

	// Quiesce: every park settled, then the witnesses.
	var park SharedBirthParkHealth
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		now, err := node.BirthParkHealth()
		park = SharedBirthParkHealth{
			Parked: now.Parked - parkBefore.Parked, Taken: now.Taken - parkBefore.Taken, Abandoned: now.Abandoned - parkBefore.Abandoned,
			Stale: now.Stale - parkBefore.Stale, PutFailed: now.PutFailed - parkBefore.PutFailed, Latched: now.Latched - parkBefore.Latched,
			TakeFailed: now.TakeFailed - parkBefore.TakeFailed, CrossGeneration: now.CrossGeneration - parkBefore.CrossGeneration,
		}
		if err == nil && park.Parked == park.Taken+park.Abandoned+park.Stale+park.Latched {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("birth parks not settled: %+v (%v)", park, err)
		}
	}
	t.Logf("birth park witness: %+v", park)
	if park.Parked == 0 || park.Stale != 0 || park.TakeFailed != 0 || park.Latched != 0 || park.PutFailed != 0 {
		t.Fatalf("birth park witness %+v: want parked births, every one taken or abandoned, none stale, failed or latched", park)
	}
	witnessAfter := sharedM4ReadWitness(t, gc)
	const construct = 5 // REAL_OWNER_RATE_CONSTRUCT
	if d := witnessAfter.rates[construct] - witnessBefore.rates[construct]; d != 0 {
		t.Fatalf("CONSTRUCT [5] +%d: a birth straddled a revision unconstructed", d)
	}
	if d := witnessAfter.rates[FailClosedRateQualify] - witnessBefore.rates[FailClosedRateQualify]; d != 0 {
		t.Fatalf("QUALIFY [6] +%d: a cross-generation first exec faulted", d)
	}
	// No leaked park: a quiet revision commits at once.
	for _, b := range bindings {
		if _, err := b.session.Publish(ctx, policy(b, 1000)); err != nil {
			t.Fatalf("%s quiet revision after the churn: %v (a leaked parked claim blocks commits)", b.name, err)
		}
	}
	if err := node.Ready(gc); !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(err.Error(), "birth-park") {
		t.Fatalf("Ready after the churn: %v", err)
	}
}
