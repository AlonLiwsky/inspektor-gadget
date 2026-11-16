// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sharedFakeCommander scripts the product commands and records the calls.
type sharedFakeCommander struct {
	mu                       sync.Mutex
	calls                    []string
	publish, verifyCode      uint32
	finishCode               uint32
	finishDetail             sharedFinishDetail
	taskCodes                map[uint32]uint32
	quarantineMisses         int // incomplete quarantine runs before a complete one
	withdrawCodes            []uint32
	recycleCodes             []uint32
	reviseCode, withdrawCode uint32
	routeState               SharedRouteState
	routeAdopting            bool
	verifyExited             bool
	publishErr               error
}

func (f *sharedFakeCommander) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *sharedFakeCommander) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *sharedFakeCommander) publishFirst(_ context.Context, _ uint32, _ uint64, _ SharedBindingPolicy, _ SharedInitIdentity) (uint32, error) {
	f.record("publish")
	return f.publish, f.publishErr
}

func (f *sharedFakeCommander) revise(context.Context, uint32, uint64, SharedBindingPolicy) (uint32, error) {
	f.record("revise")
	return f.reviseCode, nil
}

func (f *sharedFakeCommander) verify(context.Context, uint32, uint64, SharedInitIdentity) (uint32, bool, error) {
	f.record("verify")
	return f.verifyCode, f.verifyExited, nil
}

func (f *sharedFakeCommander) adoptTask(_ context.Context, _ uint32, _ uint64, tid uint32, _ SharedInitIdentity) (uint32, error) {
	f.record("task:" + string(rune('0'+tid)))
	return f.taskCodes[tid], nil
}

func (f *sharedFakeCommander) finish(context.Context, uint32, uint64) (uint32, sharedFinishDetail, error) {
	f.record("finish")
	return f.finishCode, f.finishDetail, nil
}

func (f *sharedFakeCommander) quarantine(context.Context, uint32, uint64) (sharedQuarantineResult, error) {
	f.record("quarantine")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.quarantineMisses == 0 {
		return sharedQuarantineResult{Complete: true, Quarantined: 2}, nil
	}
	f.quarantineMisses--
	return sharedQuarantineResult{Quarantined: 1, Missed: 1}, nil
}

func (f *sharedFakeCommander) pop(codes *[]uint32) uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(*codes) == 0 {
		return sharedProductOK
	}
	code := (*codes)[0]
	*codes = (*codes)[1:]
	return code
}

func (f *sharedFakeCommander) withdraw(context.Context, uint32, uint64) (uint32, error) {
	f.record("withdraw")
	if f.withdrawCodes == nil {
		return f.withdrawCode, nil
	}
	return f.pop(&f.withdrawCodes), nil
}

func (f *sharedFakeCommander) recycle(context.Context, uint32) (uint32, error) {
	f.record("recycle")
	return f.pop(&f.recycleCodes), nil
}

func (f *sharedFakeCommander) route(uint32) (SharedRouteState, error) {
	return f.routeState, nil
}

func (f *sharedFakeCommander) adopting(uint32) (bool, uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.routeAdopting, f.routeState.Class, nil
}

// sharedFakeThreads is a controllable cgroup.threads listing.
type sharedFakeThreads struct {
	mu   sync.Mutex
	tids []uint32
	gone bool
}

func (t *sharedFakeThreads) list(uint32) ([]uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.gone {
		return nil, errCgroupGone
	}
	return append([]uint32(nil), t.tids...), nil
}

func (t *sharedFakeThreads) set(tids []uint32, gone bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tids, t.gone = tids, gone
}

// newTestProductPublisher uses a fake clock: every sleep advances it.
func newTestProductPublisher(cmd *sharedFakeCommander, threads *sharedFakeThreads) (*productRoutePublisher, func() time.Duration) {
	p := newProductRoutePublisher(cmd, threads.list)
	var mu sync.Mutex
	elapsed := time.Duration(0)
	base := time.Unix(1000, 0)
	p.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return base.Add(elapsed) }
	p.sleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		mu.Lock()
		elapsed += d
		mu.Unlock()
		time.Sleep(time.Millisecond)
		return ctx.Err()
	}
	return p, func() time.Duration { mu.Lock(); defer mu.Unlock(); return elapsed }
}

var sharedTestInit = SharedInitIdentity{TGID: 7, StartTicks: 4242, MountNS: 4026531999}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestProductPublisherAdoptsLeaderFirst(t *testing.T) {
	cmd := &sharedFakeCommander{taskCodes: map[uint32]uint32{5: sharedProductRetry}, routeState: SharedRouteState{Generation: 1, Class: 2}}
	threads := &sharedFakeThreads{tids: []uint32{5, 9, 7, 9}}
	p, _ := newTestProductPublisher(cmd, threads)
	defer p.Close()
	state, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, true, sharedTestInit)
	if err != nil || state != cmd.routeState {
		t.Fatalf("publish: %+v %v", state, err)
	}
	// Leader 7 first, duplicates dropped; the vanished tid 5 (code 1) is
	// left to finish's count rule.
	want := []string{"publish", "verify", "task:7", "task:5", "task:9", "finish"}
	if got := cmd.log(); !reflect.DeepEqual(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
	if _, reported := p.adoptionStatus(0); reported {
		t.Fatal("successful adoption reported a failure")
	}
}

func TestProductPublisherRefusalReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cmd    *sharedFakeCommander
		reason string
	}{
		{"identity", &sharedFakeCommander{verifyCode: sharedProductRefused}, AdoptionRefusedIdentity},
		{"exiting at verify", &sharedFakeCommander{verifyCode: sharedProductRefused, verifyExited: true}, AdoptionThreadExited},
		{"task refused", &sharedFakeCommander{taskCodes: map[uint32]uint32{9: sharedProductRefused}}, AdoptionRefusedTask},
		{"authentication", &sharedFakeCommander{taskCodes: map[uint32]uint32{7: sharedProductAuthFailed}}, AdoptionRefusedAuth},
		{"clone refused", &sharedFakeCommander{finishCode: sharedProductRefused, finishDetail: sharedFinishDetail{Iterated: 2, Adopted: 2, AdoptingFaults: 1}}, AdoptionCloneRefused},
		{"thread exited", &sharedFakeCommander{finishCode: sharedProductRefused, finishDetail: sharedFinishDetail{Iterated: 1, Adopted: 2}}, AdoptionThreadExited},
		{"exiting", &sharedFakeCommander{finishCode: sharedProductRefused, finishDetail: sharedFinishDetail{Iterated: 2, Adopted: 2, Exiting: true, Bad: 1, ExitingCount: 1}}, AdoptionThreadExited},
		{"task appeared", &sharedFakeCommander{finishCode: sharedProductRefused, finishDetail: sharedFinishDetail{Iterated: 3, Adopted: 2, Bad: 1}}, AdoptionRefusedFinish},
		{"exiting and another mismatch", &sharedFakeCommander{finishCode: sharedProductRefused, finishDetail: sharedFinishDetail{Iterated: 2, Adopted: 2, Exiting: true, Bad: 2, ExitingCount: 1}}, AdoptionRefusedFinish},
		{"exited and appeared", &sharedFakeCommander{finishCode: sharedProductRefused, finishDetail: sharedFinishDetail{Iterated: 2, Adopted: 2, Bad: 1}}, AdoptionRefusedFinish},
		{"finish other", &sharedFakeCommander{finishCode: sharedProductRefused, finishDetail: sharedFinishDetail{Iterated: 2, Adopted: 2}}, AdoptionRefusedFinish},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := tc.cmd
			cmd.quarantineMisses = 2
			threads := &sharedFakeThreads{tids: []uint32{7, 9}}
			p, _ := newTestProductPublisher(cmd, threads)
			_, err := p.Publish(t.Context(), 1, 12, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, true, sharedTestInit)
			threads.set(nil, true) // the failed container is torn down
			var refused *ErrSharedAdoptionRefused
			if !errors.As(err, &refused) || refused.Reason != tc.reason || refused.Slot != 1 || refused.Cgroup != 12 {
				t.Fatalf("refusal %v, want reason %s", err, tc.reason)
			}
			waitFor(t, "release", func() bool { _, reported := p.adoptionStatus(1); return !reported })
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			log := strings.Join(cmd.log(), ",")
			if strings.Count(log, "quarantine") != 3 || !strings.HasSuffix(log, "withdraw,recycle") {
				t.Fatalf("failure path %s", log)
			}
		})
	}
}

// TestProductPublisherStrictStaysLatchedUntilEmpty: a quarantined Strict
// route is never withdrawn while its cgroup has tasks, reports AdoptionStuck
// after 30 s, and is withdrawn and recycled (CONTENDED retried) once empty.
func TestProductPublisherStrictStaysLatchedUntilEmpty(t *testing.T) {
	cmd := &sharedFakeCommander{verifyCode: sharedProductRefused, recycleCodes: []uint32{sharedProductRetry, sharedProductOK}}
	threads := &sharedFakeThreads{tids: []uint32{7}}
	p, elapsed := newTestProductPublisher(cmd, threads)
	defer p.Close()
	if _, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, true, sharedTestInit); err == nil {
		t.Fatal("refused adoption published")
	}
	waitFor(t, "AdoptionStuck", func() bool { st, _ := p.adoptionStatus(0); return st.Stuck })
	if elapsed() < sharedProductStuckAfter {
		t.Fatalf("stuck after %s", elapsed())
	}
	st, _ := p.adoptionStatus(0)
	if st.Reason != AdoptionRefusedIdentity || st.Cgroup != 11 || st.InitTGID != 7 || !st.Quarantined {
		t.Fatalf("status %+v", st)
	}
	if strings.Contains(strings.Join(cmd.log(), ","), "withdraw") {
		t.Fatal("Strict route withdrawn while its cgroup has tasks")
	}
	threads.set(nil, false)
	waitFor(t, "release", func() bool { _, reported := p.adoptionStatus(0); return !reported })
	if log := strings.Join(cmd.log(), ","); !strings.HasSuffix(log, "withdraw,recycle,recycle") {
		t.Fatalf("release %s", log)
	}
}

// TestProductPublisherQuarantineIncompleteStaysLatched: a quarantine that
// still misses entries after the bounded retries is not "done": the slot is
// marked failed and reported (AdoptionQuarantineIncomplete with the counts),
// and its route is never withdrawn or recycled, not even once the cgroup is
// empty, in Strict or Audit.
func TestProductPublisherQuarantineIncompleteStaysLatched(t *testing.T) {
	for _, class := range []uint32{2, 1} {
		cmd := &sharedFakeCommander{verifyCode: sharedProductRefused, quarantineMisses: 1 << 20}
		threads := &sharedFakeThreads{tids: []uint32{7}}
		p, _ := newTestProductPublisher(cmd, threads)
		_, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: class, Fallback: 2, Rules: 1}, true, sharedTestInit)
		var refused *ErrSharedAdoptionRefused
		if !errors.As(err, &refused) || refused.Reason != AdoptionRefusedQuarantined ||
			!strings.Contains(err.Error(), "marked 1, missed 1") || !strings.Contains(err.Error(), AdoptionRefusedIdentity) {
			t.Fatalf("class %d: refusal %v", class, err)
		}
		st, reported := p.adoptionStatus(0)
		if !reported || !st.Failed || st.Quarantined || st.Reason != AdoptionRefusedQuarantined || st.Marked != 1 || st.Missed != 1 || st.InitTGID != 7 {
			t.Fatalf("class %d: status %+v %v", class, st, reported)
		}
		threads.set(nil, true) // even an emptied cgroup does not release it
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		log := strings.Join(cmd.log(), ",")
		if strings.Count(log, "quarantine") != sharedQuarantineAttempts || strings.Contains(log, "withdraw") || strings.Contains(log, "recycle") {
			t.Fatalf("class %d: failed slot path %s", class, log)
		}
		if _, reported := p.adoptionStatus(0); !reported {
			t.Fatalf("class %d: failed slot no longer reported", class)
		}
	}
}

// TestProductPublisherTeardownNeverWithdrawsLatched: Close during the Strict
// poll leaves the route latched (destroyed with the collection).
func TestProductPublisherTeardownNeverWithdrawsLatched(t *testing.T) {
	cmd := &sharedFakeCommander{finishCode: sharedProductRefused, finishDetail: sharedFinishDetail{AdoptingFaults: 1}}
	threads := &sharedFakeThreads{tids: []uint32{7}}
	p, _ := newTestProductPublisher(cmd, threads)
	if _, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, true, sharedTestInit); err == nil {
		t.Fatal("refused adoption published")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(cmd.log(), ","), "withdraw") {
		t.Fatal("latched Strict route withdrawn on teardown")
	}
	if st, reported := p.adoptionStatus(0); !reported || st.Reason != AdoptionCloneRefused {
		t.Fatalf("status %+v %v", st, reported)
	}
}

// TestProductPublisherAuditWithdrawsAtOnce: an Audit adoption failure
// withdraws without waiting for the cgroup to empty.
func TestProductPublisherAuditWithdrawsAtOnce(t *testing.T) {
	cmd := &sharedFakeCommander{verifyCode: sharedProductRefused}
	threads := &sharedFakeThreads{tids: []uint32{7, 8}}
	p, _ := newTestProductPublisher(cmd, threads)
	defer p.Close()
	if _, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}, true, sharedTestInit); err == nil {
		t.Fatal("refused adoption published")
	}
	waitFor(t, "Audit release", func() bool { _, reported := p.adoptionStatus(0); return !reported })
	// Audit withdraws with its tasks present by design: no residual report.
	if slots, counts := p.adoptionReport(); len(slots) != 0 || counts[MigratedAfterRelease] != 0 {
		t.Fatalf("Audit release reported %+v %v", slots, counts)
	}
}

// TestProductPublisherMigratedAfterRelease (migrate-in residual): a task
// that migrates into a refused Strict slot's cgroup between the empty poll
// and the withdrawal runs under the WITHDRAWN (allowing) route. The release
// re-reads the cgroup after the withdrawal (G020 carryover: 3 reads over
// 250 ms, then once before the recycle) and reports the residual once,
// Degraded (MigratedAfterRelease), kept after the slot is recycled and
// counted; a cgroup still empty after the withdrawal reports nothing.
func TestProductPublisherMigratedAfterRelease(t *testing.T) {
	for _, tc := range []struct {
		name     string
		migrated bool
		gone     bool
		// from is the post-withdrawal read that first sees the task (1:
		// at once, 3: the window's last read, 4: the check before the
		// recycle); reads the post-withdrawal reads.
		from, reads int
	}{
		{"migrated in", true, false, 1, 1},
		{"migrated in late in the window", true, false, 3, 3},
		{"migrated in before the recycle", true, false, 4, 4},
		{"still empty", false, false, 0, 4},
		{"cgroup gone", false, true, 0, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &sharedFakeCommander{verifyCode: sharedProductRefused}
			threads := &sharedFakeThreads{tids: []uint32{7}}
			p, _ := newTestProductPublisher(cmd, threads)
			defer p.Close()
			withdrawn := func() bool { return strings.Contains(strings.Join(cmd.log(), ","), "withdraw") }
			var reads atomic.Int32 // post-withdrawal reads
			p.threads = func(slot uint32) ([]uint32, error) {
				if withdrawn() {
					if n := int(reads.Add(1)); tc.migrated && n >= tc.from {
						return []uint32{42}, nil // migrated in after the empty poll
					}
				}
				return threads.list(slot)
			}
			if _, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, true, sharedTestInit); err == nil {
				t.Fatal("refused adoption published")
			}
			threads.set(nil, tc.gone)
			waitFor(t, "release", func() bool { _, reported := p.adoptionStatus(0); return !reported })
			if log := strings.Join(cmd.log(), ","); !strings.HasSuffix(log, "withdraw,recycle") {
				t.Fatalf("release %s", log)
			}
			if n := int(reads.Load()); n != tc.reads {
				t.Fatalf("%d post-withdrawal reads, want %d", n, tc.reads)
			}
			slots, counts := p.adoptionReport()
			if !tc.migrated {
				if len(slots) != 0 || counts[MigratedAfterRelease] != 0 {
					t.Fatalf("no migration, yet reported %+v %v", slots, counts)
				}
				return
			}
			if len(slots) != 1 || slots[0].Reason != MigratedAfterRelease || slots[0].Slot != 0 || slots[0].Cgroup != 11 ||
				slots[0].InitTGID != 7 || slots[0].Audit || counts[MigratedAfterRelease] != 1 || counts[AdoptionRefusedIdentity] != 1 {
				t.Fatalf("migrated residual %+v %v", slots, counts)
			}
			// The slot is recycled (no per-slot status: a new binding may
			// reuse it), the residual stays reported.
			if _, reported := p.adoptionStatus(0); reported {
				t.Fatal("residual attributed to the recycled slot")
			}
		})
	}
}

// TestProductPublisherDeadlineQuarantines: a canceled start (NRI deadline)
// stops issuing adopt_task, still quarantines, and never runs finish.
func TestProductPublisherDeadlineQuarantines(t *testing.T) {
	cmd := &sharedFakeCommander{quarantineMisses: 1}
	threads := &sharedFakeThreads{tids: []uint32{7, 8}, gone: true}
	p, _ := newTestProductPublisher(cmd, threads)
	defer p.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cmd.taskCodes = map[uint32]uint32{}
	threads.tids = []uint32{7, 8}
	threads.gone = false
	// Cancel after the first adopt_task by making the listing cancel.
	list := p.threads
	p.threads = func(slot uint32) ([]uint32, error) {
		tids, err := list(slot)
		cancel()
		return tids, err
	}
	_, err := p.Publish(ctx, 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, true, sharedTestInit)
	var refused *ErrSharedAdoptionRefused
	if !errors.As(err, &refused) || refused.Reason != AdoptionRefusedDeadline {
		t.Fatalf("deadline refusal %v", err)
	}
	log := strings.Join(cmd.log(), ",")
	if strings.Contains(log, "task:") || strings.Contains(log, "finish") || !strings.Contains(log, "quarantine") {
		t.Fatalf("deadline path %s", log)
	}
}

func TestProductPublisherRevisionAndCodes(t *testing.T) {
	cmd := &sharedFakeCommander{reviseCode: sharedProductRetry, withdrawCode: sharedProductLatched}
	p, _ := newTestProductPublisher(cmd, &sharedFakeThreads{})
	defer p.Close()
	if _, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, false, SharedInitIdentity{}); !errors.Is(err, ErrSharedRetryableRefusal) || !strings.Contains(err.Error(), "retryable") {
		t.Fatalf("revision: %v", err)
	}
	if err := p.Withdraw(t.Context(), 0, 11); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("latched withdraw: %v", err)
	}
	cmd.withdrawCode = sharedProductReused
	if err := p.Withdraw(t.Context(), 0, 11); !errors.Is(err, ErrSharedBindingWithdrawn) {
		t.Fatalf("reused withdraw: %v", err)
	}
	if _, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, true, SharedInitIdentity{TGID: 7}); err == nil || len(cmd.log()) != 3 {
		t.Fatalf("incomplete identity published: %v %v", err, cmd.log())
	}
}

// TestProductPublisherRecycleUncleanAndRevisionRefusal: recycle code 6
// (UNCLEAN) keeps the slot occupied and is retried like a contended recycle;
// a refused revision (code 2: another policy UID) is terminal.
func TestProductPublisherRecycleUncleanAndRevisionRefusal(t *testing.T) {
	cmd := &sharedFakeCommander{recycleCodes: []uint32{sharedProductRecycleUnclean}, reviseCode: sharedProductRefused}
	p, _ := newTestProductPublisher(cmd, &sharedFakeThreads{})
	defer p.Close()
	if err := p.Recycle(t.Context(), 0, 11); !errors.Is(err, errSharedRecycleContended) {
		t.Fatalf("UNCLEAN recycle: %v, want a retry", err)
	}
	if err := p.Recycle(t.Context(), 0, 11); err != nil {
		t.Fatalf("clean recycle: %v", err)
	}
	_, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, false, SharedInitIdentity{})
	if err == nil || !strings.Contains(err.Error(), "changes the policy UID, class, root role or root epoch") || errors.Is(err, ErrSharedRetryableRefusal) || strings.Contains(err.Error(), "retryable") {
		t.Fatalf("refused revision: %v", err)
	}
	// The poller's release retries UNCLEAN until the recycle is clean.
	cmd.recycleCodes = []uint32{sharedProductRecycleUnclean, sharedProductRecycleUnclean, sharedProductOK}
	p.release(t.Context(), 4, 11)
	if n := strings.Count(strings.Join(cmd.log(), ","), "recycle"); n != 5 {
		t.Fatalf("%d recycles, want 2 + 3", n)
	}
}

// TestProductPublisherUnconfirmedFirstPublishLatches (review M2): a first
// publication with an unknown outcome latches the slot: reported Degraded
// (PublishUnconfirmed, failed), counted, never adopted, withdrawn or
// recycled before node teardown.
func TestProductPublisherUnconfirmedFirstPublishLatches(t *testing.T) {
	cmd := &sharedFakeCommander{publishErr: &ErrSharedPublishUnknown{Slot: 2, Cgroup: 11, Scope: 0x5c09e, Err: fmt.Errorf("lost: %w", errSharedPublishUnknown)}}
	p, _ := newTestProductPublisher(cmd, &sharedFakeThreads{tids: []uint32{7}})
	_, err := p.Publish(t.Context(), 2, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, true, sharedTestInit)
	var unknown *ErrSharedPublishUnknown
	if !errors.Is(err, errSharedPublishUnknown) || !errors.As(err, &unknown) || unknown.Scope != 0x5c09e {
		t.Fatalf("publish: %v", err)
	}
	st, reported := p.adoptionStatus(2)
	if !reported || st.Reason != PublishUnconfirmed || !st.Failed || st.Cgroup != 11 {
		t.Fatalf("status %+v %v", st, reported)
	}
	if err := p.Withdraw(t.Context(), 2, 11); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("withdraw of a latched slot: %v", err)
	}
	if err := p.Recycle(t.Context(), 2, 11); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("recycle of a latched slot: %v", err)
	}
	if _, counts := p.adoptionReport(); counts[PublishUnconfirmed] != 1 {
		t.Fatalf("counters %v", counts)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if log := strings.Join(cmd.log(), ","); log != "publish" {
		t.Fatalf("commands %s, want only the publish", log)
	}
}

// TestProductPublisherUnarmedIsTerminal: code 7 (the image's configuration
// is not installed, hooks unarmed) is a terminal control fault: never
// retried, wrapping ErrSharedNativeUnavailable, on a first publication, a
// revision and at verify.
func TestProductPublisherUnarmedIsTerminal(t *testing.T) {
	cmd := &sharedFakeCommander{publish: sharedProductUnarmed, reviseCode: sharedProductUnarmed}
	p, _ := newTestProductPublisher(cmd, &sharedFakeThreads{tids: []uint32{7}})
	defer p.Close()
	for name, first := range map[string]bool{"first": true, "revision": false} {
		_, err := p.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, first, sharedTestInit)
		if !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "hooks not armed") || errors.Is(err, ErrSharedRetryableRefusal) || strings.Contains(err.Error(), "retryable") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if strings.Count(strings.Join(cmd.log(), ","), "publish") != 1 {
		t.Fatalf("an unarmed publication was retried: %v", cmd.log())
	}
	cmd2 := &sharedFakeCommander{verifyCode: sharedProductUnarmed}
	p2, _ := newTestProductPublisher(cmd2, &sharedFakeThreads{tids: []uint32{7}})
	defer p2.Close()
	_, err := p2.Publish(t.Context(), 0, 11, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, true, sharedTestInit)
	if !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "hooks not armed") {
		t.Fatalf("unarmed verify: %v", err)
	}
}
