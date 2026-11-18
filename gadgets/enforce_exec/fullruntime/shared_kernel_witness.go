// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// D1 (LSM-only prototype), review F2 and F3: the kernel witness and the
// startup canary of a D1 object (one that carries the d1_witness map).

// ErrSharedKernelWitness reports that the kernel ran an exec or a fork
// without the node's BPF LSM program, or that ftrace was seen disabled. It
// is latched until the node (the agent) restarts: tasks that ran in the
// window are untracked or carry stale roles, and no later reading clears it.
var ErrSharedKernelWitness = errors.New("kernel witness: BPF LSM hooks did not run")

const (
	sharedKernelWitnessMap   = "d1_witness"
	sharedKernelWitnessCells = 11
	// sharedKernelWitnessCellSize: each cell is its own 64-byte line (S1
	// review N2); the count or latch is its first 8 bytes.
	sharedKernelWitnessCellSize = 64
	// sharedCanaryEnv makes this binary exit at once: the canary's exec.
	sharedCanaryEnv = "IG_ENFORCE_EXEC_CANARY"
)

func init() {
	if os.Getenv(sharedCanaryEnv) == "1" {
		os.Exit(0)
	}
}

// The d1_witness cells (bpf: D1_WIT_*).
const (
	sharedWitnessTPExec       = 0  // tp_btf/sched_process_exec runs (informational)
	sharedWitnessLSMCommit    = 1  // lsm/bprm_committed_creds runs (informational)
	sharedWitnessTPFork       = 2  // raw_tp/sched_process_fork runs (informational)
	sharedWitnessLSMAlloc     = 3  // lsm/task_alloc runs (informational)
	sharedWitnessFtraceOff    = 4  // latched: ftrace_enabled read as 0
	sharedWitnessHealed       = 5  // stale exec frames healed (informational)
	sharedWitnessExecUnmarked = 6  // execs without their LSM mark
	sharedWitnessForkUnmarked = 7  // forks without their LSM mark
	sharedWitnessKsymResolved = 8  // 1: the ftrace_enabled ksym resolved
	sharedWitnessKsymMissing  = 9  // 1: it did not ([4] is disarmed)
	sharedWitnessMarkFailed   = 10 // mark inserts that failed (informational)
)

// sharedKernelWitnessVerdict judges one reading. S1 review F2: the exec and
// fork signals are per-event marks ([6], [7]), never a comparison of
// cumulative counts, which an exec or fork failing between its two hooks
// would bank as credit masking a later silenced window.
func sharedKernelWitnessVerdict(c [sharedKernelWitnessCells]uint64) error {
	var reasons []string
	if c[sharedWitnessFtraceOff] != 0 {
		reasons = append(reasons, "kernel.ftrace_enabled was read as 0 at a syscall exit")
	}
	if n := c[sharedWitnessExecUnmarked]; n != 0 {
		reasons = append(reasons, fmt.Sprintf("%d exec(s) reached sched_process_exec without the lsm/bprm_committed_creds mark", n))
	}
	if n := c[sharedWitnessForkUnmarked]; n != 0 {
		reasons = append(reasons, fmt.Sprintf("%d fork(s) reached sched_process_fork without the lsm/task_alloc mark", n))
	}
	if c[sharedWitnessKsymMissing] != 0 {
		reasons = append(reasons, "the ftrace_enabled ksym is unresolved: the ftrace signal is disarmed")
	}
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrSharedKernelWitness, strings.Join(reasons, "; "))
}

// ErrSharedKernelWitnessRetryable marks a StartNode refusal by the kernel
// witness that a fresh StartNode may not repeat (S1 review N3): at start the
// only signals are unmarked execs or forks ([6], [7]), with ftrace seen on
// and its ksym armed. That is what an exec or fork that was between its LSM
// hook and its tracepoint while the links attached produces (its LSM half
// ran before the LSM link existed, its tracepoint half after the tracepoint
// link existed): a false alarm, but one this load can never tell from a
// silenced hook, so the node does not start on it (fail safe).
//
// Retry path: the caller stops the failed node (StartNode already tore it
// down) and calls StartNode again; the witness counts from load, so only a
// NEW load starts clean. The agent retries with backoff (the race needs an
// exec or fork in flight during the few milliseconds of the attach); a
// refusal that recurs on every attempt is not this race and is reported as
// the plain witness fault. Every other witness refusal at start (ftrace seen
// off, the ftrace ksym unresolved) is permanent for this boot: it is NOT
// marked retryable.
var ErrSharedKernelWitnessRetryable = errors.New("kernel witness: an exec or fork straddled the attach; retry StartNode")

// sharedKernelWitnessArmed is the startup check after the canary's fork,
// exec and exit (S1 review F2): the syscall-exit program must have seen the
// ftrace_enabled ksym resolved. A node whose ftrace signal is disarmed
// never starts (it cannot prove its protection). Any witness signal at
// start refuses too; see ErrSharedKernelWitnessRetryable for the one a
// fresh StartNode may clear.
func sharedKernelWitnessArmed(c [sharedKernelWitnessCells]uint64) error {
	if c[sharedWitnessKsymMissing] != 0 || c[sharedWitnessKsymResolved] != 1 {
		return fmt.Errorf("%w: the ftrace_enabled ksym did not resolve at load (resolved %d, unresolved %d): kernel.ftrace_enabled cannot be watched", ErrSharedKernelWitness, c[sharedWitnessKsymResolved], c[sharedWitnessKsymMissing])
	}
	err := sharedKernelWitnessVerdict(c)
	// Retryable only for the attach race: no ftrace-off reading and no
	// failed mark creation (S1 review 3: an allocation failure is not a
	// race a fresh load would avoid).
	if err != nil && c[sharedWitnessFtraceOff] == 0 && c[sharedWitnessMarkFailed] == 0 {
		return fmt.Errorf("%w (%w)", err, ErrSharedKernelWitnessRetryable)
	}
	return err
}

// StartNodeRetrying runs start (StartNode, or a wrapper) up to attempts
// times while it refuses with ErrSharedKernelWitnessRetryable, waiting
// backoff, then twice as long each time (capped at maxBackoff), between
// attempts (S1 review N3). Any other refusal, or the last retryable one, is
// returned as is; a canceled ctx ends the waits. A failed StartNode has
// already torn its node down, so every attempt is a fresh load.
func StartNodeRetrying(ctx context.Context, attempts int, backoff, maxBackoff time.Duration, start func(context.Context) (*NodeEnforcer, error)) (*NodeEnforcer, error) {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for attempt := 1; ; attempt++ {
		var n *NodeEnforcer
		n, err = start(ctx)
		if err == nil || !errors.Is(err, ErrSharedKernelWitnessRetryable) || attempt >= attempts {
			return n, err
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.Join(err, ctx.Err())
		case <-timer.C:
		}
		if backoff *= 2; maxBackoff > 0 && backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

type sharedLiveKernelWitness struct {
	read     func() ([sharedKernelWitnessCells]uint64, error)
	interval time.Duration

	mu    sync.Mutex
	fault error // latched
	// closed: the collection is closing; the maps are never read again and
	// the verdict is the last reading's.
	closed bool
	last   [sharedKernelWitnessCells]uint64
	stop   chan struct{}
	done   chan struct{}
	// stopOnce: NodeEnforcer.stopLiveHealth runs from Stop, Close and
	// stopLiveCollection (StopNode), which can overlap on different
	// goroutines; the poller is joined and the final reading taken once,
	// like every other live closer.
	stopOnce sync.Once
}

// borrowSharedKernelWitness borrows the witness map (the programs count from
// load; there is nothing to arm).
func borrowSharedKernelWitness(gc operators.GadgetContext, interval time.Duration) (*sharedLiveKernelWitness, error) {
	value, _ := gc.GetVar(operators.MapPrefix + sharedKernelWitnessMap)
	cells, _ := value.(*ebpf.Map)
	if cells == nil || cells.MaxEntries() != sharedKernelWitnessCells || cells.ValueSize() != sharedKernelWitnessCellSize {
		return nil, fmt.Errorf("kernel witness map unavailable or malformed")
	}
	read := func() (c [sharedKernelWitnessCells]uint64, err error) {
		// Ascending order: each tracepoint cell before its LSM cell.
		for i := range c {
			var cell [sharedKernelWitnessCellSize / 8]uint64
			if err = cells.Lookup(uint32(i), &cell); err != nil {
				return c, err
			}
			c[i] = cell[0]
		}
		return c, nil
	}
	if interval <= 0 {
		interval = SharedFailClosedPollInterval
	}
	return &sharedLiveKernelWitness{read: read, interval: interval}, nil
}

func (w *sharedLiveKernelWitness) sample() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fault != nil || w.closed {
		return
	}
	c, err := w.read()
	if err != nil {
		// An unreadable witness is unknown, never healthy.
		w.fault = fmt.Errorf("%w: unreadable: %w", ErrSharedKernelWitness, err)
		return
	}
	w.last = c
	w.fault = sharedKernelWitnessVerdict(c)
}

func (w *sharedLiveKernelWitness) start() {
	w.stop, w.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-w.stop:
				return
			case <-ticker.C:
				w.sample()
			}
		}
	}()
}

func (w *sharedLiveKernelWitness) close() {
	w.stopOnce.Do(func() {
		if w.stop != nil {
			close(w.stop)
			<-w.done
		}
		w.sample() // the final reading, before the maps close
		w.mu.Lock()
		w.closed = true
		w.mu.Unlock()
	})
}

// check samples once more (so a Ready call never trails the poller) and
// returns the latched fault.
func (w *sharedLiveKernelWitness) check() error {
	w.sample()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fault
}

// KernelWitness returns the last witness reading and the latched fault (nil
// while every exec and fork ran its LSM program).
func (n *NodeEnforcer) KernelWitness() ([sharedKernelWitnessCells]uint64, error) {
	n.mu.Lock()
	var w *sharedLiveKernelWitness
	if n.host != nil && n.host.live != nil {
		w = n.host.live.witness
	}
	n.mu.Unlock()
	if w == nil {
		return [sharedKernelWitnessCells]uint64{}, fmt.Errorf("no kernel witness")
	}
	err := w.check()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last, err
}

// sharedStartKernelWitness runs the attach canary, then borrows and arms the
// kernel witness. A variable only so that unit tests with a fake native host
// (no kernel maps, fake program IDs) can stand in for it; product code never
// replaces it.
var sharedStartKernelWitness = func(gc operators.GadgetContext, receipts map[string]*operators.NativeAttachment, interval time.Duration) (*sharedLiveKernelWitness, error) {
	if err := runSharedAttachCanary(receipts); err != nil {
		return nil, err
	}
	w, err := borrowSharedKernelWitness(gc, interval)
	if err != nil {
		return nil, err
	}
	c, err := w.read()
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable at start: %w", ErrSharedKernelWitness, err)
	}
	if err := sharedKernelWitnessArmed(c); err != nil {
		return nil, err
	}
	return w, nil
}

// runSharedAttachCanary proves, before the node is live, that EVERY attached
// program runs on this kernel (review F3): a link that attached is not a
// hook that fires (bpf missing from lsm=, ftrace off, a trampoline the
// kernel never calls). It enables BPF run statistics for its own duration,
// forks and execs this binary as a canary (which exits at once), and
// requires each receipt's program run count to have increased.
func runSharedAttachCanary(receipts map[string]*operators.NativeAttachment) error {
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		return fmt.Errorf("attach canary: BPF run statistics: %w", err)
	}
	defer stats.Close()
	runs := func() (map[string]uint64, error) {
		out := make(map[string]uint64, len(receipts))
		for name, r := range receipts {
			p, err := ebpf.NewProgramFromID(ebpf.ProgramID(r.ProgramID))
			if err != nil {
				return nil, fmt.Errorf("attach canary: program %s: %w", name, err)
			}
			st, err := p.Stats()
			p.Close()
			if err != nil {
				return nil, fmt.Errorf("attach canary: program %s: %w", name, err)
			}
			out[name] = st.RunCount
		}
		return out, nil
	}
	before, err := runs()
	if err != nil {
		return err
	}
	var silent []string
	deadline := time.Now().Add(5 * time.Second)
	for {
		cmd := exec.Command("/proc/self/exe")
		cmd.Env = []string{sharedCanaryEnv + "=1"}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("attach canary: exec: %w", err)
		}
		// task_free runs after the reaped child's RCU grace period.
		time.Sleep(50 * time.Millisecond)
		after, err := runs()
		if err != nil {
			return err
		}
		silent = silent[:0]
		for name := range receipts {
			if after[name] <= before[name] {
				silent = append(silent, name+" ("+receipts[name].Target+")")
			}
		}
		if len(silent) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			sort.Strings(silent)
			return fmt.Errorf("attach canary: attached but never ran during a fork+exec+exit: %s", strings.Join(silent, ", "))
		}
	}
}
