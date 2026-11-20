// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// fence-oracle is a disposable-VM component qualification driver. Its selective
// unpinned backend is test-only, not the IG product or node-agent integration.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	fence "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
)

type ownerProcess struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *bufio.Scanner
	log  *os.File
	inc  uint64
	done bool
}

func startOwner(ctx context.Context, root, object, backend string, inode uint64, mutant, logPath string) (*ownerProcess, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe, "owner", root, object, backend, strconv.FormatUint(inode, 10), mutant)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		in.Close()
		stdout.Close()
		return nil, err
	}
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		in.Close()
		stdout.Close()
		log.Close()
		return nil, err
	}
	p := &ownerProcess{cmd: cmd, in: in, out: bufio.NewScanner(stdout), log: log}
	r, err := p.read()
	if err != nil {
		p.kill()
		return nil, err
	}
	p.inc = r.Inc
	return p, nil
}

func (p *ownerProcess) read() (reply, error) {
	var r reply
	if !p.out.Scan() {
		return r, errors.Join(errors.New("owner ended without acknowledgement"), p.out.Err())
	}
	if _, err := fmt.Fprintln(p.log, p.out.Text()); err != nil {
		return r, err
	}
	if err := json.Unmarshal(p.out.Bytes(), &r); err != nil {
		return r, err
	}
	if !r.OK {
		return r, fmt.Errorf("owner refused: %s", r.Error)
	}
	return r, nil
}

func (p *ownerProcess) call(c command) (reply, error) {
	if err := json.NewEncoder(p.in).Encode(c); err != nil {
		return reply{}, err
	}
	return p.read()
}

func (p *ownerProcess) kill() error {
	if p == nil || p.done {
		return nil
	}
	p.done = true
	err := p.cmd.Process.Kill()
	p.in.Close()
	waitErr := p.cmd.Wait()
	closeErr := p.log.Close()
	if err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	var exit *exec.ExitError
	if waitErr != nil && (!errors.As(waitErr, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL) {
		return waitErr
	}
	return closeErr
}

func (p *ownerProcess) exit() error {
	if p.done {
		return nil
	}
	if _, err := p.call(command{Op: "exit"}); err != nil {
		return err
	}
	p.done = true
	p.in.Close()
	return errors.Join(p.cmd.Wait(), p.log.Close())
}

type pod struct {
	root, child string
	id, childID uint64
	mode        uint32
	ancestors   []string
	chainIDs    []uint64
	probe       *workload
}
type fixture struct {
	ctx                                      context.Context
	root, object, backend, out, work, mutant string
	inode                                    uint64
	owner                                    *ownerProcess
	pods                                     []pod
	sequence                                 int
	events                                   *os.File
}

func inode(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

func (f *fixture) event(name string, value any) error {
	return json.NewEncoder(f.events).Encode(struct {
		Name  string `json:"event"`
		Time  uint64 `json:"monotonic_ns"`
		Value any    `json:"value"`
	}{name, monotonicNS(), value})
}

func (f *fixture) start() error {
	f.sequence++
	p, err := startOwner(f.ctx, f.root, f.object, f.backend, f.inode, f.mutant, filepath.Join(f.out, fmt.Sprintf("owner-%d.jsonl", f.sequence)))
	if err != nil {
		return err
	}
	f.owner = p
	return f.event("owner-start", map[string]any{"pid": p.cmd.Process.Pid, "incarnation": p.inc})
}

func (f *fixture) protect(i int) error {
	p := f.pods[i]
	_, err := f.owner.call(command{Op: "protect", Pod: p.id, Child: p.childID, Mode: p.mode})
	if err != nil {
		return err
	}
	return f.event("protected-moved", i)
}

func (f *fixture) live() (uint64, error) {
	raw, err := os.ReadFile(f.object)
	if err != nil {
		return 0, err
	}
	r, err := fence.Open(f.root, raw)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	s, err := r.Snapshot()
	if err != nil {
		return 0, err
	}
	if err := f.event("snapshot", s); err != nil {
		return 0, err
	}
	return s.LiveIncarnation, nil
}

func (f *fixture) expectLive(want uint64) error {
	got, err := f.live()
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("live incarnation=%d want=%d", got, want)
	}
	return nil
}

func (f *fixture) stable(policies []samplePolicy) error {
	var wg sync.WaitGroup
	errs := make(chan error, len(f.pods))
	for i := range f.pods {
		if f.pods[i].probe == nil {
			continue
		}
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs <- f.pods[i].probe.batch(100, policies[i], nil) }(i)
	}
	wg.Wait()
	close(errs)
	var err error
	for e := range errs {
		err = errors.Join(err, e)
	}
	return err
}

func (f *fixture) policies(strict samplePolicy) []samplePolicy {
	out := make([]samplePolicy, len(f.pods))
	for i, p := range f.pods {
		out[i] = strict
		if p.mode == 1 {
			out[i] = allowAll
		}
	}
	return out
}

func monotonicNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		panic(err)
	}
	return uint64(ts.Sec)*1000000000 + uint64(ts.Nsec)
}

// Keep draining every probe while the lifecycle action runs. There is no
// callback barrier or full pipe that can pause the workload during teardown.
func (f *fixture) transition(action func() error) error {
	type observed struct {
		pod, first, last, count uint64
		err                     error
	}
	ready := make(chan struct{}, len(f.pods))
	stop := make(chan struct{})
	results := make(chan observed, len(f.pods))
	var wg sync.WaitGroup
	for _, p := range f.pods {
		if p.probe == nil {
			continue
		}
		wg.Add(1)
		go func(p pod) {
			defer wg.Done()
			policy := transitionStrict
			if p.mode == 1 {
				policy = allowAll
			}
			before := p.probe.observed
			result := observed{pod: p.id}
			first := func() error { result.first = p.probe.lastStart; ready <- struct{}{}; return nil }
			for {
				if e := p.probe.batch(100, policy, first); e != nil {
					result.err = e
					break
				}
				first = nil
				select {
				case <-stop:
					// A fresh complete batch is guaranteed to begin after the
					// lifecycle action ends, so post-transition coverage is real.
					result.err = p.probe.batch(100, policy, nil)
					result.last = p.probe.lastEnd
					result.count = p.probe.observed - before
					results <- result
					return
				default:
				}
			}
			result.last = p.probe.lastEnd
			result.count = p.probe.observed - before
			results <- result
		}(p)
	}
	for _, p := range f.pods {
		if p.probe == nil {
			continue
		}
		select {
		case <-ready:
		case failed := <-results:
			close(stop)
			wg.Wait()
			if failed.err == nil {
				failed.err = fmt.Errorf("probe stopped before transition")
			}
			return failed.err
		case <-f.ctx.Done():
			close(stop)
			wg.Wait()
			return f.ctx.Err()
		}
	}
	start := monotonicNS()
	eventErr := f.event("transition-start", start)
	err := action()
	end := monotonicNS()
	close(stop)
	wg.Wait()
	close(results)
	for result := range results {
		err = errors.Join(err, result.err)
		if result.first >= start || result.last <= end || result.count < 400 {
			err = errors.Join(err, fmt.Errorf("pod %d lacks proven transition coverage: first=%d start=%d end=%d last=%d count=%d", result.pod, result.first, start, end, result.last, result.count))
		}
		err = errors.Join(err, f.event("transition-coverage", map[string]uint64{"pod": result.pod, "first_ns": result.first, "last_ns": result.last, "samples": result.count, "action_start_ns": start, "action_end_ns": end}))
	}
	return errors.Join(eventErr, err, f.event("transition-end", end))
}

func (f *fixture) recover() error {
	if err := f.start(); err != nil {
		return err
	}
	if err := f.stable(f.policies(fencedStrict)); err != nil {
		return err
	}
	for i, p := range f.pods {
		if p.probe != nil {
			if err := f.protect(i); err != nil {
				return err
			}
		}
	}
	return f.stable(f.policies(liveStrict))
}

func (f *fixture) cleanup() error {
	var err error
	if f.owner != nil {
		err = errors.Join(err, f.owner.kill())
	}
	for i := range f.pods {
		p := &f.pods[i]
		if p.probe != nil {
			err = errors.Join(err, p.probe.close())
			p.probe = nil
		}
		if _, e := os.Stat(p.child); e == nil {
			err = errors.Join(err, os.Remove(p.child))
		}
		for j := len(p.ancestors) - 1; j >= 0; j-- {
			err = errors.Join(err, os.Remove(p.ancestors[j]))
		}
		if _, e := os.Stat(p.root); e == nil {
			err = errors.Join(err, os.Remove(p.root))
		}
	}
	raw, e := os.ReadFile(f.object)
	if e == nil {
		if _, e := os.Stat(f.root); e == nil {
			err = errors.Join(err, fence.Lift(f.root, raw))
		}
	} else {
		err = errors.Join(err, e)
	}
	return errors.Join(err, f.events.Close())
}

func setup(ctx context.Context, name, out, work, object, backend, helper, mutant string) (*fixture, error) {
	out = filepath.Join(out, name)
	work = filepath.Join(work, name)
	if err := os.Mkdir(out, 0o700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(work, 0o700); err != nil {
		return nil, err
	}
	events, err := os.OpenFile(filepath.Join(out, "lifecycle.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	f := &fixture{ctx: ctx, out: out, work: work, object: object, backend: backend, mutant: mutant, events: events, root: "/sys/fs/bpf/ig-fence-qualification-" + name + "/fence-v1"}
	raw, err := os.ReadFile(helper)
	if err != nil {
		return nil, err
	}
	denied, allowed := filepath.Join(work, "denied"), filepath.Join(work, "allowed")
	if err := os.WriteFile(denied, raw, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(allowed, raw, 0o755); err != nil {
		return nil, err
	}
	f.inode, err = inode(denied)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 4; i++ {
		p := pod{root: fmt.Sprintf("/sys/fs/cgroup/ig-fence-qualification-%s-%d", name, i), mode: 2}
		if i == 3 {
			p.mode = 1
		}
		p.child = p.root + "/container"
		if name == "deep-cgroup" {
			depth := []int{64, 65, 64, 65}[i]
			if i >= 2 {
				p.mode = 1
			}
			chain, e := deepCgroupChain(p.root, depth)
			if e != nil {
				return nil, e
			}
			p.ancestors, p.child = chain[:len(chain)-1], chain[len(chain)-1]
		}
		if name == "deep-cgroup" {
			paths := append([]string{p.root}, p.ancestors...)
			paths = append(paths, p.child)
			if _, err := createDeepPaths(paths, func(path string) error { return os.Mkdir(path, 0o755) }, os.Remove); err != nil {
				return f, err
			}
		} else {
			if err := os.Mkdir(p.root, 0o755); err != nil {
				return nil, err
			}
			if err := os.Mkdir(p.child, 0o755); err != nil {
				return nil, err
			}
		}
		if err := func() error {
			p.id, err = inode(p.root)
			if err != nil {
				return err
			}
			p.childID, err = inode(p.child)
			if err != nil {
				return err
			}
			p.probe, err = startWorkload(ctx, helper, denied, allowed, p.child, filepath.Join(out, fmt.Sprintf("probe-%d.jsonl", i)))
			if err != nil {
				return err
			}
			return nil
		}(); err != nil {
			if name == "deep-cgroup" {
				paths := append([]string{p.root}, p.ancestors...)
				paths = append(paths, p.child)
				for j := len(paths) - 1; j >= 0; j-- {
					err = errors.Join(err, os.Remove(paths[j]))
				}
			}
			return f, err
		}
		f.pods = append(f.pods, p)
	}
	if name == "deep-cgroup" {
		if err := f.attestDeepCgroups(); err != nil {
			return f, err
		}
	}
	if err := f.start(); err != nil {
		return f, err
	}
	for i, p := range f.pods {
		if _, err := f.owner.call(command{Op: "bind", Pod: p.id, Mode: p.mode, Hash: uint64(i + 1), Path: p.root}); err != nil {
			return f, err
		}
		if err := f.protect(i); err != nil {
			return f, err
		}
	}
	return f, f.stable(f.policies(liveStrict))
}

func (f *fixture) counterSnapshot() (fence.Snapshot, error) {
	raw, err := os.ReadFile(f.object)
	if err != nil {
		return fence.Snapshot{}, err
	}
	held, err := fence.Open(f.root, raw)
	if err != nil {
		return fence.Snapshot{}, err
	}
	defer held.Close()
	return held.Snapshot()
}

func (f *fixture) checkOutageTotals(before fence.Snapshot) error {
	raw, err := os.ReadFile(f.object)
	if err != nil {
		return err
	}
	held, err := fence.Open(f.root, raw)
	if err != nil {
		return err
	}
	defer held.Close()
	state, err := held.Snapshot()
	if err != nil {
		return err
	}
	for _, p := range f.pods {
		totals, exists := state.PerCgroup[p.id]
		if !exists {
			return fmt.Errorf("missing pod counters %d", p.id)
		}
		prev := before.PerCgroup[p.id]
		if totals.Audit < prev.Audit || totals.Denied < prev.Denied || totals.Lost < prev.Lost {
			return fmt.Errorf("outage counters regressed for %d", p.id)
		}
		delta := fence.Totals{Denied: totals.Denied - prev.Denied, Audit: totals.Audit - prev.Audit, Lost: totals.Lost - prev.Lost}
		if p.mode == 1 {
			if delta.Audit < 200 || delta.Denied != 0 {
				return fmt.Errorf("invalid Audit outage counters: %+v", totals)
			}
		} else if delta.Denied < 100 || delta.Audit != 0 {
			return fmt.Errorf("invalid Strict outage counters: %+v", totals)
		}
	}
	return f.event("outage-counters-attested", state)
}

func (f *fixture) scenario(name string) error {
	if name == "deep-cgroup" {
		if err := f.attestDeepCgroups(); err != nil {
			return err
		}
	}
	switch name {
	case "graceful":
		if err := f.transition(func() error {
			if _, e := f.owner.call(command{Op: "stop"}); e != nil {
				return e
			}
			return f.owner.exit()
		}); err != nil {
			return err
		}
	case "deep-cgroup", "sigkill", "partial-move", "cgroup-exit", "abi-skew", "load-failure", "nonce", "uninstall":
		if err := f.transition(f.owner.kill); err != nil {
			return err
		}
	case "selfexec", "thread-selfexec":
		if err := f.transition(func() error { _, e := f.owner.call(command{Op: name}); return e }); err != nil {
			return err
		}
	case "failed-selfexec":
		path := filepath.Join(f.work, "invalid-exec")
		if err := os.WriteFile(path, []byte{1, 2, 3, 4}, 0o755); err != nil {
			return err
		}
		if err := f.transition(func() error { _, e := f.owner.call(command{Op: "badexec", Path: path}); return e }); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown scenario %q", name)
	}
	if err := f.expectLive(0); err != nil {
		return err
	}
	if name == "deep-cgroup" {
		if err := f.attestDeepCgroups(); err != nil {
			return err
		}
	}
	beforeCounts, err := f.counterSnapshot()
	if err != nil {
		return err
	}
	if err := f.stable(f.policies(fencedStrict)); err != nil {
		return err
	}
	if err := f.checkOutageTotals(beforeCounts); err != nil {
		return err
	}
	switch name {
	case "partial-move":
		if err := f.start(); err != nil {
			return err
		}
		for k := 1; k <= 2; k++ {
			if err := f.protect(k - 1); err != nil {
				return err
			}
			policies := f.policies(fencedStrict)
			for i := 0; i < k; i++ {
				policies[i] = liveStrict
			}
			if err := f.stable(policies); err != nil {
				return err
			}
		}
		if err := f.transition(f.owner.kill); err != nil {
			return err
		}
		if err := f.expectLive(0); err != nil {
			return err
		}
		if err := f.stable(f.policies(fencedStrict)); err != nil {
			return err
		}
	case "cgroup-exit":
		p := &f.pods[0]
		if err := p.probe.close(); err != nil {
			return err
		}
		p.probe = nil
		if err := os.Remove(p.child); err != nil {
			return err
		}
		if err := os.Remove(p.root); err != nil {
			return err
		}
		if err := f.start(); err != nil {
			return err
		}
		if _, err := f.owner.call(command{Op: "remove", Pod: p.id}); err != nil {
			return err
		}
		if err := f.owner.kill(); err != nil {
			return err
		}
	case "abi-skew":
		skew := filepath.Join(filepath.Dir(f.root), "fence-v2")
		// Move the complete pinned graph to an unknown version, rather than
		// merely creating an empty sibling. Attached enforcement stays live.
		if err := os.Rename(f.root, skew); err != nil {
			return err
		}
		raw, err := os.ReadFile(f.object)
		if err != nil {
			return err
		}
		bad, e := fence.Open(f.root, raw)
		if e == nil {
			bad.Close()
			return fmt.Errorf("ABI skew was accepted")
		}
		if err := f.event("expected-skew-refusal", e.Error()); err != nil {
			return err
		}
		if err := f.stable(f.policies(fencedStrict)); err != nil {
			return err
		}
		if _, err := os.Stat(f.root); !os.IsNotExist(err) {
			return errors.Join(errors.New("ABI refusal created replacement pins"), err)
		}
		// Restore only the exact fixture-owned directory for ordinary recovery;
		// no object/map/link was unpinned or replaced during the refusal.
		if err := os.Rename(skew, f.root); err != nil {
			return err
		}
	case "load-failure":
		bad, e := fence.Open(f.root, []byte("not an ELF"))
		if e == nil {
			bad.Close()
			return fmt.Errorf("invalid fence ELF was accepted")
		}
		if err := f.event("expected-load-refusal", e.Error()); err != nil {
			return err
		}
		if err := f.expectLive(0); err != nil {
			return err
		}
	case "nonce":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(f.ctx, exe, "spoof", strconv.FormatUint(f.owner.inc+1, 10))
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		cmd.Stderr = f.events
		if err := cmd.Start(); err != nil {
			return err
		}
		defer func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() }()
		scan := bufio.NewScanner(stdout)
		if !scan.Scan() {
			return fmt.Errorf("spoof missing acknowledgement")
		}
		if err := f.expectLive(0); err != nil {
			return fmt.Errorf("unauthorized nonce changed live owner: %w", err)
		}
		if err := f.stable(f.policies(fencedStrict)); err != nil {
			return err
		}
	case "uninstall":
		raw, err := os.ReadFile(f.object)
		if err != nil {
			return err
		}
		held, err := fence.Open(f.root, raw)
		if err != nil {
			return err
		}
		defer held.Close()
		if err := fence.Lift(f.root, raw); err != nil {
			return err
		}
		if _, err := os.Stat(f.root); err != nil {
			return fmt.Errorf("uninstall lost retirement tombstone: %w", err)
		}
		state, err := held.Snapshot()
		if err != nil {
			return err
		}
		if !state.Retired || state.LiveIncarnation != 0 {
			return fmt.Errorf("uninstall retirement not attested: %+v", state)
		}
		if _, err := held.Register(); !errors.Is(err, fence.ErrRetired) {
			return errors.Join(errors.New("retired registration did not return ErrRetired"), err)
		}
		reopened, err := fence.Open(f.root, raw)
		if reopened != nil {
			reopened.Close()
		}
		if !errors.Is(err, fence.ErrRetired) {
			return errors.Join(errors.New("retired reopen did not return ErrRetired"), err)
		}
		if err := f.event("uninstall-retired", state); err != nil {
			return err
		}
		return f.stable(f.policies(allowAll))
	case "selfexec", "thread-selfexec", "failed-selfexec":
		if name == "failed-selfexec" {
			if _, err := f.owner.call(command{Op: "reregister-refused"}); err != nil {
				return err
			}
			if err := f.expectLive(0); err != nil {
				return err
			}
		}
		if err := f.owner.kill(); err != nil {
			return err
		}
	}
	if err := f.recover(); err != nil {
		return err
	}
	if name == "deep-cgroup" {
		return f.attestDeepCgroups()
	}
	return nil
}

func run() error {
	if os.Getenv("FENCE_GUEST") != "1" || os.Geteuid() != 0 || os.Getenv("UK_PAYLOAD") == "" {
		return fmt.Errorf("isolated VM FENCE_GUEST=1 and UK_PAYLOAD required; never run on workstation")
	}
	out, work := os.Getenv("UK_OUT"), os.Getenv("UK_WORK")
	object, backend, helper := os.Getenv("FENCE_OBJECT"), os.Getenv("FENCE_BACKEND"), os.Getenv("FENCE_PROBE")
	for _, p := range []string{out, work, object, backend, helper} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("absolute configured path required: %q", p)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cases, err := selectedCases(os.Getenv("FENCE_CASE"))
	if err != nil {
		return err
	}
	for _, name := range cases {
		if name == "load-failure" {
			// Refusal before any fence/engine publication, distinct from the
			// successor's refusal while old bindings already exist below.
			initialRoot := "/sys/fs/bpf/ig-fence-initial-load-refusal/fence-v1"
			held, loadErr := fence.Open(initialRoot, []byte("not an ELF"))
			if held != nil {
				held.Close()
			}
			if loadErr == nil {
				return fmt.Errorf("FAIL load-failure: initial invalid object accepted")
			}
			if _, e := os.Stat(initialRoot); !os.IsNotExist(e) {
				return errors.Join(errors.New("FAIL load-failure: initial refusal published pins"), e)
			}
			if e := os.WriteFile(filepath.Join(out, "initial-load-refusal.txt"), []byte(loadErr.Error()+"\n"), 0o600); e != nil {
				return e
			}
		}
		f, err := setup(ctx, name, out, work, object, backend, helper, os.Getenv("FENCE_MUTANT"))
		if err == nil {
			err = f.scenario(name)
		}
		// On failing rows retain kernel state until disposable guest shutdown. No
		// automatic lift may conceal the failing state from evidence collection.
		if err != nil {
			return fmt.Errorf("FAIL %s: %w", name, err)
		}
		if err := f.cleanup(); err != nil {
			return fmt.Errorf("FAIL %s cleanup: %w", name, err)
		}
		fmt.Printf("PASS %s\n", name)
	}
	return nil
}

func main() {
	if os.Getenv("FENCE_GUEST") != "1" || os.Getenv("UK_PAYLOAD") == "" || os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "isolated VM FENCE_GUEST=1 and UK_PAYLOAD required; never run on workstation")
		os.Exit(1)
	}
	var err error
	switch {
	case len(os.Args) == 7 && os.Args[1] == "owner":
		n, e := strconv.ParseUint(os.Args[5], 10, 64)
		if e != nil {
			err = e
		} else {
			err = runOwner(os.Args[2], os.Args[3], os.Args[4], n, os.Args[6])
		}
	case len(os.Args) == 3 && os.Args[1] == "spoof":
		n, e := strconv.ParseUint(os.Args[2], 10, 64)
		if e != nil {
			err = e
		} else {
			err = runSpoof(n)
		}
	case len(os.Args) == 2 && os.Args[1] == "postexec":
		err = postExec()
	case len(os.Args) == 1:
		err = run()
	default:
		err = fmt.Errorf("unsupported oracle invocation")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
