// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

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
	"strconv"
	"sync"
	"syscall"
)

type observation struct {
	Batch  uint64 `json:"batch"`
	Sample uint64 `json:"sample"`
	Target string `json:"target"`
	Errno  int    `json:"errno"`
	Exit   int    `json:"exit"`
	Signal int    `json:"signal"`
	Start  uint64 `json:"start_ns"`
	End    uint64 `json:"end_ns"`
}

type samplePolicy int

const (
	liveStrict samplePolicy = iota
	fencedStrict
	transitionStrict
	allowAll
)

func checkObservation(r observation, policy samplePolicy) error {
	if r.Target != "denied" && r.Target != "allowed" {
		return fmt.Errorf("unknown target %q", r.Target)
	}
	if r.End < r.Start || r.Start == 0 {
		return fmt.Errorf("invalid observation timestamps: %+v", r)
	}
	if r.Signal != 0 || (r.Errno == 0 && r.Exit != 0) || (r.Errno != 0 && r.Exit != 100) {
		return fmt.Errorf("probe infrastructure failure: %+v", r)
	}
	expected := 0
	if policy == fencedStrict || ((policy == liveStrict || policy == transitionStrict) && r.Target == "denied") {
		expected = int(syscall.EPERM)
	}
	if policy == transitionStrict && r.Target == "allowed" && (r.Errno == 0 || r.Errno == int(syscall.EPERM)) {
		return nil
	}
	if r.Errno != expected {
		return fmt.Errorf("target=%s errno=%d want=%d policy=%d", r.Target, r.Errno, expected, policy)
	}
	return nil
}

type workload struct {
	cmd       *exec.Cmd
	in        io.WriteCloser
	out       *bufio.Scanner
	logfile   *os.File
	mu        sync.Mutex
	batchID   uint64
	lastStart uint64
	lastEnd   uint64
	observed  uint64
	closed    bool
}

func startWorkload(ctx context.Context, helper, denied, allowed, childCG, logPath string) (*workload, error) {
	cmd := exec.CommandContext(ctx, helper, "serve", denied, allowed)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	logfile, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		in.Close()
		output.Close()
		return nil, err
	}
	cmd.Stderr = logfile
	if err := cmd.Start(); err != nil {
		in.Close()
		output.Close()
		logfile.Close()
		return nil, err
	}
	w := &workload{cmd: cmd, in: in, out: bufio.NewScanner(output), logfile: logfile}
	var ready struct {
		PID int `json:"ready_pid"`
	}
	if !w.out.Scan() {
		w.close()
		return nil, errors.Join(errors.New("probe missing ready"), w.out.Err())
	}
	if err := json.Unmarshal(w.out.Bytes(), &ready); err != nil || ready.PID != cmd.Process.Pid {
		w.close()
		return nil, fmt.Errorf("invalid probe ready: %s", w.out.Text())
	}
	if err := os.WriteFile(childCG+"/cgroup.procs", []byte(strconv.Itoa(ready.PID)), 0o600); err != nil {
		w.close()
		return nil, err
	}
	fmt.Fprintln(logfile, w.out.Text())
	return w, nil
}

// batch requires exactly two ordered records for each sample. The first callback
// runs only after evidence proves a probe has started. No blind startup sleeps.
func (w *workload) batch(count int, policy samplePolicy, first func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.batchID++
	if _, err := fmt.Fprintf(w.in, "%d %d\n", w.batchID, count); err != nil {
		return err
	}
	var verdict error
	for i := 0; i < count*2; i++ {
		if !w.out.Scan() {
			return errors.Join(fmt.Errorf("probe ended before observation %d/%d", i, count*2), w.out.Err())
		}
		line := append([]byte(nil), w.out.Bytes()...)
		if _, err := fmt.Fprintln(w.logfile, string(line)); err != nil {
			return err
		}
		var r observation
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		target := "denied"
		if i%2 == 1 {
			target = "allowed"
		}
		if r.Batch != w.batchID || r.Sample != uint64(i/2) || r.Target != target {
			return fmt.Errorf("missing/reordered observation: %+v", r)
		}
		w.lastStart, w.lastEnd = r.Start, r.End
		w.observed++
		if err := checkObservation(r, policy); err != nil && verdict == nil {
			verdict = err
		}
		if i == 0 && first != nil {
			if err := first(); err != nil && verdict == nil {
				verdict = err
			}
		}
	}
	return verdict
}

func (w *workload) close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	w.in.Close()
	// The controller calls close only after batch joins. Its context bounds a
	// stuck child; never kill an arbitrary process discovered by command text.
	err := w.cmd.Wait()
	returnErr := w.logfile.Close()
	if err != nil {
		return err
	}
	return returnErr
}
