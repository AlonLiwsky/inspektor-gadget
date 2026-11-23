// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const (
	// sharedNodeABI is the ABI of the shared node wire (sharedNodeWire.ABI).
	sharedNodeABI = 3
	pidfdThread   = 0x80 // Linux PIDFD_THREAD; older x/sys versions omit the name.
)

var ErrControlClosed = errors.New("owner command thread closed")

type (
	controlFailure struct{ err error }
	controlJob     struct {
		ctx     context.Context
		run     func() error
		result  chan error
		private bool // scalar-result callers use non-retaining panic recovery
	}
)

type controlThread struct {
	jobs       chan controlJob
	stop, done chan struct{}
	once       sync.Once
	failure    atomic.Pointer[controlFailure]
}

func safeControlCall(fn func() error) (err error, panicked bool) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("owner command panic: %v", value)
			panicked = true
		}
	}()
	return fn(), false
}

// A private panic has a fixed terminal owner and never formats or retains the
// recovered payload. This does not bound allocations made before the panic.
var (
	errPrivateControlPanic     = errors.New("private owner command panic")
	privateControlPanicFailure = &controlFailure{err: errPrivateControlPanic}
)

func safePrivateControlCall(fn func() error) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			err, panicked = errPrivateControlPanic, true
		}
	}()
	return fn(), false
}

func startControlThread(setup func() error) (*controlThread, error) {
	w := &controlThread{jobs: make(chan controlJob), stop: make(chan struct{}), done: make(chan struct{})}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Deliberately do NOT UnlockOSThread: the frozen admin nonce belongs to this
		// physical task. Exit destroys the OS thread instead of handing its authority
		// to another goroutine in the Go thread pool.
		defer close(w.done)
		err, _ := safeControlCall(setup)
		if err != nil {
			w.failure.Store(&controlFailure{err})
			ready <- err
			return
		}
		ready <- nil
		for {
			select {
			case <-w.stop:
				return
			case job := <-w.jobs:
				if err := job.ctx.Err(); err != nil {
					job.result <- err
					continue
				}
				isPrivate := job.private
				var err error
				var panicked bool
				if isPrivate {
					err, panicked = safePrivateControlCall(job.run)
					if panicked {
						// Publish terminal state BEFORE the result is observable.
						w.failure.Store(privateControlPanicFailure)
					}
				} else {
					err, panicked = safeControlCall(job.run)
				}
				job.result <- err
				if panicked {
					if !isPrivate {
						w.failure.Store(&controlFailure{err})
					}
					return
				}
			}
		}
	}()
	if err := <-ready; err != nil {
		<-w.done
		return nil, err
	}
	return w, nil
}

func (w *controlThread) unavailable() error {
	if failed := w.failure.Load(); failed != nil {
		return failed.err
	}
	return ErrControlClosed
}

func (w *controlThread) do(ctx context.Context, fn func() error) error {
	err, canceled, accepted := w.doJoined(ctx, fn, false)
	if !accepted {
		return err
	}
	return errors.Join(err, canceled)
}

// doJoined separates execution from rich error presentation. The acceptance bit
// preserves direct pre-submission errors versus joined accepted-call errors.
// Callers must not let cleanup/finish replace this cancellation snapshot.
func (w *controlThread) doJoined(ctx context.Context, fn func() error, private bool) (err, canceled error, accepted bool) {
	if err := ctx.Err(); err != nil {
		return err, nil, false
	}
	job := controlJob{ctx: ctx, run: fn, result: make(chan error, 1), private: private}
	select {
	case <-w.done:
		return w.unavailable(), nil, false
	case <-ctx.Done():
		return ctx.Err(), nil, false
	case <-w.stop:
		return ErrControlClosed, nil, false
	case w.jobs <- job:
	}
	// Once accepted, a bounded kernel call must be JOINED even after cancellation.
	// Returning early would let native rollback/reopen race an unfinished writer.
	err = <-job.result
	return err, ctx.Err(), true
}

func (w *controlThread) close() error {
	w.once.Do(func() { close(w.stop) })
	<-w.done
	if failed := w.failure.Load(); failed != nil {
		return failed.err
	}
	return nil
}

// DuplicateProcPin returns a caller-owned duplicate; retain it until root-token invalidation and
// confirmed hook teardown, even if startup fails after partial initialization.
func DuplicateProcPin(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, fmt.Errorf("trusted init proc pin required")
	}
	conn, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var duplicateErr error
	if err = conn.Control(func(original uintptr) { fd, duplicateErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0) }); err != nil {
		return nil, err
	}
	if duplicateErr != nil {
		return nil, duplicateErr
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		if err == nil {
			err = fmt.Errorf("init pin is not a proc directory")
		}
		return nil, err
	}

	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		unix.Close(fd)
		if err == nil {
			err = fmt.Errorf("init pin is not procfs")
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), "sandbox init proc pin"), nil
}
