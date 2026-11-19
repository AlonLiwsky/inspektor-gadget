// Copyright 2021 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nsenter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// ErrRestoreNamespace is wrapped by the error NetnsEnter and CgroupnsEnter
// return when the original namespace could not be restored. The callback may
// have run to completion in that case; callers that tolerate some callback
// errors must still treat this one as a failure.
var ErrRestoreNamespace = errors.New("restoring original namespace")

// ErrCallbackExited is returned when the callback did not return, for
// instance because it called runtime.Goexit (t.FailNow does). The original
// namespace was not restored, so the thread is discarded.
var ErrCallbackExited = errors.New("namespace callback exited without returning")

// setns is the setns(2) seam; tests replace it so they do not need root.
var setns = unix.Setns

// testHookThreadExit, when set, is called as the namespace goroutine exits,
// with whether its OS thread is still locked.
var testHookThreadExit func(locked bool)

// NetnsEnter enters the network namespace of a process and executes the provided function
//
// f runs on a fresh goroutine and OS thread, not on the caller's. That thread
// starts in the process's original namespaces (not the caller thread's) and
// then enters only the network namespace of pid. Calls therefore do not compose:
// a nested NetnsEnter/CgroupnsEnter inside f starts again from the original
// namespaces, so f sees only the innermost namespace switch. With pid == 0,
// f runs directly on the caller's goroutine with no namespace switch.
//
// The error wraps ErrRestoreNamespace if the original namespace could not be
// restored, and is ErrCallbackExited if f did not return. A panic in f is
// re-raised on the caller's goroutine.
func NetnsEnter(pid int, f func() error) error {
	if pid == 0 {
		return f()
	}
	return nsEnter(pid, "net", unix.CLONE_NEWNET, f)
}

// CgroupnsEnter enters the cgroup namespace of a process and executes the provided function
//
// f runs on a fresh goroutine and OS thread, not on the caller's. That thread
// starts in the process's original namespaces (not the caller thread's) and
// then enters only the cgroup namespace of pid. Calls therefore do not compose:
// a nested NetnsEnter/CgroupnsEnter inside f starts again from the original
// namespaces, so f sees only the innermost namespace switch. With pid == 0,
// f runs directly on the caller's goroutine with no namespace switch.
//
// The error wraps ErrRestoreNamespace if the original namespace could not be
// restored, and is ErrCallbackExited if f did not return. A panic in f is
// re-raised on the caller's goroutine.
func CgroupnsEnter(pid int, f func() error) error {
	if pid == 0 {
		return f()
	}
	return nsEnter(pid, "cgroup", unix.CLONE_NEWCGROUP, f)
}

// nsEnter runs f in the nsKind namespace of pid on a dedicated goroutine.
//
// setns(2) changes the namespace of the calling OS thread only, so the
// goroutine locks its thread for the whole switch. It unlocks only once the
// original namespace is restored. If the restore fails, the goroutine exits
// still locked: the Go runtime then terminates that thread instead of handing
// it to other goroutines, so the foreign namespace never leaks. A dedicated
// goroutine is needed for that, because the caller's goroutine keeps running
// and would otherwise stay pinned to the foreign-namespace thread.
//
// A panic in f is re-raised on the caller's goroutine after the restore
// attempt. If f calls runtime.Goexit, runInNamespace never returns: the
// thread stays locked (restored is still false) and exits with the goroutine,
// and the caller gets ErrCallbackExited.
func nsEnter(pid int, nsKind string, nsType int, f func() error) error {
	type result struct {
		err      error
		panicked bool
		panicVal any
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		var r result
		// Both stay false unless runInNamespace returns, so a Goexit in f
		// leaves the thread locked and reports ErrCallbackExited.
		restored, returned := false, false
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
			if !returned {
				r.err = ErrCallbackExited
			}
			if testHookThreadExit != nil {
				testHookThreadExit(!restored)
			}
			done <- r
		}()
		restored, r.err = runInNamespace(pid, nsKind, nsType, func() (err error) {
			defer func() {
				if v := recover(); v != nil {
					r.panicked, r.panicVal = true, v
					err = fmt.Errorf("panic in namespace callback: %v", v)
				}
			}()
			return f()
		})
		returned = true
	}()
	r := <-done
	if r.panicked {
		panic(r.panicVal)
	}
	return r.err
}

// runInNamespace must run on a locked OS thread. It reports restored=false
// only when the thread may be left in the target namespace.
func runInNamespace(pid int, nsKind string, nsType int, f func() error) (restored bool, err error) {
	origPath := filepath.Join("/proc", fmt.Sprint(os.Getpid()), "task", fmt.Sprint(unix.Gettid()), "ns", nsKind)
	origns, err := unix.Open(origPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return true, err
	}
	defer unix.Close(origns)

	targetPath := filepath.Join(host.HostProcFs, fmt.Sprint(pid), "ns", nsKind)
	targetns, err := unix.Open(targetPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return true, err
	}
	defer unix.Close(targetns)

	// A failed setns leaves the thread in its original namespace.
	if err := setns(targetns, nsType); err != nil {
		return true, err
	}

	err = f()

	if restoreErr := setns(origns, nsType); restoreErr != nil {
		return false, errors.Join(err, fmt.Errorf("%w %s: %w", ErrRestoreNamespace, nsKind, restoreErr))
	}
	return true, err
}
