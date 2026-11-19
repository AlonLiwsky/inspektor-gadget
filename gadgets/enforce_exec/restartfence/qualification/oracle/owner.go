// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	fence "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/restartfence"
)

// Keep the owner main goroutine on the group leader; thread-selfexec must
// originate on a different task and exercise de_thread explicitly.
func init() { runtime.LockOSThread() }

type command struct {
	Op    string `json:"op"`
	Pod   uint64 `json:"pod"`
	Child uint64 `json:"child"`
	Mode  uint32 `json:"mode"`
	Hash  uint64 `json:"hash"`
	Inc   uint64 `json:"inc"`
	Path  string `json:"path"`
}
type reply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Inc   uint64 `json:"incarnation,omitempty"`
	Live  uint64 `json:"live_incarnation"`
	State any    `json:"state,omitempty"`
}
type backendEntry struct {
	Inode uint64
	Mode  uint32
	Pad   uint32
}
type selectiveBackend struct {
	coll  *ebpf.Collection
	link  link.Link
	id    link.ID
	inode uint64
}

func openBackend(path string, inode uint64) (*selectiveBackend, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["backend_check"]})
	if err != nil {
		coll.Close()
		return nil, err
	}
	info, err := l.Info()
	if err != nil {
		l.Close()
		coll.Close()
		return nil, err
	}
	return &selectiveBackend{coll, l, info.ID, inode}, nil
}

func (b *selectiveBackend) protect(child uint64, mode uint32) error {
	want := backendEntry{Inode: b.inode, Mode: mode}
	if err := b.coll.Maps["backend_bind"].Put(child, want); err != nil {
		return err
	}
	var got backendEntry
	if err := b.coll.Maps["backend_bind"].Lookup(child, &got); err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("selective backend readback mismatch")
	}
	li, err := b.link.Info()
	if err != nil {
		return err
	}
	pi, err := b.coll.Programs["backend_check"].Info()
	if err != nil {
		return err
	}
	pid, ok := pi.ID()
	if !ok || li.ID != b.id || li.Program != pid {
		return fmt.Errorf("selective backend link attestation mismatch")
	}
	return nil
}

func (b *selectiveBackend) close() error {
	if b == nil || b.coll == nil {
		return nil
	}
	err := b.link.Close()
	b.coll.Close()
	b.coll = nil
	return err
}

func runOwner(root, object, backend string, inode uint64, mutant string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	raw, err := os.ReadFile(object)
	if err != nil {
		return err
	}
	f, err := fence.Open(root, raw)
	if err != nil {
		return err
	}
	defer f.Close()
	inc, err := f.Register()
	if err != nil {
		return err
	}
	b, err := openBackend(backend, inode)
	if err != nil {
		return err
	}
	defer b.close()
	out := json.NewEncoder(os.Stdout)
	if err := out.Encode(reply{OK: true, Inc: inc}); err != nil {
		return err
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var c command
		if err := json.Unmarshal(in.Bytes(), &c); err != nil {
			return err
		}
		r := reply{OK: true, Inc: inc}
		var opErr error
		switch c.Op {
		case "bind":
			mode := fence.Strict
			if c.Mode == 1 {
				mode = fence.Audit
			} else if c.Mode != 2 {
				opErr = fmt.Errorf("unknown fixture mode %d", c.Mode)
				break
			}
			podDir, e := os.Open(c.Path)
			if e != nil {
				opErr = e
				break
			}
			opErr = errors.Join(f.Bind(podDir, mode, c.Hash), podDir.Close())
		case "protect":
			opErr = b.protect(c.Child, c.Mode)
			if opErr == nil && mutant != "never-move" {
				opErr = f.Move(c.Pod)
			}
		case "arm":
			opErr = f.Arm()
		case "withdraw":
			opErr = b.close()
		case "remove":
			opErr = f.RemoveExited(c.Pod)
		case "snapshot":
			state, e := f.Snapshot()
			opErr = e
			if e == nil {
				r.Live = state.LiveIncarnation
				r.State = state
			}
		case "stop":
			if mutant == "restart-lift" {
				opErr = fence.Lift(root, raw)
			} else {
				opErr = f.Arm()
			}
			if opErr == nil {
				opErr = b.close()
			}
		case "selfexec":
			runtime.LockOSThread()
			opErr = unix.Exec("/proc/self/exe", []string{"fence-oracle", "postexec"}, os.Environ())
			runtime.UnlockOSThread()
		case "thread-selfexec":
			done := make(chan error, 1)
			go func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				if unix.Gettid() == os.Getpid() {
					done <- fmt.Errorf("thread exec not on a nonleader")
					return
				}
				done <- unix.Exec("/proc/self/exe", []string{"fence-oracle", "postexec"}, os.Environ())
			}()
			opErr = <-done
		case "badexec":
			runtime.LockOSThread()
			opErr = unix.Exec(c.Path, []string{c.Path}, os.Environ())
			runtime.UnlockOSThread()
			// Failure is the stimulus; only genuine exec failure is accepted.
			if errors.Is(opErr, unix.ENOEXEC) || errors.Is(opErr, unix.ENOENT) {
				opErr = nil
			} else {
				opErr = fmt.Errorf("unexpected failed-exec result: %w", opErr)
			}
		case "reregister-refused":
			if _, e := f.Register(); e == nil {
				opErr = fmt.Errorf("armed same handle registered again")
				break
			}
			other, e := fence.Open(root, raw)
			if e != nil {
				opErr = e
				break
			}
			_, e = other.Register()
			closeErr := other.Close()
			if e == nil {
				opErr = fmt.Errorf("armed same process registered with a fresh handle")
			} else {
				opErr = closeErr
			}
		case "exit":
			return out.Encode(reply{OK: true, Inc: inc})
		default:
			opErr = fmt.Errorf("unknown owner operation %q", c.Op)
		}
		if opErr != nil {
			r.OK = false
			r.Error = opErr.Error()
		}
		if err := out.Encode(r); err != nil {
			return err
		}
	}
	return in.Err()
}

func runSpoof(inc uint64) error {
	_, _, err := unix.Syscall6(unix.SYS_PRCTL, 0x4b554246, 0x1234, 0x5678, uintptr(inc), 0, 0)
	// Original prctl returns EINVAL if no hook consumes it; do not infer trust
	// from its return value. Parent examines pinned state while we remain alive.
	if err != 0 && err != syscall.EINVAL && err != syscall.EPERM {
		return err
	}
	if e := json.NewEncoder(os.Stdout).Encode(reply{OK: true}); e != nil {
		return e
	}
	_, e := bufio.NewReader(os.Stdin).ReadByte()
	return e
}

func postExec() error {
	// No fence/library call: CLOEXEC descriptors are gone. Remain alive so the
	// controller distinguishes exec arming from a later process-exit arm.
	if err := json.NewEncoder(os.Stdout).Encode(reply{OK: true}); err != nil {
		return err
	}
	_, err := bufio.NewReader(os.Stdin).ReadByte()
	return err
}
