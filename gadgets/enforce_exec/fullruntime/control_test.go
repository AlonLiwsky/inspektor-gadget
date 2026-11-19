// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestControlWireSizes(t *testing.T) {
	for _, x := range []struct {
		name      string
		got, want uintptr
	}{
		{"config", unsafe.Sizeof(ControlConfig{}), 32},
		{"command", unsafe.Sizeof(ControlCommand{}), 32},
		{"health", unsafe.Sizeof(ControlHealth{}), 128},
		{"phase", unsafe.Sizeof(ControlPhase{}), 48},
		{"row", unsafe.Sizeof(ControlRow{}), 24},
	} {
		if x.got != x.want {
			t.Errorf("%s: %d != %d", x.name, x.got, x.want)
		}
	}
}

func TestControlThreadAffinityAndFailure(t *testing.T) {
	var tid int
	w, err := startControlThread(func() error { tid = unix.Gettid(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if err = w.do(context.Background(), func() error {
			if unix.Gettid() != tid {
				return errors.New("thread changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	err = w.do(context.Background(), func() error { panic("fail closed") })
	if err == nil {
		t.Fatal("panic accepted")
	}
	if err = w.close(); err == nil {
		t.Fatal("worker failure lost")
	}
	if err = w.do(context.Background(), func() error { t.Error("closed worker ran"); return nil }); err == nil {
		t.Fatal("closed worker accepted")
	}
}

func TestControlCancellationJoinsAcceptedCall(t *testing.T) {
	w, err := startControlThread(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	entered, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- w.do(ctx, func() error { close(entered); <-release; return nil }) }()
	<-entered
	cancel()
	select {
	case <-result:
		t.Fatal("cancellation returned while command still running")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err = <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestControlCancelledQueueAndCloseJoin(t *testing.T) {
	w, err := startControlThread(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- w.do(context.Background(), func() error { close(entered); <-release; return nil }) }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = w.do(ctx, func() error { t.Error("cancelled command ran"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- w.close() }()
	select {
	case <-closed:
		t.Fatal("close did not join command")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestControlSetupFailure(t *testing.T) {
	for _, setup := range []func() error{func() error { return errors.New("setup") }, func() error { panic("setup") }} {
		if w, err := startControlThread(setup); err == nil || w != nil {
			t.Fatalf("got %v %v", w, err)
		}
	}
}
