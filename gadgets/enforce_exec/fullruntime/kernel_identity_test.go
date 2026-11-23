// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestAdmitKernel: every kernel is admitted the same way, on its checks:
// any build that passes them returns its own identity; a wrong
// architecture, a failed control and an unreadable or malformed identity
// are refused with a bare *KernelCheckError (it does not wrap
// ErrSharedNativeUnavailable).
func TestAdmitKernel(t *testing.T) {
	for _, k := range []*fakeProductKernel{arbitraryProductKernel(), otherProductKernel()} {
		useProductKernel(t, k)
		want := KernelIdentity{Arch: "amd64", Release: k.release, BTF: k.digest, BuildID: k.buildID}
		if got, err := AdmitKernel(); err != nil || got != want {
			t.Fatalf("%s: %+v %v", k.release, got, err)
		}
	}
	k := arbitraryProductKernel()
	k.release = " 7.0.0-43-generic\n"
	useProductKernel(t, k)
	if got, err := AdmitKernel(); err != nil || got.Release != "7.0.0-43-generic" {
		t.Errorf("release with spaces: %+v %v", got, err)
	}
	readErr := errors.New("read failed")
	for _, tc := range []struct {
		name   string
		mutate func(*fakeProductKernel)
		check  string
	}{
		{"other arch", func(k *fakeProductKernel) { k.arch = "arm64" }, KernelCheckArch},
		{"uname arch spelling", func(k *fakeProductKernel) { k.arch = "x86_64" }, KernelCheckArch},
		{"no bpf LSM", func(k *fakeProductKernel) { k.lsm = "selinux" }, KernelCheckBPFLSM},
		{"LSM read failure", func(k *fakeProductKernel) { k.lsmErr = readErr }, KernelCheckBPFLSM},
		{"ftrace off", func(k *fakeProductKernel) { k.ftrace = "0\n" }, KernelCheckFtrace},
		{"livepatched", func(k *fakeProductKernel) { k.tainted = fmt.Sprint(taintLivepatch) }, KernelCheckLivepatch},
		{"BTF read failure", func(k *fakeProductKernel) { k.digestErr = readErr }, KernelCheckBTF},
		{"uppercase BTF", func(k *fakeProductKernel) { k.digest = strings.ToUpper(strings.Repeat("ab", 32)) }, KernelCheckBTF},
		{"short BTF", func(k *fakeProductKernel) { k.digest = "ab" }, KernelCheckBTF},
		{"release read failure", func(k *fakeProductKernel) { k.releaseErr = readErr }, KernelCheckRelease},
		{"empty release", func(k *fakeProductKernel) { k.release = " " }, KernelCheckRelease},
		{"build-id read failure", func(k *fakeProductKernel) { k.buildIDErr = readErr }, KernelCheckBuildID},
		{"empty build-id", func(k *fakeProductKernel) { k.buildID = "" }, KernelCheckBuildID},
		{"uppercase build-id", func(k *fakeProductKernel) { k.buildID = strings.ToUpper(k.buildID) }, KernelCheckBuildID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := arbitraryProductKernel()
			tc.mutate(k)
			useProductKernel(t, k)
			got, err := AdmitKernel()
			var kerr *KernelCheckError
			ok := errors.As(err, &kerr)
			if !ok || kerr.Check != tc.check || errors.Is(err, ErrSharedNativeUnavailable) || got != (KernelIdentity{}) {
				t.Fatalf("got %+v err %v, want a bare *KernelCheckError %q", got, err, tc.check)
			}
		})
	}
}

// TestCheckKernelRuntime: ftrace and livepatch are re-read at each call
// (never cached) and every failure, a read failure included, is typed.
func TestCheckKernelRuntime(t *testing.T) {
	k := arbitraryProductKernel()
	useProductKernel(t, k)
	reads := 0
	sharedProductKernelProbes.ftrace = func() (string, error) { reads++; return k.ftrace, k.ftraceErr }
	if err := CheckKernelRuntime(); err != nil {
		t.Fatalf("healthy: %v", err)
	}
	steps := []struct {
		ftrace, tainted string
		ftraceErr       error
		check           string
	}{
		{"0\n", "0\n", nil, KernelCheckFtrace},
		{"1\n", "0\n", nil, ""},
		{"1\n", "32768\n", nil, KernelCheckLivepatch},
		{"", "0\n", os.ErrPermission, KernelCheckFtrace},
		{"1\n", "0\n", nil, ""},
	}
	for i, s := range steps {
		k.ftrace, k.tainted, k.ftraceErr = s.ftrace, s.tainted, s.ftraceErr
		err := CheckKernelRuntime()
		var kerr *KernelCheckError
		switch {
		case s.check == "" && err != nil:
			t.Fatalf("step %d: %v", i, err)
		case s.check != "" && (!errors.As(err, &kerr) || kerr.Check != s.check):
			t.Fatalf("step %d: %v, want check %q", i, err, s.check)
		}
	}
	if reads != len(steps)+1 {
		t.Fatalf("ftrace read %d times in %d calls", reads, len(steps)+1)
	}
}

func TestKernelCheckErrorNilSafe(t *testing.T) {
	var nilErr *KernelCheckError
	if got := nilErr.Error(); got != "kernel check failed" {
		t.Fatalf("nil receiver Error() = %q", got)
	}
	if nilErr.Unwrap() != nil {
		t.Fatal("nil receiver Unwrap() != nil")
	}
	e := &KernelCheckError{Check: KernelCheckBTF}
	if got := e.Error(); got != "kernel check "+KernelCheckBTF+" failed" {
		t.Fatalf("nil Err Error() = %q", got)
	}
}
