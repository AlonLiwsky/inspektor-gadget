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

// TestQualifiedKernels: the exported list is exactly the shared product
// pins, sorted by release, and a returned slice cannot change the pins.
func TestQualifiedKernels(t *testing.T) {
	got := QualifiedKernels()
	if len(got) != len(sharedProductPins) {
		t.Fatalf("%d qualified kernels, %d pins", len(got), len(sharedProductPins))
	}
	for i, id := range got {
		pin, ok := sharedProductPins[id.BTF]
		if !ok || id.Arch != "amd64" || id.Release != pin.Release || id.BuildID != pin.BuildID {
			t.Errorf("entry %d %+v does not match its pin %+v", i, id, pin)
		}
		if i > 0 && got[i-1].Release >= id.Release {
			t.Errorf("not sorted by release: %q before %q", got[i-1].Release, id.Release)
		}
	}
	got[0].BuildID = strings.Repeat("0", 40)
	if QualifiedKernels()[0].BuildID == got[0].BuildID {
		t.Fatal("the returned list aliases the pins")
	}
	if _, err := kernelIdentitiesByBTF(QualifiedKernels()); err != nil {
		t.Fatalf("the exec pins are a well-formed list: %v", err)
	}
}

// TestVerifyKernel: each qualified build passes and returns its entry; every
// other identity, control or list is a *KernelCheckError naming the check,
// never a pass. Read failures are refusals too.
func TestVerifyKernel(t *testing.T) {
	all := QualifiedKernels()
	for _, want := range all {
		useProductKernel(t, pinnedProductKernel(want.BTF))
		got, err := VerifyKernel(all)
		if err != nil || got != want {
			t.Fatalf("%s: %+v %v", want.Release, got, err)
		}
	}
	first, second := all[0], all[1]
	readErr := errors.New("read failed")
	cases := []struct {
		name      string
		qualified []KernelIdentity
		mutate    func(*fakeProductKernel)
		check     string
		reason    string
	}{
		{"nil list", nil, nil, KernelCheckQualifiedList, "no qualified kernel builds"},
		{"empty list", []KernelIdentity{}, nil, KernelCheckQualifiedList, "no qualified kernel builds"},
		{"section admits only the other build", []KernelIdentity{second}, nil, KernelCheckBTF, "not a qualified kernel build"},
		{"entry without build-id", []KernelIdentity{{Arch: "amd64", Release: first.Release, BTF: first.BTF}}, nil, KernelCheckQualifiedList, "malformed"},
		{"entry without arch", []KernelIdentity{{Release: first.Release, BTF: first.BTF, BuildID: first.BuildID}}, nil, KernelCheckQualifiedList, "malformed"},
		{"entry without release", []KernelIdentity{{Arch: "amd64", BTF: first.BTF, BuildID: first.BuildID}}, nil, KernelCheckQualifiedList, "malformed"},
		{"wildcard BTF", []KernelIdentity{{Arch: "amd64", Release: first.Release, BTF: "*", BuildID: first.BuildID}}, nil, KernelCheckQualifiedList, "malformed"},
		{"uppercase BTF entry", []KernelIdentity{{Arch: "amd64", Release: first.Release, BTF: strings.ToUpper(first.BTF), BuildID: first.BuildID}}, nil, KernelCheckQualifiedList, "malformed"},
		{"short BTF entry", []KernelIdentity{{Arch: "amd64", Release: first.Release, BTF: first.BTF[:62], BuildID: first.BuildID}}, nil, KernelCheckQualifiedList, "malformed"},
		{"uname arch spelling", []KernelIdentity{{Arch: "x86_64", Release: first.Release, BTF: first.BTF, BuildID: first.BuildID}}, nil, KernelCheckQualifiedList, "malformed"},
		{"non-hex build-id entry", []KernelIdentity{{Arch: "amd64", Release: first.Release, BTF: first.BTF, BuildID: "zz"}}, nil, KernelCheckQualifiedList, "malformed"},
		{"duplicate BTF", []KernelIdentity{first, first}, nil, KernelCheckQualifiedList, "listed twice"},
		{"other arch", all, func(k *fakeProductKernel) { k.arch = "arm64" }, KernelCheckArch, "require amd64, running on arm64"},
		{"entry arch differs", []KernelIdentity{first, {Arch: "arm64", Release: second.Release, BTF: second.BTF, BuildID: second.BuildID}}, func(k *fakeProductKernel) { k.arch = "arm64" }, KernelCheckBTF, "not a qualified"},
		{"unlisted BTF", all, func(k *fakeProductKernel) { k.digest = strings.Repeat("0", 64) }, KernelCheckBTF, "not a qualified"},
		{"BTF read failure", all, func(k *fakeProductKernel) { k.digestErr = os.ErrPermission }, KernelCheckBTF, "kernel BTF"},
		{"release of the other build", all, func(k *fakeProductKernel) { k.release = second.Release }, KernelCheckRelease, "kernel release"},
		{"release read failure", all, func(k *fakeProductKernel) { k.releaseErr = readErr }, KernelCheckRelease, "read failed"},
		{"build-id of the other build", all, func(k *fakeProductKernel) { k.buildID = second.BuildID }, KernelCheckBuildID, "build-id"},
		{"build-id read failure", all, func(k *fakeProductKernel) { k.buildIDErr = readErr }, KernelCheckBuildID, "read failed"},
		{"no bpf LSM", all, func(k *fakeProductKernel) { k.lsm = "lockdown,capability,selinux" }, KernelCheckBPFLSM, "BPF LSM not active"},
		{"LSM read failure", all, func(k *fakeProductKernel) { k.lsmErr = readErr }, KernelCheckBPFLSM, "read failed"},
		{"ftrace off", all, func(k *fakeProductKernel) { k.ftrace = "0\n" }, KernelCheckFtrace, "ftrace is not enabled"},
		{"ftrace read failure", all, func(k *fakeProductKernel) { k.ftraceErr = readErr }, KernelCheckFtrace, "read failed"},
		{"livepatched", all, func(k *fakeProductKernel) { k.tainted = fmt.Sprint(taintLivepatch | 1<<12) }, KernelCheckLivepatch, "livepatched"},
		{"malformed taint", all, func(k *fakeProductKernel) { k.tainted = "x" }, KernelCheckLivepatch, "kernel taint"},
		{"taint read failure", all, func(k *fakeProductKernel) { k.taintedErr = readErr }, KernelCheckLivepatch, "read failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := pinnedProductKernel(first.BTF)
			if tc.mutate != nil {
				tc.mutate(k)
			}
			useProductKernel(t, k)
			got, err := VerifyKernel(tc.qualified)
			var kerr *KernelCheckError
			if !errors.As(err, &kerr) || kerr.Check != tc.check || !strings.Contains(err.Error(), tc.reason) || got != (KernelIdentity{}) {
				t.Fatalf("got %+v err %v, want check %q with %q", got, err, tc.check, tc.reason)
			}
			if errors.Is(err, ErrSharedNativeUnavailable) {
				t.Fatalf("the exported check is not the exec engine's refusal: %v", err)
			}
		})
	}
	// A taint other than TAINT_LIVEPATCH (EKS AMIs: 12288) is admitted.
	k := pinnedProductKernel(first.BTF)
	k.tainted = "12288\n"
	useProductKernel(t, k)
	if _, err := VerifyKernel(all); err != nil {
		t.Fatalf("out-of-tree taint alone: %v", err)
	}
}

// TestAdmitKernel: every kernel is admitted the same way, on its checks: a
// pinned AL2023 build and any other build that passes them return their own
// identity; a wrong architecture, a failed control and an unreadable or
// malformed identity are refused with a bare *KernelCheckError (it does not
// wrap ErrSharedNativeUnavailable).
func TestAdmitKernel(t *testing.T) {
	all := QualifiedKernels()
	for _, want := range all {
		useProductKernel(t, pinnedProductKernel(want.BTF))
		if got, err := AdmitKernel(); err != nil || got != want {
			t.Fatalf("%s: %+v %v", want.Release, got, err)
		}
	}
	first, second := all[0], all[1]
	for name, mutate := range map[string]func(*fakeProductKernel){
		"unlisted BTF":                func(k *fakeProductKernel) { k.digest = strings.Repeat("0", 64) },
		"release of the other build":  func(k *fakeProductKernel) { k.release = second.Release },
		"build-id of the other build": func(k *fakeProductKernel) { k.buildID = second.BuildID },
		"release with spaces":         func(k *fakeProductKernel) { k.release = " 7.0.0-43-generic\n" },
	} {
		k := pinnedProductKernel(first.BTF)
		mutate(k)
		useProductKernel(t, k)
		got, err := AdmitKernel()
		want := KernelIdentity{Arch: "amd64", Release: strings.TrimSpace(k.release), BTF: k.digest, BuildID: k.buildID}
		if err != nil || got != want {
			t.Errorf("%s: %+v %v, want %+v", name, got, err, want)
		}
	}
	readErr := errors.New("read failed")
	unpinned := strings.Repeat("0", 64)
	for _, tc := range []struct {
		name   string
		mutate func(*fakeProductKernel)
		check  string
	}{
		{"other arch", func(k *fakeProductKernel) { k.arch = "arm64" }, KernelCheckArch},
		{"uname arch spelling", func(k *fakeProductKernel) { k.arch = "x86_64" }, KernelCheckArch},
		{"no bpf LSM, pinned", func(k *fakeProductKernel) { k.lsm = "selinux" }, KernelCheckBPFLSM},
		{"no bpf LSM, unpinned", func(k *fakeProductKernel) { k.digest, k.lsm = unpinned, "selinux" }, KernelCheckBPFLSM},
		{"LSM read failure", func(k *fakeProductKernel) { k.lsmErr = readErr }, KernelCheckBPFLSM},
		{"ftrace off, unpinned", func(k *fakeProductKernel) { k.digest, k.ftrace = unpinned, "0\n" }, KernelCheckFtrace},
		{"livepatched, unpinned", func(k *fakeProductKernel) { k.digest, k.tainted = unpinned, fmt.Sprint(taintLivepatch) }, KernelCheckLivepatch},
		{"BTF read failure", func(k *fakeProductKernel) { k.digestErr = readErr }, KernelCheckBTF},
		{"uppercase BTF", func(k *fakeProductKernel) { k.digest = strings.ToUpper(strings.Repeat("ab", 32)) }, KernelCheckBTF},
		{"short BTF", func(k *fakeProductKernel) { k.digest = "ab" }, KernelCheckBTF},
		{"release read failure", func(k *fakeProductKernel) { k.digest, k.releaseErr = unpinned, readErr }, KernelCheckRelease},
		{"empty release", func(k *fakeProductKernel) { k.digest, k.release = unpinned, " " }, KernelCheckRelease},
		{"build-id read failure", func(k *fakeProductKernel) { k.buildIDErr = readErr }, KernelCheckBuildID},
		{"empty build-id", func(k *fakeProductKernel) { k.digest, k.buildID = unpinned, "" }, KernelCheckBuildID},
		{"uppercase build-id", func(k *fakeProductKernel) { k.buildID = strings.ToUpper(k.buildID) }, KernelCheckBuildID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := pinnedProductKernel(first.BTF)
			tc.mutate(k)
			useProductKernel(t, k)
			got, err := AdmitKernel()
			kerr, ok := err.(*KernelCheckError)
			if !ok || kerr.Check != tc.check || errors.Is(err, ErrSharedNativeUnavailable) || got != (KernelIdentity{}) {
				t.Fatalf("got %+v err %v, want a bare *KernelCheckError %q", got, err, tc.check)
			}
		})
	}
}

// TestCheckKernelRuntime: ftrace and livepatch are re-read at each call
// (never cached) and every failure, a read failure included, is typed.
func TestCheckKernelRuntime(t *testing.T) {
	k := pinnedProductKernel(QualifiedKernels()[0].BTF)
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
