// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// KernelIdentity is one exact kernel build: the architecture (Go GOARCH), the
// release (uname -r), the sha256 of the vmlinux BTF (/sys/kernel/btf/vmlinux,
// lowercase hex) and the vmlinux GNU build-id (/sys/kernel/notes, lowercase
// hex). The BTF digest alone does not identify a build. SharedProductKernel
// and AdmitKernel return the running kernel's identity, for status and logs;
// it is never matched against a list.
type KernelIdentity struct {
	Arch    string
	Release string
	BTF     string
	BuildID string
}

// Kernel check names, the KernelCheckError.Check of a failed check.
const (
	KernelCheckArch      = "arch"
	KernelCheckBTF       = "btf"
	KernelCheckRelease   = "release"
	KernelCheckBuildID   = "build-id"
	KernelCheckBPFLSM    = "bpf-lsm"
	KernelCheckFtrace    = "ftrace"
	KernelCheckLivepatch = "livepatch"
)

// KernelCheckError is a failed kernel check: Check names it, Err is why. A
// read failure is a failed check too, never a pass. SharedProductKernel,
// AdmitKernel and CheckKernelRuntime report it.
type KernelCheckError struct {
	Check string
	Err   error
}

func (e *KernelCheckError) Error() string {
	if e == nil {
		return "kernel check failed"
	}
	if e.Err == nil {
		return "kernel check " + e.Check + " failed"
	}
	return e.Err.Error()
}

func (e *KernelCheckError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func kernelCheckFailed(check string, err error) *KernelCheckError {
	return &KernelCheckError{Check: check, Err: err}
}

// AdmitKernel runs the checks of the product kernel gate (SharedProductKernel)
// on the running kernel, for the other BPF LSM sections of an agent: the
// architecture is amd64, the vmlinux BTF sha256 is readable lowercase hex,
// the release is non-empty, the GNU build-id is lowercase hex, bpf is in the
// active LSM list, ftrace is enabled and the kernel is not livepatched. Every
// kernel is admitted the same way, on these checks; no build list is
// consulted. It returns the running kernel's identity. Every failure, a read
// failure included, is a bare *KernelCheckError: the caller must then not
// enforce.
func AdmitKernel() (KernelIdentity, error) {
	return admitKernelIdentity(sharedProductKernelProbes)
}

// admitKernelIdentity runs AdmitKernel through probe p, in order:
// architecture, BTF digest, release, build-id (an identity failure is
// reported as such), then bpf LSM, ftrace and livepatch.
func admitKernelIdentity(p sharedProductKernelProbe) (KernelIdentity, error) {
	if arch := p.arch(); arch != sharedProductImageArch {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckArch, fmt.Errorf("the shared exec engine requires %s, running on %s", sharedProductImageArch, arch))
	}
	digest, err := p.btfDigest()
	if err != nil {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckBTF, fmt.Errorf("kernel BTF: %w", err))
	}
	if !isLowerHex(digest, 64) {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckBTF, fmt.Errorf("kernel BTF sha256 %q is not lowercase hex", digest))
	}
	release, err := p.release()
	if err != nil {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckRelease, fmt.Errorf("kernel release: %w", err))
	}
	if release = strings.TrimSpace(release); release == "" {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckRelease, fmt.Errorf("empty kernel release"))
	}
	buildID, err := p.buildID()
	if err != nil {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckBuildID, fmt.Errorf("kernel build-id: %w", err))
	}
	if !isLowerHex(buildID, 0) {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckBuildID, fmt.Errorf("kernel build-id %q is not lowercase hex", buildID))
	}
	lsm, err := p.lsm()
	if err != nil {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckBPFLSM, fmt.Errorf("LSM list: %w", err))
	}
	if err := requireBPFLSM(lsm); err != nil {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckBPFLSM, err)
	}
	if err := checkSharedProductKernelRuntime(p); err != nil {
		return KernelIdentity{}, err
	}
	return KernelIdentity{Arch: sharedProductImageArch, Release: release, BTF: digest, BuildID: buildID}, nil
}

// CheckKernelRuntime re-reads the two kernel controls that can change while
// the agent runs: ftrace_enabled and the livepatch taint. Call it at every
// status computation; it is never cached. A failure is a *KernelCheckError
// (KernelCheckFtrace or KernelCheckLivepatch) and means NotReady: with ftrace
// off, BPF trampolines (fentry/fexit and BPF LSM) stop running, so a deny
// becomes an allow. It is detected here, not guarded.
func CheckKernelRuntime() error {
	return checkSharedProductKernelRuntime(sharedProductKernelProbes)
}

// isLowerHex reports whether s is non-empty lowercase hex of n characters
// (any even length if n is 0).
func isLowerHex(s string, n int) bool {
	if s == "" || len(s)%2 != 0 || (n != 0 && len(s) != n) || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
