// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// KernelIdentity is one exact kernel build: the architecture (Go GOARCH), the
// release (uname -r), the sha256 of the vmlinux BTF (/sys/kernel/btf/vmlinux,
// lowercase hex) and the vmlinux GNU build-id (/sys/kernel/notes, lowercase
// hex). The BTF digest alone does not identify a build.
type KernelIdentity struct {
	Arch    string
	Release string
	BTF     string
	BuildID string
}

// Kernel check names, the KernelCheckError.Check of a failed check.
const (
	KernelCheckQualifiedList = "qualified-list" // the caller's list is empty or malformed
	KernelCheckArch          = "arch"
	KernelCheckBTF           = "btf"
	KernelCheckRelease       = "release"
	KernelCheckBuildID       = "build-id"
	KernelCheckBPFLSM        = "bpf-lsm"
	KernelCheckFtrace        = "ftrace"
	KernelCheckLivepatch     = "livepatch"
)

// KernelCheckError is a failed kernel check: Check names it, Err is why. A
// read failure is a failed check too, never a pass.
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

// QualifiedKernels returns the kernel builds the shared exec engine is
// qualified on (sharedProductPins), sorted by release. Callers may admit a
// subset of them, or other builds with their own posted evidence, through
// VerifyKernel; configuration must never add an entry.
func QualifiedKernels() []KernelIdentity {
	out := make([]KernelIdentity, 0, len(sharedProductIdentities))
	for _, id := range sharedProductIdentities {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b KernelIdentity) int { return strings.Compare(a.Release, b.Release) })
	return out
}

// VerifyKernel is the kernel identity check that gates the shared exec
// engine, for any caller with its own compiled-in qualified list. It admits
// the running kernel only if it is exactly one of qualified (architecture,
// BTF sha256, release and GNU build-id) and bpf is in the active LSM list,
// ftrace is enabled and the kernel is not livepatched. It returns the
// matching entry. Every failure, an empty or malformed list and every read
// failure included, is a *KernelCheckError: the caller must then not enforce.
func VerifyKernel(qualified []KernelIdentity) (KernelIdentity, error) {
	byBTF, err := kernelIdentitiesByBTF(qualified)
	if err != nil {
		return KernelIdentity{}, err
	}
	return verifyKernelIdentity(sharedProductKernelProbes, byBTF)
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

// sharedProductIdentities are sharedProductPins as kernel identities.
var sharedProductIdentities = func() map[string]KernelIdentity {
	out := make(map[string]KernelIdentity, len(sharedProductPins))
	for digest, pin := range sharedProductPins {
		out[digest] = KernelIdentity{Arch: "amd64", Release: pin.Release, BTF: digest, BuildID: pin.BuildID}
	}
	return out
}()

// kernelIdentitiesByBTF indexes a caller's qualified list by BTF digest. An
// entry with an empty field, a digest or build-id that is not lowercase hex,
// an Arch that is not a Go GOARCH value this package qualifies ("amd64",
// "arm64"; not the uname spelling "x86_64"), or a BTF digest listed twice is
// refused.
func kernelIdentitiesByBTF(qualified []KernelIdentity) (map[string]KernelIdentity, error) {
	out := make(map[string]KernelIdentity, len(qualified))
	for _, id := range qualified {
		if (id.Arch != "amd64" && id.Arch != "arm64") || id.Release == "" || !isLowerHex(id.BTF, 64) || !isLowerHex(id.BuildID, 0) {
			return nil, kernelCheckFailed(KernelCheckQualifiedList, fmt.Errorf("malformed qualified kernel %+v", id))
		}
		if _, dup := out[id.BTF]; dup {
			return nil, kernelCheckFailed(KernelCheckQualifiedList, fmt.Errorf("qualified kernel BTF %s listed twice", id.BTF))
		}
		out[id.BTF] = id
	}
	return out, nil
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

// verifyKernelIdentity runs the checks of VerifyKernel through probe p,
// in order: architecture, BTF digest, release, build-id, bpf LSM, then the
// runtime controls.
func verifyKernelIdentity(p sharedProductKernelProbe, qualified map[string]KernelIdentity) (KernelIdentity, error) {
	if len(qualified) == 0 {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckQualifiedList, fmt.Errorf("no qualified kernel builds"))
	}
	arch := p.arch()
	var archs []string
	for _, id := range qualified {
		if !slices.Contains(archs, id.Arch) {
			archs = append(archs, id.Arch)
		}
	}
	slices.Sort(archs)
	if !slices.Contains(archs, arch) {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckArch, fmt.Errorf("qualified kernels require %s, running on %s", strings.Join(archs, " or "), arch))
	}
	digest, err := p.btfDigest()
	if err != nil {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckBTF, fmt.Errorf("kernel BTF: %w", err))
	}
	id, ok := qualified[digest]
	if !ok || id.Arch != arch {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckBTF, fmt.Errorf("kernel BTF sha256 %s is not a qualified kernel build", digest))
	}
	release, err := p.release()
	if err != nil {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckRelease, fmt.Errorf("kernel release: %w", err))
	}
	if release != id.Release {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckRelease, fmt.Errorf("kernel release %q, the pinned BTF %s is %q", release, digest, id.Release))
	}
	buildID, err := p.buildID()
	if err != nil {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckBuildID, fmt.Errorf("kernel build-id: %w", err))
	}
	if buildID != id.BuildID {
		return KernelIdentity{}, kernelCheckFailed(KernelCheckBuildID, fmt.Errorf("kernel build-id %s, %s is pinned to %s", buildID, id.Release, id.BuildID))
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
	return id, nil
}
