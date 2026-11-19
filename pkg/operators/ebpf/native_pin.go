// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// The caller retains the directory FD until S has opened and verified its own
// handle. Pinning through procfd keeps basename resolution beneath that exact
// directory; it does not prove that the mount is visible in S's namespace.
func nativeRecoveryPinDirectory(dirFD int) error {
	var st unix.Stat_t
	var fs unix.Statfs_t
	if dirFD < 0 || unix.Fstat(dirFD, &st) != nil || unix.Fstatfs(dirFD, &fs) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) ||
		st.Mode&0o077 != 0 || fs.Type != unix.BPF_FS_MAGIC {
		return fmt.Errorf("recovery pin directory is not a private owned bpffs directory")
	}
	return nil
}

type nativePinnedLink struct {
	link link.Link
	name string
	want link.Info
}

func (p *nativePinnedLink) FD() int {
	fd, ok := p.link.(interface{ FD() int })
	if !ok {
		return -1
	}
	return fd.FD()
}

func (p *nativePinnedLink) PinName() string { return p.name }

func (p *nativePinnedLink) Check() error {
	return nativeAttachmentCheck(p.name, p.want.ID, p.want.Type, p.want.Program, p.link.Info)()
}

func (p *nativePinnedLink) Close() error { return p.link.Close() }

func nativePinAndVerifyLink(original link.Link, name, path string, want *link.Info,
	load func(string, *ebpf.LoadPinOptions) (link.Link, error),
) (operators.NativePinnedLink, error) {
	if original == nil || want == nil || want.ID == 0 || want.Program == 0 ||
		want.Type != link.TracingType {
		return nil, fmt.Errorf("invalid recovery link identity")
	}
	pinned, ok := original.(interface{ IsPinned() bool })
	if !ok || pinned.IsPinned() {
		return nil, fmt.Errorf("recovery link already pinned or pin state unavailable")
	}
	check := nativeAttachmentCheck(name, want.ID, want.Type, want.Program, original.Info)
	if err := check(); err != nil {
		return nil, err
	}
	if err := original.Pin(path); err != nil {
		return nil, fmt.Errorf("pin recovery link %s: %w", name, err)
	}
	// Do not remove an ambiguous pin on error. Retain it for S/operator
	// containment; a later owner must reconcile the exact path and link ID.
	reopened, err := load(path, nil)
	if err != nil {
		return nil, fmt.Errorf("reopen pinned recovery link %s (pin retained): %w", name, err)
	}
	if reopened == nil {
		return nil, fmt.Errorf("reopen pinned recovery link %s returned nil (pin retained)", name)
	}
	lease := &nativePinnedLink{link: reopened, name: name, want: *want}
	if err := lease.Check(); err != nil {
		_ = lease.Close()
		return nil, fmt.Errorf("verify pinned recovery link %s (pin retained): %w", name, err)
	}
	if lease.FD() < 0 {
		_ = lease.Close()
		return nil, fmt.Errorf("pinned recovery link %s has no transferable FD (pin retained)", name)
	}
	return lease, nil
}

func newNativeRecoveryPin(original link.Link, name string, want *link.Info) func(int) (operators.NativePinnedLink, error) {
	var mu sync.Mutex
	var attempted bool
	frozen := *want
	return func(dirFD int) (operators.NativePinnedLink, error) {
		mu.Lock()
		defer mu.Unlock()
		if attempted {
			return nil, fmt.Errorf("recovery link %s pin already attempted", name)
		}
		if err := nativeRecoveryPinDirectory(dirFD); err != nil {
			return nil, err
		}
		attempted = true           // any syscall result can be ambiguous; never retry
		basename := name + ".link" // name is one of two admitted constants
		path := fmt.Sprintf("/proc/self/fd/%d/%s", dirFD, basename)
		return nativePinAndVerifyLink(original, basename, path, &frozen, link.LoadPinnedLink)
	}
}
