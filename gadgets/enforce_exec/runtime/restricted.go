// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ErrRestrictedWorkload means the requested host-namespace exception cannot be
// justified. The caller may retain an existing strict binding; a rejected request
// never removes or changes that binding.
var ErrRestrictedWorkload = errors.New("workload is not eligible for the host namespace exception")

// WorkloadCredentials describes final workload credentials supplied by a trusted
// runtime owner. A snapshot of the container init alone is not sufficient.
type WorkloadCredentials struct {
	NoNewPrivileges bool
	Privileged      bool
	Effective       uint64
	Permitted       uint64
	Inheritable     uint64
	Ambient         uint64
	Bounding        uint64
}

// RestrictedWorkloadContract records guarantees made by the trusted owner, not
// facts that this controller can discover or enforce on future runtime requests.
type RestrictedWorkloadContract struct {
	// Includes later runtime exec requests; no entrant may gain host authority.
	// Descendant user namespaces do not themselves grant host capabilities.
	AllWorkloadEntriesRestricted bool
	// Excludes host process control and delegation to privileged host services.
	NoHostDelegation bool
}

// RestrictedWorkload requests an exception only for the actual host mount
// namespace. The owner authenticates host identity, associates the workload
// namespaces with the container, and guarantees the contract for its lifetime.
// Namespace files are borrowed for the call; the controller keeps its own copies
// of the mount namespaces until removal or program detachment.
type RestrictedWorkload struct {
	HostMountNamespace *os.File
	MountNamespace     *os.File
	UserNamespace      *os.File
	Credentials        WorkloadCredentials
	OwnerContract      RestrictedWorkloadContract
}

type namespaceIdentity struct {
	Device, Inode uint64
}

type namespaceRefs struct {
	host, mount     *os.File
	hostID, mountID namespaceIdentity
}

func (r *namespaceRefs) close() error {
	return errors.Join(r.host.Close(), r.mount.Close())
}

func (r *namespaceRefs) same(other *namespaceRefs) bool {
	return r.hostID == other.hostID && r.mountID == other.mountID
}

func (w RestrictedWorkload) validateCredentials() error {
	if !w.OwnerContract.AllWorkloadEntriesRestricted || !w.OwnerContract.NoHostDelegation {
		return fmt.Errorf("owner must guarantee all workload entries are restricted and cannot delegate to the host")
	}
	if w.Credentials.Privileged || !w.Credentials.NoNewPrivileges {
		return fmt.Errorf("requires an unprivileged workload with no_new_privs")
	}
	const forbidden = uint64(1<<unix.CAP_SYS_ADMIN | 1<<unix.CAP_SYS_PTRACE)
	c := w.Credentials
	if (c.Effective|c.Permitted|c.Inheritable|c.Ambient|c.Bounding)&forbidden != 0 {
		return fmt.Errorf("SYS_ADMIN and SYS_PTRACE must be absent from every workload capability set")
	}
	return nil
}

// duplicateNamespace uses RawConn.Control to prevent a concurrent File.Close
// from reusing the descriptor between acquisition and duplication.
func duplicateNamespace(file *os.File, kind int) (*os.File, namespaceIdentity, error) {
	if file == nil {
		return nil, namespaceIdentity{}, fmt.Errorf("missing namespace descriptor")
	}
	conn, err := file.SyscallConn()
	if err != nil {
		return nil, namespaceIdentity{}, err
	}
	fd := -1
	var duplicateErr error
	if err := conn.Control(func(original uintptr) {
		fd, duplicateErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0)
	}); err != nil {
		return nil, namespaceIdentity{}, err
	}
	if duplicateErr != nil {
		return nil, namespaceIdentity{}, duplicateErr
	}
	owned := os.NewFile(uintptr(fd), "enforce-exec-namespace")
	id, err := namespaceInfo(owned, kind)
	if err != nil {
		owned.Close()
		return nil, namespaceIdentity{}, err
	}
	return owned, id, nil
}

func namespaceInfo(file *os.File, kind int) (namespaceIdentity, error) {
	actual, err := unix.IoctlRetInt(int(file.Fd()), unix.NS_GET_NSTYPE)
	if err != nil {
		return namespaceIdentity{}, fmt.Errorf("checking namespace descriptor: %w", err)
	}
	if actual != kind {
		return namespaceIdentity{}, fmt.Errorf("namespace type %d does not match required type %d", actual, kind)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return namespaceIdentity{}, err
	}
	if stat.Ino == 0 || stat.Ino > uint64(^uint32(0)) {
		return namespaceIdentity{}, fmt.Errorf("namespace inode cannot be represented by the kernel namespace ID")
	}
	return namespaceIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func namespaceOwner(file *os.File) (namespaceIdentity, error) {
	fd, err := unix.IoctlRetInt(int(file.Fd()), unix.NS_GET_USERNS)
	if err != nil {
		return namespaceIdentity{}, fmt.Errorf("reading namespace owner: %w", err)
	}
	owner := os.NewFile(uintptr(fd), "enforce-exec-namespace-owner")
	defer owner.Close()
	return namespaceInfo(owner, unix.CLONE_NEWUSER)
}

func prepareRestricted(w RestrictedWorkload) (_ *namespaceRefs, result error) {
	defer func() {
		if result != nil {
			result = fmt.Errorf("%w: %w", ErrRestrictedWorkload, result)
		}
	}()
	if err := w.validateCredentials(); err != nil {
		return nil, err
	}
	host, hostID, err := duplicateNamespace(w.HostMountNamespace, unix.CLONE_NEWNS)
	if err != nil {
		return nil, fmt.Errorf("host mount namespace: %w", err)
	}
	defer func() {
		if result != nil {
			host.Close()
		}
	}()
	mount, mountID, err := duplicateNamespace(w.MountNamespace, unix.CLONE_NEWNS)
	if err != nil {
		return nil, fmt.Errorf("workload mount namespace: %w", err)
	}
	defer func() {
		if result != nil {
			mount.Close()
		}
	}()
	if hostID == mountID {
		return nil, fmt.Errorf("workload must not share the host mount namespace")
	}
	user, userID, err := duplicateNamespace(w.UserNamespace, unix.CLONE_NEWUSER)
	if err != nil {
		return nil, fmt.Errorf("workload user namespace: %w", err)
	}
	defer user.Close()
	hostOwner, err := namespaceOwner(host)
	if err != nil {
		return nil, err
	}
	mountOwner, err := namespaceOwner(mount)
	if err != nil {
		return nil, err
	}
	if userID != hostOwner || mountOwner != hostOwner {
		return nil, fmt.Errorf("initial workload and mount namespace must belong to the host user namespace")
	}
	return &namespaceRefs{host: host, mount: mount, hostID: hostID, mountID: mountID}, nil
}

// BindRestricted enables the host mount namespace exception for an explicitly
// admitted target. Use a startup operator after this controller to include it in
// readiness. Changing an existing binding's scope requires explicit Unbind.
func (b *Bindings) BindRestricted(c ContainerIdentity, workload RestrictedWorkload) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped {
		return b.recordError(fmt.Errorf("binding controller is not running"))
	}
	if err := c.validate(); err != nil {
		return b.recordError(err)
	}
	if !b.hostNamespaceSupported {
		return b.recordError(fmt.Errorf("%w: gadget image does not support the host namespace exception", ErrRestrictedWorkload))
	}
	refs, err := prepareRestricted(workload)
	if err != nil {
		return b.recordError(err)
	}
	return b.recordError(b.bindWithScope(c, refs))
}
