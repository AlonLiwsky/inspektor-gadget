// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

func eligibleCredentials() RestrictedWorkload {
	return RestrictedWorkload{
		Credentials: WorkloadCredentials{NoNewPrivileges: true},
		OwnerContract: RestrictedWorkloadContract{
			AllWorkloadEntriesRestricted: true,
			NoHostDelegation:             true,
		},
	}
}

func TestRestrictedCredentialsRequireDurableOwnerContract(t *testing.T) {
	valid := eligibleCredentials()
	require.NoError(t, valid.validateCredentials())
	for _, name := range []string{"future entrants", "host delegation", "no new privileges", "privileged"} {
		t.Run(name, func(t *testing.T) {
			w := valid
			switch name {
			case "future entrants":
				w.OwnerContract.AllWorkloadEntriesRestricted = false
			case "host delegation":
				w.OwnerContract.NoHostDelegation = false
			case "no new privileges":
				w.Credentials.NoNewPrivileges = false
			case "privileged":
				w.Credentials.Privileged = true
			}
			_, err := prepareRestricted(w)
			require.ErrorIs(t, err, ErrRestrictedWorkload)
		})
	}
	for _, capability := range []uint{unix.CAP_SYS_ADMIN, unix.CAP_SYS_PTRACE} {
		for _, set := range []string{"effective", "permitted", "inheritable", "ambient", "bounding"} {
			t.Run(set, func(t *testing.T) {
				w := valid
				value := uint64(1) << capability
				switch set {
				case "effective":
					w.Credentials.Effective = value
				case "permitted":
					w.Credentials.Permitted = value
				case "inheritable":
					w.Credentials.Inheritable = value
				case "ambient":
					w.Credentials.Ambient = value
				case "bounding":
					w.Credentials.Bounding = value
				}
				require.Error(t, w.validateCredentials(), "a capability outside CapEff still prevents eligibility")
			})
		}
	}
}

func TestNamespaceDescriptorsAreTypedAndOwned(t *testing.T) {
	mount, err := os.Open("/proc/self/ns/mnt")
	require.NoError(t, err)
	t.Cleanup(func() { mount.Close() })
	owned, id, err := duplicateNamespace(mount, unix.CLONE_NEWNS)
	require.NoError(t, err)
	t.Cleanup(func() { owned.Close() })
	require.NotZero(t, id.Inode)
	_, _, err = duplicateNamespace(mount, unix.CLONE_NEWUSER)
	require.ErrorContains(t, err, "namespace type")
	ordinary, err := os.Open("/proc/self/status")
	require.NoError(t, err)
	defer ordinary.Close()
	_, _, err = duplicateNamespace(ordinary, unix.CLONE_NEWNS)
	require.ErrorContains(t, err, "checking namespace descriptor")
	_, _, err = duplicateNamespace(nil, unix.CLONE_NEWNS)
	require.Error(t, err)
	require.NoError(t, mount.Close())
	_, err = owned.Stat()
	require.NoError(t, err, "caller closure must not release the owned namespace reference")
	_, _, err = duplicateNamespace(mount, unix.CLONE_NEWNS)
	require.Error(t, err, "closed files cannot be admitted")
}

func TestRestrictedRejectionRetainsExistingStrictBinding(t *testing.T) {
	b, m := controller()
	c := identity(1)
	require.NoError(t, b.Bind(c))
	require.Zero(t, m.values[c.CgroupID], "strict membership never encodes a namespace exemption")
	require.NoError(t, b.Ready(nil))
	require.ErrorIs(t, b.BindRestricted(c, RestrictedWorkload{}), ErrRestrictedWorkload)
	require.Equal(t, 1, b.Status().Bound)
	require.Zero(t, b.Status().RestrictedBindings)
	mount, err := os.Open("/proc/self/ns/mnt")
	require.NoError(t, err)
	defer mount.Close()
	w := eligibleCredentials()
	w.HostMountNamespace, w.MountNamespace = mount, mount
	require.ErrorContains(t, b.BindRestricted(c, w), "must not share the host mount namespace")
	_, err = mount.Stat()
	require.NoError(t, err, "rejection must not close borrowed files")
	require.Zero(t, m.values[c.CgroupID])
	require.Equal(t, 1, b.Status().Bound)
}

// ownedRefsForTest exercises ownership after eligibility validation. Distinct
// namespace eligibility itself is covered by the privileged runtime tests.
func ownedRefsForTest(t *testing.T) *namespaceRefs {
	t.Helper()
	file, err := os.Open("/proc/self/ns/mnt")
	require.NoError(t, err)
	defer file.Close()
	host, hostID, err := duplicateNamespace(file, unix.CLONE_NEWNS)
	require.NoError(t, err)
	mount, mountID, err := duplicateNamespace(file, unix.CLONE_NEWNS)
	require.NoError(t, err)
	return &namespaceRefs{host: host, mount: mount, hostID: hostID, mountID: mountID}
}

func requireRefsClosed(t *testing.T, refs *namespaceRefs) {
	t.Helper()
	_, err := refs.host.Stat()
	require.ErrorIs(t, err, os.ErrClosed)
	_, err = refs.mount.Stat()
	require.ErrorIs(t, err, os.ErrClosed)
}

func TestRestrictedBindingOwnershipAndScopeChanges(t *testing.T) {
	b, m := controller()
	c := identity(1)
	refs := ownedRefsForTest(t)
	require.NoError(t, b.bindWithScope(c, refs))
	require.Equal(t, refs.hostID.Inode, m.values[c.CgroupID])
	require.Equal(t, 1, b.Status().RestrictedBindings)
	duplicate := ownedRefsForTest(t)
	require.NoError(t, b.bindWithScope(c, duplicate))
	requireRefsClosed(t, duplicate)
	_, err := refs.host.Stat()
	require.NoError(t, err)
	require.ErrorContains(t, b.Bind(c), "binding scope differs")
	changed := ownedRefsForTest(t)
	changed.mountID.Inode++
	require.ErrorContains(t, b.bindWithScope(c, changed), "binding scope differs")
	requireRefsClosed(t, changed)
	stale := c
	stale.ID = "old"
	require.NoError(t, b.Unbind(stale))
	require.Equal(t, 1, b.Status().RestrictedBindings)
	m.err = errors.New("map delete failed")
	require.Error(t, b.Unbind(c))
	_, err = refs.host.Stat()
	require.NoError(t, err, "a live map entry must retain its namespace")
	m.err = nil
	require.NoError(t, b.Unbind(c))
	requireRefsClosed(t, refs)
	require.Zero(t, b.Status().RestrictedBindings)
	require.NoError(t, b.Bind(c), "scope may change only after explicit removal")
	require.Zero(t, m.values[c.CgroupID])
}

func TestRestrictedFailedWritesReleaseOnlyUnpublishedReferences(t *testing.T) {
	b, m := controller()
	refs := ownedRefsForTest(t)
	m.err = errors.New("map write failed")
	require.Error(t, b.bindWithScope(identity(1), refs))
	requireRefsClosed(t, refs)
	require.Empty(t, m.values)
	require.Zero(t, b.Status().RestrictedBindings)
	m.err = nil
	require.NoError(t, b.Bind(identity(1)))
	refs = ownedRefsForTest(t)
	require.ErrorContains(t, b.bindWithScope(identity(1), refs), "binding scope differs")
	requireRefsClosed(t, refs)
	require.Zero(t, m.values[1])
}

func TestRestrictedStopRetainsFailedDeletesUntilAfterDetach(t *testing.T) {
	b, m := controller()
	refs := ownedRefsForTest(t)
	require.NoError(t, b.bindWithScope(identity(1), refs))
	require.Error(t, b.PostStop(nil), "post-stop cannot precede stop")
	m.err = errors.New("map delete failed")
	require.Error(t, b.Stop(nil))
	_, err := refs.host.Stat()
	require.NoError(t, err)
	require.Error(t, b.Close(nil), "Close cannot discard references while a failed deletion remains live")
	_, err = refs.mount.Stat()
	require.NoError(t, err)
	// The framework calls PostStop only after the eBPF operator has detached.
	require.NoError(t, b.PostStop(nil))
	requireRefsClosed(t, refs)
	require.Zero(t, b.Status().RestrictedBindings)
	require.NoError(t, b.Close(nil))
	require.NoError(t, b.PostStop(nil), "cleanup is idempotent")
}

func TestRestrictedBindingRequiresImageFeature(t *testing.T) {
	for _, supported := range []bool{false, true} {
		gc := gadgetcontext.New(context.Background(), "test")
		metadata := "annotations:\n  enforce-exec: true\n"
		if supported {
			metadata += "  enforce-exec-host-namespace: true\n"
		}
		require.NoError(t, gc.SetMetadata([]byte(metadata)))
		config := Config{}
		config.Entries[0].Generation = 1
		WithConfig(config)(gc)
		instance, err := New().InstantiateDataOperator(gc, nil)
		require.NoError(t, err)
		b := instance.(*Bindings)
		m := &fakeMap{values: map[uint64]uint64{}}
		b.ready, b.members = true, m
		c := identity(1)
		require.NoError(t, b.Bind(c))
		// Missing descriptors distinguish feature gating from later admission
		// validation. Neither rejection may touch the existing strict binding.
		err = b.BindRestricted(c, eligibleCredentials())
		require.ErrorIs(t, err, ErrRestrictedWorkload)
		if supported {
			require.ErrorContains(t, err, "missing namespace descriptor")
		} else {
			require.ErrorContains(t, err, "gadget image does not support")
		}
		require.Equal(t, map[uint64]uint64{c.CgroupID: 0}, m.values)
		require.Equal(t, 1, b.Status().Bound)
		require.Zero(t, b.Status().RestrictedBindings)
	}
}
