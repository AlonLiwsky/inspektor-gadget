// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// Physical accounts outlive logical policy sessions. The duplicated cgroup
// directory pins its kernfs identity on the admitted kernels, not necessarily a
// live struct cgroup. Liveness/qualified root proof remains a kernel operation.
type sharedPhysicalScope struct {
	native             sharedScopeCommandState
	mu                 sync.Mutex
	preparedID, cgroup uint64
	registration       sharedReceiptWire
	pins               *sharedPhysicalPins
	// containerID is the binding's trusted containerd container ID (G020
	// image index), set with the first pins and immutable after.
	containerID string
	route       sharedLiveRoute
	// withdrawn is terminal: the account's route was withdrawn, so this
	// cgroup is never bound or published again on this node (D5).
	withdrawn bool
	// retired: withdrawn and its slot recycled; dropped from the node's
	// scopes, remembered only in NodeEnforcer.withdrawnCgroups.
	retired bool
	// released: the poller withdrew and recycled this account's refused
	// adoption while its session was still bound; Remove then frees the slot
	// without a withdrawal (releasedAdoptionSlot).
	released bool
}

// initIdentity derives SharedInitIdentity from the account's retained pins;
// a.mu is held. The start time is the pinned /proc stat field 22 in clock
// ticks, unchanged.
func (a *sharedPhysicalScope) initIdentity() (SharedInitIdentity, error) {
	p := a.pins
	if p != nil && p.identityTest != nil {
		id := *p.identityTest
		if id.ContainerID == "" {
			id.ContainerID = a.containerID
		}
		return id, nil
	}
	if p == nil || p.initPID == 0 || p.mount == nil {
		return SharedInitIdentity{}, fmt.Errorf("no retained init pins")
	}
	ticks, err := strconv.ParseUint(p.start, 10, 64)
	if err != nil || ticks == 0 {
		return SharedInitIdentity{}, fmt.Errorf("invalid pinned start time %q", p.start)
	}
	mount, err := mountNamespaceIdentity(p.mount)
	if err != nil {
		return SharedInitIdentity{}, err
	}
	return SharedInitIdentity{TGID: p.initPID, StartTicks: ticks, MountNS: mount[1], ContainerID: a.containerID}, nil
}

// sharedLiveRoute is the last-good publication of one live route slot.
type sharedLiveRoute struct {
	published, withdrawPending bool
	state                      SharedRouteState
	policy                     SharedBindingPolicy
	// fault is a first publication whose outcome Go could not confirm: the
	// kernel route read back after the failure (state, published when
	// non-zero), or why it could not be read. Inspect reports it until a
	// later publication succeeds.
	fault error
	// epoch is the compiled policy's root epoch (its UID's first successful
	// activation), retained across revisions (CompileKernelWithRoleEpochs).
	epoch uint64
}
type sharedPhysicalPins struct {
	lease                          BindingLease
	cgroup, proc, mount, hostMount *os.File
	cgroupID                       uint64
	initPID                        uint32
	start                          string
	identity                       [2]uint64
	checkTest                      func(context.Context) error // private ownership-test injection only
	identityTest                   *SharedInitIdentity         // private test injection only
}

func (p *sharedPhysicalPins) InitProc() *os.File           { return p.proc }
func (p *sharedPhysicalPins) Cgroup() *os.File             { return p.cgroup }
func (p *sharedPhysicalPins) MountNamespace() *os.File     { return p.mount }
func (p *sharedPhysicalPins) HostMountNamespace() *os.File { return p.hostMount }
func (p *sharedPhysicalPins) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || p.lease == nil {
		return fmt.Errorf("physical binding pins unavailable")
	}
	if p.checkTest != nil {
		return p.checkTest(ctx)
	}
	if err := p.lease.Check(ctx); err != nil {
		return err
	}
	start, err := readPinnedInitStart(p.proc, p.initPID)
	if err != nil {
		return err
	}
	if start != p.start {
		return fmt.Errorf("trusted init starttime changed")
	}
	if err := checkBindingScope(p.proc, p, p.cgroupID); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(p.cgroup.Fd()), &stat); err != nil {
		return err
	}
	if [2]uint64{uint64(stat.Dev), stat.Ino} != p.identity {
		return fmt.Errorf("retained cgroup identity changed")
	}
	return ctx.Err()
}

func (p *sharedPhysicalPins) Close() error {
	if p == nil {
		return nil
	}
	// Failed trusted-owner cleanup retains our own independent kernfs pin.
	if p.lease != nil {
		if err := p.lease.Close(); err != nil {
			return err
		}
		p.lease = nil
	}
	var result error
	for _, f := range []**os.File{&p.proc, &p.mount, &p.hostMount, &p.cgroup} {
		if *f != nil {
			result = errors.Join(result, (*f).Close())
			*f = nil
		}
	}
	return result
}

func duplicateSharedPin(file *os.File, name string) (*os.File, error) {
	if file == nil {
		return nil, fmt.Errorf("missing %s pin", name)
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var dupErr error
	if err = raw.Control(func(original uintptr) { fd, dupErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0) }); err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, dupErr
	}
	return os.NewFile(uintptr(fd), name), nil
}

func prepareSharedPhysicalPins(ctx context.Context, c SharedBindingConfig, lease BindingLease) (*sharedPhysicalPins, error) {
	p := &sharedPhysicalPins{lease: lease, cgroupID: c.CgroupID, initPID: c.InitHostPID}
	if lease == nil {
		return p, fmt.Errorf("missing binding lease")
	}
	if err := lease.Check(ctx); err != nil {
		return p, err
	}
	var err error
	p.cgroup, err = duplicateSharedPin(lease.Cgroup(), "shared physical cgroup")
	if err != nil {
		return p, err
	}
	p.proc, err = DuplicateProcPin(lease.InitProc())
	if err != nil {
		return p, err
	}
	p.mount, err = duplicateSharedPin(lease.MountNamespace(), "shared workload mount namespace")
	if err != nil {
		return p, err
	}
	p.hostMount, err = duplicateSharedPin(lease.HostMountNamespace(), "shared host mount namespace")
	if err != nil {
		return p, err
	}
	p.start, err = readPinnedInitStart(p.proc, c.InitHostPID)
	if err != nil {
		return p, err
	}
	var stat unix.Stat_t
	if err = unix.Fstat(int(p.cgroup.Fd()), &stat); err != nil {
		return p, err
	}
	p.identity = [2]uint64{uint64(stat.Dev), stat.Ino}
	// Independently check the borrowed and retained identities, then re-attest
	// trusted ownership/starttime after duplication. No root-role authorization.
	if err = checkBindingScope(p.proc, lease, c.CgroupID); err != nil {
		return p, err
	}
	return p, p.Check(ctx)
}

// bindRefusalLocked names the first reason a new binding is refused. Every
// reason is fail-closed; n.mu is held.
func (n *NodeEnforcer) bindRefusalLocked(cgroup uint64) error {
	switch {
	case n.closed:
		return fmt.Errorf("shared binding unavailable: node closed")
	case n.host != nil && n.host.released:
		return fmt.Errorf("shared binding unavailable: node resources released")
	case n.collectionClosed:
		return fmt.Errorf("shared binding unavailable: node collection closed")
	case n.closing:
		return fmt.Errorf("shared binding unavailable: node stopping")
	case n.bindings[cgroup] != nil:
		return fmt.Errorf("shared binding unavailable: cgroup %d already has a binding", cgroup)
	case n.isWithdrawnLocked(cgroup):
		// Terminal (D5), refused before any lease is acquired: the answer
		// does not depend on the cgroup's init being alive.
		return ErrSharedBindingWithdrawn
	case uint64(len(n.preparations)) >= n.config.Profile.Bindings:
		return fmt.Errorf("shared binding unavailable: %d binding preparations in flight (profile allows %d bindings): %w", len(n.preparations), n.config.Profile.Bindings, ErrSharedBindingCapacity)
	}
	return nil
}

func (n *NodeEnforcer) bindPhysicalScope(ctx context.Context, c SharedBindingConfig) (*BindingSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.CgroupID == 0 || c.InitHostPID == 0 || c.Acquire == nil {
		return nil, fmt.Errorf("trusted cgroup and init identity required")
	}
	if c.ContainerID != "" && !ValidSharedContainerID(c.ContainerID) {
		return nil, fmt.Errorf("container ID %q is not a containerd identifier", c.ContainerID)
	}
	n.mu.Lock()
	if err := n.bindRefusalLocked(c.CgroupID); err != nil {
		n.mu.Unlock()
		return nil, err
	}
	if n.scopes == nil {
		n.scopes = map[uint64]*sharedPhysicalScope{}
	}
	account := n.scopes[c.CgroupID]
	fresh := account == nil
	if fresh {
		if uint64(len(n.scopes)) >= n.config.Profile.Bindings {
			n.mu.Unlock()
			return nil, fmt.Errorf("shared binding unavailable: %d physical scopes retained (profile allows %d bindings): %w", len(n.scopes), n.config.Profile.Bindings, ErrSharedBindingCapacity)
		}
		if n.nextPreparedID >= math.MaxUint64-1 {
			n.mu.Unlock()
			return nil, fmt.Errorf("retained physical scope capacity exhausted")
		}
		n.nextPreparedID++
		account = &sharedPhysicalScope{preparedID: n.nextPreparedID, cgroup: c.CgroupID}
		n.scopes[c.CgroupID] = account
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &BindingSession{node: n, prepared: account.preparedID, cgroup: c.CgroupID, account: account, prepareCancel: cancel, prepareDone: make(chan struct{})}
	if n.preparations == nil {
		n.preparations = make(map[*BindingSession]struct{})
	}
	n.preparations[s] = struct{}{}
	s.mu.Lock()
	n.bindings[c.CgroupID] = s
	n.mu.Unlock()
	defer func() {
		cancel()
		// Closing done and removing the registry entry are one publication;
		// shutdown cannot miss a preparation whose final cleanup still runs.
		n.mu.Lock()
		delete(n.preparations, s)
		close(s.prepareDone)
		n.mu.Unlock()
	}()
	lease, err := c.Acquire(ctx)
	if err != nil {
		s.pending = &sharedPhysicalPins{lease: lease}
	} else {
		prepare := n.prepareBinding
		if prepare == nil {
			prepare = prepareSharedPhysicalPins
		}
		s.pending, err = prepare(ctx, c, lease)
		if err == nil && s.pending == nil {
			err = fmt.Errorf("missing prepared physical pins")
		}
	}
	if err == nil {
		account.mu.Lock()
		if account.withdrawn {
			err = ErrSharedBindingWithdrawn
		} else if account.pins != nil && account.containerID != c.ContainerID {
			// G020: the image index belongs to the cgroup's container.
			err = fmt.Errorf("rebind cannot replace the retained container ID")
		} else if account.pins == nil {
			account.pins = s.pending
			account.containerID = c.ContainerID
			s.pending = nil
		} else {
			old, candidate := account.pins, s.pending
			if old.identity != candidate.identity || old.initPID != candidate.initPID || old.start != candidate.start {
				err = fmt.Errorf("rebind cannot replace retained physical scope/init identity")
			} else {
				err = old.Check(ctx)
			}
			if err == nil {
				err = candidate.Close()
				if err == nil {
					s.pending = nil
				}
			}
		}
		account.mu.Unlock()
	}
	if err == nil {
		// A live node maps each binding to a route slot of its one collection.
		err = n.reserveLiveRoute(account)
	}
	if err == nil {
		err = ctx.Err()
	}
	n.mu.Lock()
	stopping := n.closing
	n.mu.Unlock()
	if err == nil && stopping {
		err = fmt.Errorf("node stopping")
	}
	s.mu.Unlock()
	if err != nil {
		cleanup := s.Remove(context.WithoutCancel(ctx), 0)
		if cleanup != nil {
			return s, errors.Join(err, cleanup)
		}
		// A never-installed account has no kernel/history authority to preserve.
		if fresh {
			// Account->node is the only nested order; no node-locked path
			// acquires an account lock. Keep the empty check atomic with
			// removal so a fast rebind/remove cannot lose its new pins.
			account.mu.Lock()
			if account.pins == nil {
				n.mu.Lock()
				if n.scopes[c.CgroupID] == account && n.bindings[c.CgroupID] == nil {
					delete(n.scopes, c.CgroupID)
				}
				n.mu.Unlock()
			}
			account.mu.Unlock()
		}
		return nil, err
	}
	return s, nil
}

func (s *BindingSession) removePhysicalSession(ctx context.Context, generation uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.removed {
		return nil
	}
	s.account.mu.Lock()
	route, released := s.account.route, s.account.released
	s.account.mu.Unlock()
	if released {
		// The route was already withdrawn and recycled by the refused
		// adoption's poller: nothing left to withdraw at any generation.
	} else if route.published {
		if generation != route.state.Generation {
			return fmt.Errorf("remove generation %d, route at %d", generation, route.state.Generation)
		}
		if err := s.withdrawLiveRoute(ctx); err != nil {
			return err
		}
	} else if generation != 0 {
		return ErrSharedNativeUnavailable
	}
	s.account.mu.Lock()
	registered := s.account.registration.Sequence != 0 || s.account.native.attempted
	s.account.mu.Unlock()
	if registered {
		return ErrSharedNativeUnavailable
	} // requires actual withdrawal, not preparation cleanup
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.pending != nil {
		if err := s.pending.Close(); err != nil {
			return err
		}
		s.pending = nil
	}
	s.node.mu.Lock()
	if s.node.bindings[s.cgroup] != s {
		s.node.mu.Unlock()
		return fmt.Errorf("binding ownership mismatch")
	}
	delete(s.node.bindings, s.cgroup)
	s.removed = true
	s.node.mu.Unlock()
	// Race with the refused adoption's release callback
	// (releasedAdoptionSlot): it sets released (account lock) and then looks
	// for the binding (node lock); this deletes the binding (node lock) and
	// then reads released (account lock). At least one side sees the
	// other's write, so the slot is always freed (freeRecycledSlot is
	// idempotent when both do).
	s.account.mu.Lock()
	released = s.account.released
	slot := s.account.native.slot
	s.account.mu.Unlock()
	if released {
		s.node.freeRecycledSlot(s.account, slot)
	}
	return nil
}

// Called only after joined collection teardown. Logical Remove alone cannot
// prove task/inode/snapshot charge quiescence, so it never releases these pins.
func (n *NodeEnforcer) releasePhysicalScopes() error {
	n.mu.Lock()
	detached := n.collectionClosed || (n.host != nil && n.host.released)
	if !detached || len(n.bindings) != 0 {
		n.mu.Unlock()
		return fmt.Errorf("physical scope release requires detached collection and retired sessions")
	}
	protocolDestroyed := n.host != nil && n.host.protocol != nil && n.host.released && n.host.operatorClosed && n.host.commandsJoined
	liveDestroyed := n.host != nil && n.host.gadgetStopped && n.host.released
	accounts := make([]*sharedPhysicalScope, 0, len(n.scopes))
	for _, a := range n.scopes {
		accounts = append(accounts, a)
	}
	n.mu.Unlock()
	var result error
	for _, a := range accounts {
		a.mu.Lock()
		var err error
		if (a.registration.Sequence != 0 || a.native.attempted) && !protocolDestroyed {
			err = ErrSharedNativeUnavailable
		} else {
			if protocolDestroyed {
				a.native.destroyed = true
			} // not an acknowledged WITHDRAW
			err = a.pins.Close()
		}
		// Full attached images still need their real all-consumer quiescence barrier.
		// The private protocol capability is only minted for one nonattached syscall.
		if err == nil {
			a.pins = nil
		}
		a.mu.Unlock()
		result = errors.Join(result, err)
		if err == nil {
			n.mu.Lock()
			if n.scopes[a.cgroup] == a {
				delete(n.scopes, a.cgroup)
				if (protocolDestroyed || liveDestroyed) && a.native.reserved {
					n.host.scopeSlots[a.native.slot] = nil
				}
			}
			n.mu.Unlock()
		}
	}
	return result
}

// withdrawLiveRoute withdraws this session's published route slot. Without a
// kernel withdrawal (ErrSharedNativeUnavailable) the route keeps its
// last-good policy, so in-flight and later execs in that cgroup stay under it
// (fail-closed), and the slot stays retained until node teardown.
func (s *BindingSession) withdrawLiveRoute(ctx context.Context) error {
	publisher, err := s.node.livePublisher(false)
	if err != nil {
		s.node.mu.Lock()
		teardown := s.node.host != nil && s.node.host.live != nil && s.node.host.live.publisherClosed
		if teardown {
			s.node.host.live.teardownPending++
		}
		s.node.mu.Unlock()
		if !teardown {
			return err
		}
		// The live publisher already closed in node teardown: the route
		// keeps its last-good (or latched) state and dies with the
		// collection (fail-closed); the removal records it as pending.
		s.account.mu.Lock()
		s.account.route.withdrawPending = true
		s.account.mu.Unlock()
		return nil
	}
	a := s.account
	a.mu.Lock()
	defer a.mu.Unlock()
	err = publisher.Withdraw(ctx, a.native.slot, s.cgroup)
	switch {
	case err == nil:
		a.route = sharedLiveRoute{}
		a.withdrawn = true
		s.node.markWithdrawn(a.cgroup)
		if r, ok := publisher.(sharedRouteRecycler); ok {
			s.node.startRecycle(a, a.native.slot, r)
		}
	case errors.Is(err, ErrSharedNativeUnavailable):
		a.route.withdrawPending = true
	default:
		return fmt.Errorf("withdraw route slot %d: %w", a.native.slot, err)
	}
	return nil
}
