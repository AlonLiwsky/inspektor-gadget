// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedLiveProductPublisher is the node's product route publisher (G1): the
// adopting productRoutePublisher over a productCommander on the node's one
// product admin thread. Close joins the pollers first, then ends the admin
// thread (closeControl, the control's close).
type sharedLiveProductPublisher struct {
	*productRoutePublisher
	closeControl func() error
}

var (
	_ SharedRoutePublisher   = (*sharedLiveProductPublisher)(nil)
	_ sharedRouteRecycler    = (*sharedLiveProductPublisher)(nil)
	_ sharedAdoptionReporter = (*sharedLiveProductPublisher)(nil)
	_ sharedImageReporter    = (*sharedLiveProductPublisher)(nil)
)

func (p *sharedLiveProductPublisher) Close() error {
	if p == nil {
		return nil
	}
	var pollers, control error
	if p.productRoutePublisher != nil {
		pollers = p.productRoutePublisher.Close() // joins every poller
	}
	if p.closeControl != nil {
		control = p.closeControl()
	}
	return errors.Join(pollers, control)
}

// sharedHasProductCommands reports whether the admitted object carries the
// product publisher: all 8 commands (sharedCandidateCommandsOf already
// refuses a partial set at admission).
func sharedHasProductCommands(admitted *operators.NativeResources) bool {
	if admitted == nil {
		return false
	}
	for _, name := range sharedProductCommands {
		if _, ok := admitted.Programs[name]; !ok {
			return false
		}
	}
	return true
}

// sharedNewProductControl is newSharedProductControl; tests replace it.
var sharedNewProductControl = newSharedProductControl

// borrowSharedProductPublisher builds the product publisher over handles the
// eBPF operator published in the host gadget context (the commands under
// operators.ProgramPrefix, the maps under operators.MapPrefix; the operator
// owns and closes them).
func (n *NodeEnforcer) borrowSharedProductPublisher(gc operators.GadgetContext, admitted *operators.NativeResources) (SharedRoutePublisher, error) {
	if _, recovery := admitted.Maps["se_rm_control"]; recovery || admitted.Maps["se_admin"] == (operators.NativeMapResource{}) {
		// A recovered-control object authenticates commands through
		// se_rm_command_authorized, not the se_admin nonce: the product admin
		// control cannot run on it.
		return nil, fmt.Errorf("shared product publisher refuses a recovery object (no se_admin; recovered control)")
	}
	programs := map[string]sharedCommandProgram{}
	for _, name := range sharedProductCommands {
		value, _ := gc.GetVar(operators.ProgramPrefix + name)
		program, _ := value.(*ebpf.Program)
		if program == nil {
			return nil, fmt.Errorf("shared product command %s was not published", name)
		}
		programs[name] = program
	}
	maps := map[string]*ebpf.Map{}
	for _, name := range []string{"se_admin", "se_configuration", "se_routes", "se_objects", "opaque_real_adopt_state", "se_bindings", sharedImageBindingsMap} {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, _ := value.(*ebpf.Map)
		if m == nil {
			return nil, fmt.Errorf("shared product map %s was not published", name)
		}
		maps[name] = m
	}
	p, err := n.buildSharedProductPublisher(context.WithoutCancel(gc.Context()), admitted, programs,
		maps["se_admin"], maps["se_configuration"], maps["se_routes"], maps["se_objects"], maps["opaque_real_adopt_state"])
	if err != nil {
		return nil, err // never a typed nil in the interface
	}
	if err := n.withImageIndex(p, maps[sharedImageBindingsMap]); err != nil {
		return nil, errors.Join(err, p.Close())
	}
	return p.withBindings(maps["se_bindings"]), nil
}

// withImageIndex gives the commander the G020 image index over the
// se_image_bindings map, with a containerd resolver when the node config
// names a containerd socket (none otherwise: no image sets are built).
func (n *NodeEnforcer) withImageIndex(p *sharedLiveProductPublisher, bindings sharedBytesMap) error {
	cmd, ok := p.cmd.(*productCommander)
	if !ok {
		return nil
	}
	var resolver sharedImageResolving
	if n.host != nil && n.host.imageSource != nil {
		r, err := newSharedImageLayerResolver(n.host.imageSource, sharedImageProcHost{ProcRoot: n.config.ImageProcRoot, HostRoot: n.config.ImageHostRoot}, n.config.Profile.PerBinding.Images)
		if err != nil {
			return err
		}
		resolver = r
	} else if n.config.ContainerdAddress != "" {
		source, err := newSharedImageContainerdSource(n.config.ContainerdAddress, "")
		if err != nil {
			return err
		}
		r, err := newSharedImageLayerResolver(source, sharedImageProcHost{ProcRoot: n.config.ImageProcRoot, HostRoot: n.config.ImageHostRoot}, n.config.Profile.PerBinding.Images)
		if err != nil {
			return errors.Join(err, source.Close())
		}
		resolver = r
		closeControl := p.closeControl
		p.closeControl = func() error { return errors.Join(closeControl(), source.Close()) }
	}
	index, err := newProductImageIndex(cmd.control.run, bindings, resolver, n.config.Profile)
	if err != nil {
		return err
	}
	index.overlayUnavailable = n.host.overlayUnavailable
	cmd.image = index
	return nil
}

// withBindings gives the commander the bindings map, to report a RETIRING
// record's readers (G019 gap 3). Never nil.
func (p *sharedLiveProductPublisher) withBindings(bindings sharedBytesMap) *sharedLiveProductPublisher {
	if cmd, ok := p.cmd.(*productCommander); ok {
		cmd.bindings = bindings
	}
	return p
}

// buildSharedProductPublisher installs the node's admin thread
// (newSharedProductControl: se_admin and se_configuration written and
// frozen) and builds the commander and publisher over it. A control that
// failed after its thread started is closed.
func (n *NodeEnforcer) buildSharedProductPublisher(ctx context.Context, admitted *operators.NativeResources, programs map[string]sharedCommandProgram,
	admin sharedAdminMap, configuration sharedProductConfigMap, routes, objects, adoptState sharedBytesMap,
) (*sharedLiveProductPublisher, error) {
	control, err := sharedNewProductControl(ctx, n.config.Profile, admitted, admin, configuration, programs)
	if err != nil {
		if control != nil {
			err = errors.Join(err, control.close())
		}
		return nil, err
	}
	cmd := newProductCommander(control, routes, objects, adoptState, n.config.Profile)
	cmd.revisionDrainTimeout = n.config.RevisionDrainTimeout
	return &sharedLiveProductPublisher{productRoutePublisher: newProductRoutePublisher(cmd, n.slotThreads), closeControl: control.close}, nil
}

// slotThreads lists the tids of the cgroup bound to a route slot, through
// the owning account's retained cgroup pin. The tids are init-namespace tids
// only when the agent runs in the initial pid namespace (design 13.8):
// otherwise it refuses, so an adoption fails rather than adopting the wrong
// tasks.
//
// Invariant (why a.pins is read without a.mu): an account's pins are set
// at Bind, before its slot is reserved (reserveLiveRoute), and cleared only
// (1) by releasePhysicalScopes, which requires the collection detached,
// i.e. after closeLivePublisher joined every poller, or (2) by
// freeRecycledSlot, which first removes the account from scopeSlots, under
// the same node lock this function reads scopeSlots with, after the slot's
// route was withdrawn and recycled (no adoption or poller of that slot is
// left). So every caller (Publish with a.mu held, the pollers without) sees
// a stable pin.
func (n *NodeEnforcer) slotThreads(slot uint32) ([]uint32, error) {
	n.mu.Lock()
	var a *sharedPhysicalScope
	var refused error
	if n.host != nil {
		refused = n.host.strictRefused
		if int(slot) < len(n.host.scopeSlots) {
			a = n.host.scopeSlots[slot]
		}
	}
	n.mu.Unlock()
	if refused != nil {
		return nil, fmt.Errorf("cgroup.threads of slot %d not in init-namespace tids: %w", slot, refused)
	}
	if a == nil || a.pins == nil {
		return nil, fmt.Errorf("route slot %d has no bound cgroup pin", slot)
	}
	return sharedCgroupThreads(a.pins.cgroup)
}

// sharedNilPublisher reports a nil publisher, including a typed nil pointer
// stored in the interface (never used, never closed).
func sharedNilPublisher(p SharedRoutePublisher) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	return v.Kind() == reflect.Pointer && v.IsNil()
}
