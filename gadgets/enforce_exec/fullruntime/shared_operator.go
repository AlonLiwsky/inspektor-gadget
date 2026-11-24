// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// BindingLease is supplied ONLY by a trusted runtime owner. Acquire transfers
// ownership. It must pin the exact runtime container, init proc allocation,
// cgroup, mount namespace and any image/lower-root evidence for its lifetime.
// Check authenticates runtime ownership and re-attests all pins/root constraints.
// It must reject host/unsupported namespaces and runtime helper ingress, never
// infer exemptions. Policy metadata/annotations are not evidence. InitProc is a
// borrowed proc-directory pin for the exact InitHostPID, not /proc's root directory.
type BindingLease interface {
	Check(context.Context) error
	InitProc() *os.File
	Cgroup() *os.File
	MountNamespace() *os.File
	HostMountNamespace() *os.File
	Close() error
}

// sharedOperator is the data operator that claims a shared node's host
// gadget: a gadget context carrying a node (WithSharedNodeHost) or an image
// annotated with a shared profile. Every other gadget gets no instance.
type sharedOperator struct{}

// New returns the shared node data operator.
func New() operators.DataOperator                  { return &sharedOperator{} }
func init()                                        { operators.RegisterDataOperator(New()) }
func (*sharedOperator) Name() string               { return "enforce-exec-owner" }
func (*sharedOperator) Priority() int              { return 1 }
func (*sharedOperator) Init(*params.Params) error  { return nil }
func (*sharedOperator) GlobalParams() api.Params   { return nil }
func (*sharedOperator) InstanceParams() api.Params { return nil }
func (*sharedOperator) InstantiateDataOperator(gc operators.GadgetContext, _ api.ParamValues) (operators.DataOperatorInstance, error) {
	value, _ := gc.GetVar("config")
	metadata, ok := value.(*viper.Viper)
	sharedValue, sharedSupplied := gc.GetVar(sharedNodeKey)
	if sharedSupplied || (ok && metadata != nil && metadata.GetString("annotations.enforce-exec-shared-profile") != "") {
		node, _ := sharedValue.(*NodeEnforcer)
		return instantiateSharedNode(gc, metadata, node)
	}
	// An enforce_exec owner image without a shared node is never loaded as
	// an ordinary gadget: the per-binding owner engine is gone, so nothing
	// would manage its LSM programs.
	if ok && metadata != nil && metadata.GetString("annotations.enforce-exec-owner-abi") != "" {
		return nil, fmt.Errorf("enforce_exec image %s carries an owner ABI annotation but no shared node profile: refused", gc.ImageName())
	}
	return nil, nil
}

// KernelEventCounters counts evaluator events, not every denied exec. Early
// gate/lineage refusals return before verdict emission and are excluded.
// Live per-CPU reads are not atomic across CPUs or keys. Final is set only after
// verified attachment teardown; an error means the counts are incomplete
// (the last successful sample, if any).
type KernelEventCounters struct {
	Submitted         uint64
	Lost              uint64 // failed verdict ring-buffer reservations
	ObservationErrors uint64
	Final             bool
}

func validateCounterMap(info *ebpf.MapInfo) error {
	if info == nil || info.Type != ebpf.PerCPUArray || info.KeySize != 4 || info.ValueSize != 8 || info.MaxEntries != 3 {
		return fmt.Errorf("incompatible full verdict counters map")
	}
	return nil
}
