// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"maps"
	"math"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

const (
	sharedTaskValueBytes       = 960
	sharedInvocationValueBytes = 19184
)

// The fixed-pool map contract is checked at the same host admission boundary
// as the current shared image. It is deliberately not an enablement switch:
// the product hooks and semantic-owner cleanup do not yet use these maps.
const sharedPoolMapPrefix = "se_pool_"

const sharedPoolReaperProgramPrefix = "se_pool_reaper_"

const sharedOpaqueTaskMapPrefix = "se_opaque_"

// This is source-shape accounting for the replacement TASK owner, not an
// admission switch or physical kernel-allocation measurement.
type sharedOpaqueTaskUsage struct{ MapValueBytes uint64 }

func hasSharedOpaqueTaskMaps(r *operators.NativeResources) bool {
	if r == nil {
		return false
	}
	for name := range r.Maps {
		if strings.HasPrefix(name, sharedOpaqueTaskMapPrefix) {
			return true
		}
	}
	return false
}

func sharedOpaqueTaskGeometry(p SharedProfile) (map[string]operators.NativeMapResource, sharedOpaqueTaskUsage, error) {
	var zero sharedOpaqueTaskUsage
	if _, err := p.Validate(); err != nil {
		return nil, zero, err
	}
	// The locator reserves 14 low bits for its fixed TASK slot. The current
	// source partitions every slot into one original binding account.
	if p.Tasks > 1<<14 || p.Bindings*p.PerBinding.Tasks != p.Tasks {
		return nil, zero, fmt.Errorf("opaque TASK locator/partition geometry unsupported")
	}
	words := (p.PerBinding.Tasks + 63) / 64
	if words == 0 || 32+8*words > math.MaxUint32 {
		return nil, zero, fmt.Errorf("opaque TASK account bitmap exceeds uint32")
	}
	t, b := uint32(p.Tasks), uint32(p.Bindings)
	array := func(size, count, flags uint32) operators.NativeMapResource {
		return operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: size, MaxEntries: count, Flags: flags}
	}
	want := map[string]operators.NativeMapResource{
		"se_opaque_keys":         {Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: 8, MaxEntries: t, Flags: unix.BPF_F_RDONLY},
		"se_opaque_archive":      array(8, t, unix.BPF_F_RDONLY),
		"se_opaque_meta":         array(128, t, unix.BPF_F_RDONLY),
		"se_opaque_payload":      array(1280, t, unix.BPF_F_RDONLY),
		"se_opaque_payload_zero": array(1280, 1, unix.BPF_F_RDONLY_PROG),
		"se_opaque_accounts":     array(uint32(32+8*words), b, unix.BPF_F_RDONLY),
		"se_opaque_charges":      array(40, t, unix.BPF_F_RDONLY),
		"se_opaque_sequence":     array(16, 1, unix.BPF_F_RDONLY),
	}
	usage := zero
	for _, shape := range want {
		bytes, err := checkedSharedProduct(uint64(shape.ValueSize), uint64(shape.MaxEntries))
		if err != nil || usage.MapValueBytes > math.MaxUint64-bytes {
			return nil, zero, fmt.Errorf("opaque TASK map-value budget overflow")
		}
		usage.MapValueBytes += bytes
	}
	return want, usage, nil
}

func validateSharedOpaqueTaskResources(p SharedProfile, r *operators.NativeResources) (sharedOpaqueTaskUsage, error) {
	var zero sharedOpaqueTaskUsage
	want, usage, err := sharedOpaqueTaskGeometry(p)
	if err != nil {
		return zero, err
	}
	if r == nil {
		return zero, fmt.Errorf("missing opaque TASK manifest")
	}
	for _, legacy := range []string{"se_tasks", "se_zero_tasks", "se_task_sequences", "se_invocations", "se_zero_invocations"} {
		if _, present := r.Maps[legacy]; present {
			return zero, fmt.Errorf("opaque TASK image retains legacy storage %s", legacy)
		}
	}
	if hasSharedPoolMaps(r) {
		return zero, fmt.Errorf("opaque TASK image retains address-mixer pool maps")
	}
	for name, shape := range want {
		if got, ok := r.Maps[name]; !ok || got != shape {
			return zero, fmt.Errorf("opaque TASK map %s missing or incompatible", name)
		}
	}
	for name := range r.Maps {
		if strings.HasPrefix(name, sharedOpaqueTaskMapPrefix) {
			if _, ok := want[name]; !ok {
				return zero, fmt.Errorf("unexpected opaque TASK map %s", name)
			}
		}
	}
	return usage, nil
}

// The replacement owner needs TASK and WORK credits in one image. This is a
// source-shape contract, not native admission: selected callbacks, catalogue,
// and source-owned cleanup must still be qualified before Ready is possible.
func sharedOpaqueOwnerGeometry(p SharedProfile) (map[string]operators.NativeMapResource, sharedOpaqueTaskUsage, error) {
	want, usage, err := sharedOpaqueTaskGeometry(p)
	if err != nil {
		return nil, sharedOpaqueTaskUsage{}, err
	}
	// One 64-bit account bitmap per binding, and a power of two: the
	// verdict source refuses any other WORK quota at compile time (it grows
	// the fork source past the 512-byte combined stack) and further bounds
	// its own quota to 32.
	if p.PerBinding.Scratch == 0 || p.PerBinding.Scratch > 64 ||
		p.PerBinding.Scratch&(p.PerBinding.Scratch-1) != 0 ||
		p.Bindings*p.PerBinding.Scratch != p.Scratch {
		return nil, sharedOpaqueTaskUsage{}, fmt.Errorf("opaque WORK requires an exact per-binding partition of a power-of-two quota of at most 64 credits")
	}
	array := func(size, count, flags uint32) operators.NativeMapResource {
		return operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: size, MaxEntries: count, Flags: flags}
	}
	work := map[string]operators.NativeMapResource{
		"se_opaque_work_accounts": array(40, uint32(p.Bindings), unix.BPF_F_RDONLY),
		"se_opaque_work_charges":  array(56, uint32(p.Scratch), unix.BPF_F_RDONLY),
		"se_opaque_work_sequence": array(16, 1, unix.BPF_F_RDONLY),
		"se_opaque_work_meta":     array(80, uint32(p.Scratch), unix.BPF_F_RDONLY),
		"se_opaque_work_payload":  array(19456, uint32(p.Scratch), unix.BPF_F_RDONLY),
		"se_opaque_work_zero":     array(19456, 1, unix.BPF_F_RDONLY_PROG),
	}
	for name, shape := range work {
		bytes, err := checkedSharedProduct(uint64(shape.ValueSize), uint64(shape.MaxEntries))
		if err != nil || usage.MapValueBytes > math.MaxUint64-bytes {
			return nil, sharedOpaqueTaskUsage{}, fmt.Errorf("opaque WORK map-value budget overflow")
		}
		usage.MapValueBytes += bytes
		want[name] = shape
	}
	return want, usage, nil
}

func validateSharedOpaqueOwnerResources(p SharedProfile, r *operators.NativeResources) (sharedOpaqueTaskUsage, error) {
	if err := refuseSharedProductForbiddenMaps(r); err != nil {
		return sharedOpaqueTaskUsage{}, err
	}
	want, usage, err := sharedOpaqueOwnerGeometry(p)
	if err != nil {
		return sharedOpaqueTaskUsage{}, err
	}
	if r == nil {
		return sharedOpaqueTaskUsage{}, fmt.Errorf("missing or mixed opaque owner manifest")
	}
	// The opaque owner may carry the reviewed unattached reaper transport,
	// whose wire names use se_pool_. Never admit any flat-pool owner map or a
	// partial/mutated transport merely because that prefix is present.
	transportMaps, transportPrograms := sharedOpaqueReaperTransportGeometry()
	transportPresent := false
	for name := range r.Maps {
		transportPresent = transportPresent || strings.HasPrefix(name, sharedPoolMapPrefix)
	}
	for name := range r.Programs {
		transportPresent = transportPresent || strings.HasPrefix(name, sharedPoolReaperProgramPrefix)
	}
	if transportPresent {
		for name, shape := range transportMaps {
			if got, ok := r.Maps[name]; !ok || got != shape {
				return sharedOpaqueTaskUsage{}, fmt.Errorf("opaque reaper transport map %s missing or incompatible", name)
			}
			bytes, err := checkedSharedProduct(uint64(shape.ValueSize), uint64(shape.MaxEntries))
			if err != nil || usage.MapValueBytes > math.MaxUint64-bytes {
				return sharedOpaqueTaskUsage{}, fmt.Errorf("opaque reaper transport map-value budget overflow")
			}
			usage.MapValueBytes += bytes
			want[name] = shape
		}
		for name, shape := range transportPrograms {
			got, ok := r.Programs[name]
			if !ok || got.Type != shape.Type || got.Target != "" || got.Instructions == 0 {
				return sharedOpaqueTaskUsage{}, fmt.Errorf("opaque reaper transport program %s missing or incompatible", name)
			}
		}
	}
	for _, legacy := range []string{"se_tasks", "se_zero_tasks", "se_task_sequences", "se_invocations", "se_zero_invocations"} {
		if _, present := r.Maps[legacy]; present {
			return sharedOpaqueTaskUsage{}, fmt.Errorf("opaque owner image retains legacy storage %s", legacy)
		}
	}
	// The opaque_ namespace belongs to disposable fixtures, not the selected
	// owner. A finite denylist would silently admit a newly added diagnostic
	// gate or program before its synthetic authority was reviewed.
	for name := range r.Maps {
		if strings.HasPrefix(name, "opaque_") {
			return sharedOpaqueTaskUsage{}, fmt.Errorf("opaque owner image retains diagnostic map %s", name)
		}
	}
	for name := range r.Programs {
		if strings.HasPrefix(name, "opaque_") {
			return sharedOpaqueTaskUsage{}, fmt.Errorf("opaque owner image retains diagnostic program %s", name)
		}
	}
	for name, shape := range want {
		if got, ok := r.Maps[name]; !ok || got != shape {
			return sharedOpaqueTaskUsage{}, fmt.Errorf("opaque owner map %s missing or incompatible", name)
		}
	}
	for name := range r.Maps {
		if strings.HasPrefix(name, sharedOpaqueTaskMapPrefix) {
			if _, ok := want[name]; !ok {
				return sharedOpaqueTaskUsage{}, fmt.Errorf("unexpected opaque owner map %s", name)
			}
		}
		if strings.HasPrefix(name, sharedPoolMapPrefix) {
			if _, ok := want[name]; !ok {
				return sharedOpaqueTaskUsage{}, fmt.Errorf("unexpected flat-pool/transport map %s", name)
			}
		}
	}
	for name := range r.Programs {
		if strings.HasPrefix(name, sharedPoolReaperProgramPrefix) {
			if _, ok := transportPrograms[name]; !ok {
				return sharedOpaqueTaskUsage{}, fmt.Errorf("unexpected opaque reaper program %s", name)
			}
		}
	}
	return usage, nil
}

func sharedOpaqueReaperTransportGeometry() (map[string]operators.NativeMapResource, map[string]operators.NativeProgramResource) {
	maps, programs := sharedPoolReaperTransportGeometry()
	maps["se_pool_reap_request"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 64, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG}
	maps["se_pool_reap_control"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 64, MaxEntries: 1, Flags: unix.BPF_F_RDONLY}
	maps["se_pool_reap_receipt"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 128, MaxEntries: 1, Flags: unix.BPF_F_RDONLY}
	return maps, programs
}

type sharedPoolUsage struct {
	MapValueBytes uint64
	Directories   uint32
	BitmapBytes   uint32
}

func hasSharedPoolMaps(r *operators.NativeResources) bool {
	if r == nil {
		return false
	}
	for name := range r.Maps {
		if strings.HasPrefix(name, sharedPoolMapPrefix) {
			return true
		}
	}
	return false
}

func sharedPoolGeometry(p SharedProfile) (map[string]operators.NativeMapResource, sharedPoolUsage, error) {
	var zero sharedPoolUsage
	if _, err := p.Validate(); err != nil {
		return nil, zero, err
	}
	if p.Tasks > math.MaxUint32 || p.Scratch > math.MaxUint32 ||
		p.Bindings > math.MaxUint32 || p.PerBinding.Tasks > math.MaxUint32 ||
		p.PerBinding.Scratch > math.MaxUint32 {
		return nil, zero, fmt.Errorf("fixed-pool geometry exceeds uint32")
	}
	// Validate already checked B*QT<=T and B*QW<=W. A remainder is
	// deliberately unavailable to every binding.
	t, w, b := uint32(p.Tasks), uint32(p.Scratch), uint32(p.Bindings)
	qt, qw := uint32(p.PerBinding.Tasks), uint32(p.PerBinding.Scratch)
	if t == 0 || w == 0 || b == 0 {
		return nil, zero, fmt.Errorf("fixed-pool geometry is empty")
	}
	// shared_pool_task_core.h statically bounds SE_POOL_TASK_WORDS to 128.
	// Reject a host profile that the selected BPF image cannot compile.
	if (uint64(qt)+63)/64 > 128 {
		return nil, zero, fmt.Errorf("fixed-pool task quota exceeds kernel bitmap scan bound")
	}
	d64 := uint64(1)
	for d64 < (uint64(t)+3)/4 {
		d64 *= 2
		if d64 > math.MaxUint32 {
			return nil, zero, fmt.Errorf("fixed-pool directory exceeds uint32")
		}
	}
	bitmap64 := uint64(16) + 8*((uint64(qt)+63)/64+(uint64(qw)+63)/64)
	if bitmap64 > math.MaxUint32 {
		return nil, zero, fmt.Errorf("fixed-pool bitmap exceeds uint32")
	}
	if uint64(t)+uint64(w) > math.MaxUint32 {
		return nil, zero, fmt.Errorf("fixed-pool charge array exceeds uint32")
	}
	d, bitmap := uint32(d64), uint32(bitmap64)
	array := func(size, count uint32, flags uint32) operators.NativeMapResource {
		return operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: size, MaxEntries: count, Flags: flags}
	}
	maps := map[string]operators.NativeMapResource{
		"se_pool_task_meta":    array(128, t, unix.BPF_F_RDONLY),
		"se_pool_task_payload": array(1280, t, unix.BPF_F_RDONLY),
		"se_pool_work_meta":    array(80, w, unix.BPF_F_RDONLY),
		"se_pool_work_payload": array(19456, w, unix.BPF_F_RDONLY),
		"se_pool_charges":      array(32, t+w, unix.BPF_F_RDONLY),
		"se_pool_directory":    array(392, d, unix.BPF_F_RDONLY),
		"se_pool_bitmaps":      array(bitmap, b, unix.BPF_F_RDONLY),
		"se_pool_task_zero":    array(1280, 1, unix.BPF_F_RDONLY_PROG),
		"se_pool_work_zero":    array(19456, 1, unix.BPF_F_RDONLY_PROG),
		"se_pool_sequence":     array(16, 1, unix.BPF_F_RDONLY),
		"se_pool_reap_request": array(64, 1, unix.BPF_F_RDONLY_PROG),
		"se_pool_reap_control": array(64, 1, unix.BPF_F_RDONLY),
		"se_pool_reap_receipt": array(128, 1, unix.BPF_F_RDONLY),
	}
	usage := sharedPoolUsage{Directories: d, BitmapBytes: bitmap}
	for _, spec := range maps {
		n := uint64(spec.ValueSize) * uint64(spec.MaxEntries)
		if usage.MapValueBytes > math.MaxUint64-n {
			return nil, zero, fmt.Errorf("fixed-pool map-value budget overflow")
		}
		usage.MapValueBytes += n
	}
	return maps, usage, nil
}

// The tail-call transport is a separate candidate revision of the pool ABI.
// Its stage is BPF-writable but cannot be modified by userspace; its one
// program-array slot must be installed with the exact loaded chunk program
// before any reaper step is accepted. Geometry alone never makes it Ready.
func sharedPoolReaperTransportGeometry() (map[string]operators.NativeMapResource, map[string]operators.NativeProgramResource) {
	maps := map[string]operators.NativeMapResource{
		"se_pool_reap_stage": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 144, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
		"se_pool_reap_chain": {Type: uint32(ebpf.ProgramArray), KeySize: 4, ValueSize: 4, MaxEntries: 1},
	}
	programs := map[string]operators.NativeProgramResource{
		"se_pool_reaper_entry": {Type: uint32(ebpf.SchedCLS), Instructions: 1},
		"se_pool_reaper_chunk": {Type: uint32(ebpf.SchedCLS), Instructions: 1},
	}
	return maps, programs
}

func hasSharedPoolReaperTransport(r *operators.NativeResources) bool {
	if r == nil {
		return false
	}
	maps, programs := sharedPoolReaperTransportGeometry()
	for name := range maps {
		if _, ok := r.Maps[name]; ok {
			return true
		}
	}
	for name := range programs {
		if _, ok := r.Programs[name]; ok {
			return true
		}
	}
	return false
}

func validateSharedPoolImageResources(p SharedProfile, r *operators.NativeResources) (sharedPoolUsage, error) {
	var zero sharedPoolUsage
	want, usage, err := sharedPoolGeometry(p)
	if err != nil {
		return zero, err
	}
	if r == nil {
		return zero, fmt.Errorf("missing fixed-pool manifest")
	}
	if _, legacy := r.Maps["se_tasks"]; legacy {
		return zero, fmt.Errorf("fixed-pool image retains legacy task storage")
	}
	if _, legacy := r.Maps["se_invocations"]; legacy {
		return zero, fmt.Errorf("fixed-pool image retains legacy work storage")
	}
	if hasSharedPoolReaperTransport(r) {
		transportMaps, transportPrograms := sharedPoolReaperTransportGeometry()
		for name, shape := range transportMaps {
			if got, ok := r.Maps[name]; !ok || got != shape {
				return zero, fmt.Errorf("fixed-pool transport map %s missing or incompatible", name)
			}
			want[name] = shape
			usage.MapValueBytes += uint64(shape.ValueSize) * uint64(shape.MaxEntries)
		}
		for name, shape := range transportPrograms {
			got, ok := r.Programs[name]
			if !ok || got.Type != shape.Type || got.Target != "" || got.Instructions == 0 {
				return zero, fmt.Errorf("fixed-pool transport program %s missing or incompatible", name)
			}
		}
	}
	for name, shape := range want {
		if got, ok := r.Maps[name]; !ok || got != shape {
			return zero, fmt.Errorf("fixed-pool map %s missing or incompatible", name)
		}
	}
	for name := range r.Maps {
		if strings.HasPrefix(name, sharedPoolMapPrefix) {
			if _, ok := want[name]; !ok {
				return zero, fmt.Errorf("unexpected fixed-pool map %s", name)
			}
		}
	}
	for name := range r.Programs {
		if strings.HasPrefix(name, sharedPoolReaperProgramPrefix) &&
			name != "se_pool_reaper_entry" && name != "se_pool_reaper_chunk" {
			return zero, fmt.Errorf("unexpected fixed-pool transport program %s", name)
		}
	}
	return usage, nil
}

// This is the exact transitional reachable image, including its implicit .bss.
// Recognizing fixed-pool geometry is not kernel lifetime or qualification proof.
type sharedImageUsage struct {
	sharedResourceUsage
	PendingEnforcementQualification bool
}

func sharedImageGeometry(p SharedProfile) (map[string]operators.NativeMapResource, map[string]operators.NativeProgramResource) {
	maps := map[string]operators.NativeMapResource{
		"se_tasks":            {Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: sharedTaskValueBytes, MaxEntries: uint32(p.Tasks), Flags: unix.BPF_F_RDONLY},
		"se_zero_tasks":       {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: sharedTaskValueBytes, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
		"se_invocations":      {Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: sharedInvocationValueBytes, MaxEntries: uint32(p.Scratch), Flags: unix.BPF_F_RDONLY},
		"se_zero_invocations": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: sharedInvocationValueBytes, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
		"se_accepted_epochs":  {Type: uint32(ebpf.Hash), KeySize: 16, ValueSize: 8, MaxEntries: uint32(p.AcceptedUIDs), Flags: unix.BPF_F_RDONLY},
		"se_task_sequences":   {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 16, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
		"se_inode_facts":      {Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: 48, MaxEntries: uint32(p.InodeFacts), Flags: unix.BPF_F_RDONLY},
		"se_inode_accounts":   {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 48, MaxEntries: uint32(p.Bindings) + 1, Flags: unix.BPF_F_RDONLY},
		"events":              {Type: uint32(ebpf.RingBuf), MaxEntries: 262144},
		"counters":            {Type: uint32(ebpf.PerCPUArray), KeySize: 4, ValueSize: 8, MaxEntries: 3},
		".bss":                {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 16, MaxEntries: 1},
		"se_arm_requests":     {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 176, MaxEntries: 1, Flags: unix.BPF_F_WRONLY},
		"se_arm_receipts":     {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 48, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
		"se_epoch_bank":       {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 32, MaxEntries: uint32(p.AcceptedUIDs), Flags: unix.BPF_F_RDONLY},
		"se_epoch_index":      {Type: uint32(ebpf.Hash), KeySize: 16, ValueSize: 4, MaxEntries: uint32(p.AcceptedUIDs), Flags: unix.BPF_F_RDONLY},
		"se_arm_frame":        {Type: uint32(ebpf.PerCPUArray), KeySize: 4, ValueSize: 176, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
	}
	programs := map[string]operators.NativeProgramResource{
		"se_command":               {Type: uint32(ebpf.Syscall)},
		"se_publication_arm":       {Type: uint32(ebpf.Tracing), Target: "cgroup_kn_lock_live"},
		"se_sched_exec":            {Type: uint32(ebpf.Tracing), Target: "sched_process_exec"},
		"se_bprm_exit":             {Type: uint32(ebpf.Tracing), Target: "bprm_execve"},
		"se_task_alloc":            {Type: uint32(ebpf.LSM), Target: "task_alloc"},
		"se_task_free":             {Type: uint32(ebpf.LSM), Target: "task_free"},
		"se_inode_free":            {Type: uint32(ebpf.LSM), Target: "inode_free_security"},
		"enforce_exec_full":        {Type: uint32(ebpf.LSM), Target: "bprm_check_security"},
		"enforce_exec_track_memfd": {Type: uint32(ebpf.LSM), Target: "inode_init_security_anon"},
	}
	return maps, programs
}

func validateSharedImageResources(p SharedProfile, r *operators.NativeResources) (sharedImageUsage, error) {
	var zero sharedImageUsage
	if _, err := p.Validate(); err != nil {
		return zero, err
	}
	if r == nil {
		return zero, fmt.Errorf("missing shared image manifest")
	}
	extra, programs := sharedImageGeometry(p)
	protocol := &operators.NativeResources{Maps: maps.Clone(r.Maps), Programs: map[string]operators.NativeProgramResource{"se_command": r.Programs["se_command"]}}
	for name, want := range extra {
		if got, ok := r.Maps[name]; !ok || got != want {
			return zero, fmt.Errorf("shared image map %s missing or incompatible", name)
		}
		delete(protocol.Maps, name)
	}
	base, err := validateSharedProtocolResources(p, protocol)
	if err != nil {
		return zero, err
	}
	if len(r.Programs) != len(programs) {
		return zero, fmt.Errorf("unexpected shared image program inventory")
	}
	// G020: the shared image no longer declares the legacy 65536-cell
	// image_origins/image_ready maps (full/program.bpf.c under
	// ENFORCE_EXEC_SHARED_NODE), so Images is no longer pinned to them; the
	// image index geometry (se_image_keys = Images cells, se_image_bindings
	// per binding) is the product object's (sharedProductImageGeometry).
	if p.TelemetryBytes < 262144 {
		return zero, fmt.Errorf("transitional telemetry geometry exceeds declared profile")
	}
	usage := sharedImageUsage{sharedResourceUsage: base, PendingEnforcementQualification: true}
	usage.ProgramInstructions = 0
	for name, want := range programs {
		got, ok := r.Programs[name]
		if !ok || got.Type != want.Type || got.Target != want.Target || got.Instructions == 0 {
			return zero, fmt.Errorf("shared image program %s missing or incompatible", name)
		}
		usage.ProgramInstructions, err = checkedSharedResourceSum(usage.ProgramInstructions, got.Instructions)
		if err != nil {
			return zero, err
		}
	}
	for name, m := range extra {
		payload, err := checkedSharedProduct(uint64(m.ValueSize), uint64(m.MaxEntries))
		if err != nil {
			return zero, err
		}
		if name == "events" {
			payload = uint64(m.MaxEntries)
		}
		if name == "counters" || name == "se_arm_frame" {
			payload, err = checkedSharedProduct(payload, uint64(p.PossibleCPUs))
			if err != nil {
				return zero, err
			}
		}
		usage.MapPayloadBytes, err = checkedSharedResourceSum(usage.MapPayloadBytes, payload)
		if err != nil {
			return zero, err
		}
	}
	usage.ProgramBytes, err = checkedSharedProduct(usage.ProgramInstructions, 8)
	if err != nil {
		return zero, err
	}
	usage.LogicalBytes, err = checkedSharedResourceSum(usage.MapPayloadBytes, usage.AdminPayloadBytes, usage.ProgramBytes, usage.NativeAllowanceBytes)
	if err != nil {
		return zero, err
	}
	return usage, nil
}

// sharedProductForbiddenMaps are maps that may exist only in a diagnostic
// twin, never in a product image, refused by name before any allowlist (the
// opaque_ prefix rule below is the general one, and it will narrow once
// product admission is enabled). opaque_real_publish_fault is the
// publication fault injector of the non-recovery publisher twin
// (SE_PRODUCT_DIAGNOSTIC_TWIN), which only the tagged qualification path
// admits; the opaque_real_fc_* maps are the twin's test-only fail-closed
// injectors (ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC and
// its _EXT_ extension: selector, counts and pending marker, extended
// periods and counts); opaque_real_interp_stale_resume is the twin's
// interpreter-continuation stale-resume injector
// (ENFORCE_EXEC_POOL_OPAQUE_INTERP_STALE_RESUME_DIAGNOSTIC);
// opaque_real_verdict_suspend_fault is the twin's verdict-event
// suspension-fault injector (ENFORCE_EXEC_POOL_OPAQUE_VERDICT_SUSPEND_FAULT_DIAGNOSTIC, G020 H2);
// opaque_real_fact_witness is the per-pass fact witness ring
// (ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_WITNESS, G020).
var sharedProductForbiddenMaps = []string{
	"opaque_real_publish_fault",
	"opaque_real_fc_inject_selector",
	"opaque_real_fc_inject_counts",
	"opaque_real_fc_pending_marked",
	"opaque_real_fc_inject_ext",
	"opaque_real_fc_inject_ext_counts",
	"opaque_real_interp_stale_resume",
	"opaque_real_verdict_suspend_fault",
	sharedFactWitnessMap,
}

func refuseSharedProductForbiddenMaps(r *operators.NativeResources) error {
	if r == nil {
		return nil
	}
	for _, name := range sharedProductForbiddenMaps {
		if _, present := r.Maps[name]; present {
			return fmt.Errorf("product image carries the diagnostic-twin map %s", name)
		}
	}
	return nil
}
