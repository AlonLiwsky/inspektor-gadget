// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package operators

const (
	// NativeResourcesKey exposes a compact pre-load resource manifest, never BTF,
	// instructions or write authority. It is local-only, not the remote API.
	NativeResourcesKey = "ebpf/native-resources"
	// NativeOwnerRequiredKey marks local native-owner use before OCI layer
	// instantiation, including when the image omits its required ABI annotation.
	// Such images must contain exactly one eBPF layer and no executable guests.
	NativeOwnerRequiredKey = "ebpf/native-owner-required"
	// NativeResourceValidatorKey holds a local func(*NativeResources) error.
	// Native owners install it before Start; the eBPF operator invokes it on the
	// final transformed collection immediately before allocating kernel resources.
	NativeResourceValidatorKey = "ebpf/native-resource-validator"
	// NativeRecoveryTestRunKey is a trusted local opt-in for the two recovery
	// SchedCLS programs that must be loaded for TEST_RUN, never attached to TC.
	// The native resource validator must still admit the exact recovered image.
	NativeRecoveryTestRunKey = "ebpf/native-recovery-test-run"
	NativeAttachmentPrefix   = "attachment/"
	// NativeAttachReserveKey optionally holds an int: the trampoline links per
	// hook (R) a native family must leave free for third parties. Absent means
	// nativeattach.DefaultReservePerHook. Ordinary gadgets ignore it.
	NativeAttachReserveKey = "ebpf/native-attach-reserve"
	// NativeAttachRetryKey optionally overrides the attach retry of a native
	// family. Absent means nativeattach.DefaultRetry: a family refused for
	// attach capacity stays NotReady (logged, naming the target) and retries
	// the whole transaction with capped exponential backoff until it attaches
	// or the gadget context is done. A nativeattach.Retry replaces the default
	// (reporting through Retry.State); false opts out and refuses at once, as
	// the legacy per-cgroup Owner and the shared node do. The retry runs
	// inside Start, so a gadget started through an instance manager holds
	// the manager's lifecycle lock across every backoff wait; such hosts
	// opt out and retry the whole start outside the lock instead (the shared
	// node's StartNode does). Ordinary gadgets ignore it.
	NativeAttachRetryKey = "ebpf/native-attach-retry"
	// NativeLoadedProgramPrefix borrows every program in the exact admitted
	// recovered collection for H's pin/FD ledger. It is not an invocation
	// permission and is absent for ordinary or protocol-only images.
	NativeLoadedProgramPrefix = "ebpf/native-loaded-program/"
	// NativeConstantsKey optionally holds a map[string]uint32,
	// map[string]uint64 or map[string]any (uint32 or uint64 values) the
	// native owner installs before Start: each name is a read-only constant
	// (`const volatile __u32` for a uint32, `__u64` for a uint64) of the
	// collection, set before admission and loading. A name absent from the
	// collection is skipped; a present one that is not a read-only constant
	// of the value's size refuses the load. The constants set are reported
	// in NativeResources.Constants. Ordinary gadgets ignore it.
	NativeConstantsKey = "ebpf/native-constants"
	// NativeProgramDigestKey holds a string the eBPF operator sets only when
	// NativeOwnerRequiredKey is true: the lowercase hex sha256 of the eBPF
	// program layer bytes it loads, recorded before any parsing. A second
	// eBPF layer sets it to "" (sticky), so a native owner can bind the
	// exact object bytes of its one-layer image. Ordinary gadgets never see
	// it.
	NativeProgramDigestKey = "ebpf/native-program-sha256"
)

type NativeMapResource struct {
	Type, KeySize, ValueSize, MaxEntries, Flags uint32
	// InnerMap describes the separately allocated map-of-maps template.
	InnerMap *NativeMapResource
}
type NativeProgramResource struct {
	Type   uint32
	Target string
	// Conservative encoded instruction count (LD_IMM64 occupies two words).
	Instructions uint64
}
type NativeResources struct {
	Maps     map[string]NativeMapResource
	Programs map[string]NativeProgramResource
	// TailCalls are the PROG_ARRAY slots the eBPF operator installs at load,
	// before any hook attaches (metadata `tail_calls`), as admitted here.
	TailCalls []NativeTailCall
	// Constants are the NativeConstantsKey constants set in the
	// collection (name -> byte size); absent names are not listed.
	Constants map[string]uint32
}

// NativeTailCall is one declared PROG_ARRAY slot: Map[Index] = Program.
type NativeTailCall struct {
	Map     string `mapstructure:"map"`
	Index   uint32 `mapstructure:"index"`
	Program string `mapstructure:"program"`
}

// NativeAttachment is a borrowed, live receipt, not an owned link. Check fails
// when the exact link identity, type or linked program changes. IDs are
// diagnostic evidence, not authority to reopen or pin a link. Callers must
// join checks before Stop; image metadata or a loaded program FD is not proof
// of hook presence.
type NativeAttachment struct {
	Type, LinkID, ProgramID uint32
	Target                  string
	Check                   func() error
	// PinAt is present only on admitted recovery task LSM links. dirFD must
	// reference a private, host-visible bpffs directory. A successful pin is
	// retained on later errors; the future S pin ledger owns unlinking.
	PinAt func(dirFD int) (NativePinnedLink, error)
}

// NativePinnedLink owns a reopened link FD, not the pin itself. Close releases
// that FD but leaves the bpffs pin intact. PinName is a fixed basename for S.
type NativePinnedLink interface {
	FD() int
	PinName() string
	Check() error
	Close() error
}
