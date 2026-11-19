// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

func filesystemRequired(config Config) bool {
	if config.Full == nil || len(config.Full.Entries) == 0 {
		return false
	}
	header, err := fullpolicy.Decode[fullpolicy.KernelHeader](config.Full.Entries[0])
	if err != nil {
		return false
	}
	for i := uint32(0); i < header.RuleCount; i++ {
		index := header.RuleBase + i
		if uint64(index) >= uint64(len(config.Full.Entries)) {
			return false
		}
		rule, err := fullpolicy.Decode[fullpolicy.KernelRule](config.Full.Entries[index])
		if err == nil && rule.FSType.Count > 0 {
			return true
		}
	}
	return false
}

// Install borrowed map checks; only called after configuration validation.
// The probe runs at final Ready, after every operator has attached its hooks.
// It proves this candidate's own marker map observes the kernel class hook.
func (b *Bindings) configureFilesystem(origins, diagnostics *ebpf.Map) error {
	tracker, err := NewFilesystemTracker(origins, diagnostics)
	if err != nil {
		return err
	}
	b.fsProbe = tracker.Probe
	b.fsHealth = tracker.Check
	return nil
}

// FilesystemTracker validates this loaded candidate's own memfd class tracker.
// It borrows maps; the caller serializes checks with native teardown.
type FilesystemTracker struct{ probe, check func() error }

func (t *FilesystemTracker) Probe() error { return t.probe() }
func (t *FilesystemTracker) Check() error { return t.check() }
func NewFilesystemTracker(origins, diagnostics *ebpf.Map) (*FilesystemTracker, error) {
	if origins == nil || origins.Type() != ebpf.InodeStorage || origins.KeySize() != 4 || origins.ValueSize() != 8 || origins.MaxEntries() != 0 || origins.Flags() != unix.BPF_F_NO_PREALLOC {
		return nil, fmt.Errorf("invalid filesystem inode-origin map")
	}
	if diagnostics == nil || diagnostics.Type() != ebpf.Array || diagnostics.KeySize() != 4 || diagnostics.ValueSize() != 16 || diagnostics.MaxEntries() != 1 {
		return nil, fmt.Errorf("invalid filesystem diagnostics map")
	}
	tracker := new(FilesystemTracker)
	tracker.probe = func() error {
		fd, err := unix.MemfdCreate("enforce-exec-tracker-probe", unix.MFD_CLOEXEC)
		if err != nil {
			return fmt.Errorf("filesystem tracker probe creation: %w", err)
		}
		defer unix.Close(fd)
		var marker uint64
		if err := origins.Lookup(uint32(fd), &marker); err != nil {
			return fmt.Errorf("filesystem tracker not observing new memfds: %w", err)
		}
		if marker != 1 {
			return fmt.Errorf("filesystem tracker returned invalid marker")
		}
		return nil
	}
	tracker.check = func() error {
		var state struct{ Credits, Faults uint64 }
		if err := diagnostics.Lookup(uint32(0), &state); err != nil {
			return fmt.Errorf("reading filesystem tracker diagnostics: %w", err)
		}
		if state.Faults != 0 {
			return fmt.Errorf("filesystem tracker lost authoritative observations (fault mask %d)", state.Faults)
		}
		return nil
	}
	return tracker, nil
}
