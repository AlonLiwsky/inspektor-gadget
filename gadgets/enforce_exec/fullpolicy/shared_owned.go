// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"math"
	"strings"
	"unsafe"
)

// newSharedOwnedPolicy receives exclusively compiler-owned slices and pointers
// from Compile/CompileKernel. Their strings are immutable but may still reference
// arbitrarily large caller allocations; give every retained string owned backing.
func newSharedOwnedPolicy(entries []Blob, uid uint64, source Policy) *SharedPolicy {
	source.ID = strings.Clone(source.ID)
	source.Revision = strings.Clone(source.Revision)
	source.Mode = Mode(strings.Clone(string(source.Mode)))
	source.RootRole = strings.Clone(source.RootRole)
	source.Default = Action(strings.Clone(string(source.Default)))
	cloneValues := func(values []string) {
		for i, s := range values {
			values[i] = strings.Clone(s)
		}
	}
	for i := range source.Rules {
		r := &source.Rules[i]
		r.Name = strings.Clone(r.Name)
		r.Origin = strings.Clone(r.Origin)
		r.Action = Action(strings.Clone(string(r.Action)))
		r.Mode = Mode(strings.Clone(string(r.Mode)))
		r.Target.SetRole = strings.Clone(r.Target.SetRole)
		cloneValues(r.Actor.Path)
		cloneValues(r.Actor.Role)
		cloneValues(r.Actor.Container)
		cloneValues(r.Target.Path)
		cloneValues(r.Target.FSType)
		if r.Actor.Ancestor != nil {
			cloneValues(r.Actor.Ancestor.Path)
		}
		if r.Target.Argv != nil {
			cloneValues(r.Target.Argv.Contains)
			cloneValues(r.Target.Argv.Prefix)
		}
	}
	return &SharedPolicy{entries: entries, uid: uid, source: &source}
}

// EntryCount is the number of fixed-size upload cells in the immutable object.
func (p *SharedPolicy) EntryCount() uint32 {
	if p == nil {
		return 0
	}
	return uint32(len(p.entries))
}

// Entry returns one fixed-size value copy, never a mutable arena or a full-arena
// clone. Out-of-range indices do not silently supply an upload padding cell.
func (p *SharedPolicy) Entry(index uint32) (Blob, error) {
	if p == nil || uint64(index) >= uint64(len(p.entries)) {
		return Blob{}, fmt.Errorf("shared entry index out of range")
	}
	return p.entries[index], nil
}

// RetainedBytes counts logical owned storage: object/source structs, actual
// backing slice capacities, separately allocated predicate structs/bools, and
// owned string bytes. It excludes allocator size classes/GC metadata and all
// transient compiler work. Callers must reserve compile work BEFORE compilation;
// this measurement is not an admission reservation or physical RSS guarantee.
func (p *SharedPolicy) RetainedBytes() (uint64, error) {
	if p == nil || p.source == nil {
		return 0, fmt.Errorf("missing owned shared policy")
	}
	var size sharedOwnedSize
	size.add(uint64(unsafe.Sizeof(*p)))
	size.add(uint64(unsafe.Sizeof(*p.source)))
	size.array(cap(p.entries), unsafe.Sizeof(Blob{}))
	s := p.source
	size.text(s.ID, s.Revision, string(s.Mode), s.RootRole, string(s.Default))
	size.array(cap(s.Rules), unsafe.Sizeof(Rule{}))
	for _, r := range s.Rules {
		size.text(r.Name, r.Origin, string(r.Action), string(r.Mode), r.Target.SetRole)
		size.values(r.Actor.Path)
		size.values(r.Actor.Role)
		size.values(r.Actor.Container)
		size.array(cap(r.Actor.UID), unsafe.Sizeof(int64(0)))
		size.values(r.Target.Path)
		size.values(r.Target.FSType)
		if r.Actor.FromImage != nil {
			size.add(uint64(unsafe.Sizeof(bool(false))))
		}
		if r.Target.FromImage != nil {
			size.add(uint64(unsafe.Sizeof(bool(false))))
		}
		if a := r.Actor.Ancestor; a != nil {
			size.add(uint64(unsafe.Sizeof(*a)))
			size.values(a.Path)
		}
		if a := r.Target.Argv; a != nil {
			size.add(uint64(unsafe.Sizeof(*a)))
			size.values(a.Contains)
			size.values(a.Prefix)
			if a.StdinIsPipe != nil {
				size.add(uint64(unsafe.Sizeof(bool(false))))
			}
		}
	}
	if size.overflow {
		return 0, fmt.Errorf("shared retained storage overflow")
	}
	return size.bytes, nil
}

type sharedOwnedSize struct {
	bytes    uint64
	overflow bool
}

func (s *sharedOwnedSize) add(n uint64) {
	if math.MaxUint64-s.bytes < n {
		s.overflow = true
		return
	}
	s.bytes += n
}

func (s *sharedOwnedSize) array(count int, width uintptr) {
	if count < 0 || (width != 0 && uint64(count) > math.MaxUint64/uint64(width)) {
		s.overflow = true
		return
	}
	s.add(uint64(count) * uint64(width))
}

func (s *sharedOwnedSize) text(values ...string) {
	for _, v := range values {
		s.add(uint64(len(v)))
	}
}

func (s *sharedOwnedSize) values(values []string) {
	s.array(cap(values), unsafe.Sizeof(string("")))
	s.text(values...)
}

// ExecutionClass returns the validated object's execution classification using
// the same policy fallback and resolved rule-mode logic as whole-set admission.
// It grants no scope, root, accepted-epoch or image qualification authority.
func (p *SharedPolicy) ExecutionClass() (uint32, error) {
	if p == nil || p.source == nil || len(p.entries) == 0 {
		return 0, fmt.Errorf("missing owned shared policy")
	}
	metadata, err := sharedExecutionMetadata(p.entries, []SharedPolicyRef{{Object: p}})
	if err != nil {
		return 0, err
	}
	return metadata.metadata.ExecutionClass, nil
}
