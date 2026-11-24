// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

func TestSharedExecMapFlags(t *testing.T) {
	yes := true
	imageOnly := &fullpolicy.Policy{Mode: fullpolicy.Enforce, Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{
		{Action: fullpolicy.Allow, Target: fullpolicy.Target{FromImage: &yes}},
		{Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{"/usr/bin/id"}}},
	}}
	// Mixed modes (review 2, item 3): an audit policy with an enforce deny
	// rule is a Strict binding whose audit default lets any program run.
	auditDefault := &fullpolicy.Policy{Mode: fullpolicy.Audit, Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{
		{Action: fullpolicy.Allow, Target: fullpolicy.Target{FromImage: &yes}},
		{Action: fullpolicy.Deny, Mode: fullpolicy.Enforce, Target: fullpolicy.Target{Path: []string{"/usr/bin/nc"}}},
	}}
	auditDeny := &fullpolicy.Policy{Mode: fullpolicy.Enforce, Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{
		{Action: fullpolicy.Allow, Target: fullpolicy.Target{FromImage: &yes}},
		{Action: fullpolicy.Deny, Mode: fullpolicy.Audit, Target: fullpolicy.Target{Path: []string{"/tmp/**"}}},
	}}
	auditDefaultMode := &fullpolicy.Policy{Mode: fullpolicy.Enforce, Default: fullpolicy.Deny, DefaultMode: fullpolicy.Audit, Rules: []fullpolicy.Rule{
		{Action: fullpolicy.Allow, Target: fullpolicy.Target{FromImage: &yes}},
	}}
	pathAllow := &fullpolicy.Policy{Mode: fullpolicy.Enforce, Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{
		{Action: fullpolicy.Allow, Target: fullpolicy.Target{FromImage: &yes}},
		{Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{"/data/tool"}}},
	}}
	defaultAllow := &fullpolicy.Policy{Default: fullpolicy.Allow}
	for _, c := range []struct {
		name   string
		m      SharedExecMap
		source *fullpolicy.Policy
		handle uint64
		want   uint32
		err    bool
		noIdx  bool
	}{
		{name: "off", source: imageOnly, handle: 7, want: 0},
		{name: "off without index", source: imageOnly, want: 0},
		{name: "judge, image-only policy", m: SharedExecMap{Judge: true}, source: imageOnly, handle: 7, want: sharedExecMapFlagJudge},
		{name: "judge, path allow", m: SharedExecMap{Judge: true}, source: pathAllow, handle: 7, want: sharedExecMapFlagJudge | sharedExecMapFlagExeExempt},
		{name: "judge, default allow", m: SharedExecMap{Judge: true}, source: defaultAllow, handle: 7, want: sharedExecMapFlagJudge | sharedExecMapFlagExeExempt},
		{name: "deny anonymous", m: SharedExecMap{Judge: true, DenyAnonymous: true}, source: imageOnly, handle: 7, want: sharedExecMapFlagJudge | sharedExecMapFlagDenyAnon},
		{name: "audit policy, enforce deny rule", m: SharedExecMap{Judge: true}, source: auditDefault, handle: 7, want: sharedExecMapFlagJudge | sharedExecMapFlagExeExempt},
		{name: "audit deny rule", m: SharedExecMap{Judge: true}, source: auditDeny, handle: 7, want: sharedExecMapFlagJudge | sharedExecMapFlagExeExempt},
		{name: "audit default mode", m: SharedExecMap{Judge: true}, source: auditDefaultMode, handle: 7, want: sharedExecMapFlagJudge | sharedExecMapFlagExeExempt},
		{name: "judge without index", m: SharedExecMap{Judge: true}, source: imageOnly, err: true, noIdx: true},
		{name: "deny anonymous without judge", m: SharedExecMap{DenyAnonymous: true}, source: imageOnly, handle: 7, err: true},
		{name: "judge without source", m: SharedExecMap{Judge: true}, handle: 7, err: true},
	} {
		got, err := sharedExecMapFlags(c.m, c.source, c.handle)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("%s: got %#x, %v; want %#x, error %v", c.name, got, err, c.want, c.err)
		}
		if c.noIdx && !errors.Is(err, ErrSharedImageIndexUnavailable) {
			t.Errorf("%s: %v does not wrap ErrSharedImageIndexUnavailable", c.name, err)
		}
	}
}

func TestSharedProductPublishBodyExecMap(t *testing.T) {
	f := sharedPublishFields{container: "c", imageHandle: 7, imageDev: 0x2a, execMap: sharedExecMapFlagJudge | sharedExecMapFlagExeExempt}
	b, err := sharedProductPublishBody(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != sharedProductPublishRequestBytes-sharedProductHeaderBytes {
		t.Fatalf("body %d bytes", len(b))
	}
	m := b[80 : 80+sharedSnapshotMetadataBytes]
	if got := binary.LittleEndian.Uint32(m[sharedExecMapMetadataOffset:]); got != f.execMap {
		t.Fatalf("exec_map_flags %#x, want %#x", got, f.execMap)
	}
	if got := binary.LittleEndian.Uint32(m[sharedExecMapMetadataOffset+4:]); got != 0 {
		t.Fatalf("exec_map_reserved %#x", got)
	}
	for _, bad := range []sharedPublishFields{
		{container: "c", execMap: sharedExecMapFlagJudge},                                     // no image
		{container: "c", imageHandle: 7, imageDev: 0x2a, execMap: sharedExecMapFlagDenyAnon},  // no judge
		{container: "c", imageHandle: 7, imageDev: 0x2a, execMap: sharedExecMapFlagExeExempt}, // no judge
		{container: "c", imageHandle: 7, imageDev: 0x2a, execMap: 8 | sharedExecMapFlagJudge}, // unknown bit
	} {
		if _, err := sharedProductPublishBody(bad); err == nil {
			t.Errorf("publish body accepted exec_map_flags %#x with handle %d", bad.execMap, bad.imageHandle)
		}
	}
}

func TestSharedBindingPolicyExecMapValidate(t *testing.T) {
	p := SharedBindingPolicy{Class: 2, Rules: 1, ExecMap: SharedExecMap{Judge: true}}
	if err := p.validate(); err == nil {
		t.Fatal("a gate without a source policy was accepted")
	}
}

func TestFailClosedExecMap(t *testing.T) {
	var v FailClosedRateVerdict
	if err := FailClosedExecMap(&v, 3, 3, 100, 0); err != nil || v.ExecMap != 0 || v.Degraded {
		t.Fatalf("quiet window: %+v %v", v, err)
	}
	if err := FailClosedExecMap(&v, 3, 5, 0, 0.5); err != nil || v.ExecMap != 2 || v.ExecMapRate != 2 || !v.Degraded {
		t.Fatalf("no attempts: %+v %v", v, err)
	}
	v = FailClosedRateVerdict{}
	if err := FailClosedExecMap(&v, 0, 1, 10000, 0.001); err != nil || v.Degraded || v.Total != 0 {
		t.Fatalf("diluted fault: %+v %v", v, err)
	}
	if err := FailClosedExecMap(&v, 5, 4, 1, 0); err == nil {
		t.Fatal("a counter that moved backwards was accepted")
	}
}
