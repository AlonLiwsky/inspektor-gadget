// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"math"
	"slices"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// These are compiler/coordinator fixtures, not a kernel uploader. The real
// se_command endpoint still requires the recovered physical admin. Neither a
// matching transcript nor PREPARED grants publication, root authority or Ready.
func opaqueVerdictPolicy(mode fullpolicy.Mode, rules int) fullpolicy.Policy {
	p := fullpolicy.Policy{ID: "opaque-verdict-compiled-policy", Revision: "fixture-v1", Mode: mode, RootRole: "root", Default: fullpolicy.Deny}
	for i := 0; i < rules; i++ {
		p.Rules = append(p.Rules, fullpolicy.Rule{Name: fmt.Sprintf("uid-%d", i), Action: fullpolicy.Allow, Actor: fullpolicy.Actor{UID: []int64{int64(i)}}})
	}
	return p
}

func opaqueVerdictCompilerTranscript(t *testing.T, p fullpolicy.Policy) (*fullpolicy.SharedPolicy, fullpolicy.SharedSnapshot, []sharedCommandWire) {
	t.Helper()
	object, err := fullpolicy.CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	n, s, _ := sharedRegistryFixture(t)
	s.account.pins.lease = sharedNamedTestLease{BindingLease: s.account.pins.lease, name: "app"}
	f := &sharedSnapshotTransport{refusePin: -1}
	c, result, _, err := runSharedIntegratedTest(t, s, []fullpolicy.Policy{p}, math.MaxUint64, f)
	if err != nil || result.failed() {
		t.Fatalf("actual compiler/upload/stage coordinator: result=%+v err=%v", result, err)
	}
	snapshot, err := fullpolicy.NewSharedSnapshot(s.ScopeCookie(), 1, "app", []fullpolicy.SharedPolicyRef{{Object: object, RootEpoch: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if !object.Equal(n.objects.records[c.record].source[0]) {
		t.Fatal("coordinator changed compiler-owned policy content")
	}
	if got := s.Inspect(); got.Ready || got.RootAuthorized || got.Generation != 0 {
		t.Fatal("preparation granted activation authority")
	}
	return object, snapshot, slices.Clone(f.commands)
}

// This checks a future live fixture's recorded input against the immutable
// compiler output; it never creates an authenticated command or modifies bytes.
func validateOpaqueVerdictCompilerTranscript(object *fullpolicy.SharedPolicy, snapshot fullpolicy.SharedSnapshot, commands []sharedCommandWire) error {
	if object == nil {
		return fmt.Errorf("missing compiler object")
	}
	entries := object.Entries()
	metadata, err := snapshot.ExecutionMetadata()
	if err != nil {
		return err
	}
	header, err := fullpolicy.Decode[fullpolicy.KernelHeader](entries[0])
	if err != nil {
		return err
	}
	class, err := object.ExecutionClass()
	if err != nil {
		return err
	}
	if len(commands) != len(entries)+5 {
		return fmt.Errorf("incomplete object/stage transcript")
	}
	begin := commands[0]
	if begin.Operation != 1 || begin.Count != uint32(len(entries)) || begin.Generation != 0 || begin.Attempt == 0 {
		return fmt.Errorf("invalid object begin")
	}
	for i, entry := range entries {
		c := commands[i+1]
		if c.Operation != 2 || c.Object != begin.Object || c.Generation != 1 || c.Attempt != begin.Attempt || c.Index != uint32(i) || c.Value != entry {
			return fmt.Errorf("compiler cell %d altered or missing", i)
		}
	}
	final := commands[len(entries)+1]
	if final.Operation != 3 || final.Object != begin.Object || final.Generation != 1 || final.Attempt != begin.Attempt || final.Count != header.RuleCount || final.ExecutionClass != class {
		return fmt.Errorf("invalid compiler finalize")
	}
	prepare := commands[len(entries)+2]
	if prepare.Operation != 8 || prepare.Count != 1 || prepare.Scope != snapshot.ScopeCookie || prepare.ExecutionClass != metadata.ExecutionClass || prepare.Metadata.PolicyUIDs[0] != object.UID() || prepare.Metadata.RootEpochs[0] != 1 || prepare.Metadata.RoleWriters != metadata.RoleWriters || prepare.Metadata.RequiredKnown != metadata.RequiredKnown || prepare.Metadata.ContainerLength != uint32(len(snapshot.Container)) || string(prepare.Metadata.Container[:len(snapshot.Container)]) != snapshot.Container {
		return fmt.Errorf("snapshot does not preserve compiler identity/class")
	}
	pin, seal := commands[len(entries)+3], commands[len(entries)+4]
	if pin.Operation != 9 || pin.Object != begin.Object || pin.Index != 0 || pin.Scope != snapshot.ScopeCookie || seal.Operation != 10 || seal.Scope != snapshot.ScopeCookie {
		return fmt.Errorf("missing exact pin/seal")
	}
	for i, c := range commands {
		if c.NodeCookie == 0 || c.Nonce == 0 || c.Sequence == 0 || i > 0 && c.Sequence <= commands[i-1].Sequence {
			return fmt.Errorf("invalid command identity/order")
		}
	}
	return nil
}

func TestOpaqueVerdictCompilerTranscript(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  fullpolicy.Mode
		rules int
	}{
		{"strict-one-rule", fullpolicy.Enforce, 1}, {"audit-one-rule", fullpolicy.Audit, 1}, {"strict-256-rules", fullpolicy.Enforce, 256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			object, snapshot, commands := opaqueVerdictCompilerTranscript(t, opaqueVerdictPolicy(tc.mode, tc.rules))
			if err := validateOpaqueVerdictCompilerTranscript(object, snapshot, commands); err != nil {
				t.Fatal(err)
			}
			if object.UID() == 0 || object.UID() == 1 {
				t.Fatal("fixture relies on synthetic UID1 instead of canonical compiler identity")
			}
		})
	}
}

func TestOpaqueVerdictCompilerTranscriptRejectsMutation(t *testing.T) {
	object, snapshot, original := opaqueVerdictCompilerTranscript(t, opaqueVerdictPolicy(fullpolicy.Enforce, 1))
	n := len(object.Entries())
	for _, tc := range []struct {
		name   string
		mutate func([]sharedCommandWire) []sharedCommandWire
	}{
		{"cell", func(c []sharedCommandWire) []sharedCommandWire { c[2].Value[0] ^= 1; return c }},
		{"uid", func(c []sharedCommandWire) []sharedCommandWire { c[n+2].Metadata.PolicyUIDs[0] = 1; return c }},
		{"class", func(c []sharedCommandWire) []sharedCommandWire { c[n+1].ExecutionClass = 1; return c }},
		{"epoch", func(c []sharedCommandWire) []sharedCommandWire { c[n+2].Metadata.RootEpochs[0] = 0; return c }},
		{"write-order", func(c []sharedCommandWire) []sharedCommandWire { c[1], c[2] = c[2], c[1]; return c }},
		{"missing-write", func(c []sharedCommandWire) []sharedCommandWire { return append(c[:2], c[3:]...) }},
		{"sequence", func(c []sharedCommandWire) []sharedCommandWire { c[2].Sequence = c[1].Sequence; return c }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateOpaqueVerdictCompilerTranscript(object, snapshot, tc.mutate(slices.Clone(original))); err == nil {
				t.Fatal("altered compiler transcript accepted")
			}
		})
	}
}

func TestOpaqueVerdictCompilerOracleControls(t *testing.T) {
	strict := opaqueVerdictPolicy(fullpolicy.Enforce, 1)
	program, err := fullpolicy.Compile([]fullpolicy.Policy{strict})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		uid            *uint32
		block, failure bool
	}{
		{"healthy-allow", new(uint32(0)), false, false}, {"known-deny", new(uint32(1)), true, false}, {"unknown-strict", nil, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := program.Evaluate(fullpolicy.Facts{EffectiveUID: tc.uid, RoleBootstrap: true})
			if d.Block != tc.block || (err != nil) != tc.failure {
				t.Fatalf("decision=%+v err=%v", d, err)
			}
		})
	}
	audit := opaqueVerdictPolicy(fullpolicy.Audit, 1)
	audit.Rules[0].Target.SetRole = "child"
	program, err = fullpolicy.Compile([]fullpolicy.Policy{audit})
	if err != nil {
		t.Fatal(err)
	}
	d, err := program.Evaluate(fullpolicy.Facts{RoleBootstrap: true})
	if err != nil || d.Block || len(d.SetRoles) != 0 || !d.UncertainRoles[audit.ID] {
		t.Fatalf("uncertain Audit role leaked: %+v err=%v", d, err)
	}
}
