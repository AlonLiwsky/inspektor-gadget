// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// SharedPredicateKind names one rule predicate of fullpolicy.Rule by the
// kernel fact it needs (struct fe_facts, fullpolicy/bpf/evaluator.h).
// Target.SetRole is an effect, not a predicate, and is not listed.
type SharedPredicateKind string

const (
	SharedPredicateActorRole      SharedPredicateKind = "actor.role"         // Actor.Role: roles
	SharedPredicateActorUID       SharedPredicateKind = "actor.uid"          // Actor.UID: effective_uid
	SharedPredicateActorContainer SharedPredicateKind = "actor.container"    // Actor.Container: snapshot metadata container
	SharedPredicateActorPath      SharedPredicateKind = "actor.path"         // Actor.Path: actor_path
	SharedPredicateActorImage     SharedPredicateKind = "actor.fromImage"    // Actor.FromImage: actor_image
	SharedPredicateActorAncestor  SharedPredicateKind = "actor.ancestor"     // Actor.Ancestor: ancestors
	SharedPredicateTargetPath     SharedPredicateKind = "target.path"        // Target.Path: target_path
	SharedPredicateTargetImage    SharedPredicateKind = "target.fromImage"   // Target.FromImage: target_image
	SharedPredicateTargetFSType   SharedPredicateKind = "target.fsType"      // Target.FSType: fs_mask/fs_known
	SharedPredicateTargetStdin    SharedPredicateKind = "target.stdinIsPipe" // Target.Argv.StdinIsPipe: stdin_pipe
	SharedPredicateTargetArgv     SharedPredicateKind = "target.argv"        // Target.Argv.Contains/Prefix: argv
)

// SharedFactSupport is whether the product evaluator produces the fact a
// predicate kind needs.
type SharedFactSupport uint8

const (
	// SharedFactNotYet: the product evaluator leaves the fact unknown, so
	// the predicate would evaluate UNKNOWN (Strict denies, Audit unknown).
	// Admission refuses it until a kernel producer lands (G020).
	SharedFactNotYet SharedFactSupport = iota
	// SharedFactSupported: the product evaluator produces the fact
	// (each such kind carries a producer source pin, see tests).
	SharedFactSupported
	// SharedFactRefused: permanently refused for the PoC.
	SharedFactRefused
)

func (s SharedFactSupport) String() string {
	switch s {
	case SharedFactSupported:
		return "supported"
	case SharedFactRefused:
		return "refused"
	default:
		return "not yet"
	}
}

// sharedProductFactSupport is the single switch for product admission: a
// predicate kind is admitted only when its entry is SharedFactSupported.
// G020 step 2 landed the per-pass path, fs class, stdin and ancestor facts
// (full/shared_pass_facts.h), part 4 the image facts (the classifier,
// full/shared_image_classify.h, against the reader-held snapshot's image
// index). Only argv stays refused.
var sharedProductFactSupport = map[SharedPredicateKind]SharedFactSupport{
	SharedPredicateActorRole:      SharedFactSupported,
	SharedPredicateActorUID:       SharedFactSupported,
	SharedPredicateActorContainer: SharedFactSupported,
	SharedPredicateActorPath:      SharedFactSupported,
	SharedPredicateActorImage:     SharedFactSupported,
	SharedPredicateActorAncestor:  SharedFactSupported,
	SharedPredicateTargetPath:     SharedFactSupported,
	SharedPredicateTargetImage:    SharedFactSupported,
	SharedPredicateTargetFSType:   SharedFactSupported,
	SharedPredicateTargetStdin:    SharedFactSupported,
	SharedPredicateTargetArgv:     SharedFactRefused,
}

// SharedProductFactSupport returns a copy of the product fact capability
// table: which predicate kinds the shared product evaluator can produce.
func SharedProductFactSupport() map[SharedPredicateKind]SharedFactSupport {
	out := make(map[SharedPredicateKind]SharedFactSupport, len(sharedProductFactSupport))
	for k, v := range sharedProductFactSupport {
		out[k] = v
	}
	return out
}

// ErrSharedPredicateUnsupported is wrapped by every product admission
// refusal of a predicate kind the product evaluator cannot produce.
var ErrSharedPredicateUnsupported = errors.New("shared product predicate unsupported")

// SharedPredicateUnsupportedError names the first offending predicate: its
// policy, rule index (into Policy.Rules), exception index (-1: the rule
// itself) and kind.
type SharedPredicateUnsupportedError struct {
	Policy    string
	Rule      int
	Exception int
	Kind      SharedPredicateKind
	Support   SharedFactSupport
}

const sharedArgvRefusal = "argv predicates are refused for the PoC: the stock-kernel product evaluator has no authoritative argv fact (a documented limitation, follow-up issue)"

func (e *SharedPredicateUnsupportedError) Error() string {
	where := fmt.Sprintf("policy %s rule %d", e.Policy, e.Rule)
	if e.Exception >= 0 {
		where += fmt.Sprintf(" exception %d", e.Exception)
	}
	if e.Support == SharedFactRefused {
		return fmt.Sprintf("%s: %s: %s: %s", ErrSharedPredicateUnsupported, where, e.Kind, sharedArgvRefusal)
	}
	return fmt.Sprintf("%s: %s: %s: the product evaluator does not produce this fact yet (it would evaluate UNKNOWN)", ErrSharedPredicateUnsupported, where, e.Kind)
}

func (e *SharedPredicateUnsupportedError) Unwrap() error { return ErrSharedPredicateUnsupported }

// sharedPredicateKinds lists the predicate kinds one actor/target pair uses,
// in a fixed order.
func sharedPredicateKinds(a fullpolicy.Actor, t fullpolicy.Target) []SharedPredicateKind {
	var kinds []SharedPredicateKind
	add := func(used bool, kind SharedPredicateKind) {
		if used {
			kinds = append(kinds, kind)
		}
	}
	add(len(a.Role) != 0, SharedPredicateActorRole)
	add(len(a.UID) != 0, SharedPredicateActorUID)
	add(len(a.Container) != 0, SharedPredicateActorContainer)
	add(len(a.Path) != 0, SharedPredicateActorPath)
	add(a.FromImage != nil, SharedPredicateActorImage)
	add(a.Ancestor != nil, SharedPredicateActorAncestor)
	add(len(t.Path) != 0, SharedPredicateTargetPath)
	add(t.FromImage != nil, SharedPredicateTargetImage)
	add(len(t.FSType) != 0, SharedPredicateTargetFSType)
	if t.Argv != nil {
		add(t.Argv.StdinIsPipe != nil, SharedPredicateTargetStdin)
		add(len(t.Argv.Contains) != 0 || len(t.Argv.Prefix) != 0, SharedPredicateTargetArgv)
	}
	return kinds
}

// admitSharedProductPolicy refuses a policy using any predicate kind the
// product evaluator cannot produce, naming the first offending rule (rule
// order, then the rule's own predicates before its exceptions).
func admitSharedProductPolicy(p *fullpolicy.Policy) error {
	for i, r := range p.Rules {
		if err := admitSharedPredicates(p.ID, i, -1, r.Actor, r.Target); err != nil {
			return err
		}
		for j, ex := range r.Except {
			if err := admitSharedPredicates(p.ID, i, j, ex.Actor, ex.Target); err != nil {
				return err
			}
		}
	}
	return nil
}

func admitSharedPredicates(policy string, rule, exception int, a fullpolicy.Actor, t fullpolicy.Target) error {
	for _, kind := range sharedPredicateKinds(a, t) {
		if s := sharedProductFactSupport[kind]; s != SharedFactSupported {
			return &SharedPredicateUnsupportedError{Policy: policy, Rule: rule, Exception: exception, Kind: kind, Support: s}
		}
	}
	return nil
}
