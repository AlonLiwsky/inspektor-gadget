// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// SharedNodeAPIVersion is the version of the exported shared-node engine
// surface a node agent builds against (G020): StartNode/Bind, the binding's
// Compile/PublishCompiled/Publish/Inspect/Remove, the node's health reports
// (KernelEventCounters, Ready and the per-witness reports) and the verdict
// event ABI (SharedEventABIVersion). It changes with any incompatible change
// of that surface.
const SharedNodeAPIVersion = 1

// ErrSharedCompiledStale is wrapped by PublishCompiled's refusal of a
// SharedCompiled that no longer describes the binding's next publication:
// the binding's route moved since Compile (another publication committed,
// so the generation the compilation was made for is gone), the root epoch it
// was compiled with changed, it was compiled by another binding, or
// recompiling its inputs no longer gives the same program and shared object
// (the authored policy or container changed). Nothing was published; Compile
// again (and re-stage anything keyed by the old generation).
var ErrSharedCompiledStale = errors.New("compiled shared policy is stale")

// ErrSharedMultiPolicyUnsupported is SharedSinglePolicy's refusal of a plan
// that binds more than one policy to one binding (G020 user decision D3):
// the shared engine evaluates exactly one authored policy per binding (its
// compiled header must carry PolicyCount 1). A node agent must refuse such a
// plan for the shared engine (the per-binding legacy engine keeps
// multi-policy plans); multi-policy bindings are a follow-up.
var ErrSharedMultiPolicyUnsupported = errors.New("shared engine binds exactly one policy per binding (multi-policy plans are unsupported, G020 D3)")

// SharedSinglePolicy validates a binding's policy plan for the shared engine
// and returns its one policy. More than one policy is refused with
// ErrSharedMultiPolicyUnsupported, none with a plain error. The result is the
// Source of the binding's SharedBindingPolicy; the exported surface never
// takes more than one policy per binding.
func SharedSinglePolicy(plan []fullpolicy.Policy) (*fullpolicy.Policy, error) {
	switch len(plan) {
	case 0:
		return nil, fmt.Errorf("shared binding plan has no policy")
	case 1:
		p := plan[0]
		return &p, nil
	}
	ids := make([]string, len(plan))
	for i := range plan {
		ids[i] = plan[i].ID
	}
	return nil, fmt.Errorf("plan binds %d policies %q: %w", len(plan), ids, ErrSharedMultiPolicyUnsupported)
}

// SharedCompiled is one binding's policy compiled for the binding's next
// publication and not committed (BindingSession.Compile). A node agent stages
// what it decodes verdict events with (the matched-rule mapping of
// Program.Rules) for Generation before PublishCompiled commits it; a
// verdict event of the route carries that generation.
type SharedCompiled struct {
	// Generation is the route generation this publication creates: the
	// binding's last committed generation + 1 (1 for a first publication).
	Generation uint64
	// Program is the exact role-epoch compilation the publication commits
	// (fullpolicy.CompileKernelWithRoleEpochs at Generation): Program.Rules
	// is indexed by the zero-based global rule index the kernel reports,
	// the bit index of a verdict event's matched rules. Nil for a policy
	// without Source (the qualification Class/Fallback/Rules form). Read
	// only: PublishCompiled refuses a Program that differs from a fresh
	// compilation of the same inputs.
	Program *fullpolicy.KernelProgram
	// Epochs is the root epoch per policy ID the program carries: the epoch
	// a revision of the same policy UID retains, or the epoch of its first
	// activation. Empty without Source.
	Epochs map[string]uint64

	session *BindingSession
	// base is the route the compilation was made against; policy the
	// compiled binding policy and input its uncompiled form.
	base          sharedLiveRoute
	policy, input SharedBindingPolicy
}

// Compile compiles policy for this binding's next publication without
// committing it: the product admission of its predicates
// (ErrSharedPredicateUnsupported: every predicate kind must have a kernel
// fact producer), the compilation at the next generation with the root epoch
// the binding retained for that policy UID, and the terminal refusals of a
// revision (execution class change, ErrSharedClassChange; policy UID or root
// role change) and of a Strict policy on a node that refuses Strict, exactly
// as Publish runs them. It requires a live binding with a route slot, like
// Publish; it changes nothing.
func (s *BindingSession) Compile(policy SharedBindingPolicy) (SharedCompiled, error) {
	if err := policy.validate(); err != nil {
		return SharedCompiled{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.publishableLocked(context.Background()); err != nil {
		return SharedCompiled{}, err
	}
	a := s.account
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := s.routeInitLocked(); err != nil {
		return SharedCompiled{}, err
	}
	return s.compileLocked(policy)
}

// PublishCompiled commits a SharedCompiled of this binding, exactly as
// Publish commits the policy it was compiled from. It refuses with
// ErrSharedCompiledStale, before any command runs, when c no longer
// describes the binding's next publication (see ErrSharedCompiledStale); of
// two compilations made against the same route, at most one commits.
func (s *BindingSession) PublishCompiled(ctx context.Context, c SharedCompiled) (SharedRouteState, error) {
	if c.session != s {
		return SharedRouteState{}, fmt.Errorf("compiled for another binding: %w", ErrSharedCompiledStale)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	publisher, err := s.publishableLocked(ctx)
	if err != nil {
		return SharedRouteState{}, err
	}
	a := s.account
	a.mu.Lock()
	defer a.mu.Unlock()
	init, err := s.routeInitLocked()
	if err != nil {
		return SharedRouteState{}, err
	}
	fresh, err := s.checkCompiledLocked(c)
	if err != nil {
		return a.route.state, err
	}
	return s.publishCompiledLocked(ctx, publisher, init, fresh.policy)
}

// publishableLocked is the session half of the publication preconditions;
// s.mu is held.
func (s *BindingSession) publishableLocked(ctx context.Context) (SharedRoutePublisher, error) {
	if s.removed {
		return nil, fmt.Errorf("binding removed")
	}
	publisher, err := s.node.livePublisher(true)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return publisher, nil
}

// routeInitLocked is the account half of the publication preconditions: a
// reserved, not withdrawn route slot and the bound init's identity; s.mu and
// the account lock are held.
func (s *BindingSession) routeInitLocked() (SharedInitIdentity, error) {
	a := s.account
	if !a.native.reserved {
		return SharedInitIdentity{}, fmt.Errorf("binding has no route slot")
	}
	if a.withdrawn {
		return SharedInitIdentity{}, ErrSharedBindingWithdrawn
	}
	init, err := a.initIdentity()
	if err != nil {
		return SharedInitIdentity{}, fmt.Errorf("init identity: %w", err)
	}
	return init, nil
}

// compileLocked compiles policy against the account's current route and runs
// the refusals that depend on it; s.mu and the account lock are held.
func (s *BindingSession) compileLocked(policy SharedBindingPolicy) (SharedCompiled, error) {
	a := s.account
	last := a.route
	c := SharedCompiled{Generation: last.state.Generation + 1, session: s, base: last, input: policy}
	if policy.Source != nil {
		// Compiled at the generation this publication creates, with the
		// root epoch of a policy UID this binding already activated.
		activated := map[string]uint64{}
		if last.published && last.policy.Source != nil && last.policy.Source.ID == policy.Source.ID && last.epoch != 0 {
			activated[policy.Source.ID] = last.epoch
		}
		var err error
		if policy, err = policy.compile(c.Generation, activated); err != nil {
			return SharedCompiled{}, err
		}
	}
	if last.published && last.policy.Class != policy.Class {
		// Checked first: the most specific terminal refusal (G019 gap 6).
		return SharedCompiled{}, sharedClassChangeError(a.native.slot, last.policy.Class, policy.Class)
	}
	if policy.Class == sharedClassStrict {
		s.node.mu.Lock()
		refused := s.node.host.strictRefused
		s.node.mu.Unlock()
		if refused != nil {
			return SharedCompiled{}, fmt.Errorf("strict publication refused (design 13.8): %w: %w", refused, ErrSharedNativeUnavailable)
		}
	}
	if last.published && last.policy.program != nil && policy.program != nil {
		// G019 limit (lead decision, fail-closed): a revision keeps the
		// policy UID and root role; either change is terminal.
		was, _ := sharedCompiledPolicyOf(last.policy.program, last.policy.object)
		now, _ := sharedCompiledPolicyOf(policy.program, policy.object)
		if was.UID != now.UID || was.RootRole != now.RootRole {
			return SharedCompiled{}, fmt.Errorf("revision changes the policy UID or root role (terminal): %w", ErrSharedNativeUnavailable)
		}
	}
	c.policy, c.Program, c.Epochs = policy, policy.program, map[string]uint64{}
	if policy.program != nil {
		compiled, _ := sharedCompiledPolicyOf(policy.program, policy.object) // validated by compile
		c.Epochs[policy.Source.ID] = compiled.RootEpoch
	}
	return c, nil
}

// checkCompiledLocked refuses a stale c (ErrSharedCompiledStale) and returns
// a fresh compilation of its inputs, which must equal c; s.mu and the account
// lock are held.
func (s *BindingSession) checkCompiledLocked(c SharedCompiled) (SharedCompiled, error) {
	route := s.account.route
	if route.published != c.base.published || route.state != c.base.state || route.epoch != c.base.epoch || c.Generation != route.state.Generation+1 {
		return SharedCompiled{}, fmt.Errorf("compiled for generation %d against route %+v, binding route is now %+v: %w",
			c.Generation, c.base.state, route.state, ErrSharedCompiledStale)
	}
	fresh, err := s.compileLocked(c.input)
	if err != nil {
		return SharedCompiled{}, err
	}
	same := fresh.Generation == c.Generation && reflect.DeepEqual(fresh.Program, c.Program) &&
		fresh.policy.Class == c.policy.Class && fresh.policy.Fallback == c.policy.Fallback && fresh.policy.Rules == c.policy.Rules &&
		fresh.policy.Container == c.policy.Container
	if same && fresh.policy.object != nil {
		same = c.policy.object != nil && fresh.policy.object.Equal(c.policy.object)
	}
	if !same {
		return SharedCompiled{}, fmt.Errorf("compiled program no longer matches its policy and container: %w", ErrSharedCompiledStale)
	}
	return fresh, nil
}

// publishCompiledLocked commits a compiled policy into the binding's route
// slot (Publish's commit half); s.mu and the account lock are held, and the
// policy was compiled against the account's current route.
func (s *BindingSession) publishCompiledLocked(ctx context.Context, publisher SharedRoutePublisher, init SharedInitIdentity, policy SharedBindingPolicy) (SharedRouteState, error) {
	a := s.account
	last := a.route
	state, err := publisher.Publish(ctx, a.native.slot, s.cgroup, policy, !last.published, init)
	if err == nil {
		err = checkPublishedRoute(last, state, s.cgroup, policy)
	}
	if err != nil {
		err = fmt.Errorf("publish route slot %d: %w", a.native.slot, err)
		var adoption *ErrSharedAdoptionRefused
		if errors.As(err, &adoption) || errors.Is(err, errSharedPublishUnknown) {
			// A refused adoption (its route latched or being released) or an
			// unconfirmed first publication (latched) makes the cgroup
			// terminal at once (D5, design 13.15): no Publish of this session
			// and no rebind of the cgroup, even while the slot is latched.
			// This includes AdoptionRefusedIdentity refused before anything
			// was committed (an incomplete init identity): the identity comes
			// from the binding's immutable pins, so a retry cannot succeed.
			a.withdrawn = true
			s.node.markWithdrawn(s.cgroup)
		}
		if !last.published {
			// No last-good exists: the kernel may hold a route Go never
			// accepted. Read it back and record it as a fault, so Inspect
			// reports it and Remove withdraws at its generation.
			a.route = unconfirmedFirstRoute(publisher, a.native.slot, policy, err)
			return a.route.state, err
		}
		// Last-good: the recorded tuple stays authoritative; Inspect
		// reports any kernel divergence from it as a fault.
		return last.state, err
	}
	a.route = sharedLiveRoute{published: true, state: state, policy: policy}
	if policy.program != nil {
		c, _ := sharedCompiledPolicyOf(policy.program, policy.object) // validated by compile
		a.route.epoch = c.RootEpoch
	}
	return state, nil
}
