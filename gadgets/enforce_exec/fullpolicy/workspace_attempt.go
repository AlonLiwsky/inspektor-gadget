// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import "unsafe"

// This private model is not an artifact qualifier or runtime activation API.
// It sums logical allocation histories, including exposed backing capacities,
// with no GC/dedup refund. It excludes stacks, allocator slack and process globals.
// Its pinned compiler-lowering premises require separate consuming-build proof.
type sharedPolicyModel struct {
	total, bulk, pathSlots uint64
}

type attemptSum struct {
	bytes uint64
	err   error
}

func (s *attemptSum) add(n uint64) {
	if s.err == nil {
		s.bytes, s.err = syntaxWorkspaceSum(s.bytes, n)
	}
}

// With old=0 and byte width1, Grow selects required directly, then applies only
// noscan roundupsize. There is no nextslicecap growth term in this specialization.
func attemptByteCapacity(n uint64) (uint64, error) {
	if n == 0 {
		return 0, nil
	}
	return syntaxWorkspaceGrow(n, 0, syntaxWorkspaceBytes)
}

func attemptGlobBytes(n uint64) (uint64, error) {
	if n == 0 || n > MaxStringBytes {
		return 0, errSyntaxWorkspaceModel
	}
	var s attemptSum
	if n > 32 {
		v, e := attemptByteCapacity(4 * n)
		if e != nil {
			return 0, e
		}
		s.add(v)
	}
	main, e := attemptByteCapacity(9 + 21*n)
	if e != nil {
		return 0, e
	}
	s.add(main)
	// Independent class backings: disjoint source spans have length >=k+2+z.
	// Max rounded bytes/source-byte ratio covers their SUM, not a pooled capacity.
	var unit uint64
	for z := uint64(0); z <= 1; z++ {
		for k := uint64(1); k+2+z <= n; k++ {
			capacity, e := attemptByteCapacity(2 + z + 10*k)
			if e != nil {
				return 0, e
			}
			span := k + 2 + z
			unit = max(unit, (capacity+span-1)/span)
		}
	}
	s.add(n * unit)
	s.add(2 * n) // one two-byte QuoteMeta result per possible literal occurrence
	classes, e := syntaxWorkspaceAllClassCalls(n)
	if e != nil {
		return 0, e
	}
	s.add(classes)
	parser, e := syntaxWorkspaceFullParse(n)
	if e != nil {
		return 0, e
	}
	s.add(parser)
	code, e := syntaxWorkspaceKnownCosts(n)
	if e != nil {
		return 0, e
	}
	s.add(code.instructionBytes)
	s.add(code.progBytes) // parser already includes nodes
	return s.bytes, s.err
}

// The scan bounds follow actual allocation guards, not untrusted lengths. It
// selects no authored diagnostic: the original core retains validation order.
// Invalid strings never reach conversion; later unreachable bounded terms may
// be conservatively charged, but arbitrary caller graph tails are never scanned.
func sharedPolicyModelDebit(p Policy) (sharedPolicyModel, error) {
	return nativeModelDebit([]Policy{p}, true, "shared-object")
}

// nativeModelDebit shares one globally bounded authored-prefix scan. ownedSource
// selects the object-only retained source/digest costs; union output costs are
// distinct and never obtained by adding independent object debits.
func nativeModelDebit(policies []Policy, ownedSource bool, container string) (sharedPolicyModel, error) {
	var s attemptSum
	rules := 0
	for _, p := range policies {
		rules += min(len(p.Rules), MaxRules-rules)
	}
	s.add(uint64(unsafe.Sizeof(preparedProgram[nativePath]{})))
	s.add(uint64(len(policies)) * uint64(unsafe.Sizeof(preparedPolicy[nativePath]{})))
	s.add(uint64(rules) * uint64(unsafe.Sizeof(preparedRule[nativePath]{})))
	if ownedSource {
		s.add(uint64(rules) * uint64(unsafe.Sizeof(Rule{})))
		s.add(uint64(unsafe.Sizeof(SharedPolicy{})) + uint64(unsafe.Sizeof(Policy{})))
	} else {
		s.add(uint64(len(policies)) * uint64(unsafe.Sizeof(Policy{})))
		s.add(uint64(unsafe.Sizeof(sharedSnapshotExecution{})))
		s.add(uint64(len(policies)) * uint64(unsafe.Sizeof(SharedPolicyRef{})))
		s.add(uint64(unsafe.Sizeof(SharedSnapshot{})))
		s.add(uint64(min(len(container), MaxStringBytes)))
	}
	s.add(uint64(unsafe.Sizeof(kernelCompiler{})) + uint64(unsafe.Sizeof(emittedKernel{})))
	s.add(uint64(rules) * uint64(unsafe.Sizeof(RuleMetadata{})))
	if ownedSource {
		s.add(32)
	} // object digest Sum(nil)
	var patterns, pathSlots, instructions, roles, uids, stringsCount uint64
	identities := uint64(2 * len(policies))
	var costs [MaxStringBytes + 1]uint64 // stack-only length cache, not a global model cache
	text := func(v string) {
		if ownedSource {
			s.add(uint64(min(len(v), MaxStringBytes)))
		}
	}
	hash := func(v string) {
		n := uint64(min(len(v), MaxStringBytes))
		if n > 32 {
			b, e := attemptByteCapacity(n)
			if e != nil {
				s.err = e
			}
			s.add(b)
		}
	}
	// Every emitter identity call plus an upper bound on occupied validation calls.
	identity := func(v string) { hash(v); hash(v) }
	list := func(values []string, validate bool, filesystem bool) {
		count := min(len(values), MaxValues)
		s.add(uint64(count) * uint64(unsafe.Sizeof("")))
		for _, v := range values[:count] {
			text(v)
			if validate && len(v) > 32 && len(v) <= MaxStringBytes {
				s.add(uint64(len(v)))
				if filesystem {
					s.add(uint64(len(v)))
				}
			}
		}
	}
	paths := func(values []string) {
		list(values, false, false)
		if patterns > MaxPatterns || len(values) > MaxValues {
			return
		}
		pathSlots += uint64(len(values))
		s.add(uint64(len(values)) * uint64(unsafe.Sizeof(nativePath{})))
		for _, v := range values {
			patterns++
			if patterns > MaxPatterns {
				break
			}
			n := len(v)
			if n == 0 || n > MaxStringBytes {
				continue
			}
			if costs[n] == 0 {
				var e error
				costs[n], e = attemptGlobBytes(uint64(n))
				if e != nil {
					s.err = e
					return
				}
			}
			s.add(costs[n])
			instructions += uint64(2*n + 5)
		}
	}
	processedRules := 0
	for _, p := range policies {
		policyRules := min(len(p.Rules), MaxRules-processedRules)
		processedRules += policyRules
		root := p.RootRole
		if root == "" {
			root = "agent"
		}
		text(p.ID)
		text(p.Revision)
		text(string(p.Mode))
		text(root)
		text(string(p.Default))
		identity(p.ID)
		identity(root)
		for _, r := range p.Rules[:policyRules] {
			text(r.Name)
			text(r.Origin)
			text(string(r.Action))
			text(string(r.Mode))
			text(r.Target.SetRole)
			hash(p.ID) // rule metadata validation
			if r.Actor.FromImage != nil {
				s.add(1)
			}
			if r.Target.FromImage != nil {
				s.add(1)
			}
			paths(r.Actor.Path)
			paths(r.Target.Path)
			list(r.Actor.Role, false, false)
			nr := min(len(r.Actor.Role), MaxValues)
			roles += uint64(nr)
			identities += uint64(nr)
			for _, role := range r.Actor.Role[:nr] {
				identity(role)
			}
			if r.Target.SetRole != "" {
				identities++
				identity(r.Target.SetRole)
			}
			list(r.Actor.Container, true, false)
			list(r.Target.FSType, true, true)
			stringsCount += uint64(min(len(r.Actor.Container), MaxValues) + min(len(r.Target.FSType), MaxValues))
			nu := uint64(min(len(r.Actor.UID), MaxValues))
			uids += nu
			s.add(8 * nu)
			if a := r.Actor.Ancestor; a != nil {
				s.add(uint64(unsafe.Sizeof(Ancestor{})))
				paths(a.Path)
			}
			if a := r.Target.Argv; a != nil {
				s.add(uint64(unsafe.Sizeof(Argv{})))
				if a.StdinIsPipe != nil {
					s.add(1)
				}
				list(a.Contains, true, false)
				list(a.Prefix, true, false)
				stringsCount += uint64(min(len(a.Contains), MaxValues) + min(len(a.Prefix), MaxValues))
			}
		}
	}
	if len(container) > 32 && len(container) <= MaxStringBytes {
		s.add(uint64(len(container)))
	}

	q := min(patterns, uint64(MaxPatterns))
	s.add(identities * uint64(unsafe.Sizeof(identitySlot{})))
	s.add(q * uint64(unsafe.Sizeof(expressionSlot{})))
	s.add(8 * (roles + uids))
	entryBound := min(uint64(MaxKernelEntries), uint64(KernelRuleBase+rules)+1+q+roles+uids+stringsCount+min(uint64(MaxRegexInstructions), instructions))
	// Existing reserve's exact initial/doubling/clamped allocation history.
	var backing attemptSum
	capacity := uint64(KernelRuleBase + rules)
	allocations := uint64(0)
	for {
		backing.add(capacity * KernelBlobSize)
		allocations++
		if capacity >= entryBound {
			break
		}
		capacity = min(uint64(MaxKernelEntries), 2*capacity)
	}
	if s.err != nil {
		return sharedPolicyModel{}, s.err
	}
	if backing.err != nil {
		return sharedPolicyModel{}, backing.err
	}
	var total attemptSum
	total.add(uint64(unsafe.Sizeof(compilerWorkspace{})))
	total.add(s.bytes)
	total.add(backing.bytes)
	total.add(entryBound + uint64(len(policies))*uint64(unsafe.Sizeof(KernelPolicy{})))
	total.add((allocations + 2) * uint64(unsafe.Sizeof(workspaceReservation{})))
	return sharedPolicyModel{total: total.bytes, bulk: s.bytes, pathSlots: pathSlots}, total.err
}

// compileSharedPolicyModel is deliberately private: arithmetic is not authority
// to activate a native runtime. D is cumulative, on success and admitted failure;
// local token releases never refund that externally returned debit.
func compileSharedPolicyModel(policy Policy, remaining uint64) (object *SharedPolicy, debit uint64, err error) {
	model, modelErr := sharedPolicyModelDebit(policy)
	if modelErr != nil {
		return nil, 0, compactFailure(DiagnosticInternal, DiagnosticNone)
	}
	if model.total > remaining {
		return nil, 0, compactFailure(DiagnosticCapacity, DiagnosticNone)
	}
	debit = model.total
	work := compilerWorkspace{limit: model.total - uint64(unsafe.Sizeof(compilerWorkspace{}))}
	bulk, reserveErr := work.reserve(model.bulk)
	if reserveErr != nil {
		return nil, debit, compactDiagnosticsPolicy.forward(reserveErr)
	}
	defer func() {
		if releaseErr := bulk.release(); releaseErr != nil {
			object = nil
			err = compactDiagnosticsPolicy.join(err, releaseErr)
		}
		if work.used != work.metadata {
			object = nil
			err = compactDiagnosticsPolicy.join(err, errWorkspaceOwner)
		}
	}()
	object, err = compileSharedPolicyWithWorkspace(policy, compactDiagnosticsPolicy, &work)
	return object, debit, err
}
