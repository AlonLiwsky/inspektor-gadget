// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"regexp/syntax"
	"unicode"
)

const (
	KernelBlobSize      = 288
	MaxKernelEntries    = 16384
	MaxRoleEpochHistory = 65536
	// UnknownRoleEpoch is reserved by the kernel role-history contract.
	UnknownRoleEpoch     = ^uint64(0)
	MaxRegexStates       = 512
	MaxRegexInstructions = 8192
	MaxRuneRanges        = 8
	KernelPolicyBase     = 1
	KernelRuleBase       = KernelPolicyBase + MaxPolicies
)

// Blob is the universal immutable inner-map value. All integers are little endian;
// every typed entry includes explicit padding to exactly288 bytes. References are
// absolute map keys except regex PCs, which are relative to Pattern.CodeBase.
type Blob [KernelBlobSize]byte

// KernelHeader offsets: generation0, policyCount8, ruleBase12, ruleCount16,
// containerRef20. Policies always occupy keys1..8; rules begin at9.
type KernelHeader struct {
	Generation                                     uint64
	PolicyCount, RuleBase, RuleCount, ContainerRef uint32
	Padding                                        [264]byte
}

// KernelPolicy offsets: UID0, rootRole8, default16 (0 absent,1 allow,2 deny),
// mode20 (1 audit,2 enforce), rootEpoch24. Stable hashes are not generation-local IDs.
// RootEpoch identifies the UID's first successful activation, not the current
// revision. A persistent owner retains it across removal/re-addition; staged role
// seeds from a failed attempt must never be accepted under another epoch.
type KernelPolicy struct {
	UID, RootRole uint64
	Default, Mode uint32
	RootEpoch     uint64
	Padding       [256]byte
}
type KernelList struct{ Base, Count uint32 }

// KernelRule offsets: policyIndex0 (zero based), mode4, deny8, actorImage12,
// targetImage16, stdin20, ancestorDepth24, reserved28, setRole32, lists40.
// Tri-state predicates encode -1 absent,0 false,1 true. Rule mode is resolved
// against the policy at compile time. SetRole0 means no transition.
type KernelRule struct {
	PolicyIndex, Mode, Deny                                                                        uint32
	ActorImage, TargetImage, Stdin                                                                 int32
	AncestorDepth, Reserved                                                                        uint32
	SetRole                                                                                        uint64
	ActorPath, TargetPath, AncestorPath, ActorRole, UID, Container, FSType, ArgContains, ArgPrefix KernelList
	Padding                                                                                        [176]byte
}

// KernelString bytes are UTF-8, without a terminator in Length; the remaining bytes
// are zero. The maximum authored length255 leaves an explicit trailing NUL.
type KernelString struct {
	Length  uint32
	Bytes   [256]byte
	Padding [28]byte
}
type KernelValue struct {
	Value   uint64
	Padding [280]byte
}
type KernelPattern struct {
	CodeBase, Start, Count uint32
	Padding                [276]byte
}

// The opcodes intentionally match regexp/syntax, but consuming variants are
// normalized to KernelRune with inclusive rune ranges. Consumers must decode
// UTF-8 input into runes; byte matching would silently alter Unicode predicates.
const (
	KernelAlt        uint32 = 0
	KernelEmptyWidth uint32 = 3
	KernelMatch      uint32 = 4
	KernelFail       uint32 = 5
	KernelNop        uint32 = 6
	KernelRune       uint32 = 7
	KernelBeginText  uint32 = 4
	KernelEndText    uint32 = 8
)

// KernelInstruction offsets: op0,out4,arg8,count12,ranges16. Arg is an alternate PC
// for Alt, an EmptyWidth mask for EmptyWidth, and zero otherwise. Count is the
// number of inclusive rune pairs (not the number of endpoints).
type KernelInstruction struct {
	Op, Out, Arg, Count uint32
	Ranges              [2 * MaxRuneRanges]uint32
	Padding             [208]byte
}

type RuleMetadata struct {
	PolicyIndex                      uint32
	PolicyID, Revision, Name, Origin string
}
type KernelProgram struct {
	// Identities lets a persistent owner also check collisions against names in
	// retained role state from older generations before committing this one.
	Identities map[uint64]string
	Entries    []Blob
	// Rules is indexed by the zero-based global rule index emitted by the kernel.
	// Entry key = KernelRuleBase + index. This is provenance, not matching input.
	Rules []RuleMetadata
}

// Decode reads a complete typed entry and rejects layout mismatches. It does not
// validate references in an untrusted map snapshot; only CompileKernel output
// is intended to be installed as a frozen program.
func Decode[T any](blob Blob) (T, error) {
	return decodeWithDiagnostics[T](blob, richDiagnostics)
}

func decodeWithDiagnostics[T any](blob Blob, d diagnosticPolicy) (T, error) {
	var result T
	if binary.Size(result) != KernelBlobSize {
		if d.compact {
			return result, compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return result, fmt.Errorf("entry layout must be %d bytes", KernelBlobSize)
	}
	if _, err := binary.Decode(blob[:], binary.LittleEndian, &result); err != nil {
		if d.compact {
			return result, d.forward(err)
		}
		// Preserve binary.Read's historical error spelling for unsupported generic
		// types. Successful fixed-width decoding needs neither reader nor scratch.
		err = binary.Read(bytes.NewReader(blob[:]), binary.LittleEndian, &result)
		return result, err
	}
	return result, nil
}

func encode(value any) (Blob, error) {
	return encodeWithDiagnostics(value, richDiagnostics)
}

func encodeWithDiagnostics(value any, d diagnosticPolicy) (Blob, error) {
	var result Blob
	if binary.Size(value) != KernelBlobSize {
		if d.compact {
			return result, compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return result, fmt.Errorf("entry layout must be %d bytes", KernelBlobSize)
	}
	if _, err := binary.Encode(result[:], binary.LittleEndian, value); err != nil {
		if d.compact {
			return Blob{}, d.forward(err)
		}
		// Keep the old error contract without retaining a buffer on valid paths.
		result = Blob{}
		var b bytes.Buffer
		if err := binary.Write(&b, binary.LittleEndian, value); err != nil {
			return result, err
		}
		copy(result[:], b.Bytes())
	}
	return result, nil
}

func stableHash(value string) uint64 {
	sum := sha256.Sum256([]byte(value))
	return binary.LittleEndian.Uint64(sum[:8])
}

type kernelCompiler struct {
	diagnostics  diagnosticPolicy
	work         *compilerWorkspace
	entriesWork  *workspaceReservation
	entries      []Blob
	instructions int
	names        fixedIdentities
	patterns     fixedExpressions
	hash         func(string) uint64
}

// CompileKernel prepares bounded frozen-map data; it neither loads BPF nor
// claims kernel capability support. Any error returns nil, never partial rules.
func CompileKernel(policies []Policy, generation uint64, container string) (*KernelProgram, error) {
	p, err := compileKernel(policies, generation, container, stableHash)
	if err != nil {
		return nil, err
	}
	if err = ValidateKernelProgram(p); err != nil {
		return nil, err
	}
	return p, nil
}

// CompileKernelWithRoleEpochs preserves successful policy-UID activations across
// revisions. Epochs are trusted persistent-owner state, never policy-authored
// input. New UIDs use this attempt's generation. The owner records a new epoch
// only at successful publication; failed attempts cannot establish a root role.
// This metadata does not bootstrap tasks or authorize seed writes by itself.
func CompileKernelWithRoleEpochs(policies []Policy, generation uint64, container string, activated map[string]uint64) (*KernelProgram, error) {
	if len(activated) > MaxRoleEpochHistory {
		return nil, fmt.Errorf("role activation history capacity exceeded")
	}
	// The owner's lifetime catalogue may include currently absent policies. Only
	// active candidates are encoded, but ALL supplied epochs must be well-formed.
	for id, epoch := range activated {
		if id == "" {
			return nil, fmt.Errorf("empty historical policy UID")
		}
		if err := validateString(id); err != nil {
			return nil, err
		}
		if epoch == 0 || epoch == UnknownRoleEpoch || epoch > generation {
			return nil, fmt.Errorf("invalid successful role activation epoch")
		}
	}
	p, err := CompileKernel(policies, generation, container)
	if err != nil {
		return nil, err
	}
	for i := range policies {
		key := KernelPolicyBase + i
		entry := decodeKernelPolicy(p.Entries[key])
		epoch, retained := activated[p.Identities[entry.UID]]
		if !retained {
			continue
		}
		entry.RootEpoch = epoch
		p.Entries[key] = encodeKernelPolicy(entry)
	}
	if err := ValidateKernelProgram(p); err != nil {
		return nil, err
	}
	return p, nil
}

func compileKernel(policies []Policy, generation uint64, container string, hash func(string) uint64) (*KernelProgram, error) {
	program, err := preparePolicies(policies, nativeGlob)
	if err != nil {
		return nil, err
	}
	emitted, err := compilePreparedKernel(program, generation, container, hash)
	if err != nil {
		return nil, err
	}
	return emitted.legacy(), nil
}

// compilePreparedKernel consumes private validated, copied source and exact glob
// expressions. Callers must validate the emitted data before exposing it.
func compilePreparedKernel(program *preparedProgram[nativePath], generation uint64, container string, hash func(string) uint64) (*emittedKernel, error) {
	return compilePreparedKernelWithDiagnostics(program, generation, container, hash, richDiagnostics)
}

func compilePreparedKernelWithDiagnostics(program *preparedProgram[nativePath], generation uint64, container string, hash func(string) uint64, d diagnosticPolicy) (*emittedKernel, error) {
	return compilePreparedKernelWithWorkspace(program, generation, container, hash, d, nil, nil)
}

// entriesOwner is private synchronous transfer to the enclosing attempt only.
// No token is stored in emitted data or the returned immutable shared object.
func compilePreparedKernelWithWorkspace(program *preparedProgram[nativePath], generation uint64, container string, hash func(string) uint64, d diagnosticPolicy, work *compilerWorkspace, entriesOwner **workspaceReservation) (_ *emittedKernel, resultErr error) {
	if work != nil && entriesOwner == nil {
		return nil, d.forward(errWorkspaceOwner)
	}
	if generation == 0 || generation == UnknownRoleEpoch {
		if d.compact {
			return nil, d.reject()
		}
		return nil, fmt.Errorf("generation must be nonzero and below the unknown-epoch sentinel")
	}
	if err := validateStringWithDiagnostics(container, d); err != nil {
		if d.compact {
			return nil, d.forward(err)
		}
		return nil, fmt.Errorf("container name: %w", err)
	}
	count := 0
	for _, p := range program.policies {
		count += len(p.rules)
	}
	identityCapacity, expressionCapacity := preparedLookupCapacities(program)
	c := &kernelCompiler{work: work, diagnostics: d, names: fixedIdentities{slots: make([]identitySlot, identityCapacity)}, patterns: fixedExpressions{slots: make([]expressionSlot, expressionCapacity)}, hash: hash}
	defer func() {
		if c.entriesWork != nil {
			if err := c.entriesWork.release(); err != nil {
				resultErr = d.join(resultErr, err)
			}
		}
	}()
	if _, err := c.reserve(KernelRuleBase + count); err != nil {
		return nil, err
	}
	result := &emittedKernel{Rules: make([]RuleMetadata, 0, count)}
	containerRef, err := c.strings([]string{container})
	if err != nil {
		return nil, err
	}
	if err := c.put(0, encodeKernelHeader(KernelHeader{Generation: generation, PolicyCount: uint32(len(program.policies)), RuleBase: KernelRuleBase, RuleCount: uint32(count), ContainerRef: containerRef.Base})); err != nil {
		return nil, err
	}
	for pi, p := range program.policies {
		uid, err := c.identifier(p.source.ID)
		if err != nil {
			return nil, err
		}
		root, err := c.identifier(p.source.RootRole)
		if err != nil {
			return nil, err
		}
		var defaultAction uint32
		switch p.source.Default {
		case Allow:
			defaultAction = 1
		case Deny:
			defaultAction = 2
		}
		if err := c.put(uint32(KernelPolicyBase+pi), encodeKernelPolicy(KernelPolicy{UID: uid, RootRole: root, Default: defaultAction, Mode: kernelMode(p.source.Mode), RootEpoch: generation})); err != nil {
			return nil, err
		}
		for _, cr := range p.rules {
			r := cr.source
			mode := r.Mode
			if mode == "" {
				mode = p.source.Mode
			}
			entry := KernelRule{PolicyIndex: uint32(pi), Mode: kernelMode(mode), ActorImage: tri(r.Actor.FromImage), TargetImage: tri(r.Target.FromImage), Stdin: -1}
			if r.Action == Deny {
				entry.Deny = 1
			}
			if r.Target.SetRole != "" {
				entry.SetRole, err = c.identifier(r.Target.SetRole)
				if err != nil {
					return nil, err
				}
			}
			if entry.ActorPath, err = c.pathList(cr.actor); err != nil {
				return nil, err
			}
			if entry.TargetPath, err = c.pathList(cr.target); err != nil {
				return nil, err
			}
			if entry.AncestorPath, err = c.pathList(cr.ancestor); err != nil {
				return nil, err
			}
			if r.Actor.Ancestor != nil {
				entry.AncestorDepth = uint32(r.Actor.Ancestor.Depth)
			}
			roles := make([]uint64, len(r.Actor.Role))
			for i, role := range r.Actor.Role {
				roles[i], err = c.identifier(role)
				if err != nil {
					return nil, err
				}
			}
			if entry.ActorRole, err = c.values(roles); err != nil {
				return nil, err
			}
			uids := make([]uint64, len(r.Actor.UID))
			for i, uid := range r.Actor.UID {
				uids[i] = uint64(uid)
			}
			if entry.UID, err = c.values(uids); err != nil {
				return nil, err
			}
			if entry.Container, err = c.strings(r.Actor.Container); err != nil {
				return nil, err
			}
			if entry.FSType, err = c.strings(r.Target.FSType); err != nil {
				return nil, err
			}
			if a := r.Target.Argv; a != nil {
				entry.Stdin = tri(a.StdinIsPipe)
				if entry.ArgContains, err = c.strings(a.Contains); err != nil {
					return nil, err
				}
				if entry.ArgPrefix, err = c.strings(a.Prefix); err != nil {
					return nil, err
				}
			}
			if err := c.put(uint32(KernelRuleBase+len(result.Rules)), encodeKernelRule(entry)); err != nil {
				return nil, err
			}
			result.Rules = append(result.Rules, RuleMetadata{PolicyIndex: uint32(pi), PolicyID: p.source.ID, Revision: p.source.Revision, Name: r.Name, Origin: r.Origin})
		}
	}
	result.identities = c.names
	result.Entries = c.entries
	if entriesOwner != nil {
		*entriesOwner = c.entriesWork
		c.entriesWork = nil
	}
	return result, nil
}

func kernelMode(mode Mode) uint32 {
	if mode == Enforce {
		return 2
	}
	return 1
}

func tri(value *bool) int32 {
	if value == nil {
		return -1
	}
	if *value {
		return 1
	}
	return 0
}

func (c *kernelCompiler) identifier(value string) (uint64, error) {
	id := c.hash(value)
	if err := c.names.insertWithDiagnostics(id, value, c.diagnostics); err != nil {
		return 0, err
	}
	return id, nil
}

func (c *kernelCompiler) reserve(count int) (KernelList, error) {
	if count == 0 {
		return KernelList{}, nil
	}
	if count < 0 || count > MaxKernelEntries-len(c.entries) {
		if c.diagnostics.compact {
			return KernelList{}, compactFailure(DiagnosticCapacity, DiagnosticNone)
		}
		return KernelList{}, fmt.Errorf("kernel entry capacity exceeds %d", MaxKernelEntries)
	}
	// A metered backing must retain its exact owner until replacement or
	// explicit transfer. Never silently adopt an already uncharged buffer.
	if c.work != nil {
		if cap(c.entries) == 0 {
			if c.entriesWork != nil {
				return KernelList{}, c.diagnostics.forward(errWorkspaceOwner)
			}
		} else if c.entriesWork == nil || c.entriesWork.self != c.entriesWork || c.entriesWork.owner != c.work || c.entriesWork.bytes != uint64(cap(c.entries))*KernelBlobSize || c.work.metadata > c.work.used || c.entriesWork.bytes > c.work.used-c.work.metadata {
			return KernelList{}, c.diagnostics.forward(errWorkspaceOwner)
		}
	} else if c.entriesWork != nil {
		return KernelList{}, c.diagnostics.forward(errWorkspaceOwner)
	}
	list := KernelList{Base: uint32(len(c.entries)), Count: uint32(count)}
	needed := len(c.entries) + count
	if needed <= cap(c.entries) {
		c.entries = c.entries[:needed]
		clear(c.entries[list.Base:])
		return list, nil
	}
	capacity := cap(c.entries)
	if capacity == 0 {
		capacity = needed
	}
	for capacity < needed {
		capacity = min(MaxKernelEntries, 2*capacity)
	}
	// Reserve the replacement while the old backing is still charged. The
	// fixed entry cap makes this multiplication bounded before allocation.
	charge, err := c.work.reserve(uint64(capacity) * KernelBlobSize)
	if err != nil {
		return KernelList{}, c.diagnostics.forward(err)
	}
	entries := make([]Blob, needed, capacity)
	copy(entries, c.entries)
	if c.entriesWork != nil {
		if err := c.entriesWork.release(); err != nil {
			// Ownership was checked above and no concurrent use is permitted. Keep
			// the old buffer intact if the invariant nevertheless fails.
			_ = charge.release()
			return KernelList{}, c.diagnostics.forward(err)
		}
	}
	c.entries, c.entriesWork = entries, charge
	return list, nil
}

func (c *kernelCompiler) put(index uint32, blob Blob) error {
	if int(index) >= len(c.entries) {
		if c.diagnostics.compact {
			return compactFailure(DiagnosticInternal, DiagnosticNone)
		}
		return fmt.Errorf("entry index out of bounds")
	}
	c.entries[index] = blob
	return nil
}

func (c *kernelCompiler) strings(values []string) (KernelList, error) {
	list, err := c.reserve(len(values))
	if err != nil {
		return KernelList{}, c.diagnostics.forward(err)
	}
	for i, value := range values {
		if err := validateStringWithDiagnostics(value, c.diagnostics.invariant()); err != nil {
			return KernelList{}, c.diagnostics.forward(err)
		}
		entry := KernelString{Length: uint32(len(value))}
		copy(entry.Bytes[:], value)
		if err := c.put(list.Base+uint32(i), encodeKernelString(entry)); err != nil {
			return KernelList{}, c.diagnostics.forward(err)
		}
	}
	return list, nil
}

func (c *kernelCompiler) values(values []uint64) (KernelList, error) {
	list, err := c.reserve(len(values))
	if err != nil {
		return KernelList{}, c.diagnostics.forward(err)
	}
	for i, value := range values {
		if err := c.put(list.Base+uint32(i), encodeKernelValue(KernelValue{Value: value})); err != nil {
			return KernelList{}, c.diagnostics.forward(err)
		}
	}
	return list, nil
}

func (c *kernelCompiler) pathList(patterns []nativePath) (KernelList, error) {
	list, err := c.reserve(len(patterns))
	if err != nil {
		return KernelList{}, c.diagnostics.forward(err)
	}
	for i, path := range patterns {
		expression := path.expression
		pattern, ok := c.patterns.lookup(expression)
		if !ok {
			pattern, err = c.regexNative(path)
			if err != nil {
				return KernelList{}, c.diagnostics.forward(err)
			}
			if err = c.patterns.insertWithDiagnostics(expression, pattern, c.diagnostics); err != nil {
				return KernelList{}, c.diagnostics.forward(err)
			}
		}
		if err := c.put(list.Base+uint32(i), encodeKernelPattern(pattern)); err != nil {
			return KernelList{}, c.diagnostics.forward(err)
		}
	}
	return list, nil
}

// Authored provenance is checked at the actual full Parse boundary on metered
// calls. Its complete syntax history was reserved before preparation.
func (c *kernelCompiler) regexNative(path nativePath) (KernelPattern, error) {
	if c.work != nil && (path.authoredBytes == 0 || path.authoredBytes > MaxStringBytes) {
		return KernelPattern{}, compactFailure(DiagnosticInternal, DiagnosticNone)
	}
	return c.regex(path.expression)
}

func (c *kernelCompiler) regex(expression string) (KernelPattern, error) {
	re, err := syntax.Parse(expression, syntax.Perl)
	if err != nil {
		return KernelPattern{}, c.diagnostics.forward(err)
	}
	program, err := syntax.Compile(re.Simplify())
	if err != nil {
		return KernelPattern{}, c.diagnostics.forward(err)
	}
	if len(program.Inst) > MaxRegexStates {
		if c.diagnostics.compact {
			return KernelPattern{}, compactFailure(DiagnosticCapacity, DiagnosticNone)
		}
		return KernelPattern{}, fmt.Errorf("pattern exceeds %d regex states", MaxRegexStates)
	}
	if len(program.Inst) > MaxRegexInstructions-c.instructions {
		if c.diagnostics.compact {
			return KernelPattern{}, compactFailure(DiagnosticCapacity, DiagnosticNone)
		}
		return KernelPattern{}, fmt.Errorf("program exceeds %d regex instructions", MaxRegexInstructions)
	}
	code, err := c.reserve(len(program.Inst))
	if err != nil {
		return KernelPattern{}, c.diagnostics.forward(err)
	}
	for i, instruction := range program.Inst {
		packed, err := packInstructionWithDiagnostics(instruction, c.diagnostics.invariant())
		if err != nil {
			return KernelPattern{}, c.diagnostics.forward(err)
		}
		if err := c.put(code.Base+uint32(i), encodeKernelInstruction(packed)); err != nil {
			return KernelPattern{}, c.diagnostics.forward(err)
		}
	}
	c.instructions += len(program.Inst)
	return KernelPattern{CodeBase: code.Base, Start: uint32(program.Start), Count: code.Count}, nil
}

func packInstruction(in syntax.Inst) (KernelInstruction, error) {
	return packInstructionWithDiagnostics(in, richDiagnostics)
}

func packInstructionWithDiagnostics(in syntax.Inst, d diagnosticPolicy) (KernelInstruction, error) {
	out := KernelInstruction{Out: in.Out}
	var ranges []rune
	switch in.Op {
	case syntax.InstAlt, syntax.InstAltMatch:
		out.Op = KernelAlt
		out.Arg = in.Arg
	case syntax.InstEmptyWidth:
		if in.Arg & ^uint32(syntax.EmptyBeginText|syntax.EmptyEndText) != 0 {
			if d.compact {
				return out, d.reject()
			}
			return out, fmt.Errorf("unsupported regexp boundary")
		}
		out.Op = KernelEmptyWidth
		out.Arg = in.Arg
	case syntax.InstMatch:
		out.Op = KernelMatch
	case syntax.InstFail:
		out.Op = KernelFail
	case syntax.InstNop, syntax.InstCapture:
		out.Op = KernelNop
	case syntax.InstRune, syntax.InstRune1:
		if in.Arg != 0 {
			if d.compact {
				return out, d.reject()
			}
			return out, fmt.Errorf("unsupported regexp rune flags")
		}
		if len(in.Rune) == 1 {
			ranges = []rune{in.Rune[0], in.Rune[0]}
		} else {
			ranges = in.Rune
		}
		out.Op = KernelRune
	case syntax.InstRuneAny:
		out.Op = KernelRune
		ranges = []rune{0, unicode.MaxRune}
	case syntax.InstRuneAnyNotNL:
		out.Op = KernelRune
		ranges = []rune{0, '\n' - 1, '\n' + 1, unicode.MaxRune}
	default:
		if d.compact {
			return out, d.reject()
		}
		return out, fmt.Errorf("unsupported regexp instruction %d", in.Op)
	}
	if len(ranges)%2 != 0 || len(ranges) > 2*MaxRuneRanges {
		if d.compact {
			if len(ranges)%2 != 0 {
				return out, compactFailure(DiagnosticInternal, DiagnosticNone)
			}
			return out, compactFailure(DiagnosticCapacity, DiagnosticNone)
		}
		return out, fmt.Errorf("regexp instruction exceeds %d rune ranges", MaxRuneRanges)
	}
	out.Count = uint32(len(ranges) / 2)
	for i, value := range ranges {
		if value < 0 || value > unicode.MaxRune {
			if d.compact {
				return out, d.reject()
			}
			return out, fmt.Errorf("invalid regexp rune")
		}
		out.Ranges[i] = uint32(value)
	}
	return out, nil
}
