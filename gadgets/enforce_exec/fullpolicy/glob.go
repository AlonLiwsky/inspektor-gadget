// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"path"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
)

// nativePath preserves conversion provenance per original authored occurrence.
// The matcher deduplication key is expression alone; authoredBytes is not part
// of native content or identity and grants no memory-admission authority.
type nativePath struct {
	expression    string
	authoredBytes uint64
}

// nativeGlob is the native preparePolicies backend. preparePaths validates the
// original absolute path and byte limit before calling it. Capture that length
// BEFORE conversion, whose class parser calls precede native matcher emission.
// No workspace qualification or reservation is implied by this metadata.
func nativeGlob(pattern string) (nativePath, error) {
	return nativeGlobWithDiagnostics(pattern, richDiagnostics)
}

func nativeGlobWithDiagnostics(pattern string, d diagnosticPolicy) (nativePath, error) {
	authoredBytes := uint64(len(pattern))
	expression, err := globExpressionWithDiagnostics(pattern, d)
	if err != nil {
		return nativePath{}, err
	}
	return nativePath{expression: expression, authoredBytes: authoredBytes}, nil
}

// glob uses pathname semantics: '*' and '?' do not cross '/', '**' does.
// Character classes follow path.Match, including negation and ranges. Rejecting
// malformed patterns is mandatory; they cannot become unconstrained predicates.
func globExpression(pattern string) (string, error) {
	return globExpressionWithDiagnostics(pattern, richDiagnostics)
}

func globExpressionWithDiagnostics(pattern string, d diagnosticPolicy) (string, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		if d.compact {
			return "", d.reject()
		}
		return "", fmt.Errorf("malformed glob %q: %w", pattern, err)
	}
	chars := []rune(pattern)
	var b strings.Builder
	// The wrapper uses nine bytes; each authored byte produces at most one
	// 21-byte normalized interval. Overflow only omits this growth optimization.
	if capacity, ok := checkedGlobCapacity(len(pattern), 21, 9); ok {
		b.Grow(capacity)
	}
	var scratch [10]byte
	b.WriteString("\\A(?s:")
	for i := 0; i < len(chars); i++ {
		switch c := chars[i]; c {
		case '*':
			if i+1 < len(chars) && chars[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			var classPattern strings.Builder
			if capacity, ok := globClassCapacity(chars, i); ok {
				classPattern.Grow(capacity)
			}
			classPattern.WriteByte('[')
			i++
			if chars[i] == '^' {
				classPattern.WriteByte('^')
				i++
			}
			for chars[i] != ']' {
				switch chars[i] {
				case '\\':
					i++
					encoded, ok := runeEscape(chars[i], &scratch)
					if !ok {
						return "", compactFailure(DiagnosticInternal, DiagnosticNone)
					}
					classPattern.Write(encoded)
				case '-':
					classPattern.WriteByte('-')
				default:
					encoded, ok := runeEscape(chars[i], &scratch)
					if !ok {
						return "", compactFailure(DiagnosticInternal, DiagnosticNone)
					}
					classPattern.Write(encoded)
				}
				i++
			}
			classPattern.WriteByte(']')
			// Expand classes once using path.Match class semantics.
			// Canonicalize path.Match escapes before parsing:
			// [\\d] contains literal d, not a regexp digit shorthand.
			class, err := syntax.Parse(classPattern.String(), syntax.Perl)
			if err != nil {
				if d.compact {
					return "", compactClassParseFailure(err)
				}
				return "", fmt.Errorf("malformed glob %q: %w", pattern, err)
			}
			switch class.Op {
			case syntax.OpLiteral, syntax.OpCharClass:
				// Literal runes feed (r,r) directly into the same interval
				// emitter; character-class ranges remain borrowed parser data.
			default:
				if d.compact {
					return "", compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				return "", fmt.Errorf("unsupported character class")
			}
			b.WriteByte('[')
			written := false
			for j := 0; j < len(class.Rune); {
				lo := class.Rune[j]
				hi := lo
				j++
				if class.Op == syntax.OpCharClass {
					hi = class.Rune[j]
					j++
				}
				if lo > hi {
					continue
				}
				// Validate BOTH endpoints before writing either escape. Each
				// escape fits the caller-owned ten-byte scratch exactly.
				if lo < 0 || hi > unicode.MaxRune {
					return "", compactFailure(DiagnosticInternal, DiagnosticNone)
				}
				encoded, _ := runeEscape(lo, &scratch)
				b.Write(encoded)
				b.WriteByte('-')
				encoded, _ = runeEscape(hi, &scratch)
				b.Write(encoded)
				written = true
			}
			// Defensive representation for an empty class.
			if !written {
				b.WriteString("^\\x{0}-\\x{10ffff}")
			}
			b.WriteByte(']')
		case '\\':
			i++
			b.WriteString(regexp.QuoteMeta(string(chars[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(")\\z")
	return b.String(), nil
}

func nativeGlobCompact(pattern string) (nativePath, error) {
	return nativeGlobWithDiagnostics(pattern, compactDiagnosticsPolicy)
}

// runeEscape writes \x{hex} without formatting or append growth. Unicode's
// largest code point uses six hex digits: three prefix bytes + six + one suffix.
// Invalid endpoints leave the caller-owned scratch unchanged.
func runeEscape(r rune, scratch *[10]byte) ([]byte, bool) {
	if r < 0 || r > unicode.MaxRune {
		return nil, false
	}
	width := 1
	for value := uint32(r); value >= 16; value >>= 4 {
		width++
	}
	scratch[0], scratch[1], scratch[2] = '\\', 'x', '{'
	value := uint32(r)
	const hex = "0123456789abcdef"
	for i := width + 2; i >= 3; i-- {
		scratch[i] = hex[value&15]
		value >>= 4
	}
	scratch[width+3] = '}'
	return scratch[:width+4], true
}

// compactClassParseFailure classifies only the raw generated-class parser leaf.
// After pathname validation and hexadecimal escaping, reversed authored ranges
// are the only expected syntax failure. Other codes (including size/depth) mean
// an internal invariant failed; never retain the parser expression or cause.
func compactClassParseFailure(err error) error {
	if leaf, ok := err.(*syntax.Error); ok && leaf != nil && leaf.Code == syntax.ErrInvalidCharRange { //nolint:errorlint // Direct raw parser leaf only; do not traverse causes.
		return compactFailure(DiagnosticInvalidInput, DiagnosticNone)
	}
	return compactFailure(DiagnosticInternal, DiagnosticNone)
}

// checkedGlobCapacity computes a construction length bound, not allocated size
// or memory admission. A failed check means callers retain ordinary builder
// growth, preserving the unrestricted converter's acceptance behavior.
func checkedGlobCapacity(count, scale, base int) (int, bool) {
	maxInt := int(^uint(0) >> 1)
	if count < 0 || scale <= 0 || base < 0 || count > (maxInt-base)/scale {
		return 0, false
	}
	return base + scale*count, true
}

// globClassCapacity counts data tokens in an already path.Match-validated class
// beginning at start. Escaped runes count once; raw hyphens count as tokens, not
// parsed ranges. No validation or class parsing moves ahead of syntax.Parse.
// Brackets + optional negation + at most ten bytes per hex-escaped token.
func globClassCapacity(chars []rune, start int) (int, bool) {
	i := start + 1
	base := 2
	if chars[i] == '^' {
		base++
		i++
	}
	tokens := 0
	for chars[i] != ']' {
		if chars[i] == '\\' {
			i++
		}
		tokens++
		i++
	}
	return checkedGlobCapacity(tokens, 10, base)
}
