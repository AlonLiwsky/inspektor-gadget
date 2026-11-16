// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import "errors"

// DiagnosticCode classifies a compact compiler failure, not runtime fault scope
// or permission to discard last-good state.
type DiagnosticCode uint8

const (
	DiagnosticNone DiagnosticCode = iota
	DiagnosticInvalidInput
	DiagnosticCapacity
	DiagnosticInternal
	DiagnosticOwnership
	diagnosticCount
)

// CompactDiagnostic contains only immutable scalar codes. It deliberately does
// not retain authored strings, parser errors, causes or formatting closures.
// The static diagnostic table is process-lifetime storage, not admitted memory.
type CompactDiagnostic interface {
	error
	Primary() DiagnosticCode
	Cleanup() DiagnosticCode
	compactDiagnostic()
}

type compactDiagnosticError struct{ primary, cleanup DiagnosticCode }

func (*compactDiagnosticError) compactDiagnostic()        {}
func (e *compactDiagnosticError) Primary() DiagnosticCode { return e.primary }
func (e *compactDiagnosticError) Cleanup() DiagnosticCode { return e.cleanup }
func (e *compactDiagnosticError) Error() string {
	if e.cleanup != DiagnosticNone {
		return "compiler failure with cleanup failure"
	}
	switch e.primary {
	case DiagnosticInvalidInput:
		return "invalid compiler input"
	case DiagnosticCapacity:
		return "compiler capacity exceeded"
	case DiagnosticOwnership:
		return "compiler ownership failure"
	default:
		return "internal compiler failure"
	}
}

var compactDiagnostics = func() [diagnosticCount][diagnosticCount]compactDiagnosticError {
	var table [diagnosticCount][diagnosticCount]compactDiagnosticError
	for i := range table {
		for j := range table[i] {
			table[i][j] = compactDiagnosticError{DiagnosticCode(i), DiagnosticCode(j)}
		}
	}
	return table
}()

func compactFailure(primary, cleanup DiagnosticCode) error {
	return &compactDiagnostics[primary][cleanup]
}

type diagnosticPolicy struct {
	compact bool
	invalid DiagnosticCode
}

var (
	richDiagnostics          = diagnosticPolicy{}
	compactDiagnosticsPolicy = diagnosticPolicy{compact: true, invalid: DiagnosticInvalidInput}
)

func (d diagnosticPolicy) invariant() diagnosticPolicy { d.invalid = DiagnosticInternal; return d }
func (d diagnosticPolicy) reject() error               { return compactFailure(d.invalid, DiagnosticNone) }

// forward preserves existing compact categories, classifies known private
// workspace errors, and treats unknown internal failures as internal, never as
// authored invalidity. Rich errors retain their exact concrete causes.
func (d diagnosticPolicy) forward(err error) error {
	if !d.compact || err == nil {
		return err
	}
	if e, ok := err.(*compactDiagnosticError); ok { //nolint:errorlint // Compiler leaves return these exact private records; never traverse unknown causes.
		return e
	}
	switch err {
	case errWorkspaceLimit: //nolint:errorlint // Workspace returns exact private sentinels, not wrapped errors.
		return compactFailure(DiagnosticCapacity, DiagnosticNone)
	case errWorkspaceOwner:
		return compactFailure(DiagnosticOwnership, DiagnosticNone)
	default:
		return compactFailure(DiagnosticInternal, DiagnosticNone)
	}
}

func (d diagnosticPolicy) join(primary, cleanup error) error {
	if !d.compact {
		return errors.Join(primary, cleanup)
	}
	if cleanup == nil {
		return d.forward(primary)
	}
	p := DiagnosticNone
	if primary != nil {
		p = d.forward(primary).(*compactDiagnosticError).primary //nolint:errorlint // Compact forward always returns this private scalar record.
	}
	c := d.forward(cleanup).(*compactDiagnosticError).primary //nolint:errorlint // Compact forward always returns this private scalar record.
	return compactFailure(p, c)
}
