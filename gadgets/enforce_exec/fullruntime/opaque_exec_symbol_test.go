// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

// This diagnostic-only lookup identifies a symbol, not its source semantics.
// Kernel qualification still has to certify the selected function's contract.
func opaqueDiagnosticExecOuterSymbol(r io.Reader) (string, error) {
	return opaqueDiagnosticKernelTextSymbol(r, "do_execveat_common", true)
}

// A different handler boundary requires explicit diagnostic selection; absence
// of the default symbol never authorizes a replacement or product admission.
func opaqueDiagnosticExecHandlerSymbol(r io.Reader, selected string) (string, error) {
	switch selected {
	case "":
		selected = "search_binary_handler"
	case "search_binary_handler", "exec_binprm":
	default:
		return "", fmt.Errorf("unsupported diagnostic exec handler source %q", selected)
	}
	return opaqueDiagnosticKernelTextSymbol(r, selected, false)
}

func opaqueDiagnosticKernelTextSymbol(r io.Reader, base string, allowISRA bool) (string, error) {
	const maxBytes = 64 << 20
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 1024), 4096)
	var found string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Exclude module symbols and anything other than built-in text.
		if len(fields) != 3 || (fields[1] != "t" && fields[1] != "T") {
			continue
		}
		name := fields[2]
		if name != base {
			suffix, ok := strings.CutPrefix(name, base+".isra.")
			if !allowISRA || !ok || suffix == "" || strings.IndexFunc(suffix, func(r rune) bool {
				return r < '0' || r > '9'
			}) >= 0 {
				continue
			}
		}
		if _, err := strconv.ParseUint(fields[0], 16, 64); err != nil {
			return "", fmt.Errorf("invalid address for diagnostic symbol %s: %w", name, err)
		}
		if found != "" {
			return "", fmt.Errorf("ambiguous diagnostic symbols: %s and %s", found, name)
		}
		found = name
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read kallsyms: %w", err)
	}
	if limited.N == 0 {
		return "", errors.New("kallsyms exceeds diagnostic input limit")
	}
	if found == "" {
		return "", fmt.Errorf("no unique built-in diagnostic symbol for %s", base)
	}
	return found, nil
}

func TestOpaqueDiagnosticExecHandlerSymbol(t *testing.T) {
	const both = "00000000 t search_binary_handler\n00000001 t exec_binprm\n"
	for _, tt := range []struct {
		name, input, selected, want string
		wantErr                     bool
	}{
		{"default", both, "", "search_binary_handler", false},
		{"explicit default", both, "search_binary_handler", "search_binary_handler", false},
		{"explicit exec_binprm", both, "exec_binprm", "exec_binprm", false},
		{"no automatic fallback", "00000000 t exec_binprm\n", "", "", true},
		{"missing selection", "00000000 t search_binary_handler\n", "exec_binprm", "", true},
		{"unsupported selection", both, "bprm_execve", "", true},
		{"duplicate", "00000000 t exec_binprm\n00000001 T exec_binprm\n", "exec_binprm", "", true},
		{"no cloned handler", "00000000 t exec_binprm.isra.0\n", "exec_binprm", "", true},
		{"no module handler", "00000000 t exec_binprm [module]\n", "exec_binprm", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := opaqueDiagnosticExecHandlerSymbol(strings.NewReader(tt.input), tt.selected)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("got (%q, %v), want (%q, error=%v)", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestOpaqueDiagnosticExecOuterSymbol(t *testing.T) {
	for _, tt := range []struct {
		name, input, want string
		wantErr           bool
	}{
		{"base", "00000000 T do_execveat_common\n", "do_execveat_common", false},
		{"Rocky", "00000000 t do_execveat_common.isra.38\n", "do_execveat_common.isra.38", false},
		{"AL2023", "00000000 t do_execveat_common.isra.0\n", "do_execveat_common.isra.0", false},
		{"unrelated", "00000000 t __pfx_do_execveat_common.isra.0\n00000000 T __x64_sys_execve\n00000000 t do_execveat_common.isra.0\n", "do_execveat_common.isra.0", false},
		{"none", "", "", true},
		{"ambiguous", "00000000 t do_execveat_common\n00000000 t do_execveat_common.isra.0\n", "", true},
		{"duplicate", "00000000 t do_execveat_common\n00000001 t do_execveat_common\n", "", true},
		{"invalid address", "invalid t do_execveat_common\n", "", true},
		{"data", "00000000 d do_execveat_common\n", "", true},
		{"module", "00000000 t do_execveat_common [module]\n", "", true},
		{"empty suffix", "00000000 t do_execveat_common.isra.\n", "", true},
		{"nonnumeric suffix", "00000000 t do_execveat_common.isra.x\n", "", true},
		{"other clone", "00000000 t do_execveat_common.constprop.0\n", "", true},
		{"overlong line", strings.Repeat("x", 4096), "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := opaqueDiagnosticExecOuterSymbol(strings.NewReader(tt.input))
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("got (%q, %v), want (%q, error=%v)", got, err, tt.want, tt.wantErr)
			}
		})
	}
	t.Run("read error", func(t *testing.T) {
		want := errors.New("read failed")
		if _, err := opaqueDiagnosticExecOuterSymbol(opaqueExecSymbolErrorReader{want}); !errors.Is(err, want) {
			t.Fatalf("got %v, want wrapped %v", err, want)
		}
	})
}

type opaqueExecSymbolErrorReader struct{ err error }

func (r opaqueExecSymbolErrorReader) Read([]byte) (int, error) { return 0, r.err }
