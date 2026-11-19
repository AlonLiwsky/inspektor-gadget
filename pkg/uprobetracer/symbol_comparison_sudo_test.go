// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package uprobetracer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
)

// Compare against cilium's public name-based attachment API, not a copy of its
// symbol parser. The kernel reports the actual file offset used by the probe,
// so aliases in libc do not make a reverse address-to-name lookup ambiguous.
// Run with go test -exec sudo ./pkg/uprobetracer -run TestCachedSymbolMatchesCilium.
// Requires a kernel exposing perf-event uprobe link info (Linux 6.6+), a C
// compiler, and the libc/OpenSSL development libraries.
func TestCachedSymbolMatchesCilium(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for uprobe attachment")
	}
	cc, err := exec.LookPath("cc")
	require.NoError(t, err, "install a C compiler and libc/OpenSSL development libraries")
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Kprobe, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, prog.Close()) })

	for _, library := range []struct {
		name    string
		symbols []string
	}{
		{"libc.so.6", []string{"malloc", "free", "read", "write"}},
		{"libssl.so", []string{"SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex"}},
	} {
		t.Run(library.name, func(t *testing.T) {
			output, err := exec.Command(cc, "-print-file-name="+library.name).Output()
			require.NoError(t, err)
			path := strings.TrimSpace(string(output))
			require.True(t, filepath.IsAbs(path), "compiler could not locate %s: %q", library.name, path)
			file, err := os.Open(path)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, file.Close()) })
			for _, kind := range []string{"entry", "return"} {
				t.Run(kind, func(t *testing.T) {
					for _, symbol := range append(library.symbols, "__ig_missing_ordinary_symbol__") {
						t.Run(symbol, func(t *testing.T) {
							// Fresh instances guarantee each case exercises a cold lookup
							// followed by the same result from both implementations' caches.
							executable, err := link.OpenExecutable(path)
							require.NoError(t, err)
							attach := executable.Uprobe
							if kind == "return" {
								attach = executable.Uretprobe
							}
							cache := newSymbolCache(16, parseOrdinaryContext)
							for _, temperature := range []string{"cold", "warm"} {
								t.Run(temperature, func(t *testing.T) {
									offset, cachedErr := cache.resolve(file, symbol)
									probe, ciliumErr := attach(symbol, prog, nil)
									if symbol == "__ig_missing_ordinary_symbol__" {
										require.Nil(t, probe)
										require.ErrorIs(t, ciliumErr, link.ErrNoSymbol)
										require.ErrorIs(t, cachedErr, link.ErrNoSymbol)
										return
									}
									require.NoError(t, ciliumErr)
									t.Cleanup(func() { require.NoError(t, probe.Close()) })
									require.NoError(t, cachedErr)
									info, err := probe.Info()
									require.NoError(t, err)
									require.NotNil(t, info.PerfEvent(), "kernel must expose perf-event link info")
									uprobe := info.PerfEvent().Uprobe()
									require.NotNil(t, uprobe, "kernel must expose uprobe link info")
									require.Equal(t, uint64(uprobe.Offset), offset, "cached lookup must match cilium's name-based attachment")
								})
							}
						})
					}
				})
			}
		})
	}
}
