// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package uprobetracer

import (
	"context"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/safeelf"
)

// maxGoSectionSize is the maximum size we'll read for .gopclntab and
// .gosymtab sections. This prevents a malicious binary inside a container
// from causing excessive memory allocation in the privileged IG process.
// 64 MiB is generous: typical Go binaries have .gopclntab well under 32 MiB
// even for very large programs.
const maxGoSectionSize = 64 * 1024 * 1024

// maxGoFuncCount is the maximum number of functions we accept in a
// .gopclntab section. debug/gosym allocates two slices of that many elements
// (152 bytes per function on amd64) from a function count that is only
// constrained by the functab fitting in the section, at 8 bytes per function.
// A crafted section is therefore amplified about 19 times, while a legitimate
// one uses around 280 bytes of pclntab per function. The limit keeps the
// worst case at roughly 150 MiB and is generous: kubelet declares about 67000
// functions and ig about 103000.
const maxGoFuncCount = 1000 * 1000

// moduledataTextOffset is the pointer-sized field index of moduledata.text
// in the Go 1.26 moduledata layout. It follows pcHeader, six slices,
// findfunctab, minpc, and maxpc. Go does not expose this internal layout via
// the standard library. See:
// https://github.com/golang/go/blob/go1.26.5/src/runtime/symtab.go#L402-L450.
const moduledataTextOffset = 22

// goModuleTextStart reads moduledata.text from Go 1.26+'s .go.module
// section. The section contains the link-time moduledata structure emitted by
// the Go linker. A false result means that the binary predates this section.
func goModuleTextStart(f *safeelf.File) (textStart uint64, found bool, err error) {
	moduleSection := f.Section(".go.module")
	if moduleSection == nil {
		return 0, false, nil
	}
	if moduleSection.Size > maxGoSectionSize {
		return 0, true, fmt.Errorf("%w: .go.module too large (%d bytes, max %d)", errGoSymbolUnsupported, moduleSection.Size, maxGoSectionSize)
	}

	data, err := moduleSection.Data()
	if err != nil {
		return 0, true, fmt.Errorf("reading .go.module: %w", err)
	}

	ptrSize := 4
	if f.Class == elf.ELFCLASS64 {
		ptrSize = 8
	} else if f.Class != elf.ELFCLASS32 {
		return 0, true, fmt.Errorf("%w: unsupported ELF class for .go.module: %v", errGoSymbolUnsupported, f.Class)
	}
	offset := moduledataTextOffset * ptrSize
	if len(data) < offset+ptrSize {
		return 0, true, fmt.Errorf("%w: .go.module too small for moduledata.text: %d bytes", errGoSymbolUnsupported, len(data))
	}

	if ptrSize == 4 {
		return uint64(f.ByteOrder.Uint32(data[offset:])), true, nil
	}
	return f.ByteOrder.Uint64(data[offset:]), true, nil
}

// pclntabHeaderPtrSize validates the header at the beginning of a .gopclntab
// section and returns its pointer size.
func pclntabHeaderPtrSize(data []byte, order binary.ByteOrder) (int, error) {
	if len(data) < 32 {
		return 0, fmt.Errorf("pclntab header too short: %d bytes", len(data))
	}

	// These magic values identify the Go pclntab formats used across Go
	// releases, including the legacy Go 1.2 and newer formats. See
	// https://github.com/golang/go/blob/go1.26.5/src/internal/abi/symtab.go#L15-L25.
	switch order.Uint32(data[0:4]) {
	case 0xfffffff0, 0xfffffff1, 0xfffffffa, 0xfffffffb:
	default:
		return 0, fmt.Errorf("invalid Go pclntab magic: %#x", order.Uint32(data[0:4]))
	}

	ptrSize := int(data[7])
	if ptrSize != 4 && ptrSize != 8 {
		return 0, fmt.Errorf("unsupported Go pclntab pointer size: %d", ptrSize)
	}

	return ptrSize, nil
}

// pclntabFuncCount reads the number of functions declared in the header of a
// .gopclntab section. In every format supported by debug/gosym, it is the
// first pointer-sized field following the 8-byte header prefix. See
// https://github.com/golang/go/blob/go1.26.5/src/debug/gosym/pclntab.go#L250-L285.
func pclntabFuncCount(data []byte, order binary.ByteOrder) (uint64, error) {
	ptrSize, err := pclntabHeaderPtrSize(data, order)
	if err != nil {
		return 0, err
	}

	if ptrSize == 4 {
		return uint64(order.Uint32(data[8:])), nil
	}
	return order.Uint64(data[8:]), nil
}

// pclntabTextStart reads the textStart field from Go's runtime metadata
// header at the beginning of a .gopclntab section. This field contains the
// link-time virtual address used as the base for Go function offsets. A zero
// result means that this binary's metadata does not provide a usable Go text
// base.
func pclntabTextStart(data []byte, order binary.ByteOrder) (uint64, error) {
	ptrSize, err := pclntabHeaderPtrSize(data, order)
	if err != nil {
		return 0, err
	}

	textStartOffset := 8 + 2*ptrSize
	if len(data) < textStartOffset+ptrSize {
		return 0, errors.New("pclntab header truncated")
	}

	if ptrSize == 4 {
		return uint64(order.Uint32(data[textStartOffset:])), nil
	}
	return order.Uint64(data[textStartOffset:]), nil
}

// goTextStart returns the link-time virtual address used as the base for Go
// pclntab function offsets. It prefers moduledata.text from .go.module, then
// the textStart field in Go's runtime metadata header, then the runtime.text
// ELF symbol, and finally .text.Addr for internally linked binaries whose
// metadata header leaves textStart unset.
func goTextStart(f *safeelf.File, textSection *elf.Section, pclntabData []byte) (uint64, error) {
	if textStart, found, err := goModuleTextStart(f); found {
		if err != nil {
			return 0, err
		}
		if textStart == 0 {
			return 0, fmt.Errorf("%w: .go.module contains an empty moduledata.text", errGoSymbolUnsupported)
		}
		return textStart, nil
	}

	textStart, err := pclntabTextStart(pclntabData, f.ByteOrder)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", errGoSymbolUnsupported, err)
	}
	if textStart != 0 {
		return textStart, nil
	}

	// runtime.text is an ELF symbol, not executable data. Stripping may remove
	// it because the loader does not need symbol names to run the program.
	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		var runtimeText uint64
		var found bool
		err = f.IterateSymbols(typ, func(symbol elf.Symbol) bool {
			if symbol.Name != "runtime.text" {
				return false
			}
			runtimeText = symbol.Value
			found = true
			return true
		})
		if err != nil {
			return 0, fmt.Errorf("reading %s: %w", typ, err)
		}
		if found {
			return runtimeText, nil
		}
	}

	// An undefined dynamic symbol indicates external linking (for example,
	// cgo's libc imports). With no runtime.text symbol and an unset pclntab
	// textStart, .text.Addr is not reliable, so refuse to guess.
	var externallyLinked bool
	err = f.IterateSymbols(elf.SHT_DYNSYM, func(symbol elf.Symbol) bool {
		if symbol.Section != elf.SHN_UNDEF || symbol.Name == "" {
			return false
		}
		externallyLinked = true
		return true
	})
	if err != nil {
		return 0, fmt.Errorf("reading .dynsym: %w", err)
	}
	if externallyLinked {
		return 0, fmt.Errorf("%w: pclntab textStart unavailable for externally linked binary", errGoSymbolUnsupported)
	}

	// Internally linked binaries may leave textStart unset. In that format,
	// pclntab function offsets are relative to the ELF .text section.
	return textSection.Addr, nil
}

// errGoSymbolNotFound reports that the binary parsed cleanly and has no such
// function. It is a stable answer for a file version, so goSymbols caches it.
var errGoSymbolNotFound = errors.New("not found in .gopclntab")

// errGoSymbolUnsupported reports a binary layout this resolver cannot read.
// It depends only on the file version, so goSymbols caches it as a negative
// answer instead of reading .gopclntab again on every attach. Each layout
// check marks its own error; a failed read is not marked, so it stays
// uncached and a later attach reads the file again.
var errGoSymbolUnsupported = errors.New("unsupported Go binary")

// goParseSlots bounds concurrent .gopclntab reads, so their peaks do not
// stack. goSymbols already collapses concurrent reads of one binary for one
// symbol name.
// Only the read and the table build hold a slot; the cheap section checks
// before them do not, so non-Go executables never wait.
var goParseSlots = make(chan struct{}, 2)

// acquireGoParseSlot takes a parse slot. It takes a free slot even when ctx is
// already done, so a caller under the tracer lock passes a done context: it
// parses when a slot is free and fails at once when none is, and never waits
// there. Other callers wait until ctx ends. The error is not cached.
func acquireGoParseSlot(ctx context.Context) error {
	select {
	case goParseSlots <- struct{}{}:
		return nil
	default:
	}
	select {
	case goParseSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for a .gopclntab parse slot: %w", ctx.Err())
	}
}

// resolveGoSymbol is the Go symbol resolver. It looks up a function address in
// a Go binary's .gopclntab section. It works when the standard ELF symbol
// table (.symtab) is removed, as long as .gopclntab and a usable Go text base
// remain. For Go 1.16 and later, debug/gosym can resolve names from pclntab
// alone, so this resolver passes nil when the optional .gosymtab section is
// absent.
//
// This resolver supports ELF Go binaries that retain .gopclntab and a usable
// Go text base, including stripped pure-Go binaries and Go 1.26+ binaries with
// .go.module. When .go.module is absent and textStart is unset, it uses
// runtime.text or .text.Addr only for binaries linked by the Go linker without
// an external system linker; in that layout, Go function offsets are relative
// to .text.
//
// Binaries whose pclntab data remains only in a PT_LOAD segment after section
// headers were removed are not supported. Resolving those binaries requires a
// bounded PT_LOAD scan, which is intentionally not performed here.
//
// | Binary layout                                      | Support |
// |----------------------------------------------------|---------|
// | .gopclntab and usable Go text base                 | Yes     |
// | Go 1.26+ with .go.module                           | Yes     |
// | Stripped pure-Go (-s -w)                           | Yes     |
// | Older external-linked binary without a text base   | No      |
// | pclntab section header or data removed             | No      |
//
// The caller must pass an already-opened *os.File (typically obtained via
// secureopen.OpenInContainer) to avoid re-opening untrusted paths.
//
// Returns a file offset suitable for use with UprobeOptions.Address.
func resolveGoSymbol(file *os.File, symbol string) (uint64, error) {
	return resolveGoSymbolContext(context.Background(), file, symbol)
}

// resolveGoSymbolContext is resolveGoSymbol with a context that bounds the wait
// for a parse slot.
func resolveGoSymbolContext(ctx context.Context, file *os.File, symbol string) (addr uint64, err error) {
	// debug/elf and debug/gosym are not hardened against adversarial inputs
	// and may panic on malformed data. Since we're parsing files from
	// untrusted containers, recover from panics.
	defer func() {
		if r := recover(); r != nil {
			addr = 0
			err = fmt.Errorf("%w: panic parsing Go symbol table: %v", errGoSymbolUnsupported, r)
		}
	}()

	f, err := safeelf.NewFile(file)
	if err != nil {
		return 0, fmt.Errorf("reading ELF: %w", err)
	}
	defer f.Close()

	pclntab := f.Section(".gopclntab")
	if pclntab == nil {
		return 0, fmt.Errorf("no .gopclntab section found (not a Go binary?)")
	}
	if pclntab.Size > maxGoSectionSize {
		return 0, fmt.Errorf("%w: .gopclntab too large (%d bytes, max %d)", errGoSymbolUnsupported, pclntab.Size, maxGoSectionSize)
	}

	// .gosymtab may be absent in stripped binaries. Go 1.16+ embeds all
	// needed information in .gopclntab, so gosym.NewTable works with nil symtab.
	symtab := f.Section(".gosymtab")
	if symtab != nil && symtab.Size > maxGoSectionSize {
		return 0, fmt.Errorf("%w: .gosymtab too large (%d bytes, max %d)", errGoSymbolUnsupported, symtab.Size, maxGoSectionSize)
	}

	textSection := f.Section(".text")
	if textSection == nil {
		return 0, fmt.Errorf("no .text section found")
	}

	// Every section read runs inside the slot, so lookups queued for a slot
	// hold no section data.
	if err := acquireGoParseSlot(ctx); err != nil {
		return 0, err
	}
	defer func() { <-goParseSlots }()
	var symtabData []byte
	if symtab != nil {
		symtabData, err = symtab.Data()
		if err != nil {
			return 0, fmt.Errorf("reading .gosymtab: %w", err)
		}
	}
	pclntabData, err := pclntab.Data()
	if err != nil {
		return 0, fmt.Errorf("reading .gopclntab: %w", err)
	}
	textStart, err := goTextStart(f, textSection, pclntabData)
	if err != nil {
		return 0, fmt.Errorf("reading Go text start: %w", err)
	}

	// debug/gosym allocates one Func and one Sym per function upfront, from
	// a count read in the header. Reject implausible counts: a failing
	// allocation is a fatal runtime error that recover() cannot catch.
	funcCount, err := pclntabFuncCount(pclntabData, f.ByteOrder)
	if err != nil {
		return 0, fmt.Errorf("%w: reading Go function count: %w", errGoSymbolUnsupported, err)
	}
	if funcCount > maxGoFuncCount {
		return 0, fmt.Errorf("%w: too many Go functions: %d (max %d)", errGoSymbolUnsupported, funcCount, maxGoFuncCount)
	}

	lineTable := gosym.NewLineTable(pclntabData, textStart)
	table, err := gosym.NewTable(symtabData, lineTable)
	if err != nil {
		return 0, fmt.Errorf("%w: parsing Go symbol table: %w", errGoSymbolUnsupported, err)
	}

	fn := table.LookupFunc(symbol)
	if fn == nil {
		return 0, fmt.Errorf("symbol %q: %w", symbol, errGoSymbolNotFound)
	}

	// Convert virtual address to file offset using the executable LOAD segment.
	// The uprobe subsystem needs a file offset, not a virtual address.
	fileSize, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat: %w", err)
	}
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		// Only the first Filesz bytes of a segment are backed by the
		// file. The rest (Memsz - Filesz) is zero filled at load time
		// and has no file offset.
		if fn.Entry < prog.Vaddr || fn.Entry-prog.Vaddr >= prog.Filesz {
			continue
		}
		offset := fn.Entry - prog.Vaddr
		if offset > ^uint64(0)-prog.Off {
			return 0, fmt.Errorf("%w: file offset overflow for symbol %q", errGoSymbolUnsupported, symbol)
		}
		offset += prog.Off
		if offset >= uint64(fileSize.Size()) {
			return 0, fmt.Errorf("%w: file offset 0x%x for symbol %q is past the end of the file", errGoSymbolUnsupported, offset, symbol)
		}
		return offset, nil
	}

	return 0, fmt.Errorf("%w: symbol %q (VA 0x%x) not found in any executable LOAD segment", errGoSymbolUnsupported, symbol, fn.Entry)
}
