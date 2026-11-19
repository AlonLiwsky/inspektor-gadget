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
	"container/list"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
)

// Keep only individual answers, never ELF symbol tables, executable objects or
// descriptors. The bound covers successes and stable negative answers alike.
var ordinarySymbols = newSymbolCache(2048, parseOrdinaryContext)

// goSymbols caches the stripped-Go fallback. One lookup reads all of
// .gopclntab and builds a table of every function in the binary, tens of
// megabytes for a large binary. Uncached, that work repeated on every attach
// to every process of the binary, and a burst of new Go processes pushed the
// agent past its memory limit.
var goSymbols = newSymbolCache(2048, parseGoSymbol)

type symbolVersion struct {
	device, inode     uint64
	size              int64
	modified, changed syscall.Timespec
}

type symbolKey struct {
	version symbolVersion
	name    string
}
type symbolResult struct {
	address, size uint64
	found         bool
	// reason explains a cached negative answer that is not a plain missing
	// symbol, such as a Go binary layout the resolver cannot read.
	reason string
}
type symbolEntry struct {
	key    symbolKey
	result symbolResult
}
type symbolFlight struct {
	done   chan struct{}
	result symbolResult
	err    error
}
type symbolCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[symbolKey]*list.Element
	recent   list.List
	pending  map[symbolKey]*symbolFlight
	parse    func(context.Context, *os.File, string) (symbolResult, error)
}

func newSymbolCache(capacity int, parse func(context.Context, *os.File, string) (symbolResult, error)) *symbolCache {
	return &symbolCache{capacity: capacity, entries: make(map[symbolKey]*list.Element), pending: make(map[symbolKey]*symbolFlight), parse: parse}
}

// parseOrdinaryContext adapts parseOrdinarySymbol to the cache. Ordinary
// lookups stream bounded buffers and do not wait for a parse slot.
func parseOrdinaryContext(_ context.Context, file *os.File, name string) (symbolResult, error) {
	return parseOrdinarySymbol(file, name)
}

// parseGoSymbol adapts resolveGoSymbolContext to the cache. A missing function
// and an unsupported layout (a recovered parse panic included) are cached
// negative answers, and an unsupported layout keeps its reason for the attach
// log. Every other error (a failed read, a canceled wait for a parse slot)
// stays uncached, as for ordinary symbols.
func parseGoSymbol(ctx context.Context, file *os.File, name string) (symbolResult, error) {
	return goSymbolResult(resolveGoSymbolContext(ctx, file, name))
}

func goSymbolResult(address uint64, err error) (symbolResult, error) {
	if errors.Is(err, errGoSymbolNotFound) {
		return symbolResult{}, nil
	}
	if errors.Is(err, errGoSymbolUnsupported) {
		return symbolResult{reason: err.Error()}, nil
	}
	if err != nil {
		return symbolResult{}, err
	}
	// .gopclntab gives no ELF symbol size. A resolved function is never empty,
	// so report a non-zero size for offset().
	return symbolResult{address: address, size: 1, found: true}, nil
}

func fileSymbolVersion(file *os.File) (symbolVersion, error) {
	info, err := file.Stat()
	if err != nil {
		return symbolVersion{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return symbolVersion{}, fmt.Errorf("unsupported file stat for symbol lookup")
	}
	return symbolVersion{device: uint64(st.Dev), inode: st.Ino, size: st.Size, modified: st.Mtim, changed: st.Ctim}, nil
}

func (r symbolResult) offset(name string) (uint64, error) {
	if !r.found {
		if r.reason != "" {
			return 0, fmt.Errorf("symbol %s: %s: %w", name, r.reason, link.ErrNoSymbol)
		}
		return 0, fmt.Errorf("symbol %s: %w", name, link.ErrNoSymbol)
	}
	if r.address == 0 {
		return 0, fmt.Errorf("resolving library call %q: %w", name, link.ErrNotSupported)
	}
	if r.size == 0 {
		return 0, fmt.Errorf("offset 0 is out of range of symbol %s", name)
	}
	return r.address, nil
}

func (c *symbolCache) resolve(file *os.File, name string) (uint64, error) {
	return c.resolveContext(context.Background(), file, name)
}

// resolveContext is resolve with a context that bounds the waits: for another
// caller's parse of the same key, and for a parse slot. A done context never
// waits; it still reads a cached answer and still parses when a slot is free.
func (c *symbolCache) resolveContext(ctx context.Context, file *os.File, name string) (uint64, error) {
	version, err := fileSymbolVersion(file)
	if err != nil {
		return 0, err
	}
	// Symbol names normally come from gadget configuration. Do not let an
	// unbounded name turn the entry limit into an unbounded memory limit.
	if len(name) > 1024 {
		result, err := c.parse(ctx, file, name)
		if err != nil {
			return 0, err
		}
		current, err := fileSymbolVersion(file)
		if err != nil {
			return 0, err
		}
		if current != version {
			return 0, fmt.Errorf("file changed during symbol lookup")
		}
		return result.offset(name)
	}
	key := symbolKey{version: version, name: name}
	c.mu.Lock()
	if entry := c.entries[key]; entry != nil {
		c.recent.MoveToFront(entry)
		result := entry.Value.(symbolEntry).result
		c.mu.Unlock()
		return result.offset(name)
	}
	if flight := c.pending[key]; flight != nil {
		c.mu.Unlock()
		select {
		case <-flight.done:
		default:
			select {
			case <-flight.done:
			case <-ctx.Done():
				return 0, fmt.Errorf("waiting for symbol lookup: %w", ctx.Err())
			}
		}
		if flight.err != nil {
			if isWaitEnded(flight.err) && ctx.Err() == nil {
				// The owner's wait ended, not this caller's: look again
				// with this caller's own context.
				return c.resolveContext(ctx, file, name)
			}
			return 0, flight.err
		}
		current, err := fileSymbolVersion(file)
		if err != nil {
			return 0, err
		}
		if current != version {
			return 0, fmt.Errorf("file changed during symbol lookup")
		}
		return flight.result.offset(name)
	}
	// Copy only on a miss: a short name may otherwise retain a large backing string.
	key.name = strings.Clone(name)
	flight := &symbolFlight{done: make(chan struct{})}
	c.pending[key] = flight
	c.mu.Unlock()
	result, err := c.parse(ctx, file, name)
	if err == nil {
		current, statErr := fileSymbolVersion(file)
		if statErr != nil {
			err = statErr
		} else if current != version {
			err = fmt.Errorf("file changed during symbol lookup")
		}
	}
	c.mu.Lock()
	if err == nil {
		c.entries[key] = c.recent.PushFront(symbolEntry{key: key, result: result})
		if c.recent.Len() > c.capacity {
			oldest := c.recent.Back()
			delete(c.entries, oldest.Value.(symbolEntry).key)
			c.recent.Remove(oldest)
		}
	}
	flight.result, flight.err = result, err
	delete(c.pending, key)
	close(flight.done)
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return result.offset(name)
}

// parseOrdinarySymbol matches cilium/ebpf v0.22's ordinary-symbol lookup,
// including dynamic table precedence, zero-address rejection and executable
// segment translation. It streams the tables instead of materializing them
// (see symbol_stream.go): memory use is a few fixed-size buffers plus one
// offset per occurrence of the wanted name in the string table, and does not
// depend on the binary's symbol count.
func parseOrdinarySymbol(file *os.File, name string) (result symbolResult, err error) {
	// debug/elf may panic on malformed input; cilium's SafeELFFile likewise
	// converts such panics to errors. They must never populate the negative cache.
	defer func() {
		if value := recover(); value != nil {
			result = symbolResult{}
			err = fmt.Errorf("reading ELF symbols: %v", value)
		}
	}()
	f, err := elf.NewFile(file)
	if err != nil {
		return result, err
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return result, fmt.Errorf("the given file is not an executable or a shared object")
	}
	scanner := newSymbolScanner(f, name)
	defer scanner.release()
	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		if err := scanner.scan(typ); err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return symbolResult{}, err
		}
	}
	return scanner.result, nil
}

// lockedLookup is the context for symbol lookups under t.mu. It is already
// done, so such a lookup never waits for a parse slot or for another caller's
// parse. The attach paths resolve before they take t.mu (prepareSymbolOffsets),
// so under t.mu the answer normally comes from the cache.
var lockedLookup = func() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}()

// resolveSymbolOffset resolves the attach symbol through the bounded caches.
// ctx bounds only the stripped-Go fallback: ordinary lookups stream bounded
// buffers and always run to the end.
func (t *Tracer[Event]) resolveSymbolOffset(ctx context.Context, file *os.File) (uint64, error) {
	offset, err := ordinarySymbols.resolve(file, t.attachSymbol)
	if errors.Is(err, link.ErrNoSymbol) && t.progType == ProgUprobe {
		// Keep the bounded ordinary-symbol cache, but retain upstream's
		// fallback for stripped Go binaries. Go uretprobes are excluded
		// because their return handling must account for moving stacks.
		var goErr error
		offset, goErr = goSymbols.resolveContext(ctx, file, t.attachSymbol)
		if goErr != nil {
			if isWaitEnded(goErr) {
				// The wait for a parse slot, or for another caller's parse,
				// ended first. That is not an answer: do not report it as a
				// missing symbol, so the attach counts as failed and the next
				// attach tries again.
				return 0, fmt.Errorf("resolving symbol %q: %w: %w", t.attachSymbol, errSymbolLookupIncomplete, goErr)
			}
			return 0, fmt.Errorf("resolving symbol %q (ELF: %w; gopclntab: %w)", t.attachSymbol, err, goErr)
		}
		err = nil
	}
	return offset, err
}

// errSymbolLookupIncomplete marks a symbol lookup whose wait ended before an
// answer. It is not a negative answer: the attach fails, and nothing records
// the target as handled.
var errSymbolLookupIncomplete = errors.New("symbol lookup did not finish")

// isWaitEnded reports a lookup that ended on its context: the wait for a parse
// slot, or for another caller's parse of the same key.
func isWaitEnded(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// preparedSymbol records the file version that an open-phase symbol lookup
// read. The zero value means the offsets did not come from that lookup.
type preparedSymbol struct {
	used    bool
	version symbolVersion
}

// forCommit runs under t.mu. It returns the offsets to bind. When the file
// changed after the open phase, it drops the open-phase answer, and the commit
// resolves the symbol again.
func (p preparedSymbol) forCommit(file *os.File, offsets []uint64) []uint64 {
	if !p.used {
		return offsets
	}
	if version, err := fileSymbolVersion(file); err != nil || version != p.version {
		return nil
	}
	return offsets
}

// prepareSymbolOffsets runs in the open phase, without t.mu. When there are
// no custom offsets, it resolves the attach symbol there, so the commit under
// t.mu binds a known offset and does not parse. It returns the file version
// the lookup read, for the commit to check. On any error it returns no
// offsets, and the commit resolves again under t.mu without waiting
// (lockedLookup): a stable negative answer comes from the cache, a free slot
// still parses, and a busy one fails the attach so the next attach retries.
func (t *Tracer[Event]) prepareSymbolOffsets(ctx context.Context, file *os.File, offsets []uint64) ([]uint64, preparedSymbol) {
	if len(offsets) > 0 || t.progType == ProgUSDT {
		return offsets, preparedSymbol{}
	}
	version, err := fileSymbolVersion(file)
	if err != nil {
		return nil, preparedSymbol{}
	}
	offset, err := t.resolveSymbolOffset(ctx, file)
	if err != nil {
		return nil, preparedSymbol{}
	}
	return []uint64{offset}, preparedSymbol{used: true, version: version}
}

// bindOrdinarySites keeps custom offsets intact and resolves ordinary names
// before binding, so cilium receives a nonzero explicit address and never
// materializes its full symbol map on this path. USDT bypasses this helper.
// It runs under t.mu, so it resolves with lockedLookup.
func (t *Tracer[Event]) bindOrdinarySites(file *os.File, offsets []uint64, bind func(*uint64) (link.Link, error)) ([]link.Link, error) {
	if len(offsets) == 0 {
		offset, err := t.resolveSymbolOffset(lockedLookup, file)
		if err != nil {
			return nil, err
		}
		offsets = []uint64{offset}
	}
	return t.bindSites(offsets, bind)
}
