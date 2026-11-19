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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
)

// buildStrippedGoBinary builds a stripped Go binary from source and returns
// its path.
func buildStrippedGoBinary(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	main := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(main, []byte(source), 0o600))
	binary := filepath.Join(dir, "target")
	output, err := exec.Command("go", "build", "-buildvcs=false", "-ldflags=-s -w", "-o", binary, main).CombinedOutput()
	require.NoError(t, err, "%s", output)
	return binary
}

const goTargetSource = `package main
//go:noinline
func target() { println("target") }
func main() { target() }
`

// goTargetMovedSource puts more code before main.target, so the symbol has a
// different offset than in goTargetSource.
const goTargetMovedSource = `package main
//go:noinline
func pad(n int) int {
	s := 0
	for i := 0; i < n; i++ {
		s += i * i
		s ^= i << 3
		s -= i >> 1
		println("pad", i, s)
	}
	return s
}
//go:noinline
func target() { println("target") }
func main() { target(); println(pad(3)) }
`

func goSymbolOffset(t *testing.T, binary string) uint64 {
	t.Helper()
	f, err := os.Open(binary)
	require.NoError(t, err)
	defer f.Close()
	offset, err := resolveGoSymbol(f, "main.target")
	require.NoError(t, err)
	return offset
}

// newGoAttachTracer is a test tracer whose attach goes through the real
// bindOrdinarySites lookup. It records the offsets each bind used.
func newGoAttachTracer(t *testing.T, path string) (*Tracer[any], *testState, *[]uint64) {
	t.Helper()
	tr, st := newTestTracer(t)
	tr.progType = ProgUprobe
	tr.attachSymbol = "main.target"
	tr.openInContainer = func(context.Context, uint32, string) (*os.File, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		st.openFiles = append(st.openFiles, f)
		return f, nil
	}
	var bound []uint64
	tr.attachToFile = func(file *os.File, offsets []uint64) ([]link.Link, error) {
		links, err := tr.bindOrdinarySites(file, offsets, func(offset *uint64) (link.Link, error) {
			bound = append(bound, *offset)
			return nil, nil
		})
		if err != nil {
			return nil, err
		}
		st.attachCount++
		return links, nil
	}
	return tr, st, &bound
}

// On the exec path, while both Go parse slots are
// busy, the open-phase lookup times out. The exec must not be recorded as
// handled, so the next exec of the same binary attaches once a slot is free.
func TestExecRetriesAfterGoParseSlotTimeout(t *testing.T) {
	procRoot := withFakeProcRoot(t)
	withShortAttachIOTimeout(t, 50*time.Millisecond)
	binary := buildStrippedGoBinary(t, goTargetSource)
	want := goSymbolOffset(t, binary)
	tr, st, bound := newGoAttachTracer(t, binary)
	tr.containerPid2Inodes[fakePid] = nil
	st.currentInode = 701

	release := takeAllGoParseSlots(t)
	exec1 := fakePid + 1
	fakeExeProc(t, procRoot, exec1, "/app/server")
	require.NoError(t, tr.ReattachContainerExecPid(fakePid, exec1))
	require.Empty(t, *bound, "nothing can bind while every parse slot is busy")
	require.Equal(t, 0, st.attachCount)

	release()
	exec2 := fakePid + 2
	fakeExeProc(t, procRoot, exec2, "/app/server")
	require.NoError(t, tr.ReattachContainerExecPid(fakePid, exec2))
	require.Equal(t, []uint64{want}, *bound, "the next exec must retry and bind")
	require.Equal(t, 1, st.attachCount)

	// Now the exec is recorded: a third exec is a cache hit.
	exec3 := fakePid + 3
	fakeExeProc(t, procRoot, exec3, "/app/server")
	require.NoError(t, tr.ReattachContainerExecPid(fakePid, exec3))
	require.Equal(t, 1, st.attachCount)
}

// The binary is rewritten in place between the
// open phase and the commit, and the symbol moves. The commit must bind the
// new offset, not the one the open phase found.
func TestCommitRebindsAfterInPlaceRewrite(t *testing.T) {
	original := buildStrippedGoBinary(t, goTargetSource)
	moved := buildStrippedGoBinary(t, goTargetMovedSource)
	oldOffset := goSymbolOffset(t, original)
	newOffset := goSymbolOffset(t, moved)
	require.NotEqual(t, oldOffset, newOffset, "the test needs the symbol to move")

	path := filepath.Join(t.TempDir(), "server")
	content, err := os.ReadFile(original)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, content, 0o755))

	tr, st, bound := newGoAttachTracer(t, path)
	st.currentInode = 702
	tr.containerPid2Inodes[fakePid] = nil

	opened, openFailed := tr.openTargets(context.Background(), fakePid, []string{"/app/server"})
	require.False(t, openFailed)
	require.Len(t, opened, 1)
	require.Equal(t, []uint64{oldOffset}, opened[0].offsets)

	// Rewrite the same inode in place.
	content, err = os.ReadFile(moved)
	require.NoError(t, err)
	rewrite, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	require.NoError(t, err)
	_, err = rewrite.Write(content)
	require.NoError(t, err)
	require.NoError(t, rewrite.Close())

	tr.mu.Lock()
	failed, _ := tr.commitOpenedTargets(fakePid, opened)
	tr.mu.Unlock()
	require.False(t, failed)
	require.Equal(t, []uint64{newOffset}, *bound)
}

// Without a rewrite, the commit binds the open-phase offset and does not parse
// under t.mu, even with every parse slot taken.
func TestCommitBindsPreparedOffsetWithoutParse(t *testing.T) {
	binary := buildStrippedGoBinary(t, goTargetSource)
	want := goSymbolOffset(t, binary)
	tr, st, bound := newGoAttachTracer(t, binary)
	st.currentInode = 703
	tr.containerPid2Inodes[fakePid] = nil

	opened, _ := tr.openTargets(context.Background(), fakePid, []string{"/app/server"})
	require.Len(t, opened, 1)
	takeAllGoParseSlots(t)
	tr.mu.Lock()
	failed, _ := tr.commitOpenedTargets(fakePid, opened)
	tr.mu.Unlock()
	require.False(t, failed)
	require.Equal(t, []uint64{want}, *bound)
}

// The open-phase lookup times out while every parse slot is busy. The commit
// looks up again under t.mu without waiting, and binds once a slot is free.
// This keeps the create-time attach, which has no later retry.
func TestCommitRetriesLookupAfterOpenPhaseTimeout(t *testing.T) {
	binary := buildStrippedGoBinary(t, goTargetSource)
	want := goSymbolOffset(t, binary)
	tr, st, bound := newGoAttachTracer(t, binary)
	st.currentInode = 704
	tr.containerPid2Inodes[fakePid] = nil

	release := takeAllGoParseSlots(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	opened, _ := tr.openTargets(ctx, fakePid, []string{"/app/server"})
	require.Len(t, opened, 1)
	require.Nil(t, opened[0].offsets)

	release()
	tr.mu.Lock()
	failed, _ := tr.commitOpenedTargets(fakePid, opened)
	tr.mu.Unlock()
	require.False(t, failed)
	require.Equal(t, []uint64{want}, *bound)
}

// A caller waiting for another caller's parse gets an answer within its own
// context, not the owner's context error.
func TestFlightWaiterRetriesWithOwnContext(t *testing.T) {
	file := buildStrippedGoTarget(t)
	want, err := resolveGoSymbol(file, "main.target")
	require.NoError(t, err)
	c := newSymbolCache(8, parseGoSymbol)

	freeOne := takeAllGoParseSlots(t)
	ownerCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ownerDone := make(chan error, 1)
	go func() {
		_, err := c.resolveContext(ownerCtx, file, "main.target")
		ownerDone <- err
	}()
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.pending) == 1
	}, time.Second, time.Millisecond)

	waiterCtx, cancelWaiter := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelWaiter()
	type result struct {
		offset uint64
		err    error
	}
	waiterDone := make(chan result, 1)
	go func() {
		offset, err := c.resolveContext(waiterCtx, file, "main.target")
		waiterDone <- result{offset, err}
	}()
	require.ErrorIs(t, <-ownerDone, context.DeadlineExceeded)
	freeOne()
	r := <-waiterDone
	require.NoError(t, r.err)
	require.Equal(t, want, r.offset)
}

// A layout error found after the parse slot depends only on the file
// version, so it is cached: .gopclntab is read once, not on every attach.
func TestGoLayoutErrorAfterSlotIsCached(t *testing.T) {
	src := buildStrippedGoBinary(t, goTargetSource)
	path := filepath.Join(t.TempDir(), "server")
	content, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, content, 0o755))

	ef, err := elf.Open(path)
	require.NoError(t, err)
	module := ef.Section(".go.module")
	if module == nil {
		ef.Close()
		t.Skip("toolchain does not emit .go.module")
	}
	offset := int64(module.Offset) + moduledataTextOffset*8
	ef.Close()
	// Zero moduledata.text: the text start can no longer be read.
	w, err := os.OpenFile(path, os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = w.WriteAt(make([]byte, 8), offset)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()

	var parses atomic.Int32
	c := newSymbolCache(8, func(ctx context.Context, f *os.File, name string) (symbolResult, error) {
		parses.Add(1)
		return parseGoSymbol(ctx, f, name)
	})
	for range 3 {
		_, err = c.resolve(file, "main.target")
		require.ErrorIs(t, err, link.ErrNoSymbol)
		require.ErrorContains(t, err, "reading Go text start")
	}
	require.Equal(t, int32(1), parses.Load())
}

// moveSectionPastEOF points a section's file offset past the end of the file,
// so reading the section fails while the ELF headers still parse.
func moveSectionPastEOF(t *testing.T, path, section string) {
	t.Helper()
	ef, err := elf.Open(path)
	require.NoError(t, err)
	index := -1
	for i, s := range ef.Sections {
		if s.Name == section {
			index = i
		}
	}
	class, order := ef.Class, ef.ByteOrder
	ef.Close()
	if index < 0 {
		t.Skipf("toolchain does not emit %s", section)
	}
	require.Equal(t, elf.ELFCLASS64, class)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	shoff := order.Uint64(content[0x28:])
	shentsize := uint64(order.Uint16(content[0x3a:]))
	// Elf64_Shdr.sh_offset is at byte 0x18 of the section header.
	at := shoff + uint64(index)*shentsize + 0x18
	order.PutUint64(content[at:], uint64(len(content))+0x1000)
	require.NoError(t, os.WriteFile(path, content, 0o755))
}

// A failed read is not a layout answer. It
// must stay uncached, so the next lookup reads the file again.
func TestGoSectionReadErrorIsNotCached(t *testing.T) {
	src := buildStrippedGoBinary(t, goTargetSource)
	path := filepath.Join(t.TempDir(), "server")
	content, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, content, 0o755))
	moveSectionPastEOF(t, path, ".go.module")

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()

	_, err = resolveGoSymbol(file, "main.target")
	require.ErrorContains(t, err, "reading .go.module")
	require.NotErrorIs(t, err, errGoSymbolUnsupported)

	var parses atomic.Int32
	c := newSymbolCache(8, func(ctx context.Context, f *os.File, name string) (symbolResult, error) {
		parses.Add(1)
		return parseGoSymbol(ctx, f, name)
	})
	for range 3 {
		_, err = c.resolve(file, "main.target")
		require.ErrorContains(t, err, "reading .go.module")
		require.NotErrorIs(t, err, link.ErrNoSymbol)
	}
	require.Equal(t, int32(3), parses.Load())
}

func withShortRetryDelay(t *testing.T, d time.Duration) {
	t.Helper()
	orig := incompleteLookupRetryDelay
	incompleteLookupRetryDelay = d
	t.Cleanup(func() { incompleteLookupRetryDelay = orig })
}

// countIncompleteBinds wraps the tracer's attach and calls onIncomplete on
// every commit whose symbol lookup did not finish.
func countIncompleteBinds(tr *Tracer[any], onIncomplete func(n int)) {
	attach := tr.attachToFile
	n := 0
	tr.attachToFile = func(file *os.File, offsets []uint64) ([]link.Link, error) {
		links, err := attach(file, offsets)
		if errors.Is(err, errSymbolLookupIncomplete) {
			n++
			onIncomplete(n)
		}
		return links, err
	}
}

// An already-running service gets one
// create-time attach and no exec event. When both parse slots stay busy
// through that attach, a bounded retry binds once a slot is free.
func TestCreateTimeAttachRetriesIncompleteLookup(t *testing.T) {
	withShortAttachIOTimeout(t, 50*time.Millisecond)
	withShortRetryDelay(t, 10*time.Millisecond)
	binary := buildStrippedGoBinary(t, goTargetSource)
	want := goSymbolOffset(t, binary)
	tr, st, bound := newGoAttachTracer(t, binary)
	st.currentInode = 704
	tr.containerPid2Inodes[fakePid] = nil

	release := takeAllGoParseSlots(t)
	// Free a slot only after the first attempt has failed.
	countIncompleteBinds(tr, func(n int) {
		if n == 1 {
			release()
		}
	})
	tr.runAttachJob(attachJob{pid: fakePid, attachFilePath: tr.attachFilePath, attachSymbol: tr.attachSymbol, progName: tr.progName}, nil)

	require.Equal(t, []uint64{want}, *bound)
	require.Equal(t, 1, st.attachCount)
	tr.mu.Lock()
	require.Len(t, tr.containerPid2Inodes[fakePid], 1)
	tr.mu.Unlock()
}

// The retry is bounded: with every slot busy for the whole time, the job
// stops after incompleteLookupRetries more attempts.
func TestCreateTimeAttachRetryIsBounded(t *testing.T) {
	withShortAttachIOTimeout(t, 20*time.Millisecond)
	withShortRetryDelay(t, time.Millisecond)
	binary := buildStrippedGoBinary(t, goTargetSource)
	tr, st, bound := newGoAttachTracer(t, binary)
	st.currentInode = 705
	tr.containerPid2Inodes[fakePid] = nil

	takeAllGoParseSlots(t)
	attempts := 0
	countIncompleteBinds(tr, func(n int) { attempts = n })
	tr.runAttachJob(attachJob{pid: fakePid, attachFilePath: tr.attachFilePath, attachSymbol: tr.attachSymbol, progName: tr.progName}, nil)

	require.Equal(t, 1+incompleteLookupRetries, attempts)
	require.Empty(t, *bound)
}

// Close ends a retry wait at once, so it never waits out the delay.
func TestCloseEndsCreateTimeRetryWait(t *testing.T) {
	withShortAttachIOTimeout(t, 20*time.Millisecond)
	withShortRetryDelay(t, time.Hour)
	binary := buildStrippedGoBinary(t, goTargetSource)
	tr, st, _ := newGoAttachTracer(t, binary)
	st.currentInode = 706
	tr.containerPid2Inodes[fakePid] = nil

	takeAllGoParseSlots(t)
	failed := make(chan struct{})
	countIncompleteBinds(tr, func(n int) {
		if n == 1 {
			close(failed)
		}
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.runAttachJob(attachJob{pid: fakePid, attachFilePath: tr.attachFilePath, attachSymbol: tr.attachSymbol, progName: tr.progName}, nil)
	}()
	<-failed
	tr.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end the retry wait")
	}
}

// A settled container: the startup scan skips the entrypoint, so the
// create-time attach is its only attempt. A lookup that cannot finish there is
// retried, and the entrypoint binds once a slot is free.
func TestSettledEntrypointRetriesIncompleteLookup(t *testing.T) {
	proc := withFakeProcRoot(t)
	withShortAttachIOTimeout(t, 50*time.Millisecond)
	withShortRetryDelay(t, 10*time.Millisecond)
	fakeStartupProcess(t, proc, 100, "mnt:[1]", "/app/server")
	binary := buildStrippedGoBinary(t, goTargetSource)
	want := goSymbolOffset(t, binary)
	tr, st, bound := newGoAttachTracer(t, binary)
	tr.attachFilePath = "/app/server"
	st.currentInode = 707

	release := takeAllGoParseSlots(t)
	countIncompleteBinds(tr, func(n int) {
		if n == 1 {
			release()
		}
	})
	require.NoError(t, tr.AttachContainer(settledTestContainer(100)))

	require.Equal(t, []uint64{want}, *bound)
	tr.mu.Lock()
	require.Len(t, tr.containerPid2Inodes[100], 1)
	tr.mu.Unlock()
}

// Close also ends a retry that waits for an attachSem slot another tracer
// holds.
func TestCloseEndsRetryWaitForAttachSlot(t *testing.T) {
	withShortAttachIOTimeout(t, 20*time.Millisecond)
	withShortRetryDelay(t, time.Millisecond)
	binary := buildStrippedGoBinary(t, goTargetSource)
	tr, st, _ := newGoAttachTracer(t, binary)
	st.currentInode = 708
	tr.containerPid2Inodes[fakePid] = nil

	takeAllGoParseSlots(t)
	sem := make(chan struct{}, 1)
	failed := make(chan struct{})
	countIncompleteBinds(tr, func(n int) {
		if n == 1 {
			close(failed)
		}
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.runAttachJob(attachJob{pid: fakePid, attachFilePath: tr.attachFilePath, attachSymbol: tr.attachSymbol, progName: tr.progName}, sem)
	}()
	<-failed
	// Another tracer takes the only slot once the first attempt gives it back.
	sem <- struct{}{}
	tr.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end the wait for an attach slot")
	}
}
