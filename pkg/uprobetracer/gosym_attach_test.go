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

// Matthias's first finding on the exec path: while both Go parse slots are
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

// Matthias's second finding: the binary is rewritten in place between the
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
	failed := tr.commitOpenedTargets(fakePid, opened)
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
	failed := tr.commitOpenedTargets(fakePid, opened)
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
	failed := tr.commitOpenedTargets(fakePid, opened)
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
