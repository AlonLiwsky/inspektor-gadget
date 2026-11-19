// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// installNativePoolReaperChain is called after final source admission and
// collection load, but before any handle is published or hook attached. The
// exact loaded chunk FD is installed in slot zero; no external TC attachment
// or userspace-written stage is part of this candidate transport. The host
// still refuses the pool product image until typed hooks and native lifecycle
// qualification are complete.
func (i *ebpfInstance) installNativePoolReaperChain(gc operators.GadgetContext) error {
	if i.collectionSpec == nil {
		return fmt.Errorf("missing native collection spec")
	}
	const entryName = "se_pool_reaper_entry"
	const chunkName = "se_pool_reaper_chunk"
	const stageName = "se_pool_reap_stage"
	const chainName = "se_pool_reap_chain"
	var candidate bool
	for name := range i.collectionSpec.Programs {
		if strings.HasPrefix(name, "se_pool_reaper_") {
			if name != entryName && name != chunkName {
				return fmt.Errorf("unreviewed pool reaper program %s", name)
			}
			candidate = true
		}
	}
	for name := range i.collectionSpec.Maps {
		if strings.HasPrefix(name, "se_pool_reap_") && name != "se_pool_reap_request" &&
			name != "se_pool_reap_control" && name != "se_pool_reap_receipt" {
			if name != stageName && name != chainName {
				return fmt.Errorf("unreviewed pool reaper map %s", name)
			}
			candidate = true
		}
	}
	if !candidate {
		return nil
	}
	entry, chunk := i.collectionSpec.Programs[entryName], i.collectionSpec.Programs[chunkName]
	stageSpec, chainSpec := i.collectionSpec.Maps[stageName], i.collectionSpec.Maps[chainName]
	if entry == nil || chunk == nil || stageSpec == nil || chainSpec == nil ||
		stageSpec.Type != ebpf.Array || stageSpec.KeySize != 4 ||
		stageSpec.ValueSize != 144 || stageSpec.MaxEntries != 1 ||
		stageSpec.Flags != unix.BPF_F_RDONLY || stageSpec.InnerMap != nil ||
		chainSpec.Type != ebpf.ProgramArray || chainSpec.KeySize != 4 ||
		chainSpec.ValueSize != 4 || chainSpec.MaxEntries != 1 ||
		chainSpec.Flags != 0 || chainSpec.InnerMap != nil ||
		len(chainSpec.Contents) != 0 {
		return fmt.Errorf("incomplete or incompatible pool reaper transport")
	}
	for _, spec := range []*ebpf.ProgramSpec{entry, chunk} {
		selected, err := i.nativeRecoveryTestRunProgram(gc, spec)
		if err != nil {
			return err
		}
		if !selected || !i.recoveryTestRunSelected ||
			!i.recoveryTestRunAdmitted || i.recoveryTestRunFault {
			return fmt.Errorf("pool reaper TEST_RUN lacks final admission")
		}
	}
	if i.collection == nil {
		return fmt.Errorf("missing loaded pool reaper collection")
	}
	stage, chain := i.collection.Maps[stageName], i.collection.Maps[chainName]
	loadedEntry, loadedChunk := i.collection.Programs[entryName], i.collection.Programs[chunkName]
	if stage == nil || chain == nil || loadedEntry == nil || loadedChunk == nil ||
		stage.FD() < 0 || chain.FD() < 0 ||
		loadedEntry.FD() < 0 || loadedChunk.FD() < 0 ||
		stage.Type() != ebpf.Array || stage.KeySize() != 4 ||
		stage.ValueSize() != 144 || stage.MaxEntries() != 1 ||
		stage.Flags() != unix.BPF_F_RDONLY ||
		chain.Type() != ebpf.ProgramArray || chain.KeySize() != 4 ||
		chain.ValueSize() != 4 || chain.MaxEntries() != 1 ||
		chain.Flags() != 0 ||
		loadedEntry.Type() != ebpf.SchedCLS ||
		loadedChunk.Type() != ebpf.SchedCLS {
		return fmt.Errorf("loaded pool reaper transport differs from admitted source")
	}
	info, err := loadedChunk.Info()
	if err != nil {
		return fmt.Errorf("pool reaper chunk identity: %w", err)
	}
	chunkID, ok := info.ID()
	if !ok || chunkID == 0 {
		return fmt.Errorf("pool reaper chunk identity unavailable")
	}
	var previous *ebpf.Program
	err = chain.Lookup(uint32(0), &previous)
	if previous != nil {
		previous.Close()
	}
	if err == nil || !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("pool reaper chain is not initially empty: %w", err)
	}
	if err := chain.Update(uint32(0), loadedChunk, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("installing pool reaper chunk: %w", err)
	}
	var installed *ebpf.Program
	if err := chain.Lookup(uint32(0), &installed); err != nil {
		return fmt.Errorf("reading installed pool reaper chunk: %w", err)
	}
	if installed == nil {
		return fmt.Errorf("installed pool reaper chunk unavailable")
	}
	defer installed.Close()
	installedInfo, err := installed.Info()
	if err != nil {
		return fmt.Errorf("installed pool reaper chunk identity: %w", err)
	}
	installedID, ok := installedInfo.ID()
	if !ok || installedID != chunkID || installed.Type() != ebpf.SchedCLS {
		return fmt.Errorf("installed pool reaper chunk identity mismatch")
	}
	return nil
}
