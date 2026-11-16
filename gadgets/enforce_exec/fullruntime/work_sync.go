// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

// Cells of the opaque_real_work_sync witness of the synchronous WORK return
// (G019 option C, ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE in
// bpf/opaque_real_owner_child_candidate.bpf.c, REAL_OWNER_WORK_SYNC_*).
//
// A settling program (the task_alloc target for the birth WORK, the exec
// terminals for the evaluation WORK, the exit or task_free fallback for a
// WORK suspended at death) hands the WORK it just moved to DONE to the
// synchronous return, counted settled per site. Each settled WORK ends in
// exactly one outcome:
//   - returned: its credit is back;
//   - claim-lost: the reaper held the visit claim and finishes the WORK
//     (benign);
//   - stale: the charge no longer named a just-settled WORK, or a stage
//     answered STALE/ALREADY_RETURNED (benign; a recovery wakeup is
//     emitted);
//   - pending, fault: a stage refused; the WORK waits for the reaper, which
//     gets a recovery wakeup. Degraded: the capacity claim does not hold for
//     that WORK.
//
// stuck is counted by the reap command when the same visit claim stays held
// for a second (a lost release): Degraded. The map's presence is also the
// "has the synchronous return" signal of ConcurrentBirthCapacity.
const (
	workSyncSettledBirth = iota
	workSyncSettledExec
	workSyncSettledDeath
	workSyncReturned
	workSyncClaimLost
	workSyncStale
	workSyncPending
	workSyncFault
	workSyncStuck
	workSyncCounters
)

// WorkSyncWitnessMap is the synchronous WORK return witness map.
const WorkSyncWitnessMap = "opaque_real_work_sync"
