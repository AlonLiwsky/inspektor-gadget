// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

// These are fexit arm operations, not se_command opcodes. Operation 16 remains
// the last syscall operation. A sharedCommandWire receipt cannot prove commit
// or withdrawal.
const (
	sharedArmCommit   uint32 = 1
	sharedArmWithdraw uint32 = 2
	sharedArmBind     uint32 = 3
)

type sharedArmRequest struct {
	NodeCookie, Nonce, Sequence                      uint64
	Scope, Serial, ExpectedGeneration, Qualification uint64
	Operation, Binding, Record, Count, Reserved      uint32
	BankIndex                                        [8]uint32
	Epochs                                           [8]uint64
}
type sharedArmReceipt struct {
	NodeCookie, Sequence, Generation, Serial uint64
	Operation, Status, Value, Reserved       uint32
}

func sharedArmProvesCommit(req sharedArmRequest, receipt sharedArmReceipt) bool {
	return req.Operation == sharedArmCommit && req.Sequence != 0 &&
		req.ExpectedGeneration < ^uint64(0)-1 &&
		receipt.NodeCookie == req.NodeCookie && receipt.Sequence == req.Sequence &&
		receipt.Operation == sharedArmCommit && receipt.Status == 0 &&
		receipt.Reserved == 0 && receipt.Generation == req.ExpectedGeneration+1 &&
		receipt.Serial == req.Serial && receipt.Serial != 0
}

func sharedArmProvesWithdraw(generation uint64, req sharedArmRequest, receipt sharedArmReceipt) bool {
	return req.Operation == sharedArmWithdraw && req.Sequence != 0 &&
		req.ExpectedGeneration == generation &&
		receipt.NodeCookie == req.NodeCookie && receipt.Sequence == req.Sequence &&
		receipt.Operation == sharedArmWithdraw && receipt.Status == 0 &&
		receipt.Reserved == 0 && receipt.Generation == generation &&
		receipt.Serial == 0
}
