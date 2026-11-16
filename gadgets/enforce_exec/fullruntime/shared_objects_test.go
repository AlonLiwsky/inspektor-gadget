// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"testing"
)

func TestSharedObjectCoordinatorNeverReceivesUnvalidatedReceipt(t *testing.T) {
	c := &sharedControl{config: sharedNodeWire{NodeCookie: 11, Nonce: 22}}
	f := &sharedCommandFaultTransport{readErr: errors.New("partially filled failed lookup")}
	request := sharedCommandWire{Operation: 1, Object: 0, Attempt: 1, Count: 1}
	receipt, err := c.callCommand(request, f)
	if err == nil || receipt != (sharedReceiptWire{}) || c.pending == nil {
		t.Fatalf("unvalidated read exposed as outcome: %+v %v", receipt, err)
	}
	f.readErr = nil
	f.receipt.Sequence++
	receipt, err = c.callCommand(request, f)
	if err == nil || receipt != (sharedReceiptWire{}) || c.pending == nil {
		t.Fatalf("foreign receipt exposed as outcome: %+v %v", receipt, err)
	}
	f.receipt.Sequence--
	receipt, err = c.callCommand(request, f)
	if err != nil || receipt.Sequence != 1 || c.pending != nil || f.runs != 1 {
		t.Fatalf("validated outcome lost: %+v %v", receipt, err)
	}
}
