// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"
)

func TestSharedPublicationArmHeader(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "arm")
	cmd := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "testdata/shared_publication_arm.c", "-o", binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("arm: %v %s", err, out)
	}
}

func TestSharedArmNativeABI(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "arm-abi")
	cmd := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "testdata/shared_arm_abi.c", "-o", binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile native arm ABI: %v %s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("native arm ABI: %v %s", err, out)
	}
}

func TestSharedArmNativeTransaction(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full/owner")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "arm-tx")
	cmd := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root,
		"testdata/shared_arm_transaction.c", filepath.Join(root, "shared-arm-transaction.c"), "-o", binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile native arm transaction: %v %s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("native arm transaction: %v %s", err, out)
	}
}

func TestSharedArmNativeTrigger(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full/owner")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "arm-trigger")
	cmd := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root,
		"testdata/shared_arm_trigger.c", filepath.Join(root, "shared-arm-trigger.c"), "-o", binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile native arm trigger: %v %s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("native arm trigger: %v %s", err, out)
	}
}

func TestSharedArmNativeJournal(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full/owner")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "arm-journal")
	cmd := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root,
		"testdata/shared_arm_journal.c", filepath.Join(root, "shared-arm-journal.c"),
		filepath.Join(root, "shared-arm-transaction.c"), "-o", binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile native arm journal: %v %s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("native arm journal: %v %s", err, out)
	}
}

func TestSharedArmReceiptIsNotSyscallProof(t *testing.T) {
	if unsafe.Sizeof(sharedArmRequest{}) != 176 || unsafe.Sizeof(sharedArmReceipt{}) != 48 {
		t.Fatalf("arm wire drifted: request %d receipt %d", unsafe.Sizeof(sharedArmRequest{}), unsafe.Sizeof(sharedArmReceipt{}))
	}
	if sharedLastOperation != 16 || sharedNodeInspect != sharedLastOperation {
		t.Fatal("syscall operation domain gained a commit opcode")
	}
	req := sharedArmRequest{NodeCookie: 4, Sequence: 8, Serial: 3, ExpectedGeneration: 0, Operation: sharedArmCommit}
	receipt := sharedArmReceipt{NodeCookie: 4, Sequence: 8, Generation: 1, Serial: 3, Operation: sharedArmCommit}
	if !sharedArmProvesCommit(req, receipt) {
		t.Fatal("barrier commit receipt rejected")
	}
	syscall := sharedCommandWire{Operation: sharedArmCommit, Sequence: 8, Generation: 1}
	if sharedArmProvesCommit(req, sharedArmReceipt{NodeCookie: syscall.NodeCookie, Sequence: syscall.Sequence, Generation: syscall.Generation, Operation: syscall.Operation}) {
		t.Fatal("syscall-shaped receipt accepted as commit")
	}
	if sharedArmProvesCommit(req, sharedArmReceipt{NodeCookie: 4, Sequence: 8, Generation: 0, Serial: 3, Operation: sharedArmCommit}) {
		t.Fatal("generation zero accepted as commit")
	}
	req.Operation = sharedArmBind
	if sharedArmProvesCommit(req, sharedArmReceipt{NodeCookie: 4, Sequence: 8, Generation: 1, Serial: 3, Operation: sharedArmBind}) {
		t.Fatal("index bind accepted as commit")
	}
	withdraw := sharedArmRequest{NodeCookie: 4, Sequence: 9, ExpectedGeneration: 1, Operation: sharedArmWithdraw}
	if !sharedArmProvesWithdraw(1, withdraw, sharedArmReceipt{NodeCookie: 4, Sequence: 9, Generation: 1, Operation: sharedArmWithdraw}) {
		t.Fatal("withdrawal receipt rejected")
	}
	if sharedArmProvesWithdraw(1, withdraw, sharedArmReceipt{NodeCookie: 4, Sequence: 9, Generation: 2, Operation: sharedArmWithdraw}) {
		t.Fatal("withdrawal minted a generation")
	}
}
