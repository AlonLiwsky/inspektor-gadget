// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// A deadline with silent programs is ErrAttachCanarySilent; the message and
// the deadline cause stay as they were.
func TestAttachCanaryDeadlineErrorSilent(t *testing.T) {
	err := sharedAttachCanaryDeadlineError([]string{"b (task_alloc)", "a (file_open)"}, nil)
	if !errors.Is(err, ErrAttachCanarySilent) {
		t.Fatalf("silent programs not marked: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline cause lost: %v", err)
	}
	want := "attach canary: attached but never ran during a fork+exec+exit: a (file_open), b (task_alloc): context deadline exceeded"
	if err.Error() != want {
		t.Fatalf("message changed:\n got %q\nwant %q", err.Error(), want)
	}
	var silent *AttachCanarySilentError
	if !errors.As(err, &silent) || strings.Join(silent.Programs, ",") != "a,b" {
		t.Fatalf("silent programs not named: %v", err)
	}
}

// A child that exits non-zero at the deadline keeps its exit error too.
func TestAttachCanaryDeadlineErrorSilentKeepsChildError(t *testing.T) {
	child := exec.Command("/bin/false").Run()
	err := sharedAttachCanaryDeadlineError([]string{"a (file_open)"}, child)
	var exit *exec.ExitError
	if !errors.Is(err, ErrAttachCanarySilent) || !errors.As(err, &exit) {
		t.Fatalf("silent mark or child error lost: %v", err)
	}
}

// A deadline before any sample, or any other canary failure, is not a
// silent program: nothing is known about the hooks.
func TestAttachCanaryDeadlineErrorNotSilent(t *testing.T) {
	if err := sharedAttachCanaryDeadlineError(nil, nil); errors.Is(err, ErrAttachCanarySilent) {
		t.Fatalf("no sample marked silent: %v", err)
	}
}

// RunAttachCanary refuses a receipt whose program cannot be read, and that
// refusal is not a silent program.
func TestRunAttachCanaryUnknownProgram(t *testing.T) {
	receipts := map[string]*operators.NativeAttachment{"missing": {ProgramID: ^uint32(0), Target: "file_open"}}
	err := RunAttachCanary(context.Background(), receipts, []string{"/bin/true"})
	if err == nil {
		t.Fatal("an unreadable program was accepted")
	}
	if errors.Is(err, ErrAttachCanarySilent) {
		t.Fatalf("an unreadable program was reported silent: %v", err)
	}
	if !strings.HasPrefix(err.Error(), "attach canary:") {
		t.Fatalf("unexpected error: %v", err)
	}
}
