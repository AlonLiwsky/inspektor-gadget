package fullruntime

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSharedAttachCanaryChildDeadline(t *testing.T) {
	silent := []string{"example_2 (task_alloc)", "example_1 (bprm_committed_creds)"}
	child := func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestSharedAttachCanaryChildHelper$")
	}
	for _, tc := range []struct {
		name       string
		scenario   string
		stats      bool
		wantSilent bool
	}{
		{"success", "success", true, false},
		{"ordinary-exit", "exit", true, false},
		{"independent-sigkill", "kill", true, false},
		{"our-deadline-with-sample", "local", true, true},
		{"our-deadline-no-sample", "local", false, false},
		{"our-deadline-before-start-with-sample", "expired", true, true},
		{"our-deadline-before-start-no-sample", "expired", false, false},
		{"caller-already-cancelled", "cancelled", true, false},
		{"caller-deadline", "caller", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent, cancelParent := context.WithCancel(context.Background())
			defer cancelParent()
			if tc.scenario == "caller" {
				var done context.CancelFunc
				parent, done = context.WithTimeout(parent, 2*time.Second)
				defer done()
			}
			d := 5 * time.Second
			switch tc.scenario {
			case "local":
				d = 2 * time.Second
			case "expired":
				d = -time.Second
			}
			budget, cancelBudget := context.WithTimeout(parent, d)
			defer cancelBudget()
			cmd := child(budget)
			cmd.Env = []string{"IG_SHARED_CANARY_DIAGNOSTIC=" + tc.scenario, "GORACE=atexit_sleep_ms=0"}
			if tc.scenario == "cancelled" {
				cancelParent()
			}

			var s []string
			if tc.stats {
				s = append([]string(nil), silent...)
			}
			err := runSharedAttachCanaryChild(parent, budget, cmd, s)
			if tc.scenario == "success" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("unhealthy subprocess was accepted")
			}
			hasSilent := strings.Contains(err.Error(), "example_1 (bprm_committed_creds), example_2 (task_alloc)")
			if hasSilent != tc.wantSilent {
				t.Errorf("has an ordered observed silent list = %v, want %v: %v", hasSilent, tc.wantSilent, err)
			}
			if tc.wantSilent && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("own deadline cause lost: %v", err)
			}
			if tc.scenario == "expired" {
				if cmd.Process != nil || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("pre-start deadline lost or child unexpectedly started: %v, %v", err, cmd.Process)
				}
				if !tc.wantSilent && strings.Contains(err.Error(), "example_") {
					t.Fatalf("false silence attribution: %v", err)
				}
				return
			}
			if tc.scenario == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Errorf("parent cancel lost: %v", err)
				}
				return
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("raw exit cause lost: %v", err)
			}
			ws, ok := exitErr.Sys().(syscall.WaitStatus)
			if !ok {
				t.Fatal("missing child WaitStatus")
			}
			if tc.scenario == "exit" {
				if ws.ExitStatus() != 7 {
					t.Fatalf("exit status: %v", ws)
				}
			} else if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("signal: %v", ws)
			}
			if !tc.wantSilent && strings.Contains(err.Error(), "example_") {
				t.Fatalf("false silence attribution: %v", err)
			}
		})
	}
}

func TestSharedAttachCanaryChildHelper(t *testing.T) {
	switch os.Getenv("IG_SHARED_CANARY_DIAGNOSTIC") {
	case "success":
		os.Exit(0)
	case "exit":
		os.Exit(7)
	case "kill":
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		os.Exit(8)
	case "deadline-then-clean-exit", "deadline-then-failed-exit":
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			os.Exit(11)
		}
		if os.Getenv("IG_SHARED_CANARY_DIAGNOSTIC") == "deadline-then-failed-exit" {
			os.Exit(7)
		}
		os.Exit(0)
	case "local", "caller":
		time.Sleep(time.Minute)
		os.Exit(9)
	}
}

// CommandContext can return its context error even after a successful
// child wait if its cancellation request raced that exit. Make that result
// deterministic by allowing a benign subprocess to exit on a pipe EOF
// from the cancel callback.
func TestSharedAttachCanaryDeadlineAfterCleanExit(t *testing.T) {
	for _, tc := range []struct {
		name                                   string
		caller, prior, exitFailure, wantSilent bool
	}{
		{"local-with-sample", false, true, false, true},
		{"local-no-sample", false, false, false, false},
		{"caller-with-sample", true, true, false, false},
		{"child-nonzero-with-sample", false, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := context.Background()
			d := 2 * time.Second
			if tc.caller {
				var cancel context.CancelFunc
				parent, cancel = context.WithTimeout(parent, d)
				defer cancel()
				d = 5 * time.Second
			}
			budget, cancel := context.WithTimeout(parent, d)
			defer cancel()
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			cmd := exec.CommandContext(budget, "/proc/self/exe", "-test.run=^TestSharedAttachCanaryChildHelper$")
			mode := "deadline-then-clean-exit"
			if tc.exitFailure {
				mode = "deadline-then-failed-exit"
			}
			cmd.Env = []string{"IG_SHARED_CANARY_DIAGNOSTIC=" + mode, "GORACE=atexit_sleep_ms=0"}
			cmd.Stdin = r
			cmd.Cancel = w.Close
			var prior []string
			if tc.prior {
				prior = []string{"example_1 (task_alloc)"}
			}
			err = runSharedAttachCanaryChild(parent, budget, cmd, prior)
			if err == nil {
				t.Fatal("canary admitted incomplete run")
			}
			if hasSilent := strings.Contains(err.Error(), "example_1 (task_alloc)"); hasSilent != tc.wantSilent {
				t.Errorf("has measured silent hook = %v, want %v: %v", hasSilent, tc.wantSilent, err)
			}
			if cmd.ProcessState == nil {
				t.Fatalf("child not reaped: %v", err)
			}
			if tc.exitFailure {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 7 {
					t.Fatalf("unrelated child exit lost: %v", err)
				}
				return
			}
			if !cmd.ProcessState.Success() || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected successful child plus deadline error, child state %v, err %v", cmd.ProcessState, err)
			}
			t.Logf("child success=%v, parent=%v, budget=%v, result=%v", cmd.ProcessState.Success(), parent.Err(), budget.Err(), err)
		})
	}
}
