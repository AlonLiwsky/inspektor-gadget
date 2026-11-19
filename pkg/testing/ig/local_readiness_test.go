// Copyright 2019-2024 The Inspektor Gadget authors
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

package ig

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
)

func TestLocalReadinessExactMarker(t *testing.T) {
	for _, valid := range []string{"level=debug msg=running...\n", "level=debug msg=\"running...\"\n"} {
		r := newLocalReadiness()
		for _, invalid := range []string{
			"level=debug msg=\"node-a | running...\"\n",
			"level=warning msg=running...\n", "level=info msg=running...\n",
			"prefix level=debug msg=running...\n", "level=debug msg=running...suffix\n",
			"level=debug msg=\"prefix running...\"\n", "level=debug msg=\"running... suffix\"\n",
		} {
			_, err := r.Write([]byte(invalid))
			require.NoError(t, err)
		}
		select {
		case <-r.ready:
			t.Fatal("invalid marker accepted")
		default:
		}
		_, err := r.Write([]byte(valid[:len(valid)-2]))
		require.NoError(t, err)
		select {
		case <-r.ready:
			t.Fatal("partial marker accepted")
		default:
		}
		_, err = r.Write([]byte(valid[len(valid)-2:]))
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, r.wait(ctx, make(chan struct{}), func() error { return nil }))
		_, err = r.Write([]byte(valid))
		require.NoError(t, err) // Duplicate must not panic.
	}
}

func TestLocalReadinessLogrusFormat(t *testing.T) {
	r := newLocalReadiness()
	logger := log.New()
	logger.SetOutput(r)
	logger.SetLevel(log.DebugLevel)
	logger.Debug("running...")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, r.wait(ctx, make(chan struct{}), func() error { return nil }))
}

func TestLocalReadinessFailure(t *testing.T) {
	for _, alreadyReady := range []bool{false, true} {
		for _, cause := range []string{"cancel", "deadline", "exit-success", "exit-error"} {
			t.Run(fmt.Sprintf("%v/%s", alreadyReady, cause), func(t *testing.T) {
				r := newLocalReadiness()
				if alreadyReady {
					_, err := fmt.Fprintln(r, "level=debug msg=running...")
					require.NoError(t, err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				exited := make(chan struct{})
				var exitErr error
				switch cause {
				case "cancel":
					cancel()
				case "deadline":
					var c context.CancelFunc
					ctx, c = context.WithDeadline(ctx, time.Now().Add(-time.Second))
					defer c()
				case "exit-success":
					close(exited)
				case "exit-error":
					exitErr = fmt.Errorf("startup failed")
					close(exited)
				}
				err := r.wait(ctx, exited, func() error { return exitErr })
				require.ErrorContains(t, err, "local gadget readiness")
				if exitErr != nil {
					require.ErrorIs(t, err, exitErr)
				}
				if ctx.Err() != nil {
					require.ErrorIs(t, err, ctx.Err())
				}
			})
		}
	}
}

func TestLocalReadinessProcessExit(t *testing.T) {
	for _, status := range []string{"0", "7"} {
		t.Run(status, func(t *testing.T) {
			r := newLocalReadiness()
			c := &command.Command{Name: "local-exit", Cmd: exec.Command("sh", "-c", "printf 'startup diagnostic\\n' >&2; exit "+status), StdErrWriter: r, ObserveExit: true}
			c.Start(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := r.wait(ctx, c.Exited(), c.ExitError)
			require.ErrorContains(t, err, "local gadget readiness")
			require.NotErrorIs(t, err, context.DeadlineExceeded)
			select {
			case <-c.Exited():
			default:
				t.Fatal("process not reaped")
			}
		})
	}
}

func TestLocalReadinessOptions(t *testing.T) {
	for _, options := range [][]Option{
		{WithLocalReady(time.Second), WithKubernetesReady(time.Second)},
		{WithKubernetesReady(time.Second), WithLocalReady(time.Second)},
		{WithLocalReady(0)},
		{WithLocalReady(-time.Second)},
	} {
		r := &runner{}
		for _, option := range options {
			option(r)
		}
		require.Error(t, r.validateReadiness())
	}
	for _, options := range [][]Option{nil, {WithLocalReady(time.Second)}, {WithKubernetesReady(time.Second)}} {
		r := &runner{}
		for _, option := range options {
			option(r)
		}
		require.NoError(t, r.validateReadiness())
	}
}

func TestLocalRunnerWaitsAndPreservesCapture(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "gadget")
	started := filepath.Join(dir, "started")
	release := filepath.Join(dir, "release")
	output := filepath.Join(dir, "output")
	require.NoError(t, os.WriteFile(script, []byte(fmt.Sprintf(`#!/bin/sh
printf 'startup diagnostic\n' >&2
printf '%%5000s\n' before >&2
touch '%s'
while ! test -e '%s'; do sleep 0.01; done
printf 'level=debug msg=running...\n' >&2
printf '%%5000s\n' after >&2
printf '{"event":"retained"}\n'
touch '%s'
exec sleep 60
`, started, release, output)), 0o700))
	r := &runner{path: script, image: "test", outputMode: "json"}
	WithLocalReady(time.Second)(r)
	r.ValidateOutput = func(t *testing.T, value string) { require.JSONEq(t, `{"event":"retained"}`, value) }
	var stderr bytes.Buffer
	r.StdErrWriter = &stderr
	returned := make(chan struct{})
	go func() { defer close(returned); r.Start(t) }()
	require.Eventually(t, func() bool { _, err := os.Stat(started); return err == nil }, time.Second, time.Millisecond)
	select {
	case <-returned:
		t.Fatal("Start returned before local readiness")
	case <-time.After(20 * time.Millisecond):
	}
	require.NoError(t, os.WriteFile(release, nil, 0o600))
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("Start did not return after readiness")
	}
	require.Eventually(t, func() bool { _, err := os.Stat(output); return err == nil }, time.Second, time.Millisecond)
	require.Contains(t, r.Cmd.Args, "--verbose")
	require.NotContains(t, r.Cmd.Args, "--node=")
	r.Stop(t)
	require.Equal(t, "startup diagnostic\n"+fmt.Sprintf("%5000s\n", "before")+"level=debug msg=running...\n"+fmt.Sprintf("%5000s\n", "after"), stderr.String())
}

func TestLocalReadinessIgnoresStdoutMarker(t *testing.T) {
	ready := newLocalReadiness()
	c := &command.Command{
		Name:           "stdout-is-not-readiness",
		Cmd:            exec.Command("sh", "-c", "printf 'level=debug msg=running...\\n'"),
		StdErrWriter:   ready,
		ObserveExit:    true,
		ValidateOutput: func(t *testing.T, output string) { require.Equal(t, "level=debug msg=running...\n", output) },
	}
	c.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.ErrorContains(t, ready.wait(ctx, c.Exited(), c.ExitError), "command exited before capture")
	c.Stop(t)
}

func TestLocalReadinessTimeoutStopsProcess(t *testing.T) {
	ready := newLocalReadiness()
	c := &command.Command{Name: "local-timeout", Cmd: exec.Command("sleep", "60"), StdErrWriter: ready, ObserveExit: true}
	c.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, ready.wait(ctx, c.Exited(), c.ExitError), context.DeadlineExceeded)
	c.Stop(t)
	select {
	case <-c.Exited():
	default:
		t.Fatal("timed-out process not reaped")
	}
}

func TestLocalReadinessDiscardsOversizedSplitLine(t *testing.T) {
	r := newLocalReadiness()
	chunk := strings.Repeat("x", 1024)
	for range 5 {
		n, err := r.Write([]byte(chunk))
		require.NoError(t, err)
		require.Equal(t, len(chunk), n)
		require.LessOrEqual(t, len(r.pending), 4096, "unterminated line retention must be bounded")
	}
	require.Zero(t, len(r.pending), "oversized line must be discarded, not retain its tail")
	_, err := r.Write([]byte("level=debug msg=running...\n"))
	require.NoError(t, err)
	select {
	case <-r.ready:
		t.Fatal("oversized line suffix spoofed readiness")
	default:
	}
	_, err = r.Write([]byte("level=debug msg=running...\n"))
	require.NoError(t, err)
	select {
	case <-r.ready:
	default:
		t.Fatal("legitimate line after discarded line did not signal readiness")
	}
}

func TestLocalReadinessDiscardsOversizedSingleWrite(t *testing.T) {
	r := newLocalReadiness()
	data := strings.Repeat("x", 1<<20)
	n, err := r.Write([]byte(data))
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.Zero(t, len(r.pending), "oversized input must not be retained")
	_, err = r.Write([]byte("\nlevel=debug msg=running...\n"))
	require.NoError(t, err)
	select {
	case <-r.ready:
	default:
		t.Fatal("legitimate line after oversized write was ignored")
	}
}

func TestLocalReadinessStopsParsingAfterReady(t *testing.T) {
	r := newLocalReadiness()
	input := "level=debug msg=running...\n" + strings.Repeat("x", 1024)
	n, err := r.Write([]byte(input))
	require.NoError(t, err)
	require.Equal(t, len(input), n)
	require.Zero(t, len(r.pending), "tail of readiness write must not be parsed or retained")
	n, err = r.Write([]byte(strings.Repeat("x", 1<<20)))
	require.NoError(t, err)
	require.Equal(t, 1<<20, n)
	require.Zero(t, len(r.pending), "writes after readiness must not be parsed or retained")
}
