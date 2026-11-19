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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStdErrWriterStreamsAndRetainsSynchronousCapture(t *testing.T) {
	dir := t.TempDir()
	release := filepath.Join(dir, "release")
	script := filepath.Join(dir, "gadget")
	require.NoError(t, os.WriteFile(script, []byte(fmt.Sprintf(`#!/bin/sh
printf 'startup phase\n' >&2
while ! test -e '%s'; do sleep 0.01; done
printf 'capture complete\n' >&2
printf '{"event":"retained"}\n'
`, release)), 0o700))
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	defer reader.Close()
	lines := make(chan string, 2)
	var scanErr error
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		scanErr = scanner.Err()
	}()
	stdoutValidated, stderrValidated := false, false
	r := New("diagnostic-test", WithPath(script), WithStdErrWriter(writer),
		WithValidateOutput(func(t *testing.T, output string) {
			require.JSONEq(t, `{"event":"retained"}`, output)
			stdoutValidated = true
		}),
		WithValidateStderrOutput(func(t *testing.T, output string) {
			require.Equal(t, "startup phase\ncapture complete\n", output)
			stderrValidated = true
		}),
	)
	require.False(t, r.IsStartAndStop())
	done := make(chan struct{})
	go func() { defer close(done); defer writer.Close(); r.Run(t) }()
	t.Cleanup(func() {
		// Also release the fake command if an assertion fails before the gate opens.
		_ = os.WriteFile(release, nil, 0o600)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("synchronous command did not exit")
		}
	})
	select {
	case line := <-lines:
		require.Equal(t, "startup phase", line)
	case <-time.After(5 * time.Second):
		t.Fatal("stderr was not forwarded before process exit")
	}
	select {
	case <-done:
		t.Fatal("Run returned before the subprocess naturally completed")
	default:
	}
	require.NoError(t, os.WriteFile(release, nil, 0o600))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("synchronous Run did not finish")
	}
	var remaining []string
	for line := range lines {
		remaining = append(remaining, line)
	}
	require.NoError(t, scanErr)
	require.Equal(t, []string{"capture complete"}, remaining)
	require.True(t, stdoutValidated)
	require.True(t, stderrValidated)
	require.False(t, r.Running())
}
