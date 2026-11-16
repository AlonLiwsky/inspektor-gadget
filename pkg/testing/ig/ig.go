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

// Package ig provides executable wrapper for ig binary.
//
// Mainly used for testing of image-based gadgets.
package ig

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

// runner is responsible for storing configuration of ig executable and provide methods to interact with.
type runner struct {
	path       string
	image      string
	outputMode string

	// command.Command contains *exec.Cmd and additional properties and methods for the same.
	command.Command
	flags            []string
	readinessTimeout time.Duration
	kubernetesReady  bool
	localReady       bool
	// Mainline default readiness gate is used for StartAndStop unless opted out.
	waitReady       bool
	readyWatcher    *readinessWatcher
	noReadinessGate bool
}

func (ig *runner) createCmd() {
	args := append([]string{"run", ig.image}, ig.flags...)
	args = append(args, "-o="+ig.outputMode)

	ig.Cmd = exec.Command(ig.path, args...)
}

// Start waits for gadget startup only when a readiness option is enabled.
func (ig *runner) Start(t *testing.T) {
	if (!ig.kubernetesReady && !ig.localReady) || ig.Running() {
		ig.Command.Start(t)
		return
	}
	require.NoError(t, ig.validateReadiness(), "invalid readiness options")
	ctx, cancel := context.WithTimeout(t.Context(), ig.readinessTimeout)
	defer cancel()
	var writer io.Writer
	var waitReady func() error
	if ig.localReady {
		ready := newLocalReadiness()
		writer = ready
		waitReady = func() error { return ready.wait(ctx, ig.Exited(), ig.ExitError) }
	} else {
		nodes, namespace, err := ig.kubernetesTargets(ctx)
		require.NoError(t, err, "discovering gadget nodes")
		ig.flags = append(ig.flags, "--node="+strings.Join(nodes, ","), "--gadget-namespace="+namespace)
		ready := newNodeReadiness(nodes)
		writer = ready
		waitReady = func() error { return ready.wait(ctx, ig.Exited(), ig.ExitError) }
	}
	ig.flags = append(ig.flags, "--verbose")
	ig.createCmd()
	if ig.StdErrWriter != nil {
		writer = io.MultiWriter(ig.StdErrWriter, writer)
	}
	ig.StdErrWriter = writer
	ig.ObserveExit = true
	ig.Command.Start(t)
	// RunTestSteps normally stops the command first. Also cover a direct Start
	// caller whose readiness check fails before it can arrange cleanup.
	t.Cleanup(func() {
		if ig.Running() {
			ig.Stop(t)
		}
	})
	require.NoError(t, waitReady(), "waiting for gadget readiness")
}

func (ig *runner) validateReadiness() error {
	if ig.localReady && ig.kubernetesReady {
		return fmt.Errorf("local and Kubernetes readiness options are mutually exclusive")
	}
	if (ig.localReady || ig.kubernetesReady) && ig.readinessTimeout <= 0 {
		return fmt.Errorf("readiness timeout must be positive")
	}
	return nil
}

type Option func(*runner)

// WithLocalReady gates Start on the local GadgetContext.Run debug marker after
// operator Start, final Readiness checks and the startup callback. It does not
// wait for later asynchronous AddContainer callbacks. Use only with local ig,
// never a remote client, whose bare marker is emitted before remote readiness.
// The timeout bounds startup, not capture; it cannot be combined with
// WithKubernetesReady.
func WithLocalReady(timeout time.Duration) Option {
	return func(ig *runner) {
		ig.localReady = true
		ig.readinessTimeout = timeout
	}
}

// WithKubernetesReady gates Start on the existing remote, node-prefixed debug
// marker. The timeout bounds discovery and startup, not the capture interval.
func WithKubernetesReady(timeout time.Duration) Option {
	return func(ig *runner) {
		ig.kubernetesReady = true
		ig.readinessTimeout = timeout
	}
}

// WithoutReadinessGate opts out of the default StartAndStop marker gate.
func WithoutReadinessGate() Option {
	return func(ig *runner) { ig.noReadinessGate = true }
}

// WithPath used for providing custom path to ig executable.
func WithPath(path string) Option {
	return func(ig *runner) {
		ig.path = path
	}
}

// WithFlags args should be in form: "--flag_name=value" or "-shorthand=value".
func WithFlags(flags ...string) Option {
	return func(ig *runner) {
		ig.flags = append(ig.flags, flags...)
	}
}

// WithStartAndStop used to set StartAndStop value to true.
func WithStartAndStop() Option {
	return func(ig *runner) {
		ig.StartAndStop = true
	}
}

// WithValidateOutput used to compare the actual output with expected output.
func WithValidateOutput(validateOutput func(t *testing.T, output string)) Option {
	return func(ig *runner) {
		ig.ValidateOutput = validateOutput
	}
}

// WithValidateStderrOutput used to compare the actual output with expected output.
func WithValidateStderrOutput(validateOutput func(t *testing.T, output string)) Option {
	return func(ig *runner) {
		ig.ValidateStdErrOutput = validateOutput
	}
}

// WithStdOutWriter sets a writes that receives the standard output of the command.
func WithStdOutWriter(writer io.Writer) Option {
	return func(ig *runner) {
		ig.StdOutWriter = writer
	}
}

// WithStdErrWriter forwards stderr while retaining its full captured output.
func WithStdErrWriter(writer io.Writer) Option {
	return func(ig *runner) {
		ig.StdErrWriter = writer
	}
}

// WithOutputMode sets the output mode
func WithOutputMode(outputMode string) Option {
	return func(ig *runner) {
		ig.outputMode = outputMode
	}
}

// New creates a new IG configured with the Options passed as parameters.
func New(image string, opts ...Option) igtesting.TestStep {
	commandName := fmt.Sprintf("Run_%s", image)
	image = gadgetrunner.GetGadgetImageName(image)

	factoryRunner := &runner{
		path:       "ig",
		image:      image,
		outputMode: "json",
		Command: command.Command{
			Name: commandName,
		},
	}

	if path, ok := os.LookupEnv("IG_PATH"); ok {
		factoryRunner.path = path
	}

	// append IG_FLAGS flags separately to ensure
	// one from the option aren't overwritten
	if flags, ok := os.LookupEnv("IG_FLAGS"); ok {
		split := strings.Split(flags, " ")
		factoryRunner.flags = append(factoryRunner.flags, split...)
	}

	if publicKey := os.Getenv("IG_PUBLIC_KEY"); publicKey != "" {
		factoryRunner.flags = append(factoryRunner.flags, "--public-keys="+publicKey)
	}

	for _, opt := range opts {
		opt(factoryRunner)
	}

	if factoryRunner.StartAndStop && !factoryRunner.noReadinessGate && !factoryRunner.localReady && !factoryRunner.kubernetesReady {
		factoryRunner.enableReadinessGate()
	}

	factoryRunner.createCmd()

	return factoryRunner
}
