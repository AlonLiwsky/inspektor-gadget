// Copyright 2024 The Inspektor Gadget authors
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

package tests

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type traceTCPretransEvent struct {
	utils.CommonData

	Timestamp string        `json:"timestamp"`
	NetNs     uint64        `json:"netns_id"`
	Proc      utils.Process `json:"proc"`

	Type string           `json:"type"`
	Src  utils.L4Endpoint `json:"src"`
	Dst  utils.L4Endpoint `json:"dst"`
}

func TestTraceTCPretrans(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		t.Skip("Skipping test as K8s doesn't support privileged containers")
	} else if utils.CurrentTestComponent == utils.IgLocalTestComponent && utils.Runtime == "containerd" {
		t.Skip("Skipping test as containerd test utils can't use the network")
	}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-tcpretrans"
	containerImage := gadgettesting.NetworkMultitoolImage

	var ns string
	// run the container with privileged mode to be able to use tc command
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage), containers.WithPrivileged()}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-tcpretrans")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}
	// Keep the container idle until the tracer reports readiness.
	cmds := "exec tail -f /dev/null"
	testContainer := containerFactory.NewContainer(
		containerName,
		cmds,
		containerOpts...,
	)
	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})
	// Drop only the test TCP destination, not ARP or unrelated control traffic.
	// All unclassified priorities use band 1; only the explicit filter uses 3.
	tcSetup := "tc qdisc add dev eth0 root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 && " +
		"tc qdisc add dev eth0 parent 1:3 handle 30: netem loss 100% && " +
		"tc filter add dev eth0 protocol ip parent 1: prio 1 u32 " +
		"match ip dst 1.1.1.1/32 match ip protocol 6 0xff match ip dport 443 0xffff flowid 1:3"
	dockerExec := func(script string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "docker", "exec", testContainer.ID(), "sh", "-c", script).CombinedOutput()
	}
	t.Cleanup(func() {
		out, err := dockerExec("tc -s qdisc show dev eth0; tc -s filter show dev eth0 parent 1:; cat /proc/net/snmp; cat /tmp/retrans-wget.stderr")
		t.Logf("retransmission stimulus diagnostics (error=%v):\n%s", err, out)
	})
	out, err := dockerExec(tcSetup)
	require.NoError(t, err, "installing targeted packet loss: %s", out)
	// Retain tracer startup and attachment diagnostics.
	runnerOpts := []igrunner.Option{
		igrunner.WithFlags("--verbose"),
		igrunner.WithStdErrWriter(os.Stderr),
	}
	commonDataOpts := []utils.CommonDataOption{utils.WithContainerImageName(containerImage), utils.WithContainerID(testContainer.ID())}

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithLocalReady(2*time.Minute), igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), "--timeout=5"))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns), "--timeout=5"))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}
	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntries := &traceTCPretransEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Proc:       utils.BuildProc("wget", 0, 0),
				Src: utils.L4Endpoint{
					Addr:    utils.NormalizedStr,
					Version: 4,
					Port:    utils.NormalizedInt,
					Proto:   "TCP",
				},
				Dst: utils.L4Endpoint{
					Addr:    utils.NormalizedStr,
					Version: 4,
					Port:    443,
					Proto:   "TCP",
				},
				Type: "RETRANS",

				Timestamp: utils.NormalizedStr,
				NetNs:     utils.NormalizedInt,
			}

			if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
				expectedEntries.Src.K8s = utils.K8s{
					Kind: "raw",
				}
				expectedEntries.Dst.K8s = expectedEntries.Src.K8s
			}

			normalize := func(e *traceTCPretransEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeInt(&e.NetNs)
				utils.NormalizeProc(&e.Proc)
				utils.NormalizeString(&e.Src.Addr)
				utils.NormalizeInt(&e.Src.Port)

				if e.Dst.Addr != "1.1.1.1" && e.Dst.Addr != "1.0.0.1" {
					t.Fatalf("unexpected destination address: %s", e.Dst.Addr)
				}
				utils.NormalizeString(&e.Dst.Addr)
			}
			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries)
		},
	))
	traceTCPCmd := igrunner.New("trace_tcpretrans", runnerOpts...)

	// Readiness enables observed exit on the existing runner. Do not use the
	// generic start/stop test-step path, which adds a fixed ten-second sleep.
	observed, ok := traceTCPCmd.(interface {
		Exited() <-chan struct{}
		ExitError() error
	})
	require.True(t, ok, "tracer must expose observed completion")
	traceTCPCmd.Start(t)
	require.NotNil(t, observed.Exited(), "tracer must observe natural completion")

	// One fresh connection starts AFTER attach/readiness. Success is neither
	// expected nor required: every test SYN is deliberately dropped.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	workload := exec.CommandContext(ctx, "docker", "exec", testContainer.ID(), "sh", "-c",
		"echo $$ > /tmp/retrans-wget.pid; "+
			"unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY; "+
			"exec wget --no-check-certificate -O /dev/null https://1.1.1.1 2>/tmp/retrans-wget.stderr")
	var workloadOutput bytes.Buffer
	workload.Stdout = &workloadOutput
	workload.Stderr = &workloadOutput
	require.NoError(t, workload.Start(), "starting retransmission workload")
	workloadDone := make(chan struct{})
	var workloadErr error
	go func() {
		workloadErr = workload.Wait()
		close(workloadDone)
	}()
	t.Cleanup(func() {
		cancel()
		<-workloadDone // Join the docker client; container cleanup joins wget.
		t.Logf("workload client completed (error=%v): %s", workloadErr, workloadOutput.String())
	})
	select {
	case <-workloadDone:
		t.Fatalf("wget exited before capture completed: %v: %s", workloadErr, workloadOutput.String())
	case <-observed.Exited():
		require.NoError(t, observed.ExitError(), "tracer natural completion")
	}
	select {
	case <-workloadDone:
		t.Fatalf("wget did not remain alive for capture: %v: %s", workloadErr, workloadOutput.String())
	default:
	}
	out, err = dockerExec("pid=$(cat /tmp/retrans-wget.pid) && kill -0 \"$pid\" && test \"$(cat /proc/$pid/comm)\" = wget")
	require.NoError(t, err, "checking live wget after capture: %s", out)
	traceTCPCmd.Stop(t) // Already exited: validate the original event assertions.
}
