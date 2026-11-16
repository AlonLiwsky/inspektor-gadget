// Copyright 2026 The Inspektor Gadget authors
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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"

	igconfig "github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

const (
	// readinessMarker is the debug message the gadget logs right after all operators
	// (including the eBPF programs) have been started. Waiting for it lets the harness run
	// the workload only once the gadget is actually capturing, instead of betting on a fixed
	// sleep. It is emitted by pkg/gadget-context (see run.go and gadget-context.go); keep this
	// string in sync with those log messages.
	//
	// Beyond this string, the gate also relies on two stable behaviours of the CLI stderr:
	// the gRPC runtime forwards remote-node logs prefixed with "<node> | " as the raw message
	// (pkg/runtime/grpc, see parseReadyNode), and logrus uses its non-TTY key=value format
	// ("level=debug", quoted msg). If either changes, node discrimination or debug filtering
	// here must be updated accordingly.
	readinessMarker = "running..."

	// nodeMarkerSep identifies a readiness marker that was forwarded from a remote node by the
	// gRPC runtime, which prefixes forwarded logs with "<node> | " (see pkg/runtime/grpc).
	nodeMarkerSep = "| " + readinessMarker

	// dispatchMarker is the debug message the gRPC runtime (kubectl-gadget) logs once for each
	// node it runs the gadget on, before that node starts (see runGadgetOnTargets in
	// pkg/runtime/grpc/oci.go). Counting these tells the gate how many nodes to expect a
	// readiness marker from, honouring --node scoping, without querying the cluster. A node is
	// always dispatched before it can report ready, so "all dispatched nodes are ready" is
	// reached exactly when the number of distinct ready nodes equals the dispatched count.
	dispatchMarker = "running gadget on node "

	// readinessTimeout bounds how long the gate waits for the readiness marker. It only needs to
	// exceed the worst-case cold start (first-run OCI image pull plus load/attach on a slow
	// node; heavier gadgets that bundle a WASM module take noticeably longer, especially on the
	// multi-node minikube runners where the "nodes" share one host). A gadget that fails to
	// start exits and is caught immediately by exit tracking (see WaitForReady), so this can be
	// generous without making failing tests hang. If it expires with at least one instance
	// capturing, the gate proceeds anyway.
	readinessTimeout = 120 * time.Second
)

// readinessWatcher tracks gadget readiness on stderr. For the gRPC runtime (kubectl-gadget) it
// counts the nodes the gadget was dispatched to and the distinct nodes that reported ready (each
// via a node-prefixed marker); for the local runtime (ig) a single bare marker is expected.
type readinessWatcher struct {
	mu         sync.Mutex
	dispatched int
	nodes      map[string]struct{}
	bareSeen   bool
	updated    chan struct{}
}

func newReadinessWatcher() *readinessWatcher {
	return &readinessWatcher{
		nodes:   make(map[string]struct{}),
		updated: make(chan struct{}, 1),
	}
}

// observe is invoked with each stderr line while the gadget is running.
func (w *readinessWatcher) observe(line string) {
	var changed bool

	switch {
	case strings.Contains(line, dispatchMarker):
		w.mu.Lock()
		w.dispatched++
		changed = true
		w.mu.Unlock()
	case strings.Contains(line, readinessMarker):
		node, isNode := parseReadyNode(line)
		w.mu.Lock()
		if isNode {
			if _, ok := w.nodes[node]; !ok {
				w.nodes[node] = struct{}{}
				changed = true
			}
		} else if !w.bareSeen {
			w.bareSeen = true
			changed = true
		}
		w.mu.Unlock()
	}

	if changed {
		select {
		case w.updated <- struct{}{}:
		default:
		}
	}
}

// ready reports whether every node the gadget was dispatched to has reported ready (gRPC), or a
// bare marker was seen (local). Because a node is always dispatched before it can report ready,
// this is true exactly when all expected nodes are capturing.
//
// This compares a running count of dispatched nodes against the ready set, which is safe because
// dispatch lines and readiness markers arrive on the same, in-order stderr stream: a node's
// dispatch line is logged client-side within microseconds of the run starting (in the goroutine
// spawn loop of runGadgetOnTargets, pkg/runtime/grpc/oci.go), while its readiness marker is only
// produced after a full gRPC round trip plus image pull/load/attach (seconds later, forwarded
// from the node). So by the time observe() sees any readiness marker, every dispatch line that
// precedes it in the stream has already been counted; the running dispatched count is therefore
// already final. The dispatch line is logged exactly once per target (no retry), so counting
// occurrences equals the node count. A hypothetical extra or missing marker cannot cause an early
// pass: it would only delay the gate until the graceful timeout in WaitForReady.
func (w *readinessWatcher) ready(nodeMode bool) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if nodeMode {
		return w.dispatched >= 1 && len(w.nodes) >= w.dispatched
	}
	return w.bareSeen
}

// someReady reports whether at least one instance has reported ready. It's used to decide
// whether to proceed (with a warning) when not all dispatched nodes are ready before the
// timeout, so a lagging or unreachable node cannot fail an otherwise-capturing run.
func (w *readinessWatcher) someReady(nodeMode bool) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if nodeMode {
		return len(w.nodes) >= 1
	}
	return w.bareSeen
}

func (w *readinessWatcher) summary() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return fmt.Sprintf("%d/%d node(s) ready, bare marker seen: %v", len(w.nodes), w.dispatched, w.bareSeen)
}

// parseReadyNode extracts a distinct node identifier from a forwarded, node-prefixed readiness
// marker. It returns (_, false) for a bare (non-forwarded) marker. The gRPC runtime forwards
// remote logs as `fmt.Sprintf("%-20s | %s", node, msg)`, which the client re-logs (logrus
// key=value, non-TTY) as `... msg="<node>          | running..."`.
func parseReadyNode(line string) (string, bool) {
	i := strings.Index(line, nodeMarkerSep)
	if i < 0 {
		return "", false
	}
	// Everything up to the separator ends with the padded node name; trim the "%-20s" padding.
	prefix := strings.TrimRight(line[:i], " ")
	// The node name is the logrus message value, i.e. what follows the last `msg="`.
	if j := strings.LastIndex(prefix, `msg="`); j >= 0 {
		return prefix[j+len(`msg="`):], true
	}
	// Fallback: the last whitespace-separated token (node names contain no spaces).
	fields := strings.Fields(prefix)
	if len(fields) == 0 {
		return "", false
	}
	return fields[len(fields)-1], true
}

// isDebugLine reports whether a stderr line is a logrus debug line. Such lines are the verbose
// noise produced by "-v" and are dropped from the stored stderr to keep test reports readable.
func isDebugLine(line string) bool {
	return strings.Contains(line, "level=debug")
}

// enableReadinessGate configures the runner to detect the gadget readiness marker on stderr. It
// runs the gadget with "-v" so the marker is emitted, observes stderr live and drops the extra
// debug noise from the stored stderr.
func (ig *runner) enableReadinessGate() {
	ig.waitReady = true
	ig.readyWatcher = newReadinessWatcher()
	ig.flags = append(ig.flags, "-v")
	ig.StdErrLineObserver = ig.readyWatcher.observe
	ig.StdErrStoreFilter = isDebugLine
	// Track the process exit so the gate can fail fast if the gadget exits before it becomes
	// ready (e.g. image pull, signature, eBPF load/verifier or capability errors), instead of
	// waiting for readinessTimeout.
	ig.TrackExit()
}

// WaitForReady blocks until the gadget has reported that it is running (and thus capturing) on
// all expected instances, or fails the test after readinessTimeout. It is a no-op when the
// readiness gate is not enabled.
func (ig *runner) WaitForReady(t *testing.T) {
	if !ig.waitReady || ig.readyWatcher == nil {
		return
	}
	nodeMode := utils.CurrentTestComponent == utils.KubectlGadgetTestComponent
	partial, err := waitForReadiness(ig.readyWatcher, nodeMode, readinessTimeout, ig.ExitCh(), ig.ExitErr)
	if err != nil {
		t.Fatalf("[%s] %v (%s)", ig.Name, err, ig.readyWatcher.summary())
	}
	if partial {
		t.Logf("[%s] gadget readiness timed out after %s; proceeding with partial readiness (%s)",
			ig.Name, readinessTimeout, ig.readyWatcher.summary())
	} else {
		t.Logf("[%s] gadget ready (%s)", ig.Name, ig.readyWatcher.summary())
	}
}

// waitForReadiness returns partial=true only for a live gadget with at least one
// capturing instance when the deadline expires. A known process exit wins over
// both the complete-ready and partial-ready paths, regardless of select order.
func waitForReadiness(w *readinessWatcher, nodeMode bool, timeout time.Duration, exitCh <-chan struct{}, exitErr func() error) (partial bool, err error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	exited := func() error {
		if err := exitErr(); err != nil {
			return fmt.Errorf("gadget exited before it started capturing: %w", err)
		}
		return fmt.Errorf("gadget exited before it started capturing")
	}
	checkExit := func() error {
		select {
		case <-exitCh:
			return exited()
		default:
			return nil
		}
	}
	for {
		if w.ready(nodeMode) {
			if err := checkExit(); err != nil {
				return false, err
			}
			return false, nil
		}
		select {
		case <-w.updated:
		case <-exitCh:
			return false, exited()
		case <-deadline.C:
			// A closed exit channel and an expired timer can both be selected. Never
			// release a workload after a known exit, even if some nodes were ready.
			if err := checkExit(); err != nil {
				return false, err
			}
			if w.someReady(nodeMode) {
				return true, nil
			}
			return false, fmt.Errorf("gadget did not become ready within %s", timeout)
		}
	}
}

// stderr is piped, so logrus uses its non-terminal text format. Require the
// complete remote message: the bare client "running..." precedes subscription.
// A target can finish while the client is still waiting for other targets.
// Both error and clean remote termination invalidate the startup barrier.
var remoteTerminated = regexp.MustCompile(`(?:^| )level=debug msg="([a-zA-Z0-9._-]+) +\| (done from server side \(.*\))"(?: |$)`)

var remoteRunning = regexp.MustCompile(`(?:^| )level=debug msg="([a-zA-Z0-9._-]+) +\| running\.\.\."(?: |$)`)

type nodeReadiness struct {
	expected    map[string]bool
	mu          sync.Mutex
	pending     string
	missing     map[string]bool
	ready       chan struct{}
	failed      chan struct{}
	terminalErr error
}

func newNodeReadiness(nodes []string) *nodeReadiness {
	r := &nodeReadiness{
		expected: make(map[string]bool),
		missing:  make(map[string]bool),
		ready:    make(chan struct{}),
		failed:   make(chan struct{}),
	}
	for _, node := range nodes {
		r.missing[node] = true
		r.expected[node] = true
	}
	return r
}

func (r *nodeReadiness) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending += string(p)
	for {
		line, rest, ok := strings.Cut(r.pending, "\n")
		if !ok {
			break
		}
		r.pending = rest
		if match := remoteTerminated.FindStringSubmatch(line); len(match) == 3 && r.expected[match[1]] && r.terminalErr == nil {
			r.terminalErr = fmt.Errorf("node %s terminated before capture: %s", match[1], match[2])
			close(r.failed)
		}
		match := remoteRunning.FindStringSubmatch(line)
		if len(match) == 2 && r.missing[match[1]] {
			delete(r.missing, match[1])
			if len(r.missing) == 0 {
				close(r.ready)
			}
		}
	}
	return len(p), nil
}

func (r *nodeReadiness) failure(cause error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	nodes := make([]string, 0, len(r.missing))
	for node := range r.missing {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	return fmt.Errorf("remote gadget readiness missing nodes [%s]: %w", strings.Join(nodes, ", "), cause)
}

func (r *nodeReadiness) wait(ctx context.Context, exited <-chan struct{}, exitError func() error) error {
	if len(r.expected) == 0 {
		return fmt.Errorf("no expected gadget nodes")
	}
	exitFailure := func() error {
		err := exitError()
		if err == nil {
			err = fmt.Errorf("command exited before capture")
		}
		return r.failure(err)
	}
	select {
	case <-ctx.Done():
		return r.failure(ctx.Err())
	case <-exited:
		return exitFailure()
	case <-r.failed:
		return r.failure(r.terminalErr)
	case <-r.ready:
		// Do not release a workload if cancellation or target/process exit is known.
		if err := ctx.Err(); err != nil {
			return r.failure(err)
		}
		select {
		case <-r.failed:
			return r.failure(r.terminalErr)
		case <-exited:
			return exitFailure()
		default:
			return nil
		}
	}
}

func (ig *runner) kubernetesTargets(ctx context.Context) ([]string, string, error) {
	flags := pflag.NewFlagSet("test readiness", pflag.ContinueOnError)
	flags.ParseErrorsAllowlist.UnknownFlags = true
	config := genericclioptions.NewConfigFlags(false)
	config.AddFlags(flags)
	var configPath string
	flags.StringVar(&configPath, "config", "", "")
	var selection string
	var namespace string
	flags.StringVar(&selection, "node", "", "")
	flags.StringVar(&namespace, "gadget-namespace", grpcruntime.DefaultGadgetNamespace, "")
	if err := flags.Parse(ig.flags); err != nil {
		return nil, "", err
	}
	if err := rejectImplicitTargetConfig(flags, configPath); err != nil {
		return nil, "", err
	}
	client, err := k8sutil.NewClientsetFromConfigFlags(config)
	if err != nil {
		return nil, "", err
	}
	if !flags.Changed("gadget-namespace") {
		namespace, err = gadgetNamespace(ctx, client)
		if err != nil {
			return nil, "", err
		}
	}
	nodes, err := gadgetNodes(ctx, client, namespace, params.SplitStringSlice(selection))
	if err != nil {
		return nil, "", err
	}
	// Replace discovery inputs with the exact frozen targets used by the barrier.
	filtered := make([]string, 0, len(ig.flags))
	for i := 0; i < len(ig.flags); i++ {
		arg := ig.flags[i]
		if arg == "--node" || arg == "--gadget-namespace" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--node=") || strings.HasPrefix(arg, "--gadget-namespace=") {
			continue
		}
		filtered = append(filtered, arg)
	}
	ig.flags = filtered
	return nodes, namespace, nil
}

func gadgetNodes(ctx context.Context, client kubernetes.Interface, namespace string, selected []string) ([]string, error) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "k8s-app=gadget"})
	if err != nil {
		return nil, err
	}
	available := make(map[string]bool)
	for _, pod := range pods.Items {
		if pod.Spec.NodeName == "" && len(selected) == 0 {
			return nil, fmt.Errorf("gadget pod %s/%s has no assigned node", namespace, pod.Name)
		}
		available[pod.Spec.NodeName] = true
	}
	if len(available) == 0 {
		return nil, fmt.Errorf("no gadget pods found in namespace %q", namespace)
	}
	nodes := make([]string, 0, len(available))
	if len(selected) > 0 {
		seen := make(map[string]bool)
		for _, node := range selected {
			if !available[node] {
				return nil, fmt.Errorf("node %q does not have a gadget pod in namespace %q", node, namespace)
			}
			if seen[node] {
				return nil, fmt.Errorf("duplicate selected node %q", node)
			}
			nodes = append(nodes, node)
			seen[node] = true
		}
	} else {
		for node := range available {
			nodes = append(nodes, node)
		}
	}
	sort.Strings(nodes)
	return nodes, nil
}

// Match kubectl-gadget namespace auto-discovery, but fail closed on API errors.
func gadgetNamespace(ctx context.Context, client kubernetes.Interface) (string, error) {
	daemonSets, err := client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=gadget", LabelSelector: "k8s-app=gadget",
	})
	if err != nil {
		return "", err
	}
	switch len(daemonSets.Items) {
	case 0:
		return grpcruntime.DefaultGadgetNamespace, nil
	case 1:
		return daemonSets.Items[0].Namespace, nil
	default:
		return "", fmt.Errorf("multiple gadget namespaces; specify --gadget-namespace")
	}
}

// The CLI applies its own config/env overrides before loading Kubernetes config.
// Keep this test helper small: require those target overrides to be explicit,
// rather than silently discovering in a different cluster or reimplementing CLI
// configuration. The standard KUBECONFIG loader is still used normally.
func rejectImplicitTargetConfig(flags *pflag.FlagSet, path string) error {
	explicit := path != ""
	if !explicit {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, ".ig", "config.yaml")
	}
	config := igconfig.NewWithPath(path)
	if err := config.ReadInConfig(); explicit && err != nil {
		return err
	}
	for _, name := range []string{"kubeconfig", "context", "cluster", "user", "server", "tls-server-name", "insecure-skip-tls-verify", "certificate-authority", "client-certificate", "client-key", "token", "as", "as-group", "as-uid", "username", "password", "gadget-namespace", "node"} {
		key := name
		if name == "gadget-namespace" || name == "node" {
			key = igconfig.RuntimeKey + "." + name
		}
		if err := config.BindEnv(key); err != nil {
			return err
		}
		if config.IsSet(key) && !flags.Changed(name) {
			return fmt.Errorf("readiness discovery requires explicit --%s instead of implicit Inspektor Gadget config/environment override", name)
		}
	}
	return nil
}
