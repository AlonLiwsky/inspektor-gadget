// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// Attached-test helpers shared by the tagged qualification tests and the
// untagged product test (TestSharedProductNodeReadyAttached): trusted
// leases over a test-spawned init, container-like inits in a dedicated
// cgroup and the M4 test policy. Moved unchanged out of
// shared_node_qualification_attached_test.go and
// shared_node_m4_attached_test.go (plan F7).

// sharedM2Lease is a trusted lease over one init process the test spawned in
// the dedicated cgroup. Test only.
type sharedM2Lease struct{ proc, cgroup, mount, hostMount *os.File }

func (*sharedM2Lease) Check(context.Context) error    { return nil }
func (l *sharedM2Lease) InitProc() *os.File           { return l.proc }
func (l *sharedM2Lease) Cgroup() *os.File             { return l.cgroup }
func (l *sharedM2Lease) MountNamespace() *os.File     { return l.mount }
func (l *sharedM2Lease) HostMountNamespace() *os.File { return l.hostMount }
func (l *sharedM2Lease) Close() error {
	var result error
	for _, f := range []*os.File{l.proc, l.cgroup, l.mount, l.hostMount} {
		if f != nil {
			result = errors.Join(result, f.Close())
		}
	}
	return result
}

// startSharedTestInit starts a bound workload's init the way a container
// runtime does, so the binding scope check (no host mount namespace, no
// inferred exemption) holds: sleep, cloned directly into cgroup (CgroupFD)
// with its own private mount namespace (CLONE_NEWNS; Go remounts / private
// before exec). InitHostPID is this child. Killed and reaped at test end.
func startSharedTestInit(t *testing.T, cgroup, name string, seconds int) *exec.Cmd {
	t.Helper()
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	cmd := exec.Command("/bin/sleep", strconv.Itoa(seconds))
	cmd.Args[0] = name
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s in its own mount namespace and %s: %v", name, cgroup, err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := cmd.Process.Pid
	var child, host unix.Stat_t
	if err := errors.Join(unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &child), unix.Stat("/proc/self/ns/mnt", &host)); err != nil {
		t.Fatal(err)
	}
	if child.Ino == host.Ino && child.Dev == host.Dev {
		t.Fatalf("%s (pid %d) shares the host mount namespace", name, pid)
	}
	data, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil || !strings.Contains("\n"+string(data), "\n"+strconv.Itoa(pid)+"\n") {
		t.Fatalf("%s (pid %d) is not in %s: %v", name, pid, cgroup, err)
	}
	return cmd
}

// sharedPipeInit is a container-like init that runs commands it reads from
// a pipe (like a runtime's init before the entrypoint exec): a shell cloned
// directly into the cgroup with its own mount namespace. Every command it
// runs is forked and executed by the adopted init itself, so its verdicts
// are the bound route's (unlike a shell joining the cgroup from the host,
// which has no TASK).
type sharedPipeInit struct {
	cmd  *exec.Cmd
	mu   sync.Mutex
	in   io.WriteCloser
	out  *bufio.Reader
	path string
	ino  uint64
}

const sharedPipeInitScript = `while IFS= read -r line; do /bin/sh -c "$line"; echo "@@done $?"; done`

func startSharedPipeInit(t *testing.T, cgroup, name string) *sharedPipeInit {
	t.Helper()
	return startSharedPipeInitShell(t, cgroup, name, "/bin/sh")
}

// startSharedPipeInitShell is startSharedPipeInit with an explicit shell
// (bash survives a refused fork; dash exits on it).
func startSharedPipeInitShell(t *testing.T, cgroup, name, shell string) *sharedPipeInit {
	t.Helper()
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	cmd := exec.Command(shell, "-c", sharedPipeInitScript)
	cmd.Args[0] = name
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s in %s: %v", name, cgroup, err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	return &sharedPipeInit{cmd: cmd, in: in, out: bufio.NewReader(out), path: cgroup, ino: st.Ino}
}

// run executes line inside the init and returns its stdout and exit status.
// It gives up when ctx ends (the init is killed at cleanup).
func (p *sharedPipeInit) run(ctx context.Context, line string) (string, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	type result struct {
		out  string
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		if _, err := io.WriteString(p.in, line+"\n"); err != nil {
			done <- result{err: err}
			return
		}
		var out strings.Builder
		for {
			l, err := p.out.ReadString('\n')
			if err != nil {
				done <- result{out: out.String(), err: fmt.Errorf("init output: %w", err)}
				return
			}
			var code int
			if _, scanErr := fmt.Sscanf(l, "@@done %d", &code); scanErr == nil {
				done <- result{out: strings.TrimSpace(out.String()), code: code}
				return
			}
			out.WriteString(l)
		}
	}()
	select {
	case r := <-done:
		return r.out, r.code, r.err
	case <-ctx.Done():
	}
	// Canceled: never leave a reader behind on the shared output (a later
	// run would read this command's "@@done"). Still holding p.mu, wait for
	// the command to finish; if it does not, kill the init so the reader
	// ends at EOF.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
	}
	return "", 0, ctx.Err()
}

// smoke returns the cgroup's verdicts for one exec as euid 0 and one as
// euid 1000, both forked and executed by the adopted init.
func (p *sharedPipeInit) smoke(t *testing.T, ctx context.Context) string {
	t.Helper()
	out, err := p.smokeE(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// smokeE is smoke returning its failure, so a caller can log diagnostics
// before failing.
func (p *sharedPipeInit) smokeE(ctx context.Context) (string, error) {
	out, code, err := p.run(ctx, `/bin/true; a=$?; setpriv --reuid=1000 --regid=1000 --clear-groups /bin/true; b=$?; echo "r0=$a r1000=$b"`)
	if err != nil || code != 0 {
		return out, fmt.Errorf("smoke in %s: %q code %d: %w", p.path, out, code, err)
	}
	return out, nil
}

// stop ends the init: its stdin closes (the read loop ends), then it is
// killed and reaped, so its TASK settles.
func (p *sharedPipeInit) stop() {
	_ = p.in.Close()
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

func (p *sharedPipeInit) acquire(context.Context) (BindingLease, error) {
	pid := p.cmd.Process.Pid
	l := &sharedM2Lease{}
	var err error
	open := func(path string, flags int) *os.File {
		f, e := os.OpenFile(path, flags, 0)
		err = errors.Join(err, e)
		return f
	}
	l.proc = open(fmt.Sprintf("/proc/%d", pid), unix.O_DIRECTORY|unix.O_RDONLY)
	l.cgroup = open(p.path, unix.O_DIRECTORY|unix.O_RDONLY)
	l.mount = open(fmt.Sprintf("/proc/%d/ns/mnt", pid), unix.O_RDONLY)
	l.hostMount = open("/proc/self/ns/mnt", unix.O_RDONLY)
	return l, err
}

// sharedM4Policy is the M2/M3 test policy as an authored fullpolicy.Policy:
// root role "app", fallback deny, one rule allowing euid 0 (M3's Strict A),
// or fallback allow.
func sharedM4Policy(id, revision string, mode fullpolicy.Mode, fallback fullpolicy.Action) *fullpolicy.Policy {
	return &fullpolicy.Policy{
		ID: id, Revision: revision, Mode: mode, RootRole: "app", Default: fallback,
		Rules: []fullpolicy.Rule{{Name: "root", Action: fullpolicy.Allow, Actor: fullpolicy.Actor{UID: []int64{0}}}},
	}
}

func mustRoute(t *testing.T, p SharedRoutePublisher, slot uint32) SharedRouteState {
	t.Helper()
	r, err := p.Route(slot)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
