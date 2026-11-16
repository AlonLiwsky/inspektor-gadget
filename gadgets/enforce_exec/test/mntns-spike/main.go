// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// This disposable-host experiment is independent of the production gadget.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type (
	config struct{ Mntns, Skip, Host uint32 }
	event  struct {
		Cgroup                                 uint64
		PID, Mntns, Expected, Mismatch, Denied uint32
		PathResult                             int32
		Userns                                 uint32
		Path                                   [256]byte
	}
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func run(args ...string) string {
	cmd := exec.Command(args[0], args[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		panic(fmt.Sprintf("%v: %v: %s", args, err, stderr.String()))
	}
	return strings.TrimSpace(string(out))
}

func inode(path string) uint64 {
	var st syscall.Stat_t
	must(syscall.Stat(path, &st))
	return st.Ino
}

func main() {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" || os.Geteuid() != 0 || len(os.Args) != 2 {
		panic("requires disposable host, root, IG_EXEC_KERNEL_TEST=1 and BPF object argument")
	}
	must(rlimit.RemoveMemlock())
	fmt.Println(run("uname", "-a"))
	fmt.Println(run("runc", "--version"))
	fmt.Println(run("docker", "version"))
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	must(err)
	coll, err := ebpf.NewCollection(spec)
	must(err)
	defer coll.Close()
	lnk, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["mntns_spike"]})
	must(err)
	defer lnk.Close()
	reader, err := ringbuf.NewReader(coll.Maps["events"])
	must(err)
	var mu sync.Mutex
	var events []event
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			rec, err := reader.Read()
			if err != nil {
				return
			}
			var e event
			must(binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e))
			mu.Lock()
			events = append(events, e)
			mu.Unlock()
			raw, _ := json.Marshal(map[string]interface{}{"pid": e.PID, "userns": e.Userns, "cgroup": e.Cgroup, "mntns": e.Mntns, "expected": e.Expected, "mismatch": e.Mismatch, "denied": e.Denied, "path_result": e.PathResult, "path": strings.SplitN(string(e.Path[:]), "\x00", 2)[0]})
			fmt.Println(string(raw))
		}
	}()
	defer func() { reader.Close(); wg.Wait() }()
	hostns := uint32(inode("/proc/1/ns/mnt"))
	if os.Getenv("IG_SPIKE_ADMISSION") == "1" {
		runAdmission(coll, hostns, func() []event { mu.Lock(); defer mu.Unlock(); return append([]event(nil), events...) })
		return
	}
	hostDir, err := os.MkdirTemp("/tmp", "ig-hostns-denied-")
	must(err)
	defer os.RemoveAll(hostDir)
	hostBinary := filepath.Join(hostDir, "true")
	executable, err := os.ReadFile("/usr/bin/true")
	must(err)
	must(os.WriteFile(hostBinary, executable, 0o755))
	for _, scenario := range []string{"normal", "privileged", "host-access"} {
		privileged := scenario != "normal"
		func() {
			args := []string{"docker", "run", "-d"}
			if privileged {
				args = append(args, "--privileged")
			}
			if scenario == "host-access" {
				args = append(args, "--pid=host")
			}
			args = append(args, "alpine:3.21", "sleep", "600")
			id := run(args...)
			defer func() { fmt.Println(run("docker", "rm", "-f", id)) }()
			run("docker", "exec", id, "cp", "/bin/busybox", "/tmp/busybox")
			run("docker", "exec", id, "cp", "/bin/busybox", "/runc")
			allowedPath := run("docker", "exec", id, "readlink", "-f", "/bin/true")
			if privileged {
				run("docker", "exec", id, "apk", "add", "--no-cache", "util-linux")
			}
			pid := run("docker", "inspect", "--format", "{{.State.Pid}}", id)
			data, err := os.ReadFile("/proc/" + pid + "/cgroup")
			must(err)
			cgpath := strings.TrimPrefix(strings.TrimSpace(string(data)), "0::")
			cgid := inode(filepath.Join("/sys/fs/cgroup", cgpath))
			ns := inode("/proc/" + pid + "/ns/mnt")
			fmt.Printf("TARGET scenario=%s privileged=%v pid=%s cgroup=%d mntns=%d host_mntns=%d\n", scenario, privileged, pid, cgid, ns, hostns)
			defer coll.Maps["targets"].Delete(cgid)
			for _, skip := range []uint32{0, 1, 2} {
				must(coll.Maps["targets"].Update(cgid, config{uint32(ns), skip, hostns}, ebpf.UpdateAny))
				for _, path := range []string{"/bin/true", "/tmp/busybox", "/runc"} {
					mu.Lock()
					start := len(events)
					mu.Unlock()
					argv := []string{"exec", id, path}
					if path != "/bin/true" {
						argv = append(argv, "echo", "workload-ran")
					}
					out, err := exec.Command("docker", argv...).CombinedOutput()
					time.Sleep(150 * time.Millisecond)
					fmt.Printf("CASE privileged=%v skip=%d path=%s error=%v output=%q\n", privileged, skip, path, err, out)
					if path == "/bin/true" {
						must(err)
					} else if err == nil {
						panic("denied workload executed")
					}
					mu.Lock()
					batch := append([]event(nil), events[start:]...)
					mu.Unlock()
					seen := false
					for _, e := range batch {
						p := strings.SplitN(string(e.Path[:]), "\x00", 2)[0]
						expectedPath := path
						if path == "/bin/true" {
							expectedPath = allowedPath
						}
						if p == expectedPath && e.Mismatch == 0 {
							seen = true
							if path != "/bin/true" && e.Denied != 1 {
								panic("workload not denied")
							}
						}
					}
					if !seen {
						panic("missing matching-namespace workload event")
					}
				}
			}
			if privileged {
				// An application can create another mount namespace without leaving its
				// cgroup. Demonstrate whether the proposed skip becomes a policy bypass.
				for _, skip := range []uint32{0, 1, 2} {
					must(coll.Maps["targets"].Update(cgid, config{uint32(ns), skip, hostns}, ebpf.UpdateAny))
					mu.Lock()
					start := len(events)
					mu.Unlock()
					out, err := exec.Command("docker", "exec", id, "unshare", "--mount", "/tmp/busybox", "echo", "namespace-bypass").CombinedOutput()
					time.Sleep(150 * time.Millisecond)
					fmt.Printf("UNSHARE skip=%d error=%v output=%q\n", skip, err, out)
					if skip != 1 && err == nil {
						panic("unshare unexpectedly bypassed baseline or host-only rule")
					}
					if skip == 1 && (err != nil || !strings.Contains(string(out), "namespace-bypass")) {
						panic("namespace bypass experiment did not reproduce")
					}
					mu.Lock()
					batch := append([]event(nil), events[start:]...)
					mu.Unlock()
					seen := false
					for _, e := range batch {
						if strings.SplitN(string(e.Path[:]), "\x00", 2)[0] == "/tmp/busybox" && e.Cgroup == cgid && e.Mntns != 0 && e.Mntns != uint32(ns) && e.Mntns != hostns {
							expectedDeny := uint32(1)
							if skip == 1 {
								expectedDeny = 0
							}
							if e.Denied != expectedDeny {
								panic("unexpected new-namespace workload verdict")
							}
							seen = true
						}
					}
					if !seen {
						panic("missing new-namespace workload verdict in original cgroup")
					}
				}
			}
			if scenario == "host-access" {
				for _, skip := range []uint32{0, 1, 2} {
					must(coll.Maps["targets"].Update(cgid, config{uint32(ns), skip, hostns}, ebpf.UpdateAny))
					mu.Lock()
					start := len(events)
					mu.Unlock()
					out, err := exec.Command("docker", "exec", id, "nsenter", "--mount=/proc/1/ns/mnt", "--root=/proc/1/root", hostBinary).CombinedOutput()
					time.Sleep(150 * time.Millisecond)
					fmt.Printf("HOST-ENTER skip=%d error=%v output=%q\n", skip, err, out)
					if skip == 0 && err == nil {
						panic("baseline host-namespace execution unexpectedly allowed")
					}
					if skip != 0 {
						must(err)
					}
					mu.Lock()
					batch := append([]event(nil), events[start:]...)
					mu.Unlock()
					found := false
					for _, e := range batch {
						if strings.SplitN(string(e.Path[:]), "\x00", 2)[0] == hostBinary && e.Mntns == hostns && e.Cgroup == cgid {
							expectedDeny := uint32(0)
							if skip == 0 {
								expectedDeny = 1
							}
							if e.Denied != expectedDeny {
								panic("unexpected host-namespace verdict")
							}
							found = true
						}
					}
					if !found {
						panic("missing host-namespace workload verdict in original cgroup")
					}
				}
				// A target configured in the host namespace must not inherit
				// the helper exception. This is a map-level guard test, not
				// a full shared-namespace container deployment test.
				must(coll.Maps["targets"].Update(cgid, config{hostns, 2, hostns}, ebpf.UpdateAny))
				mu.Lock()
				start := len(events)
				mu.Unlock()
				out, err := exec.Command("docker", "exec", id, "nsenter", "--mount=/proc/1/ns/mnt", "--root=/proc/1/root", hostBinary).CombinedOutput()
				time.Sleep(150 * time.Millisecond)
				fmt.Printf("HOST-TARGET-GUARD error=%v output=%q\n", err, out)
				if err == nil {
					panic("host-target guard failed")
				}
				mu.Lock()
				batch := append([]event(nil), events[start:]...)
				mu.Unlock()
				seen := false
				for _, e := range batch {
					if strings.SplitN(string(e.Path[:]), "\x00", 2)[0] == hostBinary && e.Mntns == hostns && e.Denied == 1 && e.Mismatch == 0 {
						seen = true
					}
				}
				if !seen {
					panic("missing host-target guard verdict")
				}
			}
			must(coll.Maps["targets"].Delete(cgid))
			fmt.Println("RELEASE", strconv.FormatBool(privileged), run("docker", "exec", id, "/tmp/busybox", "echo", "released"))
		}()
	}
	fmt.Println("PASS: host-only rule blocks new-namespace bypass; host-namespace entry bypass reproduced")
}
