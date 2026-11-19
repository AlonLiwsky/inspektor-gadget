// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

// runAdmission isolates capability checks from default seccomp/AppArmor profiles.
// It is an experiment, not a production admission implementation.
func runAdmission(coll *ebpf.Collection, hostns uint32, snapshot func() []event) {
	helper := os.Getenv("IG_SPIKE_CAP_HELPER")
	if helper == "" {
		panic("IG_SPIKE_CAP_HELPER must name the static capability fixture")
	}
	// Hand the already-open namespace FD to the fixture over SCM_RIGHTS.
	// This isolates setns permission from procfs access and mount plumbing.
	dir, err := os.MkdirTemp("/root", "ig-admission-")
	must(err)
	defer os.RemoveAll(dir)
	must(os.Chmod(dir, 0o755))
	namespace, err := os.Open("/proc/1/ns/mnt")
	must(err)
	defer namespace.Close()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "ns.sock"), Net: "unix"})
	must(err)
	must(os.Chmod(filepath.Join(dir, "ns.sock"), 0o666))
	var server sync.WaitGroup
	server.Add(1)
	go func() {
		defer server.Done()
		for {
			connection, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			_, _, err = connection.WriteMsgUnix([]byte{1}, syscall.UnixRights(int(namespace.Fd())), nil)
			connection.Close()
			must(err)
		}
	}()
	defer func() { listener.Close(); server.Wait() }()
	// Build once; tests never install packages while enforcing or weaken policy to do so.
	build := run("docker", "run", "-d", "alpine:3.21", "sleep", "600")
	defer func() { run("docker", "rm", "-f", build) }()
	run("docker", "exec", build, "apk", "add", "--no-cache", "util-linux")
	image := "ig-admission-spike:" + fmt.Sprint(os.Getpid())
	run("docker", "commit", build, image)
	defer func() { run("docker", "image", "rm", image) }()
	hostUser := uint32(inode("/proc/1/ns/user"))
	fmt.Printf("ADMISSION host_mntns=%d host_userns=%d seccomp=unconfined apparmor=unconfined\n", hostns, hostUser)
	for _, name := range []string{"default-caps-fd", "no-admin-hostpid", "no-admin-fd", "admin-hostpid-ptrace", "admin-fd", "effective-only", "privileged-exec", "child-userns"} {
		func() {
			hasAdmin := name == "admin-hostpid-ptrace" || name == "admin-fd" || name == "effective-only"
			args := []string{"docker", "run", "-d", "--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined", "--security-opt", "no-new-privileges:true"}
			if name != "default-caps-fd" {
				args = append(args, "--cap-drop=ALL", "--cap-add=SYS_CHROOT")
			}
			if hasAdmin {
				args = append(args, "--cap-add=SYS_ADMIN")
			}
			if name == "admin-hostpid-ptrace" {
				args = append(args, "--cap-add=SYS_PTRACE")
			}
			nsfile := "/unused"
			if strings.Contains(name, "hostpid") {
				args = append(args, "--pid=host")
				nsfile = "/proc/1/ns/mnt"
			} else {
				args = append(args, "--mount", "type=bind,src="+dir+",dst=/handoff,readonly")
			}
			if name == "child-userns" {
				args = append(args, "--user=1000:1000")
			}
			args = append(args, image, "sleep", "600")
			id := run(args...)
			defer func() { run("docker", "rm", "-f", id) }()
			run("docker", "cp", helper, id+":/tmp/busybox")
			run("docker", "cp", helper, id+":/usr/bin/capability-helper")
			pid := run("docker", "inspect", "--format", "{{.State.Pid}}", id)
			data, err := os.ReadFile("/proc/" + pid + "/cgroup")
			must(err)
			cgid := inode(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(strings.TrimSpace(string(data)), "0::")))
			ns := uint32(inode("/proc/" + pid + "/ns/mnt"))
			must(coll.Maps["targets"].Update(cgid, config{ns, 2, hostns}, ebpf.UpdateAny))
			defer coll.Maps["targets"].Delete(cgid)
			fmt.Printf("PROFILE %s cgroup=%d mntns=%d userns=%d\n", name, cgid, ns, inode("/proc/"+pid+"/ns/user"))
			status, err := os.ReadFile("/proc/" + pid + "/status")
			must(err)
			for _, l := range strings.Split(string(status), "\n") {
				if strings.HasPrefix(l, "Cap") || strings.HasPrefix(l, "NoNewPrivs:") {
					fmt.Println(l)
					fields := strings.Fields(l)
					if len(fields) == 2 && strings.HasPrefix(l, "Cap") {
						var bits uint64
						_, err := fmt.Sscanf(fields[1], "%x", &bits)
						must(err)
						if !hasAdmin && bits&(1<<21) != 0 {
							panic("restricted init retains SYS_ADMIN in a capability set")
						}
					}
					if strings.HasPrefix(l, "NoNewPrivs:") && (len(fields) != 2 || fields[1] != "1") {
						panic("no_new_privs missing")
					}
				}
			}
			// Baseline must reach and deny the copied workload, not just a helper.
			start := len(snapshot())
			out, execErr := exec.Command("docker", "exec", id, "/tmp/busybox", "echo", "baseline").CombinedOutput()
			time.Sleep(150 * time.Millisecond)
			if execErr == nil {
				panic("baseline workload ran")
			}
			found := false
			for _, e := range snapshot()[start:] {
				if eventPath(e) == "/tmp/busybox" && e.Cgroup == cgid && e.Mntns == ns && e.Denied == 1 {
					found = true
				}
			}
			if !found {
				panic(fmt.Sprintf("baseline missing workload verdict: %s", out))
			}
			argv := []string{"exec", id, "/usr/bin/capability-helper", "receive", "/tmp/busybox", "echo", "host-entered"}
			if strings.Contains(name, "hostpid") {
				argv = []string{"exec", id, "nsenter", "--mount=" + nsfile, "--root=/proc/self/root", "/tmp/busybox", "echo", "host-entered"}
			}
			if name == "privileged-exec" {
				argv = append([]string{"exec", "--privileged"}, argv[1:]...)
			}
			if name == "effective-only" {
				argv = []string{"exec", id, "/usr/bin/capability-helper", "clear-effective", "/usr/bin/capability-helper", "receive", "/tmp/busybox", "echo", "host-entered"}
			}
			if name == "child-userns" {
				argv = []string{"exec", id, "unshare", "--user", "--map-root-user", "--mount", "/usr/bin/capability-helper", "receive", "/tmp/busybox", "echo", "host-entered"}
			}
			start = len(snapshot())
			out, execErr = exec.Command("docker", argv...).CombinedOutput()
			time.Sleep(150 * time.Millisecond)
			fmt.Printf("ATTEMPT %s error=%v output=%q\n", name, execErr, out)
			found = false
			for _, e := range snapshot()[start:] {
				if eventPath(e) == "/tmp/busybox" && e.Cgroup == cgid && e.Mntns == hostns && e.Denied == 0 {
					found = true
				}
			}
			if hasAdmin {
				if execErr != nil || !strings.Contains(string(out), "host-entered") || !found {
					panic("host-entry positive control did not bypass")
				}
				if name == "effective-only" && !strings.Contains(string(out), "CLEARED_EFFECTIVE") {
					panic("effective clearing fixture did not run")
				}
			} else if name == "privileged-exec" {
				if execErr == nil {
					if !found || !strings.Contains(string(out), "host-entered") {
						panic("privileged exec succeeded without matching workload verdict")
					}
					fmt.Println("PRIVILEGED-EXEC: runtime granted host entry despite restricted init")
				} else {
					if found {
						panic("host workload ran despite privileged exec error")
					}
					fmt.Println("PRIVILEGED-EXEC: request failed; no claim that init admission covers all runtimes")
				}
			} else {
				if execErr == nil || strings.Contains(string(out), "host-entered") || found {
					panic("no-admin profile entered host namespace")
				}
				if strings.Contains(name, "hostpid") {
					if !strings.Contains(string(out), "nsenter:") || (!strings.Contains(string(out), "Permission denied") && !strings.Contains(string(out), "Operation not permitted")) {
						panic("hostpid attempt failed for unrelated reason")
					}
				} else {
					if !strings.Contains(string(out), "RECEIVED_HOST_NAMESPACE_FD") || !strings.Contains(string(out), "SETNS_FAILED errno=1 ") {
						panic("FD test did not reach a kernel setns rejection")
					}
				}
			}
			if name == "child-userns" {
				childHelper := false
				for _, e := range snapshot()[start:] {
					if eventPath(e) == "/usr/bin/capability-helper" && e.Cgroup == cgid && e.Mntns != 0 && e.Mntns != ns && e.Mntns != hostns && e.Userns != 0 && e.Userns != hostUser {
						childHelper = true
					}
				}
				if !childHelper {
					panic("host-entry rejection did not occur in child namespaces")
				}
				// Require successful child namespace creation and an actual denied workload
				// there. A sysctl/seccomp denial of unshare is not evidence for our boundary.
				start = len(snapshot())
				out, execErr = exec.Command("docker", "exec", id, "unshare", "--user", "--map-root-user", "--mount", "/tmp/busybox", "echo", "child-ran").CombinedOutput()
				time.Sleep(150 * time.Millisecond)
				fmt.Printf("CHILD-EXEC error=%v output=%q\n", execErr, out)
				found = false
				for _, e := range snapshot()[start:] {
					if eventPath(e) == "/tmp/busybox" && e.Cgroup == cgid && e.Mntns != ns && e.Mntns != hostns && e.Userns != hostUser && e.Userns != 0 && e.Denied == 1 {
						found = true
					}
				}
				if execErr == nil || !found {
					panic("child namespace control did not reach denied workload")
				}
			}
			must(coll.Maps["targets"].Delete(cgid))
			if !strings.Contains(run("docker", "exec", id, "/tmp/busybox", "echo", "released"), "released") {
				panic("binding not released")
			}
			fmt.Println("PASS PROFILE", name)
		}()
	}
	fmt.Println("PASS ADMISSION: capability-boundary matrix completed")
}

func eventPath(e event) string { return strings.SplitN(string(e.Path[:]), "\x00", 2)[0] }
