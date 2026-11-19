/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Process-topology prerequisite for the recovered physical admin. This does
 * not run BPF or confer authority; S is deliberately its own process/waiter. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "shared_recovery_abi.h"

#define RECOVERY_CLONE_FLAGS (CLONE_PARENT | SIGCHLD)
_Static_assert(RECOVERY_CLONE_FLAGS == 0x8011, "recovery clone flags changed");

enum {
	GUARDIAN = 1,
	CANDIDATE = 2,
	CLONE_RESULT = 3,
	FD_SIGNAL_RESULT = 4,
	REGISTER_RESULT = 5,
	ARM_RESULT = 6,
	READY_RESULT = 7,
	COMMIT_RESULT = 8,
	REAP_RESULT = 9,
	CAPTURE_RESULT = 10
};
enum {
	G_PROGRAM_FD = 3,
	A_PROGRAM_FD,
	G_REQUEST_FD,
	A_REQUEST_FD,
	CONTROL_FD,
	G_RECEIPT_FD,
	A_RECEIPT_FD,
	TARGET_PROC_FD,
	CONSUMED_FD,
	REAPER_PROGRAM_FD
};
struct record {
	int32_t role, pid, ppid, sid, pgid, child;
};
static int guardian_pid, candidate_pid, session_id;
static int live, live_reap, live_churn, live_swap, live_exit;
static int guardian_command[2], candidate_command[2], records[2], rights[2];

static void deadline(int signal)
{
	(void)signal;
	if (session_id > 0)
		(void)syscall(SYS_kill, -session_id, SIGKILL);
	else if (guardian_pid > 0)
		(void)syscall(SYS_kill, guardian_pid, SIGKILL);
	syscall(SYS_exit, 124);
}

static void die(const char *message)
{
	fprintf(stderr, "topology: %s: %s\n", message, strerror(errno));
	if (session_id > 0 && session_id != getpgrp())
		(void)kill(-session_id, SIGKILL);
	if (candidate_pid > 0)
		(void)kill(candidate_pid, SIGKILL);
	if (guardian_pid > 0)
		(void)kill(guardian_pid, SIGKILL);
	while (waitpid(-1, NULL, 0) > 0) {
	}
	exit(1);
}
static void exact_read(int fd, void *value, size_t size)
{
	char *bytes = value;
	while (size) {
		ssize_t n = read(fd, bytes, size);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			die("short record/command read");
		bytes += n;
		size -= (size_t)n;
	}
}
static void exact_write(int fd, const void *value, size_t size)
{
	const char *bytes = value;
	while (size) {
		ssize_t n = write(fd, bytes, size);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			die("short record/command write");
		bytes += n;
		size -= (size_t)n;
	}
}
static struct record self_record(int role, int child)
{
	return (struct record){ role,	   getpid(),   getppid(),
				getsid(0), getpgid(0), child };
}
static int receive_proc_fd(void)
{
	char data = 0;
	struct iovec io = { .iov_base = &data, .iov_len = 1 };
	union {
		struct cmsghdr align;
		char bytes[CMSG_SPACE(sizeof(int))];
	} ancillary = {};
	struct msghdr msg = {
		.msg_iov = &io,
		.msg_iovlen = 1,
		.msg_control = ancillary.bytes,
		.msg_controllen = sizeof(ancillary.bytes),
	};
	if (syscall(SYS_recvmsg, rights[1], &msg, MSG_CMSG_CLOEXEC) != 1 ||
	    data != 'P' || msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
		return -1;
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(int)) || CMSG_NXTHDR(&msg, cmsg))
		return -1;
	int fd;
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return fd;
}
static void send_proc_fd(int socket, int fd)
{
	char data = 'P';
	struct iovec io = { .iov_base = &data, .iov_len = 1 };
	union {
		struct cmsghdr align;
		char bytes[CMSG_SPACE(sizeof(int))];
	} ancillary = {};
	struct msghdr msg = {
		.msg_iov = &io,
		.msg_iovlen = 1,
		.msg_control = ancillary.bytes,
		.msg_controllen = sizeof(ancillary.bytes),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	if (sendmsg(socket, &msg, 0) != 1)
		die("proc FD handoff");
}
static void map_write(int fd, const void *value)
{
	__u32 key = 0;
	union bpf_attr attr = {
		.map_fd = (__u32)fd,
		.key = (__u64)(uintptr_t)&key,
		.value = (__u64)(uintptr_t)value,
		.flags = BPF_ANY,
	};
	if (syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)))
		die("live request update");
}
static void map_read(int fd, void *value)
{
	__u32 key = 0;
	union bpf_attr attr = {
		.map_fd = (__u32)fd,
		.key = (__u64)(uintptr_t)&key,
		.value = (__u64)(uintptr_t)value,
	};
	if (syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)))
		die("live receipt/control lookup");
}
static void test_run(int fd)
{
	/* A single inert Ethernet frame is enough for a TC TEST_RUN. The
	 * endpoint uses only bpf_get_current_task(), never packet contents. */
	unsigned char frame[14] = {};
	unsigned char output[14] = {};
	union bpf_attr attr = {
		.test.prog_fd = (__u32)fd,
		.test.data_size_in = sizeof(frame),
		.test.data_size_out = sizeof(output),
		.test.data_in = (__u64)(uintptr_t)frame,
		.test.data_out = (__u64)(uintptr_t)output,
		.test.repeat = 1,
	};
	if (syscall(SYS_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr)))
		die("live TEST_RUN");
}
static void guardian_step(__u32 operation, __u64 sequence, __u64 epoch)
{
	struct rm_grequest request = {
		.incarnation = 11,
		.nonce = 13,
		.sequence = sequence,
		.recovery_epoch = epoch,
		.operation = operation,
	};
	map_write(G_REQUEST_FD, &request);
	test_run(G_PROGRAM_FD);
}
static void admin_ready(void)
{
	struct rm_arequest request = {
		.incarnation = 11,
		.generation = 1,
		.sequence = 1,
		.recovery_epoch = 1,
		.operation = RM_A_READY,
	};
	map_write(A_REQUEST_FD, &request);
	test_run(A_PROGRAM_FD);
}
static void require_step(int receipt_fd, __u32 operation, __u64 sequence,
			 __u32 phase, __u64 physical)
{
	struct rm_receipt receipt = {};
	struct rm_control control = {};
	map_read(receipt_fd, &receipt);
	map_read(CONTROL_FD, &control);
	if (receipt.operation != operation ||
	    receipt.attempted_sequence != sequence ||
	    receipt.status != RM_ACCEPT ||
	    receipt.observed_physical_task == 0 ||
	    (physical && receipt.observed_physical_task != physical) ||
	    receipt.recovery_phase != phase ||
	    control.recovery_phase != phase ||
	    (phase == RM_COMMITTED &&
	     (control.admin_task != receipt.candidate_task ||
	      control.admin_generation != 1))) {
		fprintf(stderr,
			"step=%u seq=%llu phase=%u receipt={op=%u seq=%llu status=%u physical=%llx phase=%u candidate=%llx} control={phase=%u guardian=%llx admin=%llx generation=%llu candidate=%llx}\n",
			operation, (unsigned long long)sequence, phase,
			receipt.operation,
			(unsigned long long)receipt.attempted_sequence,
			receipt.status,
			(unsigned long long)receipt.observed_physical_task,
			receipt.recovery_phase,
			(unsigned long long)receipt.candidate_task,
			control.recovery_phase,
			(unsigned long long)control.guardian_task,
			(unsigned long long)control.admin_task,
			(unsigned long long)control.admin_generation,
			(unsigned long long)control.candidate_task);
		errno = EPROTO;
		die("live recovered transition mismatch");
	}
}
static void candidate(void)
{
	(void)close(guardian_command[0]);
	struct record r = {
		.role = CANDIDATE,
		.pid = (int32_t)syscall(SYS_getpid),
		.ppid = (int32_t)syscall(SYS_getppid),
		.sid = (int32_t)syscall(SYS_getsid, 0),
		.pgid = (int32_t)syscall(SYS_getpgid, 0),
	};
	if (syscall(SYS_write, records[1], &r, sizeof(r)) != sizeof(r))
		syscall(SYS_exit, 91);
	if (live) {
		char command;
		if (syscall(SYS_read, candidate_command[0], &command, 1) != 1 ||
		    command != 'R')
			syscall(SYS_exit, 95);
		admin_ready();
		r.role = READY_RESULT;
		if (syscall(SYS_write, records[1], &r, sizeof(r)) != sizeof(r))
			syscall(SYS_exit, 96);
	}
	int proc_fd = receive_proc_fd();
	if (proc_fd < 0 || syscall(SYS_pidfd_send_signal, proc_fd, 0, NULL, 0))
		syscall(SYS_exit, 93);
	if (live_swap || live_exit) {
		r.role = CAPTURE_RESULT;
		if (syscall(SYS_write, records[1], &r, sizeof(r)) != sizeof(r))
			syscall(SYS_exit, 94);
		char proceed;
		if (syscall(SYS_read, candidate_command[0], &proceed, 1) != 1 ||
		    proceed != 'S')
			syscall(SYS_exit, 95);
		if (!syscall(SYS_pidfd_send_signal, proc_fd, 0, NULL, 0) ||
		    errno != (live_exit ? ESRCH : EPERM))
			syscall(SYS_exit, 93);
	} else if (live &&
		   syscall(SYS_pidfd_send_signal, proc_fd, 0, NULL, 0)) {
		syscall(SYS_exit, 93);
	}
	(void)syscall(SYS_close, proc_fd);
	(void)syscall(SYS_close, rights[1]);
	r.role = FD_SIGNAL_RESULT;
	r.child = live_exit ? ESRCH : live_swap ? EPERM : 0;
	if (syscall(SYS_write, records[1], &r, sizeof(r)) != sizeof(r))
		syscall(SYS_exit, 94);
	char command;
	if (live_reap || live_churn) {
		for (;;) {
			if (syscall(SYS_read, candidate_command[0], &command,
				    1) != 1)
				syscall(SYS_exit, 97);
			if (command == 'X')
				break;
			if (command != 'P')
				syscall(SYS_exit, 97);
			test_run(REAPER_PROGRAM_FD);
			r.role = REAP_RESULT;
			if (syscall(SYS_write, records[1], &r, sizeof(r)) !=
			    sizeof(r))
				syscall(SYS_exit, 98);
		}
	} else {
		if (syscall(SYS_read, candidate_command[0], &command, 1) != 1 ||
		    command != 'X')
			syscall(SYS_exit, 92);
	}
	syscall(SYS_exit, 0);
	__builtin_unreachable();
}
static void guardian(void)
{
	(void)close(records[0]);
	(void)close(rights[0]);
	/* S alone retains the held target descriptor. A receives it only after
	 * COMMIT through SCM_RIGHTS, never by inheritance from G. */
	if (live)
		(void)close(TARGET_PROC_FD);
	(void)close(guardian_command[1]);
	(void)close(candidate_command[1]);
	if (setsid() != getpid())
		die("guardian setsid");
	struct record r = self_record(GUARDIAN, 0);
	exact_write(records[1], &r, sizeof(r));
	char command;
	if (live) {
		exact_read(guardian_command[0], &command, 1);
		if (command != 'R')
			die("guardian register command");
		guardian_step(RM_REGISTER, 1, 0);
		r = self_record(REGISTER_RESULT, 0);
		exact_write(records[1], &r, sizeof(r));
		exact_read(guardian_command[0], &command, 1);
		if (command != 'A')
			die("guardian arm command");
		guardian_step(RM_ARM, 2, 0);
		r.role = ARM_RESULT;
		exact_write(records[1], &r, sizeof(r));
	}
	exact_read(guardian_command[0], &command, 1);
	if (command != 'S')
		die("guardian start command");
	long child =
		syscall(SYS_clone, RECOVERY_CLONE_FLAGS, NULL, NULL, NULL, 0);
	if (child < 0)
		die("raw CLONE_PARENT candidate");
	if (child == 0)
		candidate();
	(void)close(rights[1]);
	(void)close(candidate_command[0]);
	r = self_record(CLONE_RESULT, (int)child);
	exact_write(records[1], &r, sizeof(r));
	if (live) {
		exact_read(guardian_command[0], &command, 1);
		if (command != 'C')
			die("guardian commit command");
		guardian_step(RM_COMMIT, 3, 1);
		r.role = COMMIT_RESULT;
		exact_write(records[1], &r, sizeof(r));
	}
	exact_read(guardian_command[0], &command, 1);
	if (command != 'X')
		die("guardian stop command");
	_exit(0);
}
static void require_record(struct record r, int role, int parent, int sid,
			   int pgid)
{
	if (r.role != role || r.pid <= 0 || r.ppid != parent || r.sid != sid ||
	    r.pgid != pgid) {
		errno = EPROTO;
		die("wrong kernel-reported process relationship");
	}
}
static void reap_exact(int pid, int expected_code, int expected_signal)
{
	siginfo_t info = {};
	if (waitid(P_PID, (id_t)pid, &info, WEXITED | WNOWAIT) ||
	    info.si_pid != pid ||
	    (expected_signal ? info.si_code != CLD_KILLED ||
				       info.si_status != expected_signal :
			       info.si_code != CLD_EXITED ||
				       info.si_status != expected_code)) {
		errno = EPROTO;
		die("wrong WNOWAIT terminal record");
	}
	int status;
	if (waitpid(pid, &status, 0) != pid ||
	    (expected_signal ? !WIFSIGNALED(status) ||
				       WTERMSIG(status) != expected_signal :
			       !WIFEXITED(status) ||
				       WEXITSTATUS(status) != expected_code)) {
		errno = EPROTO;
		die("wrong exact child reap");
	}
}
int main(int argc, char **argv)
{
	if (argc != 2 ||
	    (strcmp(argv[1], "normal") && strcmp(argv[1], "guardian-death") &&
	     strcmp(argv[1], "bad-fd") && strcmp(argv[1], "live") &&
	     strcmp(argv[1], "live-reap") && strcmp(argv[1], "live-churn") &&
	     strcmp(argv[1], "live-swap") && strcmp(argv[1], "live-exit")))
		return 90;
	live_reap = !strcmp(argv[1], "live-reap");
	live_churn = !strcmp(argv[1], "live-churn");
	live_swap = !strcmp(argv[1], "live-swap");
	live_exit = !strcmp(argv[1], "live-exit");
	live = !strcmp(argv[1], "live") || live_reap || live_churn ||
	       live_swap || live_exit;
	int subreaper = -1;
	if (prctl(PR_GET_CHILD_SUBREAPER, &subreaper) || subreaper != 0)
		die("S must not be a subreaper");
	struct sigaction action = { .sa_handler = SIG_DFL };
	if (sigaction(SIGCHLD, &action, NULL))
		die("S SIGCHLD default");
	if (pipe(records) || pipe(guardian_command) ||
	    pipe(candidate_command) ||
	    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, rights))
		die("pipes/socketpair");
	struct sigaction timer = { .sa_handler = deadline };
	if (sigaction(SIGALRM, &timer, NULL))
		die("deadline handler");
	int supervisor = getpid();
	guardian_pid = fork();
	if (guardian_pid < 0)
		die("fork guardian");
	if (guardian_pid == 0)
		guardian();
	alarm(live_churn ? 900 : live_swap || live_exit ? 30 : 10);
	(void)close(records[1]);
	(void)close(rights[1]);
	(void)close(guardian_command[0]);
	(void)close(candidate_command[0]);
	struct record g;
	exact_read(records[0], &g, sizeof(g));
	require_record(g, GUARDIAN, supervisor, guardian_pid, guardian_pid);
	if (g.pid != guardian_pid || getpgid(guardian_pid) != guardian_pid ||
	    getsid(guardian_pid) != guardian_pid)
		die("G not direct session/group leader");
	session_id = guardian_pid;
	if (live) {
		struct record event;
		exact_write(guardian_command[1], "R", 1);
		exact_read(records[0], &event, sizeof(event));
		require_record(event, REGISTER_RESULT, supervisor, session_id,
			       session_id);
		require_step(G_RECEIPT_FD, RM_REGISTER, 1, RM_IDLE, 0);
		exact_write(guardian_command[1], "A", 1);
		exact_read(records[0], &event, sizeof(event));
		require_record(event, ARM_RESULT, supervisor, session_id,
			       session_id);
		require_step(G_RECEIPT_FD, RM_ARM, 2, RM_ARMED, 0);
	}
	exact_write(guardian_command[1], "S", 1);
	struct record first, second, a, clone;
	exact_read(records[0], &first, sizeof(first));
	exact_read(records[0], &second, sizeof(second));
	if (first.role == CANDIDATE && second.role == CLONE_RESULT)
		a = first, clone = second;
	else if (second.role == CANDIDATE && first.role == CLONE_RESULT)
		a = second, clone = first;
	else {
		errno = EPROTO;
		die("missing A/clone records");
	}
	require_record(a, CANDIDATE, supervisor, session_id, session_id);
	require_record(clone, CLONE_RESULT, supervisor, session_id, session_id);
	candidate_pid = a.pid;
	if (clone.pid != guardian_pid || clone.child != candidate_pid ||
	    getpgid(candidate_pid) != session_id ||
	    getsid(candidate_pid) != session_id)
		die("A not exact direct S child in G group");
	siginfo_t pending = {};
	if (waitid(P_ALL, 0, &pending, WEXITED | WNOHANG | WNOWAIT) ||
	    pending.si_pid)
		die("unexpected exited S child before release");
	if (live) {
		struct record event;
		exact_write(candidate_command[1], "R", 1);
		exact_read(records[0], &event, sizeof(event));
		require_record(event, READY_RESULT, supervisor, session_id,
			       session_id);
		struct rm_control control = {};
		map_read(CONTROL_FD, &control);
		require_step(A_RECEIPT_FD, RM_A_READY, 1, RM_READY,
			     control.candidate_task);
		exact_write(guardian_command[1], "C", 1);
		exact_read(records[0], &event, sizeof(event));
		require_record(event, COMMIT_RESULT, supervisor, session_id,
			       session_id);
		require_step(G_RECEIPT_FD, RM_COMMIT, 3, RM_COMMITTED,
			     control.guardian_task);
		/* The same exact target FD must not authorize S, whose physical
		 * task is not the committed A. The one-shot remains unconsumed. */
		if (syscall(SYS_pidfd_send_signal, TARGET_PROC_FD, 0, NULL, 0))
			die("S wrong-sender zero signal");
		__u32 consumed = 1;
		map_read(CONSUMED_FD, &consumed);
		if (consumed) {
			errno = EPROTO;
			die("wrong physical sender consumed witness");
		}
	}
	/* Open after G has closed its socket endpoint and after A is verified.
	 * Neither child inherited this descriptor; only S can pass it to A. */
	int bad_fd = !strcmp(argv[1], "bad-fd");
	int proc_fd =
		live ? TARGET_PROC_FD :
		       open(bad_fd ? "/dev/null" : "/proc/self",
			    O_RDONLY | O_CLOEXEC | (bad_fd ? 0 : O_DIRECTORY));
	if (proc_fd < 0)
		die("S proc pin");
	send_proc_fd(rights[0], proc_fd);
	(void)close(proc_fd);
	(void)close(rights[0]);
	if (live_swap || live_exit) {
		struct record captured;
		exact_read(records[0], &captured, sizeof(captured));
		require_record(captured, CAPTURE_RESULT, supervisor, session_id,
			       session_id);
		if (captured.pid != candidate_pid)
			die("wrong physical capture sender");
		printf("CAPTURED %d\n", guardian_pid);
		fflush(stdout);
		char proceed;
		exact_read(STDIN_FILENO, &proceed, 1);
		if (proceed != 'S')
			die("invalid swap continuation");
		exact_write(candidate_command[1], "S", 1);
	}
	if (bad_fd) {
		/* A must fail on the actual transferred descriptor. There is no
		 * numeric-PID fallback, ACK, or inferred successful witness. */
		reap_exact(candidate_pid, 93, 0);
		exact_write(guardian_command[1], "X", 1);
		reap_exact(guardian_pid, 0, 0);
		goto joined;
	}
	struct record used_fd;
	exact_read(records[0], &used_fd, sizeof(used_fd));
	require_record(used_fd, FD_SIGNAL_RESULT, supervisor, session_id,
		       session_id);
	if (used_fd.pid != candidate_pid ||
	    used_fd.child != (live_exit ? ESRCH :
			      live_swap ? EPERM :
					  0))
		die("A did not use transferred proc FD");
	if (live_swap || live_exit) {
		puts(live_exit ? "EXIT_DENIED" : "SWAP_DENIED");
		fflush(stdout);
	}
	if (live_reap || live_churn) {
		printf("ENROLLED %d\n", guardian_pid);
		fflush(stdout);
		char command;
		if (live_reap) {
			exact_read(STDIN_FILENO, &command, 1);
			if (command != 'D')
				die("reap requires confirmed target death");
		}
		for (;;) {
			exact_read(STDIN_FILENO, &command, 1);
			if (command == 'X')
				break;
			if (command != 'P')
				die("invalid reap step command");
			exact_write(candidate_command[1], "P", 1);
			struct record reaped;
			exact_read(records[0], &reaped, sizeof(reaped));
			require_record(reaped, REAP_RESULT, supervisor,
				       session_id, session_id);
			if (reaped.pid != candidate_pid)
				die("wrong physical reaper");
			puts("REAP_STEP");
			fflush(stdout);
		}
		exact_write(candidate_command[1], "X", 1);
		reap_exact(candidate_pid, 0, 0);
		exact_write(guardian_command[1], "X", 1);
		reap_exact(guardian_pid, 0, 0);
	} else if (!strcmp(argv[1], "normal") || live_swap || live_exit) {
		exact_write(candidate_command[1], "X", 1);
		reap_exact(candidate_pid, 0, 0);
		exact_write(guardian_command[1], "X", 1);
		reap_exact(guardian_pid, 0, 0);
	} else {
		exact_write(guardian_command[1], "X", 1);
		/* G remains a waitable zombie, reserving the exact PGID while S
		 * performs one final group containment of A. */
		siginfo_t info = {};
		if (waitid(P_PID, (id_t)guardian_pid, &info,
			   WEXITED | WNOWAIT) ||
		    info.si_pid != guardian_pid || info.si_code != CLD_EXITED)
			die("G WNOWAIT reservation");
		if (kill(-session_id, SIGTERM))
			die("reserved PGID containment");
		reap_exact(candidate_pid, 0, SIGTERM);
		reap_exact(guardian_pid, 0, 0);
	}
joined:
	pending = (siginfo_t){};
	if (waitid(P_ALL, 0, &pending, WEXITED | WNOHANG | WNOWAIT) != -1 ||
	    errno != ECHILD)
		die("unexplained S child after exact reaps");
	alarm(0);
	printf("topology PASS mode=%s S=%d G=%d A=%d flags=%#x proc_fd_signal=%s\n",
	       argv[1], supervisor, guardian_pid, candidate_pid,
	       RECOVERY_CLONE_FLAGS,
	       bad_fd	 ? "refused" :
	       live_exit ? "ESRCH" :
	       live_swap ? "EPERM" :
			   "0");
	return 0;
}
