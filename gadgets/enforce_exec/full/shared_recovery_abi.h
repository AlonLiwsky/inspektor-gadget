#ifndef ENFORCE_EXEC_SHARED_RECOVERY_ABI_H
#define ENFORCE_EXEC_SHARED_RECOVERY_ABI_H
/* Reviewed G005 wire ABI. vmlinux.h supplies fixed-width types and spinlock. */
#define RM_MAX ((__u64)~0ULL)
#define RM_U64(v) v##ULL
#define RM_ABI 2u
#define RM_CLONE_FLAGS RM_U64(0x8011)
/* Newer kernel_clone separates exit_signal from flags before task_alloc;
 * older copy_process passes the legacy combined clone word to the hook. */
#define RM_LSM_CLONE_FLAGS_NO_SIGNAL RM_U64(0x8000)
#define RM_PREHOOK_INVALID_FLAGS RM_U64(0x8811)
#define RM_LAST (RM_MAX - 1)
enum rm_guardian_phase {
	RM_G_UNREGISTERED = 0,
	RM_G_ALIVE = 1,
	RM_G_CLOSED = 2
};
enum rm_admin_phase { RM_A_EMPTY = 0, RM_A_ALIVE = 1, RM_A_CLOSED = 2 };
enum rm_recovery_phase {
	RM_IDLE = 0,
	RM_ARMED = 1,
	RM_CAPTURED = 2,
	RM_READY = 3,
	RM_DEAD = 4,
	RM_CANCELLED = 5,
	RM_COMMITTED = 6
};
enum rm_terminal { RM_NORMAL = 0, RM_GUARDIAN_DEAD = 1 };
enum rm_gop { RM_REGISTER = 1, RM_ARM = 2, RM_CANCEL = 3, RM_COMMIT = 4 };
enum rm_aop { RM_A_READY = 1, RM_CHECK = 2 };
enum rm_status {
	RM_ACCEPT = 0,
	RM_BAD_CONFIG = 1,
	RM_BAD_REQUEST = 2,
	RM_WRONG_INCARNATION = 3,
	RM_WRONG_NONCE = 4,
	RM_BAD_STATE = 5,
	RM_NOT_REGISTERED = 6,
	RM_TERMINAL = 7,
	RM_WRONG_TASK = 8,
	RM_EXHAUSTED = 9,
	RM_REPLAY = 10,
	RM_WRONG_OLD_TUPLE = 11,
	RM_WRONG_EPOCH = 12,
	RM_WRONG_GENERATION = 13,
	RM_NOT_ALIVE = 14
};
enum rm_endpoint { RM_GUARDIAN_ENDPOINT = 1, RM_ADMIN_ENDPOINT = 2 };
struct rm_config {
	__u64 incarnation, bootstrap_nonce;
	__u32 abi, scenario;
	__u64 clone_flags;
};
struct rm_grequest {
	__u64 incarnation, nonce, sequence, expected_admin_generation,
		expected_admin_sequence, recovery_epoch;
	__u32 operation, reserved32;
	__u64 reserved64;
};
struct rm_arequest {
	__u64 incarnation, generation, sequence, recovery_epoch;
	__u32 operation, reserved;
};
struct rm_control {
	struct bpf_spin_lock lock;
	__u32 terminal;
	__u64 incarnation, guardian_task, guardian_sequence;
	__u32 guardian_phase, admin_phase;
	__u64 admin_task, admin_generation, admin_sequence, admin_counter;
	__u64 admin_death_task, admin_death_generation, admin_death_sequence;
	__u32 admin_death_count, recovery_phase;
	__u64 recovery_epoch, expected_old_generation, expected_old_sequence,
		candidate_task, candidate_generation;
	__u32 candidate_death_count, capture_count;
	__u64 candidate_death_task, candidate_death_generation,
		guardian_death_task, guardian_death_sequence;
	__u32 guardian_death_count, reserved;
};
struct rm_receipt {
	__u64 incarnation, attempted_sequence, observed_physical_task,
		resulting_guardian_sequence, admin_generation, admin_sequence,
		recovery_epoch, candidate_task;
	__u32 operation, status, guardian_phase, admin_phase, recovery_phase,
		terminal, reserved0, reserved1;
};
#define SIZE(T, N)                                         \
	_Static_assert(sizeof(struct T) == N, #T " size"); \
	_Static_assert(_Alignof(struct T) == 8, #T " alignment")
#define OFF(T, F, N)                                         \
	_Static_assert(__builtin_offsetof(struct T, F) == N, \
		       #T "." #F " offset")
SIZE(rm_config, 32);
SIZE(rm_grequest, 64);
SIZE(rm_arequest, 40);
SIZE(rm_control, 192);
SIZE(rm_receipt, 96);
OFF(rm_config, incarnation, 0);
OFF(rm_config, bootstrap_nonce, 8);
OFF(rm_config, abi, 16);
OFF(rm_config, scenario, 20);
OFF(rm_config, clone_flags, 24);
OFF(rm_grequest, incarnation, 0);
OFF(rm_grequest, nonce, 8);
OFF(rm_grequest, sequence, 16);
OFF(rm_grequest, expected_admin_generation, 24);
OFF(rm_grequest, expected_admin_sequence, 32);
OFF(rm_grequest, recovery_epoch, 40);
OFF(rm_grequest, operation, 48);
OFF(rm_grequest, reserved32, 52);
OFF(rm_grequest, reserved64, 56);
OFF(rm_arequest, incarnation, 0);
OFF(rm_arequest, generation, 8);
OFF(rm_arequest, sequence, 16);
OFF(rm_arequest, recovery_epoch, 24);
OFF(rm_arequest, operation, 32);
OFF(rm_arequest, reserved, 36);
OFF(rm_control, lock, 0);
OFF(rm_control, terminal, 4);
OFF(rm_control, incarnation, 8);
OFF(rm_control, guardian_task, 16);
OFF(rm_control, guardian_sequence, 24);
OFF(rm_control, guardian_phase, 32);
OFF(rm_control, admin_phase, 36);
OFF(rm_control, admin_task, 40);
OFF(rm_control, admin_generation, 48);
OFF(rm_control, admin_sequence, 56);
OFF(rm_control, admin_counter, 64);
OFF(rm_control, admin_death_task, 72);
OFF(rm_control, admin_death_generation, 80);
OFF(rm_control, admin_death_sequence, 88);
OFF(rm_control, admin_death_count, 96);
OFF(rm_control, recovery_phase, 100);
OFF(rm_control, recovery_epoch, 104);
OFF(rm_control, expected_old_generation, 112);
OFF(rm_control, expected_old_sequence, 120);
OFF(rm_control, candidate_task, 128);
OFF(rm_control, candidate_generation, 136);
OFF(rm_control, candidate_death_count, 144);
OFF(rm_control, capture_count, 148);
OFF(rm_control, candidate_death_task, 152);
OFF(rm_control, candidate_death_generation, 160);
OFF(rm_control, guardian_death_task, 168);
OFF(rm_control, guardian_death_sequence, 176);
OFF(rm_control, guardian_death_count, 184);
OFF(rm_control, reserved, 188);
OFF(rm_receipt, incarnation, 0);
OFF(rm_receipt, attempted_sequence, 8);
OFF(rm_receipt, observed_physical_task, 16);
OFF(rm_receipt, resulting_guardian_sequence, 24);
OFF(rm_receipt, admin_generation, 32);
OFF(rm_receipt, admin_sequence, 40);
OFF(rm_receipt, recovery_epoch, 48);
OFF(rm_receipt, candidate_task, 56);
OFF(rm_receipt, operation, 64);
OFF(rm_receipt, status, 68);
OFF(rm_receipt, guardian_phase, 72);
OFF(rm_receipt, admin_phase, 76);
OFF(rm_receipt, recovery_phase, 80);
OFF(rm_receipt, terminal, 84);
OFF(rm_receipt, reserved0, 88);
OFF(rm_receipt, reserved1, 92);
#undef SIZE
#undef OFF
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "little endian ABI");
#endif
