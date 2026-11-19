// SPDX-License-Identifier: GPL-2.0
#ifndef IG_PREFIX_H
#define IG_PREFIX_H
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
#define PX_LIMIT 8
#define PX_INITIAL 1
#define PX_OWNED_BIRTH 2
#define PX_LATE 3
#define PX_PIN 1
#define PX_ENABLE 2
#define PX_BARRIER 3
#define PX_INVENTORY 4
#define PX_REFUSE 5
#define PX_RELEASE_REFS 6
#define PX_HOLD 7
#define PX_DIAG_RELEASE 8
#define PX_DIAG_ARM 9
struct px_config {
	__u64 admin, nonce;
	__u32 target_fd, control_fd, creator_cpu, admin_cpu;
};
struct px_command {
	__u64 nonce, operation, argument;
};
#define PX_STATE_FIELDS                                                       \
	__u64 admin_task, target_kn, control_kn, target_sb, control_sb;       \
	__u64 serial, writers, initial_started, inventory_serial,             \
		inventory_generation, refusal_serial, refusal_inventory,      \
		refusal_barrier;                                              \
	__u64 pinned, enabled, barrier, initial_done, next_cookie, retained,  \
		inflight;                                                     \
	__u64 allocs, births, frees, failed, unowned, errors, inventory,      \
		refusals;                                                     \
	__u64 target_id, prefix_missing, history_unknown, strict_ready, held, \
		diagnostic_task, diagnostic_nonce, diagnostic_enter;          \
	__u64 diagnostic_release, diagnostic_exit, diagnostic_timeout,        \
		diagnostic_cpu, admin_cpu;                                    \
	__u64 diagnostic_child, diagnostic_used;
struct px_state {
	__u32 lock, pad;
	PX_STATE_FIELDS
};
#define PX_ROW_FIELDS                                                     \
	__u64 cookie, origin, owns_slot, boundary_seen, prefix_qualified, \
		history_complete;                                         \
	__u64 birth_uncertain, live, parent_cookie, child, child_cookie;  \
	__u64 alloc_seen, new_seen, retfork_seen, entries, exits,         \
		retfork_entries, first_exit_entries;                      \
	__u64 read_enter, read_exit, pid;                                 \
	__u64 history[4];
struct px_row {
	__u32 lock, pad;
	PX_ROW_FIELDS
};
/* Deliberately no root/lineage inference; qualification cannot populate history. */
static inline int px_eligible(__u64 origin, __u64 uncertain, __u64 live,
			      __u64 fork_seen, __u64 entries,
			      __u64 fork_entries, __u64 inventory_complete,
			      __u64 child, __u64 child_cookie)
{
	return inventory_complete && !child && !child_cookie && !uncertain &&
	       (origin == PX_INITIAL || (origin == PX_OWNED_BIRTH && live &&
					 fork_seen && entries == fork_entries));
}
static inline int px_snapshot_valid(__u64 serial, __u64 expected, __u64 writers,
				    __u64 expected_writers)
{
	return serial && serial != ~0ULL && serial == expected &&
	       writers == expected_writers;
}
static inline int px_refusal_valid(__u64 requested, __u64 refusals, __u64 inv,
				   __u64 refused_inv, __u64 serial,
				   __u64 refused_serial, __u64 barrier,
				   __u64 refused_barrier, __u64 writers)
{
	return requested && requested == refusals && inv &&
	       inv == refused_inv && barrier && barrier == refused_barrier &&
	       px_snapshot_valid(serial, refused_serial, writers, 0);
}
/* Diagnostic only. Caller has already matched the typed child physical key
 * and owned birth. Never use a PID to establish ownership or qualification. */
static inline void px_birth_diagnostic_pid(__u64 *diagnostic_pid,
					   __u64 row_cookie, __u64 owned_cookie,
					   __u64 observed_pid)
{
	if (row_cookie && row_cookie == owned_cookie)
		*diagnostic_pid = observed_pid;
}
#endif
