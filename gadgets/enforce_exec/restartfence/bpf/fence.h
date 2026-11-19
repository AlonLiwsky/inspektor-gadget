/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#ifndef UK_RESTART_FENCE_H
#define UK_RESTART_FENCE_H

#define FENCE_PRCTL 0x4b554246
#define FENCE_STRICT 1
#define FENCE_AUDIT 2
#define FENCE_SECTION_EXEC (1U << 0)
#define FENCE_MAX_PODS 4096

struct fence_identity {
	__u64 incarnation;
	__u64 start_boottime;
	__u32 tgid;
	__u32 reserved;
};

struct fence_challenge {
	__u64 incarnation;
	__u64 lo;
	__u64 hi;
};

struct fence_binding {
	__u64 owner;
	__u64 pod_uid_hash;
	__u32 strict_sections;
	__u32 audit_sections;
	__u32 bound_sections;
	__u32 reserved;
};

struct fence_totals {
	__u64 denied;
	__u64 audit;
	__u64 lost;
};

struct fence_event {
	__u64 ktime;
	__u64 cgroup_id;
	__u64 pod_uid_hash;
	__u32 tgid;
	__u32 mode;
};

#endif
