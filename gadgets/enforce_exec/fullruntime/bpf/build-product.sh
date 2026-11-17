#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# Builds the shared product objects g19pkg{64,128,256,512}-<kernel>.bpf.o
# for the two qualified AL2023 kernels and, with --check, compares each
# sha256 with fullruntime/testdata/shared_product_pins.tsv (sharedProductPins).
#
# Usage: build-product.sh [--check] [OUTDIR]     (default OUTDIR: a temp dir)
#   CLANG   the compiler (default clang-21). It must be the Debian package
#           clang-21 1:21.1.8-3~bpo13+2: its version string is in the
#           object (DW_AT_producer), so any other build changes the bytes.
#
# Run it in the pinned Debian trixie container, as the CI job
# test-enforce-exec-product-objects does (`make enforce-exec-product-objects`
# runs the same image and scripts with docker): install-product-toolchain.sh
# installs clang-21 and libbpf-dev 1:1.5.0-3 from one snapshot.debian.org
# timestamp, checked against product-toolchain-debs.sha256.
#
# This is the product subset of the qualification build (its scripts are
# not in this repository): the same flags, in the same order. Product
# objects only; the diagnostic twins and the negative builds of that build
# are not reproduced here.
#
# The vmlinux.h files (testdata/al2023-vmlinux/<kernel>/vmlinux.h.xz) are
# `bpftool btf dump file <BTF> format c` of the pinned kernel BTF
# (btf-sha256 in the pins); the sha256 of the decompressed header is
# checked below.
set -euo pipefail

# Refuse to run on a host: the build creates the neutral directories below.
# Run it only in the pinned container (make enforce-exec-product-objects)
# or the CI job.
if [[ ! -e /.dockerenv && -z ${CI:-} && ${ENFORCE_EXEC_PRODUCT_CONTAINER:-} != 1 ]]; then
	echo "$0: run this in the pinned container or CI (or set ENFORCE_EXEC_PRODUCT_CONTAINER=1)" >&2
	exit 1
fi

# ---------------------------------------------------------------------------
# Neutral build paths (pinset p1). The objects carry, in DWARF and BTF, the
# absolute paths of the build: the repository (also the working directory)
# and the directory of each kernel's vmlinux.h. The BPF backend also copies
# each source line's text into .BTF, reading the file at that path, and the
# order of the BTF FWD types follows the real paths the compiler opens. So
# the compile always runs at these fixed real directories, never at the
# checkout path, and the objects are byte-identical wherever the checkout
# is. A missing directory is created (needs write access, as in the
# container) with a copy of the BPF sources or the header; an existing one
# must be this checkout, or a tree whose source directories are identical
# both ways (diff -r). Measured on Debian trixie: a symlink to another
# directory, or -fdebug-prefix-map from another checkout path, changed the
# FWD order in the 6.12 objects, so prefix maps are not used.
CANON_REPO=/src/inspektor-gadget
CANON_BTF=/src/btf
# ---------------------------------------------------------------------------
CLANG_VERSION='Debian clang version 21.1.8 (3~bpo13+2)'
LIBBPF_VERSION='1:1.5.0-3'

check=0
if [[ ${1:-} == --check ]]; then
	check=1
	shift
fi
[[ $# -le 1 ]] || { echo "usage: $0 [--check] [OUTDIR]" >&2; exit 2; }

bpf=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$bpf/../../../.." && pwd)
testdata=$repo/gadgets/enforce_exec/fullruntime/testdata
pins=$testdata/shared_product_pins.tsv
out=${1:-$(mktemp -d)}
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd)

clang=${CLANG:-clang-21}
version=$("$clang" --version | head -n1)
if [[ $version != "$CLANG_VERSION" ]]; then
	echo "$clang reports '$version'; the pinned objects need '$CLANG_VERSION' (install-product-toolchain.sh)" >&2
	exit 1
fi
# The libbpf headers (/usr/include/bpf) are part of the input.
libbpf=$(dpkg-query -W -f='${Version}' libbpf-dev 2>/dev/null) || libbpf=none
if [[ $libbpf != "$LIBBPF_VERSION" ]]; then
	echo "libbpf-dev is '$libbpf'; the pinned objects need the Debian package libbpf-dev $LIBBPF_VERSION headers (install-product-toolchain.sh)" >&2
	exit 1
fi

declare -A vmlinux_sha256=(
	[6.12]=ee6e2d8ede842bbb5a541682c721b4381ab9f15ffbda42f98f626f162d163e47
	[6.18]=a6b003369e04fe8b0382f2704e64e0c0f71c211dd54a5b160f60de21bd00a4e2
)

P=-DENFORCE_EXEC_POOL_OPAQUE_
# compile-pkg.sh: the product base (no REAL_RECOVERY, PRCTL_ARM or
# REAL_LIVE_BOOTSTRAP) and its default profile, overridden below.
BASE=(
	"${P}REAL_POLICY_VERDICT_CANDIDATE=1" "${P}REAL_STAGE_BEGIN_DIAGNOSTIC=1" "${P}REAL_RULE_WINDOW_DIAGNOSTIC=1" "${P}SUCCESSFUL_BIRTH_DIAGNOSTIC=1"
	"${P}FAILURE_SOURCE_COMPLETION_DIAGNOSTIC=1" "${P}SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC=1"
	"${P}REAL_POLICY_BRIDGE_CANDIDATE=1" "${P}TERMINAL_RACE_DIAGNOSTIC=1"
	"${P}READER_BEGIN_PROBE=1" "${P}READER_LIFECYCLE_PROBE=1" "${P}WORK_READER_CATALOGUE_CANDIDATE=1" "${P}WORK_COMPLETION_PROBE=1"
	"${P}FAILURE_FINAL_RETURN_PROBE=1"
	-DSE_PROFILE_BINDINGS=2 -DSE_PROFILE_TASKS=256 -DSE_PROFILE_SCRATCH=64 -DSE_PROFILE_TASK_QUOTA=128 -DSE_PROFILE_SCRATCH_QUOTA=32
	-DSE_PROFILE_ACCEPTED_UIDS=8 -DSE_PROFILE_INODE_FACTS=2 -DSE_PROFILE_INODE_QUOTA=1 -DSE_PROFILE_IMAGES=2 -DSE_PROFILE_IMAGE_QUOTA=1
	-DSE_PROFILE_SLOTS_256=4 -DSE_PROFILE_SLOTS_1024=0 -DSE_PROFILE_SLOTS_4096=0 -DSE_PROFILE_SLOTS_16384=0
)
# build-g19pkg.sh PKG: the product extras (source capsule, eval-WORK
# witness, fail-closed rate, reap events, credit at exit, no TEST_RUN,
# synchronous WORK return, 8192 exit tombstones, product publisher with the
# image geometry, native config gate, interpreter continuation).
PKG=(
	"${P}SOURCE_CAPSULE_CANDIDATE=1" "${P}EVAL_WORK_WITNESS_DIAGNOSTIC=1" "${P}FAIL_CLOSED_RATE_CANDIDATE=1"
	"${P}REAP_EVENTS_CANDIDATE=1" "${P}EXIT_CREDIT_CANDIDATE=1" -DSE_PRODUCT_NO_TEST_RUN=1
	"${P}WORK_SYNC_RETURN_CANDIDATE=1" -DSE_PROFILE_EXIT_TOMBSTONES=8192
	"${P}PRODUCT_PUBLISHER_CANDIDATE=1" -USE_PROFILE_IMAGES -DSE_PROFILE_IMAGES=256 -USE_PROFILE_IMAGE_QUOTA -DSE_PROFILE_IMAGE_QUOTA=128
	"${P}NATIVE_CONFIG_GATE_CANDIDATE=1" "${P}INTERP_CONTINUATION_CANDIDATE=1"
)
# q TASK WORK: the per-binding quota profile.
q() {
	echo "-USE_PROFILE_TASKS -DSE_PROFILE_TASKS=$((2 * $1)) -USE_PROFILE_TASK_QUOTA -DSE_PROFILE_TASK_QUOTA=$1" \
		"-USE_PROFILE_SCRATCH -DSE_PROFILE_SCRATCH=$((2 * $2)) -USE_PROFILE_SCRATCH_QUOTA -DSE_PROFILE_SCRATCH_QUOTA=$2" \
		"-DSE_PROFILE_WORK_RETRIES=$(($2 < 16 ? $2 : 16))"
}
# The product profiles, in pin order: name TASK WORK.
PROFILES=("g19pkg64 64 8" "g19pkg128 128 32" "g19pkg256 256 32" "g19pkg512 512 16")

SOURCES=(include gadgets/enforce_exec/full gadgets/enforce_exec/fullpolicy/bpf gadgets/enforce_exec/fullruntime/bpf)
if [[ ! -e $CANON_REPO ]]; then
	mkdir -p -- "$CANON_REPO"
	(cd -- "$repo" && tar -cf - "${SOURCES[@]}") | tar -xf - -C "$CANON_REPO"
fi
if [[ $(realpath -- "$CANON_REPO") != "$(realpath -- "$repo")" ]]; then
	# Another tree at the canonical path: its source directories must be
	# identical to ours, both ways.
	for dir in "${SOURCES[@]}"; do
		diff -rq -- "$repo/$dir" "$CANON_REPO/$dir" >&2 ||
			{ echo "$CANON_REPO/$dir differs from this checkout; build in the container" >&2; exit 1; }
	done
fi

# The build runs in the canonical repository root (BTF FWD order follows
# it): a logical cd, so PWD (which clang uses) is the canonical path.
cd -- "$CANON_REPO"
fail=0
for kernel in 6.12 6.18; do
	header=$testdata/al2023-vmlinux/$kernel/vmlinux.h.xz
	got=$(xz -dc -- "$header" | sha256sum | cut -d' ' -f1)
	[[ $got == "${vmlinux_sha256[$kernel]}" ]] || { echo "$header decompresses to sha256 $got, want ${vmlinux_sha256[$kernel]}" >&2; exit 1; }
	if [[ ! -e $CANON_BTF/$kernel/vmlinux.h ]]; then
		mkdir -p -- "$CANON_BTF/$kernel" && xz -dc -- "$header" >"$CANON_BTF/$kernel/vmlinux.h"
	fi
	got=$(sha256sum "$CANON_BTF/$kernel/vmlinux.h" | cut -d' ' -f1)
	[[ $got == "${vmlinux_sha256[$kernel]}" ]] || { echo "$CANON_BTF/$kernel/vmlinux.h sha256 $got, want ${vmlinux_sha256[$kernel]}" >&2; exit 1; }
	want=$(awk -F'\t' -v k="$kernel." 'index($1, k) == 1 { print $6 }' "$pins")
	[[ -n $want ]] || { echo "no pin for kernel $kernel in $pins" >&2; exit 1; }
	IFS=, read -r -a wants <<<"$want"
	[[ ${#wants[@]} -eq ${#PROFILES[@]} ]] || { echo "kernel $kernel: ${#wants[@]} pinned objects, want ${#PROFILES[@]}" >&2; exit 1; }
	for i in "${!PROFILES[@]}"; do
		read -r name task work <<<"${PROFILES[$i]}"
		obj=$out/$name-$kernel.bpf.o
		# shellcheck disable=SC2046 # q prints separate flags
		"$clang" -target bpf -O2 -g -D__TARGET_ARCH_x86 \
			"${BASE[@]}" "${PKG[@]}" $(q "$task" "$work") \
			-Wno-missing-declarations -I "$CANON_BTF/$kernel" -I "$CANON_REPO/include" -I "$CANON_REPO/gadgets/enforce_exec/full" \
			-I "$CANON_REPO/gadgets/enforce_exec/fullpolicy/bpf" \
			-c "$CANON_REPO/gadgets/enforce_exec/fullruntime/bpf/opaque_real_owner_child_candidate.bpf.c" -o "$obj" 2>"$obj.log" ||
			{ cat "$obj.log" >&2; echo "BUILD FAIL $name-$kernel" >&2; exit 1; }
		# No build-host path may reach a published object.
		for path in /home/ /root/ "$repo/"; do
			[[ $path == "$CANON_REPO/" ]] && continue
			if grep -qaF -- "$path" "$obj"; then
				echo "$name-$kernel embeds the path $path; build at $CANON_REPO" >&2
				exit 1
			fi
		done
		sum=$(sha256sum "$obj" | cut -d' ' -f1)
		if [[ $check == 0 ]]; then
			echo "$sum  $obj"
		elif [[ $sum == "${wants[$i]}" ]]; then
			echo "OK   $name-$kernel $sum"
		else
			echo "FAIL $name-$kernel $sum, pinned ${wants[$i]}"
			fail=1
		fi
	done
done
exit $fail
