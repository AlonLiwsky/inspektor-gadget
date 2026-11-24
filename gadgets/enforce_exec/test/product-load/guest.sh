#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# Guest runner of the product object-load run. Runs as root on a disposable
# test machine with any kernel (e.g. a DigitalOcean droplet), from a
# read-only bundle that host.sh built:
#
#   guest.sh <bundle> <out>
#     bundle  bin/{fullruntime.test,verdict-load,judge,test2json,bpftool},
#             objects/, objects.tsv, layout/, images.tsv, bundle.sha256sums,
#             common.sh
#     out     writable; receives <out>/kernel/<step>__<profile>.json (the
#             test2json streams the judge reads) and <out>/kernel/evidence/
#
#   PRODUCT_LOAD_PROFILES  profiles of the per-profile steps (common.sh)
#   PRODUCT_LOAD_RUN       run id ([a-z0-9-], names the test cgroups)
#   PRODUCT_LOAD_BURNIN    burn-in only (never set it in a real run): skip-kill
#                          (the restart child is not SIGKILLed until the end),
#                          plant-warning (a kernel WARNING line in the log),
#                          plant-se-pin (a se_* pin in bpffs). A set value also
#                          writes an unexpected stream, so the run is always red.
#
# The kernel is whatever the machine runs: the identity rows record it (no
# pinned build is compared); bpf LSM, ftrace on and no livepatch are
# required, as the product kernel gate requires them.
#
# Every check is a row in a test2json stream: Go tests through test2json,
# harness checks through `judge row`. The exit code is 0 when the harness
# itself completed (the judge decides pass or fail from the streams), and
# nonzero on a harness error. An identity failure stops the run: the later
# streams are then missing, which the judge reports as missing rows.
set -uo pipefail

die() { echo "guest.sh: $*" >&2; exit 3; }
# Only the values this script sets may reach the tests: drop every inherited
# IG_* variable (a stray IG_SHARED_PRODUCT_* would change what a test does).
for v in $(compgen -e); do [[ $v == IG_* ]] && unset "$v"; done
[[ $# -eq 2 ]] || die "usage: guest.sh <bundle> <out>"
TAG=kernel B=$(cd -- "$1" && pwd) OUT=$2
[[ $(id -u) == 0 ]] || die "root required"
# shellcheck source=common.sh
. "$B/common.sh" || die "no common.sh in the bundle"
product_require_profiles || exit 3
# The object pins: profile name (g19pkg<N>) to sha256.
declare -A OBJECT_SHA256=()
while IFS=$'\t' read -r name sum; do
	[[ -z $name || $name == '#'* ]] && continue
	OBJECT_SHA256[$name]=$sum
done <"$B/objects.tsv" || die "no objects.tsv in the bundle"
[[ ${#OBJECT_SHA256[@]} == 4 ]] || die "objects.tsv holds ${#OBJECT_SHA256[@]} object pins, want 4"
[[ ${PRODUCT_LOAD_RUN:-} =~ ^[a-z0-9-]{1,40}$ ]] || die "PRODUCT_LOAD_RUN must match [a-z0-9-]{1,40}"
BURNIN=${PRODUCT_LOAD_BURNIN:-}
case $BURNIN in "" | skip-kill | plant-warning | plant-se-pin) ;; *) die "unknown PRODUCT_LOAD_BURNIN $BURNIN" ;; esac

R=$OUT/$TAG EV=$OUT/$TAG/evidence
[[ ! -e $R ]] || die "$R exists (never overwrite evidence)"
mkdir -p "$EV" || die "cannot create $EV"
exec > >(tee -a "$EV/guest.log") 2>&1
J=$B/bin/judge T2J=$B/bin/test2json TEST=$B/bin/fullruntime.test BPFTOOL=$B/bin/bpftool
for f in "$J" "$T2J" "$TEST" "$B/bin/verdict-load" "$BPFTOOL"; do [[ -x $f ]] || die "missing $f"; done
WORK=$(mktemp -d /var/tmp/product-load-work.XXXXXX) || die "mktemp"
cd "$WORK" || die "cd $WORK"
echo "guest.sh: run=$PRODUCT_LOAD_RUN profiles='$PRODUCT_LOAD_PROFILES' burnin='$BURNIN' kernel=$(uname -r) start=$(date -u +%FT%TZ)"

# ---- stream helpers -------------------------------------------------------
stream() { echo "$R/$1__$2.json"; } # step profile
row() {                             # stream test pass|fail detail
	"$J" row -stream "$1" -test "$2" -status "$3" -detail "$4" || die "judge row $2"
	echo "  [$3] $2: $4"
}
check() { # stream test detail -- command...: pass when the command succeeds
	local s=$1 t=$2 d=$3
	shift 4
	if "$@"; then row "$s" "$t" pass "$d"; else row "$s" "$t" fail "$d"; fi
}
end() { "$J" end -stream "$1" || die "judge end $1"; }
# failed: does the stream hold a failed row?
failed() { grep -q '"Action":"fail"' "$1"; }

# gotest step profile test env...: one Go test through test2json, the
# test binary prefixed with WRAP (e.g. unshare -m).
WRAP=()
gotest() {
	local step=$1 profile=$2 test=$3
	shift 3
	echo "== go test $test ($step, profile $profile) ${WRAP[*]}"
	env "$@" "$T2J" -t -p fullruntime "${WRAP[@]}" "$TEST" -test.v=test2json -test.count=1 -test.timeout=30m -test.run "^$test\$" >"$(stream "$step" "$profile")"
	echo "   exit $?"
}

# ---- leftover probes --------------------------------------------------------
# The product object's program names (verdict-load prints the spec, full
# names) identify enforce_exec programs. bpftool prints the full name when
# the program has BTF func info and the kernel's 15-byte name otherwise, so
# a loaded name matches a full name or its 15-byte truncation.
enforce_names() { "$B/bin/verdict-load" -object "$1" | awk '$1 == "spec" && $2 == "program" { print $3 }' | sort -u; }
# enforce_progs: "id name" of every loaded enforce_exec program.
enforce_progs() {
	"$BPFTOOL" prog show 2>/dev/null | awk -v names="$NAMES" 'BEGIN { n = split(names, a, "\n"); for (i = 1; i <= n; i++) if (a[i] != "") { want[a[i]] = 1; want[substr(a[i], 1, 15)] = 1 } }
		/^[0-9]+: / { for (i = 2; i < NF; i++) if ($i == "name" && ($(i + 1) in want)) print $1 + 0, $(i + 1) }'
}
link_ids() { "$BPFTOOL" link show 2>/dev/null | awk '/^[0-9]+: / { print $1 + 0 }' | LC_ALL=C sort; }
se_pins() { find /sys/fs/bpf -name 'se_*' 2>&1; }
wait_no_progs() { # seconds
	local i
	for ((i = 0; i < $1 * 10; i++)); do
		[[ -z $(enforce_progs) ]] && return 0
		sleep 0.1
	done
	return 1
}

# dmesg_check stream: the kernel log since the start (cleared there, so a
# wrapped ring buffer cannot hide or shift anything) has no splat. A dmesg
# or grep error (grep exit 2) fails the row.
dmesg_check() {
	local rc
	if ! dmesg >"$EV/dmesg-new.txt" 2>&1; then
		row "$1" dmesg_clean fail "dmesg failed: $(head -c 200 "$EV/dmesg-new.txt")"
		return
	fi
	grep -E "BUG:|WARNING:|Oops|lockdep|circular locking|soft lockup|hung_task|RCU stall" "$EV/dmesg-new.txt" >"$EV/dmesg-splats.txt"
	rc=$?
	case $rc in
	1) row "$1" dmesg_clean pass "no BUG/WARNING/Oops/lockdep since the start ($(wc -l <"$EV/dmesg-new.txt") lines)" ;;
	0) row "$1" dmesg_clean fail "$(wc -l <"$EV/dmesg-splats.txt") splat lines, first: $(head -n1 "$EV/dmesg-splats.txt")" ;;
	*) row "$1" dmesg_clean fail "grep exit $rc" ;;
	esac
}

# ---- baseline -----------------------------------------------------------------
# Save the boot log, then clear the ring buffer: dmesg_check reads only what
# the run logged. A failed clear leaves no clean baseline: dmesg_clean fails.
dmesg >"$EV/dmesg-start.txt" 2>&1 && dmesg --clear || { echo "guest.sh: dmesg --clear failed" >&2; DMESG_BASELINE=failed; }
DMESG_BASELINE=${DMESG_BASELINE:-cleared}
link_ids >"$EV/links-start.txt"
"$BPFTOOL" prog show >"$EV/progs-start.txt" 2>&1
CG_ROOT=/sys/fs/cgroup
CG_PREFIX=ig-product-load-$PRODUCT_LOAD_RUN
# burnin_mark: a burn-in run writes a stream the judge never expects.
burnin_mark() {
	[[ -z $BURNIN ]] && return
	row "$(stream burnin -)" "$BURNIN" fail "burn-in run: never green"
	end "$(stream burnin -)"
}
case $BURNIN in
plant-warning) echo "WARNING: product-load burn-in planted line" >/dev/kmsg ;;
plant-se-pin) "$BPFTOOL" map create /sys/fs/bpf/se_burnin type array key 4 value 4 entries 1 name se_burnin ;;
esac

# ---- step 0: identity -----------------------------------------------------------
S=$(stream identity -)
check "$S" bundle_manifest "sha256sum -c bundle.sha256sums" -- bash -c 'cd "$1" && sha256sum --quiet -c bundle.sha256sums' _ "$B"
REL=$(uname -r)
BTF=$(sha256sum /sys/kernel/btf/vmlinux 2>/dev/null | cut -d' ' -f1)
le32() { echo $((16#${1:6:2}${1:4:2}${1:2:2}${1:0:2})); }
# build_id: the NT_GNU_BUILD_ID note of /sys/kernel/notes.
build_id() {
	local hex i=0 n namesz descsz type name desc
	hex=$(od -An -v -tx1 /sys/kernel/notes | tr -d ' \n') || return 1
	n=${#hex}
	while ((i + 24 <= n)); do
		namesz=$(le32 "${hex:i:8}") descsz=$(le32 "${hex:i+8:8}") type=$(le32 "${hex:i+16:8}")
		i=$((i + 24))
		name=${hex:i:namesz*2}
		i=$((i + (namesz + 3) / 4 * 8))
		desc=${hex:i:descsz*2}
		i=$((i + (descsz + 3) / 4 * 8))
		if ((type == 3)) && [[ $name == 474e5500 ]]; then
			echo "$desc"
			return 0
		fi
	done
	return 1
}
BUILDID=$(build_id || echo none)
LSM=$(cat /sys/kernel/security/lsm 2>/dev/null || echo unreadable)
FTRACE=$(cat /proc/sys/kernel/ftrace_enabled 2>/dev/null || echo unreadable)
TAINT=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo unreadable)
# Recorded, never compared with a pinned build: each row passes when the
# value was read and well formed.
check "$S" uname_r "uname -r $REL" -- test -n "$REL"
check "$S" btf_sha256 "btf $BTF" -- bash -c '[[ $1 =~ ^[0-9a-f]{64}$ ]]' _ "$BTF"
check "$S" build_id "build-id $BUILDID" -- bash -c '[[ $1 =~ ^([0-9a-f]{2})+$ ]]' _ "$BUILDID"
check "$S" lsm_bpf "lsm $LSM" -- bash -c 'tr , "\n" <<<"$1" | grep -qx bpf' _ "$LSM"
check "$S" ftrace_enabled "kernel.ftrace_enabled=$FTRACE" -- test "$FTRACE" = 1
check "$S" livepatch_clear "kernel.tainted=$TAINT" -- bash -c '[[ $1 =~ ^[0-9]+$ ]] && (( ($1 & (1 << 15)) == 0 ))' _ "$TAINT"
end "$S"
cat >"$EV/identity.json" <<JSON
{
  "run": "$PRODUCT_LOAD_RUN",
  "time": "$(date -u +%FT%TZ)",
  "uname_r": "$REL",
  "btf_sha256": "$BTF",
  "gnu_build_id": "$BUILDID",
  "lsm": "$LSM",
  "ftrace_enabled": "$FTRACE",
  "tainted": "$TAINT",
  "cmdline": "$(tr -d '"\\' </proc/cmdline)",
  "bundle_sha256sums_sha256": "$(sha256sum "$B/bundle.sha256sums" | cut -d' ' -f1)",
  "identity_rows_pass": $(failed "$S" && echo false || echo true)
}
JSON
if failed "$S"; then
	echo "guest.sh: identity failed; no test runs on this kernel (the judge reports the missing rows)"
	exit 0
fi

NAMES=$(for p in $PRODUCT_LOAD_ALL_PROFILES; do enforce_names "$B/objects/$(product_object "$p")"; done | sort -u)
[[ -n $NAMES ]] || die "no program names from the objects"
printf '%s\n' "$NAMES" >"$EV/enforce-program-names.txt"

# ---- step 1: raw load (every product object) --------------------------------------
S=$(stream raw-load -)
for p in $PRODUCT_LOAD_ALL_PROFILES; do
	o=$(product_object "$p")
	# The object must be the pinned ELF before it is loaded: verdict-load
	# accepts any object, and a flipped byte in a debug section still loads.
	sum=$(sha256sum "$B/objects/$o" | cut -d' ' -f1)
	if [[ $sum != "${OBJECT_SHA256[g19pkg$p]:-}" ]]; then
		row "$S" "verdict_load/g19pkg$p" fail "object sha256 $sum is not the pin ${OBJECT_SHA256[g19pkg$p]:-none}; not loaded"
		continue
	fi
	"$B/bin/verdict-load" -run-isolated -object "$B/objects/$o" >"$EV/verdict-load-$o.log" 2>&1
	rc=$?
	summary=$(grep -E '^PASS:' "$EV/verdict-load-$o.log" || tail -n1 "$EV/verdict-load-$o.log")
	if [[ $rc == 0 ]] && grep -q '^PASS:' "$EV/verdict-load-$o.log"; then
		row "$S" "verdict_load/g19pkg$p" pass "sha256 $sum (pinned); $summary"
	else
		row "$S" "verdict_load/g19pkg$p" fail "exit $rc: $summary"
	fi
done
end "$S"
wait_no_progs 10 || echo "guest.sh: enforce programs still loaded after the raw load"

# ---- steps 2-4 per profile ---------------------------------------------------------------
for p in $PRODUCT_LOAD_PROFILES; do
	image=$(product_image "$p") object=$B/objects/$(product_object "$p")
	common=(IG_SHARED_PRODUCT_LAYOUT="$B/layout" IG_SHARED_PRODUCT_IMAGE="$image" IG_SHARED_PRODUCT_OBJECT="$object" IG_SHARED_PRODUCT_PROFILE="$p")
	E=$(stream evidence "$p")

	# Step 2: the Ready path (never toggles ftrace; it must stop clean).
	cga=$CG_ROOT/$CG_PREFIX-p$p-a cgb=$CG_ROOT/$CG_PREFIX-p$p-b
	mkdir "$cga" "$cgb" || die "cannot create the test cgroups"
	gotest ready "$p" TestSharedProductNodeReadyAttached "${common[@]}" IG_SHARED_PRODUCT_CGROUP_A="$cga" IG_SHARED_PRODUCT_CGROUP_B="$cgb"
	# Step 3 (the restart child) uses cgroup A for nothing; remove both now.
	rmdir "$cga" "$cgb" 2>>"$EV/cgroup-rmdir.log" || echo "guest.sh: cgroup rmdir failed (hygiene row)"
	s=$(stream ready "$p")
	admitted=$(grep -o 'product-kernel-admitted: [^"\\]*' "$s" | head -n1)
	check "$E" kernel_admitted "${admitted:-no admitted identity logged}" -- grep -qF "product-kernel-admitted: arch=amd64 release=$REL btf=$BTF build-id=$BUILDID" "$s"
	check "$E" strict_deny_126 "A Strict r1000=126, B Audit r1000=0" -- grep -q 'product-strict-deny A r0=0 r1000=126, product-audit B r0=0 r1000=0' "$s"
	check "$E" in_test_restart "SIGKILLed child left nothing, restart Ready" -- grep -q 'product-restart: SIGKILLed child left no link or program' "$s"

	# Step 3: the restart child under unshare -m: READY, SIGKILL, nothing
	# left, then a child that reaches READY and exits 0.
	clog=$EV/restart-child-$p.log
	env "${common[@]}" IG_SHARED_PRODUCT_CHILD=1 unshare -m "$TEST" -test.v -test.count=1 -test.timeout=10m \
		-test.run '^TestSharedProductNodeReadyAttached$' >"$clog" 2>&1 &
	pid=$!
	for ((i = 0; i < 3000; i++)); do
		grep -qE '^PRODUCT-CHILD (READY|REFUSED)' "$clog" && break
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	check "$E" restart_child_ready "child printed PRODUCT-CHILD READY" -- bash -c 'grep -qx "PRODUCT-CHILD READY" "$1" && ! grep -q "^PRODUCT-CHILD REFUSED" "$1"' _ "$clog"
	# Positive control of the leftover probes: the live child's programs and
	# links are visible, so "nothing left" below can fail.
	enforce_progs >"$EV/child-progs-$p.txt"
	link_ids >"$EV/child-links-$p.txt"
	nlinks=$(comm -13 "$EV/links-start.txt" "$EV/child-links-$p.txt" | wc -l)
	check "$E" restart_child_visible "live child: $(wc -l <"$EV/child-progs-$p.txt") enforce_exec programs, $nlinks new links" -- test -s "$EV/child-progs-$p.txt" -a "$nlinks" -gt 0
	if [[ $BURNIN == skip-kill ]]; then
		KEEP_PID=$pid crc=skipped
	else
		kill -KILL "$pid" 2>/dev/null
		wait "$pid"
		crc=$?
	fi
	check "$E" restart_child_killed "child SIGKILLed (exit $crc)" -- test "$crc" = 137
	check "$E" restart_no_leftover "no enforce_exec program 10 s after the SIGKILL" -- wait_no_progs 10
	WRAP=(unshare -m)
	gotest restart-exit "$p" TestSharedProductNodeReadyAttached "${common[@]}" IG_SHARED_PRODUCT_CHILD=1 IG_SHARED_PRODUCT_CHILD_EXIT=1
	WRAP=()
	s=$(stream restart-exit "$p")
	check "$E" restart_exit_ready "exit child printed PRODUCT-CHILD READY, no REFUSED" -- bash -c 'grep -q "PRODUCT-CHILD READY" "$1" && ! grep -q "PRODUCT-CHILD REFUSED" "$1"' _ "$s"

	# Step 4: the product StartNode refuses the qualification seam before
	# any host run (the per-object refusals are unit tests).
	gotest negatives "$p" TestSharedProductNodeNegativesAttached "${common[@]}" IG_SHARED_PRODUCT_NEG_IMAGES=
	check "$E" neg_qualification_seam_refused "the qualification seam refused by the product StartNode" -- grep -q "product-neg-qualification: refused before any host run" "$(stream negatives "$p")"
	end "$E"
	wait_no_progs 10 || echo "guest.sh: enforce programs still loaded after profile $p"
done

# ---- step 2b: the ftrace negative, on its own node (after every profile) -------------
# After the ftrace-off window the kernel witness keeps the node
# NotReady until it stops (and stale exit credit may add a Degraded fault);
# the test requires StopNode to report the latched witness and at most stale
# exit credit.
p=$PRODUCT_LOAD_FTRACE_PROFILE
cga=$CG_ROOT/$CG_PREFIX-ftrace-a
mkdir "$cga" || die "cannot create the ftrace cgroup"
gotest ftrace "$p" TestSharedProductNodeFtraceNegativeAttached IG_SHARED_PRODUCT_LAYOUT="$B/layout" \
	IG_SHARED_PRODUCT_IMAGE="$(product_image "$p")" IG_SHARED_PRODUCT_OBJECT="$B/objects/$(product_object "$p")" \
	IG_SHARED_PRODUCT_PROFILE="$p" IG_SHARED_PRODUCT_CGROUP_A="$cga" IG_SHARED_PRODUCT_FTRACE_NEG=1
rmdir "$cga" 2>>"$EV/cgroup-rmdir.log" || echo "guest.sh: cgroup rmdir failed (hygiene row)"
s=$(stream ftrace "$p") E=$(stream ftrace-evidence "$p")
check "$E" ftrace_notready "Ready went NotReady naming ftrace" -- grep -q 'product-ftrace-neg: Ready ' "$s"
check "$E" ftrace_restore_126 "enforcement back after restore: r1000=126" -- grep -q 'product-ftrace-restore: r1000=126 ready=' "$s"
outcome=$(grep -o 'product-ftrace-outcome: [a-z-]*' "$s" | head -n1)
check "$E" ftrace_outcome "${outcome:-no outcome logged}" -- grep -qE 'product-ftrace-outcome: witness-latched' "$s"
end "$E"
wait_no_progs 10 || echo "guest.sh: enforce programs still loaded after the ftrace negative"

# ---- step 6: hygiene -------------------------------------------------------------------------
S=$(stream hygiene -)
se_pins >"$EV/se-pins-end.txt"
check "$S" no_se_pins "bpffs mounted at /sys/fs/bpf and no se_* pin in it" -- bash -c 'mountpoint -q /sys/fs/bpf && [[ $(stat -f -c %T /sys/fs/bpf) == bpf_fs ]] && test ! -s "$1"' _ "$EV/se-pins-end.txt"
enforce_progs >"$EV/enforce-progs-end.txt"
"$BPFTOOL" prog show >"$EV/progs-end.txt" 2>&1
check "$S" no_enforce_progs "no enforce_exec program loaded" -- test ! -s "$EV/enforce-progs-end.txt"
link_ids >"$EV/links-end.txt"
"$BPFTOOL" link show >"$EV/links-end-full.txt" 2>&1
check "$S" no_new_links "no BPF link beyond the start baseline" -- bash -c '[[ -z $(comm -13 "$1" "$2") ]]' _ "$EV/links-start.txt" "$EV/links-end.txt"
ls -d "$CG_ROOT/$CG_PREFIX"-* >"$EV/cgroups-end.txt" 2>/dev/null
check "$S" cgroups_removed "no $CG_PREFIX-* cgroup left" -- test ! -s "$EV/cgroups-end.txt"
if [[ $DMESG_BASELINE == cleared ]]; then dmesg_check "$S"; else row "$S" dmesg_clean fail "no clean baseline (dmesg --clear failed)"; fi
end "$S"
burnin_mark
# Burn-in cleanup after the rows: the kept child, the planted pin.
if [[ -n ${KEEP_PID:-} ]]; then kill -KILL "$KEEP_PID" 2>/dev/null; wait "$KEEP_PID"; fi
[[ $BURNIN == plant-se-pin ]] && rm -f /sys/fs/bpf/se_burnin
cd / && rm -rf -- "$WORK"
echo "guest.sh: done end=$(date -u +%FT%TZ)"
exit 0
