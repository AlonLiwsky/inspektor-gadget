#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# Host side of the product object-load run: builds the bundle on a
# workstation, runs guest.sh on a disposable test machine over ssh (any
# kernel; e.g. a DigitalOcean droplet), and judges the result.
#
#   host.sh build  <run-dir>                objects, layout, binaries -> <run-dir>/bundle
#   host.sh remote <run-dir> <ssh-target>   copy the bundle, run guest.sh as root, fetch
#                                           results/kernel (ssh/scp: root@<ip> or a Host alias)
#   host.sh judge  <run-dir>                judge every result; its exit code is the verdict
#   host.sh all    <run-dir> <ssh-target>   build, remote, judge
#
#   PRODUCT_LOAD_PROFILES   profiles of the per-profile steps (common.sh;
#                           default all four, must include 128)
#   PRODUCT_LOAD_PARTIAL=1  allow a narrowed judge: a profile subset or
#                           PRODUCT_LOAD_JUDGE_GROUPS. Without it, judge requires
#                           every group and profile (exactly PRODUCT_LOAD_FULL_ROWS rows).
#   PRODUCT_LOAD_JUDGE_GROUPS  groups the judge requires (default build,kernel)
#   PRODUCT_LOAD_BURNIN     burn-in only (guest.sh); the run is then always red
#   PRODUCT_LOAD_BPFTOOL_TARBALL  bpftool-v7.8.1-amd64.tar.gz (checked by sha256;
#                           downloaded from the libbpf/bpftool release when unset)
#
# <run-dir> must not exist for build (evidence is never overwritten); every
# later step writes only new files under it. Results: <run-dir>/results/<group>/
# (test2json streams, infra.tsv, evidence/), <run-dir>/results.tsv and
# <run-dir>/verdict.txt.
set -uo pipefail
# Build with the module of this checkout only (a go.work outside it must not
# change what is built).
export GOWORK=off

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$HERE/../../../.." && pwd)
# shellcheck source=common.sh
. "$HERE/common.sh"
BPFTOOL_URL=https://github.com/libbpf/bpftool/releases/download/v7.8.1/bpftool-v7.8.1-amd64.tar.gz
BPFTOOL_SHA256=112026bbdf48d0d00ccfc4926e59878d47943f97c197f959f110abe29c898ddc
FULL_GROUPS=build,kernel
# The full run's row count (expected.tsv with every group and profile).
PRODUCT_LOAD_FULL_ROWS=77

die() { echo "host.sh: $*" >&2; exit 2; }
log() { echo "[host.sh $(date -u +%T)] $*"; }

# infra name rc detail: one infrastructure step of the current group
# (INFRA is the group's infra.tsv). A nonzero rc makes the judge red.
infra() {
	printf '%s\t%s\t%s\n' "$1" "$2" "${3//$'\t'/ }" >>"$INFRA"
	[[ $2 == 0 ]] || log "INFRA FAIL $1 ($2): $3"
}

require_config() {
	product_require_profiles || exit 2
}

cmd_build() {
	local rd=$1 b R J obj objs rc
	[[ ! -e $rd ]] || die "$rd exists (never overwrite evidence)"
	require_config
	mkdir -p "$rd/bundle/bin" "$rd/bundle/objects" "$rd/results/build/evidence" "$rd/build" || die "mkdir $rd"
	rd=$(cd -- "$rd" && pwd)
	b=$rd/bundle R=$rd/results/build INFRA=$rd/results/build/infra.tsv
	tr -c 'a-z0-9-\n' '-' <<<"$(basename -- "$rd" | tr 'A-Z' 'a-z')" | cut -c1-40 >"$rd/run-id"
	cd -- "$REPO" || die "cd $REPO"
	git rev-parse HEAD >"$R/evidence/git-head.txt" 2>/dev/null
	git status --porcelain >"$R/evidence/git-status.txt" 2>/dev/null

	# The judge first: it writes the harness rows.
	CGO_ENABLED=0 go build -o "$b/bin/judge" ./gadgets/enforce_exec/test/product-load/judge
	rc=$?
	infra judge "$rc" "go build judge"
	J=$b/bin/judge
	[[ $rc == 0 ]] || return 1

	# The object pins (profile, sha256): the source of truth, copied.
	cp -- "$REPO/gadgets/enforce_exec/fullruntime/testdata/shared_product_objects.tsv" "$b/objects.tsv"
	rc=$?
	infra pins "$rc" "objects.tsv from testdata/shared_product_objects.tsv"
	[[ $rc == 0 ]] || return 1
	cp -- "$b/objects.tsv" "$R/evidence/"

	log "product objects (pinned container)"
	make -C "$REPO" enforce-exec-product-objects ENFORCE_EXEC_PRODUCT_OUT="$rd/build/objects" >"$R/evidence/build-product.log" 2>&1
	rc=$?
	infra objects "$rc" "make enforce-exec-product-objects (build-product.sh --check)"
	local S=$R/objects__-.json name status
	while read -r status name sum _; do
		[[ $status == OK || $status == FAIL ]] || continue
		"$J" row -stream "$S" -test "pin/$name" -status "$([[ $status == OK ]] && echo pass || echo fail)" -detail "$status $name ${sum%,}"
	done <"$R/evidence/build-product.log"
	[[ -s $S ]] && "$J" end -stream "$S"
	objs=()
	# One CO-RE object per profile, for every kernel.
	for p in $PRODUCT_LOAD_ALL_PROFILES; do
		obj=$rd/build/objects/$(product_object "$p")
		cp -- "$obj" "$b/objects/" && objs+=("$b/objects/$(basename -- "$obj")")
	done
	sha256sum "${objs[@]}" | sed "s|$b/||" >"$R/evidence/objects.sha256"
	local list
	list=$(IFS=,; echo "${objs[*]}")

	log "OCI layout (tag-only builder, twice)"
	IG_ENFORCE_EXEC_PRODUCT_OBJECTS=$list IG_SHARED_PRODUCT_LAYOUT_OUT=$rd/build/layout-1 \
		go test -json -count=1 -tags 'enforce_exec_shared_qualification enforce_exec_product_layout' -run '^TestBuildSharedProductLayout$' ./gadgets/enforce_exec/fullruntime >"$R/layout__-.json" 2>"$R/evidence/layout.stderr"
	infra layout $? "TestBuildSharedProductLayout"
	IG_ENFORCE_EXEC_PRODUCT_OBJECTS=$list IG_SHARED_PRODUCT_LAYOUT_OUT=$rd/build/layout-2 \
		go test -count=1 -tags 'enforce_exec_shared_qualification enforce_exec_product_layout' -run '^TestBuildSharedProductLayout$' ./gadgets/enforce_exec/fullruntime >"$R/evidence/layout-2.log" 2>&1
	infra layout-2 $? "TestBuildSharedProductLayout, second process"
	S=$R/layout-repro__-.json
	if diff -r "$rd/build/layout-1" "$rd/build/layout-2" >"$R/evidence/layout-diff.txt" 2>&1; then
		"$J" row -stream "$S" -test rebuild_identical -status pass -detail "index.json sha256 $(sha256sum "$rd/build/layout-1/layout/index.json" | cut -d' ' -f1), identical in a second process"
	else
		"$J" row -stream "$S" -test rebuild_identical -status fail -detail "layouts differ: $(head -c 300 "$R/evidence/layout-diff.txt")"
	fi
	"$J" end -stream "$S"
	cp -a -- "$rd/build/layout-1/layout" "$rd/build/layout-1/images.tsv" "$rd/build/layout-1/layout.sha256sums" "$b/"
	infra layout-copy $? "layout into the bundle"
	cp -- "$rd/build/layout-1/images.tsv" "$rd/build/layout-1/layout.sha256sums" "$R/evidence/"

	log "userspace object checks"
	IG_ENFORCE_EXEC_PRODUCT_OBJECTS=$list go test -json -count=1 \
		-run '^(TestSharedProductManifestMatchesObjects|TestCandidateAttachSetObjects|TestSharedCandidateMergedMetadataObjects)$' \
		./gadgets/enforce_exec/fullruntime >"$R/userspace__-.json" 2>"$R/evidence/userspace.stderr"
	infra userspace $? "userspace object checks"

	log "binaries"
	CGO_ENABLED=0 go test -c -o "$b/bin/fullruntime.test" ./gadgets/enforce_exec/fullruntime
	infra test-binary $? "go test -c ./gadgets/enforce_exec/fullruntime (product build, no tag)"
	CGO_ENABLED=0 go build -o "$b/bin/verdict-load" ./gadgets/enforce_exec/test/product-load/verdict-load
	infra verdict-load $? "go build verdict-load"
	CGO_ENABLED=0 go build -o "$b/bin/test2json" cmd/test2json
	infra test2json $? "go build cmd/test2json"
	local tarball=${PRODUCT_LOAD_BPFTOOL_TARBALL:-$rd/build/bpftool-v7.8.1-amd64.tar.gz}
	[[ -f $tarball ]] || curl -fsSL --retry 3 -o "$tarball" "$BPFTOOL_URL"
	if [[ $(sha256sum "$tarball" 2>/dev/null | cut -d' ' -f1) == "$BPFTOOL_SHA256" ]]; then
		tar -xzf "$tarball" -C "$b/bin" bpftool && chmod +x "$b/bin/bpftool"
		infra bpftool $? "bpftool v7.8.1 (tarball sha256 $BPFTOOL_SHA256)"
	else
		infra bpftool 1 "bpftool tarball $tarball does not match sha256 $BPFTOOL_SHA256"
	fi
	cp -- "$HERE/common.sh" "$HERE/guest.sh" "$b/" && chmod +x "$b/guest.sh"
	infra harness $? "common.sh and guest.sh"
	(cd -- "$b" && find . -type f ! -name bundle.sha256sums -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >bundle.sha256sums)
	infra manifest $? "bundle.sha256sums"
	cp -- "$b/bundle.sha256sums" "$R/evidence/"
	log "bundle $b ($(du -sh "$b" | cut -f1)), bundle.sha256sums $(sha256sum "$b/bundle.sha256sums" | cut -d' ' -f1)"
	if awk -F'\t' '$2 != 0 { bad = 1 } END { exit !bad }' "$INFRA"; then
		log "build failed: $(awk -F'\t' '$2 != 0 { printf "%s ", $1 }' "$INFRA")"
		return 1
	fi
}

# full_selection: is this the full run (every group, all 4 profiles)?
full_selection() {
	[[ ${PRODUCT_LOAD_JUDGE_GROUPS:-$FULL_GROUPS} == "$FULL_GROUPS" && $PRODUCT_LOAD_PROFILES == "$PRODUCT_LOAD_ALL_PROFILES" ]]
}

# cmd_remote: copy the bundle to target, run guest.sh there as root and
# fetch its results into results/kernel. Each step is an infra row of the
# kernel group (a failed copy, guest or fetch turns the run red).
cmd_remote() {
	local rd=$1 target=$2 run dir rc
	[[ -d $rd/bundle && -f $rd/run-id ]] || die "$rd has no bundle (host.sh build first)"
	rd=$(cd -- "$rd" && pwd)
	[[ ! -e $rd/results/kernel ]] || die "kernel already ran in $rd"
	require_config
	run=$(cat "$rd/run-id")
	dir=/var/tmp/product-load-$run
	mkdir -p "$rd/remote" || die "mkdir $rd/remote"
	INFRA=$rd/remote/infra.tsv
	local -a ssh=(ssh -o BatchMode=yes -o ConnectTimeout=30) scp=(scp -q -o BatchMode=yes -o ConnectTimeout=30)
	log "remote $target: copy the bundle to $dir"
	"${ssh[@]}" "$target" "test ! -e $dir && mkdir -p $dir/out"
	rc=$?
	infra remote-dir "$rc" "$target:$dir (must not exist)"
	if [[ $rc == 0 ]]; then
		"${scp[@]}" -r "$rd/bundle" "$target:$dir/"
		rc=$?
		infra copy "$rc" "scp bundle"
	fi
	if [[ $rc == 0 ]]; then
		log "remote $target: guest.sh (see $rd/remote/guest.log)"
		"${ssh[@]}" "$target" "s=; [ \"\$(id -u)\" = 0 ] || s=sudo; \$s env PRODUCT_LOAD_PROFILES='$PRODUCT_LOAD_PROFILES' PRODUCT_LOAD_RUN='$run' PRODUCT_LOAD_BURNIN='${PRODUCT_LOAD_BURNIN:-}' $dir/bundle/guest.sh $dir/bundle $dir/out" >"$rd/remote/guest.log" 2>&1
		rc=$?
		infra guest "$rc" "guest.sh exit"
		"${scp[@]}" -r "$target:$dir/out/kernel" "$rd/remote/"
		rc=$?
		infra fetch "$rc" "scp results"
	fi
	if [[ -d $rd/remote/kernel ]]; then cp -a -- "$rd/remote/kernel" "$rd/results/"; else mkdir -p "$rd/results/kernel/evidence"; fi
	cp -- "$INFRA" "$rd/results/kernel/infra.tsv"
	cp -- "$rd/remote/guest.log" "$rd/results/kernel/evidence/guest-ssh.log" 2>/dev/null
	log "remote $target: done ($(awk -F'\t' '$2 != 0' "$INFRA" | wc -l) infra failures; $target:$dir is left for inspection, the machine is disposable)"
}

cmd_judge() {
	local rd=$1 rc profiles pin=()
	require_config
	profiles=$(tr ' ' ',' <<<"$PRODUCT_LOAD_PROFILES")
	if full_selection; then
		pin=(-rows "$PRODUCT_LOAD_FULL_ROWS")
	elif [[ ${PRODUCT_LOAD_PARTIAL:-} != 1 ]]; then
		die "a narrowed judge (PRODUCT_LOAD_JUDGE_GROUPS or PRODUCT_LOAD_PROFILES) needs PRODUCT_LOAD_PARTIAL=1"
	fi
	"$rd/bundle/bin/judge" check -expected "$HERE/expected.tsv" -results "$rd/results" \
		-kernels "${PRODUCT_LOAD_JUDGE_GROUPS:-$FULL_GROUPS}" -profiles "$profiles" "${pin[@]}" -out "$rd/results.tsv" >"$rd/verdict.txt" 2>&1
	rc=$?
	cat "$rd/verdict.txt"
	return "$rc"
}

[[ $# -ge 2 ]] || die "usage: host.sh build|remote|judge|all <run-dir> ..."
case $1 in
build) cmd_build "$2" ;;
remote)
	[[ $# -eq 3 ]] || die "usage: host.sh remote <run-dir> <ssh-target>"
	cmd_remote "$2" "$3"
	;;
judge) cmd_judge "$2" ;;
all)
	[[ $# -eq 3 ]] || die "usage: host.sh all <run-dir> <ssh-target>"
	cmd_build "$2" || die "build failed (see $2/results/build/infra.tsv); nothing runs"
	(cmd_remote "$2" "$3")
	cmd_judge "$2"
	;;
*) die "unknown command $1" ;;
esac
