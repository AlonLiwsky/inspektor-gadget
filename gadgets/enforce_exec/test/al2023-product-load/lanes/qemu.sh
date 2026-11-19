# shellcheck shell=bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# Lane C (G035 plan section 2): nested QEMU/KVM. Sourced by host.sh; it
# implements the lane interface:
#
#   lane_preflight              requirements; nonzero refuses the lane
#   lane_run <tag> <bundle> <stage>
#                               boot a machine for <tag>, run guest.sh there
#                               as root and leave its <out> in <stage>/out
#                               and the lane's own evidence in <stage>/lane
#   lane_down <tag> <stage>     release everything lane_run created
#   lane_prove_absence <tag> <stage>
#                               prove nothing is left (nonzero otherwise)
#
# Every step reports through host.sh's `infra <name> <rc> <detail>`.
#
# Kernel parity only: the AL2023 KVM qcow2 with the pinned kernel RPM
# installed (qemu/build-image.sh); the guest proves the exact kernel
# (vmlinuz sha256, BTF, build-id). Unpinned refusal runs on the image's
# default kernel. KVM is mandatory (never TCG).
#
#   G035_QEMU_IMAGE_DIR   directory of <image>.qcow2 / derived/<image>.qcow2
#   G035_QEMU_STATE       run overlays and slot locks
#   G035_QEMU_IMAGE_6_12, G035_QEMU_IMAGE_6_18, G035_QEMU_IMAGE_UNPINNED
#                         image names (default al2023-k612, al2023-k618, al2023)
#   G035_QEMU_TIMEOUT     hard deadline per VM in seconds (default 5400)
#   G035_QEMU_MEM_MB, G035_QEMU_CPUS (default 4096, 4)

LANE_QEMU_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../qemu" && pwd)

lane_image() {
	case $1 in
	6.12) echo "${G035_QEMU_IMAGE_6_12:-al2023-k612}" ;;
	6.18) echo "${G035_QEMU_IMAGE_6_18:-al2023-k618}" ;;
	unpinned) echo "${G035_QEMU_IMAGE_UNPINNED:-al2023}" ;;
	esac
}

lane_preflight() {
	local missing=() t img
	[[ -r /dev/kvm && -w /dev/kvm ]] || missing+=("/dev/kvm (read-write; the lane never falls back to TCG)")
	for t in qemu-system-x86_64 qemu-img genisoimage; do command -v "$t" >/dev/null || missing+=("$t"); done
	[[ -n ${G035_QEMU_IMAGE_DIR:-} && -n ${G035_QEMU_STATE:-} ]] || missing+=("G035_QEMU_IMAGE_DIR and G035_QEMU_STATE")
	for t in 6.12 6.18 unpinned; do
		img=$(lane_image "$t")
		[[ -f ${G035_QEMU_IMAGE_DIR:-/nonexistent}/$img.qcow2 || -f ${G035_QEMU_IMAGE_DIR:-/nonexistent}/derived/$img.qcow2 ]] || missing+=("image $img for $t")
	done
	if ((${#missing[@]})); then
		printf 'lane qemu: missing %s\n' "${missing[@]}" >&2
		return 1
	fi
}

lane_run() {
	local tag=$1 bundle=$2 stage=$3 img rc pexit
	img=$(lane_image "$tag")
	[[ ${AL2023_BURNIN:-} =~ ^[a-z-]*$ ]] || { infra payload 1 "bad AL2023_BURNIN"; return 1; }
	mkdir -p "$stage/payload" "$stage/lane" "$stage/out" || return 1
	cp -a -- "$bundle" "$stage/payload/bundle" || { infra payload 1 "copy the bundle"; return 1; }
	cat >"$stage/payload/run-in-guest.sh" <<EOF
#!/bin/bash
export AL2023_LANE=qemu AL2023_PROFILES='$AL2023_PROFILES' AL2023_NEG_SET='$AL2023_NEG_SET' AL2023_RUN='$AL2023_RUN' AL2023_BURNIN='${AL2023_BURNIN:-}'
bash "\$UK_PAYLOAD/bundle/guest.sh" '$tag' "\$UK_PAYLOAD/bundle" "\$UK_OUT/results"
EOF
	chmod +x "$stage/payload/run-in-guest.sh"
	infra payload 0 "bundle and run-in-guest.sh for $img"
	UK_VM_MEM_MB=${G035_QEMU_MEM_MB:-4096} UK_VM_CPUS=${G035_QEMU_CPUS:-4} \
		"$LANE_QEMU_DIR/vm-run.sh" "$img" "$stage/payload" "$stage/lane/vm" --timeout "${G035_QEMU_TIMEOUT:-5400}"
	rc=$?
	infra vm "$rc" "vm-run.sh $img: $(sed -n 's/^  "status": "\(.*\)",$/\1/p' "$stage/lane/vm/run-manifest.json" 2>/dev/null)"
	pexit=$(cat "$stage/lane/vm/guest/payload.exit" 2>/dev/null || echo missing)
	infra guest "$pexit" "guest.sh exit"
	if [[ -d $stage/lane/vm/guest/results/$tag ]]; then
		cp -a -- "$stage/lane/vm/guest/results/$tag" "$stage/out/" && infra fetch 0 "results of $tag"
	else
		infra fetch 1 "no results for $tag from the guest"
	fi
	return "$rc"
}

lane_down() {
	# vm-run.sh tears its VM down on every exit path (kill + wait, then the
	# run's overlay directory); nothing else was created.
	infra down 0 "vm-run.sh teardown trap"
}

lane_prove_absence() {
	local tag=$1 stage=$2 id
	id=$(sed -n 's/^  "run_id": "\(.*\)",$/\1/p' "$stage/lane/vm/run-manifest.json" 2>/dev/null)
	if [[ -z $id ]]; then
		infra absence 1 "no run id in the VM manifest"
		return 1
	fi
	if pgrep -f "[u]k-$(lane_image "$tag")-$id" >/dev/null || [[ -e $G035_QEMU_STATE/runs/$id ]]; then
		infra absence 1 "qemu process or run directory $id still present"
		return 1
	fi
	infra absence 0 "no qemu process and no run directory for $id"
}
