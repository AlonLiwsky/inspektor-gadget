#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# Builds the QEMU lane's images in $G035_QEMU_IMAGE_DIR (the CI cache key is
# the pins in env.sh):
#
#   build-image.sh base          al2023.qcow2: the AL2023 KVM image, by sha256
#   build-image.sh 6.12|6.18     derived/al2023-k6xx.qcow2: base + the pinned
#                                kernel RPM (dnf download, sha256 checked, then
#                                installed and made the only boot entry)
#
# Adapted from the universal-kernel harness (vm/fetch-images.sh,
# vm/build-variant.sh, variants/al2023-k61x). A derived image is a read-only
# qcow2 overlay on the base. Nothing existing is overwritten. The guest still
# proves the exact kernel on every run (identity rows), so a wrong image can
# only fail, never pass.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../env.sh
. "$HERE/../env.sh"
IMG=${G035_QEMU_IMAGE_DIR:?set G035_QEMU_IMAGE_DIR}
: "${G035_QEMU_STATE:?set G035_QEMU_STATE}"
# The AL2023 KVM image the QEMU lane boots (its default kernel 6.1 is the
# unpinned-refusal kernel).
BASE_URL=https://cdn.amazonlinux.com/al2023/os-images/2023.12.20261112.0/kvm/al2023-kvm-2023.12.20261112.0-kernel-6.1-x86_64.xfs.gpt.qcow2
BASE_SHA256=ef0fe2cdda2f6a8931dad1e1c66cb21d9f6b49c85e6025b185371e90028ea7e9

[[ $# -eq 1 ]] || { echo "usage: build-image.sh base|6.12|6.18" >&2; exit 2; }
mkdir -p "$IMG/derived"
if [[ $1 == base ]]; then
	dst=$IMG/al2023.qcow2
	[[ ! -e $dst ]] || { echo "present: $dst"; exit 0; }
	curl -fsSL --retry 3 -o "$dst.part" "$BASE_URL"
	echo "$BASE_SHA256  $dst.part" | sha256sum -c -
	mv "$dst.part" "$dst" && chmod a-w "$dst"
	echo "$BASE_SHA256" >"$dst.sha256"
	exit 0
fi
k=$1
[[ -n ${AL2023_RELEASE[$k]:-} ]] || { echo "unknown kernel $k" >&2; exit 2; }
name=al2023-k$(al2023_ktag "$k")
dst=$IMG/derived/$name.qcow2
[[ ! -e $dst ]] || { echo "present: $dst"; exit 0; }
[[ -f $IMG/al2023.qcow2 ]] || { echo "no base image: build-image.sh base" >&2; exit 1; }
work=$G035_QEMU_STATE/build-$name-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$work/payload"
cat >"$work/payload/run-in-guest.sh" <<EOF
#!/bin/bash
set -eux
rpm=${AL2023_KERNEL_RPM[$k]} release=${AL2023_RELEASE[$k]}
mkdir -p /var/tmp/kernel-rpm
dnf download -y --destdir /var/tmp/kernel-rpm "\$rpm"
echo "${AL2023_KERNEL_RPM_SHA256[$k]}  /var/tmp/kernel-rpm/\$rpm.rpm" | sha256sum -c - | tee "\$UK_OUT/rpm-sha256.txt"
dnf install -y "/var/tmp/kernel-rpm/\$rpm.rpm"
K=/boot/vmlinuz-\$release
test -f "\$K"
echo "${AL2023_VMLINUZ_SHA256[$k]}  \$K" | sha256sum -c - | tee "\$UK_OUT/vmlinuz-sha256.txt"
grubby --set-default "\$K"
# AL2023's BIOS grub booted the first BLS entry regardless of saved_entry:
# keep only the pinned kernel's entry (kernel 6.1 stays installed).
mkdir -p /root/bls-hidden
for e in /boot/loader/entries/*.conf; do case "\$e" in *-\$release.conf) ;; *) mv "\$e" /root/bls-hidden/ ;; esac; done
test "\$(ls /boot/loader/entries | wc -l)" = 1
rpm -q "\$rpm" | tee "\$UK_OUT/package.txt"
EOF
chmod +x "$work/payload/run-in-guest.sh"
"$HERE/vm-run.sh" al2023 "$work/payload" "$work/out" --no-bpf-lsm --timeout "${TIMEOUT:-3000}" --save-overlay "$dst.part"
qemu-img check -q "$dst.part"
mv "$dst.part" "$dst" && chmod a-w "$dst"
sha256sum "$dst" | cut -d' ' -f1 >"$dst.sha256"
echo "built $dst (log $work/out)"
