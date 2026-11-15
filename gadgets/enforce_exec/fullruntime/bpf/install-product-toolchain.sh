#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# Installs the toolchain of the pinned product objects into a Debian trixie
# container (root; CI job test-enforce-exec-product-objects, and the
# documented docker command in the README). Every package comes from one
# snapshot.debian.org timestamp; the packages that decide the object bytes
# (clang-21 and its libraries, libbpf-dev and libbpf1) are downloaded into
# DEBDIR (kept when present, e.g. from a cache) and checked against
# product-toolchain-debs.sha256 before anything is installed.
#
# Usage: install-product-toolchain.sh DEBDIR
set -euo pipefail

# The snapshot must match the pinned image: its trixie main has the image's
# libc6 (2.41-12+deb13u4) and its trixie-backports still carries
# clang-21 1:21.1.8-3~bpo13+2.
SNAPSHOT=20261109T224401Z
[[ $# -eq 1 ]] || { echo "usage: $0 DEBDIR" >&2; exit 2; }
debs=$(mkdir -p -- "$1" && cd -- "$1" && pwd)
list=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/product-toolchain-debs.sha256

# Every apt source is the snapshot (main and backports of the same moment).
rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list
cat >/etc/apt/sources.list.d/snapshot.list <<EOF
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAPSHOT trixie main
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$SNAPSHOT trixie-backports main
EOF
apt-get update -qq

# name_version_arch.deb, the version's epoch colon written %3a by apt.
files=()
while read -r _ file; do
	IFS=_ read -r name version _ <<<"${file%.deb}"
	files+=("$debs/$file")
	[[ -f $debs/$file ]] || (cd -- "$debs" && apt-get download -qq "$name=${version//%3a/:}")
done <"$list"
(cd -- "$debs" && sha256sum --quiet -c "$list")

apt-get install -y -qq --no-install-recommends xz-utils "${files[@]}"
