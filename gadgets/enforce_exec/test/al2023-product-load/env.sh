# shellcheck shell=bash disable=SC2034 # sourced: the pins are used by the scripts that source it
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# Pins and configuration of the AL2023 product object-load run (G035).
# Sourced by host.sh, guest.sh and the lanes. Values marked PENDING Dn are
# open decisions of the G035 plan (section 7): they are configuration, set
# them explicitly; the scripts refuse when a required one is unset.

# ---- kernel pins (testdata/shared_product_pins.tsv and the G011 pass-2
# pins: g011-pass2-pins-20261114/extract-pins.sh over the AL2023 repo RPMs).
# Index: the kernel tag used for result directories (6.12, 6.18).
AL2023_KERNELS="6.12 6.18"
declare -A AL2023_RELEASE=(
	[6.12]=6.12.113-138.209.amzn2023.x86_64
	[6.18]=6.18.56-125.164.amzn2023.x86_64
)
declare -A AL2023_BTF_SHA256=(
	[6.12]=0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82
	[6.18]=d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee
)
declare -A AL2023_BUILD_ID=(
	[6.12]=1d135d67e6d0ea8f77d60a2984915eadd28a5fcf
	[6.18]=884ed4548406a1461ac5fb658c0dffdd87f1b3b2
)
# vmlinuz sha256 of the pinned kernel RPM (= the G011 pass-1 ident): the
# QEMU lane's platform identity.
declare -A AL2023_VMLINUZ_SHA256=(
	[6.12]=b1f1af82aafa27641685457572d1ee2b135853e2c30b37ae7c40d9dcc6252666
	[6.18]=537cd20f54e670b9e855d0b72b8b340a2c8f526af6449d94675bfb7c363a1068
)
# The kernel RPMs the QEMU lane installs (AL2023 repo), by sha256.
declare -A AL2023_KERNEL_RPM=(
	[6.12]=kernel6.12-6.12.113-138.209.amzn2023.x86_64
	[6.18]=kernel6.18-6.18.56-125.164.amzn2023.x86_64
)
declare -A AL2023_KERNEL_RPM_SHA256=(
	[6.12]=eef3a6aed3a0d0b889d1b33303086803fc52a9e7f18e2009a11894883a3d2154
	[6.18]=3e59fdd9b2d54e57014af7a2fdcc49061fe04d2aa7623649dda92afa5799106d
)

# The product object sha256 per kernel and profile is NOT pinned here: host.sh
# build derives AL2023_PRODUCT_ELF_SHA256[<kernel>:<profile>] from
# fullruntime/testdata/shared_product_pins.tsv (the source of truth) into the
# bundle's product-pins.sh, which the bundle manifest covers.

# ---- EC2 lane platform identity: the AMIs the G011 evidence used
# (eu-north-1, owner 137112412989 = amazon). The guest compares
# /etc/image-id image_name (IMDS is disabled on the VM, plan section 4).
# PENDING D3: the account, and private AMI copies (their IDs replace these;
# keep the public IDs and names as provenance).
AL2023_AMI_OWNER=137112412989
AL2023_AMI_REGION=${AL2023_AMI_REGION:-eu-north-1}
declare -A AL2023_AMI_ID=(
	[6.12]=ami-0e8550404ae6ca4c6
	[6.18]=ami-0516089d963059a51
)
declare -A AL2023_AMI_NAME=(
	[6.12]=al2023-ami-2023.12.20261026.1-kernel-6.12-x86_64
	[6.18]=al2023-ami-2023.12.20261102.0-kernel-6.18-x86_64
)

# ---- product objects and images (build-product.sh, the layout builder).
AL2023_ALL_PROFILES="64 128 256 512"
# The profile that also runs the ftrace negative (plan 1b step 2).
AL2023_FTRACE_PROFILE=128
al2023_ktag() { echo "${1//./}"; }                                    # 6.12 -> 612
al2023_object() { echo "g19pkg$2.bpf.o"; }                             # kernel profile (stage 1: one CO-RE object per profile)
al2023_image() { echo "local/shared-product-$(al2023_ktag "$1"):pkg$2"; } # kernel profile

# ---- open decisions (configuration, never a silent default).
# PENDING D4: the profiles per run: "64 128 256 512" (all) or "128".
# AL2023_PROFILES must be set by the caller; 128 must be in it (ftrace row).
al2023_require_profiles() {
	[[ -n ${AL2023_PROFILES:-} ]] || { echo "AL2023_PROFILES is unset (PENDING D4: '128' or '64 128 256 512')" >&2; return 1; }
	local p
	for p in $AL2023_PROFILES; do
		[[ " $AL2023_ALL_PROFILES " == *" $p "* ]] || { echo "AL2023_PROFILES: unknown profile $p" >&2; return 1; }
	done
	[[ " $AL2023_PROFILES " == *" $AL2023_FTRACE_PROFILE "* ]] || { echo "AL2023_PROFILES must include $AL2023_FTRACE_PROFILE (the ftrace negative)" >&2; return 1; }
}
# PENDING D5: the negative image set. Stage 1 builds one CO-RE object per
# profile for every kernel, qualified on both pins, so the other kernel's
# image of a profile carries the same qualified object and is NOT a negative
# any more. "seam" runs the negatives test with no negative image: the
# product StartNode must refuse the qualification seam (the per-object
# refusals are unit tests, shared_host_product_test.go). "twins" needs
# build-product.sh to build the diagnostic twins.
al2023_require_neg_set() {
	case ${AL2023_NEG_SET:-} in
	seam) ;;
	other-kernel) echo "AL2023_NEG_SET=other-kernel: stage 1 images of both kernels carry the same qualified object (not a negative); use 'seam'" >&2; return 1 ;;
	twins) echo "AL2023_NEG_SET=twins: the diagnostic twins are not buildable from the repo (build-product.sh); PENDING D5" >&2; return 1 ;;
	*) echo "AL2023_NEG_SET is unset or unknown (PENDING D5: 'seam')" >&2; return 1 ;;
	esac
}
# PENDING D8 (EC2 lane only): VM access, "ssh" (SG /32 + per-run key) or
# "s3-presigned". PENDING D6/D7 are workflow settings (cadence, required check).
