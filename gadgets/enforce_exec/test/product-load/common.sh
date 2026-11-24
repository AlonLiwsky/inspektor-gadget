# shellcheck shell=bash disable=SC2034 # sourced: the values are used by the scripts that source it
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# Settings of the product object-load run, sourced by host.sh and guest.sh
# (and shipped in the bundle). Nothing here names a kernel: the run takes the
# test machine's own kernel.

# The product profiles (one CO-RE object and one image per profile).
PRODUCT_LOAD_ALL_PROFILES="64 128 256 512"
# The profile that also runs the ftrace negative.
PRODUCT_LOAD_FTRACE_PROFILE=128
product_object() { echo "g19pkg$1.bpf.o"; }           # profile
product_image() { echo "local/shared-product:pkg$1"; } # profile (the layout builder's reference)

# PRODUCT_LOAD_PROFILES (default: every profile) selects the profiles of the
# Ready, restart and negatives steps; it must include the ftrace profile.
product_require_profiles() {
	PRODUCT_LOAD_PROFILES=${PRODUCT_LOAD_PROFILES:-$PRODUCT_LOAD_ALL_PROFILES}
	local p
	for p in $PRODUCT_LOAD_PROFILES; do
		[[ " $PRODUCT_LOAD_ALL_PROFILES " == *" $p "* ]] || { echo "PRODUCT_LOAD_PROFILES: unknown profile $p" >&2; return 1; }
	done
	[[ " $PRODUCT_LOAD_PROFILES " == *" $PRODUCT_LOAD_FTRACE_PROFILE "* ]] || { echo "PRODUCT_LOAD_PROFILES must include $PRODUCT_LOAD_FTRACE_PROFILE (the ftrace negative)" >&2; return 1; }
}
