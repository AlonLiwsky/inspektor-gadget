# shellcheck shell=bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# Lane A (G035 plan section 2): ephemeral EC2 on the pinned AMIs through
# OIDC. Same interface as lanes/qemu.sh. NOT IMPLEMENTED YET: it needs the
# AWS and repo setup of plan step 3 (account D3, role, private AMI copies,
# access D8). Until then every entry point refuses, so the lane can never
# pass by accident.
#
# What lane_run must do once step 3 exists (plan sections 2 and 4):
#   up      RunInstances m6i.large on AL2023_AMI_ID[tag] (or its private
#           copy), tags Purpose=ig-enforce-exec-al2023, Owner, ExpirationDate,
#           Run=$AL2023_RUN; no instance profile; IMDS disabled; user-data
#           `shutdown -h +90` with instance-initiated shutdown = terminate;
#           a per-run SG open only to the runner's /32 on tcp/22 and a
#           per-run key (D8: or presigned S3 URLs instead of SSH)
#   run     scp the bundle, then as root:
#           AL2023_LANE=ec2 guest.sh <tag> <bundle> <out>; fetch <out>
#   down    terminate, delete the SG and key after checking their Run tag
#   absence describe by Run tag: instances terminated, 0 volumes, 0 ENIs,
#           SG and key absent (c2-eks-probe 95-prove-absence.sh)
# Unpinned refusal (tag unpinned) runs on the runner's own kernel instead.

lane_ec2_refuse() {
	echo "lane ec2: not implemented; it needs the G035 step 3 AWS setup (PENDING D3, D8)" >&2
	return 2
}
lane_preflight() { lane_ec2_refuse; }
lane_run() { infra ec2 2 "lane not implemented"; lane_ec2_refuse; }
lane_down() { infra down 2 "lane not implemented"; lane_ec2_refuse; }
lane_prove_absence() { infra absence 2 "lane not implemented"; lane_ec2_refuse; }
