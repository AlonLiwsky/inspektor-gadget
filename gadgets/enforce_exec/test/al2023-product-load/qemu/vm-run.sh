#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# KVM runner of the G035 QEMU lane: boots a read-only AL2023 qcow2 (through
# a per-run overlay), runs <payload-dir>/run-in-guest.sh as root and copies
# its $UK_OUT back. Copied from the universal-kernel stock-kernel harness
# (vm/run.sh); changes: images and run state are configurable
# (G035_QEMU_IMAGE_DIR, G035_QEMU_STATE), and KVM is mandatory (no TCG:
# the plan never falls back to software emulation).
#   vm-run.sh <image> <payload-dir> <out-dir> [--cmdline-extra '<args>'] [--timeout <s>]
#          [--no-bpf-lsm] [--mem <MB>] [--cpus <n>] [--no-net] [--save-overlay <path>]
set -uo pipefail
VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG_DIR="${G035_QEMU_IMAGE_DIR:?set G035_QEMU_IMAGE_DIR (the directory of <image>.qcow2 or derived/<image>.qcow2)}"
STATE_DIR="${G035_QEMU_STATE:?set G035_QEMU_STATE (run overlays and slot locks)}"
SLOTS="${UK_VM_SLOTS:-1}"
MEM_MB="${UK_VM_MEM_MB:-4096}"
CPUS="${UK_VM_CPUS:-4}"
SLOT_WAIT="${UK_VM_SLOT_WAIT:-7200}"
ROOT_GB="${UK_VM_ROOT_GB:-20}"
OUT_MB="${UK_VM_OUT_MB:-2048}"
TIMEOUT=900
CMDLINE_EXTRA=""
ENSURE_BPF_LSM=1
NET=1
SAVE_OVERLAY=""     # internal: used by build-variant.sh
KEEP_RUN_DIR=0      # debug only: leave runs/<id>/ (overlay, seed) behind

die() { echo "vm-run.sh: $*" >&2; exit 2; }
usage() { sed -n '11,12p' "${BASH_SOURCE[0]}" >&2; exit 2; }
[[ $# -ge 3 ]] || usage
DISTRO="$1"; PAYLOAD="$2"; OUTDIR="$3"; shift 3
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cmdline-extra) CMDLINE_EXTRA="${2-}"; shift 2 ;;
    --timeout) TIMEOUT="${2-}"; shift 2 ;;
    --no-bpf-lsm) ENSURE_BPF_LSM=0; shift ;;
    --mem) MEM_MB="${2-}"; shift 2 ;;
    --cpus) CPUS="${2-}"; shift 2 ;;
    --no-net) NET=0; shift ;;
    --save-overlay) SAVE_OVERLAY="${2-}"; shift 2 ;;
    --keep-run-dir) KEEP_RUN_DIR=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ "$DISTRO" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "bad distro name"
[[ "$TIMEOUT" =~ ^[0-9]+$ && "$MEM_MB" =~ ^[0-9]+$ && "$CPUS" =~ ^[0-9]+$ ]] || die "numeric option expected"
[[ "$CMDLINE_EXTRA" != *[\'\"\\\$\`]* && "$CMDLINE_EXTRA" != *$'\n'* ]] || die "--cmdline-extra must not contain quotes, backslashes, \$ or newlines"

BASE="$IMG_DIR/$DISTRO.qcow2"
[[ -f "$BASE" ]] || BASE="$IMG_DIR/derived/$DISTRO.qcow2"
[[ -f "$BASE" ]] || die "unknown image '$DISTRO' (no $IMG_DIR/$DISTRO.qcow2 or $IMG_DIR/derived/$DISTRO.qcow2)"
[[ -d "$PAYLOAD" && -f "$PAYLOAD/run-in-guest.sh" ]] || die "payload dir must exist and contain run-in-guest.sh"
PAYLOAD="$(cd "$PAYLOAD" && pwd)"
ACCEL=kvm
[[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm not accessible: the QEMU lane requires KVM (never TCG)"
MACHINE=(-machine q35,accel=kvm -cpu host)

# Reuse guard: never mix two runs' results.
if [[ -e "$OUTDIR" ]]; then
  [[ -d "$OUTDIR" ]] || die "out-dir exists and is not a directory"
  [[ -z "$(ls -A "$OUTDIR")" ]] || { echo "vm-run.sh: refusing to run: out-dir '$OUTDIR' already has results" >&2; exit 3; }
fi
mkdir -p "$OUTDIR" || die "cannot create out-dir"
OUTDIR="$(cd "$OUTDIR" && pwd)"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"
RUN_DIR="$STATE_DIR/runs/$RUN_ID"
QPID=""; SLOT=""; TIMED_OUT=0; RC=1; STATUS="harness error before boot"
START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; QSTART=""
IMG_SHA="$(cat "$BASE.sha256" 2>/dev/null || echo unknown)"

json_str() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/ }"; printf '"%s"' "$s"; }
gf() { [[ -f "$OUTDIR/guest/$1" ]] && head -c 4096 "$OUTDIR/guest/$1" | head -1 || true; }

teardown() {
  trap - EXIT INT TERM HUP
  if [[ -n "$QPID" ]]; then
    # $QPID is our own child, so the PID cannot have been recycled.
    if kill -0 "$QPID" 2>/dev/null; then
      kill -TERM "$QPID" 2>/dev/null
      for _ in $(seq 50); do kill -0 "$QPID" 2>/dev/null || break; sleep 0.1; done
      kill -KILL "$QPID" 2>/dev/null
    fi
    wait "$QPID" 2>/dev/null
  fi
  # Salvage whatever the guest wrote (early facts on a timeout, full results otherwise).
  if [[ -f "$RUN_DIR/out.raw" && ! -d "$OUTDIR/guest" ]]; then
    mkdir -p "$OUTDIR/guest"
    tar -xf "$RUN_DIR/out.raw" -C "$OUTDIR/guest" --no-same-owner --no-same-permissions 2>/dev/null || true
  fi
  if [[ -n "$SAVE_OVERLAY" && "$RC" -eq 0 && -f "$RUN_DIR/root.qcow2" ]]; then
    mv "$RUN_DIR/root.qcow2" "$SAVE_OVERLAY"
  fi
  {
    echo "{"
    echo "  \"run_id\": $(json_str "$RUN_ID"),"
    echo "  \"distro\": $(json_str "$DISTRO"),"
    echo "  \"image\": $(json_str "$BASE"),"
    echo "  \"image_sha256\": $(json_str "$IMG_SHA"),"
    echo "  \"payload\": $(json_str "$PAYLOAD"),"
    echo "  \"cmdline_extra_requested\": $(json_str "$CMDLINE_EXTRA"),"
    echo "  \"ensure_bpf_lsm\": $ENSURE_BPF_LSM,"
    echo "  \"guest_cmdline_change_applied\": $(json_str "$(gf cmdline-change.txt)"),"
    echo "  \"guest_uname_r\": $(json_str "$(gf uname-r.txt)"),"
    echo "  \"guest_cmdline\": $(json_str "$(gf cmdline.txt)"),"
    echo "  \"guest_lsm\": $(json_str "$(gf lsm.txt)"),"
    echo "  \"guest_lsm_before_change\": $(json_str "$(gf lsm-before.txt)"),"
    echo "  \"accel\": $(json_str "$ACCEL"),"
    echo "  \"mem_mb\": $MEM_MB, \"cpus\": $CPUS, \"slot\": $(json_str "$SLOT"), \"timeout_s\": $TIMEOUT,"
    echo "  \"start\": $(json_str "$START_ISO"),"
    echo "  \"qemu_start\": $(json_str "$QSTART"),"
    echo "  \"end\": $(json_str "$(date -u +%Y-%m-%dT%H:%M:%SZ)"),"
    echo "  \"timed_out\": $TIMED_OUT,"
    echo "  \"status\": $(json_str "$STATUS"),"
    echo "  \"exit_code\": $RC"
    echo "}"
  } > "$OUTDIR/run-manifest.json"
  # Remove only this run's overlay/seed/payload image.
  if (( KEEP_RUN_DIR )); then echo "vm-run.sh: --keep-run-dir: leaving $RUN_DIR" >&2
  elif [[ -n "$RUN_ID" && -d "$RUN_DIR" ]]; then rm -rf -- "$RUN_DIR"; fi
  echo "vm-run.sh: $DISTRO: $STATUS (exit $RC) -> $OUTDIR" >&2
  exit "$RC"
}
trap teardown EXIT
trap 'STATUS="interrupted by signal"; RC=130; exit 130' INT TERM HUP

# ---- global slot limit -------------------------------------------------
mkdir -p "$STATE_DIR/locks" "$STATE_DIR/runs"
waited=0
while :; do
  for i in $(seq 1 "$SLOTS"); do
    exec {LOCKFD}>"$STATE_DIR/locks/slot.$i"
    if flock -n "$LOCKFD"; then SLOT="$i"; break 2; fi
    exec {LOCKFD}>&-
  done
  (( waited >= SLOT_WAIT )) && { STATUS="no free VM slot after ${SLOT_WAIT}s"; RC=4; exit 4; }
  (( waited % 60 == 0 )) && echo "vm-run.sh: all $SLOTS VM slots busy, waiting..." >&2
  sleep 5; waited=$((waited + 5))
done
echo "$$ $DISTRO $RUN_ID" >&"$LOCKFD"

# Provisioning flavor: cloud-init NoCloud seed (default) or Ignition via fw_cfg (Flatcar).
FLAVOR=cloudinit; DRIVER_PATH=/usr/local/sbin/uk-driver
if [[ "$DISTRO" == flatcar* ]]; then FLAVOR=ignition; DRIVER_PATH=/opt/bin/uk-driver; fi

# ---- per-run artifacts -------------------------------------------------
mkdir -p "$RUN_DIR/seed" || { STATUS="cannot create run dir"; exit 1; }
# Overlay size: grow to ROOT_GB, but never smaller than the base image's virtual size.
base_bytes="$(qemu-img info --output=json "$BASE" | sed -n 's/.*"virtual-size": *\([0-9]*\).*/\1/p' | sort -n | tail -1)"
want_bytes=$(( ROOT_GB * 1024 * 1024 * 1024 )); (( ${base_bytes:-0} > want_bytes )) && want_bytes="$base_bytes"
qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$RUN_DIR/root.qcow2" "$want_bytes" || { STATUS="overlay create failed"; exit 1; }
truncate -s "${OUT_MB}M" "$RUN_DIR/out.raw"
genisoimage -quiet -R -l -iso-level 3 -V UKPAYLOAD -o "$RUN_DIR/payload.iso" "$PAYLOAD" || { STATUS="payload iso failed"; exit 1; }

b64() { base64 -w0 "$1"; }
printf 'UK_RUN_ID=%s\nUK_CMDLINE_EXTRA="%s"\nUK_ENSURE_BPF_LSM=%s\n' "$RUN_ID" "$CMDLINE_EXTRA" "$ENSURE_BPF_LSM" > "$RUN_DIR/run.env"
cat > "$RUN_DIR/uk-run.service" <<UNIT
[Unit]
Description=universal-kernel harness run driver
After=local-fs.target network.target
[Service]
Type=simple
ExecStart=$DRIVER_PATH
StandardOutput=journal+console
[Install]
WantedBy=multi-user.target
UNIT
PROVARGS=()
if [[ "$FLAVOR" == cloudinit ]]; then
cat > "$RUN_DIR/seed/user-data" <<UD
#cloud-config
write_files:
  - path: $DRIVER_PATH
    permissions: '0755'
    encoding: b64
    content: $(b64 "$VM_DIR/uk-driver.sh")
  - path: /etc/uk/run.env
    permissions: '0600'
    encoding: b64
    content: $(b64 "$RUN_DIR/run.env")
  - path: /etc/systemd/system/uk-run.service
    permissions: '0644'
    encoding: b64
    content: $(b64 "$RUN_DIR/uk-run.service")
runcmd:
  - [systemctl, daemon-reload]
  - [systemctl, enable, uk-run.service]
  - [systemctl, start, --no-block, uk-run.service]
UD
printf 'instance-id: uk-%s\nlocal-hostname: uk-%s\n' "$RUN_ID" "$DISTRO" > "$RUN_DIR/seed/meta-data"
genisoimage -quiet -V cidata -J -R -o "$RUN_DIR/seed.iso" "$RUN_DIR/seed/user-data" "$RUN_DIR/seed/meta-data" || { STATUS="seed iso failed"; exit 1; }
PROVARGS=(-drive "if=none,id=seed,file=$RUN_DIR/seed.iso,format=raw,readonly=on" -device virtio-blk-pci,drive=seed,serial=ukseed)
else
python3 -I - "$VM_DIR/uk-driver.sh" "$RUN_DIR/run.env" "$RUN_DIR/uk-run.service" "$DRIVER_PATH" > "$RUN_DIR/config.ign" <<'PY' || { STATUS="ignition config failed"; exit 1; }
import base64, json, sys
drv, env, unit, path = sys.argv[1:5]
src = lambda f: {"source": "data:;base64," + base64.b64encode(open(f, "rb").read()).decode()}
print(json.dumps({"ignition": {"version": "3.3.0"},
  "storage": {"files": [{"path": path, "mode": 0o755, "contents": src(drv)}, {"path": "/etc/uk/run.env", "mode": 0o600, "contents": src(env)}]},
  "systemd": {"units": [{"name": "uk-run.service", "enabled": True, "contents": open(unit).read()}]}}))
PY
PROVARGS=(-fw_cfg "name=opt/org.flatcar-linux/config,file=$RUN_DIR/config.ign")
fi

NETARGS=(-nic none)
(( NET )) && NETARGS=(-nic "user,model=virtio-net-pci")

# ---- boot --------------------------------------------------------------
QSTART="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
qemu-system-x86_64 \
  -name "uk-$DISTRO-$RUN_ID" "${MACHINE[@]}" -smp "$CPUS" -m "$MEM_MB" \
  -nodefaults -display none -no-user-config \
  -serial "file:$OUTDIR/console.log" \
  -device VGA -device virtio-rng-pci \
  -drive "if=none,id=root,file=$RUN_DIR/root.qcow2,format=qcow2,cache=unsafe,discard=unmap" -device virtio-blk-pci,drive=root,bootindex=0 \
  "${PROVARGS[@]}" \
  -drive "if=none,id=payload,file=$RUN_DIR/payload.iso,format=raw,readonly=on" -device virtio-blk-pci,drive=payload,serial=ukpayload \
  -drive "if=none,id=out,file=$RUN_DIR/out.raw,format=raw,cache=unsafe" -device virtio-blk-pci,drive=out,serial=ukout \
  "${NETARGS[@]}" \
  > "$OUTDIR/qemu.log" 2>&1 &
QPID=$!
STATUS="guest running"
deadline=$(( $(date +%s) + TIMEOUT ))
while kill -0 "$QPID" 2>/dev/null; do
  if (( $(date +%s) >= deadline )); then
    TIMED_OUT=1; STATUS="TIMEOUT after ${TIMEOUT}s (qemu pid $QPID killed)"; RC=124
    exit 124
  fi
  sleep 1
done
wait "$QPID"; qrc=$?
QPID=""
if (( qrc != 0 )); then STATUS="qemu exited $qrc (see qemu.log)"; RC=1; exit 1; fi

mkdir -p "$OUTDIR/guest"
if ! tar -xf "$RUN_DIR/out.raw" -C "$OUTDIR/guest" --no-same-owner --no-same-permissions 2>"$OUTDIR/untar.err"; then
  STATUS="guest powered off without writing results"; RC=1; exit 1
fi
[[ -s "$OUTDIR/untar.err" ]] || rm -f "$OUTDIR/untar.err"
drc="$(gf driver.exit)"
if [[ ! "$drc" =~ ^[0-9]+$ ]]; then STATUS="guest results incomplete (no driver.exit)"; RC=1; exit 1; fi
STATUS="$(gf driver.status)"
if (( ENSURE_BPF_LSM )) && [[ ",$(gf lsm.txt)," != *,bpf,* ]]; then STATUS="bpf LSM not active: $STATUS"; RC=96; exit 96; fi
RC="$drc"
exit "$RC"
