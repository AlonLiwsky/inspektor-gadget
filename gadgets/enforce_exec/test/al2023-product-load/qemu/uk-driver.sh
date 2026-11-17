#!/bin/bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
# Copied unchanged from the universal-kernel stock-kernel harness (vm/guest/uk-driver.sh).
# In-guest driver for the universal-kernel stock VM harness. Installed by
# cloud-init as /usr/local/sbin/uk-driver and run as root by uk-run.service
# on every boot of a run. It (1) applies requested kernel cmdline changes via
# the distro's grub tooling and reboots exactly once, (2) verifies them,
# (3) runs <payload>/run-in-guest.sh, (4) writes results as a tar stream to
# the output block device and powers off.
set -u
. /etc/uk/run.env   # UK_RUN_ID UK_CMDLINE_EXTRA UK_ENSURE_BPF_LSM
ST=/var/lib/uk/$UK_RUN_ID
OUT=/uk/out
mkdir -p "$ST" "$OUT" /uk/work /uk/payload
exec 9>"$ST/lock"; flock -n 9 || exit 0
[ -e "$ST/done" ] && exit 0
exec >>"$ST/driver.log" 2>&1
con() { echo "[uk-driver] $*"; echo "[uk-driver] $*" >/dev/ttyS0 2>/dev/null || echo "[uk-driver] $*" >/dev/console 2>/dev/null || true; }
dev() {  # find the virtio-blk device with the given serial (udev by-id link, else sysfs scan)
  local d=/dev/disk/by-id/virtio-$1 i b
  for i in $(seq 60); do
    [ -b "$d" ] && { echo "$d"; return 0; }
    for b in /sys/block/vd*; do
      [ "$(cat "$b/serial" 2>/dev/null)" = "$1" ] && [ -b "/dev/${b##*/}" ] && { echo "/dev/${b##*/}"; return 0; }
    done
    sleep 0.5
  done; return 1; }

facts() {
  uname -a >"$OUT/uname.txt"; uname -r >"$OUT/uname-r.txt"
  cat /proc/cmdline >"$OUT/cmdline.txt"
  cat /sys/kernel/security/lsm >"$OUT/lsm.txt" 2>/dev/null || echo "UNREADABLE" >"$OUT/lsm.txt"
  cp /etc/os-release "$OUT/os-release.txt" 2>/dev/null
  cat /sys/kernel/security/lockdown >"$OUT/lockdown.txt" 2>/dev/null
  (getenforce 2>/dev/null || echo "n/a") >"$OUT/selinux.txt"
  [ -e "$ST/cmdline-change" ] && cp "$ST/cmdline-change" "$OUT/cmdline-change.txt" || echo "none" >"$OUT/cmdline-change.txt"
  cp "$ST/lsm-before.txt" "$OUT/lsm-before.txt" 2>/dev/null
  cp "$ST/driver.log" "$OUT/driver.log" 2>/dev/null
}
emit() {  # write $OUT as a tar stream onto the output device
  local d; d=$(dev ukout) || { con "no output device"; return 1; }
  tar -C "$OUT" -cf "$d" . && sync
}
finish() {
  echo "$1" >"$OUT/driver.exit"; con "finish rc=$1 ($2)"; echo "$2" >"$OUT/driver.status"
  facts; dmesg >"$OUT/dmesg.txt" 2>/dev/null
  emit || { con "RESULT EMIT FAILED; driver log follows"; cat "$ST/driver.log" >/dev/ttyS0 2>/dev/null; }
  touch "$ST/done"; sync
  con "UK-DONE rc=$1"
  # Orderly shutdown so filesystems are unmounted cleanly (grub does not replay the XFS log;
  # a forced power-off made bootloader changes invisible on the next boot). Force as a fallback.
  systemctl poweroff 2>/dev/null || poweroff
  sleep 90; systemctl poweroff --force --force 2>/dev/null
  sleep 30; echo o >/proc/sysrq-trigger
}

con "start run=$UK_RUN_ID kernel=$(uname -r) boot_cmdline=$(cat /proc/cmdline)"
# Let cloud-init finish so a reboot never races its first-boot modules.
if command -v cloud-init >/dev/null 2>&1; then timeout 300 cloud-init status --wait >/dev/null 2>&1; con "cloud-init: $(cloud-init status 2>&1 | head -1)"; fi

LSM_NOW=$(cat /sys/kernel/security/lsm 2>/dev/null || true)
[ -e "$ST/lsm-before.txt" ] || echo "$LSM_NOW" >"$ST/lsm-before.txt"
WANT="$UK_CMDLINE_EXTRA"
if [ "$UK_ENSURE_BPF_LSM" = 1 ] && ! echo ",$LSM_NOW," | grep -q ',bpf,'; then
  case " $WANT " in *" lsm="*) ;; *)
    L=$(echo "$LSM_NOW" | tr ',' '\n' | grep -vx capability | paste -sd, -)
    WANT="$WANT lsm=${L:+$L,}bpf" ;;
  esac
fi
MISSING=""
for a in $WANT; do case " $(cat /proc/cmdline) " in *" $a "*) ;; *) MISSING="$MISSING $a" ;; esac; done
MISSING=${MISSING# }

if [ -n "$MISSING" ]; then
  if [ -e "$ST/rebooted" ]; then finish 97 "cmdline change did not take effect after reboot: missing '$MISSING'"; exit 0; fi
  con "cmdline change needed: $MISSING"
  echo "$MISSING" >"$ST/cmdline-change"
  if grep -Eq '^ID="?flatcar' /etc/os-release 2>/dev/null; then
    oem=/oem; [ -d /oem ] || oem=/usr/share/oem
    echo "set linux_append=\"\$linux_append $MISSING\"" >>$oem/grub.cfg; rc=$?; how=flatcar-oem-grub
  elif command -v grubby >/dev/null 2>&1; then
    grubby --update-kernel=ALL --args="$MISSING"; rc=$?; how=grubby
  elif command -v update-grub >/dev/null 2>&1; then
    mkdir -p /etc/default/grub.d
    echo "GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX $MISSING\"" >/etc/default/grub.d/99-uk.cfg
    update-grub; rc=$?; how=update-grub
  elif command -v grub2-mkconfig >/dev/null 2>&1; then
    sed -i "s|^GRUB_CMDLINE_LINUX=\"\(.*\)\"|GRUB_CMDLINE_LINUX=\"\1 $MISSING\"|" /etc/default/grub
    grub2-mkconfig -o /boot/grub2/grub.cfg; rc=$?; how=grub2-mkconfig
  else rc=1; how=none; fi
  echo "via $how rc=$rc" >>"$ST/cmdline-change"
  if [ $rc -ne 0 ]; then finish 98 "grub cmdline edit failed via $how"; exit 0; fi
  touch "$ST/rebooted"; sync; con "rebooting once to apply cmdline (via $how)"
  systemctl reboot; exit 0
fi

if [ "$UK_ENSURE_BPF_LSM" = 1 ] && ! echo ",$LSM_NOW," | grep -q ',bpf,'; then
  finish 96 "bpf LSM not active after cmdline change (lsm=$LSM_NOW); CONFIG_BPF_LSM likely unset"; exit 0
fi

P=$(dev ukpayload) && mount -o ro -t iso9660 "$P" /uk/payload || { finish 95 "cannot mount payload"; exit 0; }
[ -f /uk/payload/run-in-guest.sh ] || { finish 94 "payload has no run-in-guest.sh"; exit 0; }
facts; echo "running" >"$OUT/driver.status"; emit   # early facts survive a later timeout
con "kernel=$(uname -r) lsm=$LSM_NOW cmdline=$(cat /proc/cmdline)"
con "payload start"
cd /uk/work
UK_OUT=$OUT UK_PAYLOAD=/uk/payload UK_WORK=/uk/work bash /uk/payload/run-in-guest.sh </dev/null 2>&1 | tee "$OUT/payload.log" >/dev/ttyS0
prc=${PIPESTATUS[0]}
echo "$prc" >"$OUT/payload.exit"
con "payload exit=$prc"
finish "$prc" "payload exited $prc"
