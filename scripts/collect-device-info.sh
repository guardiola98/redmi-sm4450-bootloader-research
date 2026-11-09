#!/usr/bin/env bash
# Read-only ADB baseline. No identifiers, account data, logcat, or raw dumps.
set -euo pipefail

if ! command -v adb >/dev/null 2>&1; then
  printf 'Error: adb is not installed.\n' >&2
  exit 1
fi

status="$(adb get-state 2>/dev/null || true)"
if [[ "$status" != "device" ]]; then
  printf 'Error: authorize exactly one device in ADB first.\n' >&2
  exit 1
fi

prop() {
  local label="$1" key="$2"
  printf '%-29s ' "$label"
  adb shell getprop "$key" | tr -d '\r'
}

printf '%s\n' '=== DEVICE ==='
prop 'Model:' 'ro.product.model'
prop 'Device:' 'ro.product.device'
prop 'Build:' 'ro.build.version.incremental'
prop 'Android version:' 'ro.build.version.release'
prop 'SoC:' 'ro.soc.model'
prop 'Board platform:' 'ro.board.platform'
printf '%s\n' '=== KERNEL ==='
adb shell uname -r | tr -d '\r'
printf '%s\n' '=== PATCH LEVELS ==='
prop 'Android patch:' 'ro.build.version.security_patch'
prop 'Vendor patch:' 'ro.vendor.build.security_patch'
printf '%s\n' '=== BOOT STATE ==='
prop 'Verified boot:' 'ro.boot.verifiedbootstate'
prop 'Flash locked:' 'ro.boot.flash.locked'
prop 'VBMeta device state:' 'ro.boot.vbmeta.device_state'
prop 'Active slot:' 'ro.boot.slot_suffix'
printf 'SELinux: '
adb shell getenforce | tr -d '\r'
printf '%s\n' '=== SELECTED KERNEL OPTIONS ==='
adb shell 'if [ -r /proc/config.gz ]; then zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_(BPF|KALLSYMS|KPROBES|SECURITY_SELINUX)=" || true; else echo "Kernel config unavailable"; fi' | tr -d '\r'
printf '\n%s\n' 'Done. Inspect output for any private information before sharing.'
