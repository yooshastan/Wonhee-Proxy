#!/usr/bin/env bash
# Read-only Pixel 8a / Android 16 isolated multi-exit readiness capture.
# NO route, iptables, WireGuard, DNS, profile or package modifications.
set -euo pipefail
adb_bin="${ADB:-adb}"
command -v "$adb_bin" >/dev/null || { echo 'ADB unavailable' >&2; exit 1; }
if [[ -n "${ANDROID_SERIAL:-}" ]]; then
  adb_cmd=("$adb_bin" -s "$ANDROID_SERIAL")
else
  mapfile -t phones < <("$adb_bin" devices | awk 'NR>1 && $2=="device" {print $1}')
  [[ ${#phones[@]} -eq 1 ]] || {
    echo 'Connect one authorized device or set ANDROID_SERIAL.' >&2
    exit 1
  }
  adb_cmd=("$adb_bin" -s "${phones[0]}")
fi

root_read() {
  "${adb_cmd[@]}" shell "su -c '$1'" 2>&1 | tr -d '\r'
}
section() {
  echo
  printf '===== %s =====\n' "$1"
}
section "DEVICE"
"${adb_cmd[@]}" shell getprop ro.product.model | tr -d '\r'
"${adb_cmd[@]}" shell getprop ro.build.version.release | tr -d '\r'
"${adb_cmd[@]}" shell uname -r | tr -d '\r'
section "ROOT"
root_read "id -u" || true
section "PRIVATE DNS (must remain OFF)"
"${adb_cmd[@]}" shell settings get global private_dns_mode | tr -d '\r'
section "ANDROID IP RULE SELECTORS (IPv4)"
root_read "ip -4 rule help 2>&1" | grep -Ei 'usage|SELECTOR|uidrange|fwmark|ipproto|dport|unreachable' || true
section "ANDROID IP RULE SELECTORS (IPv6)"
root_read "ip -6 rule help 2>&1" | grep -Ei 'usage|SELECTOR|uidrange|fwmark|ipproto|dport|unreachable' || true
section "ROUTE TYPES / UNREACHABLE SUPPORT (IPv4)"
root_read "ip -4 route help 2>&1" | grep -Ei 'usage|unreachable|blackhole|prohibit|metric|table' || true
section "ROUTE TYPES / UNREACHABLE SUPPORT (IPv6)"
root_read "ip -6 route help 2>&1" | grep -Ei 'usage|unreachable|blackhole|prohibit|metric|table' || true
section "ISOLATED KERNEL INTERFACES"
root_read "ip -o link show" | grep -E 'wnm[0-9a-f]{12}|wnhome0|wnair0' || true
section "WONHEE POLICY PRIORITY 12500-12999"
for family in 4 6; do
  echo "IPv$family"
  root_read "ip -$family rule show" |
    grep -E '^[[:space:]]*12[5-9][0-9]{2}:' || true
done
section "ISOLATED PRIVATE ROUTE TABLES 51000-51007"
for family in 4 6; do
  echo "IPv$family"
  root_read "ip -$family route show table all" |
    grep -E '(^|[[:space:]])table[[:space:]]+5100[0-7]([[:space:]]|$)' || true
done
section "PRE-EXISTING MANGLE OUTPUT CHAINS"
for binary in iptables ip6tables; do
  echo "$binary"
  root_read "$binary -t mangle -S OUTPUT" || true
done
section "ISOLATED OWNERSHIP JOURNAL EXISTS (content withheld)"
root_read "if [ -f /data/user/0/com.yooshastan.wonheeproxy/shared_prefs/wonhee_isolated_bootstrap_ownership_v1.xml ]; then echo PRESENT; else echo ABSENT; fi" || true
section "INSTALLED OFFICIAL APP"
"${adb_cmd[@]}" shell dumpsys package com.yooshastan.wonheeproxy |
  grep -E 'versionCode=|versionName=' | head -3 || true
echo
echo 'READ-ONLY AUDIT COMPLETE. This is NOT authorization to start isolated tunnels.'
echo 'No interfaces, routes, firewall rules, DNS settings or APKs were changed.'
