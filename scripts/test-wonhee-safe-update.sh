#!/usr/bin/env bash
# Fail-closed installer tests with fake adb/aapt/apksigner; no real device/install.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin" "$work/sdk/build-tools/35"
printf 'fake candidate' > "$work/new.apk"
printf 'fake installed' > "$work/old.apk"
cat > "$work/bin/adb" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "-s" ]]; then shift 2; fi
case "$1" in
  get-state) echo device ;;
  shell)
    case "${*:2}" in
      "pm path com.yooshastan.wonheeproxy") echo 'package:/data/app/base.apk' ;;
      "su -c 'id -u'") echo "${WN_MOCK_ROOT:-0}" ;;
      "su -c 'ip -o link show'")
        echo '1: lo: <LOOPBACK>'
        [[ -z "${WN_MOCK_LINK:-}" ]] || echo "$WN_MOCK_LINK" ;;
      "su -c 'ip -4 rule show'") echo "${WN_MOCK_RULE:-0: from all lookup local}" ;;
      "su -c 'ip -6 rule show'") echo '0: from all lookup local' ;;
      "su -c 'ip -4 route show table all'") echo "${WN_MOCK_PRIVATE_ROUTE:-}" ;;
      "su -c 'ip -6 route show table all'") echo '' ;;
      "su -c 'if [ -f /data/user/0/com.yooshastan.wonheeproxy/shared_prefs/wonhee_isolated_bootstrap_ownership_v1.xml ]; then echo exists; else echo absent; fi'")
        [[ -z "${WN_MOCK_JOURNAL_XML:-}" ]] && echo absent || echo exists ;;
      "su -c 'cat /data/user/0/com.yooshastan.wonheeproxy/shared_prefs/wonhee_isolated_bootstrap_ownership_v1.xml'")
        if [[ -f "${WN_MOCK_JOURNAL_XML:-}" ]]; then
          cat "$WN_MOCK_JOURNAL_XML"
        else
          echo 'missing journal' >&2
          exit 1
        fi ;;

      "su -c 'if [ -f /data/user/0/com.yooshastan.wonheeproxy/shared_prefs/wonhee_isolated_uid_ownership_v1.xml ]; then echo exists; else echo absent; fi'")
        [[ -z "${WN_MOCK_UID_JOURNAL_XML:-}" ]] && echo absent || echo exists ;;
      "su -c 'cat /data/user/0/com.yooshastan.wonheeproxy/shared_prefs/wonhee_isolated_uid_ownership_v1.xml'")
        if [[ -f "${WN_MOCK_UID_JOURNAL_XML:-}" ]]; then
          cat "$WN_MOCK_UID_JOURNAL_XML"
        else
          echo 'missing uid journal' >&2
          exit 1
        fi ;;
      "su -c 'iptables-save'") echo "${WN_MOCK_FIREWALL:-*filter}" ;;
      "su -c 'ip6tables-save'") echo '*filter' ;;
      "su -c 'cat /proc/net/udp'")
        echo ' sl local_address rem_address st'
        [[ -z "${WN_MOCK_DNS_SOCKET:-}" ]] ||
          echo ' 1: 0100007F:D11F 00000000:0000 07' ;;
      "su -c 'cat /proc/net/udp6'") echo ' sl local_address rem_address st' ;;
      "su -c 'cat /proc/net/tcp'") echo ' sl local_address rem_address st' ;;
      "su -c 'cat /proc/net/tcp6'") echo ' sl local_address rem_address st' ;;
      *) echo "Unknown read-only mock command: $2" >&2; exit 2 ;;
    esac ;;
  pull) cp "${WN_MOCK_OLD_APK:?}" "$3" ;;
  install) touch "${WN_MOCK_INSTALL_MARKER:?}" ;;
  *) echo "Unrecognized mock adb action" >&2; exit 2 ;;
esac
MOCK
cat > "$work/sdk/build-tools/35/apksigner" <<'MOCK'
#!/usr/bin/env bash
echo 'Signer #1 certificate SHA-256 digest: db8a1ea62938be4fd37b10c3ea9ce1130f81603984cc775f753fd6f6fed07573'
MOCK
cat > "$work/sdk/build-tools/35/aapt" <<'MOCK'
#!/usr/bin/env bash
if [[ "${*: -1}" == *current.apk ]]; then v=75; else v=76; fi
echo "package: name='com.yooshastan.wonheeproxy' versionCode='$v' versionName='test'"
MOCK
chmod +x "$work/bin/adb" "$work/sdk/build-tools/35/apksigner" "$work/sdk/build-tools/35/aapt"
export PATH="$work/bin:$PATH" ANDROID_SERIAL=mock-device ANDROID_SDK_ROOT="$work/sdk"
export WN_MOCK_OLD_APK="$work/old.apk" WN_MOCK_INSTALL_MARKER="$work/installed"
testcase() {
    local expected="$1"
    shift
    rm -f "$WN_MOCK_INSTALL_MARKER"
    if env "$@" bash "$root/scripts/install-wonhee-safe-update.sh" "$work/new.apk" \
            </dev/null >"$work/report" 2>&1; then
        echo "UNSAFE: installer unexpectedly succeeded for $expected" >&2
        exit 1
    fi
    grep -Fq "$expected" "$work/report" || {
        echo "Expected error not found: $expected" >&2
        cat "$work/report" >&2
        exit 1
    }
    [[ ! -e "$WN_MOCK_INSTALL_MARKER" ]] || {
        echo "UNSAFE: install was invoked" >&2
        exit 1
    }
}
testcase "kernel tunnel still exists" WN_MOCK_LINK='5: wnma292ddb4b6da: <POINTOPOINT,UP>'
testcase "Reserved Wonhee routing rule" WN_MOCK_RULE='12500: from all lookup 201'
testcase "Reserved Wonhee routing rule" WN_MOCK_RULE='12800: from all iif lo uidrange 10341-10341 lookup 51000'
testcase "Wonhee firewall signatures remain" WN_MOCK_FIREWALL='-A OUTPUT -m comment --comment WN_DNS_TEST -j RETURN'
testcase "DNS relay port 53535 remains bound" WN_MOCK_DNS_SOCKET=1
testcase "Private multi-exit routing table 51000-51007 is not empty" \
  WN_MOCK_PRIVATE_ROUTE='unreachable default table 51000 metric 9999'
printf '<map><string name="pending_or_installed_steps_v1">WNI1|fake|0P</string></map>' > "$work/pending.xml"
testcase "Isolated multi-exit ownership is pending or unknown" \
  WN_MOCK_JOURNAL_XML="$work/pending.xml"
printf '<map><string name="pending_or_installed_steps_v1"></string></map>' > "$work/clean.xml"
testcase "interactive confirmation required" WN_MOCK_JOURNAL_XML="$work/clean.xml"
printf '<map><string name="pending_or_installed_steps_v1">broken' > "$work/corrupt.xml"
testcase "Isolated multi-exit ownership is pending or unknown" \
  WN_MOCK_JOURNAL_XML="$work/corrupt.xml"
printf '<map><string name="pending_or_installed_uid_rules_v1">WNUP1|fake|0A</string></map>' > "$work/uid_pending.xml"
testcase "Isolated UID policy ownership is pending or unknown" \
  WN_MOCK_UID_JOURNAL_XML="$work/uid_pending.xml"
printf '<map><string name="pending_or_installed_uid_rules_v1"></string></map>' > "$work/uid_clean.xml"
testcase "interactive confirmation required" \
  WN_MOCK_UID_JOURNAL_XML="$work/uid_clean.xml"
printf '<map><string name="pending_or_installed_uid_rules_v1">broken' > "$work/uid_corrupt.xml"
testcase "Isolated UID policy ownership is pending or unknown" \
  WN_MOCK_UID_JOURNAL_XML="$work/uid_corrupt.xml"


testcase "Root inventory unavailable" WN_MOCK_ROOT=2000
testcase "interactive confirmation required"
testcase "Safe Stop bypass not supported" WONHEE_SKIP_SAFE_STOP=1
echo 'test-wonhee-safe-update: all refusal cases PASS'
