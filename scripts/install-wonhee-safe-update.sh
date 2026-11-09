#!/usr/bin/env bash
# Official in-place upgrade only. Never uninstalls or changes phone networking.
set -euo pipefail
umask 077
fail() { echo "UPDATE REFUSED: $*" >&2; exit 1; }
pkg=com.yooshastan.wonheeproxy
apk="\${1:-dist/wonhee-proxy-official-signed.apk}"
[[ -s "$apk" ]] || fail "Signed official APK missing: $apk"
[[ -z "\${WONHEE_SKIP_SAFE_STOP:-}" ]] || fail "Safe Stop bypass not supported."
command -v adb >/dev/null || fail "adb unavailable."
sdk="\${ANDROID_SDK_ROOT:-\${ANDROID_HOME:-$HOME/Android/Sdk}}"
[[ -d "$sdk/build-tools" ]] || fail "Android SDK Build Tools unavailable."
tools_dir=""
while read -r ver; do
    d="$sdk/build-tools/$ver"
    if [[ -x "$d/apksigner" && -x "$d/aapt" ]]; then tools_dir="$d"; break; fi
done < <(find "$sdk/build-tools" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -Vr)
[[ -n "$tools_dir" ]] || fail "Need aapt and apksigner."
adb_cmd=(adb)
if [[ -n "\${ANDROID_SERIAL:-}" ]]; then
    adb_cmd+=(-s "$ANDROID_SERIAL")
else
    mapfile -t devices < <(adb devices | awk 'NR>1 && $2=="device" {print $1}')
    [[ \${#devices[@]} -eq 1 ]] || fail "Require exactly one authorized device or ANDROID_SERIAL."
    adb_cmd+=(-s "\${devices[0]}")
fi
[[ "$("\${adb_cmd[@]}" get-state)" == device ]] || fail "ADB device unavailable."
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
installed="$("\${adb_cmd[@]}" shell pm path "$pkg" | tr -d '\r' |
    sed -n 's/^package://p' | grep '/base.apk$' | head -n 1)"
[[ -n "$installed" ]] || fail "Official Wonhee app not installed."
"\${adb_cmd[@]}" pull "$installed" "$tmp/current.apk" >/dev/null ||
    fail "Cannot inspect installed APK."
fingerprint() {
    "$tools_dir/apksigner" verify --verbose --print-certs "$1" |
        sed -n 's/^Signer #1 certificate SHA-256 digest: //p' |
        tr -d ':[:space:]' | tr '[:upper:]' '[:lower:]'
}
old_cert="$(fingerprint "$tmp/current.apk")" || fail "Cannot verify installed signer."
new_cert="$(fingerprint "$apk")" || fail "Cannot verify candidate signer."
[[ "$old_cert" =~ ^[0-9a-f]{64}$ && "$old_cert" == "$new_cert" ]] ||
    fail "Official APK signer mismatch; never uninstall to bypass this."
[[ "$new_cert" == db8a1ea62938be4fd37b10c3ea9ce1130f81603984cc775f753fd6f6fed07573 ]] ||
    fail "Signer differs from the verified official Wonhee certificate."
meta() { "$tools_dir/aapt" dump badging "$1" | sed -n '1p'; }
old_meta="$(meta "$tmp/current.apk")" || fail "Cannot inspect installed package."
new_meta="$(meta "$apk")" || fail "Cannot inspect candidate package."
[[ "$old_meta" == "package: name='$pkg' "* &&
   "$new_meta" == "package: name='$pkg' "* ]] || fail "Wrong Android package."
vcode() { sed -n "s/.*versionCode='\([0-9][0-9]*\)'.*/\1/p" <<< "$1"; }
old_v="$(vcode "$old_meta")"
new_v="$(vcode "$new_meta")"
[[ "$old_v" =~ ^[0-9]+$ && "$new_v" =~ ^[0-9]+$ ]] ||
    fail "Invalid app version metadata."
(( 10#$new_v > 10#$old_v )) || fail "A strictly higher versionCode is required."
root_read() { "\${adb_cmd[@]}" shell "su -c '$1'" | tr -d '\r'; }
audit_clean() {
    local links rules4 rules6 fw4 fw6 net family
    [[ "$(root_read 'id -u')" == 0 ]] || fail "Root inventory unavailable."
    links="$(root_read 'ip -o link show')" || fail "Cannot audit interfaces."
    if grep -Eq '^[[:space:]]*[0-9]+: (wnm[[:alnum:]_-]+|wnhome0|wnair0)(@[^:]*)?:' <<< "$links"; then
        fail "Wonhee kernel tunnel still exists. Use in-app Safe Stop before installing."
    fi
    rules4="$(root_read 'ip -4 rule show')" || fail "Cannot audit IPv4 policy rules."
    rules6="$(root_read 'ip -6 rule show')" || fail "Cannot audit IPv6 policy rules."
    if grep -Eq '(^|[[:space:]])12[567][0-9]{2}:' <<< "$rules4"$'\n'"$rules6"; then
        fail "Reserved Wonhee routing rule priority remains (12500-12799)."
    fi
    fw4="$(root_read 'iptables-save')" || fail "Cannot inventory IPv4 firewall."
    fw6="$(root_read 'ip6tables-save')" || fail "Cannot inventory IPv6 firewall."
    if grep -Eqi 'WN_|WN-MULTI' <<< "$fw4"$'\n'"$fw6"; then
        fail "Wonhee firewall signatures remain; no update allowed."
    fi
    for family in udp udp6 tcp tcp6; do
        net="$(root_read "cat /proc/net/$family")" || fail "Cannot audit $family sockets."
        if awk 'NR>1 {split($2,a,":"); if (toupper(a[2])=="D11F") found=1}
                END {exit !found}' <<< "$net"; then
            fail "DNS relay port 53535 remains bound ($family)."
        fi
    done
    echo "PASS: no Wonhee links, reserved routing rules, WN_ firewall entries or DNS port 53535."
}
echo "Certificate matches installed official Wonhee; versionCode $old_v -> $new_v."
echo "FIRST use Advanced -> Prepare for app update -> Safe Stop + verify (select all active tunnels)."
audit_clean
[[ -t 0 ]] || fail "No unattended updates; interactive confirmation required."
read -r -p 'Type UPDATE after checking the in-app Safe Stop report: ' choice
[[ "$choice" == UPDATE ]] || fail "Cancelled; nothing installed."
audit_clean
"\${adb_cmd[@]}" install -r "$apk" || fail "Android refused the update; no uninstall attempted."
echo "Update installed. Check profiles/settings before restarting tunnels and DNS."