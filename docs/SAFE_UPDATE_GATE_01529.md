# Wonhee 0.15.29 — Safe Update gate and interrupted-update triage

## Why this is necessary

A real 0.15.28 **in-place APK replacement** took place without first using Batch H.1 Safe Stop. Both root WireGuard interfaces remained available afterwards; DNS/ad-blocking required separate manual intervention, and “Verify + recover matching routing rules” did not work. **Tunnel continuity alone does not prove DNS protection or a safe update.** Android's Package Manager replaces an APK independently of the app's native kernel interfaces and root DNS process. The app cannot intercept or veto arbitrary `adb install -r`/external store operations.

### Supported update path (new)

1. In the existing installed official Wonhee app open **Advanced connection controls**. Select **every currently active Wonhee profile** (e.g. both Home and Internet). Tap **Prepare for app update · Safe Stop + independent verification**.
2. Confirm. This calls the existing identity-verified Batch H.1 Safe Stop: opt-out recovery intent, exact DNS firewall removal and relay shutdown, exact split-rule cleanup, identity-verified WireGuard link stop. Failure **stops** the attempt without flushing unrelated firewall state.
3. Only on success, a second read-only root lifecycle audit must return **CLEAN_STOPPED**, not merely RUNNING_OR_PARTIAL, REPAIRABLE_STOPPED or BLOCKED_UNKNOWN. If it is not clean, **DO NOT UPDATE**. Record the stage and use appropriate owned-rule audits.
4. On Fedora, use the **official, permanent-certificate-signed** APK and `bash scripts/install-wonhee-safe-update.sh dist/wonhee-proxy-official-signed.apk`, **not** unguarded `adb install -r`. It:
   - pulls the installed official APK read-only and verifies its certificate and package,
   - rejects non-matching signers (pinned official SHA-256) or a non-increasing versionCode,
   - checks `su` works and independently checks absence of `wnm*`/legacy WireGuard links, reserved IPv4/IPv6 rule priorities 12500–12799, all `WN_` IPv4/IPv6 firewall signatures, and any local TCP/UDP binding on port 53535;
   - refuses when an inspection command is unavailable or has an error;
   - requires explicit human confirmation and **rechecks immediately before** issuing `adb install -r`.
5. Reopen Wonhee. Before reconnecting, confirm profiles, imported local tracker blocklist and saved settings remain. Then start the full stack and rerun live DNS firewall/relay audit, local `dig` control and physical-interface PCAP comparison.

**Important limits:** This is the supported *app button + Fedora installer* update path. Third-party store installers, manual `adb install`, and Android OS package updates still bypass this script; Android offers no ordinary app-wide global pre-update veto. The installer checks live kernel state, not the app-private persisted ownership ledger: the in-app second audit adds that ledger requirement. TOCTOU remains possible if another actor restarts tunnels between the independent check and install. The all-traffic Batch F kill switch stays paused. Root permissions must never be used to disable Android package signature verification.

## Read-only triage for a missed Safe Stop

**Do not uninstall, re-sign, clear data, force-close app as a cleanup substitute, flush iptables, delete arbitrary policy rules, or run `ip link del` on a live tunnel.** This can strand routing/DNS or lose encrypted profiles. If networking currently works, keep USB ADB connected while identifying exact ownership.

These diagnostics only inspect the kernel. Run from Fedora; do not paste WireGuard secrets or entire profile files into issues:

```sh
adb shell "su -c 'ip -o link show'"
adb shell "su -c 'ip -4 rule show; ip -6 rule show'"
adb shell "su -c 'iptables -t nat -S OUTPUT; iptables -S OUTPUT; ip6tables -t nat -S OUTPUT; ip6tables -S OUTPUT'"
adb shell "su -c 'ss -lun | grep 53535 || true'"
```

If roots/kernel interfaces are live, use **Safe Stop complete Wonhee stack** with every active profile selected before trying *stopped-state* repair; that repair is intentionally blocked when any tunnel is UP. **“Verify + recover matching routing rules” is NOT a generic DNS restart or update-recovery button**: it only adopts a missing split-rule rollback ledger if exact kernel rules and saved public keys match.

If Safe Stop refuses, record its exact `SAFE STOP PAUSED [STAGE]` reason. Try read-only **Audit interrupted startup/shutdown** and **Audit orphaned DNS firewall** and **Audit live DNS firewall + relay**; do not blindly change rules. The “Emergency owned DNS disable” action is only appropriate when Wonhee still has a verified matching DNS ownership record. Orphan DNS repair is a separately confirmed exact-only operation and does not restore protection; it can allow unfiltered traffic. Do not use it unless the actual orphan audit proves its narrow preconditions. Ask for review rather than disabling a VPN firewall on the assumption that its tags are safe to remove.

Keep Android Private DNS OFF on this tested phone because other settings have broken Wi-Fi. For Brave, manual browser Secure DNS OFF was necessary to get expected local DNS coverage; neither setting is modified by Wonhee.

## Acceptance tests

- The app reports **UPDATE BLOCKED** when any tunnel remains up, active relay or owned DNS rules are not removable, root cannot be inspected, ownership is unknown, or cleanup is partial.
- An actual successful Safe Stop + second audit produces CLEAN_STOPPED, without changing unrelated firewall chains.
- The installer refuses an APK signed with the temporary debug rootlab certificate, a different package ID, an old/equal versionCode, absent root permissions, active Wonhee link, reserved route, WN firewall signature, DNS socket, or missing inspection tool.
- The installer never runs unattended, never uninstalls, never writes Android settings, and checks the kernel again after user confirmation.
- On a signed upgrade, no saved profiles or local hosts list disappear, and both Home and Internet tunnels + local encrypted DNS/tracker filtering restart only when explicitly requested by the user.
- No guarantee that a user cannot manually call `adb install -r` outside this supported workflow.

Related: PR #63 (0.15.28 DNS coverage), PR #64 (permanent signed candidate), incident #41 (paused Batch F firewall).