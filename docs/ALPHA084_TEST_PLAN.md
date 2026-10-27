# Wonhee Proxy Alpha 0.8.4 — Combined Reliability Test Plan

**Draft preview only.** Automation does not prove that DNS, IPv6 or all app traffic is leak-free. Do not market these checks as a firewall or independent kill switch.

## Automated / CI

- Standalone DNS preset and passive Connection Health summary tests pass.
- Both Android workflows build versionCode 12 and produce an Alpha 0.8.4 debug APK.
- Manual signed-release workflow requires five confidentially provisioned signing secrets, including the expected certificate fingerprint. The workflow must fail closed if any secret is absent or the APK's certificate fingerprint differs.
- No release signing material is committed to Git, printed in a diagnostic report, or uploaded as an artifact.

## Device tests (Pixel 8a; optionally Samsung A36)

1. Privately back up all original WireGuard .conf files and proxy credentials. GitHub CI debug APKs have unstable signatures and may not upgrade in place. **Do not uninstall your working app without a migration plan.**
2. Verify Alpha 0.8.3 saved VPN profiles, routing mode and DNS presets are present in Alpha 0.8.4 on a compatible in-place upgrade.
3. With VPN off, Connection Health must show Interface DOWN, no active handshake, and the actual Android Always-on and Block outside VPN hints. The Run Test button must be disabled.
4. Connect using the working All Internet mode and DNS preset. Connection Health should report Interface UP and fresh handshake **only when peer statistics support it**, plus DNS configured but **not tested**.
5. Tap Run DNS & HTTPS test. Confirm the consent dialog discloses a DNS lookup and one HTTPS HEAD request to example.com. Cancel: no active probe should run.
6. Run the test. A valid Android VPN Network must be present; DNS and HTTPS should be explicitly bound to it. Record the result separately from the local dashboard. If no VPN network is visible, the test should report unavailable/inconclusive without falling back to cellular or Wi-Fi.
7. Test with a deliberately unreachable DNS resolver (if compatible with routing): expect a DNS failure. Restore the working DNS preset before continuing.
8. Disable or interrupt network access with Android Block outside VPN enabled; confirm the browser stops and the test does not report unprotected internet as VPN success. Reconnect and retest.
9. Force-stop, reopen, then reboot. Verify saved preferences remain and Android Always-on restores the tunnel where the OS allows. Test Ultgram independently.
10. During a cell/Wi-Fi transition, observe handshake age and retry the explicit probe. A tunnel interface being UP must not be presented as proof of internet connectivity.
11. Check that diagnostics never display WireGuard private keys, proxy secrets, complete imported configurations or internal backend exception text.

## Gateway and packet-level validation still required for a security claim

- Watch Fedora wg0 and actual external interface while intentionally running the test. A VPN network hint and successful HTTPS request are **not** a traffic/DNS leak audit.
- Verify actual NAT, firewall and DNS forwarding rather than inferring from handshake bytes.
- Test IPv4, IPv6, system resolver and app-specific DoH/DoT separately.
- Do not assume DNS preset selection encrypts the gateway-to-public-resolver segment.

## Release signing migration

1. Generate and privately back up a long-lived keystore; add all five secrets described in docs/SIGNING.md. Never paste key bytes, passwords or the base64 keystore into chat or an issue.
2. Run workflow_dispatch on the approved branch and verify the resulting release APK plus checksum.
3. Build a second signed APK with the same identity; confirm its signing fingerprint matches the pinned value.
4. On a test installation signed with the **same release key**, install a higher versionCode using adb install -r and confirm the encrypted profile survives.
5. Treat upgrading an ephemeral debug-signed installation to the new release key as a separate migration. That transition cannot preserve installed app data via ordinary in-place update when signatures differ.

## Acceptance

- Same saved tunnel and DNS settings behave as in Alpha 0.8.3.
- Passive health text is accurate and does not overclaim.
- Active diagnostics require explicit opt-in, never silently fall back to another network and have bounded HTTPS connect/read timeouts.
- Release artifact upload requires a matching pinned signing certificate. First debug-to-release migration limitation is documented.
