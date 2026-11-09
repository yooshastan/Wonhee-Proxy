# Wonhee 0.15.25 — Batch H.2c: DNS listener lifecycle

## Observed failure

Pixel 8a audit after interrupted DNS cleanup: all tagged IPv4/IPv6 DNS OUTPUT rules were absent, HOME split priorities were gone, WireGuard interfaces were DOWN, but /proc/net/udp still showed a UDP 127.0.0.1:53535 listener (0100007F:D11F). A full uninstall had also occurred during the previous session.

Existing DNS stop logic sent a SIGTERM to the exactly recorded relay PID but cleared its ownership ledger without proving that the listener had closed. Starting another DNS helper also did not check whether the local port was already in use before preparing the native binary. This could produce false success or a second helper competing with an orphan process.

## H.2c changes

1. New read-only UDP loopback listener inventory checks /proc/net/udp; missing kernel inventory is a refusal.
2. Full-stack startup preflight and independent root DNS activation/diagnostic refuse an already occupied port 53535 *before* writing a helper binary or changing tunnels.
3. The native helper stop operation still requires an exact executable/PID identity; it now verifies BOTH that process identity has exited and the UDP listener has disappeared before returning success.
4. Owned DNS Disable, coordinated Safe stop, and activation failure rollback require the listener to be absent before clearing the owned DNS ledger. The record is retained on incomplete shutdown.
5. Owned/empty-ledger DNS audits include current firewall tag count and port listener presence, rather than using an empty SharedPreferences value as proof that enforcement is stopped.
6. Main orphan DNS audit explicitly identifies an occupied listener, even with zero WN_ firewall rules.

This does not enable the paused Batch F all-traffic kill switch or change firewall rules automatically.

## Device acceptance test (Pixel 8a, rooted Android 16)

- Preserve the original release-signing keystore and a separate encrypted backup; the next APK must use the same certificate and official package ID with a higher versionCode.
- Stop any active protected session using the existing Safe stop control, then verify no WN DNS OUTPUT tags, no priority-12500+ routes and both WG interfaces DOWN. Avoid installing while root DNS enforcement is active.
- BEFORE startup, inspect /proc/net/udp for 0100007F:D11F. If present, do NOT kill an arbitrary PID or start the VPN. Identify its owner with read-only /proc fd and executable checks.
- Install the locally signed official 0.15.25 APK as an in-place update. Do not uninstall and do not install a debug rootlab APK over the official package.
- With port free, Start full stack. Verify both HOME/AirVPN tunnels, correct split routing and DNS interception, encrypted DNS health and tracker filtering.
- Safe stop full stack. Verify absent UDP listener, no WN tags and no 125xx routing priorities; confirm selected WG links DOWN.
- Repeat start/stop once more. Run DNS enforcement audit and Orphan DNS audit while stopped. They should both report no enforcement and no listener.
- Deliberate orphan listener, SIGTERM failure and process-uninstall simulations belong on a spare rooted device/emulator, never the daily phone.
- If a listener remains after a stop failure, the ledger must remain recorded and the app must refuse to report complete. Do not flush unrelated firewall chains.

## Limitations

The port check proves only local UDP 53535 listener presence/absence; it does not prove upstream connectivity, detect browser DoH 443 or establish a network-wide fail-closed guarantee. A deleted or replaced executable cannot be safely identified by process name alone. If process/socket ownership is uncertain, require a read-only audit and explicit remediation.
