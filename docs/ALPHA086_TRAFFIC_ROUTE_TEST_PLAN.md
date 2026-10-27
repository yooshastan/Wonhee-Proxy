# Wonhee Proxy Alpha 0.8.6 — Traffic graph & route observations

**Development preview only.** Nothing here enables packet capture, probes the
internet automatically, changes your Fedora gateway, enforces DNS, or proves
an absence of IPv4/IPv6/DNS leaks. Keep Android Always-on and lockdown settings
unchanged while testing.

## Live WireGuard traffic chart

1. Install a test APK with a compatible signing certificate. If an existing
   debug APK has a different signer, **first back up private .conf files and
   proxy credentials**. Never paste keys into a bug report.
2. Connect a known-good VPN profile. The existing 0.8.5 silent throughput
   notification should continue to behave as before.
3. On the main VPN screen, look for **LIVE TUNNEL TRAFFIC**. The first sample
   is only a baseline. After approximately five seconds, rates and graph
   points should appear. Blue = download, pink = upload.
4. Download a large file, then stop traffic. Confirm rising/falling lines,
   download/upload direction, display units (Kbps/Mbps), and peaks.
5. Rotate/leave/return and reconnect. Live history must reset on backgrounding,
   disconnect or counter reset; no absurd speed spikes or negative rates.
6. Leave the screen open with the VPN active for several minutes. The plot is
   bounded to 24 samples (~2 minutes) and must not consume unbounded memory.
7. Confirm it never shows WireGuard keys, peer endpoints, SSIDs, or host IPs.
8. Disconnect while permitted; chart resets. The 0.8.5 notification must stop.
   Check force-stop, Always-on reconnect and lockdown separately.

## First-run tunnel notification permission (Android 13+)

1. On a fresh install with notifications not yet granted, open the VPN dashboard.
   Confirm a contextual explanation offers **Continue** and **Not now**.
   Continue should open Android's **Allow notifications** system prompt.
2. Allow: the dashboard says notifications are enabled; start the VPN and verify
   the silent live RX/TX notification updates.
3. Deny or tap Not now: VPN connection, DNS choices and Always-on must still
   function; the dashboard shows a clear **Enable tunnel notifications** action.
4. On denial, use the in-app action to retry when Android permits it; if the
   system no longer offers a prompt, it opens this app's notification settings.
   Return to the app after enabling and verify the status refreshes.
5. Upgrade from a version that had the old saved "already asked" flag.
   If notifications are still denied, the new on-boarding path and dashboard
   action must not be suppressed by that legacy flag.
6. Android 12 and earlier should not request POST_NOTIFICATIONS.
7. If notification permission was already granted before updating, the app
   should not prompt again. No permission path should transmit network data.

## Opt-in connection diagnostics

1. With the tunnel connected, open **CONNECTION HEALTH** and run the existing
   user-approved DNS & HTTPS test. Confirm its permission dialog still appears.
2. Verify the result begins with Android **reported** VPN-route observations:
   IPv4 default route, IPv6 default route, and DNS server count.
3. For imported-profile or Home/split mode, missing default routes can be
   intentional; do not label a split-tunnel configuration a leak automatically.
4. For full-internet mode, both IPv4 and IPv6 default routes may be reported.
   Their presence only reflects local LinkProperties, not external traffic egress.
5. The DNS and HTTPS network calls must remain explicitly bound to the sole
   Android VPN Network. No network requests occur when no VPN or when several
   ambiguous VPN networks are observed.
6. With no DNS configured, report zero and do not make a network request.
7. Test offline/bad DNS/Fedora gateway unavailable safely, keeping Android
   lockdown enabled. Failures should read **FAILED/INCONCLUSIVE**, not "safe".
8. To claim no leaks in future, collect separate phone-edge, VPN-inner and
   external/gateway packet captures for both IPv4 and IPv6. These source-level
   tests do not substitute for independent network evidence.

## Regression and release gate

- Existing profile encryption, routing mode, DNS presets, Always-on restore,
  0.8.5 notification and Ultgram proxy tools should remain unchanged.
- GitHub CI builds Android APK and runs standalone Java tests for traffic
  calculations, bounded history and route wording.
- Never publish Alpha 0.8.6 as a signed release until the maintainer signs
  with the persistent **same** certificate and device regressions pass.
