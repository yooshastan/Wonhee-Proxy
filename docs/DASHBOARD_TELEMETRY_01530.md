# Wonhee 0.15.30 — Candy Pink dashboard telemetry preview

**Base:** tested official signed 0.15.29 (`feature/update-preflight-01529`, PR #65).
**Scope:** display-only dashboard, optional traffic notification controls and manual read-only DNS verification. No WireGuard backend, routing rules, DNS relay, tracker blocklist, kill switch, recovery, or Safe Stop changes.

## What changes

- The existing **Home / Profiles / Protection / Activity** Candy Pink dashboard preview now shows live **download/upload Mbps** from aggregate verified kernel WireGuard byte counters. First sample, profile-count transitions, stale (over one minute), decreasing counters and unavailable root verification all show **measuring/unavailable** instead of a fabricated rate.
- The existing DNS blocked-reply counter is visible on the Home dashboard when the active relay PID/statistics are verified. These are **local DNS replies**, not page ads or all trackers. Counters reset with relay lifetime.
- The same opt-in persistent notification can be enabled or disabled from Home or Activity, without searching advanced menus. Android 13+ notification permission is requested on explicit enable only. Notification is not Android's system VPN badge; foreground service restrictions may prevent visibility.
- Protection tab now makes local relay status distinct from proving encrypted upstream DNS or device-wide leak freedom, and provides a manual read-only checklist. **Android Private DNS stays OFF on this phone**, as Automatic/custom previously broke Wi-Fi.
- The launcher and proven Advanced Connect/Safe Stop controls remain unchanged. The new UI is a **preview**, not the default; no network mutations from preview.

## Acceptance plan on Pixel 8a / Axion Android 16

1. **Safety baseline:** Confirm signed 0.15.29 works with Home + AirVPN, Navidrome, DNS relay, 3/3 split routes, IPv4+IPv6 exit, Safe Stop and Safe Start. Do not update over active tunnels. Use the official signed local build and independently guarded installer after H.1 Safe Stop + H.2a CLEAN_STOPPED.
2. **UI:** Open `Preview new multi-connection dashboard` from the launcher or Advanced Controls. Test Home, Profiles (up to eight saved profiles), Protection, Activity. Ensure no imported profiles/settings are lost.
3. **Rates:** With two verified tunnels, wait for two 8-second samples. Transfer known data through AirVPN and access Navidrome over Home. Speeds should update, not claim device-wide totals; pause/resume and reconnect should show `measuring` before a new rate.
4. **Blocked counter:** With verified DNS ownership, relay and tracker filter, query a permitted domain and blocked domain through `dig @127.0.0.1 -p 53535 ...`. Confirm local lifetime count increases; block count displays `unavailable` or `off` if relay or filtering is not verified.
5. **Persistent notification:** Opt in on Home; verify Android notification permission and a low-priority status notification with down/up rates and blocked DNS total. Toggle off; confirm notification vanishes without disconnecting tunnels. Re-enable, Safe Stop, and ensure it disappears; Safe Start again and verify opt-in behavior. Do not confuse the app's own notification with Android VpnService.
6. **DNS/leaks:** Verify visible IPLeak IPv4/IPv6/WebRTC exits align with configured AirVPN, DNS leak test providers align with configured upstream (Cloudflare anycast IPs in several countries are not by themselves a leak), and browser Secure DNS settings are tested separately. For independent underlay evidence, use trusted capture on the physical interface; browser test scores alone do not establish full-device protection.
7. **Regression:** Confirm H.1 Safe Stop and H.2a CLEAN_STOPPED again before any later update, preserve exact DNS and split-route ledger ownership. Never enable Batch F kill switch without its own controlled test plan.

## Known limitations

- No full-device kill switch, Android VPN key icon or enforced fail-closed behavior is claimed by this preview.
- Rate sampling uses verified interface byte counters; it can differ from public-link throughput, especially with multiple tunnels. A rate transition can briefly show `measuring`.
- External DNS/IP-leak web tests are browser-specific and may be influenced by browser settings. DNS relay status alone does not prove encrypted upstream transport or all-app coverage.
- Foreground service availability/notification visibility vary by Android permission and background restrictions; opting in is not a guarantee the service is running.
- This branch is an unshipped candidate until signed APK, on-device smoke tests and owner review.
