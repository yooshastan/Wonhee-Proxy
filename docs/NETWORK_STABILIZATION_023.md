# Wonhee 0.23 — Networking stabilization acceptance gate

Status: feature freeze initiated; device acceptance pending. This is a test plan, not a release certificate.
Baseline: 0.22.3-native-protected-routing, debug versionCode 158, commit 9ca62b07a9ab3944748e79bdab2b246ef558d61d.
Android run 45824351349 and native run 45824351348 succeeded; signed release job skipped. Keep the native lab package and its saved profiles separate from the official signed app. Preserve Product Batch A–I mapping.

## P0 — device baseline before changing the engine
- [ ] Confirm installed version and existing signing/update identity; safe-stop the active lab session before updating. Never uninstall just to overcome a signing mismatch.
- [ ] Keep Android Private DNS OFF on the Pixel 8a; no unrelated AFWall+ or kernel rule changes.
- [ ] Connect Exit A, Exit B and optional Home with existing profiles; verify distinct peers and live traffic, not simply interface state.
- [ ] Use known-good Quad9 DoQ or a previously verified encrypted provider/transport as the control. Run Test active DNS provider, then Test TCP DNS and HOSTS with a usable imported list. Record authenticated result, TCP answer and HOSTS NXDOMAIN/block evidence separately; cached public answers do not prove upstream reachability.
- [ ] AdGuard DoT control; test AdGuard DoQ and experimental DoH3 separately only when safe to interrupt selected apps. Record endpoint choice, exit, QUIC handshake/tx/rx/TUN counters and provider result. Do not increase retry budget or auto-fallback. If repeated DoQ failure is confirmed, exclude that combination from the beta selector and reject stale configurations explicitly; preserve other transports.
- [ ] Verify two selected apps simultaneously use their intended independent public exits by actual external observations, and Moka reaches the configured private Navidrome destination through Home. Verify protocol TCP/UDP overrides, explicit DROP precedence, and no private destinations outside configured Home ranges.
- [ ] Audit IPv6 coverage explicitly. Current NativeAppRoutingPolicy packet parser is IPv4-only; check actual VPN route coverage and IPv6 bypass/block behavior. Do not describe IPv6 forwarding or protection as validated without packet evidence.
- [ ] Test unselected-app behavior separately: scoped VpnService does not imply device-wide protection. Document selection and Android lockdown limitations.
- [ ] Check LAN behavior and AFWall+ interoperability without blanket allow rules or disabling existing protections. Use independent USB ADB for recovery tests.

## P1 — next combined 0.23 test APK
Implement only evidenced regressions and explicit unsupported-mode gating; preserve imported profiles, package/signing continuity, strict resolver/no plaintext fallback, bounded caches/queues, and routing policy. Add regression tests for each change. Validate startup/stop, repeated DNS tests, app selection/route precedence, tunnel-specific traffic, DNS failure and UI health. Keep stable release variant unchanged. Use a single incremented preview version and one verified CI artifact once code changes warrant a build. No production kill-switch activation in this phase.

## Evidence and release boundaries
Record per-test PASS/FAIL/SKIPPED, build/commit, selected scope, network type and redacted observations. Avoid credentials, endpoints and DNS query payloads in public logs. CI success is not device acceptance. A failed tunnel/resolver must not cause silent direct Internet fallback for protected scope. Do not call the app leak-proof; crash/handoff/lockdown, exact-owned root cleanup and broader device coverage are separate Product C/F/G/I release gates. See #89 and #41. Do not advance to a signed public beta until these are resolved or unsupported features are clearly excluded.
