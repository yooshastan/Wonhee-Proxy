# Wonhee 0.15.44 — Dashboard reliability and diagnostics

Based on on-device 0.15.43 observations: two verified tunnels, active DNS relay, blocked total 2/22 (9.1%) after restart, and saved-baseline comparison detecting relay PID replacement.

## UI-only / read-only enhancements
- Condense the DNS **Protection** section to three essential statuses; technical routing, kill-switch and network caveats are visible behind an explicit details toggle.
- Display each saved tunnel independently under **Tunnels** with current interface presence, identity-verified/UP status, last handshake age, and cumulative RX/TX when valid. These use bounded read-only root WireGuard queries during the existing foreground eight-second snapshot. No per-tunnel live bitrate or end-to-end health is claimed.
- Keep recovery panel read-only and guide user to existing lifecycle/safe controls rather than automating changes.
- Detect within the current dashboard process whether a verified DNS relay PID changed, a blocked count decreased, or continuity is unknown. Never classify a restart as a failure without further evidence. Display current verified relay lifetime blocked counts and percent as before.
- Avoid duplicating caveat text above-the-fold while preserving explicit explanations and guard-safety status in details.

## Safety and privacy
No WireGuard tunnel creation, route mutation, firewall activation, DNS enforcement change, ad-block policy change, hidden background polling, packet capture, private endpoint/key export, automatic recovery, or RCS/IMS changes. Keep Android Private DNS OFF on the Pixel 8a. The all-traffic Batch F guard remains paused. A stale handshake may indicate idleness and must not trigger a kill switch.

## Verification
- [ ] Android compilation and native WireGuard workflows pass
- [ ] Dashboard visible-only polling stops on pause and no root failures cause crashes
- [ ] Tunnels tab presents stopped, unverified, counter-unavailable, and healthy cases accurately
- [ ] DNS details expansion persists in current Activity only; no settings mutated
- [ ] DNS PID replacement / counter reset / unknown relay labels tested against real snapshots
- [ ] Saved baseline, tracker blocking and DNS relay audits unchanged
- [ ] Original keystore signed local build; H.1 Safe Stop + H.2a CLEAN_STOPPED + guarded update only
