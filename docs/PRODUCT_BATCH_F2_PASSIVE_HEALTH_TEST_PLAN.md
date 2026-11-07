# Wonhee 0.15.14 — Batch F.2 passive health snapshots

Status: **draft / diagnostic-only**. Builds upon the user's installed and initially stable 0.15.13.1 (Batch F.1) configuration, preserving the independently verified three-rule HOME/AirVPN split routing. Batch F firewall activation and its optional packet challenge remain hard-disabled.

## Scope

One manually requested, read-only collection of:
- Verified selected WireGuard kernel interface identity and UP state.
- Latest single-peer handshake age and cumulative RX/TX transfer counters (not connection-health proof).
- Current WireGuard UDP fwmark and numeric endpoint **family** (the endpoint address and peer public key are never displayed).
- Existing marked kernel route prediction to each selected WireGuard endpoint. Shows the predicted physical underlay, such as wlan0 or rmnet16.
- Private split route and public IPv4/IPv6 representative root lookups.
- Split-routing ledger count, live reserved priority count and exact ownership matching.
- The state of Wonhee's Batch F ownership ledger, explicitly labeled as *ledger only* (use the separate existing guard audit to inspect live chains).

A second manual tap displays deltas since the prior snapshot **in this app process** and identifies changed underlay route predictions or WireGuard endpoint values **without disclosing the endpoint addresses**. No samples, keys or endpoints are saved to SharedPreferences, files, GitHub, or the diagnostic journal. After process death there is no previous comparison baseline.

## Security boundaries

- No connection test, ICMP, DNS lookup, packet challenge, firewall mutation, routing operation, WireGuard connect/disconnect or background scheduler is triggered by the new button.
- No automatic recovery is performed. A stale handshake or unchanged counters can mean an idle connection and is **not** by itself a failure.
- Route lookups and WireGuard counters do not demonstrate app socket behavior, active packet routing, DNS privacy, or leak-free handoff.
- A CHECK REQUIRED result means one or more observations were missing or inconsistent, **not** an instruction to automatically repair the kernel.
- The root tools may be initialized in Wonhee's app sandbox for diagnostics; the operation does not change networking policy.

## Device testing (Pixel 8a)

1. Keep the tested HOME and AirVPN profiles running and leave the three split-route overrides installed. Keep Batch F OFF.
2. Confirm using existing read-only audits that split-route ownership has ledger 3/live 3, private 3/3, Android mark-aware simulations 70/70 if the same marks are present, public IPv4 and IPv6 correct, and Batch F owned guard OFF with no live reserved firewall anchors or chains.
3. Open Multi-Tunnel Lab → Network Protection · Read Only. Select both profiles. Tap **Batch F.2 · Snapshot live tunnel health · read only** once.
4. Inspect that both kernel identities are verified, both counters read, both endpoints have physical underlay candidates, and both HOME/public route lookups match. Confirm endpoint IPs/public keys are not printed.
5. Tap the same snapshot button a second time later, **without disconnecting, switching networks or changing policies**. The report may show byte-counter growth or quiet tunnels; either is observational, not a leak test.
6. Verify the Batch F enable and packet-challenge controls remain disabled. Do not intentionally cause tunnel/network interruption to force a change notification.
7. Test install/signing compatibility. Do not uninstall the working version to force a debug APK update: that could delete the routing ownership ledger.

## Regression coverage

Pure Java tests verify malformed/zero/multiple-peer handshake parsing, stale/clock-skew semantics, first and repeated manual snapshots, counter growth, unchanged counters, reset detection, underlay and endpoint change markers, endpoint address suppression and strict WireGuard device shape.

CI must pass Android compilation, core tests and native multi-tunnel tests before declaring an APK ready for this read-only check.

## Remaining Batch F blockers

The active firewall's impact on Android Wi-Fi/cellular control traffic is still **not confirmed** from packet captures. Issue [#41](https://github.com/yooshastan/Wonhee-Proxy/issues/41) remains open. Do not reactivate Batch F until separately designed runtime safeguards, exact recovery verification and independent USB ADB fallback are evaluated. This branch does **not** implement auto-recovery, unattended telemetry, new kill-switch exceptions or fail-closed guarantees.
