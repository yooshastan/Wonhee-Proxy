# Wonhee 0.15.13 — Batch F.1 diagnostic-only safety revision

Status: **DRAFT / firewall activation quarantined** pending investigation of [#41](https://github.com/yooshastan/Wonhee-Proxy/issues/41). Derived from the tested Batch B.1 split-routing baseline. This build is NOT a fix for active firewall continuity and is NOT a fail-closed release.

## Why this exists

The Pixel 8a completed Batch B.1 routing, packet-path and exact rollback tests. When Batch F's experimental IPv4/IPv6 OUTPUT guard was active, the device lost connectivity. The user disabled the guard and also removed routing overrides before the exact recovery timing could be established. Reapplying the split rules restored Internet and private Navidrome. Later read-only audits confirmed the Batch F ownership ledger OFF, anchors/chains absent, routing ledger 3, private 3/3 and 70/70 marked-route simulations PASS.

The existing Batch F guard plan permits loopback, exactly marked WireGuard UDP endpoint IP/port combinations, selected tunnel destinations, then terminates with REJECT. Its preflight validates a static configuration but **does not** verify continued Android Wi-Fi/cellular network management, changing endpoint destinations, validated network state or handoffs.

## Non-disruptive changes

1. **Hard activation quarantine.** The internal root `enableGuard` worker rejects before the first firewall write or ledger mutation. UI activation is disabled. A call from any UI path still refuses in session code.
2. **Packet challenge quarantine.** The optional physical-underlay challenge is disabled in UI and refused in the session before any packet is sent.
3. **Read-only control-plane flow model.** New button in Batch F: **Preview firewall impact on Android network control · read only**. It uses a verified selected-tunnel plan and reads current endpoint/underlay *route prediction*. No test packets, HTTP, DNS, firewall rules or tunnel settings are changed.
4. **First-match simulator** covers only the precise, app-owned chain grammar (loopback; exact marked WireGuard UDP endpoints; private destination anti-fallback; tunnel destination allowances; terminal REJECT). It deliberately returns UNKNOWN if a rule shape is unrecognized.
5. **Regression tests** exercise correct tunnel allowances, private destination cross-tunnel blocking, exact marked endpoint exceptions, simulated DHCP/DNS/HTTP validation/IPv6 router-solicitation rejection on both Wi-Fi and cellular, and the hard activation gate.
6. **Existing disable guard / owned-rule audit remains available** in case an earlier APK left an active guard. Batch B.1 split-route code and ledger are unchanged.

## Device acceptance test — safe, read only

1. Keep Batch F OFF. Leave working HOME/AirVPN routing and its 3 owned split-rule entries unchanged.
2. Confirm Wonhee's **Verify live IPv4/IPv6 guard + rollback ledger** says OFF and both IPv4/IPv6 anchors and reserved chains are absent.
3. Record the already working Batch B route audit (private 3/3; mark-aware all probes PASS; public IPv4/IPv6 AirVPN; rollback ledger 3 / live rules 3).
4. Select HOME and AirVPN; run **Preview firewall impact on Android network control · read only**. Check that the reported underlay is the current physical candidate (e.g. `wlan0` or `rmnet16`), and that modeled ordinary underlay control-plane flows say REJECT while selected tunnel egress remains RETURN.
5. If the underlay is changing or a selected tunnel is down, the preview must refuse rather than infer a safe result.
6. Confirm **Review + enable experimental kill switch** and optional packet challenge controls are disabled; if invoked programmatically, the root session must refuse without mutation.
7. Keep the device on normal Internet and confirm both browser Internet and private Navidrome remain usable. Do not disconnect/switch tunnels just for this diagnostic.

## Interpretation

- REJECT for a synthetic underlay DHCP/validation/IPv6 control flow means **this plan's owned OUTPUT chain would reject that hypothetical flow**. It does *not* prove Android actually sent it or that it caused the incident.
- RETURN for selected VPN packets means only the isolated chain modeled would allow it. Other iptables rules, Android netd rules, interface availability, packet delivery and failover are outside the simulation.
- Real packet captures, runtime connectivity-health monitoring, guarded rollback scheduling, independent USB ADB recovery and fail-safe transition handling are needed before another live Batch F activation.
- Do not add broad `wlan0`/`rmnet16` OUTPUT exceptions or disable the terminal rejects as a workaround. These would undermine the intended security guarantees.

## Recovery and signing

The debug application uses the project's existing `.rootlab` application ID suffix; its signing identity may differ from a previously installed variant. Do **not** uninstall the user's working app or reset routing/firewall ownership ledgers to force an update. Install only with compatible signing; otherwise test on a separate device. Root-capable Termux is useful for read-only diagnostics but does not replace independent USB ADB recovery for future guard activation.

Issue [#41](https://github.com/yooshastan/Wonhee-Proxy/issues/41) remains open. The original [Batch F plan](PRODUCT_BATCH_F_0156_KILLSWITCH_TEST_PLAN.md) is superseded by this activation pause for 0.15.13.
