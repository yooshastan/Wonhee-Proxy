# Wonhee 0.11.0 — Batch C multi-tunnel network protection readiness

Batch C is a **non-enforcing observation and planning build**. It extends the
rooted Multi-Tunnel Lab's previously tested independent kernel WireGuard
interfaces and Batch B split-route policy. No kill-switch, firewall, DNS
interception, Android VPN lockdown or tracker-blocking rules are installed.

The aim is to establish truthful device-specific inputs for later *guard
enforcement* without creating a silent leak, stranding a service route, or
breaking WireGuard UDP transport during a handoff.

## Before testing

- Use a rooted Pixel 8a with working USB ADB and a way to recover connectivity.
- Preserve your encrypted profiles; if Android reports an APK signature
  mismatch, do **not** uninstall until backed up.
- If a Batch B routing ledger or priority rules remain, verify/recover and
  remove them using the tested 0.10.2 workflow before changing tunnels.
- Select your working `wgs_client1` Home split profile and `AirVPNEurope`
  Internet default profile. The planner supports more selected profiles, up
  to the existing eight-profile storage limit, but has no automatic chaining.

## Batch C read-only checks

1. Verify versionName `0.11.0-batchC-guard-readiness` and that the existing
   Multi-Tunnel Lab Connect, Disconnect, Preview, Audit, Apply, Recover and
   Remove actions remain present. The original legacy Home + AirVPN controller
   must remain unchanged.
2. Check that **NETWORK PROTECTION · READ ONLY** clearly says the kill switch
   is **OFF**, and its two diagnostic buttons are reachable above the Android
   navigation bar. Neither button should ask for a firewall activation.
3. With both experimental tunnels UP and identities MATCH, tap **Check
   multi-tunnel guard readiness**. Capture the output. Expected categories:
   - Each selected profile UP / public identity MATCH; recent or idle handshake.
   - Numeric UDP endpoint availability and transport fwmark state, without
     exposing peer public keys or private config contents.
   - Home split root-route matching count, public IPv4 default, IPv6 default.
   - IPv4/IPv6 OUTPUT table and mark-matcher availability, guard chain
     collision, and owned routing ledger consistency.
   - A conspicuous **ACTUAL KILL SWITCH: OFF** warning.
4. Tap **Audit configured DNS routes**. Expect resolver destinations (if any)
   from selected encrypted runtime configs, their expected interface by
   longest-prefix AllowedIPs and the actual UID-0 root route. If no DNS
   resolver was configured, it must say **NO CONFIGURED RESOLVERS** rather than
   claiming no DNS leak. This does not audit Private DNS, app DoH, DoQ, or
   Android's DNS socket fwmarks.
5. Confirm neither test created any `WN_MULTI_GUARD4`/`WN_MULTI_GUARD6`
   iptables/ip6tables chains or changed selected tunnel state. Check via
   read-only `iptables -S` / `ip6tables -S` if available; no changes should
   occur to Android's policy rule priorities.
6. Force-close and reopen Wonhee. Inspect live interfaces. A present identity
   should still be checked but **not automatically adopted** by a new process.
   Any Batch B owned routing ledger must survive and must be cleaned up before
   stopping tunnels.
7. Optional when alternate connectivity is available: switch Wi-Fi → mobile
   data → Wi-Fi, then repeat read-only diagnostics. Capture whether handshakes
   recover. Treat a successful route lookup as insufficient to prove actual
   app traffic, resolver traffic, or crash-safe blocking.
8. Optional when a third configured private server is available: select a
   third profile with **non-overlapping** private CIDRs; the DNS/route
   expectation must follow its own destination rather than assuming Home
   and AirVPN are the only two choices.

## How to report results

One local session report with the two new diagnostic results, plus the final
kernel status, is enough. Never paste private keys or tokens. Profiles and
addresses may identify your private network, so review exports before sharing.

If all read-only diagnostics complete, the batch has passed as an **audit
foundation only**. The next enforcement gate needs verified endpoint UDP
exemptions, app-level routing, DNS/IPv6 packet observations, crash/reboot
behavior, and explicit rollback mechanics. Do not enable firewall blocking
solely because the output says the design preconditions partially pass.
