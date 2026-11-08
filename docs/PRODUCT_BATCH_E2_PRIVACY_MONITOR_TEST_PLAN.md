# Wonhee Proxy 0.15.21 — Batch E.2 Privacy Monitor and DNS coverage

## Objective

Improve diagnostics without changing the verified WireGuard dual-tunnel routing, upstream DNS transports, firewall redirection/rollback or experimental Batch F guard quarantine.

## Features

1. Live relay aggregate counters: DNS queries received, locally blocked replies, successfully forwarded encrypted responses, and failed/dropped attempts. Counts reset when the specific root relay process restarts and are saved every ~2 seconds to a private file. No DNS domain names, client IDs, queried IPs, timestamps per query, destinations or per-app history are saved.
2. A read-only Privacy Monitor in the Batch D DNS enforcement panel. It requires exact DNS firewall rule verification, the root process executable identity and the PID from Wonhee's owned DNS ledger before accepting a counter snapshot.
3. Read-only DNS coverage explanation: the observed firewall rules intercept IPv4 TCP/UDP 53, block IPv6 port 53 and disallow traditional DoT and non-root UDP/853; counters only describe DNS traffic arriving at Wonhee's local relay.
4. Offline domain rule tester in the Batch E tracker panel. It compiles the selected imported/allow/custom lists and reports ALLOWLIST, BLOCKLIST or NO MATCH for one user-entered domain without any network request. This is a PLANNED-POLICY PREVIEW, not proof of the current relay's live immutable snapshot.

## Important limitations

- External DNS-over-HTTPS or DNS-over-HTTP/3 on TCP/UDP 443, apps connecting directly to IP addresses, independent per-app VPN paths and DNS over arbitrary ports may bypass the port-53 rule. Neither this report nor localhost query tests prove complete DNS leak freedom.
- Stats snapshots are periodic, so the newest one may lag by up to two seconds. Packet counts are local relay outcomes, not absolute Android DNS totals.
- No automatic blocklist downloads, cosmetic browser ad filtering, HTTPS interception, kernel KPM loading, netfilter modification, additional routing rules or changes to restart policy.
- An existing DNS ownership record remains a critical safety prerequisite; never disconnect tunnels while owned DNS rules remain installed.
- Reboot stale routing ledger reconciliation remains a separate safety-critical product task, not fixed in this build.

## Pixel 8a device acceptance

1. With USB ADB available, turn off Batch D DNS enforcement using its exact owned-rule rollback; inspect firewall tags and verify the relay has stopped. Remove owned split-route overrides via the app and only then disconnect tunnels before installing 0.15.21 over the existing rootlab APK.
2. Reconnect HOME and AirVPN, restore the three exact HOME routes and verify Navidrome and normal public routing work. Keep automatic recovery, kill switch and untested filtering features OFF.
3. Use the offline domain tester BEFORE enabling DNS. Test built-in tracker, imported-list-only domain, allowlisted exception and unrelated domain. Verify that results are clearly marked as draft/planned policy and no queries are sent.
4. With Android Private DNS OFF and verified selected AirVPN route, opt into the tested system DNS relay + tracker filtering. Audit exact DNS firewall rules and process identity first.
5. Tap Batch E.2 Privacy Monitor; verify counts show a real snapshot and rule coverage disclaimers. Using Termux, make several known blocked A and AAAA requests, then at least one allowed A request. Tap Privacy Monitor again after a few seconds: received and blocked should increase, forwarded should increase; no per-domain history appears.
6. Run one temporarily blocked/allowlist test, check app browsing and Navidrome. Compare observed counters, but do not treat the monitor as proof that every app resolver is intercepted.
7. Disable exactly owned DNS enforcement; verify no tagged firewall rules, local relay stopped, DNS ledger OFF and preserved HOME/AirVPN routes. Confirm Internet browsing and Navidrome.
8. If any audit or disable stage fails, keep both tunnels UP, do not flush unrelated firewall tables and use USB ADB to inspect ownership.

## Regression test coverage

- Pure Java parser refuses incorrect PID, invalid version, negative/overflowed values or impossible positive counts.
- Pure Java policy explains ALLOWLIST precedence, BLOCKLIST suffix matching and unmapped domains.
- Native Go tests verify private snapshot format, aggregates only, and refusal of arbitrary stats paths.
- Existing encryption, DNS and dual WireGuard workflows remain enabled.
