# Wonhee 0.15.20 — Batch E.1 managed local HOSTS list import

## Purpose

Improve Wonhee's basic nine-domain DNS filtering without destabilizing independently verified HOME + AirVPN kernel WireGuard routing. This is a local, offline and opt-in import stage, not automatic blocklist subscriptions.

## Scope

- Android Storage Access Framework picker (ACTION_OPEN_DOCUMENT) for a user-selected local text blocklist.
- Accept 0.0.0.0 domain, 127.0.0.1 domain, :: domain, ::1 domain HOSTS formats, or one plain domain per line. Multiple domains on a HOSTS row allowed.
- Reject unsupported Adblock Plus-style rule syntax, wildcard/IP-address rules, unknown nonlocal tokens and input over 20 MiB / 250,000 unique domains / 420,000 lines. Do not auto-convert unsupported syntaxes.
- Normalize and deduplicate names. Ignore local networking names such as localhost and .local/.arpa. Allowlist still overrides blocklist suffix matching.
- Maintain one previous valid snapshot under private app storage with atomic replace. Never update a live root DNS relay from an import.
- Only compile imported domains into a new root policy when user explicitly selects Batch E filtering and separately opts into system encrypted DNS activation.
- Native Go relay loads at most 24 MiB and 250,512 unique entries in a bounded streaming read, refusing invalid policy. Match blocked queries for A and AAAA; no DNS history or telemetry.
- No remote list downloading, scheduling, implicit updates, routing, DNS or firewall modifications in importer. No KPM / boot-image changes.
- Compiled filter list does not protect browsers/apps that use their own HTTPS DNS or VPN bypass. It does not implement webpage cosmetic or cookie popup filtering.

## First device acceptance on Pixel 8a

1. Install 0.15.20 debug over 0.15.19 rootlab only when CI succeeds. Before updating, remove owned split rules using the app's verified rollback, then disconnect both tunnels. Do not uninstall or clear app data.
2. Connect both selected tunnels, install the 3 exact HOME split rules. Confirm Navidrome and public Internet still work. Keep Batch C recovery and F kill switch disabled.
3. Keep Batch D system DNS enforcement OFF. Use Inspect saved blocklist (expect NONE); preview with tracker filtering OFF.
4. Download one legitimate HOSTS/plain-domain list manually using a browser. Review its license/source. Import via the explicit Import local hosts/domain blocklist picker.
5. Inspect saved snapshot and SHA-256 digest, preview total planned blocked suffixes. Test invalid-file refusal without changing the saved snapshot; import a second small file and exercise Restore previous imported blocklist.
6. With functional USB ADB, Android Private DNS OFF, two verified tunnels UP, choose tested AirVPN DoH upstream and explicitly opt into Batch E tracker filtering + Batch D system DNS interception. Health check must report the local tracker test blocked and relay alive. Test blocked domain via DNS queries (A and AAAA), allowed domain, nonblocked domain, regular browser and Navidrome.
7. Audit exact owned DNS firewall rules/relay; use Disable owned DNS rules + restore resolution. Verify no tagged IPv4/IPv6 firewall rules, listener gone, DNS ledger OFF, HOME/AirVPN routes unchanged, Navidrome/public browsing restored.
8. Only after that rollback cycle should a larger public list be imported/tested. Avoid stacking overlapping huge lists by default.

## Blocklist source notes

- https://github.com/bindhosts/bindhosts/blob/master/Documentation/sources.md provides discovery; it is not a combined list to import.
- https://github.com/StevenBlack/hosts is a useful baseline.
- https://github.com/hagezi/dns-blocklists offers different protection levels. Prefer the lighter list first.
- AdAway, 1Hosts and others can be added by explicit user selection if their actual downloaded format is supported. Check license before bundling or redistribution.
- Never assume HOSTS, Adblock Plus, and cosmetic CSS rules are the same format.

## Follow-ups intentionally deferred

- Managed subscriptions with pinned URLs, update verification, last-known-good rollback and per-source enable controls.
- Per-app filtering analytics and privacy-safe aggregate counters.
- Browser-specific cosmetic/annoyance rules, not systemwide HTTPS interception.
- Reboot-safe exact routing ledger reconciliation.
- Research-only optional KernelPatch KPM helper (no kernel modifications in E.1).
