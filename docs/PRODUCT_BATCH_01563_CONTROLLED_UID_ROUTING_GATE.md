# Wonhee 0.15.63 — controlled UID routing acceptance gate

Status: **engineering gate, not a release or permission to activate routing**.
Based on the user's 2026-11-20 Pixel 8a results from 0.15.62 triple-link lab.

## Confirmed starting evidence

- Three separate encrypted peer configurations (Exit A, Exit B, Home) passed profile compatibility and private-table bootstrap (20/20 owned journal stages).
- Exit A and Exit B each replied to a separately bound numeric ICMP probe; Home replied to a bound private-LAN ICMP probe.
- All three peers showed verified recent handshakes.
- Exact-owned Safe Stop reached CLEAN_STOPPED with zero persistent entries, leaving ordinary Android networking untouched.
- Critically, the lab itself states **no Android apps were routed** and **no UID, firewall or DNS rules were changed**.
- ICMP replies **do not** establish TCP/HTTPS, DNS, per-app isolation or tunnel-loss no-fallback.

## Constraints that must remain intact

1. Android Private DNS stays OFF (device Wi-Fi compatibility requirement).
2. Do not touch Android netd-managed rules, default/main routes, DNS settings, connmark chains, kernel marks or the all-device kill switch in this gate.
3. WireGuard keys/peer endpoints never enter diagnostics, logs, command arguments printed to users or commits.
4. Changes require exact-owned durable journal records and reverse-order Safe Stop, including interrupted recoveries.
5. No production signed APK or versionCode bump until on-device acceptance evidence passes.

## First feature slice — single UID, single exit

- Require prior CLEAN_STOPPED and a validated three-link isolated Start.
- Explicitly opt in one non-system test app UID to Exit A; leave all other UIDs untouched.
- Preflight the real device's v4/v6 UID rule syntax, private route tables, underlay WireGuard endpoint protection, resolver behavior and no-fallback terminal route behavior before installing any selector.
- If DNS UID attribution, dual-stack blocking or endpoint protection is unknown, **refuse activation**. A rootless planner / UI preview is not enough.
- Install verified per-table terminal blockers before owned UID selectors. Read back exact family, priority, UID range, mask, lookup table and blocker routes.
- No automatic selection of additional apps; no Android system UID, shared UID or shell UID as a test subject.

## Evidence required for acceptance

| Test | Pass condition |
| --- | --- |
| Baseline | Before adding UID selectors, normal Android app connectivity unchanged |
| Exit A selected UID | App traffic's actual external IP matches Exit A, with packet trace bound to selected UID |
| Nonselected app | Normal routing unchanged; no redirection into A/B/Home |
| Exit B selected UID | A *different* explicitly selected test UID uses B while A remains independent |
| Home TCP | Bound TCP connection and HTTP status from Navidrome at 10.0.0.169:4533 over Home, while A/B remain responsive |
| IPv4 and IPv6 | Packet evidence for both families, or verified deliberate family blocking; no physical fallback |
| DNS | Requests resolved through an explicitly controlled protected path with no unexpected system-resolver escape |
| Exit down | Traffic selected to failed exit stops; never falls to other exit, Wi-Fi or cellular |
| Wi-Fi to cellular | Underlay reconnect is safe, identities stable; neither leaked app packets nor orphaned rules |
| Exact Safe Stop | Both UID policy journal and link journal empty; owned selectors/routes/interfaces gone, Android-owned objects untouched |
| Restart/recovery | Interrupted transaction refuses unknown ownership and safely recovers without deleting foreign objects |

## Port/protocol precedence — *later slice*

The Pixel 8a's `ip rule` utility does not advertise direct `ipproto/dport` selectors. Existing Android netfilter/connmark mark masks conservatively cover all 32 bits. **Do not** enable the speculative port-rule planner or write arbitrary `MARK --set-xmark` rules. After UID-only paths and exit-loss blocking pass, investigate a separately verified classifier that interoperates with netd; exact TCP/UDP port overrides must take priority over category/UID defaults while preserving Android's packet marks.

## Release decision

- **PASS:** repeatable packet-level proof on all selected paths, leak-safe failure, exact owned cleanup, CI tests and signed upgrade under safe installer.
- **BLOCKED:** handshake-only success, missing dual-stack/DNS/underlay proof, any fallback or mark collision, stale journal, unknown ownership, failed Safe Stop, or any unsupported Android routing command.

No claim of an APK is justified by this document alone.
