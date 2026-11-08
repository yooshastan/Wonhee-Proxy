# Wonhee Proxy 0.15.23 — Batch H.2a: Safe Reconciliation

## Goal
Keep 0.15.22's tested full-stack start/stop implementation intact, while adding an explicit, inspectable path to recover from **stale root ownership records after a reboot or interrupted shutdown**. Avoid repeating manual ADB scripts. This is **not** unattended boot startup, automatic tunnel reconnection, or a universal VPN kill switch.

## New controls in Connection Controls
- **Audit interrupted startup/shutdown · read only**: independently inspect exact persistently owned DNS and split-routing records, known DNS firewall tags, all IPv4/IPv6 reserved priorities 12500–12799, active native WireGuard interfaces, and loopback UDP 53535. Check the Batch F guard is fully absent.
- **Repair VERIFIED stopped ownership · opt in**: explicitly confirmed and **only** permitted when *no* WireGuard kernel tunnels or relay/listener are active. No unknown firewall or routing rules may be present. It preflights twice and then removes only exact saved DNS and split-routing rules and clears the associated records, in that order, checking the live kernel after each phase.

## Classification states
- CLEAN_STOPPED: all known ownership records empty and no matching live rules or tunnels
- RUNNING_OR_PARTIAL: a live WireGuard interface exists; operator must use the already-tested Batch H.1 Safe stop, not stopped-only repair
- REPAIRABLE_STOPPED: all live rules match recorded ownership and interfaces/relay are down; exact cleanup possible after explicit confirmation
- BLOCKED_UNKNOWN: foreign/duplicate/modified rules, absent ownership for live DNS tags, live relay, Batch F guard, or unverifiable state. Refuse mutation.

## Safety invariants
- No boot-start, no new background services, no changes to DNS transport, DNS filtering, packet enforcement, tunnels or app signing.
- No blind automatic adoption of unowned priority rules; no firewall table flush.
- Refuse any active tunnel, any localhost DNS listener (even when the saved PID is stale), a live process matching the recorded root relay, any known DNS tag without a saved ledger, unknown IPv4/IPv6 reserved-priority rules, and any Batch F guard/record.
- A signed explicit repair must verify the live state *twice* in the same serialized root worker before mutation. It stops unattended Batch C recovery intent, but never initiates a new tunnel or DNS session.
- Crash between phases: the exact pending record remains, and subsequent repair can resume. No background task automatically rewrites persistent ownership metadata.
- This status is not a traffic leak audit; it cannot detect arbitrary browser DoH over 443, unknown firewall rules with non-Wonhee tags or undetected root-level kernel bugs.

## Pixel 8a acceptance — USB ADB available
1. Preserve the current working 0.15.22 profile data, imported HOSTS list, and tested Safe stop. **Before upgrading**, run Safe stop and confirm neither WireGuard interface exists, no 12500–12799 priorities remain, and no WN DNS rules are active. Don't uninstall or clear app data.
2. Install 0.15.23 over the existing debug-signed APK. If installation reports a signature mismatch, stop without uninstalling.
3. With the full stack STOPPED: tap the new *Audit interrupted startup/shutdown*. Expect CLEAN_STOPPED. Tap *Repair VERIFIED stopped ownership*: expect ALREADY CLEAN; no kernel mutations.
4. Start full Wonhee stack using the unchanged 0.15.22 Start control. Confirm HOME, AirVPN, imported tracker list and encrypted DNS. Run the H.2a audit while connected: expect RUNNING_OR_PARTIAL. Do not run Repair while connected; it must refuse.
5. Safe stop normally. Check with ADB: no DNS firewall tags, no 125xx priorities in either IP family, no localhost UDP 53535 relay and both named WireGuard interfaces DOWN. H.2a audit should return CLEAN_STOPPED.
6. Repeat once before testing process termination. Only then run controlled reboot and crash tests in H.2b; do not reboot with active DNS enforcement just to create a stale state.
7. Repairable crash state and foreign-rule refusal should be validated on a spare rooted test device or emulator, not on a daily-use device. If anything says BLOCKED_UNKNOWN or CHECK REQUIRED, preserve state and inspect with USB ADB.

## Deferred to Batch H.2b
- A durable lifecycle transaction journal for restarting an interrupted *startup*, independent of Activity callbacks.
- Controlled handoff recovery (Wi-Fi/cellular), bounded retries and DNS health checks with fail-closed semantics.
- Optional boot activation only after reboot and failure-injection acceptance, with a clear user-controlled off switch.
- Streamlined top-level status panel and automatic recovery traces without DNS query history.
