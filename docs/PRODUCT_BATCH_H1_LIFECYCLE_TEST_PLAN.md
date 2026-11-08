# Wonhee Proxy 0.15.22 — Batch H.1 Coordinated Lifecycle

## Why it is moved forward

0.15.19–0.15.21 required separate operations for DNS rollback, HOME routing cleanup, and tunnel disconnect. A partially completed operation could leave a kernel/ledger mismatch, requiring manual ADB intervention. Routine updates should not require shell scripts.

## Included in H.1

### One-confirmation full-stack start (manual opt-in)
1. Read-only clean-state preflight: no stale DNS/route/guard ledger; no untracked reserved routing priorities or guard tags; no already-running experimental tunnel; Android Private DNS off; Batch C recovery off.
2. Start selected encrypted WireGuard profiles through existing identity-verified connector.
3. Install exact HOME mark-aware split routing, with its existing durable ledger and route audits.
4. Start the existing encrypted DNS relay through the chosen profile, with optional imported tracker filtering.
5. Audit exact owned DNS firewall rules, relay identity and tracker response. On failure after a successful connect stage, attempt a coordinated safe-stop rollback.

### One-confirmation Safe stop (single root worker, resumable)
1. Persist user manual stop to prevent unattended recovery; require selected encrypted profiles and check exact public identities of every active experimental tunnel. Refuse unknown, unselected or legacy tunnels.
2. Refuse an active or untracked experimental Batch F guard. Remove only exact owned DNS rules and verified relay, then clear DNS ledger once complete.
3. Preflight **all** IPv4 and IPv6 reserved priority rules against the exact stored app ownership record. Accept partially completed cleanup after app crash but reject duplicates, unknown priorities, mutated selectors or extra rules.
4. Remove exactly owned live routing entries, verify zero reserved entries and only then clear ledger.
5. Check guard/DNS/routing again and only then disconnect selected, identity-verified WireGuard interfaces; verify each DOWN and ownership ledgers cleared.

A failure pauses at a named stage and leaves remaining exact ledgers intact. No broad firewall flush, app-data reset, kernel module changes, or unknown rule deletion.

### Scope and limitations
- Start and stop are explicit opt-ins. No boot autostart, Always-on VPN, KPM, automatic DNS subscriptions, background web request history, or active Batch F kill switch.
- Startup is limited to a selected HOME split + Internet default setup with an actual split-route correction plan.
- Normal Wi-Fi/cellular can resume after disconnect; **this is not a zero-leak kill switch**.
- Do not claim H.1 fixed reboot-time stale ownership or total DNS coverage until tested across reboot; H.2 is for durable startup resumption and optional boot/handoff operation.

## Regression coverage

Pure-Java routing tests now check actual Android tab-formatted live output for the three HOME rules, acceptance of partial/existing-zero rules following a crash, and rejection of duplicates, foreign route tables, untracked IPv4 and IPv6 priorities. Existing native WireGuard and DNS helper tests remain.

## Pixel 8a acceptance

1. Before upgrading from 0.15.21, use the **existing verified procedure**: disable owned DNS, remove owned route overrides, disconnect both tunnels. Inspect the firewall and kernel links via USB ADB. Do not update while root DNS is active.
2. Install APK in-place using the same signing identity; never clear data or uninstall after a signature mismatch.
3. Select HOME and AirVPN, choose the AirVPN DNS profile, correct encrypted endpoint/bootstrap, tracker filtering, Android Private DNS OFF, Batch C recovery OFF and Batch F guard OFF.
4. Tap Start complete Wonhee stack. Confirm both selected links UP and exact 12500–12502 policy rules, DNS rules, root relay, and Privacy Monitor verified.
5. Validate Navidrome over HOME, Internet egress over AirVPN, normal DNS resolution and blocked A/AAAA DNS domains.
6. Tap Safe stop complete Wonhee stack; confirm no Wonhee DNS tags, no reserved IPv4/IPv6 priorities, no loopback root relay, both WireGuard interfaces DOWN.
7. Repeat start/stop twice without separate advanced-menu cleanup. Safe stop twice should be idempotent.
8. Do collision/failure injection only on a spare/emulator. If a stage pauses, inspect with ADB rather than flushing or force-deleting rules.

## Next, H.2
Durable on-device lifecycle progress/reconciliation on process death, explicit optional boot/handoff startup, proven robust fail-closed guard, controlled failure injection and clear status UI. Do not enable unattended boot networking until exact rollback and recovery on this device are verified.
