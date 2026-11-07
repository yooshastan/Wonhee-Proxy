# Batch F.3 — Root fail-closed control-plane redesign (RFC)

**Status: design only; no firewall activation permitted.** Branch derives from Batch F.2 0.15.14 after successful paired read-only health snapshots. Issue #41 remains open. Do not treat this RFC as a validated production or beta kill switch.

## Evidence and uncertainty

- Batch B.1 exact owned routing and rollback passed on Pixel 8a. HOME traffic was observed through its WireGuard interface, with no matching cleartext Navidrome packets observed on wlan0 in a separate filtered capture.
- Batch F guard preflight showed ACTIVE/MATCH and the user lost connectivity before disabling the guard and removing split overrides in quick succession. The cause was not isolated: a delayed guard removal, split-rule removal, cellular transition, or their interaction could have contributed.
- F.1's pure first-match model predicts REJECT for selected synthetic unprotected DHCP, HTTP validation, DNS, and IPv6 router-solicitation flows on wlan0/rmnet interfaces. A synthetic rule verdict does **not** show that Android actually sent these packets through the OUTPUT chain or depended on them.
- F.2 on 0.15.14 passed two RAM-only snapshots 265 seconds apart: HOME +3032 RX/+3400 TX bytes and AirVPN +6027976 RX/+1981624 TX bytes. Both remained on predicted wlan0 with no endpoint-change flag; this is stable-Wi-Fi observation, not handoff proof. Batch F owned ledger was OFF, verified separately with no owned OUTPUT anchors or chains.

## Current owned-chain design (source-referenced)

Source: app/src/main/java/com/yooshastan/wonheeproxy/RootFailClosedFirewallPlan.java and RootFailClosedFirewallRuntime.java.

1. The plan allows loopback; exact marked WireGuard UDP endpoint-address/port tuples; selected private-destination and egress-interface routes; then terminates IPv4 and IPv6 owned chains with REJECT.
2. WireGuard currently shares fwmark 0x20000 (Android protected-from-VPN bit) between the two selected kernel tunnels. This mark is *not* a unique socket/tunnel identity; an identical mark plus the exact tuple may pass the current allow rule, even if not the intended kernel WireGuard socket.
3. The runtime verifies both chains before anchoring them into OUTPUT, persists owned-rule records and supports exact-owned removal; neither verification nor route prediction proves continued Android underlay connectivity.
4. The current rooted guard requires a tunnel/endpoint identity and fixed endpoint tuple; it does not maintain verified updates to those exceptions when endpoints or network paths change.

## Threat model and required invariants

- Prevent private HOME subnet destinations from falling back to AirVPN or direct Wi-Fi/cellular when HOME is lost.
- Prevent generic application traffic, including DNS, from escaping directly over the physical underlay without user-authorized policy.
- Permit necessary *verified* outer WireGuard transport traffic without accidentally admitting unrelated sockets that reuse a common Android fwmark. Treat mark+destination+port alone as an insufficient identity proof.
- Do not silently permit unverified physical-interface traffic (including arbitrary DHCP, captive-portal validation, generic DNS, or IPv6) merely to restore connectivity. Whether those packets are required, who creates them, how they traverse OUTPUT, and what counters show must first be established on the device.
- Never lose the ability to remove only exact Wonhee-owned rules. Unknown, changed, duplicated or untracked chain content must force review, not broad flush or takeover.
- Preserve the working Batch B.1 three priority-12500+ routing overrides, Android priority-13000 rules and HOME/AirVPN interface identities unless separately requested and independently audited.
- Fail to a **diagnostic/refuse state before activation** when socket identity, dynamic endpoint updates, underlay continuity, IPv6, counters, or rollback cannot be demonstrated. Do not guess which interface is safe from a stale snapshot.

## Proposed architecture (NOT implemented)

### 1. Observe and attribute underlay/control flows

- With firewall OFF, collect narrowly scoped, opt-in read-only packet/decision metadata from Android netd, kernel counters and selected Wi-Fi/cellular interfaces. Avoid payload, credentials, full endpoint addresses and peer keys in reports.
- Separate traffic into user/app sockets, WireGuard outer transport, Android connectivity validation/DHCP, IPv6 link-local control, and unknown origin. Record whether flows actually traverse local OUTPUT as opposed to kernel/input/forward paths.
- Record observed interface transitions and current endpoint resolution at discrete times; never infer continuous health from one lookup.

### 2. Plan source-bound exceptions

- Define explicit exceptions only after the origin, destination, port, protocol, fwmark, interface and actual route have been verified for the selected device; distinguish kernel-generated traffic from app-originated traffic where kernel facilities permit.
- Assess whether Linux/Android actually supports authenticated matching of WireGuard kernel sockets. If it does not, mark that guarantee **UNSATISFIED** and do not claim an airtight exception policy.
- Require protocol-family symmetry: IPv4/IPv6 endpoint and private-route behavior must be checked separately; link-local IPv6 cannot be solved with a broad ::/0 allow.
- Dynamic endpoint/underlay changes require staged reconciliation, exact ownership validation and rollback; old exceptions must not remain indefinitely usable.

### 3. Control-plane continuity and recovery

- Use independent USB ADB + root for all future device-enforcement tests. Termux alone is not an independent recovery channel.
- Keep activation hard-disabled until a separate reviewed source change explicitly removes the safety gate; never enable automatically following an app update.
- Define a bounded, user-visible test window with a deterministic emergency rollback mechanism that is demonstrably independent of the affected network path. Do not implement an automatic guard disable that would silently expose app traffic when a tunnel fails.
- On suspected failure, preserve a minimal audit snapshot and refuse mutations until identity/ledger agreement is established; require explicit user choice for recovery.

## Verification matrix before any live reactivation

| Gate | Minimum acceptance |
|---|---|
| Exact ownership | Ledger, live rules and selected public identities match before/after proposed operations; unknown rules are never flushed |
| Pure plan simulation | Both families, interface and fwmark variants, exact tuple mismatches, reject order, endpoint rotation, and absence of broad underlay bypass are covered |
| Underlay attribution | Show which control-plane packet classes *actually* traverse OUTPUT on the target Android build; record counters without payload |
| WireGuard outer delivery | Verify real UDP transport remains viable with observed IPv4 HOME/AirVPN endpoints under stable Wi-Fi and cellular separately |
| Private no-fallback | HOME loss cannot route private destinations directly or via AirVPN, including application UID and DNS cases |
| Public no-direct | Non-approved application destinations cannot bypass AirVPN over physical underlay, including IPv6 |
| Handoff | Wi-Fi-to-cellular and cellular-to-Wi-Fi transitions have verified exceptions, continuity observations and independent rescue |
| Endpoint change | Changing endpoint/underlay does not leave obsolete broad exceptions or silently lose owner verification |
| Failure and recovery | Reboot, crash, duplicate/foreign rules, partial installs, lost root and explicit rollback are tested with independent rescue |
| Moka | Moka's separate Android TRANSPORT_VPN private HTTP gate remains closed unless independently secured; browser route evidence does not override it |

## Work packages

1. **F.3a (now):** source/design audit, precise flow classification and pure-Java rule simulator tests; no kernel writes and no production firewall change.
2. **F.3b:** opt-in read-only observation of actual control-plane flow routing and counters during *normal* connection use; no forced handoff or firewall activation.
3. **F.3c:** design owner-verified, family-specific exception/reconciliation prototype with strict deny-default for non-transport app traffic; test in a disposable or isolated environment.
4. **F.4:** independent recovery protocol and controlled on-device enforcement testing, only after F.3 blockers are resolved.

## Stop conditions

Any unknown socket origin, unverified transport mark/endpoint, ledger mismatch, unmanaged firewall rule, non-reproducible underlay observation, missing independent recovery, or nonconverging dual-stack policy prevents guard activation. No version in this RFC is authorized to re-enable Batch F.

Related: [connectivity incident #41](https://github.com/yooshastan/Wonhee-Proxy/issues/41), [F.2 PR #43](https://github.com/yooshastan/Wonhee-Proxy/pull/43).