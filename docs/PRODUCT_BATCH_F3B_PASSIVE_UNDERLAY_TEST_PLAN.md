# Wonhee 0.15.15 — Batch F.3b passive underlay observation

**Draft / opt-in diagnostic only. Batch F guard ACTIVATION remains hard-blocked.** Built upon the passing F.3a offline rule matrix, the 0.15.14 F.2 stable-Wi-Fi paired health test and the verified 3-rule HOME split-route ownership state.

## Purpose and bounded behavior

The user experienced a connectivity interruption during a previously active Batch F guard. The failure was not isolated because firewall and route removal were triggered close together. The F.1 offline simulation predicts some Android network-control traffic would be rejected by the old guard, but it has not established whether Android actually emits such traffic through local OUTPUT.

F.3b collects a **single, explicitly approved, 5-second outgoing interface-header sample** from the verified physical underlay, normally `wlan0` or `rmnet16`. Uses existing root `tcpdump` and `timeout` if available. It is passive: no packets sent, no DNS requests, no port scan, no Wi-Fi/cellular transition, no tunnel or firewall changes. The filter includes DNS UDP/TCP 53, DHCPv4 UDP 67/68, HTTP TCP 80 and ICMPv6 candidates. Up to 32 outgoing packet headers, snap length 64 bytes; no pcap output. Raw summaries are immediately reduced to aggregate counts and discarded from memory, not shown or saved to persistent journal.

The capture is **NOT Android netd/OUTPUT-chain attribution**. Ordinary application traffic can also match, the sender UID cannot be identified and a packet appearing at an interface is not proof that it was permitted/rejected by a particular firewall rule. A zero count means no matching headers in that brief window, not proof a class never appears. This limited evidence tells us which classes merit later safe investigation.

## Prerequisites

- Root available, selected HOME and AirVPN independently running and their public identities/marked endpoint paths validated.
- Batch B.1 ownership ledger and exact live routing rules agree (3 and 3 for this test device).
- Batch F guard ledger OFF and the **actual** owned IPv4/IPv6 anchors/chains absent.
- DNS enforcement and unattended recovery must not be active; existing preflight refusal is preserved.
- `tcpdump` and `timeout` available to the **app's root shell**; Termux's separate `tcpdump` installation may not appear in that shell. If unavailable, refuse without capture.
- No deliberate underlay change, tunnel disconnect/reconnect, forced DHCP renewal, firewall activation, or packet-generation challenge.

## Pixel 8a procedure

1. Keep stable HOME and AirVPN connections; confirm browser Internet and private Navidrome normally work.
2. Run **Verify live IPv4/IPv6 guard + rollback ledger** to confirm OWNED GUARD OFF, ledger OFF, anchors and chains ABSENT.
3. Verify read-only HOME split routing, ledger 3/live 3, private 3/3, public IPv4/IPv6 correct. Do not remove/reapply rules just to test.
4. Open Multi-Tunnel Lab → Network Protection → **Batch F.3b · Observe underlay control headers · opt in**.
5. Read the explicit consent and tap **Observe headers** once. No action is required if it refuses because tcpdump or timeout is missing.
6. Review reported physical interface, completed/failed capture, category **aggregate counts**, and disclaimers. Do not interpret any candidate category as a confirmed Android process or confirmed cause of the earlier outage.
7. If you need to share output, share only the summary screen. Do not capture/share full raw packets, endpoint IPs, WireGuard keys or full root logs.
8. Reconfirm Internet/Navidrome usability and the guard still OFF. Do not enable Batch F or attempt Wi-Fi/cellular handoff under the guard.

## Source and security boundaries

- `RootUnderlayControlEvidence.java`: strict interface-name checking, finite tcpdump command, in-memory count-only header classifier and explicit incomplete status.
- `RootMultiKernelSession.observePhysicalControlHeaders`: guard ledger OFF plus exact live-chain preflight, exact owned split-route verification and selected kernel identities before any capture; no firewall writes.
- `RootMultiKernelActivity.java`: explicit dialog and result journal redaction to avoid persisting observed addresses.
- `core-tests/RootUnderlayControlEvidenceTest.java`: classifier categories, bounded command, invalid interface rejection, redacted reports and incomplete capture handling.

## Blocking acceptance

The following remain UNSATISFIED for live kill-switch reactivation: verified Android OUTPUT chain traversal and packet creator UID; verified kernel WireGuard socket identity beyond shared fwmark 0x20000; dynamic endpoint/underlay exception reconciliation; independent USB ADB recovery; safe fail-closed behavior on tunnel loss/handoff and both IPv4/IPv6. Issue [#41](https://github.com/yooshastan/Wonhee-Proxy/issues/41) remains open. A successful F.3b device report **must not unblock firewall activation**.

Related RFC: [F.3 design](PRODUCT_BATCH_F3_FAIL_CLOSED_REDESIGN_RFC.md).