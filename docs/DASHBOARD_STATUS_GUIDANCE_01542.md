# Wonhee 0.15.42 — Dashboard status and recovery guidance

## UI
The existing Candy Pink dashboard now uses four shorter tabs: **Status**, **Tunnels**, **DNS**, and **Activity**. The Status view shows verified/present root tunnel identities, aggregate root tunnel speeds (only when available), local DNS relay status and blocked DNS reply totals, plus a **What to check next** panel. The DNS view includes available root-verified relay counters (received, forwarded, blocked, failed). Connection actions remain in existing Safe Controls.

## Measurement and safety boundaries
- Live aggregate counters refresh every eight seconds **only while dashboard is visible**, already present before this PR. No per-tunnel speed or heartbeat/handshake claim is invented.
- The dashboard does not audit the live DNS firewall rules; a recorded ledger or a verified relay is not proof of end-to-end DNS coverage.
- The blocked count reflects only DNS replies processed by Wonhee's current locally verified relay. It does not count all ads or all apps.
- The recovery panel recommends **read-only** investigation appropriate to unknown root state, identity mismatch, empty tunnel set, unverified counters, unverified relay, or nominal snapshots. It does not repair, start/stop, switch networks, or override a safety refusal.
- Existing H.1 Safe Stop, H.2a CLEAN_STOPPED, original-signing-key requirements, and paused Batch F guard remain intact. Keep Android Private DNS OFF on the Pixel 8a.
- No iptables/ip6tables, tunnel routing, DNS enforcement, tracker policy or network control changes.

## Device acceptance
1. Android build and native WireGuard CI pass on the final commit.
2. Verify the dashboard opens, renders all tabs, displays concise verified X/Y counters and changes to unavailable when evidence is incomplete.
3. Verify DNS counters reflect a running verified relay, and label unverifiable stats as unavailable (not zero). Blocked count is relay lifetime.
4. Verify notification opt-in/off behavior and that visible-only sampling stops when the dashboard pauses.
5. Confirm guidance varies with stopped/unverified/working state and only navigates to existing safe controls.
6. Check RCS, Home and AirVPN tunnels, tracker protection, DNS relay, Android Private DNS OFF, and regression of diagnostic export.
7. Build official package locally with original certificate; H.1 Safe Stop + H.2a CLEAN_STOPPED + guarded installer before on-device upgrade. PR/debug artifacts are not signed official releases.
