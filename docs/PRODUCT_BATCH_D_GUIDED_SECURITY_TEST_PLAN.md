# Product Batch D stage 2.1 — guided security controls (0.15.2)

This is a **UI/read-only orchestration preview**, layered on top of the tested
0.15.1 root-bound DoH transport. It does **not** add a system DNS service,
DoQ/DoH3, automatic firewall policy or a kill switch. Product Batch D is not
complete until the remaining implementation and device tests are done.

## Quick device test

1. Keep the known-good tunnels and routing ledger unchanged. Do not uninstall
   a previous experimental build without preserving its tunnel state, signing
   identity and rollback ledger. Keep root Termux and USB ADB available.
2. In **Multi-Tunnel Lab**, select the Home and Internet profiles that are UP.
   The main screen shows connection controls and a **Security Assistant** card.
3. Tap **Run guided safety check · read only**. It runs five sequential audits,
   shows ongoing progress, prevents overlapping root operations, and reports
   findings with an action-oriented next step. Tap **Review safety check details**
   to inspect each raw report.
4. Confirm **KILL SWITCH: OFF · DNS ENFORCEMENT: OFF** remains visible even if
   all audit destinations match. The assistant must never claim leak freedom.
5. Tap **Show advanced security controls**. Confirm recovery, routing, DNS,
   and packet tests remain accessible, with their original opt-in prompts.
   Collapse them again. No tunnel or routing changes should occur.
6. Select no profiles and repeat the guide action: it should request selection
   without running a root audit. A selected DOWN profile should show
   **CHECK IDENTITIES** instead of a false green pass. An empty routing ledger
   with reserved priorities should still warn in route details.

## Compare Android root state (read-only)

Termux:

```sh
su -c 'ip -o link show' | grep wnm
su -c 'ip -4 rule show' | grep -E '^12[5-7][0-9][0-9]:'
su -c 'ip -4 route get 1.1.1.1'
su -c 'ip -4 route get 10.0.0.169'
```

ADB from Fedora:

```sh
adb shell su -c 'ip -o link show' | grep wnm
adb shell su -c 'ip -4 rule show' | grep -E '^12[5-7][0-9][0-9]:'
adb shell su -c 'ip -4 route get 1.1.1.1'
adb shell su -c 'ip -4 route get 10.0.0.169'
```

The route observations are UID-0 lookups; neither these nor the guide prove
per-app network behavior, DNS fallback prevention or a functional kill switch.
