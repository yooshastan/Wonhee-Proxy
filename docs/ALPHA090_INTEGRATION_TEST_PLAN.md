# Wonhee Alpha 0.9 — combined preview and private Navidrome gateway

**Preview only** — versionCode 19, versionName `0.9.0-alpha09-preview`. This branch stacks on unmerged Alpha 0.8.9 recovery, which itself includes Alpha 0.8.8 private service testing and Alpha 0.8.7 local diagnostics. Main's tested Alpha 0.8.6 remains unchanged.

## Included in one Android preview

- **0.8.7 local diagnostics:** bounded ephemeral connection-event labels, explicit redacted support-report clipboard, optional Quick Settings tile that **only opens** Wonhee.
- **0.8.8 home-service check:** a single user-approved TCP connection using the exact Android VPN network to a numeric private IPv4 address and port (including 4533); no DNS and no direct network fallback.
- **0.8.9 recovery:** opt-in, disabled by default, requires Android Always-on and successful manual Connect. Attempts recovery only when the WireGuard interface is **actually DOWN** using bounded delays plus an Android JobScheduler best-effort fallback. Respect manual Disconnect, VPN permission revocation and battery restrictions. A stale handshake while interface stays UP is not automatically repaired.
- **0.9 Fedora gateway:** a systemd unit that persists the private `10.77.0.1:4533 → 127.0.0.1:4533` Navidrome forwarder, with one-peer firewalld instructions. Install separately on Fedora; this APK cannot configure or open the home server.

The new 0.9 branch deliberately **does not import the separate Alpha 0.8.7 reconnect backend** from PR #15. It would duplicate and conflict with the later 0.8.9 recovery machinery. Only the independently useful Fedora service is carried forward.

## CI, signing, rollout

1. One automatic GitHub Actions `build.yml` PR run should execute pure Java regression tests and compile the combined debug APK, with an artifact named `wonhee-proxy-alpha09-preview-debug-apk`.
2. The *separate manual* signed job must require trusted `main` and the maintainer's pinned persistent Wonhee signing secrets. No debug APK is suitable for store/public distribution. The signed 0.9 build is not published.
3. Run full Pixel 8a GrapheneOS and Samsung A36 tests below **before merging this stacked preview into main**, and do not assume unattended restoration is guaranteed.
4. Back up original WireGuard `.conf` before switching APK signing identities; never paste or upload private keys.

## Pixel 8a and Samsung A36 acceptance

- [ ] Connect a saved profile, verify tunnel handshake, RX/TX chart, Ultgram MTProxy and ordinary apps.
- [ ] Use Quick Settings tile; ensure it opens the dashboard without changing VPN state.
- [ ] Check event history and copied report; no IP endpoint, key, phone hostname or full profile should appear.
- [ ] Run **Home Service Check** with `10.77.0.1:4533` (with consent), verify pass when Fedora forwarder is active and failure when its listener is stopped. No DNS or non-VPN fallback.
- [ ] Enable **Retry if WireGuard interface stops** and Android Always-on; controlled unexpected interface-down should recover, without runaway retries or password prompts. Confirm manual Disconnect stays OFF even overnight.
- [ ] Wi-Fi ↔ cellular handoff, screen lock/Doze, reboot and overnight standby; note last handshake and whether VPN recovered. Do not enable Android *Block connections without VPN* until IPv4/IPv6/DNS routing has been verified.
- [ ] With gateway unreachable but interface still UP, app must not claim the connection is healthy merely from UP state or churn the tunnel on stale handshake.
- [ ] Confirm Moka's `http://10.77.0.1:4533` still works via VPN, and fails without VPN; normal HTTPS Navidrome remains independent.
- [ ] Install the Fedora unit, persist the narrow firewall rule, reboot Fedora, then verify the listener and Moka again.

## Fedora procedure

Follow [the exact gateway installation and verification guide](../gateway/WONHEE_NAVIDROME_SYSTEMD.md). Inspect and stop only the identified old manual `socat` PID before enabling the unit. Do not publish TCP 4533 through the home router or change Podman to bind `0.0.0.0`.

## Not implemented or verified yet

- Full-tunnel leak-free or fail-closed guarantees, Android lockdown correctness, DNS-over-QUIC/DoH3, DNS ad blocking, tracker protection, captive-portal handling, guaranteed reconnect after force-stop, and automatic stale-handshake recovery.
- This preview is not a formal security audit and is not a guarantee that cellular calls or other Android services follow the VPN.
