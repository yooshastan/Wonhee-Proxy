# Product Batch C — Connection recovery (0.14.0 preview)

**Schedule identity:** Product Batch C in the canonical [A–I product roadmap](https://github.com/yooshastan/Wonhee-Proxy/blob/main/docs/PRODUCT_BATCH_ROADMAP_A_I.md). Diagnostic PRs #28–#31 reused the letters C/D/E for read-only experiments; those are separate and do **not** complete product C/D/E.

**Status:** user-reported Pixel 8a PASS on 2026-11-06 for the agreed Wi-Fi/cellular handoff, process restart, reboot, and manual-stop recovery checks. Product Batch D (DNS infrastructure) now follows on its own test branch; Product C's outstanding negative/security limitations below remain in scope and **do not** imply a kill switch.

## Boundaries and expected behavior

- Recovery defaults **OFF**; the user must explicitly select all currently UP independent root tunnels and acknowledge the warning.
- Stores only selected profile names and SHA-256 digests of their prepared saved configurations, not plaintext keys or passwords. Changes to keys, allowed IPs, DNS or routes invalidate consent for recovery.
- For a previously enrolled selection, checks the running kernel interfaces and both WireGuard public-key identities, and adopts exact matching survivors even after an app process restart. Only a missing approved link may be restarted.
- Rejects unmanaged `wnm*` interfaces, legacy root pair collisions, changed/missing policy rules, and any reserved routing priority not matching Wonhee's persisted rollback ledger. Never installs, replaces or removes routing rules automatically.
- Manual Disconnect persists *stop intent before* attempting to stop links, including when split rules prevent a safe disconnect. Explicit Disable immediately cancels future recovery while leaving interfaces unchanged.
- Android jobs are persisted and best-effort (periodic, deferred retry, boot/unlock scheduling); in-process network handoff callback is best-effort. Doze, battery restrictions and locked credential storage can defer or prevent recovery. Six failed attempts exhaust the automatic retry budget until the user explicitly re-enables.
- **No kill switch or DNS/firewall enforcement is installed.** Recovery does not verify payload path, HTTPS, authenticated service, UDP delivery or leak freedom. Traffic can use an unprotected fallback while links are down.

## One combined Pixel 8a checklist — preferably Termux

1. **Baseline:** Back up/imported encrypted profiles and keep root recovery access; verify Home `wnma292ddb4b6da` and AirVPN `wnm68fe81200daa` are both UP. Verify required Home split routes (3/3), owned ledger, public IPv4/IPv6 defaults and that the kill switch reports OFF. Do not change these for the test.
2. **Default:** New screen says Product Batch C recovery OFF. Do not opt in until both interfaces and routing audit match the intended baseline.
3. **Opt in:** Select **both** running profiles and tap `Enable recovery for selected UP tunnels`. Verify `OPTED IN` status. Do not select unrelated root links.
4. **No-op:** Tap `Check / recover missing selected links now`: reports 0 restored, 2 selected UP; no new kernel routes or firewall rules.
5. **Controlled missing link:** In an isolated test window with local root recovery available and no sensitive traffic, simulate an *unplanned* missing enrolled interface using a separately reviewed lab procedure, then run the check. Do **not** use Wonhee's Manual Disconnect for this test: it intentionally pauses recovery. Verify the missing interface's exact identity and that the other link was never touched. Never test while depending on the tunnel for your only remote access; an interface outage can expose fallback traffic because the kill switch is OFF.
6. **Process restart:** With both tunnels UP and recovery enabled, force-stop/relaunch the app, then run the check. It should adopt matching survivors without replacing them. Android force-stop can suspend jobs until the user opens the app again.
7. **Manual stop precedence:** Tap `Disconnect selected tunnels`. Recovery should become `PAUSED` immediately, even if owned split rules prevent safe disconnect. No automatic retry may re-enable the links. Remove/recover owned rules explicitly before completing a manual disconnection.
8. **Disable:** Tap `Disable automatic recovery`; confirm no subsequent background restoration while the kernel interfaces already UP remain unchanged.
9. **Negative tests:** Edit an enrolled profile; attempt adoption with a changed/missing routing ledger; introduce an unrelated `wnm*` interface only in a controlled lab. Each must refuse, leaving unknown links and external rules unchanged. Do not intentionally introduce priority-rule collisions on a daily-driver device.
10. **Handoff/reboot:** After re-enrollment test Wi-Fi ↔ cellular and a reboot separately. A missing/mismatched rule after reboot must block auto-restore, not silently recreate the split routes. After reboot use the app's read-only audit before considering manual repair. Background work may be delayed by Android.
11. **Stability:** Recheck root identities, WireGuard handshake timestamps, Home/private route and public defaults, DNS route audits and battery impact. Validate that no firewall rules were installed and no unsupported fail-closed claim appears.

## Termux read-only checks

```sh
su -c 'wg show interfaces'
su -c 'wg show wnma292ddb4b6da public-key'
su -c 'wg show wnm68fe81200daa public-key'
su -c 'ip -4 rule show'
su -c 'ip -6 rule show'
su -c 'wg show all latest-handshakes'
```

Do **not** post WireGuard private keys, config files or credentials to testing reports. Record pass/fail, the two interface names, warning text and relevant redacted errors. Batch C passes only after device tests; a green CI APK is a candidate, not completion.

## Deferred compatibility regression (after Batch I)

Moka Music Player reportedly works under a conventional single VPN but cannot connect to its Navidrome service when the independent Home + AirVPN tunnels run together. Browser TCP/HTTP to `10.0.0.169:4533` succeeds through Home while a Moka attempt produced no matching Home-interface TCP packets. Do not conflate that separate Android app-UID routing issue with successful root route lookups or Batch C recovery. Track in [post-batch compatibility backlog](POST_BATCH_I_COMPATIBILITY_BACKLOG.md) and retest after A–I.
