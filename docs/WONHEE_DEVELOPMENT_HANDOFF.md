# Wonhee Proxy — Development Handoff

Last updated: 2026-11-07

## Active development checkpoint

- Current test version: **0.15.12**, versionCode **59**
- Active branch: `feature/batch-b1-android-mark-aware-routing-01512`
- Draft PR: [#40 — Product Batch B.1 Android mark-aware split routing](https://github.com/yooshastan/Wonhee-Proxy/pull/40)
- PR #40 base: `feature/product-batch-f-killswitch-0156`
- PR #39 (Batch F) remains a draft. Do not merge Batch F before Batch B.1 device verification.
- GitHub Actions run 144: **PASS** — Android 16 debug APK built and standalone core tests passed.
- Native dual-WireGuard workflow run 56: **PASS** — native session tests and Android ARM64 cross-compile passed.
- Artifact: `wonhee-01512-product-b1-mark-aware-split-routing-debug-apk`
  - Contains `app-debug.apk`
  - Run: https://github.com/yooshastan/Wonhee-Proxy/actions/runs/42406854947
  - Artifact expires 2026-11-21.

## Device findings before 0.15.12

- HOME and AirVPN both connected on the Pixel 8a.
- HOME route table: 1076; routes: `10.0.0.0/24`, `10.6.0.0/24`, `10.77.0.0/24`.
- AirVPN route table: 1075; route: `default`.
- Root UID route audit showed 3/3 HOME routes and public IPv4/IPv6 on AirVPN.
- Three legacy priority-12500+ rules were installed and their rollback ownership was recovered.
- Actual Navidrome browser access and Moka connection both failed.
- UID/mark route lookups showed all five tested marks — `0x1009d`, `0xc489e`, `0xce8a6`, `0x1489e`, `0x1e8a6` — selecting AirVPN for both the HOME address and public IPv4.
- The original `fwmark 0x0/0x2ffff` selector excluded those marked sockets. Android's earlier priority-13000 AirVPN default lookup therefore won before the HOME rule.

## First 0.15.12 device audit (2026-11-07)

- User-supplied Pixel 8a screenshots show **root split-route matches 3/3** but **Android marked-route simulations 31/70 (14 discovered unprotected marks): FAIL**.
- Failing private destination lookups at representative UID 10000 still select AirVPN interface `wnm68fe81200daa` instead of HOME interface `wnma292ddb4b6da`, including for marks `0x1009d`, `0x1489e`, `0x1e8a6` and others.
- Protected-from-VPN lookups avoided HOME in **3/3** cases. The installed build incorrectly displayed `protectedFromVpn bypass: 3/3 · FAIL` because the label used the combined marked-route PASS flag. The indicator has been corrected on the development branch to report bypass and marked-route results separately; the installed APK still has the old label.
- The screenshot is from the **read-only audit before the user has confirmed removing old routing overrides and applying the new 0x0/0x20000 rules**. Do not interpret 31/70 as a post-install failure of the new selector.
- Next safe gate: confirm rollback ledger and live reserved priorities match, remove only the exact old Wonhee rules via the app, inspect the resulting RPDB, then explicitly apply the new selector and retest. Batch F remains OFF; do not manually flush Android rules or disconnect tunnels.

## 0.15.12 post-cleanup preflight refusal (2026-11-07)

- User successfully recovered the **three** legacy priority-12500–12502 rules using the exact matching-rule recovery UI, then removed them through Wonhee. A Termux `ip -4 rule show` inspection confirmed priorities 12500–12502 absent while all four Android priority-13000 rules remained unchanged.
- On selecting **Apply split-route correction · experimental**, Wonhee displayed **ROUTING PREFLIGHT REFUSED. NO ROUTING RULES CHANGED**. There is no evidence the new mark-aware rules were installed.
- The failure reason is **not yet identified**: `applyRouting()` catches all preflight exceptions and previously displayed only a generic message. Possible gates include DNS/Batch F ownership ledger, selected WireGuard identities, numeric endpoint availability and overlap, marked endpoint physical-underlay routing, or a reserved IPv4/IPv6 priority collision. Do not assume which one failed.
- The development branch now reports a **non-sensitive preflight stage label** in the refusal message; it does not disclose endpoints, IP addresses, public keys or arbitrary exception messages.
- Device can run the existing **Inspect UDP endpoint egress + Private DNS** read-only audit and **Audit owned DNS enforcement** before trying any mutation. Preserve active HOME and AirVPN tunnels and keep Batch F OFF.

## Batch B.1 correction in 0.15.12

- New HOME destination rules use `fwmark 0x0/0x20000`, `iif lo`, UID range `0-99999`.
- This matches locally generated traffic whose Android `protectedFromVpn` bit is clear, regardless of network ID. Protected sockets with bit `0x20000` are excluded.
- Public destinations do not match HOME prefixes and should continue to use AirVPN's default.
- The read-only audit now simulates representative unprotected marks discovered from live IPv4/IPv6 policy rules, using app UID 10000. It also checks public defaults and protected-socket bypass. This remains a route simulation, not proof of actual app sockets.
- Apply, Batch C readiness and Batch F gates require mark-aware route simulations.
- Batch C readiness accepts either distinct nonzero transport marks or the explicitly supported shared Android protectedFromVpn mark (`0x20000`), consistent with Batch F activation.
- Numeric WireGuard endpoints must be outside HOME split prefixes and their marked route must use a physical underlay before applying overrides or proceeding to Batch F.
- Five-field 0.15.11 ledgers decode as legacy `0x0/0x2ffff` rules, preserving exact deletion. Orphan legacy rules can only be adopted if every reserved rule and selected tunnel identity matches exactly.
- Android/netd priority-13000 rules are not modified.

## Next device actions

1. Keep HOME and AirVPN connected. Keep USB ADB authorized. Keep Batch F OFF.
2. Install 0.15.12 from the run 144 artifact.
3. Run **Audit effective routes · read only**. With the legacy rules still installed, root lookups may remain 3/3, but the mark-aware audit should expose the legacy-selector mismatch.
4. Use **Remove Wonhee routing overrides** to remove the exact three legacy rules from the recovered ledger. Do not disconnect tunnels.
5. Verify no Wonhee priority-12500–12799 rules remain and Android's priority-13000 rules are unchanged.
6. Use **Apply split-route correction · experimental**. The app must verify both tunnel identities, numeric endpoint non-overlap, physical endpoint underlay, and empty reserved priorities before mutation. If any check refuses, stop and capture the report.
7. Run the read-only audit. Expected: all HOME routes match for live unprotected marks, public IPv4/IPv6 remain on AirVPN, protectedFromVpn bypass passes, and the new three-rule ledger exactly matches the live rules.
8. Test actual browser access to `http://10.0.0.169:4533` and Moka Navidrome streaming. Also verify public IP/IPv6 exit behavior.
9. Test **Remove Wonhee routing overrides** and verify only the three exact new rules are removed and the ledger clears.

## Release gates

- Batch B: mark-aware routing, actual app traffic, endpoint underlay and exact rollback all pass.
- Batch F: remains disabled until Batch B passes; then separately validate preflight, controlled packet challenge, firewall counters and rollback.
- Batches D/E/G/H/I continue only with their own implementation, CI, device and rollback evidence.
- A successful CI build is not device security verification. Keep implementation, CI, device behavior, actual packet evidence and rollback status separate in every checkpoint.

## Safety rules

- Do not disconnect either tunnel or reboot while owned routing rules or Batch F guard rules are active.
- Do not edit Android's priority-13000 policy rules.
- Do not add broad fallback routes or weaken firewall policy as a workaround. The approved `0x0/0x20000` selector is destination-scoped to HOME prefixes.
- If ownership, route selection, endpoint egress or rollback is ambiguous, stop and preserve ADB recovery.
- Keep PR #40 draft until device tests pass.