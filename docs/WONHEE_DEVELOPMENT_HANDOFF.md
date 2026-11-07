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

## Post-install Batch B.1 device result and Moka compatibility (2026-11-07)

- The Pixel 8a screenshot reports **Installed 3 Wonhee-owned split priority rules** in 0.15.12, with UID-0 and representative UID-10000 fwmark route simulations passing. This establishes that the device accepted the new destination-specific kernel policy rules; capture the full post-install root audit, exact rule listing, and rollback still remain to be independently verified.
- The browser can now open the configured Navidrome server at `http://10.0.0.169:4533`. This proves browser reachability, **not by itself the exact tunnel packet path**, especially if the device is on the same Wi-Fi as the server.
- Moka still reports: **Approved private Navidrome VPN route is unavailable; no direct fallback was used.** This is expected given Moka's `PrivateVpnNetworkGate`, which explicitly requires an Android `TRANSPORT_VPN` Network and matching `LinkProperties` route, not merely root kernel WireGuard interfaces or RPDB rules.
- Do not relax Moka's private HTTP fail-closed behavior or use plain `URL.openConnection()` as a fallback. The Moka issue to track a verified implementation is https://github.com/yooshastan/MokaMusicPlayer/issues/26.
- Next: verify kernel rule selector `0x0/0x20000`, complete a full read-only audit and exact rollback verification, and test actual tunneled traffic independently. For Moka connectivity, either use a trusted HTTPS Navidrome endpoint or implement an Android-visible VPN/network-bound tunnel data path with fail-closed tests.

## Batch B.1 post-install routing audit PASS (2026-11-07)

- User screenshot of the read-only root route audit reports **3/3 HOME split-route matches**, **public IPv4 and IPv6 through AirVPN: MATCH**, and **70/70 representative UID-10000 Android mark-route simulations across 14 unprotected marks: PASS**.
- The same audit shows **protectedFromVpn bypass 3/3 PASS**, **rollback ledger 3 rules**, **live reserved-priority rules 3**. Planned rules at 12500, 12501, 12502 use `fwmark 0x0/0x20000` for `10.0.0.0/24`, `10.6.0.0/24`, and `10.77.0.0/24` to HOME interface `wnma292ddb4b6da`.
- Separate root route simulations using Moka UID 10300 and Wi-Fi mark `0x1009d` route `10.0.0.169` through HOME and `1.1.1.1` through AirVPN.
- Browser access to private Navidrome is working; Moka private-HTTP still fails closed because it requires an Android-recognized `TRANSPORT_VPN` Network (see Moka issue #26).
- **Not yet verified:** actual packet capture proving browser traffic traverses HOME and does not travel directly on Wi-Fi; device-run exact owned-rule rollback for the new 0.15.12 rules; application-specific IPv6 egress; fail-closed tunnel interruption. Do not mark Batch B or F fully complete based on root and representative simulated route lookups alone.
- **Next controlled test:** confirm `tcpdump` availability in Termux and collect narrowly filtered interface-level evidence while refreshing Navidrome. Preserve current routes and both connected tunnels; keep Batch F OFF. After traffic verification, perform exact owned-rule rollback via Wonhee UI and confirm Android priority-13000 rules remain unchanged.

## First captured Navidrome packets on HOME (2026-11-07)

- A Pixel 8a Termux read-only `tcpdump -ni any -c 24 'host 10.0.0.169 and tcp port 4533'` capture showed 24 packets on HOME interface `wnma292ddb4b6da` between client source `10.6.0.2` and server `10.0.0.169:4533`.
- Observed outbound SYNs, inbound SYN/ACKs, client ACKs and bidirectional application-payload TCP packets. Capture summary: **24 packets captured; 116 packets received by filter; zero packets dropped by kernel**.
- This is actual application packet-path evidence that browser Navidrome traffic traversed the HOME kernel interface, stronger than UID/mark route simulations. It does **not** independently rule out concurrent cleartext packets on the physical `wlan0` interface, nor establish that WireGuard outer UDP delivery is leak-proof under disconnection.
- Next safe check: bounded read-only `tcpdump` on `wlan0` for cleartext destination `10.0.0.169` TCP port `4533` while refreshing the browser. Expected: no matching physical-interface cleartext packets. Keep both tunnels and all routing rules in place, Batch F off.
- After absence of cleartext direct traffic is established, test **Remove Wonhee routing overrides** exact rollback and verify priorities 12500–12502 disappear, Android priority-13000 rules remain, and rollback ledger clears; reapply correction only via guarded app workflow if continuing tests.

## Physical underlay cleartext check — no packets observed (2026-11-07)

- User's Termux tcpdump on physical `wlan0` with `host 10.0.0.169 and tcp port 4533` returned **0 packets captured, 0 received by filter, 0 dropped by kernel**. This is consistent with the preceding verified bidirectional Navidrome TCP exchange on HOME kernel interface `wnma292ddb4b6da`.
- Interpret the result as **no matching direct cleartext Navidrome traffic observed during this capture**. A definitive negative conclusion requires confirming that the browser refresh occurred while the physical capture was active; this single filter does not establish complete leak prevention during disconnects, handoffs, other interfaces or other destinations.
- Next device gate: inspect ledger (3 owned) and live reserved rules (3), perform **Remove Wonhee routing overrides** in UI with both tunnels connected, Batch F OFF and root/ADB recovery available. Verify priorities 12500–12502 disappear, Android's four priority-13000 rules remain, and ledger clears. If continuing tests, reapply through the guarded Wonhee UI (never by hand) and re-audit the 70/70 marked-route selection.

## New-selector kernel rollback verified (2026-11-07)

- After testing the 0.15.12 rules with successful 70/70 Android mark-route simulations and a successful HOME Navidrome packet capture, the user ran `ip -4 rule show` after using Wonhee's cleanup flow.
- **Priorities 12500, 12501, 12502 are absent**. The four original Android **priority-13000 rules are still present**, unchanged in the reported output.
- This verifies exact **kernel-rule removal** for the three new overrides. The app-level rollback ledger clearing has **not** yet been independently reported; a read-only Wonhee routing audit is needed.
- With both tunnels still connected and Batch F OFF, verify ledger EMPTY and no reserved-priority rules. If confirmed, explicitly reapply the new correction via Wonhee, then run the read-only route audit. Required: ledger 3, live rules 3, private 3/3, public IPv4/IPv6 MATCH, Android mark-aware 70/70 (or all probes currently discovered), protected-from-VPN 3/3. Do not enable Batch F before these gates.
- If app-level recovery/ledger status mismatches the kernel snapshot, do not manually edit rules or disconnect tunnels; investigate before reapply.

## Full ledger-empty rollback audit confirmed (2026-11-07)

- Following removal of the new 0.15.12 three-rule correction via the Wonhee UI, a fresh **read-only routing audit** showed **Wonhee rollback ledger EMPTY** and **Live reserved-priority rules: 0**.
- The private HOME destinations `10.0.0.0/24`, `10.6.0.0/24`, and `10.77.0.0/24` again resolved to AirVPN, marked **MISMATCH** as expected without the split correction.
- Public IPv4 and IPv6 remained on AirVPN, both **MATCH**. The earlier Termux `ip -4 rule show` also confirmed only Android's four priority-13000 rules remained and no 12500–12502 rules.
- This independently verifies both the **kernel-rule removal** and **application rollback ledger clearing** portions of Batch B.1. A `CHECK REQUIRED` label in the audit is expected while no split rules are installed; it does not indicate cleanup failure.
- Next: with both tunnels still connected and Batch F OFF, explicitly **Apply split-route correction · experimental** to reinstall the 0.15.12 mark-aware HOME rules. Re-audit HOME 3/3, Android mark-aware simulations all passing (70/70 if same marks), protectedFromVpn 3/3, public IPv4/IPv6 AirVPN, and ledger/live priority counts both 3. Verify application access again. Do not enable Batch F before this validation.

## Post-rollback reinstallation: complete (2026-11-07)

- New Pixel 8a read-only audit after explicit 0.15.12 split-route reinstallation shows **COMPLETE** with 3/3 HOME IPv4 destinations to `wnma292ddb4b6da`, public IPv4 and IPv6 to AirVPN `wnm68fe81200daa` **MATCH**.
- The three planned priority 12500, 12501, 12502 rules use **`fwmark 0x0/0x20000`**, with **Wonhee rollback ledger 3** and **live reserved-priority rules 3**.
- **Android mark-aware simulations 70/70 PASS over 14 unprotected marks; protectedFromVpn bypass 3/3 PASS.** This confirms successful reapplication after earlier exact removal and EMPTY-ledger audit.
- Combined Batch B.1 evidence: root and marked route simulations, actual bidirectional Navidrome TCP observed on HOME, zero direct HTTP packets observed on `wlan0` during separate filtered capture, safe exact rule removal, empty ledger verification, and successful reinstallation.
- **Remaining limitations:** no independent disconnect/reboot/handoff leak claims, and Moka private cleartext HTTP remains blocked by its Android-recognized VPN network gate (Moka issue #26). Avoid upgrading the routing prototype's status to system-wide fail-closed verification.
- **Next step (Batch F read-only gate):** with both tunnels connected, USB ADB recovery prepared, Batch F guard OFF, Batch D/E DNS enforcement OFF, Batch C unattended recovery OFF, verify the guard's owned-ledger/live-chain OFF status and run **Batch F guided preflight · read only**. Require full preflight pass before separately considering an opt-in guard activation and controlled rollback.

## Batch F guard-off and guided preflight PASS (2026-11-07)

- Pixel 8a screenshot: **BATCH F — VERIFIED OWNED GUARD OFF**, with **ownership ledger OFF**, **live IPv4/IPv6 OUTPUT anchors ABSENT**, and **app-reserved guard chains ABSENT**. This verifies only the app-owned guard state; not rules from other owners.
- Second screenshot: **BATCH F — GUIDED DUAL-TUNNEL TEST PREFLIGHT COMPLETE**. It reports **2 independent kernel identities VERIFIED**, endpoint fwmarks and current physical underlay routes VERIFIED, underlay `wlan0` (route prediction), selected split/default routes MATCH, exact IPv4/IPv6 guard OFF/ABSENT, separate DNS guard OFF, unattended recovery OFF, configured Android Private DNS OFF.
- No packets were sent and no policies were modified in this preflight. This is **not** packet-level leak-proof validation, automatic failover testing, or reboot safety.
- Next controlled gate, **only with confirmed USB ADB and root recovery**: snapshot current IPv4 and IPv6 OUTPUT rules; ensure both tunnels still UP and route audit remains valid; explicitly enable Batch F guard once; immediately audit live exact IPv4/IPv6 anchors/chains + rollback ownership, then rerun the guided preflight while guard is active. Keep tunnels connected and do not reboot. Review results before running optional two-packet challenge. If guard refuses, preserve the error stage and do not retry blindly. When appropriate, explicitly disable Batch F and verify exact rollback.
- Moka private HTTP integration remains a separate issue and is not a blocker to Batch F firewall ownership testing. Do not imply real-app protection or full fail-closed capability based on guard plan/preflight checks alone.

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