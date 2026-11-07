# Wonhee Proxy — Development Handoff

Last updated: 2026-11-07

## Batch F.3b 0.15.15 — Opt-in passive physical underlay headers (2026-11-07)

- New draft PR [#46](https://github.com/yooshastan/Wonhee-Proxy/pull/46) on `feature/batch-f3b-underlay-passive-01515`; version **0.15.15**, code **63**. Separate from F.3a's test-only PR #45 and F.3 RFC #44.
- One opt-in **5-second** outgoing physical-interface capture of up to **32** packet headers (`-s 64`), only when both selected kernel identities, exact 3-rule routing ledger/live ownership and actual IPv4/IPv6 guard-OFF preflight pass. Requires root `tcpdump`/`timeout`; absence safely refuses.
- In-memory ephemeral `tcpdump` summaries become aggregate candidate counts only (DHCPv4 UDP, plain DNS UDP/TCP, TCP/80, ICMPv6). Raw addresses, endpoint tuples and packet summaries are never shown or recorded in Wonhee's diagnostic journal. No pcap file, generated traffic, probes, firewall/routing/tunnel/DNS changes, or forced handoffs.
- **Limit**: observing headers on a physical interface does **not** prove that Android's own control-plane emitted them, that they traversed local OUTPUT, or that the old kill switch caused the previous interruption. A blank window is not proof of absence; packet classification is provisional. Batch F remains **hard disabled**.
- Test-only classifier and redaction unit tests added; device protocol at `docs/PRODUCT_BATCH_F3B_PASSIVE_UNDERLAY_TEST_PLAN.md`. **CI PASS**: [Android + Java #42423508558](https://github.com/yooshastan/Wonhee-Proxy/actions/runs/42423508558), [native dual-WireGuard #42423508569](https://github.com/yooshastan/Wonhee-Proxy/actions/runs/42423508569). Installable artifact `wonhee-01515-f3b-passive-underlay-debug-apk` (ZIP with app-debug.apk); Pixel 8a consented device observation pending.
- Keep current HOME/AirVPN split routing stable and guard OFF. Never uninstall the working app to force an APK install if debug signatures differ; doing so could erase route ownership records. Issue [#41](https://github.com/yooshastan/Wonhee-Proxy/issues/41) remains unresolved and no live firewall activation is authorized.

## Batch F.3a — Offline contract matrix (2026-11-07)

- Following successful 0.15.14 F.2 paired health snapshots, F.3 RFC is in [draft PR #44](https://github.com/yooshastan/Wonhee-Proxy/pull/44), with **pure-code safety checks** in [draft PR #45](https://github.com/yooshastan/Wonhee-Proxy/pull/45) on `feature/batch-f3a-static-policy-matrix`.
- Files added: `RootGuardF3PolicyMatrix.java`, `RootGuardF3PolicyMatrixTest.java`, and `docs/PRODUCT_BATCH_F3A_OFFLINE_MATRIX_TEST_PLAN.md`; workflow compiles and runs new Java test. No APK version bump, no UI/root write changes.
- F.3a tests the existing owned-chain first-match **synthetic** IPv4/IPv6 HOME/Internet route policy, direct underlay REJECT, marked exact WireGuard endpoint, mark/port mismatch, endpoint rotation, IPv6 control-plane candidates, and physical-underlay change. It explicitly flags shared Android mark `0x20000`, unverified socket provenance and independent recovery as blocking issues.
- **Activation remains blocked irrespective of model test result.** A matching simulated RETURN or REJECT does not prove real traffic, DNS isolation, underlying Android netd handling, or fail-closed continuity. Keep HOME/AirVPN routing untouched and Batch F OFF. Issue #41 remains open.
- **CI PASS:** Android compilation and core tests [42422780898](https://github.com/yooshastan/Wonhee-Proxy/actions/runs/42422780898); native WireGuard tests [42422780906](https://github.com/yooshastan/Wonhee-Proxy/actions/runs/42422780906). No new APK version is needed for this test-only policy work. PR #45 stays draft until F.3b read-only traffic attribution and later F.3c/F.4 recovery gates are defined.
- Next F.3b gate: design a *read-only*, privacy-minimizing local OUTPUT-chain attribution method on target Android before considering any scope-limited exceptions. No forced tunnel disconnections or firewall activation.

## Batch F.2 second manual snapshot PASS (2026-11-07)

- Pixel 8a read-only second snapshot **COMPLETE**, 265 seconds after first. HOME `wnma292ddb4b6da`: cumulative RX 97,726,320, TX 698,572 bytes, **RX +3,032 / TX +3,400 bytes**, last handshake 83 seconds ago; IPv6 endpoint, marked physical route `wlan0`.
- AirVPN `wnm68fe81200daa`: cumulative RX 891,161,476, TX 116,677,112 bytes, **RX +6,027,976 / TX +1,981,624 bytes**, last handshake 116 seconds ago; IPv4 endpoint, marked physical route `wlan0`.
- No endpoint-change or underlay-change flags emitted. Both tunnel identities **2/2**, counters **2/2**, endpoint route predictions **2/2**. Exact owned routing MATCH: ledger **3**, live **3**, HOME root **3/3**, public root **2/2**. Batch F ledger OFF; separate live guard audit confirmed owned anchors and chains absent.
- **F.2 first + second stable-Wi-Fi manual snapshot device milestone PASS.** This is not automatic outage detection, real endpoint packet-path verification, network-handoff testing or fail-closed proof. Batch F remains hard-disabled.
- Next engineering stage: F.3 offline policy/spec and controlled rollback/fail-closed test matrix, without altering running kernel rules.

## Batch F owned guard OFF reverified during F.2 testing (2026-11-07)

- User uploaded a separate read-only Batch F exact guard audit: **COMPLETE · VERIFIED OWNED GUARD OFF**; ownership ledger **OFF**, live IPv4/IPv6 OUTPUT anchors **ABSENT**, and app-reserved guard chains **ABSENT**.
- This supports that the previous experiment's Wonhee-owned guard was fully removed, but does not cover foreign firewall rules or prove leak-free traffic.
- **Do not mistake this screenshot for the second F.2 passive health comparison.** First F.2 snapshot was already completed; comparison of RAM-only RX/TX deltas, changed endpoint values and underlay predictions is still pending. Batch F activation stays paused.

## Batch F.2 first device snapshot passed (2026-11-07)

- Pixel 8a 0.15.14 screenshot reports **COMPLETE** for first manual passive health snapshot.
- Exact split-routing ledger **3**, live priorities **3**, ownership **MATCH**; HOME root lookups **3/3**, public root lookups **2/2**. Batch F guard **ledger OFF** (live anchors still require separate guard audit).
- HOME `wnma292ddb4b6da`: handshake 64s ago, cumulative RX 97,723,288 / TX 695,172 bytes, endpoint family IPv6, marked underlay prediction `wlan0`.
- AirVPN `wnm68fe81200daa`: handshake 92s ago, cumulative RX 885,133,500 / TX 114,695,488 bytes, endpoint family IPv4, marked underlay prediction `wlan0`.
- Two kernel identities verified; 2/2 transfer counters readable and 2/2 endpoint route predictions. Both reported UDP mark 0x20000 (shared Android protected-from-VPN bit; not unique per tunnel identity).
- **This is only the first manual sample**: no delta, live packet path, underlay-handoff or firewall-blocking inference can be drawn. Repeat manual snapshot without changing network; compare RAM-only counters/endpoints/underlay predictions. Keep Batch F OFF and perform exact separate owned guard audit if not already done in this build.

## Batch F.2 0.15.14 manual passive health diagnostics (2026-11-07)

- New isolated branch: `feature/batch-f2-readonly-health-01514`, derived from user's installed 0.15.13.1 diagnostic branch. Version **0.15.14** / code **62**; no changes to the working split-route or Batch F guard implementation.
- New **manual read-only F.2 snapshot** in Multi-Tunnel Lab > Network Protection, with a separate pure Java classifier/test. Collects verified kernel interface/UP state, latest handshake age, cumulative RX/TX, UDP mark, numeric endpoint **family** and predicted physical underlay; private/public representative root route lookups plus exact split-route ledger/live ownership.
- A second tap compares RAM-only snapshots for counter deltas, endpoint changes and underlay prediction changes. Endpoint address and public key are never emitted or journaled; no background monitoring, DNS queries, app sockets, firewall/routing writes or automatic recovery.
- Guard ownership **ledger only** is shown; existing exact live-chain audit is still required. A quiet/stale handshake cannot alone establish failure, and a predicted underlay cannot establish actual UDP egress.
- Device plan: `docs/PRODUCT_BATCH_F2_PASSIVE_HEALTH_TEST_PLAN.md`. **CI PASS**: Java core and Android debug compilation [42421267321](https://github.com/yooshastan/Wonhee-Proxy/actions/runs/42421267321), native independent WireGuard tests [42421267283](https://github.com/yooshastan/Wonhee-Proxy/actions/runs/42421267283). Artifact `wonhee-01514-f2-manual-health-diagnostic-debug-apk` (GitHub Actions ZIP); read-only Pixel 8a test pending. **Batch F activation remains quarantined** after issue #41 and future operational recovery needs independent USB ADB support.

## 0.15.13.1 device smoke test (2026-11-07)

- User installed the diagnostic APK and reported **everything appears to be running as expected**. This confirms installation and initial observed normal operation; no fresh per-button routing/ownership or firewall audit screenshot was supplied on 0.15.13.1.
- Do not claim live routing security tests, ongoing connectivity/underlay handoff or Batch F fail-closed behavior passed on this version. Keep Batch F activation paused.
- Next development gate: Batch F.2 **read-only** runtime health monitoring with a manual snapshot of tunnel identities, last handshake age, RX/TX growth, endpoint/underlay changes, exact route/ledger state; never automatically modify firewall/routing or send connectivity test packets.

## Routing ownership recovered; audit status fix in progress (2026-11-07)

- On the 0.15.13 diagnostic APK, first screenshot showed **guard ledger OFF**, **no IPv4/IPv6 OUTPUT anchors or app-reserved guard chains**, plus a read-only Batch F model predicting **REJECT** for direct underlay DHCPv4, HTTP validation, DNS UDP/53 and IPv6 router solicitation; selected HOME/Navidrome and public AirVPN packet models showed **RETURN**. These are hypothetical, not captured Android packets or evidence of outage causation.
- The same device initially showed **routing rollback ledger EMPTY** despite **3 live reserved-priority rules**, **HOME 3/3**, **UID-10000 70/70 marked simulations PASS**, and **protectedFromVpn 3/3 PASS**. User used the *exact identity-verifying Verify + recover matching routing rules* function, then posted a fresh audit showing **routing ledger 3**, **live reserved rules 3**, **HOME 3/3**, **AirVPN public IPv4/IPv6 MATCH**, **70/70 mark-aware simulations PASS**, and **protectedFromVpn 3/3 PASS**.
- The restored state is a strong working baseline; **do not remove/reapply any routing rules unnecessarily**. Keep Batch F firewall disabled.
- A source bug caused `auditRouting()` to return successful status from matching route simulations even when its own warning showed missing/unverified ownership. The follow-up patch requires that owned ledger content agrees with selected profiles, all reserved priorities have the correct count, and the **exact live commands** match saved rules. Missing/unverified/foreign/stale records return CHECK REQUIRED. Verified legacy selectors remain supported for exact rollback.
- Added pure Java regression tests for missing ledger with live rules, extra/missing priorities, selector verification, foreign interface, and exact legacy selector adoption. This change is audit/reporting-only; no root firewall or routing commands are modified.
- Packaged as **0.15.13.1** (versionCode **61**) diagnostic-only build, with a distinct artifact name to distinguish it from previously tested 0.15.13. Audit/reporting fixes only; no routing policy changes and Batch F activation remains paused. CI must pass on this final commit before device testing. Draft PR #42 remains open and the [Batch F connectivity issue #41](https://github.com/yooshastan/Wonhee-Proxy/issues/41) remains unresolved.

## Batch F.1 diagnostic branch (2026-11-07)

- **New draft PR #42:** https://github.com/yooshastan/Wonhee-Proxy/pull/42
- Branch `feature/batch-f1-control-plane-risk-audit-01513` derived from tested Batch B.1 PR #40.
- Version **0.15.13**, code **60**, experimental `.rootlab` debug application.
- **Batch F activation and optional underlay packet challenge are quarantined** at both UI and root-session level. No activation can be initiated through the diagnostic build until the code is deliberately changed and retested.
- A new Batch F **read-only control-plane flow preview** models the owned firewall's first-match actions for exact marked WireGuard UDP endpoint exceptions, tunneled traffic, HOME anti-fallback, DHCP UDP/67, underlay HTTP/DNS and IPv6 router solicitation.
- The modeled REJECTs are potential contributors to the observed connectivity interruption; they are not proof that these flows were emitted or that Android needed them. No broad underlay bypasses were introduced.
- Pure-Java regression tests cover IPv4/IPv6 rule matching and activation quarantine. CI status must be checked before providing a test artifact.
- Read-only ownership audit and **Disable Batch F + exact cleanup** are retained. Batch B.1 split routing, ledger and Android routing rules are unmodified. Issue #41 stays open.
- Device test plan: `docs/PRODUCT_BATCH_F1_CONTROL_PLANE_DIAGNOSTIC_TEST_PLAN.md`. **No activation/packet challenge testing** with 0.15.13.

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

## Batch F active guard preflight PASS — first activation (2026-11-07)

- Pixel 8a user screenshot: **BATCH F — GUIDED DUAL-TUNNEL TEST PREFLIGHT COMPLETE** while **Live exact IPv4/IPv6 guard: ACTIVE · MATCH**.
- Selected independent kernel tunnel identities: **2 VERIFIED**. Endpoint marks and current underlay routes: **VERIFIED**. Selected split/default routes: **MATCH**.
- Current underlay reported **`rmnet16` (route prediction only)**, whereas the earlier preflight used **`wlan0`**. This is consistent with cellular becoming the underlay, but the screenshot alone does **not** establish when or why it changed, or certify handoff safety.
- Separate DNS guard OFF; unattended recovery OFF; configured Android Private DNS OFF.
- Preflight sent **no packets** and changed **no policies**. This validates active rule shape/state against the app's plan, not packet-level drop behavior or fail-closed tunnel loss.
- Next safest device step: **Verify live IPv4/IPv6 guard + rollback ledger** independently while guard is active. Only with functional USB ADB recovery and explicit consent should the optional one-packet-per-family challenge be considered. Otherwise **Disable Batch F guard + verify exact rollback** now, then run guard read-only audit requiring ownership ledger OFF and no app-reserved OUTPUT anchors or chains.
- While guard ACTIVE: do not disconnect tunnels, reboot or intentionally force a Wi-Fi/cellular handoff. Do not assume local Termux alone is an independent recovery channel.
- Batch F must not be marked fully fail-closed tested until controlled packet blocking and exact rollback are both verified, and broader disconnect/handoff behavior remains a separate gate.

## Batch F active-guard connectivity loss — BLOCKER (2026-11-07)

- After Batch F guided preflight showed **ACTIVE · MATCH** for both IPv4 and IPv6 owned guard chains, user reported: **"I lost connection while that was active so I had to disable it."**
- User took recovery action by disabling the guard. **Post-disable ledger/OUTPUT-chain absence and connectivity restoration are not yet independently confirmed** in the conversation.
- Earlier active preflight reported physical underlay as `rmnet16` (cellular), versus `wlan0` in the earlier guard-off preflight. This is a lead for underlay transition/control-plane trouble, **not proof of the cause**.
- Implementation audit: Batch F OUTPUT guard permits loopback, exact WireGuard UDP endpoint tuple + mark, selected tunnel-interface traffic and configured peer CIDRs, then terminal REJECT. Its preflight verifies static rule ownership and predicted routes, not ongoing connectivity/underlay handoff. The terminal REJECT could block Android underlay-related/control traffic; dynamic endpoint/underlay changes could also break tunnels. No unverified automatic firewall exemption should be installed.
- **Batch F testing BLOCKED pending post-disable verification and root-cause investigation. DO NOT RE-ENABLE** just to reproduce without independent USB ADB recovery and a revised test plan. Do not mark F fail-closed validated.
- GitHub tracking issue: https://github.com/yooshastan/Wonhee-Proxy/issues/41.
- Next safe checks: run Wonhee **Verify live IPv4/IPv6 guard + rollback ledger** and require OFF ledger, absent OUTPUT anchors and chains. Termux read-only checks can additionally inspect the three split-route rules and current connectivity; share whether HOME, public Internet, or both failed. Retain HOME/AirVPN if functioning and preserve Batch B.1 routing policy.

## Connectivity recovery clarification (2026-11-07)

- User clarified that after experiencing connectivity loss with Batch F active, they selected **Disable Batch F** and **Remove routing overrides**, perhaps before the firewall-removal process had finished. Connectivity returned either immediately or during the firewall removal; exact timing is uncertain.
- User then explicitly **reapplied the Batch B.1 split-routing correction**. **Public Internet and private Navidrome are now both accessible again.**
- Because BOTH Batch F and the split-routing overrides were removed in close succession, this incident **does not isolate the active OUTPUT guard as the sole cause** of the outage. The return of connectivity may also have been due to delayed firewall cleanup. Treat a transient handoff/control-plane effect as a hypothesis only.
- Next safe step: while guard remains OFF, verify **owned guard ledger OFF**, **no IPv4/IPv6 owned OUTPUT anchors/chains**, and **reapplied split-routing ledger/live rules 3, HOME 3/3, mark-aware routes PASS, public IPv4/IPv6 MATCH**.
- Avoid further Batch F activation without independent USB ADB recovery, clearly defined connectivity monitoring and controlled rollback. Preserve separate validation statuses for Batch B and Batch F. Issue: https://github.com/yooshastan/Wonhee-Proxy/issues/41.

## Post-incident restoration audits PASS (2026-11-07)

- User uploaded two latest-readout screenshots after disabling Batch F, removing split overrides during recovery, and reapplying Batch B.1.
- **Root route audit COMPLETE:** 3/3 HOME IPv4 routes to `wnma292ddb4b6da` MATCH; public IPv4 and IPv6 to `wnm68fe81200daa` MATCH; UID-10000 mark-aware simulations **70/70 PASS** across 14 marks; protectedFromVpn bypass **3/3 PASS**; routing rollback ledger 3; live reserved priorities 3.
- **Batch F firewall audit COMPLETE:** VERIFIED OWNED GUARD OFF; ownership ledger OFF; IPv4/IPv6 OUTPUT anchors ABSENT; app-reserved guard chains ABSENT.
- User reported both Internet and Navidrome available again. The static audits corroborate restored expected routing and fully removed Wonhee-owned Batch F guard. They do not explain whether the original outage was due to the active guard, underlay handoff, delayed removal or interaction with routing cleanup.
- **Preserve this known-good state; DO NOT RE-ENABLE Batch F until its connectivity interruption is addressed.** Continue code/test investigation of a dynamic underlay, Android network management traffic and the guard terminal REJECT behavior. The guard must not be declared fail-closed and operationally reliable based only on installation and ownership checks.
- Tracking: https://github.com/yooshastan/Wonhee-Proxy/issues/41. Moka's Android `TRANSPORT_VPN` gate remains a separate compatibility issue.

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