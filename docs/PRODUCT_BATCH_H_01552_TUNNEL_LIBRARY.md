# Wonhee Product H — 0.15.52: One selection, one tunnel library

**Development candidate. Not a beta release.** Incorporates the 0.15.51 navigation / notification fix and the user-requested removal of duplicate Tunnels selections. VersionCode 99; `0.15.52-simplified-tunnels`.

## Everyday mental model

- **Home — choose and use.** Root Home checkboxes decide what the *next* Start uses. Standard Home radio selection chooses one Android VPN. Start/Stop stay on Home. Active root tunnels still require identity-verified Safe Stop.
- **Tunnels — add and configure.** Show all saved profiles, their traffic role and a direct **Edit settings** action on that profile. **No second select-these-tunnels checkbox panel, no "Manage tunnel connections & routes" detour to Root Lab, no default jump to legacy WireGuard manager.**
- **Protect — check DNS/filtering and security claims.** Clear separated states and explicit deep controls.
- **Stats — activity and diagnostics.** History uncertainty is not an error or proof of a leak.
- **More — deliberate advanced network tools.** The laboratory is available but is never the place normal users are routed to for selecting their next VPN connection.

## Focused tunnel settings screen

- Edit exactly the profile selected in the Tunnels library. No second profile picker.
- Configure original WireGuard routes, private-destination CIDRs, or experimental IPv4 + IPv6 Internet exit; choose imported or preset/custom DNS *inside* the profile.
- Save the same encrypted profile, preserving its imported keys and original wg-quick configuration. Validate route CIDRs with `VpnRouteModes.prepare` and DNS with `VpnDnsOverride.prepare`. No import/reparse secrets in logs or to remote servers.
- Optional Remove requires explicit confirmation, verifies exact unchanged profile, and updates Home's next-Start selection.
- Saved-profile edits and deletion are blocked while the Android VPN is active or busy; Root mode additionally requires available read-only root snapshot, no saved-profile tunnel present and no recorded owned DNS/firewall/route rules. Standard view with unverified old rooted state is also blocked.
- It is a **settings editor**, not live traffic routing or an all-traffic kill switch. It never starts/stops WireGuard, changes Android Private DNS, or alters firewall/routing rules itself.
- Return from Edit goes back to the saved Tunnels tab in the new dashboard. No old first-run manager appears unless deliberately opened for legacy-specific functions.

## Consolidated next on-device test pass

### Priority A — navigation, no network mutation

- [ ] A1 Launcher, quick tile, root notification and Standard notification always open Home.
- [ ] A2 Root Home displays both saved profiles with checkboxes; Tunnels screen shows saved cards with **Edit settings**, not another checkbox group.
- [ ] A3 Standard Home displays radio selection; Tunnels screen shows the same saved-card library and no second chooser.
- [ ] A4 Tap Tunnels → Edit on Internet profile: see **that exact name**. Tap Back: return to Tunnels (not old Wonhee).
- [ ] A5 Edit a second profile: its own values show, not first profile's.
- [ ] A6 Tap Add tunnel, cancel Android picker with Back: return to Home; no old manager.
- [ ] A7 Add a valid test profile, save and return: profile appears once in Home and Tunnels; selection remains.
- [ ] A8 Five bottom tabs remain readable in three-button and gesture navigation with large display text; card buttons do not clip.
- [ ] A9 Reopen Wonhee by app icon, app switcher and after force-stop (with tunnels safely down): new Home every time.
- [ ] A10 Navigate through More → Ultgram proxy tools and back: Home, not VpnActivity.

### Priority B — focused saved configuration, no active tunnels

- [ ] B1 Edit Internet exit / private-destination / original-route selections and save; reopen same profile and verify persistence.
- [ ] B2 Edit DNS preset and custom DNS IP; save valid config and verify persistence. Invalid DNS or CIDRs show a safe error; no saved change.
- [ ] B3 Save without changes, then reopen and confirm original profile key material is preserved; never expose keys in screenshots/logs.
- [ ] B4 Cancel edit without saving: no stored changes.
- [ ] B5 Cancel Remove: profile still exists. Remove a disposable test profile and verify it disappears from Home/Tunnels and the saved next-Start list.
- [ ] B6 Edit/remove while Android VPN running: refused. Edit/remove while root tunnel running, DNS/guard/route ledger recorded, or root status unknown: refused.
- [ ] B7 Reboot app normally, re-open Tunnels: no duplicate profiles or altered profile selection.

### Priority C — guarded connections, protection and recovery

- [ ] C1 With known-clean rooted network, Home Start uses selected profiles and retains existing H.1 confirmation; no second picker.
- [ ] C2 Cancel Start: network unchanged. Confirm Start: routes and DNS verified. Home reports verified state, not proof of leak-free internet.
- [ ] C3 Safe Stop targets actual identity-verified running profiles, even if next-Start checkboxes differ. Independent H.2a clean-stop audit must pass before update.
- [ ] C4 Wi-Fi ↔ cellular + background/resume: UI status refreshes accurately. Android Private DNS remains OFF on Pixel 8a testing.
- [ ] C5 Navidrome, browser DNS/ad blocking, and notification speeds continue working or produce a reportable concrete failure.
- [ ] C6 Standard VPN single-profile connect, Android permission, disconnect, and Always-on/lockdown guidance verified separately on non-root test phone.
- [ ] C7 No menu or status claims that the all-traffic kill switch is released: it remains a separate development / failure-test gate.

## Report findings in one consolidated reply

```text
Device / Android version / Root or Standard:
A1-A10: PASS/FAIL/NOT RUN
B1-B7: PASS/FAIL/NOT RUN
C1-C7: PASS/FAIL/NOT RUN
Top 3 things still requiring too many taps:
1.
2.
3.
Screenshots: only failed screens, redact secrets
```

**Do not deliberately trigger a root kernel/kill-switch failure while testing these UI changes.** Use H.1 Safe Stop and H.2a CLEAN_STOPPED before local signed installs. An official APK must use the original release keystore and the guarded update script, not the differently signed `.rootlab` CI artifact.
