# Wonhee Product H · 0.15.49 quick-connect UX

This is an in-place iteration of PR #84, responding to the first on-phone screenshots of 0.15.48. **Do not merge or publish as beta until the manual checklist below passes.** No route, firewall, encrypted DNS, backend or kill-switch enforcement code is changed.

## Four reported failures and corrections

1. **Start hidden behind explanations** — Home now begins immediately after the brand with a large **Start / Stop** button, then **Add tunnel**. Status and saved-tunnel summary follow, with no lab jargon above the first action.
2. **Bottom buttons overlap Android system navigation and clip text** — apply status bar, cutout, left/right and navigation bar window insets to the dashboard frame; use five icons with short captions (Home, Tunnels, Protect, Stats, More), equal-weight taps, accessible captions and a 60dp minimum touch region.
3. **Settings “WireGuard profile manager” apparently did nothing** — remove that redundant entry. Home **Add tunnel** and Tunnels **Add tunnel** now open the existing Android document picker directly through `VpnActivity`'s import handler. Home Start/Stop enter existing explicit connection workflows.
4. **“REBOOT OR DEVICE CLOCK CHANGE SUSPECTED” sounded like a VPN failure** — Stats now says DNS history needs a fresh check after a possible restart or clock change; original diagnostic details remain in an opt-in explanation. The warning does **not** mean that current DNS is leaking.

## User-first flows

### Root workspace

- First action is **Start** if no saved-profile root tunnels are detected, **Stop** if detected identities are fully verified, or **Review connection** if some detected identities do not match. An unavailable snapshot disables the quick action rather than guessing.
- Start opens a compact multi-choice tunnel picker in the existing root control activity. The selection is saved locally for convenience. The existing H.1 `startManagedStack` validation and explicit final confirmation still run; no network mutation is triggered just by opening the screen.
- Stop passes the currently detected *identity-verified saved-profile* tunnel names into the picker. User must confirm the selection, then the existing H.1 Safe Stop confirmation runs. It does not flush unknown firewall rules.
- A new or empty installation is sent toward **Add tunnel** instead of an inactive control.

### Standard VPN

- Start opens the existing WireGuard connection confirmation. If the user has several profiles, ask which to use; if none, offer Add tunnel.
- Stop asks permission and warns that disconnecting can restore unprotected internet access. Android-managed Always-on connections direct the user to Android VPN settings.
- Add tunnel launches Android's file picker, not the lengthy profile manager. Import does not automatically connect.

## Out-of-scope guardrails

- No invisible connection/start on launch, no connection to every saved tunnel without explicit selection, no silent direct fallback, no claims of a working all-traffic kill switch.
- `VpnActivity` continues to house advanced per-profile controls; it is no longer the first stop for normal tasks.
- Android Private DNS remains **OFF** for the established test environment. Neither quick action modifies it.
- A `.rootlab` test APK cannot read a separate signed app's encrypted saved profiles. Do not trust a “none detected” result as full-device evidence across distinct installs.

## On-device acceptance tests

- [ ] Cold launch: top visible action is Start/Stop and Add tunnel is directly under it; no explanatory wall of text before the buttons.
- [ ] Android gesture navigation and three-button navigation: custom bottom bar is wholly above Android controls. Status bar text never intersects card headings.
- [ ] Pixel 8a and Samsung A36: 5 short nav items are readable even at large system font. No horizontal clipping or view overlap.
- [ ] Tap each bottom tab; active tab, scroll location, and selections persist across app background/resume.
- [ ] Start rooted with 2 chosen profiles: correct boxes, DNS upstream, existing preflight and confirmation, no premature network change.
- [ ] Stop rooted with 2 active identities: both selected, Safe Stop confirms, other interfaces untouched.
- [ ] Start rooted with 3+ saved profiles: previous selection retained; overlapping defaults safely refused by existing routing validation.
- [ ] Root identity mismatch: **Review connection**, not misleading Start/Stop.
- [ ] Standard mode Start with zero/one/multiple profiles: file picker or explicit profile selection, Android VPN permission and confirmation.
- [ ] Add tunnel from Home and Tunnels: ACTION_OPEN_DOCUMENT appears, imported profile remains in encrypted store after restart.
- [ ] Standard mode Stop: explicit confirmation and Android Always-on handling.
- [ ] Settings no longer duplicates the profile manager; advanced tools remain available intentionally.
- [ ] Stats after reboot/time change: concise historical-warning text; detailed evidence is available on request.
- [ ] No regression to H.1 Safe Stop, H.2a CLEAN_STOPPED, DNS relay ownership, private destination access or network handoff.
- [ ] CI compile, native/core tests, certificate check, strict versionCode increase, guarded installer and manual QA pass before considering Product H complete.

## How to install official candidate

On maintainer's Fedora laptop, with original signing keystore:

```bash
git fetch origin
git switch feature/unified-everyday-ui-01548
git pull --ff-only origin feature/unified-everyday-ui-01548
bash scripts/build-wonhee-official-local.sh
# On phone: H.1 Safe Stop -> H.2a CLEAN_STOPPED
bash scripts/install-wonhee-safe-update.sh
```

VersionCode **96**; versionName **0.15.49-quick-connect-ui**. Signing and network ownership checks are never bypassed. On-device approval is required before marking Product Batch H complete.
