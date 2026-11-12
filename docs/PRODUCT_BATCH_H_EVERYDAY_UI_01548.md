# Product Batch H — Wonhee Everyday UI (0.15.48)

> **Status:** development candidate, not signed or beta-ready. This is a frontend-only pass built on `feature/shared-lab-context-01547` (PR #83); keep existing branches/PR dependencies intact.

## Design goal

A person opening Wonhee should understand **what it knows, what it does not know, and what to do next** in a few seconds. We favor recognizable words and safe operations over a crowded diagnostics laboratory.

Three priorities, in order:

1. **Simplicity.** Home leads with one honest VPN state and one next action.
2. **Reliability.** Do not move, stop, or start tunnels just by navigating. Reuse tested controls; maintain existing profiles and safe-stop process.
3. **Creature comforts.** Fixed bottom navigation, persistent tab selection, scroll-position continuity, remembered workspace choice, accessible minimum touch targets, and speed-notification opt-in in Settings.

## Information architecture

Persistent bottom navigation in both modes:

| Destination | Standard (no root) | Advanced (root only) |
| --- | --- | --- |
| Home | Single Android VPN interface status, manage connection, privacy guidance | Verified root tunnel identities, live aggregate counters, DNS evidence, one link to Safe Controls |
| Tunnels | Saved profiles and Android VPN connection manager | Identity-verified tunnel cards, importing profiles, routing control shortcut |
| Protect | Honest VPN/lockdown/DNS status and Android Settings shortcut | DNS relay, filtering, DNS-port policy, paused all-traffic guard, scoped advanced DNS controls |
| Activity | Single-VPN statistics via existing manager | Verified aggregate throughput, relay counters, scoped advanced diagnostics |
| Settings | Switch to rooted mode after explicit read-only root check, single-VPN notifications, profile tools | Persistent notification opt-in, guarded switch back to Standard, tools |

The pre-existing Root Multi-Tunnel Lab still has **Status / Tunnels / DNS / Activity** subnavigation and opt-in deep controls. Dashboard shortcuts select that existing section; they do not execute a command.

## Mode behavior

- Fresh install defaults to **Standard**. This is a deliberate product choice, not an Android API limitation.
- Existing users with a recorded root-lab state, owned route/DNS/guard preferences, or active root speed-notification preference default to the **Root workspace** to prevent unexpectedly showing only the standard VPN.
- If the user manually selects Root workspace, run one read-only root snapshot and show the advanced UI only after it reports root availability.
- Standard mode never starts a root tunnel or a background root sampler.
- Switching back to Standard is blocked when root state is unknown, a saved-profile root tunnel is present, or owned DNS/guard policy is recorded. The user is guided to the existing Safe Controls first.
- Workspace and tab choices are local UI preferences only. Switching modes never modifies WireGuard, DNS, routing, firewall, root permissions or Android Private DNS.

## Security and truth-in-UI rules

- **Never equate an interface being UP with protected traffic.** Show that the interface is active but leak resistance is not audited.
- Do not invent a green security score, a per-app route, an IP geolocation or blocked-request counter.
- Display DNS block totals only for an identity-verified relay; never imply device-wide coverage.
- Root speed counters represent the aggregate of identity-verified root WireGuard interfaces, not all device traffic.
- The all-traffic kill switch remains **not released / activation safety-paused**. DNS-port rules and a route ledger do not prove fail-closed internet traffic.
- Standard-mode guidance points to Android's official Always-on and Block connections without VPN controls, not a nonexistent Wonhee kill switch.
- Do not change or turn on Android Private DNS as part of this work. The current Pixel 8a test setup requires Android Private DNS OFF.
- No current automatic US/Netherlands routing, traffic-purpose detection or obfuscation claims.

## UX acceptance checklist

### Navigation and comfort
- [ ] Cold launch opens Wonhee Home; no obsolete dense profile form as initial screen.
- [ ] Bottom navigation stays visible when long content is scrolled, including system navigation gesture inset.
- [ ] All five destinations open and stay selected; the choice survives app pause/resume and process restart.
- [ ] Periodic telemetry refresh does not jump to the top of the current screen or steal focus.
- [ ] Connection, profile, DNS and diagnostics shortcuts open the **correct** destination.
- [ ] Button labels are intelligible with TalkBack; normal touch target size is at least 48dp.
- [ ] Text is legible on Pixel 8a and Samsung A36 with large system font.
- [ ] No UI action quietly changes tunnel or firewall state.

### Standard mode
- [ ] Does not prompt for root on a fresh non-root installation.
- [ ] Correctly distinguishes connected / disconnected / unavailable Android VPN interface.
- [ ] Imports and connects a saved single WireGuard profile through existing safe UI.
- [ ] Android Always-on and lockdown controls are reachable without a promise of leak protection.
- [ ] Root-only counters, per-app routing, and kernel controls are not shown as working.
- [ ] Notifications and saved profiles are accessible.
- [ ] No regression to reconnect, Android VPN permission or off state.

### Root mode
- [ ] Existing rooted installation opens Root workspace without losing local profiles.
- [ ] A new root user must explicitly request the root workspace; denied root does not switch modes.
- [ ] Home correctly handles zero, one, two, and more saved/active tunnels; mismatched identities remain warnings.
- [ ] Route to Root Lab Status/Tunnels/DNS/Activity is correct, keeps selections and never executes action on entry.
- [ ] Existing managed Start, H.1 Safe Stop, H.2a lifecycle audit and update-preflight remain unchanged.
- [ ] DNS unavailable / failed / verified statuses remain distinct; counters are absent rather than zero when unknown.
- [ ] Can't accidentally switch to Standard while rooted tunnels or recorded DNS/guard policy still exist.
- [ ] Persistent root status notification opt-in/out still works with Android 13+ permission behavior.
- [ ] Root tunnel speed measurements never pretend to represent all device traffic.

### Build, install and release gate
- [ ] Android build and native/core tests pass on this PR.
- [ ] Confirm APK package ID and signature before installation. PR debug APK uses `.rootlab` and is **not** the signed production update.
- [ ] Do not uninstall a signed production APK to install this preview.
- [ ] If replacing an existing rooted build, use the established **H.1 Safe Stop → H.2a CLEAN_STOPPED → guarded signed update** procedure; do not update while tunnels/guard/rules are live.
- [ ] Test cold start, background/resume, Wi-Fi ↔ cellular, offline DNS, reboot, rotation, accessibility, and notification state.
- [ ] Product Batch F all-traffic kill switch needs its own fail-closed QA before beta claims.
- [ ] Do not mark Product Batch H or I complete from CI alone: device acceptance is required.

## Out of scope in 0.15.48

No backend changes, per-app routing, geofencing, tunnel obfuscation, kill-switch enforcement, DNS ownership changes, tracker-list edits, auto-recovery algorithm changes, or new signing identities. Those belong to separately validated batches.

## Review target

Ship a coherent development candidate after CI passes, collect one consolidated Pixel/Samsung UX review, then polish usability defects in a coordinated follow-up—not a string of one-button APKs.
