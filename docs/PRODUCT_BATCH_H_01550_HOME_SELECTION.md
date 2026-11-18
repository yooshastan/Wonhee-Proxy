# Product H · 0.15.50 — Home tunnel selection and import return

**Status:** draft UI candidate. Root and non-root must pass device acceptance before release. Networking backends, DNS firewall, routes, and kill switch enforcement are not modified.

## User-observed defects

1. **Tunnel selection was missing from the first screen.** Users had to open a second chooser after pressing Start.
2. **The Android document picker cancelled back to the obsolete WireGuard manager.** This made the main UI feel like an overlay rather than a coherent app.

## Updated interaction contract

### Home — Root mode

- Top of Home: **Start / Stop**, **Add tunnel**, and visible checkboxes for each encrypted saved tunnel, in that order. Status, protection, counters and diagnostic details come later.
- New selection defaults to one Internet exit and one Home/private destination if present; users can change the selection before Start. No tunnel starts automatically.
- Selection is saved locally by exact profile name under `wonhee_everyday_ui_v1:last_quick_profiles`. No configurations, secrets, endpoint addresses, public keys or DNS queries are written to this UI preference.
- Tunnels tab mirrors the same selection; switching screens and backgrounding preserves it.
- Start passes the chosen names into **existing H.1 guarded full-stack start**. No redundant tunnel picker in Root Lab. The existing preflight, explicit connection confirmation and safety rollback remain intact.
- Stop acts on **all currently identity-verified running saved-profile tunnels**, not only the selected profiles for the next Start. Identity mismatches remain a review-required state; never silently attempt destructive recovery.
- On successful H.1 Start/Safe Stop, return to Home, which refreshes its read-only verified status. On failure, the existing full diagnostic report remains visible.
- The ROOT interface does not infer a working all-traffic kill switch, nor does it turn off Android Private DNS (which must remain OFF in the current test environment).

### Home — Standard mode

- Top of Home: **Start / Stop**, **Add tunnel**, then one selected profile (radio controls).
- A selection saves the existing `SecureTunnelProfileStore.rememberSelectedIndex`. Starting from Home uses it without another profile picker, then runs the existing Android VPN permission and confirmation logic.
- Changing profiles while the Android VPN is connected is unavailable; the UI warns the user to disconnect first.
- Standard mode does not expose root-only multi-exit functionality or pretend an active VPN interface is a leak audit.

### Add tunnel / document picker

- Home and Tunnels Add tunnel use the already validated SecureTunnelProfileStore import logic (up to eight .conf files with roles, DNS and route validation); **do not duplicate the parser** or change keystore storage.
- During the picker and per-file configuration, the background is a compact Add Tunnel interface, NOT the legacy scroll-heavy WireGuard manager.
- **Cancel/back from the Android picker finishes the import helper and reveals the existing Home.**
- After completed imports or skipped/invalid files, a concise summary is shown and closing it returns Home.
- Other explicit entries to the full `VpnActivity` continue to function as the advanced single-VPN configuration manager.

## Device acceptance gates

- [ ] Root Home with two known tunnels: both checkbox states visible before any scroll; select AirVPN + home; Start shows the existing safety confirmation **without a duplicate tunnel chooser**.
- [ ] Deselect/reselect either tunnel; selection survives tab switches and app relaunch.
- [ ] Root Stop operates on verified currently running tunnels, even if Home's future Start selection changed.
- [ ] No root operation occurs merely because a checkbox was tapped.
- [ ] Cancel Start confirmation returns to Home without changing routing or DNS.
- [ ] Success returns to Home and shows refreshed state; failure retains usable diagnostics.
- [ ] Standard Home radio selection persists; Start uses the selected profile; Android VPN permission remains explicit.
- [ ] Tap Add tunnel, press Android Back in file picker: **Home**, not the old dashboard.
- [ ] Import one or multiple valid WireGuard .conf files, save one or more, acknowledge summary: **Home** with updated tunnel names.
- [ ] Import invalid file or skip all: shows a summary, then returns Home; no secrets or parsing errors shown.
- [ ] If Android VPN is connected, import is safely refused, and Home remains accessible.
- [ ] Reboot/handoff/DNS failure/owning firewall rules continue to behave as in previously tested code. No changes to underlying root routing.
- [ ] Test the actual update built with the original release signing key; never uninstall to bypass mismatched signatures.
- [ ] Confirm H.1 Safe Stop and independent H.2a CLEAN_STOPPED before running the guarded local updater.

VersionCode **97**, versionName **0.15.50-home-tunnel-selection**. Product Batch H remains open until device checks pass. Kill switch completion and beta release remain separate gates.
