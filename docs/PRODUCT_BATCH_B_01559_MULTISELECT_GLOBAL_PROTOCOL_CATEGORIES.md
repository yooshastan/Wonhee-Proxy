# Wonhee 0.15.59 — select several tunnels + global port/protocol categories

**Status: review candidate.** versionCode 106, versionName 0.15.59-multiselect-category-protocols. Based on the draft UID/transport planning branch 0.15.58; still not beta-ready.

## Device-reported usability issue

With AirVPN Europe (NL), AirVPN America (US) and Home selected, Home previously opened a wall of text saying two Internet exits conflict. The root backend has always supported a single dual-stack Internet exit *plus multiple non-overlapping destination tunnels*, not two unrestricted defaults. The user wants to keep multiple VPN profiles selected and also assign **global TCP/UDP protocol/port rules to categories**, with those rules overriding each app's ordinary category.

## Implemented in this candidate

- Multiple profiles may remain checked on Home; a pure analyzer validates the **actual effective WireGuard routes** and identifies all full Internet exits.
- If more than one unrestricted exit is selected, Home presents a **short primary-exit picker**. It does not pick a region silently.
- On approval, only **the chosen primary Internet exit and non-overlapping destination-specific tunnels** are sent to the existing root preflight/connection/DNS/routing sequence. Additional full Internet exits remain selected as **not connected / waiting**. The confirmation names both groups explicitly.
- The existing startup validator, H.1 Safe Stop, DNS rollback and all-traffic guard activation remain unchanged; no route conflicts are suppressed or hidden.
- **Tunnels → Set up app categories → Protocols:** configure global TCP, UDP, an optional numeric destination port (blank = any destination port for that transport), and the **app-use category** to apply. The category in turn has a preferred saved VPN tunnel in the **Categories** tab.
- All global rules are saved *only* in private local draft preferences, bounded to 20 selectors, and can be removed. A rule never changes WireGuard routes, marks, filters, DNS, Android Private DNS or currently running tunnels.
- **Planning precedence:** explicit per-app protocol/port override → global TCP/UDP/port-to-category override → ordinary app-category preference → default Internet exit. This meets the requirement for global protocol choices to trump the *ordinary app category*. Explicit app protocol overrides still win.
- An existing rootless policy preview now resolves these global rules to configured category tunnels. Missing/deleted targets and Home-only split tunnels as app-wide exits are refused. Unknown Android/system UIDs are not claimed to be covered.
- Hard source safety gate: `RootPerAppUidPolicyPlan.Plan.activationAllowed() == false`. Multi-exit UID, DNS and fail-closed packet enforcement are **NOT live**. Treat preview output as design validation only.

## What remains unimplemented

It is **not** possible to use AirVPN Netherlands and AirVPN America *simultaneously as separate app Internet exits* in the current root engine. It can connect a primary Internet exit plus compatible destination-specific tunnels. The additional unrestricted exits can stay selected but **will not connect or carry packets**. No UI should claim otherwise. The long-term requirement for active simultaneous app/protocol-based multi-exit routing is tracked in issue #89.

A TCP/UDP destination port is metadata, not a trustworthy statement that traffic is login, streaming, payment, HTTPS, QUIC, DoH or DoQ. No TLS interception or encrypted traffic-type inference.

DNS startup has had LOCAL_DNS_TIMEOUT on device; this candidate does not establish that the upstream DNS problem is fixed. No unrestricted all-traffic kill switch has been activated. Pixel 8a Android Private DNS must remain OFF.

## Acceptance checklist

| Test | Expected |
|---|---|
| B59-1: select NL + US full exits + Home + Work split | Home asks the user for a primary exit; doesn't show old long error |
| B59-2: select NL as primary | NL + Home + Work can proceed to *existing guarded Start* after live preflight; US remains selected, **not connected** |
| B59-3: select US as primary | US + Home + Work can proceed; NL remains selected but not connected |
| B59-4: select only default exits, no private split tunnel | Existing full-stack root requirement remains, no false successful Start |
| B59-5: use overlapping destination CIDRs or duplicate interface addresses | Refuse **before** any routing mutation |
| B59-6: choose third full exit | Multiple candidates may be selected and clearly reported as waiting |
| B59-7: Tunnels → App Routing → Protocols | Visible, no per-app selection required, simple TCP/UDP + port → category editor |
| B59-8: save UDP port 443 → Private | Global rule persists across restart without routing changes |
| B59-9: add TCP all ports → Regional, TCP port 443 → Finance | Exact port wins over transport-wide; both override normal app category |
| B59-10: configure explicit per-app TCP port 443 | App's explicit override beats global TCP port 443 |
| B59-11: assign a global category with no tunnel / Home split as all-app exit | Dry-run refuses; never falls back to a random tunnel |
| B59-12: cancel picker or confirmation | No tunnel, DNS, route, firewall or ledger changes |
| B59-13: rootless tests and Android/native build | All pass before local original-key installation |
| B59-14: if attempting a **single approved guarded Start** on the device | Use USB recovery, report any DNS failure, verify rollback and independent H.2a CLEAN_STOPPED; do not retry a failed rollback |
| B59-15: Standard mode, Protect, Stats and More | No regression |

### Fedora update after CI

```bash
cd ~/Wonhee-Proxy-UI || exit 1
git fetch origin
git switch feature/multi-select-primary-exit-01559 || git switch --track origin/feature/multi-select-primary-exit-01559
git pull --ff-only origin feature/multi-select-primary-exit-01559
bash scripts/build-wonhee-official-local.sh
# Only after root Safe Stop and independent H.2a CLEAN_STOPPED:
bash scripts/install-wonhee-safe-update.sh
```

Do not uninstall the official app or install a differently signed debug APK over it.
