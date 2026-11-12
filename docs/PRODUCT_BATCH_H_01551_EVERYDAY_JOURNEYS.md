# Wonhee 0.15.51 — Everyday-use regression flight

**Status:** UI development candidate. Android CI compilation/native tests are necessary, but device acceptance is required before Beta. `com.yooshastan.wonheeproxy` versionCode 98 (official signed candidate), debug CI package `.rootlab` is separate and must never replace a differently signed APK.

## Why this flight exists

A user reported that launching Wonhee unexpectedly opened the **legacy WireGuard connection manager** despite the modern Home being declared launcher. Root causes identified in source:
- Quick Settings tile targeted `VpnActivity`.
- Android VPN speed notification targeted `VpnActivity`.
- Root speed notification targeted `RootMultiKernelActivity` rather than Home.
- Proxy tools' return control linked to `VpnActivity`.
- Android could restore a pre-upgrade task whose root activity was still `VpnActivity`.

The new contract: **every everyday launch or notification/tile tap lands on modern Home.** The old WireGuard configuration manager remains available only when explicitly selected through advanced configuration. All legacy entry redirects are navigation only; no tunnel, DNS, firewall or guard mutation.

## Safety and preparation

- This is a UI pass, not a kill-switch test. **Do not intentionally cut off active rooted interfaces or delete routes** to test fail-closed behavior. The all-traffic guard remains not beta-ready.
- On the Pixel 8a test configuration, **Android Private DNS stays OFF** (setting Automatic or a provider previously broke Wi-Fi). Do not change it to troubleshoot Wonhee.
- Before replacing the official rooted app: use H.1 Safe Stop, independent H.2a **CLEAN_STOPPED**, then the existing original-signed guarded installer. Never uninstall or regenerate a keystore to work around a signature mismatch.
- To compare behavior on Samsung A36 without root, use the Standard single-VPN interface; no root prompt until advanced mode is explicitly requested.
- When sharing bugs, capture the displayed state and app screen, not private WireGuard configurations, passwords, DNS query logs, tokens, or keystore files.

## Priority P0 — everyday navigation (do these before network-changing tests)

| ID | Journey | Expected result |
| --- | --- | --- |
| N01 | Tap home-screen Wonhee icon from an already-running app | **Home** appears, not legacy WireGuard or Root Lab |
| N02 | Leave Wonhee for another app; reopen it from launcher | Home with selected tunnel state intact |
| N03 | Swipe app away from Recents; launch again | Home opens; no duplicated task or legacy screen |
| N04 | Tap Wonhee Quick Settings tile | Home opens; tile itself never starts/stops VPN |
| N05 | Tap Standard VPN speed notification | Home opens; notification speeds remain informative |
| N06 | Tap Root tunnel speed + DNS-block notification | Home opens; root tunnel backend unaffected |
| N07 | From More > Ultgram proxy tools, tap Back to Wonhee | Returns to Home, not old manager |
| N08 | Open advanced saved-profile editor intentionally, then press Back | Home or caller; no accidental connection starts |
| N09 | Change tabs repeatedly and reopen via launcher | No clipping, weird stacking, lost selection or stale status |
| N10 | Try three-button navigation, then gesture navigation if available | Wonhee nav remains fully visible; Android bottom buttons do not cover it |
| N11 | Increase Android font/display size, rotate phone, background/resume | Taps remain accessible; labels fit; scroll does not jump to top every telemetry refresh |

## Priority P1 — tunnels and onboarding (mostly safe; no need to connect)

| ID | Journey | Expected result |
| --- | --- | --- |
| T01 | Root Home: check Internet and Home tunnels | Both selections visible immediately and remain checked across tabs/relaunch |
| T02 | Root Home: deselect/reselect one of two saved tunnels | Never changes live networking; only affects NEXT Start |
| T03 | Root Tunnels tab: change selection | Home mirrors the same saved selection |
| T04 | Standard Home: choose one saved VPN profile | Single selection persists; only one tunnel can be selected |
| T05 | Press Add Tunnel; press Android Back in document picker | Returns **directly to modern Home** |
| T06 | Import one valid `.conf`; save the role/route options; acknowledge summary | Home reappears with new saved profile |
| T07 | Import two `.conf` files together and skip one | Summary counts saved vs skipped; Home afterward |
| T08 | Try invalid or duplicate profile in a test copy | Validation fails safely; saved profiles remain intact; no raw config/errors shown |
| T09 | Press Start with no selected profile | A clear, short message explains how to select/add one |
| T10 | Open advanced profile editing intentionally | Existing editor remains reachable, but no normal launcher/notification ever sends users there |

## Priority P2 — actual connection and protection (run only when you can safely stop/reconnect)

| ID | Journey | Expected result |
| --- | --- | --- |
| C01 | Root Home Start with selected Internet + Home profiles | No second tunnel picker; existing H.1 preflight and confirmation appear |
| C02 | Cancel the final Start confirmation | No routing, DNS or tunnel changes; returns to Home |
| C03 | Approve Root Start after valid preflight | Internet + Home routes, DNS verification and UI identity match device state |
| C04 | Leave and reopen Wonhee while root tunnels are active | Home shows active verified profiles; does not claim unknown protection is verified |
| C05 | Root Home Stop after successful Start | Every detected identity-verified active profile proposed for Safe Stop; explicit confirmation |
| C06 | Approve Safe Stop and independently audit | DNS, routes, and profiles reconcile; CLEAN_STOPPED required before signed update |
| C07 | Standard VPN Start with selected saved profile | Uses that profile without a second picker, then explicit Android VPN permission/confirmation |
| C08 | Standard Stop | Clear confirmation and Android Always-on/lockdown handling; no silent fallback claim |
| C09 | Change network from Wi-Fi to cellular and back | UI doesn't claim full protection based solely on an interface being UP |
| C10 | Visit Navidrome from a routed browser and try Moka, separately | Observe actual route/connection outcomes without pretending a browser result proves Moka |
| C11 | Smoke-test Kroger app, Walgreens site and Google Wallet | Note any authentication problems; **geo-aware or purpose-aware auto-routing has not been implemented yet** |
| C12 | Test DNS filtering with known blocked and allowed domains | Counts only verified relay requests; no invented ad-block totals or per-app attribution |
| C13 | Tap notification while connected and return | Home loads without disconnecting root or Android VPN |
| C14 | Background Wonhee for an extended normal-use period | Status and notification update without disrupting other apps; check battery impact |

## Priority P3 — error messaging and trustworthiness

| ID | Journey | Expected result |
| --- | --- | --- |
| E01 | Reboot or change the local clock naturally, then inspect Stats | DNS history uncertainty is worded as a **historical check**, not proof of an active leak |
| E02 | Disconnect DNS in an existing controlled recovery experiment | App distinguishes DNS missing, ownership uncertain and filtering disabled; no false green state |
| E03 | Root permission denied or root stack otherwise inaccessible | No unsafe Start; user can return to Home and inspect safely |
| E04 | Route overlap or conflicting profiles proposed | Existing preflight refuses the unsafe configuration and retains useful diagnosis |
| E05 | Crash or failed import | No legacy menu exposed, no raw config/secret in UI, explicit recoverable error |
| E06 | Test notification permission granted and denied | VPN is usable; notification labels/setting match actual state |
| E07 | Test with no internet after deliberate *ordinary* cellular/Wi-Fi disconnection | Home states connection health accurately, without claiming kill-switch coverage |
| E08 | Root Start or Safe Stop fails midway in a controlled test | Preserve diagnostic evidence; do not hide failed rollback or claim a clean state |

## Report format (send one batch rather than piecemeal screenshots)

```text
Wonhee version: 0.15.51
Device / Android / root or Standard:
N01-N11: PASS / FAIL IDs + what happened
T01-T10: PASS / FAIL IDs + what happened
C01-C14: PASS / FAIL / NOT RUN IDs + what happened
E01-E08: PASS / FAIL / NOT RUN IDs + what happened
Top three annoyances:
1.
2.
3.
UI screenshots: attach only the failing screens; redact personal information.
```

**Release gate:** CI pass + P0/P1 passed + safe P2/P3 critical paths on both rooted and non-rooted devices. Product Batch F all-traffic kill switch must be independently implemented and independently failure-tested before any "fail-closed" or beta-protected claim.

## Refresh official source for local build (Fedora)

```bash
cd ~/Wonhee-Proxy-UI
git fetch origin
git switch feature/unified-everyday-ui-01548
git pull --ff-only origin feature/unified-everyday-ui-01548
bash scripts/build-wonhee-official-local.sh
# On device, H.1 Safe Stop then H.2a CLEAN_STOPPED
bash scripts/install-wonhee-safe-update.sh
```
