# Wonhee 0.15.56 — Categorize tunnels and explain multi-exit limits

**Status: draft development candidate**, versionCode 103. This branch builds on draft 0.15.55 DNS diagnostics and on the accepted 0.15.54 Home UI.

## Observed issue

An Android tester saved four VPN profiles and selected the privacy Internet exit, Home private tunnel, and additional AirVPN regional exits. Home then refused multiple Internet exits. This is not an arbitrary two-tunnel cap: the encrypted store accepts eight saved profiles and the route engine accepts one unrestricted dual-stack default exit plus multiple *non-overlapping* destination-specific routes. Two VPN profiles simultaneously claiming 0.0.0.0/0 and ::/0 are ambiguous with today's routing implementation.

## Design

- Each encrypted profile has a separate purpose category: General Internet, Privacy, Regional/local services, Home/private, Work/trusted, Media/streaming.
- Categories are user-editable **metadata**. They never rewrite AllowedIPs, change DNS, detect or change country/GPS, assign an app or override routing.
- Imported/older encrypted document schema remains version 1. The category is optional on read; migration retains original identity, keys, routes, and DNS choices.
- Tunnels groups the saved library by category; Home displays both the category and actual routing mode below each checkbox.
- Home checks the **effective parsed WireGuard routes** before Start. One Internet default plus two or more distinct split-route tunnels can pass read-only review, up to eight selected profiles.
- Two unrestricted Internet exits get a specific, actionable error naming the conflicting profiles. The user may choose one default, or use Edit settings to give the secondary tunnel vetted, non-overlapping destination CIDRs. No silent country switching or implicit network changes.
- Existing kernel root preflight, exact-owned routing, DNS enforcement/verification, and rollback are still authoritative and may independently reject a seemingly compatible selection.
- The legacy Android VPN editor preserves a profile's category when connection settings are saved.

## Explicit limitations

This patch does NOT add per-app routing, per-domain country classification, automatic US commerce behavior, dual-default load balancing, browser anonymity, or an all-traffic kill switch. Root kill-switch activation stays safety-paused. Category only labels **why** a profile is saved; its actual routes determine **where** packets go.

Android Private DNS remains OFF in the Pixel 8a testing environment.

## On-device verification

| ID | Action | Expected |
|---|---|---|
| B1 | NL default + Home split | Compatible before independent live preflight |
| B2 | NL default + Home split + a separate Work IP split | Three selected accepted, if CIDRs and WireGuard addresses do not overlap |
| B3 | NL default + US default + Home | Explicit conflicting-default warning, no network changes |
| B4 | Label US profile Regional but leave its default routes | Remains a full Internet exit and remains conflicting |
| B5 | Set US to vetted specific CIDRs, choose NL + Home + US | Read-only selection review accepts only if effective routes are distinct |
| B6 | Save category, switch tabs/restart app | Same saved category and encrypted configuration |
| B7 | Edit via legacy connection manager | Category not silently cleared |
| B8 | Select IPv4-only default / overlapping CIDRs / interface subnet conflicts | Preflight refuses safely |
| B9 | Select up to 8 compatible profiles | Read-only review handles all 8; real 8-tunnel live support still unqualified |
| B10 | Start confirmation then Cancel | No tunnel, DNS, or route mutation |
| B11 | One guarded, explicit 3-tunnel Start with USB/ADB available | Independent kernel and DNS audits must pass; on failure rollback and audit CLEAN_STOPPED |
| B12 | Standard mode and Stats/More | No regression and no misleading root-only claims |

Do not deliberately force kill-switch failures or repeatedly restart through a failed rollback.

## Fedora development checkout

    cd ~/Wonhee-Proxy-UI
    git fetch origin
    git switch feature/tunnel-categories-01556 || git switch --track origin/feature/tunnel-categories-01556
    git pull --ff-only origin feature/tunnel-categories-01556
    bash scripts/build-wonhee-official-local.sh

Before any official APK installation, complete H.1 Safe Stop and independently confirm H.2a CLEAN_STOPPED; only then run the existing guarded installer with the original release keystore.
