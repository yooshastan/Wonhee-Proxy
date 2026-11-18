# Wonhee 0.15.57 — App categories and planned tunnel assignments

**Development candidate; draft only.** The existing v0.15.56 user-facing tunnel use categories and multi-tunnel route validation are preserved. App versionCode **104**, versionName **0.15.57-app-categories-draft**.

## Why this phase is deliberately non-enforcing

The proposed user journey is:
**installed apps → app-use categories → chosen saved tunnel → later safely validated per-UID routing → later destination/traffic-type rules**.

The current rooted multi-tunnel engine does **not** safely implement multiple simultaneous full-Internet exits by Android UID. It supports only one default Internet exit together with distinct destination-specific routes, and the DNS upstream path has an outstanding startup issue. Arbitrary fwmark/UID rules would risk leaks, Android networking conflicts, or a broken Internet connection. Therefore v0.15.57 stores **preferences only**; it does NOT alter packet routing, Android VPN membership, firewall, DNS, root ownership or existing active sessions.

## Implemented

- **Tunnels → Set up app categories** opens a private dedicated screen. Existing app launch/Start and other tabs are unchanged.
- **Apps**: search Android *launcher-visible* apps, see icon, name and package ID, assign one of eight user-use categories manually. The initial category is Everyday; unassigned apps remain Everyday. Apps are enumerated locally using the launcher-intent query, not QUERY_ALL_PACKAGES, and no inventory is uploaded.
- **Categories**: choose one saved encrypted WireGuard profile as the preferred future tunnel for each app-use category. Empty mapping means inherited default privacy exit. An unavailable/deleted profile is identified rather than silently replaced.
- **Preview**: the app row displays the category's chosen tunnel and that tunnel's actual configuration mode (Internet exit, specific destination routes, or imported routes).
- **Storage**: app package→category and category→profile *name only* stored in app-private SharedPreferences. Hard limit 512 app overrides. No WireGuard key material, DNS queries, credentials, network captures, telemetry or app content stored by the planner. All edits are manual and local; no background automation.
- **Eight categories**: Everyday, Private, Regional, Finance, Home, Work, Media, System.
- **Six distinct tunnel labels** remain in the saved-profile editor: General Internet, Privacy, Regional, Home, Work and Media. An *app-use* category and a *tunnel-purpose* category are not the same thing.
- System processes without launchers are excluded at this stage. This list is not a full device package audit.

## Not implemented / never claimed

- Real Android UID routing, app-specific root firewall enforcement, automatic US/NL tunnel switching, multi-exit load balancing, DNS source-specific isolation, geo-location spoofing, TLS inspection, ad tracking classification, traffic-type recognition, a validated all-traffic kill switch, or Android background/system app inventory.
- A draft mapping to a US tunnel does **not** make regional apps use a US IP. Even after UID routing exists, GPS permissions, login identity, app telemetry and fingerprinting remain separate factors.
- The Category mapping screen allows planning different exits, **but does not activate** multiple default routes or override the current one-default route guard.
- None of these changes resolve the outstanding LOCAL_DNS_TIMEOUT / encrypted DNS upstream issue.

## Acceptance tests

| ID | Action | Expected |
|---|---|---|
| A1 | Root Tunnels tab → Set up app categories | Modern planner, with clear **PLANNING ONLY · NOT ACTIVE** notice |
| A2 | Search for installed McDonald's / Kroger / Ultgram / Moka, if present | Launchable apps appear by friendly name; search also matches package ID |
| A3 | Change McDonald's to Regional, Ultgram to Private, Moka to Home | Changes are locally persisted; no VPN, DNS or route mutation |
| A4 | Categories tab → Regional US saved profile, Private NL, Home Home profile | Each category saves its preferred tunnel; app rows show planned target |
| A5 | Reopen planner, switch tabs, reboot app | App categories and category tunnels persist |
| A6 | Select two different full Internet defaults across categories | UI makes no claim they are simultaneously active; guarded Home still refuses conflicting live routes |
| A7 | Remove/rename a saved profile after a clean stop | Planner marks the mapping unavailable, does not silently route elsewhere |
| A8 | Change category and switch out of the app | No new network services, root requests, permissions, or disconnects |
| A9 | Standard mode | Single Android VPN behavior unchanged; no live per-app routing claims |
| A10 | Notification, tile, launcher, Home Start/Stop | Existing UI and guarded workflow unchanged; legacy manager remains inaccessible via everyday entry points |
| A11 | Stats, More and Protect | Existing accepted screens unchanged |
| A12 | Import multiple split tunnels, then use Home Start only with nonoverlapping routes | Existing full-stack route safety remains authoritative; a draft category does not affect Home Start |
| A13 | Confirm app data not backed up and no broad QUERY_ALL_PACKAGES permission | Local privacy expectations preserved |
| A14 | CI: Android build, existing standalone core, app category tests, narrow package visibility/static non-enforcement test, native WireGuard | All pass before considering a signed candidate |

**No aggressive live-network stress tests until DNS startup and verified rollback are resolved.**

## Next engineering batch (separate PR)

A real root per-app routing implementation must first prove: exact UID/package ownership, multiple exits without kernel global default overlap, DNS path ownership for each exit, IPv4/IPv6 fail-closed behavior, Android network marks and system processes, no routing leaks during tunnel loss/Doze/handoff, rollback and independent H.2a CLEAN_STOPPED. Package names must resolve to installed UIDs at application time (including shared UID and app reinstall changes). These are explicitly **not** addressed by this metadata build.

## Maintainer Fedora commands (after CI success and independent CLEAN_STOPPED)

    cd ~/Wonhee-Proxy-UI
    git fetch origin
    git switch feature/app-category-routing-draft-01557 || git switch --track origin/feature/app-category-routing-draft-01557
    git pull --ff-only origin feature/app-category-routing-draft-01557
    bash scripts/build-wonhee-official-local.sh
    # With original signing certificate and independent CLEAN_STOPPED:
    bash scripts/install-wonhee-safe-update.sh

Never uninstall or generate a new keystore to bypass signature protection. Android Private DNS stays OFF for the Pixel 8a test environment.
