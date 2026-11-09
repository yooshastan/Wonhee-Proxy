# Wonhee Proxy UI redesign — first product specification (F.5 design track)

Status: **design proposal only**. No existing Android UI, signing, tunnels, storage or network controls are changed by this document.

## Problem to solve

The current `RootMultiKernelActivity` programmatically renders one large `ScrollView` starting with "MULTI-TUNNEL LAB", immediately presents profile selection, then primary connection controls, emergency DNS operations, lifecycle recovery, guided safety checks, many advanced routing/DNS/tracker and Batch F firewall experiments. Its high-density text and experimental controls crowd out the information most users actually need: **Are both connections running? Is DNS encrypted? Is leak protection in force? How do I connect or safely stop?**

The source is an engineering lab, not a consumer VPN dashboard. Preserve the underlying audited controller and exact-owned rollback semantics while replacing presentation progressively. Do not combine the UI rewrite with changes to live root firewall rules.

## Product model — connection-agnostic + protection formula (approved direction)

**HOME + Internet is a highlighted preset, never a hard-coded topology.** A saved profile can represent a work VPN, home network, self-hosted service, media subnet, lab or general Internet exit. Show the user's chosen names, not hard-coded "HOME" and "AirVPN" labels. Dashboard connection rows must render **1–8 selected tunnels** as a concise count and expandable list, with 1–2 prominent cards when few are selected and compact list when there are more.

**What the current backend actually supports:** up to eight saved WireGuard profiles and eight selected tunnels; distinct/non-overlapping destination-specific peer routes; at most one default IPv4/IPv6 Internet route per address family. The root route validator rejects two overlapping default exits, overlapping non-default CIDRs, and overlapping interface address networks. Do **not** advertise arbitrary multi-hop chaining, two simultaneously active default Internet exits, dynamic backup failover or per-app routing as supported. Show an actionable preflight conflict message and suggest editing allowed routes rather than making silent topology changes.

**Connection groups** (future product-level presets, not an existing feature): named collections of compatible profiles. Examples: "One VPN", "Internet + Home", "Internet + Work", "Internet + Media", "Custom Destinations". Allow users to rename any group; role tags describe routing intent, not the provider. Default egress and selected private resource connections are meaningful roles; neither is forced to be a home network.

**Protection formula** (navigation within Protection):
1. **Connections** — import/select WireGuard profiles, verified up/down for every tunnel.
2. **Routing** — which destinations use each tunnel; split-route ownership and conflict detection.
3. **Encrypted DNS** — resolver protocol/provider, relay and exact DNS firewall health.
4. **Ads & Trackers** — hosts/blocklists and exceptions applied inside the DNS relay; not a separate VPN hop.
5. **Firewall / Kill Switch** — exact-owned fail-closed protection; explicitly **Unavailable (under development)** while Batch F activation is paused.

An everyday user sees a single primary Connect/Safe Disconnect control on Home and per-layer status inside Protection. Enthusiasts can inspect the five-part formula, independently run read-only checks and tune advanced behavior under Settings → Advanced Tools. **Do not display internal batch identifiers** outside Advanced Tools / About.

**Visual system — shared Yooshastan K-pop character with Ultgram/Moka:**
- Elegant dark-plum background, candy-pink accent and soft lavender secondary; a matching optional **Candy Pink Day** light theme, not a blinding neon interface. Preserve sufficient contrast and grayscale/readable states.
- Rounded cards (14–20 dp), spacious typography, distinctive but restrained pastel gradients for key connection status, subtle motion; icons and text both identify status.
- Slightly playful music-app visual rhythm and Telegram-like responsive navigation, but avoid celebrity/artist assets or copyrighted K-pop branding. Use original iconography and an original "Wonhee" shield motif.
- Option to follow system theme; accessible touch targets, reduced-motion setting, Dynamic Type, TalkBack, high contrast, and small-screen behavior.
- Centralize theme tokens so Dashboard, Profiles, DNS, blocklist and advanced diagnostics share a coherent appearance. Do not duplicate multiple competing "Labs" pages.

## Navigation: four places, not one continuous menu

### Home (first screen)

* Brand + one plain-language runtime state. States: Disconnected; Connecting (current verified step); Connected with disclosed limitations; Attention (recovery needed); Disconnecting. Avoid "Fully protected" while Batch F fail-closed guard is paused and DNS/route health remain unverified. Do not infer state from saved preferences alone.
* Primary context-aware action: **Connect** (uses existing `startManagedStack` only when configured and preflight passes) or **Safe Disconnect** (uses existing `stopManagedStack`, exact rollback preserved). An always visible stop/recovery entry must remain reachable when activation fails.
* Responsive selected-tunnel section: one or two prominent cards when 1–2 profiles are selected; otherwise show a compact scrollable list with a count (up to eight). Show user-defined names and roles such as Internet exit, Private subnet, Work, Media or Custom; never assume HOME and AirVPN. Tap for details: verified up/down, handshake age, session traffic, interface and egress (redact secret keys/endpoints). Unknown live state must read "Not verified", never green.
* Two compact protection indicators: Encrypted DNS **Active / Off / Unverified**; Kill switch **Unavailable — in development** until independent tests. Tracker blocking optional compact state.
* "Details" expansion for routing and current underlay. No test UI or raw configuration visible by default.
* No more than one screen of scrolling at a common phone width for the key action/status region; preserve text enlargement and screen reader support.

### Profiles

* Saved encrypted profiles (up to eight in the current backend), import/edit/select, test route intent. Each profile card uses its user-defined name and a role label such as Internet exit / Private destination / Work / Custom. Clearly distinguish selected, running, and status unavailable. Never lock users into "Home" names.
* Setup guide: start with one Internet VPN; optional destination-specific private connection such as HOME, Work, or Media. Explain current route constraints and validate conflicts before connect. No hidden mutation. Feature an "Internet + Home" starter preset without requiring that topology.
* Backup/import management separated from connection status. Never expose config keys in screenshots or exported logs.

### Protection

* DNS protocol/provider, tracker/hosts policy and explicit privacy statements for what is and is NOT protected. Show exceptions, DNS listener status, last successful audit and severity when rules do not match saved ownership.
* Kill switch visibly labeled "Experimental — unavailable" with informational explanation. **No enable action** until independently validated and source gate deliberately reviewed. Do not present a non-operational kill switch as a working toggle.
* "Advanced" area for read-only routes/endpoint diagnostics, lab policy previews and explicit recovery with confirmation. Distinguish inspection from actions with plain verbs.

### Activity

* Short session timeline (connecting -> tunnel verified -> routes -> DNS -> session ready; or exact failed step); latest warning; counters and app health.
* Copy/share sanitized report and full opt-in redacted export; no credentials or endpoint IPs by default.
* "Technical diagnostics" section groups read-only audit actions; crash repair, DNS orphan cleanup and exact guard rollback remain high-friction and explicit, not scattered among consumer controls.

## One-button connection contract

Internally the existing safe sequence is retained, not hidden:
1. Check selected profiles and current root/session state.
2. Verify kernel tunnel identities.
3. Install and audit only precisely owned split routing.
4. Start verified encrypted DNS and tracker policy if selected; verify the relay and expected firewall tags.
5. Show Connected **with limitations**, never a blanket leak-proof assertion.
6. On stop, remove owned DNS enforcement and verify relay/port release, remove owned split rules, then disconnect selected tunnels.
7. If any cleanup step fails, show **Attention: cleanup incomplete** and preserve ownership ledger and safe read-only recovery entry. Never claim success merely because an animation finished.

## State and status truthfulness

* "Connected" means verified selected tunnels and current connection stack, not automatically leak-safe.
* If one tunnel fails, say "HOME unavailable" or "Internet unavailable", not silently "Connected".
* Separate DNS active, DNS disabled, and DNS unknown.
* Batch F is **disabled by build-time gate**; UI must not imply that a full-device kill switch is active.
* App process death, stale last check, unexpected unowned rules, partial rollback or native DNS listener without ledger must become **Attention / Needs verification** with actionable messages.
* If a button fails to run, preserve current visible state; never invent completion.
* Do not silently start rootlab and official apps against the same shared kernel resources.

## UX design language

* Keep the established dark plum and restrained pink branding, less neon/experimental documentation on the first screen.
* Use text + icon + accessible semantic cues; status never conveyed solely by color.
* One dominant button on Home, secondary stop/recovery always reachable; prevent duplicate operations while busy.
* Consistent cards, comfortable 44–48 dp touch targets, accessible dynamic type and TalkBack labels.
* No "Labs" or "Studio" sections in the main navigation. Developer-only diagnostics appear in one **Advanced Tools** area and use progressive disclosure.
* Avoid "Beta F.3d" or internal batch labels in consumer UI. Version and experiment IDs belong in About/diagnostics.
* Language: Connect; Safe Disconnect; Connections; Internet Exit; Private Connection; Routing; Encrypted DNS; Ad & Tracker Blocking; Firewall (Unavailable); Details; Troubleshooting. HOME is only a user-supplied profile name, not a mandatory product component.

## Migration strategy (avoid destabilizing working VPN)

1. Build state-to-view-model mapping and Android UI screenshot/interaction tests **without changing** `RootMultiKernelSession` networking methods.
2. Introduce new read-only dashboard alongside existing advanced manager. Show states from live audits, not only preferences.
3. Move profile and settings UI into four destinations; preserve import and secure storage.
4. Wire consumer Connect to existing proven managed start and Safe Disconnect to existing proven exact-owned stop, with explicit confirmation/error path.
5. Consolidate technical UI into Advanced Tools. Do not remove or bury orphan DNS recovery and safe stop.
6. Regression on Pixel 8a (Android 16), Samsung A36, different font scales, TalkBack, screen rotation, partial DNS failure, missing profile, app restart, root unavailable, simultaneous package warning and disconnected state.

## Text wireframe (information hierarchy only)

```text
WONHEE PROXY                         [Settings]
──────────────────────────────────────────────
 Connection overview
 3 of 3 selected tunnels — verification required

  [ AirVPN Netherlands ]  Internet exit
  [ Private Server    ]   Private network
  [ Work              ]   Work destinations
  [ Expand all • up to 8 compatible tunnels ]

  Encrypted DNS:   [Active | Off | Unverified]
  Ad & Tracker:    [On | Off | Unverified]
  Firewall:         Unavailable — in development

  [ Connect / Safe Disconnect ]
  [ Connection details ]
──────────────────────────────────────────────
 Home       Profiles       Protection      Activity
```

Inside **Protection** (do not force these all onto Home):
```text
YOUR PROTECTION STACK
  Connections      3 selected            [Manage]
  Routing          Destination rules     [Review]
  Encrypted DNS    Provider / protocol   [Configure]
  Ads & Trackers   Lists / exceptions    [Configure]
  Firewall         Unavailable           [Learn more]
  [ Advanced Tools — diagnostics and emergency recovery ]
```

Show honest status and no false green badges. When no profiles are configured, replace status cards with a short onboarding "Add a VPN profile" flow.

## For this F.5 batch

Only design documentation and a pure offline network-control *candidate* classifier are added. The app UI is **not implemented in this batch**; approval/review of the information hierarchy should precede a non-destructive staged implementation. The Batch F activation gate remains hard paused.
