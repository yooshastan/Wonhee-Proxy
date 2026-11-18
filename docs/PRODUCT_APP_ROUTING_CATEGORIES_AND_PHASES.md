# Wonhee app categories → tunnel routing → connection-purpose rules

**Decision, 2026-11-18:** Favor **app category → selected tunnel** as the first real app-routing experience. Add destination/traffic-purpose rules only after stable per-app policy enforcement. This document is a design contract, **not a claim that category-based app routing already works**.

## 1. Three distinct layers

1. **Tunnel purpose** (already being introduced in 0.15.56): descriptive saved-profile metadata, e.g. Privacy, Regional, Home, Work, Media. A label never changes WireGuard AllowedIPs or kernel routes.
2. **App use category** (next engine phase): a package/UID is assigned exactly one user-editable default category; each category maps to one trusted named exit profile. Unassigned apps inherit **General / Unassigned → Privacy Default**. Changes should affect *new* connections only. Workloads requiring private LAN services additionally need explicit destination rules.
3. **Connection-purpose routing** (later, after independent device testing): known destinations can be assigned an exit or blocked, while related authenticated sessions remain pinned. Do not infer semantic purposes from arbitrary encrypted HTTPS traffic or claim a domain-to-app correlation where DNS is unavailable.

## 2. User-facing app categories

| Category | Initial routing suggestion | Examples / notes |
| --- | --- | --- |
| General / Unassigned | Selected privacy default | All newly installed/uncategorized apps; never direct fallback |
| Privacy & Browsing | Privacy exit (e.g. Netherlands) | Browsers/search, but signed-in activity is not anonymous |
| Messaging & Social | Privacy exit | Ultgram, Signal, Discord; maintain sticky sessions |
| Shopping & Local | US compatibility exit | McDonald's, Kroger, Walgreens; stable account/ordering/checkout egress |
| Banking & Payments | User-approved stable trusted exit | Banks, Wallet; avoid country changes during payments; no automatic exceptions |
| Home & Private Network | Approved destination CIDRs via Home tunnel, other traffic via privacy default | Moka/Navidrome, NAS, SSH; do not use Home as all-Internet default unless configured |
| Media & Streaming | Performance or chosen regional exit | YouTube, Moka media streaming; private-source access still needs destination routing |
| Gaming & Real-Time | Lowest-latency trusted exit, sticky session | Games and live voice; no mid-session failover |
| Work & Security | Explicit trusted/work exit | Company VPN, authentication, enterprise tools |
| System & Updates | Protected privacy default unless explicit compatibility rule | Android/Play services; do not classify every shared/system UID automatically without verification |

A separately named **Block** policy is available as an explicit action, not a country category. Ad/tracker blocking remains an independent DNS/firewall function, not another tunnel exit.

## 3. Priority and safety rules

- Individual app override (explicit user selection) > assigned app category > protected default. For an approved private-network CIDR override, route by exact destination with explicit permission; never equate all network traffic from a media app with Home traffic.
- App identification requires verifying installed package and Linux UID, and special-casing shared UIDs and service processes. A category's guessed name is not enough to select packets.
- An app may be moved between categories without affecting live sockets or an established login; changes activate for new connections only after safety checks. Warn when the app must reconnect.
- Offline/unavailable required exit: **block** or hold the app's traffic, never reroute directly via Wi-Fi/cellular or an unapproved VPN.
- Correct policy must preserve IPv4, IPv6, DNS routing, UID-specific kernel route lookup, and WireGuard transport socket exemptions. No DNS leaks; no unverified IPv6 bypass.
- A US VPN address does not alter Android GPS/location permissions or stop app-level fingerprinting/cookies. Even a privacy exit does not confer true anonymity.
- Never change Android Private DNS from the user-verified OFF setup on the Pixel 8a.
- Do not make multiple unrestricted default WireGuard exits active merely by assigning different app categories. The current root planner intentionally rejects overlapping defaults. Per-UID separate routing tables/marks, verified forwarding, owned firewall rules, and independent fail-closed checks must be implemented *before* claims about simultaneous US+NL app exit routing.
- Non-root Standard mode continues to support one Android VPN by default. A future multi-exit non-root mode would need its own userspace packet router inside the single VpnService, not the rooted UID rules.

## 4. UI requirements, once enforcement actually works

- Home stays **Start → Add tunnel → choose tunnels**; do not add an app list to Home.
- Advanced Settings: **App Routing** shows installed app icon/name, category, and resulting tunnel; searchable/filterable with a clear **Privacy Default**.
- Categories page maps a category to one verified installed tunnel. A category assigned to an unavailable exit is visibly unavailable and cannot silently switch.
- Individual app detail can override the category exit, opt into home/private destination routes, or Block.
- Onboarding suggests categories based on a small curated local package-name catalog *only if the user opts in*. Never inspect account content, browsing history, banking data, or packet payloads for categorization.
- Display policy state as **Active / Needs configuration / Unsupported**, never a green check merely because a preference was saved.
- Advanced diagnostics can show UID→category→routing table→tunnel and independently verified per-app IPv4/IPv6/DNS paths. Do not present raw private addresses or keys in public logs.

## 5. Phasing and release gates

1. **0.15.56 Product B metadata and safe selection:** Categorize saved tunnels; show up to eight mutually compatible configured tunnels; refuse multiple unrestricted default exits with actionable feedback. This is **not per-app routing**.
2. **Next targeted root release — app category mapping & enforcement:** Implement a fully tested UID-based policy engine and app/category mapping screen; reject all unverified paths and keep a safe stop/rollback. Do not expose inert app-routing controls before actual enforcement is ready.
3. **Later — traffic purpose:** Domain/destination overrides, protected payment/login session pinning, source-aware private network routing, and independent DNS/IPv6 leak audits. Never claim generic encrypted request classification.

### Test cases before making app-routing claims

- US shopping UID and NL browser UID use their **selected** exits at the same time, with independent IPv4+IPv6 route proof.
- Home-address-only access works while other Moka traffic follows its authorized default; Moka and browser tests are separate.
- Unmatched/new packages stay on verified privacy default.
- Endpoint/WireGuard transport sockets cannot be routed into their own VPN or direct accidentally.
- On exit outage, disallowed traffic is **blocked**; never falls back to cellular/Wi-Fi. Verify this with controlled packet capture after independent safety stop/recovery checks.
- Login/checkout sessions are stable and not silently moved between countries.
- Existing system and networking services keep Android functional without ad-hoc bypass rules.
- H.1 Safe Stop and independent H.2a CLEAN_STOPPED succeed after failure cases.
- Backend and UX tests pass on a rooted Pixel and separate non-root Android device before beta statements.

**Do not merge this design requirement with an unverified live kill-switch or automatic app-routing activation.**
