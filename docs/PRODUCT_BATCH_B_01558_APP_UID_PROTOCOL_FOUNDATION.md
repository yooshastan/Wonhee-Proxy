# Wonhee 0.15.58 — per-app UID + TCP/UDP protocol-routing foundation

**Development candidate; not live routing.** VersionCode **105**, versionName **0.15.58-app-uid-protocol-plan**. Depends on draft 0.15.57 app categories, 0.15.56 tunnel labels and 0.15.55 DNS diagnostics.

## User intent

The user wants *real* app-specific tunnels and, in addition, controls by protocol within each app, e.g.:

- **Ultgram → Netherlands exit**, with optional exact TCP/UDP destination-port overrides.
- **McDonald's → US exit**, with a separate port override only if justified.
- **Moka → Home for private Navidrome destinations**, but it must not be mistakenly configured to send **every** Internet connection to a Home-only split tunnel.
- Later: category-wide/global transport policies and destination-aware traffic classification, without making a packet's encrypted payload available to Wonhee.

**The current production-style root multi-WireGuard engine does not support two simultaneous full default Internet exits by app UID.** Simply removing the one-default validation would be unsafe. This batch builds the precise app/transport policy and readiness gate first, keeping live routing disabled.

## Implemented in code

1. **App Routing → Apps → Protocol rules** is optional per app, with explicit TCP / UDP, an optional destination port (blank = any destination port for that transport), and a chosen saved VPN tunnel.
2. Users can save at most **6 overrides per app**, **72 total** in private on-device preferences. Rules can be viewed and removed. The UI is labeled **PLANNING ONLY · NOT ACTIVE**; no root commands execute from it.
3. Rule ordering is deterministic: **app + transport + exact destination port → app + transport, all ports → app-category preferred exit → configured Everyday exit**.
4. A pure independent policy planner reads selected WireGuard **effective** routes into separate *proposed* routing tables (51000+), and designs UID range / exact TCP/UDP / port lookup selectors, each with a **proposed following terminal block** so that missing routes would not fall through to the ordinary network.
5. Current installed package UIDs are freshly resolved for each read-only review. Shared UIDs, missing app ownership, deleted tunnel profiles, unsupported app/system UID ranges, duplicate selectors, IPv4-only Internet routes, a Home-only tunnel as an all-traffic exit, and missing default exit are refused. No historical UID is trusted.
6. The dedicated **Review app + protocol policy · read only** control produces an explanatory report without running any root command.
7. The independent core test suite covers multiple full exits in **separate proposed policy tables**, cross-app UID conflicts, precedence, exact port matching, supported protocols, terminal block priorities, dual-stack requirements, and hard-denied activation. Android CI additionally checks the UI and static no-kernel-write boundary.

## Protocol interpretation — important limitations

- **TCP (IP protocol 6)** and **UDP (IP protocol 17)** are network-layer/transport-header values available for classification. Numeric destination ports are useful selectors but **not reliable indicators of application intent**.
- Examples that **must never** be assumed true merely from a port: “TCP 443 is safe static media”, “UDP 443 is always QUIC”, “port 443 is always regular HTTPS”, “port 853 always means DoQ”, or “port 53 always means an ordinary DNS query”.
- Encrypted HTTPS, HTTP/3, DNS-over-HTTPS and custom protocols can share TCP/UDP ports. Wonhee does not MITM TLS/QUIC or inspect decrypted content.
- Changing tunnel exits between login and checkout can disrupt authenticated sessions. In the eventual enforcement design, route selection must be sticky for each connection. No mid-flow unannounced switching.
- **A tunnel whose routes cover only private Home CIDRs is not a full Internet exit.** A Home app policy requires destination-specific routes with a safe Internet fallback or explicit block, not a blanket UID-to-Home assignment.

## Why live enforcement is blocked

The `RootPerAppUidPolicyPlan.Plan.activationAllowed()` method **always returns false**, and no code path applies its generated route-rule proposal to the kernel. Do not enable until independently tested:

- Multiple isolated WireGuard exit tables with complete IPv4 and IPv6 coverage, no UID collisions, no route/fwmask priority collision with Android netd.
- Actual Android socket mark behavior, especially protectedFromVpn and system services; UID alone is insufficient to prove actual egress.
- Correct per-app DNS ownership and per-exit encrypted resolver selection; resolver/helper sockets must use the required tunnel, not a different exit or plaintext.
- All app/transport selectors must **fail closed** on tunnel loss, app restarts, config changes, Wi-Fi/cellular handoff and reboot. Terminal kernel rules alone are not a tested device-wide kill switch.
- Durable exact-owned policy ledger, atomic update/recovery, read-only identity audit and rollback to H.2a **CLEAN_STOPPED**; no flushing unrelated root or Android networking tables.
- No silent permissive fallback, no partial enablement, and no exposure of key material or unredacted domain names in logs.
- **0.15.55 encrypted DNS startup failure remains a separate blocker**; app routing must not obscure or bypass it.

## Device acceptance flight (UI + non-enforcement only)

| ID | Test | Expected |
|---|---|---|
| U1 | Tunnels → App Routing → Apps, select an installed app | Existing category workflow retained |
| U2 | Press “Protocol rules” on one app | Separate simple screen, category selection preserved |
| U3 | Add TCP port 443 → US tunnel | Saved, listed as draft, no active route changes |
| U4 | Add TCP all ports → NL tunnel | Saved alongside exact rule; exact port has higher future priority |
| U5 | Add UDP port 443 → US tunnel | Saved separately; no assumption it identifies QUIC |
| U6 | Leave destination port blank | Saved as “all ports” for selected TCP/UDP |
| U7 | Try port 0, 65536, nonnumeric and unsupported rules | Invalid inputs refused clearly; old rules retained |
| U8 | Delete one rule and relaunch | Only the chosen draft rule disappears; other preferences persist |
| U9 | Categories → set Everyday exit, Regional exit → read-only review | Shows current UID ownership, dual-stack conditions, proposed route priority and **ACTIVATION BLOCKED** |
| U10 | Assign Home-only private tunnel to all app traffic | Read-only review refuses; asks for destination-specific routing |
| U11 | Two simultaneous full exit profiles in draft | Read-only pure plan can identify both, but live root Home start still refuses until new backend is proven |
| U12 | Open/close app and change draft routing | No root prompt, interface start, new firewall rule, DNS change, or active connection interruption |
| U13 | Stats, More, Protect, legacy WireGuard profile editor | No UI regressions |
| U14 | Core Java tests + safety static checks + Android APK compile + native WireGuard suite | All pass; still NOT a beta/live routing release |

## Current UI entry point

**Tunnels → Set up app categories → Apps → Protocol rules · preview.**

Set per-category preferred tunnels on the Categories tab, then optionally check **Review app + protocol policy · read only**. This is a safety audit, not an activation button.

## Fedora source checkout

```bash
cd ~/Wonhee-Proxy-UI || exit 1
git fetch origin
git switch feature/root-app-uid-routing-foundation-01558 || \
  git switch --track origin/feature/root-app-uid-routing-foundation-01558
git pull --ff-only origin feature/root-app-uid-routing-foundation-01558
bash scripts/build-wonhee-official-local.sh
# Original signing key only, and only after independent H.2a CLEAN_STOPPED:
bash scripts/install-wonhee-safe-update.sh
```

**Do not install merely because CI passes.** Verify Android/app regression checks first, and preserve the paused all-traffic kill switch. On Pixel 8a, keep Android Private DNS OFF.
