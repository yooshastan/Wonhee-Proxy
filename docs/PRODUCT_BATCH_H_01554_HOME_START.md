# Wonhee 0.15.54 — Root Start and Safe Stop stay on Home

**Status:** Product H development candidate; not beta-ready; on-device acceptance required.
VersionCode **101**, versionName **0.15.54-home-start-flow**.

## Reported issue

Tapping **Start** on the main screen launched the entire old **Multi-Tunnel Lab**, exposing the lab's tabs, second connection controls, and long diagnostics instead of starting a normal everyday connection. The 0.15.53 Home action constructed an Intent for `RootMultiKernelActivity`, causing the detour even though the first action was supposed to be Start.

## Resolution

The main dashboard now owns its **root** Start / Safe Stop interaction:

1. Tap **Start** with the selected tunnel checkboxes already checked on Home.
2. Show one concise confirmation with tunnel count, chosen Internet exit, DNS provider and tracker-filter status. A **Cancel** changes no routes or network state.
3. After **Start**, show progress on Home: preflight -> WireGuard -> exact-owned private routes -> encrypted DNS -> DNS audit.
4. On each failure, preserve the existing `RootMultiKernelSession` validation and attempt exact-owned Safe Stop rollback (for failures after connection/routing). Report failures on Home, with an intentional **Diagnostics** option.
5. On success, Home refreshes verified tunnel/relay state; the old lab is **not launched**.
6. When active identities match, **Stop** presents its confirmation on Home and delegates to `RootMultiKernelSession.stopManagedStack`, verifying ownership before disconnecting and refusing unknown/failing states.

The backend remains the existing tested `RootMultiKernelSession` methods:
`preflightManagedStart`, `connect`, `applyRouting`, `enableRootDns`,
`auditRootDns`, and `stopManagedStack`.

The Home quick-start profile must contain exactly one IPv4/IPv6 Internet exit and a private-destination tunnel (required for the full-stack Home split policy). The existing preflight still refuses overlap, root-recovery conflicts, a live DNS listener, unknown firewall rules, and rooted tunnel identity conflicts.

**Current Home DNS behavior:** for this development candidate, Home explicitly confirms and uses the existing lab default *Cloudflare DoH / 1.1.1.1*, routed through the selected Internet tunnel. Custom DoQ/DoH3/provider URLs remain an advanced workflow; Home does not silently claim to honor custom lab settings. Tracker filtering and any allow/block lists are loaded from existing saved preferences. All traffic kill-switch activation remains paused and never becomes enabled.

## Non-root

The Standard one-VPN workflow is unchanged by this patch. It still uses the existing `VpnActivity` confirmation and Android permission flow. This fixes **root Home's inadvertent Tunnel Lab detour** without refactoring the non-root VPN engine.

## Regression acceptance tests

- [ ] **H01** Launch Wonhee. Confirm the app opens Home with large Start, then Add tunnel and selected tunnel checkboxes. No legacy screen.
- [ ] **H02** Press Start. A concise confirmation appears **on top of Home**. The Multi-Tunnel Lab does **not** open.
- [ ] **H03** Press Cancel. Home stays visible, with no DNS/routing/tunnel state changed.
- [ ] **H04** Choose an Internet exit + Home split tunnel; approve Start. Progress stays on Home. Existing backend preflight and DNS audit complete.
- [ ] **H05** Start with none, only Internet, only Home, or two Internet exits. Clear refusal before any mutation; no lab detour.
- [ ] **H06** Start when root state unavailable, session busy, or owned DNS/guard ledger still present. Clear refusal and no mutation.
- [ ] **H07** Root Home Stop when verified tunnels are active. Safe Stop confirmation stays on Home; cancellation leaves network unchanged.
- [ ] **H08** Complete Safe Stop and verify the backend's owned cleanup. Home returns to disconnected; independent H.2a CLEAN_STOPPED remains mandatory before updating the signed app.
- [ ] **H09** If Start fails during DNS (controlled failure; no real-world network disruption), rollback succeeds or reports an incomplete cleanup and offers manual diagnostics. No false "Connected" claim.
- [ ] **H10** After starting or stopping, move to Tunnels, Protect, Stats and More, then return to Home. No duplicated connection picker, stale modal or old dashboard.
- [ ] **H11** Root notification / tile / launcher always open Home, not Multi-Tunnel Lab.
- [ ] **H12** Root Private DNS remains OFF on the test Pixel 8a; no new background recovery, packet exception or all-traffic guard enablement.

## Safety and update

No root firewall or kill-switch code changed. The original guard remains **activation-paused**. The physical packet path and control-plane requirements of Batch F must be independently validated before activating it; this is not a kill-switch release.

On Fedora, refresh the existing checkout and build with the original keystore:

```bash
cd ~/Wonhee-Proxy-UI
git fetch origin
git switch feature/unified-everyday-ui-01548
git pull --ff-only origin feature/unified-everyday-ui-01548
bash scripts/build-wonhee-official-local.sh
# Only after H.1 Safe Stop and independently verified H.2a CLEAN_STOPPED:
bash scripts/install-wonhee-safe-update.sh
```

No installation of a differently signed .rootlab CI artifact is required.
