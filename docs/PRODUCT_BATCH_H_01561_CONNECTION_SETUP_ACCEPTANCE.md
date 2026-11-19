# Wonhee 0.15.61 — connection setup repair and honest rule targets

**Status: review candidate, not a live per-app routing release.** VersionCode 108, versionName `0.15.61-connection-setup`. Builds on PR #91.

## Why this change exists

On-device screenshots after 0.15.60 show that:
- **Protocol choices still say "draft"** and cannot control actual traffic. This is expected from the implementation (the live UID/port network engine is intentionally disabled), but NOT acceptable as a final everyday VPN workflow.
- The Global Protocol screen requires choosing a category, then switching to another tab to find which tunnel that category references. A user can select SMTP → Home even if the Home category is mapped to `wgs_client1` with **private destination routes only**. This is not a valid unrestricted Internet exit for general SMTP traffic.
- Selecting AirVPN Europe (default), wgs_client1 (private destinations) and AirVPN America (default) produces multiple checked profiles, yet only Europe + Home can start in current root mode. The other Internet profile is **not connected**. A user reasonably reads "selected" as "will run." The root engine still lacks real per-app multi-default routing.
- "Not connected" alone doesn't tell us whether Start failed due to root preflight, reserved rules/ledger, tunnel setup, routing, or `LOCAL_DNS_TIMEOUT` (previously observed). We must not guess.

## Implemented here

1. Home, under saved tunnel selection, has **Check setup · no connection changes**.
2. If multiple full Internet exit profiles are selected, the check first asks which one is the **primary**. It computes exactly which entries the existing root Start would attempt, excluding parked full exits. It **does not** start those parked tunnels or claim to.
3. It invokes the **existing read-only H.1 root preflight**, which inspects safety ledger, root readiness, actual effective routes, collisions, stale interfaces, resolver/firewall listener prerequisites, Android Private DNS OFF and unattended recovery. It does not call connect, applyRouting, enableRootDns, or install a firewall/kill switch.
4. The result is a short, user-friendly next step with no raw private shell/error data, including `H.2a` audit instructions where appropriate. A passing preflight explicitly states that it did **not** test actual connectivity or encrypted DNS. Unit/static tests enforce this distinction.
5. On **App Routing → Protocols**, the user can now choose **preset/custom TCP/UDP + port**, **category**, and the **actual saved target tunnel in one place**. Previously these were separated across tabs, making invalid mappings easy.
6. For blanket global transport rules, a tunnel whose effective parsed routes lack either IPv4 or IPv6 Internet default is rejected before saving. A Home-only CIDR tunnel cannot be silently selected for generic SMTP or HTTPS traffic.
7. The category's tunnel mapping and the port rules are stored **atomically in one private SharedPreferences commit**, so a failed save cannot leave a new rule pointing at an old target. Other apps using that category would also get the newly selected *planned* target; the confirmation says so. Nothing is enforced by merely saving.
8. The existing full-exit / split-destination root route validator, actual dual-tunnel Start, H.1 Safe Stop, DNS ownership firewall, recovery and non-root VPN mode are intentionally preserved.

## Explicitly not solved

- The root backend does **not** yet support simultaneous independent Netherlands + US unrestricted Internet exits chosen by app or port; the feature requires independent per-exit policy tables, Android fwmark and UID attribution, encrypted DNS per exit, dual-stack fail-closed firewall, and proven owned rollback. See issue #89. Extra full exits are still **selected but parked (not connected)**.
- Global TCP/UDP/port rules remain **planning-only**, not live packet routing. Their dropdown does not alter an active VPN.
- A passing read-only setup check is **not proof** that a tunnel can handshake, reach an Internet destination, or get a verified encrypted DNS response. Previous `LOCAL_DNS_TIMEOUT` is not claimed fixed here.
- No all-traffic kill switch is enabled or bypassed; Android Private DNS on the Pixel 8a environment remains OFF.

## Recommended on-device testing order

1. Cleanly stop and independently confirm **H.2a CLEAN_STOPPED**. Keep ADB recovery available.
2. Verify the original-signed candidate versionCode **108** installed in place without removing saved profiles.
3. On Home select **AirVPN Europe** (full default) and **wgs_client1** (specific private destinations). Press **Check setup · no connection changes** and capture the result.
4. If the preflight passes, press Start **once**. Capture the **Latest Result** if it fails; its stage distinguishes tunnel connection/routing/DNS, unlike "Not connected" status.
5. Only after that connection is proven and safely stopped should the **AirVPN America** full-exit profile also be selected. The primary-exit picker should activate exactly one unrestricted exit plus the compatible private tunnel, with the extra exit explicitly **not connected**. No hidden successful third connection.
6. In Protocols: choose **Email / SMTP**, select **Regional**, select a full dual-stack **AirVPN US** tunnel inline, then save. Verify both the global TCP port rules and category's chosen tunnel after reopening. They must be labelled planned, not active.
7. Try selecting **wgs_client1** (split destinations only) for a global SMTP rule. Verify it clearly refuses that invalid blanket exit **without modifying the previously saved mapping**.
8. Cancel a preset/save confirmation and verify no change; check atomic behavior at the 20-rule limit.
9. Verify Home Start remains first; Tunnels/Protect/Stats/More, import Back and non-root mode remain functional.
10. Android + native GitHub CI and rootless core checks pass before considering a signed local build candidate.

## Developer commands after CI success and independent clean-stop verification

```bash
cd ~/Wonhee-Proxy-UI || exit 1
git fetch origin
git switch feature/root-connection-setup-01561 || \
  git switch --track origin/feature/root-connection-setup-01561
git pull --ff-only origin feature/root-connection-setup-01561
bash scripts/build-wonhee-official-local.sh
# Only after fresh H.1 Safe Stop + independent H.2a CLEAN_STOPPED:
bash scripts/install-wonhee-safe-update.sh
```

**Do not interpret a successful APK build as a working simultaneous triple-VPN or live protocol-routing release.** The missing backend and real-device DNS failure diagnosis remain blocking work.
