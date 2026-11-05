# Wonhee Proxy 0.9.7.0 — rooted route and recovery audit

This is an **observation-only** regression build. It does not install a kill
switch, modify Android DNS, start tunnels at boot, or claim leak prevention.
The stable single-tunnel VPN path remains unchanged.

## Test on the rooted Pixel 8a

1. Use the installed root lab to select `wgs_client` as **Home / ASUS** and
   `AirVPNEurope` as **Internet / AirVPN**. The profiles and keys are not edited.
2. Start both rooted tunnels and verify each new WireGuard handshake.
3. Select **AUDIT PUBLIC / HOME ROUTES + ANDROID DNS**. A healthy root policy
   should report both public IP families selecting `wnair0` and all configured
   Home split routes selecting `wnhome0`.
4. Inspect **Android active-network DNS** separately. It is an observation of
   root route-get results for the DNS addresses reported by Android; it cannot
   prove how all app sockets, Private DNS, or DoH/DoQ actually route.
5. Run an independent public IPv4/IPv6, WebRTC and extended DNS-leak test from
   a browser on the phone while connected to mobile data.
6. After an app stop/relaunch, select **INSPECT KERNEL INTERFACES AFTER RESTART**.
   If interfaces remain while the app does not manage them, use explicit
   identity-verified recovery. The inspection button never alters interfaces.
7. Use **COPY LAST TEST RESULT** to share the non-secret route audit output.

## Safety gates before enabling a kernel kill switch

- Capture the **CHECK FIREWALL CAPABILITIES (READ ONLY)** result on the Pixel.
- Establish a tested transport exemption for *both* encrypted WireGuard
  endpoints, including endpoint IP change on Wi-Fi/cellular handoff.
- Prove IPv4 and IPv6 **block rather than fallback** when AirVPN fails.
- Prove DNS does not escape through unprotected networks, including app-specific
  Private DNS and encrypted resolver paths.
- Prove recovery after app crash, tunnel interruption and phone reboot without
  leaving orphaned firewall rules or blocking the owner's emergency recovery.

Do not rely on the root experiment for privacy-sensitive traffic until those
gates pass. Android VpnService lockdown is not a kill switch for interfaces
managed outside VpnService.

## Fedora / Navidrome after host reboot

The `wonhee-navidrome-proxy.service` was reported **enabled and running**.
After the host restarts, confirm its actual new state before treating access
as persistent:

```bash
systemctl is-enabled wonhee-navidrome-proxy.service
systemctl is-active wonhee-navidrome-proxy.service
curl -v --connect-timeout 5 http://10.0.0.169:4533/
```

For the last command, HTTP 302 to `/app/` demonstrates local listener
availability. It does not by itself prove access through the Pixel's ASUS
tunnel. Keep the listener private and plan trusted HTTPS for longer-term use.
