# Fedora WireGuard gateway — preparation, not deployment

Wonhee Alpha 0.4 provides the Android client only. No gateway has been
installed by this PR. **Do not expose or change Navidrome or MTProxy.**

## Architecture

- Android Wonhee imports a private WireGuard client config via the system
  document picker; this prototype holds it only in process memory.
- Fedora serves a **separate authenticated WireGuard UDP endpoint** and
  routes selected traffic for the Android peer. MTProxy remains TCP/8443.
- Split tunnel peers use WireGuard addresses and explicitly configured
  **home private subnets** in AllowedIPs.
- Full tunnel peers use `0.0.0.0/0, ::/0` only when the gateway provides
  routes, forwarding, filtering, DNS, and IPv6 egress for both families.
  Do not add ::/0 before the IPv6 gateway path is actually configured.

## Read-only Fedora checks

```bash
ip -br addr
ip -4 route
ip -6 route
sudo firewall-cmd --get-active-zones
sudo podman ps --filter name=wonhee-mtproxy
sudo podman ps --filter name=moka-navidrome
```

Gather these before creating a gateway configuration. Your Fedora host was
previously dual-homed (10.0.0.169 wired and 192.168.50.141 Wi-Fi); confirm
which interface is now the internet default. Existing Telegram MTProxy uses
TCP/8443, while WireGuard requires a separate UDP listener and firewall rule.

## Implementation checklist

1. Select non-overlapping private WireGuard IPv4 and IPv6 interface
   addressing and a listening UDP port.
2. Generate independent WireGuard server/client keypairs **locally** with
   restrictive filesystem permissions. Never commit secrets or diagnostic
   copies of private keys.
3. Install WireGuard on Fedora through the normal system package manager,
   review a private `/etc/wireguard/*.conf`, and configure explicit peers.
4. Configure the necessary Fedora forwarding, firewall, and masquerade rules
   for chosen tunnel mode, accounting for IPv4 and IPv6 independently.
   A client config with `::/0` is unsafe to call full-tunnel when the server
   has no usable IPv6 egress.
5. Only after the server is secured, configure router forwarding of the
   selected **UDP** port to the Fedora host. Do not modify MTProxy TCP/8443.
6. Test a peer handshake, then private Moka/Navidrome access using an
   authenticated private proxy/bind, then public DNS/HTTP and leakage tests.
   Navidrome currently binds `127.0.0.1:4533`; do not make it public.
7. Set up a stable endpoint name if the home's public WAN IP changes,
   and test Wi-Fi-to-cellular routing.
8. Defer Always-on, lockdown, automated startup, encrypted DNS and
   tracker blocking until the client securely persists configuration and
   is proven to reconnect safely.

**No file in this repository contains a production WireGuard key or a
complete copy-and-run public internet gateway configuration.**
