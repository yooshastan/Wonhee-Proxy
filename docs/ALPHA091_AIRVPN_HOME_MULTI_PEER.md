# Wonhee Alpha 0.9.1 — AirVPN + private home WireGuard gateway

**Status:** experimental, debug-signed development build. Do not rely on it for a
privacy or fail-closed guarantee until full device tests succeed.

## What the combined profile does

Android supports one active VPN service for a given user/profile. Wonhee uses
one WireGuard tunnel with multiple peers in the same interface:

- **Primary peer:** AirVPN or another WireGuard provider handles Internet
  egress, typically `AllowedIPs = 0.0.0.0/0, ::/0`.
- **Private peers:** the user adds home networks such as `10.77.0.0/24` or
  `192.168.50.0/24`. The most-specific matching WireGuard AllowedIPs
  determines the peer; home CIDRs must not conflict with other private peers.
- **Only one client private key and interface address** can be used. This is
  **not** two separately authenticated WireGuard VPNs running simultaneously.

You control the home gateways, so you can authorize the existing AirVPN client
**public key** and route responses to that client's existing tunnel address.
AirVPN does not need to receive your home gateway's private key. The home peer
must be reachable from the device's underlying Internet connection.

If two providers insist on distinct client keys/addresses, the peer-only
importer **cannot** connect to both at once. Use separate saved profiles and
switch, or deploy a more sophisticated nested tunnel/gateway architecture.

## Preparation on the home gateway (manual; not done by Wonhee)

1. Securely export your selected AirVPN WireGuard profile and import it as the
   **primary** profile into Wonhee. Do not publish or paste its `PrivateKey`.
2. Locally derive the **public key** of that primary client identity (the
   corresponding WireGuard public key, not the AirVPN server key). Get the
   AirVPN-assigned client tunnel IP from the primary profile's `Address`.
   These must remain the same when Wonhee connects to the home gateway.
3. Configure a peer on each home WireGuard server with **that client public
   key**. Its server-side `AllowedIPs` must include the exact AirVPN-assigned
   client tunnel address as a host route (`/32` for IPv4). For example, if the
   primary `Address` were a fictitious `10.99.23.14/32`, the home server
   peer would use `AllowedIPs = 10.99.23.14/32`. This is only a placeholder.
4. Ensure the server routes responses back to that exact tunnel address and
   permits the desired private traffic in its firewall. Check potential address
   conflicts, WireGuard routing, policy routing and reverse-path filtering.
   A handshake alone is not proof of bidirectional IP connectivity.
5. Ensure the home WireGuard server's public UDP endpoint is reachable.
   The home server may need a port forward for **WireGuard UDP only**. Do not
   publicly expose Navidrome TCP port 4533.
6. Verify that Navidrome listens only where intended (for example a service
   bound to `10.77.0.1:4533` forwarding to the container bound at
   `127.0.0.1:4533`), and that the `wonheevpn` firewalld zone permits
   only your expected private clients. Consult
   `gateway/WONHEE_NAVIDROME_SYSTEMD.md`.

The AirVPN address, DNS and routing details may differ between accounts and
device profiles. The app never assumes it can configure your home server.

## Make a peer-only home file

Create a local text file with **one** `[Peer]` stanza (not a second WireGuard
`[Interface]` stanza):

```ini
[Peer]
PublicKey = <HOME_SERVER_WIREGUARD_PUBLIC_KEY>
Endpoint = <HOME_PUBLIC_HOSTNAME_OR_IP>:51820
AllowedIPs = 10.77.0.0/24
PersistentKeepalive = 25
```

Replace the placeholders with the **home server public key and endpoint**.
Optionally add `PresharedKey` only if the home server is configured with the
matching PSK. An additional home gateway uses a separate peer-only file and
**different non-overlapping private IPv4 routes**.

The preview deliberately accepts only a single `[Peer]` per import, with
standard keys and 1–4 **entirely RFC1918** IPv4 AllowedIPs. It rejects public
destinations, default routes, IPv6 route additions, duplicate fields,
overlapping home CIDRs and multiple sections. Existing primary
`0.0.0.0/0` may overlap more-specific home routes by design.

## Import in Wonhee

1. Disconnect Wonhee, select the saved AirVPN primary profile.
2. Select **Use profile routes (unchanged)**.
3. Tap **Add private gateway peer to selected VPN**.
4. Pick your home peer-only file, review the confirmation, and create the new
   encrypted profile. **Your original AirVPN profile remains untouched.**
5. Select the newly saved combined profile and connect it. If adding another
   home gateway, disconnect and repeat starting with the combined profile.
6. If the encrypted profile store already has its maximum of eight entries,
   free a slot **only after backing up** a profile you choose to remove.

Do not import your original home **full client .conf** as a peer snippet; its
`[Interface]` contains a different client identity and must not be copied
into an AirVPN interface.

## Manual test plan — Pixel 8a / Samsung A36

- [ ] Connection: primary AirVPN peer handshakes; ordinary Internet works.
- [ ] Confirm Internet exit IP via user-chosen verification page with the
  combined profile active; it should match intended AirVPN egress.
- [ ] Home WireGuard server logs a *recent handshake* from the combined
  client's public key, then receives and returns packets.
- [ ] Through the VPN, reach `10.77.0.1:4533` and test authenticated
  Navidrome library refresh plus actual music playback in Moka.
- [ ] Disable the home peer temporarily at the home server. Verify public
  traffic still takes the AirVPN route, home service appropriately fails,
  and there is no unintended direct fallback.
- [ ] Change Wi-Fi to cellular and back; test both peers after handshakes
  resume and after an extended idle/overnight interval.
- [ ] Check configured Android DNS routes, DNS-resolution results and IPv6
  behavior. A successful IPv4 test is **not** proof of DNS/IPv6 leak prevention.
- [ ] Test Android Always-on and **Block connections without VPN** only after
  the provider's full-tunnel forwarding and recovery are functional. Manual
  disconnect must remain intentional and not trigger unattended retry.
- [ ] Confirm import errors don't reveal private keys in on-screen reports or
  logs. Confirm encrypted combined profile survives app relaunch/reboot.

## Known constraints

- Android's VPN slot is shared with Tailscale, WireGuard standalone and other
  VPN clients. Wonhee cannot operate side by side with another active VPN app.
- Multiple full independent WireGuard client profiles **cannot** be naively
  merged. This preview requires re-authorizing the same shared client identity
  on gateways you control.
- The importer builds the profile but does **not** enforce or attest route
  integrity, active peer reachability, server-side firewall policy, DNS or
  fail-closed behavior.
- AirVPN's interface `Address` may be provider-specific; never assign an
  arbitrary home IP to this interface without confirming return routing.
- Separate public/private IP overlap or endpoint routing problems may cause
  a connection to appear active while a gateway is unreachable.
