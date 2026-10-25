# Wonhee Proxy Alpha 0.6 — Manual routing mode test plan

**Build:** version 0.6.0-alpha06 (versionCode 7). Test on Pixel 8a first. Save a
private copy of your WireGuard .conf before upgrading or uninstalling. CI debug
signing can change between runs, and uninstalling can delete Android Keystore
material; do not remove Alpha 0.5 just to force an APK install.

## Baseline and persistence

1. Verify Alpha 0.5 encrypted profiles still appear in Alpha 0.6 with **Use
   profile routes (unchanged)** selected. Reconnect and check fresh handshake
   and nonzero receive/transmit counters. Retest Telegram proxy tools / Ultgram
   handoff. Do not post .conf files or private keys in test reports.
2. Choose **Home access (split routes)**. Enter `10.77.0.0/24`, tap **Save
   encrypted profile** and confirm if replacing. Force-stop and reopen Wonhee;
   check the mode and CIDRs were retained. Repeat with **Use profile routes**.
3. Check invalid Home routes (empty, `0.0.0.0/0`, `::/0`, malformed text
   and more than 16 CIDRs) are rejected before Connect or Save. Existing
   encrypted profiles must remain unchanged.
4. Try changing mode while connected: mode picker and home routes must be
   disabled. Disconnect to edit, then reconnect.

## On-device home routing

5. On the phone, disconnect Tailscale or other VPN. Prefer **cellular** for a
   true remote test; Wi-Fi on the same LAN is not sufficient.
6. In **Home access** with `10.77.0.0/24`, connect to your Fedora WireGuard
   endpoint and verify a recent handshake. Ping or request `10.77.0.1`
   through an authorized tool. Other internet requests should still use
   cellular egress (split VPN); this is expected, not a failed privacy test.
7. If you need `192.168.50.0/24`, configure and verify Fedora forwarding
   and its return route/firewall separately first. Do not assume the VPN
   server's second local interface subnet is reachable by default.

## Experimental all-internet routing — only after gateway preparation

8. Read-only Fedora precheck: `sysctl net.ipv4.ip_forward`,
   `sysctl net.ipv6.conf.all.forwarding`,
   `sudo firewall-cmd --get-active-zones`,
   `sudo firewall-cmd --get-policies` and
   `sudo firewall-cmd --zone=wonheevpn --list-all`.
   The previously suggested `wonhee-egress` policy was not created
   (`INVALID_POLICY`). Do not assume firewall forwarding/NAT is ready.
9. Choose **All internet (experimental)**. Read and accept the warning. Check
   that tunnel packets/handshakes occur and phone internet works over
   *cellular*, then confirm the phone's IPv4 egress equals your home's
   current public IPv4 address. Check IPv6 egress and DNS separately from the
   phone. A fresh handshake does not prove either test.
10. Switch networks, drop connectivity, disable the gateway and force-stop the
    app. Record which traffic resumes or fails and whether DNS/IPv6 uses a
    non-VPN path. **Always-on and kill switch are NOT implemented**; do not
    use for sensitive traffic. If internet stops, disconnect and choose Home
    access or original profile routes instead.

## Evidence and pass criteria

- Keep a redacted screenshot of routing selector, redacted VPN status, and
  whether each step passed. Do not include endpoint secrets, .conf content,
  private keys, or sensitive public IPs.
- Full tunnel is **not accepted as protective** until IPv4, IPv6, DNS and
  failure-state behavior are verified independently from the phone.
- Validate on a second device (e.g. Samsung A36) after the Pixel 8a pass.

The APK changes Android only. It does not change Fedora firewalld policies,
Podman MTProxy, Navidrome, Tailscale, or the home router.
