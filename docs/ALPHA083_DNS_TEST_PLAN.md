# Wonhee Proxy Alpha 0.8.3 DNS Presets — Device Test Plan

**Status:** Experimental preview. Not a DNS leak audit, release, or privacy guarantee.

## Changes to verify

- DNS menu: Imported profile, Cloudflare, Quad9, AdGuard, Google Public DNS, Custom.
- Named presets use two IPv4 addresses. Custom accepts one or two numeric IPv4/IPv6 addresses separated by a comma.
- Address validation refuses empty, duplicated, malformed, special-purpose, or addresses outside active WireGuard AllowedIPs. No hostname DNS lookup is used for validation.
- Save and Connect persist the resolver choice in the existing Android Keystore-encrypted profile. Imported WireGuard keys and text remain unchanged.
- Old profiles with one custom DNS IP still restore as **Custom**, rather than silently adding a second provider address.
- All Internet (experimental) with no DNS configured displays a visible warning and requires a specific "Continue without DNS" confirmation before the normal connection confirmation.

## On-device regression checklist (Pixel 8a, preferably Samsung A36 too)

1. Back up the original WireGuard .conf securely **outside the app**. Do not expose private keys in logs or screenshots. Do not uninstall a working app until you have a trusted replacement and a plan to preserve data; CI debug APK signatures vary.
2. Open an existing saved profile with a single custom DNS IP. Check that it restores under **Custom**, and the previous IP stays unchanged.
3. In All Internet mode, select **Use imported profile DNS** with a .conf containing no DNS. Confirm the on-screen warning and separate missing-DNS confirmation appear. Cancel without connecting.
4. Select **Cloudflare** and connect; check the selected pair is displayed. Confirm a working WireGuard handshake, browser hostname resolution and general browsing with Android lockdown enabled. Compare observed public IPv4 to the Fedora VPN gateway's external IPv4.
5. Disconnect and force-stop the app. Reopen it: the selected profile, All Internet mode and Cloudflare preset should still appear. Reconnect and confirm browsing works.
6. Reboot the phone with Android Always-on/lockdown configured. Confirm actual tunnel restoration and browser DNS resolution. Check Ultgram independently if installed.
7. Repeat with Quad9, AdGuard and Google. Do not assume provider filtering is the same as an in-app tracker blocker.
8. Change to **Custom** and enter a home DNS IP. It should work only if that resolver is configured, listens for clients, and is allowed through WireGuard. Test two IPs separated by a comma.
9. Reject empty custom DNS, duplicate IPs, malformed IPs, three servers, and addresses outside AllowedIPs. Failure must not start the tunnel or persist an invalid choice.
10. In Home access mode without a default tunnel route, selecting a public DNS preset should fail validation unless the appropriate public DNS IPs are explicitly tunnel-routed. Imported DNS remains unchanged.
11. Test cellular/Wi-Fi transitions, then repeat browsing and lockdown interruption testing. A successful peer handshake by itself is insufficient to prove DNS routing or leak protection.

## Fedora gateway follow-up

- With wg0 forwarding to FedoraWorkstation and masquerade in wonhee-egress, confirm actual gateway logs/counters and the enabled forward/NAT policy; do not change firewalld rules as part of this Android UI test.
- Test packet routing and DNS at the VPN gateway before labeling results a leak check. Review IPv4 and IPv6 separately, along with Private DNS / application-specific DoH behavior.
- Remember public DNS destinations receive queries from the gateway after tunnel egress; WireGuard encryption covers the phone-to-gateway segment, but this feature does not encrypt the gateway's DNS transport to the upstream resolver.

## Expected outcomes

- No loss of the selected WireGuard profile or imported keys.
- Presets remain selected on reconnect, force-stop, and reboot.
- Missing DNS is plainly surfaced before a full-tunnel connection is started.
- No security claims beyond observations verified on actual device and gateway.
