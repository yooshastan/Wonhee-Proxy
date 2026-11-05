# Wonhee Proxy 0.9.8.1 — kernel guard arming precheck

The Pixel 8a root capability report confirmed IPv4 `iptables`, IPv6
`ip6tables`, and policy routing. `nft` is unavailable and is not required for
this experiment. Tool availability is **not** proof of fail-closed networking.

## New test

1. Start the existing ASUS Home (`wnhome0`) and AirVPN (`wnair0`) kernel pair.
2. Ensure both peers show fresh handshakes and Home/Navidrome remains reachable.
3. Tap **CHECK KILL-SWITCH ARMING READINESS (READ ONLY)**.
4. Copy and share the result. No `.conf`, private keys or tunnel credentials
   are needed. The result now distinguishes Home and AirVPN marks and reports
   whether Home has a numeric peer UDP endpoint without revealing its address.
   Both filter backends, public root routes and reserved chain names are also
   checked.
5. A split-only Home profile can legitimately have no transport mark because
   `wg-quick` normally adds a mark when handling default routes. If the result
   says **HOME ENDPOINT EXEMPTION NEEDED**, the tunnel itself has not failed;
   an explicit, independently tested Home endpoint exception would be needed
   for a future fail-closed firewall policy.
6. If it says **NOT READY**, do not install or manually improvise firewall
   rules. Preserve the complete report for the next change.

This version intentionally does **not** add any OUTPUT hooks, install firewall
chains, set Android Always-on, or promise DNS leak protection. Next, design a
short-lived *opt-in* test that has safe endpoint transport exemptions, rollback
after interruption, and a separately verified emergency removal path. Both
public IP families must fail closed with AirVPN down before persistent
enforcement can be considered.
