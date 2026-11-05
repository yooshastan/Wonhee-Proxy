# Wonhee Proxy 0.9.8.0 — kernel guard arming precheck

The Pixel 8a root capability report confirmed IPv4 `iptables`, IPv6
`ip6tables`, and policy routing. `nft` is unavailable and is not required for
this experiment. Tool availability is **not** proof of fail-closed networking.

## New test

1. Start the existing ASUS Home (`wnhome0`) and AirVPN (`wnair0`) kernel pair.
2. Ensure both peers show fresh handshakes and Home/Navidrome remains reachable.
3. Tap **CHECK KILL-SWITCH ARMING READINESS (READ ONLY)**.
4. Copy and share the result. No `.conf`, private keys or tunnel credentials
   are needed. The result reports whether both socket marks are nonzero and
   distinct, both filter backends expose mark match support, the expected root
   default routes select AirVPN, and the reserved rule names are unoccupied.
5. If it says **NOT READY**, do not install or manually improvise firewall
   rules. Preserve the complete report for the next change.

This version intentionally does **not** add any OUTPUT hooks, install firewall
chains, set Android Always-on, or promise DNS leak protection. Next, design a
short-lived *opt-in* test that has safe endpoint transport exemptions, rollback
after interruption, and a separately verified emergency removal path. Both
public IP families must fail closed with AirVPN down before persistent
enforcement can be considered.
