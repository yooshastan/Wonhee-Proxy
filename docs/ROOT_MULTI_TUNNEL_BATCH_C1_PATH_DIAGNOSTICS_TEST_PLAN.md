# Wonhee 0.11.1 — Batch C.1: transport marks and service path

This is a **read-only device-configuration diagnostic** build on Batch C.
The TCP test creates one outbound connection from Wonhee's own app UID, but
sends no HTTP request or credentials. It does not change routes, tunnels,
iptables, DNS, or Android VPN settings. The actual kill switch remains **OFF**.

## Why this batch exists

- Batch B split routes matched 3/3 and private Navidrome worked once.
- Batch C found both WireGuard transports' `fwmark`s set but could not prove
  they were different. The new gate prints each numeric hexadecimal mark;
  shared marks cannot be treated as per-tunnel firewall identities.
- A later Brave test of `http://10.0.0.169:4533/app/` returned
  `ERR_CONNECTION_ABORTED`. Good UID-0 routes alone cannot distinguish
  a service not listening on LAN from an app-socket or HTTP problem.

## One batch of device checks

1. Install/update version `0.11.1-batchC1-path-diagnostics`. Do not uninstall
   a differently signed build without backing up encrypted profiles first.
2. Select existing `wgs_client1` and `AirVPNEurope` profiles in Multi-Tunnel
   Lab. This UI/route planner supports any compatible selection, up to the
   existing eight-profile limit; those two are only current test fixtures.
3. With both kernel interfaces active and the known Batch B split rules
   applied, tap **Check multi-tunnel guard readiness**. Record both `UDP mark`
   values. They may be equal; if so, report it rather than changing the marks.
4. Enter `10.0.0.169:4533` into **SERVICE PATH · APP SOCKET TEST** and tap
   **Test app TCP reachability**. Capture the full output including expected
   selected tunnel, UID-0 lookup and app socket status.
5. Tap **Audit configured DNS routes** and capture the result (even if no
   resolver destinations are configured).
6. Retry the Navidrome URL in Brave and report whether the page opens. This
   browser result is separate from Wonhee's app-UID TCP result.
7. Confirm **ACTUAL KILL SWITCH: OFF** and neither the new guard audit nor
   service test added routing/firewall rules. Stop here if anything changes
   unexpectedly; preserve a route report and ADB recovery access.

## Optional server-side listener check (on Fedora Navidrome host)

The October Podman configuration exposed port 4533 on **127.0.0.1 only**.
Verify the live listener before concluding this is a phone routing issue:

```bash
sudo podman port moka-navidrome
curl -v --connect-timeout 5 -o /dev/null http://127.0.0.1:4533/app/
curl -v --connect-timeout 5 -o /dev/null http://10.0.0.169:4533/app/
```

An HTTP response (including an error response) establishes a TCP/HTTP
connection. `Connection refused` or a timeout points earlier in the path.
Do not rebind or expose Navidrome publicly as part of this test.

## Interpretation

- **UID-0 route MATCH + app TCP CONNECTED**: basic app-side socket reaches
  the service; HTTP/browser-specific behavior still needs testing. This
  does **not** prove the app socket traveled through WireGuard.
- **UID-0 route MATCH + app TCP REFUSED**: an accepting listener, firewall
  rejection or server binding may be at fault. Check the Fedora listener.
- **UID-0 route MATCH + app TCP TIMEOUT/FAILED**: ambiguous; capture server
  listener status and device routing before proposing kernel changes.
- **Shared marks**: tunnel concurrency may still work, but an enforcement
  design may not treat shared marks as unique safe exceptions.

Neither a successful root lookup nor a TCP handshake is a packet capture,
DNS leak test, app-fwmark trace, or fail-closed/killswitch validation.
