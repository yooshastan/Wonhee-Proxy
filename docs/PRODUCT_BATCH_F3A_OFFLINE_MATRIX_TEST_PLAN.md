# Batch F.3a — Offline firewall-policy contract tests

**Status: test-only; Batch F activation remains quarantined.** Branch: `feature/batch-f3a-static-policy-matrix`, based on [F.3 RFC](PRODUCT_BATCH_F3_FAIL_CLOSED_REDESIGN_RFC.md). No changes to WireGuard configuration, routing rules, firewall installation, or APK version.

## Goal

Use the existing pure first-match `RootGuardFlowModel` to check the generated IPv4/IPv6 owned firewall plan against fail-closed expectations. This is a **simulation of a single Wonhee-owned chain**, not evidence of actual Android kernel packet delivery or socket provenance.

## Offline matrix

| Hypothetical flow | Expected verdict | Important limitation |
|---|---|---|
| HOME private Navidrome TCP over HOME | RETURN | Does not prove end-to-end reachability |
| HOME private destination through AirVPN or physical interface | REJECT | No private-address fallback in the modeled chain |
| Public HTTPS IPv4 and IPv6 through AirVPN | RETURN | Other firewall owners/netd may still block |
| Public HTTPS IPv4 and IPv6 directly over physical interface | REJECT | Does not prove no escape from another chain or API |
| Physical DNS UDP and TCP 53 | REJECT | Not a DNS leak test |
| Physical DHCPv4 and IPv6 router solicitation candidates | REJECT | Does not establish that Android sends either class through local OUTPUT |
| Exact marked WireGuard UDP endpoint tuple | RETURN | Packet attributes do not authenticate actual socket origin |
| Unmarked, wrong-port or unplanned endpoint | REJECT | Tests static plans, not real endpoint rotation |
| Exact endpoint tuple on another physical interface | RETURN | Current rule has no interface scope, so underlay change could alter egress |
| Selected endpoint plan differs from stored generated plan | DISCREPANCY | Never treat stale plan as verified |
| Two selected tunnels share Android mark `0x20000` | Activation BLOCKED | Mark is not a unique socket identity |

## Tests and invariants

`RootGuardF3PolicyMatrixTest` runs without Android, root, network access or firewall writes. It covers both `wlan0` and `rmnet16`, both endpoint address families, terminal REJECT ordering, HOME/AirVPN separation, direct IPv4/IPv6 attempts, endpoint changes, fixed UDP mark and port restrictions, and exact-plan comparison.

The matrix always reports **ACTIVATION: BLOCKED**, even if every model check passes. It explicitly flags unresolved socket provenance, shared fwmarks where present, Android underlay/control-plane attribution, independent recovery and real packet/fail-closed tests.

## Next F.3 work

- F.3b: read-only attribution of observed traffic in normal device use, minimizing collection of addresses and never capturing payloads or credentials.
- F.3c: isolated policy/provenance and endpoint-reconciliation experiments only after read-only evidence; no broad WLAN/cellular direct-access exemption.
- F.4: independent USB ADB/root recovery and a safe, controlled device-enforcement test plan.

Keep existing HOME/AirVPN routes, the 3-rule ownership ledger and **Batch F guard OFF**. Issue [#41](https://github.com/yooshastan/Wonhee-Proxy/issues/41) remains unresolved. The passed F.2 device tests do not validate a kill switch.
