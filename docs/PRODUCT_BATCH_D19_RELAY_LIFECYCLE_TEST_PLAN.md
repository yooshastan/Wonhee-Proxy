# Wonhee 0.15.19 — Batch D.19 relay lifecycle diagnostics

## Background (Pixel 8a, Android 16, 2026-11-08)

User verified two independent WireGuard root interfaces, HOME routing with priorities 12500–12502, Navidrome reachability, AirVPN IPv4/IPv6, and one-shot root-bound DoH, DoQ, DoH3. Root Go helper in app-private files executed with exit 0 and served a loopback UDP/53535 listener for eight seconds before clean timeout. App's **system DNS activation** nevertheless refused before firewall mutation, emitting generic preflight/transport text. No DNS ledger or Wonhee DNS firewall tags were found. Android ConnectivityManager-bound probe refusal for root-only WG interfaces is expected and separate.

## Scope

- New explicit **Batch D.19 · Test local DNS relay lifecycle · no firewall** control: opt-in, selected exact WG profile, the same packaged persistent Go helper, root shell process launch, exact PID identity, bounded localhost UDP/53535 listener inspection, encrypted DNS health query, exact PID-checked termination.
- Reports stage-only failure codes (POLICY_PREFLIGHT, TUNNEL_IDENTITY, UPSTREAM_ROUTE, FIREWALL_COLLISION_PREFLIGHT, RELAY_PREPARE, RELAY_LAUNCH, PROCESS_IDENTITY, LOCAL_LISTENER, LOCAL_DNS_HEALTH).
- Existing DNS activation reports its stage when refusing before changing firewall. Existing ownership ledger and exact rollback rules remain unchanged.
- The diagnostic does not install DNS/iptables rules, persist DNS ownership, modify Android Private DNS, or change root tunnel routes. It does intentionally spawn a temporary localhost-only root process and send one encrypted DNS health query.
- **Do not enable Batch F kill switch.** Existing guard activation quarantine remains.

## First device test

1. Install the new debug APK **over the existing rootlab debug package**, without uninstalling or clearing app data. Verify debug signing compatibility and avoid version downgrades.
2. With USB ADB attached, verify both selected WG profile identities UP and the HOME split routing ledger exactly matches all three live 12500–12502 rules; test Home Navidrome and public internet.
3. Confirm Batch C automatic recovery OFF, Batch F guard OFF, root DNS ownership ledger OFF, no Wonhee DNS tagged firewall rules. Set tracker filtering OFF during this baseline.
4. Under Product Batch D encrypted DNS transport, select AirVPNEurope, DoH, Cloudflare example, bootstrap 1.1.1.1. Tap **Batch D.19 · Test local DNS relay lifecycle · no firewall** once, explicitly accept the warning.
5. Capture the COMPLETE/CHECK REQUIRED result. If COMPLETED, expect launch, exact process identity, loopback readiness and encrypted local DNS health query verified, plus PID shutdown verified. The normal Android-bound probe can still fail because root WG is not an Android `Network`.
6. Recheck `/proc/net/udp` for port 53535, owned DNS ledger, and the exact firewall tags. If the diagnostic reports **RELAY SHUTDOWN NOT VERIFIED**, do not retry or enable enforcement; investigate the exact PID/port with USB ADB, and never guess a kill/iptables flush command.
7. Only after clean lifecycle PASS and independent owned DNS firewall audit, consider **system resolver enforcement** in a separate explicitly consented test with a verified rollback plan. Verify normal Android-app DNS and exact subsequent disable. Root one-shot/lifecycle PASS alone is not system-wide DNS, leak-proofing, captive portal compatibility, fail-closed reboot behavior, or Android per-app protection.

## Read-only host validation

```sh
adb shell su -c 'ip -4 rule show'
adb shell su -c 'ip -4 route get 1.1.1.1'
adb shell su -c 'ip -4 route get 10.0.0.169'
adb shell su -c 'grep -i "0100007F:D11F" /proc/net/udp || true'
adb shell su -c 'iptables -w -t nat -S OUTPUT | grep WN_DNS || true'
adb shell su -c 'iptables -w -S OUTPUT | grep WN_D || true'
adb shell su -c 'ip6tables -w -S OUTPUT | grep WN_D || true'
```

## Acceptance

CI compiles the root Go helper and Android APK; CI alone does not validate runtime PID ownership, SELinux behavior, DNS leak protection or real rollback. Acceptance requires a device result with correct stage reporting, a verified temporary helper cleanup, unchanged routing and guard state, then a separate opted-in firewall enable/disable cycle. Stop after any ambiguous cleanup or ownership mismatch.
