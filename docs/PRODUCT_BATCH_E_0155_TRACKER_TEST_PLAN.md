# Product Batch E 0.15.5 — local tracker-domain blocking (alpha)

The product roadmap is **A → B → C → D → E → F → G → H → I**. This Product E
is *DNS tracker blocking*, not the historical diagnostic labeled "Batch E"
that measured narrowly scoped packet headers in 0.13.0. F remains the
all-traffic kill-switch prototype, G background automation, H UI integration,
and I beta validation. Moka multi-tunnel compatibility is on the post-I list.

## Scope

- Disabled by default. A user chooses the tracker option **before** explicit
  Batch D encrypted DNS activation. The selected verified WireGuard interface,
  DoH/DoQ/DoH3 transport, numeric bootstrap, TLS verification and no-fallback
  protections from Batch D remain unchanged.
- Nine conservative built-in suffixes are displayed in a read-only preview.
  The user can add up to 128 custom block suffixes and 128 allowlist suffixes.
  An allowlisted domain overrides broader blocking, including its subdomains.
- Domain matching is exact or dot-boundary suffix matching. Wildcards, URLs,
  IP literals, untrusted local suffixes and malformed entries are refused.
- The root relay reads a private local policy file exactly once at startup.
  Matching DNS questions return locally constructed NXDOMAIN. Non-matching
  questions still require the selected encrypted upstream, never direct or
  plaintext fallback. No remote list downloads, logging of user DNS names,
  history, analytics or packet captures are introduced.
- The DNS ownership ledger stores whether tracker blocking was enabled. The
  read-only audit checks exact owned firewall rules, relay identity and a
  blocked-domain DNS response for enabled filtering. Disable continues to
  remove only the app's exactly tagged rules and verified relay process.
- **No DNS blocker guarantees tracker freedom.** Apps may connect directly to
  hardcoded IPs, use their own DoH/DoH3 over HTTPS 443 or use APIs without
  DNS lookups. A bad domain block can break apps; the allowlist is the recovery
  control. Android Private DNS must remain OFF during this opt-in test.

## Safe device test

1. Use USB ADB on a test device. Confirm Product D rollback is complete,
   with no Wonhee-owned DNS firewall rules and ledger OFF. Verify the two
   selected kernel WireGuard interfaces and split routing first. Temporarily
   disable Product C background tunnel recovery and manually set Android
   Private DNS OFF, as required by the Product D preflight.
2. In Advanced security controls, find **Product Batch E · Local tracker
   blocking** and check **Block known tracker domains**. Leave custom lists
   empty for the first test. Press **Preview tracker filtering**. Confirm the
   list is only nine suffixes and the firewall remains unchanged.
3. Choose the verified AirVPN DoQ configuration and enable Product D encrypted
   system DNS with the explicit confirmation. The result must say
   `Batch E local tracker filtering: ON · local block response VERIFIED`.
4. Run **Audit live DNS firewall + relay**. It should report exact rules
   MATCH, relay ALIVE and `Batch E tracker filter: LOCAL BLOCK VERIFIED`.
5. From Termux, compare a blocked and nonblocked lookup while interception is
   ON. The blocked hostname should respond NXDOMAIN, while `example.com`
   should still produce A records through the encrypted relay.
6. Press **Disable owned DNS rules** before changing profiles. Repeat the
   read-only firewall listing and confirm *zero* matching Wonhee tags, ledger
   OFF, and normal DNS after removal. Restore Android Private DNS if desired.
7. Optional second run: enter `app-measurement.com` on the allowlist, then
   preview/re-enable the relay. That name should no longer be locally
   rejected; its actual answer depends on the upstream provider. Disable and
   verify rollback again before exiting.

## Phone / Termux commands

```sh
dig +time=5 +tries=1 @1.1.1.1 app-measurement.com A
dig +time=5 +tries=1 @1.1.1.1 example.com A
su -c 'iptables -t nat -L OUTPUT -n -v' | grep 'dpt:53'
su -c 'iptables -t nat -S OUTPUT; iptables -S OUTPUT; ip6tables -S OUTPUT' | grep -E 'WN_DNS|WN_DOT|WN_DOQ'
```

The `dig` server label `1.1.1.1` is the requested destination, **not proof of
the actual upstream** when the NAT rule intercepts port 53. A blocked-domain
NXDOMAIN and NAT counters should be correlated with the app's root-bound
encrypted relay audit. Use `pkg install dnsutils` if `dig` is unavailable.

## Computer / ADB commands

```sh
adb devices -l
adb shell su -c 'ip -4 route get 1.1.1.1'
adb shell su -c 'iptables -t nat -L OUTPUT -n -v' | grep 'dpt:53'
adb shell su -c 'iptables -t nat -S OUTPUT; iptables -S OUTPUT; ip6tables -S OUTPUT' | grep -E 'WN_DNS|WN_DOT|WN_DOQ'
adb shell settings get global private_dns_mode
```

The last firewall command should be empty **only after** the app's exact
Disable control succeeds. Never flush iptables or bring down the selected
tunnels while an owned DNS policy remains. If the app refuses to remove rules,
preserve the ledger and raw listings for investigation through USB ADB.

## Release gate

CI Go/Java tests and debug APK build validate code, not real-device DNS
enforcement. Product E is ready for its device checkpoint only after local
blocking, allowlist override, encrypted upstream continuity, clean rollback
and normal app compatibility are verified. Product D's unsolved reboot,
IPv6/public leak-freedom and application-owned DoH limitations are not
retroactively considered solved by Product E.
