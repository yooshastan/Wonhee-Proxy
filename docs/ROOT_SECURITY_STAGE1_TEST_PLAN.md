# Root multi-tunnel security stage 1 — device test plan

This is a **capability/management build**, not a privacy-safe release. The
two-interface kernel engine remains unchanged. No root firewall kill switch is
installed, and no third kernel tunnel is activated by this stage.

## Baseline

- Keep the last successful dual-tunnel APK and its configuration available.
- Back up the server-side ASUS and AirVPN configuration outside this app.
- Use cellular data for all tests; disable Wi-Fi.
- Confirm Home and Internet tunnel public keys and interface names remain those
  expected. Never share private keys or full `.conf` files.

## Profile management

1. Import a fresh `.conf` as Home, choose custom split routes, and select an
   imported or valid in-tunnel DNS choice. Confirm it saves and loads correctly.
2. Import a fresh Internet-exit `.conf`, choose IPv4 + IPv6 defaults and an
   explicit DNS choice. Confirm no private key appears in error messages.
3. Select an older saved profile, change its role in the regular VPN screen,
   save, leave and reopen. Confirm the root lab uses the saved role.
4. Verify that the two selected profiles still establish independent kernel
   interfaces and that Home and AirVPN route tests still pass.

## DNS audit

1. Run **Check Internet DNS Routes** in the root lab; record the number of
   configured resolver addresses and those routed through `wnair0`.
2. Independently test browser and non-browser DNS on cellular; check IPv4,
   IPv6, DNS, Private DNS, and DoH paths. The read-only check is not a leak test.
3. Repeat after Wi-Fi/cellular switching, app restart, and AirVPN outage.

## Firewall preflight — NO kill switch yet

1. Run **Check Firewall Capabilities** and record whether IPv4 iptables,
   IPv6 ip6tables, nft, and policy routing queries work.
2. Record Android IP rules (`ip -4 rule`, `ip -6 rule`) and underlying network
   mark behavior before designing endpoint exceptions.
3. Future fail-closed implementation must block both IP families if the VPN is
   absent, preserve WireGuard encrypted transport, and allow only an explicit
   Home route exception. Verify app process death, stale interfaces, network
   switch, root shell failure, reboot, and disabled/invalid DNS.
4. A green handshake, successful IPLeak browser test or firewall tool presence
   is **not** a kill-switch guarantee. Do not mark 1.0 ready until tests prove
   the actual failure behavior.

## Concurrent profile expansion

- Up to eight encrypted profiles may be saved and assigned roles.
- This stage intentionally keeps **two active kernel interfaces**. Additional
  concurrent split tunnels need explicit route overlap checks, Android netd
  policy priorities, per-interface ownership and lifecycle recovery, and
  rollback tests before activation.
