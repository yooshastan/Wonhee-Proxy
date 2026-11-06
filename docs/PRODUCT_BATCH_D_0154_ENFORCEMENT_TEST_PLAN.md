# Product Batch D 0.15.4 — opt-in encrypted Android DNS-port enforcement

**Alpha, rooted devices only. Keep a working USB ADB connection available during the first test.**

The already-tested DoH, DoQ, and DoH3 probes remain read-only. The new
advanced-control card can explicitly start a localhost-only root DNS forwarder
using one selected, identity-verified WireGuard interface. It installs eight
tagged IPv4/IPv6 firewall rules **only after** a successful encrypted health
query and a durable rollback record. Its default state is OFF.

## Coverage and known limitations

- IPv4 UDP/TCP DNS port 53 is redirected to the local encrypted relay.
- IPv6 UDP/TCP DNS port 53 and native TCP port 853 (DoT) are rejected.
- Native UDP port 853 (DoQ) from non-root UIDs is rejected, while the root
  relay may use its selected DoQ upstream on that port.
- The upstream is numerical, TLS hostname-verified and strictly bound to the
  selected `wnm*` device; there is no alternative resolver or interface.
- **App-owned DoH or DoH3 on 443 or custom ports, captive portal DNS,
  Android DNS caches, firewall bypass by other root services and a full
  traffic kill switch are not controlled. Do not claim leak-freedom.**
- A stopped/crashed relay leaves installed port rules in place to fail closed,
  provided the kernel has not removed those rules. Reboot wipes volatile
  firewall rules; the durable ledger then requires inspection and explicit
  removal before reactivation. There is no boot-time fail-closed guarantee.
- Routing of ordinary apps, IPv6 public traffic, proxy bypass and full
  network lockdown require separate Product Batch F and later validation.

## On-device first-run procedure

1. Install the alpha **without uninstalling your existing app** (debug signing
   must match; never clear encrypted tunnel profiles). Connect USB ADB and
   verify `adb devices -l` reports `device`.
2. Ensure both selected WireGuard profiles are up and identity-verified.
   Run the guided safety audit and configured DNS route audit. Confirm both
   earlier DoQ/DoH3 probes still pass with AirVPN selected.
3. Manually turn Android **Private DNS → Off** for this experimental interception.
   The app refuses any other Private DNS mode; it never changes this setting.
   Also disable the older Batch C automatic recovery while testing this new
   firewall guard; the app refuses to combine those behaviors for now.
4. Open **Advanced security controls → Product Batch D — System resolver
   enforcement**, select AirVPN, the previously verified protocol and numeric
   upstream. Read the warning, opt in, and inspect the result.
5. Run **Audit live DNS firewall + relay**. Confirm exact owned rules and relay
   process. Test DNS resolution in a standard app and inspect both protocol
   and tunnel routes. A working probe alone is **not** proof of system-wide
   enforcement.
6. Before changing/disconnecting tunnels, tap **Disable owned DNS rules**.
   Run the audit again. Once it reports ledger OFF, inspect the firewall
   listing below for any unexpected retained rules.
7. Repeat with Wi-Fi/cellular handoff, upstream outage, app force-stop/reopen,
   and restart **only after a successful initial recovery test**. For any error,
   stop testing, keep ADB attached, and use the app's exact rollback control.

## Read-only checks — host ADB

```sh
adb shell su -c 'ip -4 route get 1.1.1.1'
adb shell su -c 'ip -4 route get 94.140.14.14'
adb shell su -c 'iptables -t nat -S OUTPUT | grep WN_DNS'
adb shell su -c 'iptables -S OUTPUT | grep WN_D'
adb shell su -c 'ip6tables -S OUTPUT | grep WN_D'
adb shell settings get global private_dns_mode
```

## Read-only checks — Termux on the same phone

```sh
su -c 'ip -4 route get 1.1.1.1'
su -c 'ip -4 route get 94.140.14.14'
su -c 'iptables -t nat -S OUTPUT | grep WN_DNS'
su -c 'iptables -S OUTPUT | grep WN_D'
su -c 'ip6tables -S OUTPUT | grep WN_D'
settings get global private_dns_mode
```

`settings` may require root in Termux; use `su -c 'settings get global private_dns_mode'`
if the unprivileged command is denied. Each `grep` producing no lines can be
normal when DNS enforcement is off; inspect the **ledger status** in Wonhee.

## Recovery discipline

The application stores the exact firewall-intent ledger *before* the first
iptables mutation. Its **Disable** action checks exact tagged rules, removes
only those matching the app plan in reverse order, verifies absence, stops
only the identified owned relay PID, then clears the ledger. It refuses to
silently adopt untracked rules or delete foreign rules. If cleanup refuses,
**do not disconnect the tunnels or guess an iptables flush command**. Preserve
the current output and exact table/rule listings and investigate with ADB.

Do **not** run `iptables -F`, `ip6tables -F`, or blanket rule deletion. This
would damage Android's other firewall/routing configuration. No manual deletion
commands are published until exact rules and their ownership are confirmed.

## Release acceptance

The GitHub CI success validates source builds and unit tests only. Batch D is
not closed until device results prove: (a) strict upstream and no plaintext
fallback; (b) UDP/TCP 53 redirection; (c) IPv6/DoT behavior; (d) exact rollback
when the selected tunnel goes down; (e) no untracked firewall rules; and (f)
honest reporting of unsupported application-specific DoH and reboot behavior.
