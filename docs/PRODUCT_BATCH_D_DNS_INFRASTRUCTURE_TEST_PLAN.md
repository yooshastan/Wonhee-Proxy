# Product Batch D — DNS infrastructure (0.15.0 stage-1 preview)

**Schedule identity:** Product **D** in the fixed [Product A–I roadmap](https://github.com/yooshastan/Wonhee-Proxy/blob/main/docs/PRODUCT_BATCH_ROADMAP_A_I.md). Do not confuse this product milestone with the earlier *diagnostic* Batch D read-only UDP/Private-DNS audit.

**Status:** **IN PROGRESS**, pending CI and rooted-device testing. Product Batch C connection recovery was user-reported passing on Pixel 8a on 2026-11-06 (handoff, process restart, reboot, manual stop). Product D does **not** automatically inherit a pass from earlier read-only DNS route inspections.

## Stage 1: exact-tunnel DNS-over-HTTPS probe

- Works with **any selected, identity-verified profile** in the multi-tunnel list; no hard-coded two-tunnel limit or Home/AirVPN names.
- User chooses **one** selected tunnel for this specific DNS query, a custom HTTPS DoH endpoint (`https://hostname/path`) and a numeric bootstrap IPv4/IPv6 address. Cloudflare is merely an example in the inputs; no endpoint configuration is saved.
- On explicit confirmation, rechecks every selected running tunnel's WireGuard public identity, ownership of reserved routing rules, and the root kernel route to the chosen numeric resolver IP.
- Requires Android `ConnectivityManager` to expose **exactly one** `Network` whose interface is the selected root kernel WireGuard device. Opens a socket with *that Network's* socket factory and only the numeric bootstrap address; the app never resolves the DNS provider name through Android DNS. There is **no default socket/network fallback** if this binding is absent or ambiguous. **Kernel-only links might not be exposed as Android Networks**, in which case this safe diagnostic refuses until a different explicitly audited root transport is implemented.
- Uses the platform trust store plus HTTPS hostname/SNI verification, sends a single DNS-wireformat `example.com` A query (RFC 8484 POST `application/dns-message`), validates the transaction ID, question, response code, complete A answer and maximum reply length. HTTP redirects and alternate upstreams are forbidden. No user browsing history or credentials are submitted by the probe.
- Never installs DNS/route/firewall redirection, changes Android Private DNS, intercepts applications, enables tracker filtering or switches on a kill switch. Does **not** make Moka or other apps use the probe's DNS provider.

## Pixel 8a checklist (Termux preferred)

1. **Keep the known-good state:** verify all intended WireGuard interfaces remain UP, owned routing priority-12500+ ledger matches and kill switch is OFF. Keep Termux root and USB recovery available.
2. **Baseline with Termux (read only):**

   ```sh
   su -c 'wg show interfaces'
   su -c 'ip -4 rule show'
   su -c 'ip -6 rule show'
   su -c 'ip -4 route get 10.0.0.169'
   su -c 'ip -4 route get 1.1.1.1'
   ```

   The two example destinations are from this *test setup*, not hard-coded in Wonhee's Product D routing.
3. **Explicit DNS test:** check every running profile you want in the experiment, use the new **Product Batch D** card, select the specific profile whose root route reaches your numeric bootstrap IP, and tap **Test selected-tunnel DoH**. Confirm that only `example.com` is sent to the selected resolver.
4. **Outcomes:** `COMPLETE` means one TLS-authenticated DoH answer was returned on the exact bound Android network. `CHECK REQUIRED` with `No verified ... Android Network binding` means the root-only link is not bindable in this design; this is an expected fail-closed outcome on some rooted phones and **not** proof of leaked DNS. Do not enable direct fallback to make it green.
5. **Optional scoped packet evidence:** with consent and no payload capture, start the following in another Termux session **on the chosen interface**, then tap the DoH button. Substitute your actual interface and resolver IP; this example targets the previously observed AirVPN default and Cloudflare:

   ```sh
   su -c 'timeout 20 tcpdump -nn -q -s 80 -l -c 24 -i wnm68fe81200daa "tcp and host 1.1.1.1 and port 443" 2>&1'
   ```

   Compare with the other selected tunnel and do not use this alone as proof of leak-free DNS. A certificate-verified app result and scoped packet evidence together are stronger, but the kernel capture still does not prove other apps use DoH.
6. **Negative checks (no device mutation):** enter an HTTP URL, malformed IP, userinfo, and an upstream IP whose route selects another interface. Each must refuse, never retry directly or perform plaintext DNS. A wrong TLS endpoint/certificate must also fail.
7. **Regression:** repeat Product C connection recovery checks; audit Home split routes, public IPv4/IPv6 default routes, DNS configured-root routes and rollback ledger. No DNS settings, firewall rules or tunnel profiles should have changed.

## Batch D work still required before calling it complete

1. Add a **real DNS transport for root-only interfaces** without silently falling back to Android's default network; test DoH over Home split and public-default routes with actual packet evidence.
2. Integrate configurable DNS resolver selection into authorized app and/or device DNS requests, with scoped rules and exact rollback. A standalone test query is **not** a DNS service.
3. Add DoQ and DoH3 only with authenticated transport, explicit opt-in, and documented provider compatibility. Preserve strict no-direct/no-plaintext fallback.
4. Run Android resolver, app-UID, dual-stack IPv6, tunnel-down, handoff/reboot, DNS-cache, certificate-failure and leak tests before enabling any system-wide mode.
5. Preserve the Batch A–I sequence: Product E tracker blocking, F kill-switch prototype, G background automation, H integration/UI, I beta validation. The separately requested Moka multi-tunnel compatibility regression stays on the **post-I** backlog.

Do not publish this stage-1 build as a privacy-secure DNS replacement or a public beta merely because CI passes.
