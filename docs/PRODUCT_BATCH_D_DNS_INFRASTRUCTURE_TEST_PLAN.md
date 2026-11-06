# Product Batch D — DNS infrastructure (0.15.1 stage-2 root transport preview)

**Schedule identity:** Product **D** in the fixed [Product A–I roadmap](https://github.com/yooshastan/Wonhee-Proxy/blob/main/docs/PRODUCT_BATCH_ROADMAP_A_I.md). Do not confuse this product milestone with the earlier *diagnostic* Batch D read-only UDP/Private-DNS audit.

**Status:** **IN PROGRESS**, pending CI and rooted-device testing. Product Batch C connection recovery was user-reported passing on Pixel 8a on 2026-11-06 (handoff, process restart, reboot, manual stop). Product D does **not** automatically inherit a pass from earlier read-only DNS route inspections. The stage-1 Android-bound probe safely refused on the Pixel because Android's `ConnectivityManager` tracked Wi-Fi/cellular/IMS but did not expose the `wnm*` kernel interfaces as bindable Networks.

## Stage 2: independently opted-in root-bound DoH probe

- A separate **Test ROOT-bound DoH** button now uses a **packaged, one-shot Android-native Go executable**, built from the checked-in `roothelper/dohprobe` source and called through Wonhee's existing root-shell session. This is *not* an Android VpnService, daemon or system DNS interceptor.
- After validating the **selected set** of UP tunnel public identities, exact owned rules and numeric bootstrap root route, it calls Linux `SO_BINDTODEVICE` on the **chosen** `wnm*` interface *before* making a TCP connection. Failure to bind refuses; no fallback to Wi-Fi, cellular, proxy, DNS or any other interface is attempted.
- The helper uses only the provided **numeric** upstream IP (no bootstrap hostname lookup) and standard TLS server-name/certificate verification for the explicitly configured HTTPS DoH hostname. It disables proxy use, connection reuse and redirects. Sends exactly one `example.com` A question and requires HTTP 200, RFC 8484 media type and a verified DNS transaction with IPv4 answers.
- A short timeout limits helper execution; it leaves no persistent service. The executable is discarded after each attempt. Java reports generic error codes without logging the DNS provider address. The provider sees the diagnostic query and tunnel exit IP when successful.
- This probe is designed for **multiple independent root tunnels** and never assumes a particular pair or profile name. It still does **not** install Android resolver policy, DNS interception, DoQ/DoH3, tracker blocking or a kill switch; it does not prove DNS leaks are impossible.
- A packaged Go executable may fail to run on a hardened device because of app-data execution/SELinux restrictions, unavailable system certificate roots or missing kernel bind privilege. Those are **device-test failures**, not permission to bypass TLS or use a default network. Keep a previously tested build installed side by side.
- This stage-2 preview packages **ARM64 only**, matching the Pixel 8a and Samsung A36 test devices. Other ABIs need Android NDK-linked binaries and separate device validation before being advertised as supported.

## Stage 1: exact-tunnel DNS-over-HTTPS probe

- Works with **any selected, identity-verified profile** in the multi-tunnel list; no hard-coded two-tunnel limit or Home/AirVPN names.
- User chooses **one** selected tunnel for this specific DNS query, a custom HTTPS DoH endpoint (`https://hostname/path`) and a numeric bootstrap IPv4/IPv6 address. Cloudflare is merely an example in the inputs; no endpoint configuration is saved.
- On explicit confirmation, rechecks every selected running tunnel's WireGuard public identity, ownership of reserved routing rules, and the root kernel route to the chosen numeric resolver IP.
- Requires Android `ConnectivityManager` to expose **exactly one** `Network` whose interface is the selected root kernel WireGuard device. Opens a socket with *that Network's* socket factory and only the numeric bootstrap address; the app never resolves the DNS provider name through Android DNS. There is **no default socket/network fallback** if this binding is absent or ambiguous. **Kernel-only links might not be exposed as Android Networks**, in which case this safe diagnostic refuses until a different explicitly audited root transport is implemented.
- Uses the platform trust store plus HTTPS hostname/SNI verification, sends a single DNS-wireformat `example.com` A query (RFC 8484 POST `application/dns-message`), validates the transaction ID, question, response code, complete A answer and maximum reply length. HTTP redirects and alternate upstreams are forbidden. No user browsing history or credentials are submitted by the probe.
- Never installs DNS/route/firewall redirection, changes Android Private DNS, intercepts applications, enables tracker filtering or switches on a kill switch. Does **not** make Moka or other apps use the probe's DNS provider.

## Pixel 8a checklist (Termux AND ADB versions)

1. **Keep the known-good state:** verify all intended WireGuard interfaces remain UP, owned routing priority-12500+ ledger matches and kill switch is OFF. Keep Termux root and USB recovery available.
2. **Baseline (read only)**

   Termux:

   ```sh
   su -c 'wg show interfaces'
   su -c 'ip -4 rule show'
   su -c 'ip -6 rule show'
   su -c 'ip -4 route get 10.0.0.169'
   su -c 'ip -4 route get 1.1.1.1'
   ```

   ADB from Fedora:

   ```sh
   adb shell su -c 'ip -o link show' | grep wnm
   adb shell su -c 'ip -4 rule show' | grep -E '^12[5-7][0-9][0-9]:'
   adb shell su -c 'ip -6 rule show' | grep -E '^12[5-7][0-9][0-9]:'
   adb shell su -c 'ip -4 route get 10.0.0.169'
   adb shell su -c 'ip -4 route get 1.1.1.1'
   ```

   If `wg` is not available on Termux's root `PATH`, interface presence can still be checked with `su -c 'ip -o link show' | grep wnm`; absence of the command alone does not mean the kernel tunnels are down.

   The two example destinations are from this *test setup*, not hard-coded in Wonhee's Product D routing.
3. **Explicit root DNS test:** check the profiles that are actually UP, use **Product Batch D**, select the profile whose route reaches the numeric bootstrap IP, and tap **Test ROOT-bound DoH**. Keep defaults `https://cloudflare-dns.com/dns-query` and `1.1.1.1` only for the AirVPN test setup (otherwise enter a custom validated endpoint + its correct numeric address). Confirm that only `example.com` is sent.
4. **Outcomes:** `COMPLETE` means one TLS-authenticated DoH answer was obtained from the selected kernel-bound interface. `CHECK REQUIRED` may mean the root helper binary cannot execute, lacks `SO_BINDTODEVICE` permission, TLS trust failed, or the route/ownership gate refused. A refusal proves **no reported success**, not that global DNS is protected. The old **ANDROID-bound DoH** button remains an informational baseline, known to refuse when the root interface is not registered with `ConnectivityManager`.
5. **Optional scoped packet evidence:** with consent and no payload capture, start the following in another Termux session **on the chosen interface**, then tap **Test ROOT-bound DoH**. Substitute your actual interface and resolver IP; this example targets the previously observed AirVPN default and Cloudflare:

   Termux:

   ```sh
   su -c 'timeout 20 tcpdump -nn -q -s 80 -l -c 24 -i wnm68fe81200daa "tcp and host 1.1.1.1 and port 443" 2>&1'
   ```

   ADB from Fedora:

   ```sh
   adb shell su -c 'timeout 20 tcpdump -nn -q -s 80 -l -c 24 -i wnm68fe81200daa "tcp and host 1.1.1.1 and port 443" 2>&1'
   ```

   Compare with the other selected tunnel and do not use this alone as proof of leak-free DNS. A certificate-verified app result and scoped packet evidence together are stronger, but the kernel capture still does not prove other apps use DoH.
6. **Negative checks (no device mutation):** enter an HTTP URL, malformed IP, userinfo, and an upstream IP whose route selects another interface. Each must refuse, never retry directly or perform plaintext DNS. A wrong TLS endpoint/certificate must also fail. Do **not** simulate missing tunnel links on a daily-driver device just for this test.
7. **Regression:** repeat Product C connection recovery checks; audit Home split routes, public IPv4/IPv6 default routes, DNS configured-root routes and rollback ledger. No DNS settings, firewall rules or tunnel profiles should have changed.

## Batch D work still required before calling it complete

1. Device-validate the packaged **root-only DoH transport**, including `SO_BINDTODEVICE`, TLS trust on GrapheneOS, exact interface packet evidence, native ABI and SELinux execution. Fix failures without any direct fallback.
2. Integrate configurable DNS resolver selection into authorized app and/or device DNS requests, with scoped rules and exact rollback. A standalone test query is **not** a DNS service.
3. Add DoQ and DoH3 only with authenticated transport, explicit opt-in, and documented provider compatibility. Preserve strict no-direct/no-plaintext fallback.
4. Run Android resolver, app-UID, dual-stack IPv6, tunnel-down, handoff/reboot, DNS-cache, certificate-failure and leak tests before enabling any system-wide mode.
5. Preserve the Batch A–I sequence: Product E tracker blocking, F kill-switch prototype, G background automation, H integration/UI, I beta validation. The separately requested Moka multi-tunnel compatibility regression stays on the **post-I** backlog.

Do not publish this stage-1 build as a privacy-secure DNS replacement or a public beta merely because CI passes.
