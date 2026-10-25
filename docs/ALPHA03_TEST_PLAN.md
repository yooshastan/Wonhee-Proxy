# Wonhee Proxy Alpha 0.3 manual test plan

Test on Pixel 8a and Samsung A36. Keep all proxy secrets and copied proxy URLs
out of screenshots, logs and GitHub issues.

## Foreground monitor

- [ ] Verify clicking Start shows the selected server and TCP port and asks
      permission for repeated connections. Cancel must send no probes.
- [ ] Start using a working public MTProxy endpoint on cellular. Expect the
      initial TCP reachability sample, then approximately 15-second spacing
      *after each prior check completes*.
- [ ] Confirm success and failure counts, recent-window counts, elapsed
      observation time and last TCP latency display correctly.
- [ ] Start monitoring an unreachable endpoint; expect timeouts or failures,
      not any "MTProto connected" claim.
- [ ] Tap Stop. Observe that no additional connection attempts are made.
- [ ] Start, then press Home or open Ultgram. Monitoring must stop when
      Wonhee leaves the foreground (no permanent service/notification).
- [ ] Rotating the phone or closing the app must not accidentally resume
      network monitoring.
- [ ] Check that profile switching while monitoring does not silently switch
      its monitored endpoint. Stop then re-start to monitor a different one.

## Redacted diagnostics

- [ ] Copy a report before the first probe; it must say zero probes.
- [ ] Copy after several successful and failed samples; counts should match.
- [ ] Ensure clipboard text contains NO configured server host, private/public
      IP, secret, username, or password.
- [ ] The report must explicitly state that it is **TCP-only** and does not
      verify MTProto/SOCKS5 authentication, DNS protection, Telegram routing,
      identity concealment, or absence of leaks.
- [ ] Verify that existing encrypted profile saving and Ultgram handoff still
      work with the new release.

## Server follow-up

The rootful Quadlet file is a **template**, not an applied migration. Verify
the persistent volume and port mapping first. Do not enable it alongside an
existing wonhee-mtproxy container that already owns port 8443.
