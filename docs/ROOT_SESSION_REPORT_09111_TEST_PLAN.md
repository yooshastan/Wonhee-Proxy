# Alpha 0.9.11.1: Root session report regression tests

This is an **export and diagnostics** update. It does not enable the kernel kill switch, add firewall
rules, change WireGuard routing, or prove Android DNS/privacy leak protection.

## Session report UI

1. Open Root Control Center > Logs; note the `Session XXXXXXXX` identifier and event count.
2. Go to Connect, tap **Read live status**, then visit Privacy and run a read-only route audit.
3. Return to Logs: event count should have increased, and the last diagnostic should be intact.
4. Tap **Save session report (.txt)**; select a file location in Android's document picker.
   Inspect the exported UTF-8 text: it must contain the session identifier, timestamps,
   selected profile labels, action/result sequence, last viewed kernel status and last diagnostic.
5. Tap **Print / Save session as PDF**; verify Android's Print dialog opens and the text renders
   over multiple pages if necessary. If available, select **Save as PDF** and inspect the file.
6. Force-stop and reopen Wonhee; check that the session identifier and prior events remain.
7. Tap **Start a new log session** and cancel: history should not change. Confirm: a new
   identifier and short history should appear, without changing profiles or tunnel state.
8. Verify the exported report does **not** include WireGuard private/preshared keys or tokens.
   It can include private IP addresses, endpoints, and profile names, so review before sharing.

## Existing connection regression (do not skip)

- Select the existing ASUS Home split profile and AirVPN Europe Internet profile.
- Connect and verify both interfaces and public IPv4/IPv6 egress. Do not assume a route lookup
  alone proves app DNS, leak isolation, or privacy.
- Disconnect, reconnect, and manually restart the managed pair; repeat reachability checks.
- Verify Navidrome through the Home route, e.g. `http://10.0.0.169:4533/app/`.
- Disconnect both when testing is complete. Root kernel interfaces may survive process death.

## Expected limitations

- Up to 160 recent timestamped entries are stored in a private, local SharedPreferences journal.
- Starting a new session discards the older **in-app** event list; save a report first.
- Live interface status is sampled into the report from the last visible reading, not an
  independently timestamped packet capture.
- This build still has **no tested/active kill switch**. It may fall back to ordinary cellular
  traffic if the tunnels are stopped or a restart fails.
