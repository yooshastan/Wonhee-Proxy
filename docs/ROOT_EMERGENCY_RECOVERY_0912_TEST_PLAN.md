# Wonhee Alpha 0.9.12.0 — Emergency recovery test plan

This increment adds a **verified Emergency Disconnect** control and read-only
kernel presence inspection on reopening Root Control Center. It does **not**
install a kernel kill switch, grant Always-on VPN protection, or prove DNS/IPv6
leak isolation. Failures may expose the normal Wi-Fi/cellular IP.

## Before testing

- Save/export the current session report and back up imported encrypted profiles.
- Test with USB ADB available and verify you can obtain root via Magisk.
- Keep actual Home/ASUS and AirVPN Europe profiles selected. Never use an unknown
  interface named wnhome0 or wnair0 for these tests.
- For privacy-sensitive tests, enable Airplane mode before stopping a tunnel.
- Do not modify Android policy rules or iptables manually.

## Test A: normal managed emergency disconnect

1. Open Connect and start the selected Home + Internet pair; verify both routes.
2. Tap the red **EMERGENCY DISCONNECT · verify first** button. Read the warning.
3. Cancel once and check that both interfaces remain untouched.
4. Tap again and confirm. The result must report both interfaces stopped, and
   then independently show each current kernel interface state.
5. Confirm with USB ADB:
   `adb shell su -c 'ip -d link show type wireguard'`
6. Verify default routes are no longer directed to wnair0. This is **not** a leak test.
7. Export the session report; confirm the emergency action and result are logged.

## Test B: orphaned tunnels after app restart

1. Start both WireGuard interfaces.
2. Force-stop the app (do not modify the interfaces using ADB).
3. Reopen Root Control Center; it should inspect the kernel links read-only and
   display their actual state without adopting/restarting them.
4. With the correct two saved profiles selected, use Emergency Disconnect.
   The app must verify both present kernel public identities and stop only matching links.
5. Confirm the interfaces are gone and root session history includes the result.

## Test C: identity / busy safety

- If either saved profile is wrong, orphan recovery must refuse without touching
  unknown interfaces. Restore the correct selection and retry.
- If root is busy, Emergency Disconnect must stay visible and report that the
  operation must complete before retrying. USB ADB remains the manual fallback.
- If one interface is missing but the other matches its saved profile, only the
  known matching interface should be stopped.
- If either teardown fails, report **NOT CONFIRMED** and display the read-only
  kernel-state inspection. Do not claim a successful emergency stop.

## Regressions

- Start, restart and disconnect the normal managed pair.
- Check Home split IPv4 route and public IPv4/IPv6 Internet route decisions.
- Export and print root session reports without exposing private WireGuard keys.
- Do not enable any new iptables rules, private DNS enforcement, or reboot cleanup.

## Limitations

- "Emergency" refers to a user-confirmed, identity-checked disconnect. It is not
  a preemptive, immediate cancellation of an already-running root command.
- If the current root operation hangs or identity checks fail, use **USB ADB** for
  manual interface deletion as previously documented. Do not delete unrelated wg0.
- Android-managed routing references may persist after kernel link deletion.
  Inspect read-only state and, if needed, reboot instead of flushing generic rules.
