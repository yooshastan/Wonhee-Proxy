# Alpha 0.9.12.1 — Restart button safe-area regression

On a Pixel 8a running Android 16:

1. Open Wonhee Root Control Center > Connect.
2. Scroll to the bottom. **Restart managed pair** must be fully visible and
   tappable above the system's bottom navigation bar.
3. Confirm the red **Emergency Disconnect** control remains reachable; it must
   never be obscured by the 3-button navigation bar.
4. Repeat with Android gesture navigation, if available.
5. Increase Android Display size / Font size, reopen Connect, and check that
   every action can still scroll above the navigation bar.
6. Switch among Connect, Profiles, Privacy, and Logs; the last control or
   text on each page must be fully readable after scrolling to the bottom.
7. With the correct Home and Internet profiles selected and USB ADB available,
   manually restart the managed pair and confirm both interfaces and expected
   routes. Do not interpret route lookups alone as a DNS/leak audit.
8. Export a root session report. Verify the latest restart result is preserved.

The release changes view padding and button order only. WireGuard routing,
kernel interface cleanup, DNS, firewall rules, and kill-switch enforcement
are unchanged.
