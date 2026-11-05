# Wonhee Proxy Alpha 0.9.11.0 — Control Center UI test plan

This build reorganizes the rooted two-kernel-tunnel UI. Its connection,
route, DNS, and read-only firewall functions are carried forward from
0.9.10.0, including the same caveats. It does **not** enable a kill switch,
automatic root recovery, local tracker filtering or system-wide DNS enforcement.

## Navigation and readability

1. From the ordinary Wonhee VPN screen, open **Open root control center · 2
   tunnels**. Confirm the screen has four tabs: **Connect**, **Profiles**,
   **Privacy**, **Logs**. Only the chosen tab's content should be displayed.
2. On Connect, check that the saved Home and Internet profile names, local
   management state, the guard-OFF warning, live readings and connect controls
   are visible without scrolling through the old diagnostics inventory.
3. Switch between all four tabs while connected. Changing tabs must not
   start, stop, reconfigure or adopt any kernel interfaces.
4. On the header, tap the most recent result. It should switch to Logs.

## Existing functional regressions

1. On Profiles, select and save the tested Home/ASUS and AirVPN Internet pair.
   Leave/reopen and confirm the same names remain selected.
2. On Profiles, inspect the Internet DNS provider, including AdGuard's
   provider-side filtering preset. Saving profile DNS still requires that
   no actively managed kernel pair is running; it must not modify keys or
   existing kernel routes.
3. On Connect, test **Read live status**, **Connect selected pair**,
   **Disconnect both tunnels**, and **Restart managed pair**. Use test traffic
   and independently inspect the expected Home and AirVPN routes.
4. Force-stop the app while the kernel pair is still running. After reopening,
   **Verify + resume existing pair** must still require identity and route
   checks before enabling management.
5. On Privacy, run the read-only DNS, public/Home route, firewall capability,
   kernel interface and guard readiness audits. The shared Android `0x20000`
   mark must **not** become a firewall exemption and no new rules may appear.
6. On Logs, check that the last completed diagnostic persists, can be copied
   separately or as a redacted support snapshot, and can be cleared.

## Important limits

- The top status line describes what the **app process manages**, not proof
  that a network path is connected or that DNS is leak-free.
- Kernel WireGuard tunnels in this lab are outside Android's native VpnService
  Always-on/lockdown enforcement. Guard protection remains OFF.
- AdGuard is a configurable upstream DNS provider for ad/tracker filtering;
  Android app DNS use and actual blocking require independent device tests.
