# Wonhee 0.10.0 Batch A — Opt-in multi-kernel lab

This is an **experimental alpha**, separate from the successful fixed `wnhome0`
+ `wnair0` controller. The original dual-tunnel workflow must continue to work.

## Before testing

- Keep a working USB ADB connection and an alternate way to access the Internet.
- Back up imported WireGuard configurations securely; never paste private keys in logs.
- The **kill switch is OFF**. Normal Wi-Fi/cellular, DNS and IPv6 leaks remain possible.
- Disconnect the Home + AirVPN pair before using Multi-Tunnel Lab.
- Ensure your imported profiles have usable, non-overlapping private interface
  networks and intended `AllowedIPs`; inspect the profile's routing mode.
- This iteration supports up to **eight saved encrypted profiles**, as imposed by
  the existing profile store. It does not yet implement traffic-based balancing,
  per-app routing, automatic endpoint exceptions, or background restart.

## Read-only checks (do these first)

1. Open Control Center → Profiles → **Open experimental multi-tunnel lab**.
2. Verify the original Connect/Profiles/Privacy/Logs tabs remain intact.
3. Select a split Home profile and an Internet exit. Tap **Preview selected
   routes**. Confirm the expected stable `wnm...` interface names, CIDRs and
   explanation that this is a *planning* check, not a route or leak audit.
4. Select two Internet profiles providing the same IPv4/IPv6 defaults. Preview
   **must reject** conflicting defaults without changing any interface.
5. Select two overlapping non-default private destinations. Preview **must
   reject** the conflicting routes. A split private CIDR and one Internet default
   can coexist, but actual route selection still requires device testing.
6. Tap **Read live kernel status**. Verify it identifies each saved `wnm...`
   interface as UP/DOWN and never claims ownership based on name alone.

## Mutating checks (only after read-only checks pass)

1. While the original Home + AirVPN pair is active, try to start an experimental
   selection. The lab **must refuse** to start anything.
2. Stop the original pair with its normal verified Disconnect action.
3. Select **one** split-tunnel profile, Connect, inspect its public identity,
   handshake and routes independently, then Disconnect. It must leave unrelated
   interfaces intact.
4. Select **two** compatible profiles (Home split + one Internet exit), preview
   routes, connect, inspect and disconnect. Test Navidrome and public IPv4+IPv6
   traffic separately. Do not treat successful app browsing as proof of isolation.
5. If a third compatible test server/profile is available, select three tunnels
   with disjoint split CIDRs and at most one default per IP family; repeat the
   preview, connect, status, individual selection/disconnect checks.
6. Force-close/reopen Wonhee while test interfaces are UP. The new UI must not
   silently adopt anything. Selected profile Disconnect should still verify
   both public keys before removing matching interfaces.
7. Replace a saved profile using a *different* key while the prior interface is
   UP. The new profile's attempt to disconnect must **refuse** the identity
   mismatch; restore the original saved profile before any recovery.
8. Try starting the original pair while a `wnm...` experimental link remains
   active. It must refuse to mix managers; the new link must remain untouched.

## Safety and failure expectations

- Starting a selection is sequential. If one new tunnel fails, Wonhee attempts
  verified rollback of only the links started in that operation. If identity or
  rollback is uncertain, it reports **ROLLBACK INCOMPLETE** instead of deleting
  unknown interfaces.
- A selected Disconnect checks all present selected interfaces first and never
  removes a link whose public identity does not match the saved profile.
- No `iptables`, `ip6tables`, `nft`, Android `VpnService` lockdown or fail-closed
  enforcement is installed or claimed.
- Report any unresponsive root command, unexpected traffic path, Android routing
  mismatch, interface left behind, unexpected duplicate IP, or DNS change with a
  session report. Do not share private keys, endpoint credentials or raw configs.

## Gate to next batch

- The legacy pair passes its old regression tests.
- Route conflict cases are caught in automated tests and on the Pixel 8a.
- A matching single experimental tunnel connects/disconnects successfully.
- Two compatible experimental tunnels work together, or any failure is clearly
  diagnosed and safely recoverable.
- Three-tunnel testing remains pending until a third independent server is ready.
