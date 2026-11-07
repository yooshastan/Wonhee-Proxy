# Wonhee 0.10.1 Batch B — experimental split-route priority

Batch B addresses the Pixel 8a / Android 16 observation where both experimental
kernel interfaces were UP, but the default AirVPN table caught `10.0.0.169`
before the separate Home lookup table was consulted. Batch A's independent
kernel interface creation and the original Home + AirVPN controls are retained.

**Important:** This is an opt-in routing experiment, not a privacy guarantee.
There is **no kill switch**, DNS leak protection, automatic fail-closed policy,
VPN lockdown or per-app routing assurance. A UID-0 route lookup does not prove
what a particular Android app does. Keep a working USB ADB recovery connection.

## Expected topology

| Profile | Example device | Intended IPv4 routes |
| --- | --- | --- |
| `wgs_client1` | `wnma292ddb4b6da` | `10.0.0.0/24`, `10.6.0.0/24`, `10.77.0.0/24` |
| `AirVPNEurope` | `wnm68fe81200daa` | `0.0.0.0/0` (and `::/0` IPv6) |

The interface names derive from profile names; use the names printed by your
installed build. No fixed pairing is hard-coded in the priority planner.

Android rules with priority 13000 previously selected the AirVPN default before
Home split routes. The original Batch B selector (`fwmark 0x0/0x2ffff`) was
too narrow: it excluded locally generated sockets carrying Android network-ID
marks, so UID-0 route lookups could pass while browser and Moka traffic still
went through AirVPN.

**Product Batch B.1 / 0.15.12** changes the destination-specific priority
12500+ rules to `fwmark 0x0/0x20000`, `iif lo`, UID 0-99999. Android's
protectedFromVpn flag is bit 17 (`0x20000`): the selector therefore matches
locally generated traffic that is not protected from VPN, regardless of its
network ID, while preserving sockets explicitly protected with
`VpnService.protect()`. Public destinations do not match the Home prefixes
and continue to use AirVPN's default route. Existing Android/netd rules are
not modified.

The 0.15.12 audit also simulates routes for representative unprotected marks
read from the live IPv4/IPv6 policy rules, using app UID 10000. These are
policy simulations, not proof of actual app socket behavior; Moka, Chrome,
Brave and real packet paths still require device testing.

## Test A — baseline and safe preflight (no policy writes)

1. Install the current Batch B debug APK as an update; recovery-safety test
   version `0.10.2-batchB-recovery-safety` adds guarded orphan-rule handling.
2. Verify the original Home + AirVPN controls still open. Stop their tunnels
   before entering the experimental Multi-Tunnel Lab.
3. Select `wgs_client1` and `AirVPNEurope`, preview routes and confirm no conflict.
4. Connect both in Multi-Tunnel Lab. Read live kernel status: both must be UP
   and identity MATCH. An UP interface alone is **not** proof of correct routing.
5. Tap **Audit effective routes · read only**. Before enabling correction, the
   Home destination may show MISMATCH and the public default may show MATCH.
6. Capture this ADB baseline (read-only):

   ```sh
   adb shell su -c 'ip -4 rule show'
   adb shell su -c 'ip -4 route get 10.0.0.169'
   adb shell su -c 'ip -4 route get 1.1.1.1'
   adb shell su -c 'ip -6 route get 2606:4700:4700::1111'
   ```

7. If another app owns priority 12500-12799, applying Wonhee rules **must refuse**.
   If any selected tunnel is absent or identity-mismatched, a numeric endpoint
   overlaps a HOME split prefix, or its marked endpoint route does not use a
   recognized physical underlay, applying **must refuse**.

## Test B — explicitly apply and verify

1. With the selected verified tunnels UP, tap **Apply split-route correction ·
   experimental** and read the confirmation. Do not proceed if USB ADB recovery
   is unavailable.
2. Expect a report of three owned IPv4 rules (for the Home /24 routes), with
   successful root route verification. Check with the **read-only audit**.
3. Repeat the four ADB route and rule commands above. Expected root routes:
   - `10.0.0.169` → Home `wnm...` interface.
   - `1.1.1.1` → AirVPN `wnm...` interface.
   - Public IPv6 → AirVPN, if its `::/0` is configured and reachable.
4. Test actual Home-service TCP access and Internet access separately. Test a
   browser and another app separately. If a root lookup succeeds but app traffic
   fails, **report a routing failure**; the UI root audit is not an app audit.
5. Force-stop and reopen Wonhee. The app must not adopt unmanaged WireGuard
   interfaces, but **Remove Wonhee routing overrides** must remain available
   without reselecting profiles, using its persistent ledger.
6. Try to disconnect while the owned-rule ledger is active: Wonhee must refuse
   and tell you to remove the overrides first.

## Test C — reversible cleanup

1. Tap **Remove Wonhee routing overrides**. This requires no selected profile.
2. The matching priority-12500+ rules must disappear. Priority-13000 Android
   rules and unrelated rules must remain untouched.
3. Re-run read-only ADB route checks and verify the device returns to its prior
   selection behavior. Then disconnect the experimental tunnels normally.
4. Repeat Test A with the original fixed Home + AirVPN controller and confirm
   it still connects/disconnects as before.

## Failure and recovery rules

- Wonhee persists an exact rule ledger *before* the first kernel policy write.
  A failed apply attempts to remove only the rules that still exactly match
  that ledger. If any priority is occupied by a different rule, it refuses
  deletion and retains the ledger for investigation.
- If the app reports **ROUTING ROLLBACK INCOMPLETE**, stop testing, keep the USB
  connection, capture `ip -4 rule show`, `ip -6 rule show`, and the session
  report. Do not blindly flush policy tables, wipe Android rules, or delete
  other VPN interfaces.
- If network connectivity is disrupted, use the local app's Remove action or
  verified ADB access. Avoid full-network resets before recording the evidence.
- No crash/reboot persistence of routes is promised: the ledger persists, but
  kernel routes may disappear after restart. Cleanup treats absent owned rules
  as already removed; it refuses to delete a rule with unexpected contents.

## Batch B recovery-safety regression (0.10.2)

The Pixel 8a recorded a 3/3 Home route audit and working Navidrome, while
its routing ledger claimed **EMPTY**. A separate ADB read-only inspection
confirmed priorities 12500, 12501 and 12502 were still installed, and both
selected experimental interfaces showed UP / public-identity MATCH. No
automatic cause of the missing ledger has been established.

1. **Before upgrading:** do not stop experimental tunnels while rules may be
   orphaned. Have USB ADB available and export your encrypted profiles safely.
2. After installing 0.10.2, select the matching Home and Internet profiles.
   Use **Audit effective routes**. It should print the count of live rules
   in reserved priority 12500–12799 and explicitly warn if the ledger is empty.
3. Tap **Verify + recover matching routing rules** only after inspecting the
   confirmation. Wonhee must independently match the selected live WireGuard
   interface public identities and **all** reserved kernel rules against the
   deterministic selected-profile plan. It must refuse any mismatch or extra
   rule without touching any interface, route or firewall.
4. If recovery succeeds, a second read-only audit must show a **three-rule
   rollback ledger**. The current routes must remain active, including
   Navidrome Home and AirVPN Internet. Recovery itself changes **no** kernel
   configuration.
5. Use **Remove Wonhee routing overrides**. This must remove the three exact
   matching rules, verify that none remains, and clear the ledger. Read-only
   audit should then show zero reserved rules. Only now use **Disconnect
   selected tunnels**.
6. When a ledger is empty but reserved policy rules remain, normal Remove must
   **refuse** instead of falsely reporting "0 removed"; experimental Connect
   and Disconnect must refuse until the orphan state is resolved.
7. Revisit the UI: long buttons should expand vertically instead of truncating
   their text, and route previews must not assert that rules are uninstalled
   merely because they are displaying a plan.

## Gate to subsequent privacy batch

Successful split/home/root routes, public IPv4/IPv6 routes, preserved Android
network controls, restart cleanup, original-pair regression, and documented
app-level connectivity results. DNS leak tests, kill-switch enforcement,
tracker blocking and fail-closed verification **remain future milestones**.

## Product Batch B.1 — Android mark-aware split routing (0.15.12)

This correction is based on the Pixel 8a evidence collected after 0.15.11:
the five tested marks `0x1009d`, `0xc489e`, `0xce8a6`, `0x1489e` and
`0x1e8a6` all selected AirVPN for both `10.0.0.169` and `1.1.1.1`.
The earlier `0x0/0x2ffff` split selector excluded those marks. Android's
priority-13000 AirVPN rule then found its default route and won before the
Home rule.

### Upgrade and migration

1. Keep HOME and AirVPN connected and USB ADB available.
2. Install 0.15.12 as an update. The new rollback decoder accepts both the
   old five-field ledger format and the new selector-aware ledger format.
3. If the existing ledger contains the three 0.15.11 rules, use
   **Remove Wonhee routing overrides** first. The decoder must issue the
   exact old `fwmark 0x0/0x2ffff` delete commands and clear the ledger.
4. Confirm the three Wonhee-owned priority rules are gone and Android's
   priority-13000 rules remain unchanged.
5. If the ledger is empty but the three old rules are orphaned, use
   **Verify + recover matching routing rules**. Recovery may adopt the legacy
   selector only if every reserved rule, destination, table, priority, flag,
   selected profile and WireGuard public identity matches exactly. It must
   refuse partial or unknown ownership.
6. Remove the recovered legacy rules before applying the new selector.

### Apply and verify the corrected selector

1. With both tunnels UP and identities verified, run the read-only audit.
   Before applying the new correction, mark-aware probes should expose the
   mismatch even if the UID-0 root route still says 3/3.
2. Apply **Apply split-route correction · experimental**. It must install
   three exact rules using `fwmark 0x0/0x20000`, at priorities 12500–12502.
3. Confirm the new audit reports:
   - HOME private routes match for all discovered unprotected Android marks.
   - Public IPv4 and configured IPv6 remain on AirVPN for those marks.
   - A synthetic protectedFromVpn mark (`0x20000`) is not captured by HOME.
   - The rollback ledger exactly matches the three live rules.
4. Inspect the live rules:

   ```sh
   adb shell ip -4 rule show
   ```

   The three Wonhee rules must show `fwmark 0x0/0x20000`; do not edit
   Android's priority-13000 rules.

5. Run actual application lookups from Fedora. This loop runs on the host,
   not inside APatch's shell:

   ```sh
   for uid in 10300 10283 10308; do
     for mark in 0x1009d 0xc489e 0xce8a6 0x1489e 0x1e8a6; do
       echo "UID=$uid MARK=$mark HOME"
       adb shell su -c "ip -4 route get 10.0.0.169 uid $uid mark $mark"
       echo "UID=$uid MARK=$mark PUBLIC"
       adb shell su -c "ip -4 route get 1.1.1.1 uid $uid mark $mark"
     done
   done
   ```

   Expected: every HOME lookup uses the HOME interface; every public lookup
   uses AirVPN. These are simulated lookups, so also test the actual browser
   and Moka application connections.

6. Open Navidrome by its private address in Chrome or Brave and stream a
   track from Moka. Confirm AirVPN public IPv4/IPv6 exit behavior separately.
7. Run the read-only audit again after force-stopping/reopening Wonhee.
8. Test **Remove Wonhee routing overrides**. It must remove only the three
   exact new rules, preserve Android rules, and clear the ledger.

### Additional safety requirements

- The numeric WireGuard UDP endpoints must remain outside the HOME split
  prefixes and route through a recognized physical underlay before the
  correction can be applied or Batch F can be armed.
- Protected-from-VPN sockets must not be captured by the new HOME selector.
- Any unrecognized priority 12500–12799 rule, unexpected endpoint route,
  missing mark probe, or mark-aware mismatch must fail closed.
- Batch F remains OFF until marked-route simulations, actual application
  traffic, endpoint underlay, rollback and the independent firewall tests pass.
