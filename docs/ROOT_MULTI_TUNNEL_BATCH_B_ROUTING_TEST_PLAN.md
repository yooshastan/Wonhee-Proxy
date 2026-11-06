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
Home split routes. Batch B can **explicitly** install destination-specific
priority 12500+ rules pointing to the Home table. They match **unmarked,
unbound locally generated traffic only** (`fwmark 0x0/0x2ffff`, `iif lo`,
UID 0-99999). They do not capture traffic from sockets explicitly bound to
Android network IDs. Existing Android/netd policy rules are not altered.

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
   If any selected tunnel is absent, identity-mismatched, or its transport fwmark
   can match the proposed rule, applying **must refuse**.

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
