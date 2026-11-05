# Alpha 0.9.12.2 — Unified Disconnect regression

The previous red **Emergency Disconnect** was an identity-verified ordinary
disconnect, not a real immediate force-stop or a fail-closed privacy guard.
It is now the one **Disconnect tunnels** button in Connect.

## UI

1. Check the Connect actions appear in order: Connect, Disconnect, Restart.
2. Confirm there is no additional alarming red Emergency Disconnect button.
3. Verify the management banner does not imply that orphaned links exist solely
   because this app process is not managing a pair.
4. Verify Restart remains reachable above the Android navigation bar.

## Managed pair

1. With USB ADB available, connect the selected ASUS Home and AirVPN Europe pair.
2. Tap Disconnect, review the confirmation, then Cancel. Neither link should change.
3. Confirm Disconnect, check both expected kernel interfaces are down, and inspect
   the read-only kernel status displayed after the operation.
4. Reconnect the pair, restart it, then disconnect it again.

## Orphaned pair

1. Start both tunnels, then force-stop/reopen the app while retaining both links.
2. The app must not automatically take ownership or restart them.
3. With the correct saved profiles, Disconnect must verify the public identities
   and stop the matching pair, without needing to open Privacy or recovery tools.
4. With an incorrect profile, Disconnect must refuse and must not touch unknown
   interfaces. Restore the correct profiles before continuing.
5. Export the session history and check that the verified Disconnect result
   includes the independent interface-state inspection.

## Security boundary

This is a UI simplification. There is **no new firewall**, **no live kill switch**,
**no preemptive cancellation of hung root commands**, and no DNS/IPv6 privacy proof.
Disconnected tunnels can expose ordinary Wi-Fi/cellular egress. The existing
USB ADB recovery procedure remains the last-resort manual fallback.
