# Wonhee Proxy Alpha 0.9.9.0 — profile persistence, monitoring, manual recovery

This release builds on the tested two-kernel-interface baseline without
changing the WireGuard backend, DNS, routing, Android VpnService, or firewall
state except when a user explicitly requests a managed-pair restart.

## Profile selection persistence

1. Import and role-label multiple `.conf` profiles as usual.
2. Select the intended Home/ASUS and AirVPN/Internet entries in the root lab.
3. Tap **SAVE SELECTED HOME + INTERNET PAIR**.
4. Leave and reopen the root lab. The selected names should be restored.
5. Rename or delete a stored profile and reopen. Missing saved names must
   gracefully fall back to available role-based selection; no tunnel starts
   automatically.

## Diagnostic persistence and support export

1. Run any read-only root diagnostic; note its result.
2. Close or force-stop the app, then reopen the root lab. The most recent
   completed result should appear with a previous-result timestamp.
3. Tap **COPY ROOT SUPPORT SNAPSHOT** to copy the selected profile names,
   current in-app live status and latest diagnostic in one operation.
4. Tap **CLEAR SAVED DIAGNOSTIC**, close and reopen, and verify the old result
   is no longer present.

Only names and diagnostic text are stored as app-private preferences. Raw
`.conf` contents and private keys remain in the encrypted profile store.
Copying diagnostics to Android's clipboard may make them visible to other apps.

## Per-tunnel live monitoring

1. Start the two known-good tunnels and wait at least 10 seconds on the root lab.
2. Check that Home and Internet each show their own RX/TX totals, live throughput
   (after two 5-second samples) and time since last WireGuard handshake.
3. Open Navidrome through Home and a public website through AirVPN. Both counters
   should change independently. An idle tunnel may have an old handshake time.
4. Stop both: the monitoring view should become idle and later starting tunnels
   should begin with fresh speed samples, not old values.

## Explicit recovery (no unattended network changes)

1. While both tunnels are managed, tap **RESTART MANAGED PAIR (CONFIRM)**.
2. Cancel once and ensure neither interface was touched.
3. Confirm a restart while on a disposable connectivity test: both tunnels
   should stop, then come back up with new handshakes. Temporarily dropped
   connectivity is expected; no fail-closed protection exists.
4. If stopping even one interface fails, the new pair must NOT start; inspect
   both interfaces and use the existing verified recovery action if needed.
5. Force-stop and reopen Wonhee. No unattended restart must occur. The normal
   Android VPN/Always-on service is separate from this root laboratory mode.

## Security status

The observed WireGuard socket marks were both `0x20000`, the Android
`protectedFromVpn` flag. This marker is not WireGuard-exclusive and must **not**
be treated as an unconditional firewall exemption. The kernel kill switch is
not installed or proven. Future enforcement must scope encrypted UDP endpoint
traffic narrowly and test IPv4/IPv6, DNS, crash/reboot, and network handoff
behavior before any persistent protection claim.
