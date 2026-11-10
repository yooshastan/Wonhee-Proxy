# Wonhee 0.15.41 — Route Evidence and Stability

## Scope
The working 0.15.40 direct-route classifier is preserved. The new **Diagnostics · Route Evidence** panel is displayed outside the long advanced controls and offers:
- Read-only live peer route prediction (same existing bounded audit, with classifications and detailed evidence).
- One-tap Android ACTION_SEND export of only the already aggregated, bounded classification summary (in memory, no permanent report file). Export is enabled only after a complete report.
- Manual passive F.2 tunnel-health snapshots before/after a naturally occurring connectivity handoff.
- Independent read-only live DNS firewall/relay inspection after handoff.

The existing detailed report stays available in Latest Result. The short summary cannot prove actual egress and treats protected-marked Android sockets as possible intentional exemptions, not confirmed leaks. Ordinary physical-route predictions still need investigation.

## Device test plan
1. Install with original release signing key only after H.1 Safe Stop and independent H.2a CLEAN_STOPPED. No PR/debug APK replaces the official app.
2. Connect Home and AirVPN, then run the new Diagnostics route check. Verify the summary agrees with the detailed route data and that the share sheet contains no remote endpoint address, port, domain, key or raw packet data.
3. Repeat an idle capture and a normal-use capture for Messages and Play services. A missing socket must be insufficient evidence rather than a clean-VPN assertion.
4. Capture F.2 snapshot, perform a *natural* Wi-Fi/cellular handoff if safe, capture again, then run the DNS read-only audit. Do not force a network transition using the app. A healthy route or counter is not packet-egress proof.
5. Check RCS, push, Wi-Fi Calling, tracker counts, relay ownership and both tunnel identities. Keep Android Private DNS OFF on the tested Pixel 8a.
6. Confirm no Batch F guard activation, firewall rule writes, DNS settings changes, or routing mutations from these diagnostics.

## Limits
No automatic handoff recovery is added here. No automatic exporting or background capture. The complete session remains available in the existing Latest Result UI, but only the short aggregate classification may be shared via this new control. A short observation can miss application flows and cannot establish leak freedom.
