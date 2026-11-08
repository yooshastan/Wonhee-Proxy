# Wonhee Proxy 0.15.24 — Batch H.2b: Orphan DNS Safety

## Incident

On a rooted Pixel 8a with two independent kernel WireGuard tunnels, the user accidentally disconnected both interfaces while root DNS-port interception was still installed. All three HOME split routes were gone, but all eight WN_ IPv4/IPv6 DNS rules remained. A previous recovery attempt also reported that the DNS ownership XML was missing. The user needed a manual orphan-rule cleanup script. Routine app operation must not be able to recreate this trap.

## H.2b changes

1. **Tunnel and routing mutation guard**: Before *manual* connect/disconnect or split route changes, independently read live IPv4 nat OUTPUT, IPv4 filter OUTPUT, and IPv6 filter OUTPUT rules. A missing DNS ledger no longer implies safe shutdown. If any WN_ DNS firewall tags are present, refuse the tunnel operation. Also quarantine a pending orphan repair marker.
2. **Emergency owned DNS Disable**: Duplicate the tested DNS disable control in the *top-level Connection Controls*. It works without a live VPN interface when the original valid ownership record exists and removes only exact owned firewall rules and a process-identity-verified native relay.
3. **Orphaned DNS Audit**: Read-only scan of exact WN DNS rules and all WN_-tagged IPv4 NAT/IPv4 filter/IPv6 filter OUTPUT entries, with Batch F guard and saved DNS ownership validation. Extra, duplicate or modified rules and unknown guard state refuse orphan repair. Tunnel and relay state are intentionally independent of DNS-only cleanup.
4. **Opt-in Orphaned DNS Repair**: Only allowed with **no** valid DNS ownership record, no Batch F guard, and no unknown DNS OUTPUT rules. Tunnels and the local relay may be UP; recovery intentionally does NOT change them or any routing rules. On first invocation requires **all eight** original exact WN DNS firewall rules (not an arbitrary partial set) with no additional WN_ OUTPUT rules. Preflights twice before committing a dedicated crash-retry marker, then deletes only the exact known rules and rechecks kernel rule absence.
5. **Crash retry**: If the process dies after the dedicated marker is committed, only the exact remaining subset of those eight rules can be removed after repeated live verification. If all eight are already absent, explicit retry clears the marker without modifying firewall.
6. **Startup held back on pending repair**: Wonhee refuses new root DNS enforcement or a new full-stack startup while the orphan recovery marker is still recorded.

No automatic orphan cleanup occurs on app start or reboot. No iptables flush, WireGuard key exposure, Android DNS configuration changes or broadened kill switch are introduced.

## Design limits

- Exact rule shape and a WN_ comment are **not cryptographic proof of ownership**. Explicit user confirmation and strict other safety gates are mandatory.
- If an unrecorded DNS relay continues listening on localhost:53535, orphan repair leaves it alone; removing DNS firewall enforcement alone does not terminate a live root helper. The separate relay lifecycle issue must be audited later.
- We do not automatically recover every partial or malformed firewall configuration. Partially removed rules with no marker are **blocked**.
- This update does not provide full VPN leak protection or unattended boot reconnection; Wi-Fi/cellular traffic may resume outside the VPN after DNS firewall removal.
- The lost DNS ledger itself is not magically restored; verified removal is preferred to adopting orphan rules as a new permanent policy.

## Safe Pixel acceptance

1. Keep current 0.15.23 configuration available for rollback. While the existing stack is running, use *Safe stop complete Wonhee stack* and independently confirm zero IPv4/IPv6 reserved priorities, zero WN DNS OUTPUT rules, and both tunnels DOWN.
2. Install 0.15.24 in place using the same debug signer; do not uninstall or clear encrypted profiles/managed HOSTS.
3. While clean/stopped, run new **Audit orphaned DNS firewall · read only**. Expected CLEAN. **Do not run orphan repair** on a clean device; it should refuse if tried.
4. Use existing Start full stack, check HOME/AirVPN, encrypted DNS, imported tracker policy and Privacy Monitor.
5. While DNS owner is recorded, the manual tunnel-only Disconnect button is disabled and hidden under Advanced. Emergency **Disable verified owned DNS · even when tunnels are DOWN** should be available without DNS-profile selection. Primary controls are full-stack Start/Safe stop.
6. Use full-stack **Safe stop**; confirm all relevant rules and links are absent. Repeat START→STOP once.
7. Only on a spare rooted device/emulator, simulate the lost-ledger/exact-eight orphan state both with tunnels UP and DOWN. Audit should report READY_FOR_EXPLICIT_REPAIR in both cases. After explicit recovery, verify absence of the eight original WN tags, unchanged tunnels, routing and unrelated iptables rules, and a cleared recovery marker.
8. Failure-injection on a spare: duplicate tag, mutated rule, foreign WN_ tag or Batch F guard must prevent any orphan deletion. Live relay/tunnel/routing must remain unchanged during DNS-only recovery. Interrupt after the marker commit and confirm exact subset retry.
9. If any CHECK REQUIRED / REFUSED result occurs on the daily phone, retain ADB access and do not reset the app or flush firewall. Stop further testing until the specific check is identified.

## Deferred

- Durable, independently audited DNS relay process lifecycle without a DNS ownership record.
- On-device upgrade migration for damaged stored records where exact provenance is proven.
- Bounded Wi-Fi/cellular handoff recovery and boot-start opt in only after safe shutdown is established.
