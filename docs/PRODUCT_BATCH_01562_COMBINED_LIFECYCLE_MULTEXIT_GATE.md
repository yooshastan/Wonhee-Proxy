# Wonhee 0.15.62 — one release, no fake multi-exit success

**Status: DRAFT / DO NOT SIGN OR INSTALL YET.** Based on 0.15.61 (versionCode 108).
Do not increment to versionCode 109 or add this branch to the official release-signing allowlist until every release gate below has evidence. This milestone intentionally bundles reliability and **real** multi-exit routing; it is not complete when the UI looks finished.

## User outcome to accept on rooted Pixel 8a (Android 16)

The Home screen must let the user import or select multiple saved tunnels without a redundant Lab selector:
- AirVPN Europe (Netherlands) handles a chosen group of installed apps.
- AirVPN America (US) handles another chosen group of installed apps.
- Fedora Home (private destination 10.0.0.169/32 and 10.77.0.0/24) reaches Navidrome, while the other two tunnels remain connected.
- TCP/UDP destination-port overrides take precedence over an app's category default.
- User can see exactly what is **connected**, which exit each active rule uses, and what is merely **saved, planned, parked, unavailable, or blocked**.
- One Start and one Safe Stop remain on Home; Stop must work without asking the user to rediscover every active profile if the active identities can be verified from the persistent session record.
- Android Private DNS stays OFF. No hidden default/fallback when a required VPN fails.

The imported WireGuard profiles' keys, endpoints and AllowedIPs are immutable unless the user explicitly edits a profile. Never share keys or full private tunnel configurations in logs or GitHub.

## Work started on this branch

1. Fix strict owned-rule comparison when Android prints an exact IPv4 host **without /32**, or an IPv6 host **without /128**. The fix refuses different CIDRs, hosts, marks, UIDs, priorities and lookup tables.
2. Add tests reproducing the exact interrupted 2026-11-19 device state: saved 12500 /32 and 12501 /24, only 12500 live. Verify rollback preflight accepts the one exact remaining host and also accepts both already absent.
3. Show the primary exit picker directly on Home. Avoid Android dialog configurations in which a message obscures the option list. Do **not** misrepresent the parked full-exit profiles as running.

## Rootless multi-exit backend groundwork (2026-11-19)

- `RootMultiExitKernelPlan` now compiles an existing validated, dry-run
  `RootPerAppUidPolicyPlan` into **independent IPv4/IPv6 private-table route
  steps** and **per-UID TCP/UDP destination-port selection steps**. For each
  selected UID/protocol selector it produces a lookup-priority rule and an
  adjacent unreachable-priority rule in BOTH address families.
- Each proposed kernel operation has a precise inverse and a reverse-order
  rollback preview (remove selectors first, private table routes last).
- Compiler rejects incomplete IPv4/IPv6 Internet exits for assigned apps,
  duplicate/mismatched route ownership, duplicate default routes,
  system UIDs, collisions in reserved priorities, bad CIDRs and invalid
  port/transport selectors. No plan changes the installed profiles.
- The existing App Routing **read-only UID check** now reports the compiled
  policy counts alongside its visible blockers. Android CI includes Java
  tests and source checks confirming there is no shell execution.
- Linux iproute2 documents `uidrange`, `ipproto`, `dport`,
  `lookup` and `unreachable` selectors/actions. Actual **Android**
  tool/kernel compatibility, socket L4 classification and netd/mark behavior
  are not established by Linux documentation or a successful core test.
- Crucially: `activationAllowed()` remains `false` in BOTH planners.
  Do not call any generated install or rollback commands on a real phone.
  This is the preflight/compiler layer, **not live policy routing**.

## Pixel 8a Android 16 ip-rule compatibility audit (2026-11-19)

User-supplied **read-only device evidence** for kernel
`6.1.145-android14-11-gec45f20f38ea-ab15260282`:

- `ip -4 rule help` and `ip -6 rule help` advertise `fwmark`,
  `iif`, `pref` and `uidrange`. Both **omit** `ipproto`,
  `sport` and `dport`; the selected Android command-line utility must
  not be assumed to accept this project's direct L4 selector syntax.
- `ACTION` help also **omits** `unreachable`, despite the **existing**
  Android RPDB rule `32000: from all unreachable`. The existing rule is
  evidence that the kernel's policy database represents this action; it
  is **not proof** that the Android CLI can add/remove a specific rule
  with this action. No write probe is authorized.
- Android-owned priorities include 10000, 11000, 15040, 15998/15999,
  16000, 17000, 18000–20000, 22040, 22998/22999, 25000, 29040,
  29998, 31000 and 32000. Observed device tables include
  `wlan0`, `rmnet16`, `ipsec13`, and `local_network`; these are not
  Wonhee-owned and must never be flushed or repurposed.
- Both families report no Wonhee-owned 12500–12799 rules. This does
  **not** independently confirm DNS/firewall ownership cleanup; H.2a
  `CLEAN_STOPPED` remains a release gate.
- Added pure `RootIpRuleHelpCapabilities` and
  `RootIpRuleHelpCapabilitiesTest` to preserve this diagnostic, warn
  about missing direct L4 selectors, and refuse to equate help text
  with a kernel/traffic-safety check.
- **Backend decision**: do not attempt to execute conceptual
  `ip rule ... ipproto ... dport ...` rules on this Pixel 8a. Evaluate
  a separately verified per-app TCP/UDP classifier that writes an
  owned packet mark (netfilter or BPF, after feature detection), then
  restrict the RPDB to the device's available UID/mark selectors.
  Prove marks cannot collide with Android netd/protectedFromVpn bits,
  prove encrypted DNS ownership, and enforce selected-exit loss
  without leaking onto another VPN or the physical network.
  Neither alternate backend is implemented or activated by this PR.

## Pixel 8a netfilter CLI inspection (2026-11-19)

The user ran **read-only** `iptables` and `ip6tables` help commands.
Both commands identify as **v1.8.11 (legacy)** and print:

- `-m owner` help: `--uid-owner userid[-userid]`
- TCP/UDP module help: `--dport`
- `MARK` target help: `--set-xmark value[/mask]` and `--set-mark value[/mask]`

The generic `--ipv4`/`--ipv6` `Error (line is ignored by
iptables-restore)` lines appear in help output and are **not runtime rule
installation errors**. This establishes advertised userspace syntax only.
It does **not** prove that the device's legacy kernel modules can install,
match or mark packets; does not prove marking `mangle/OUTPUT` reroutes
already-selected local sockets; and does not establish safe coordination with
Android `netd`'s reserved fwmark bits.

- Added pure `RootNetfilterHelpCapabilities` and a Java test based on the
  observed v4/v6 help text, including missing-module, backend mismatch
  and token-spoof refusal tests. `activationAllowed()` remains `false`.
- Proposed architecture to evaluate, **not install**: per-UID TCP/UDP
  destination-port classification in a *Wonhee-owned* local-output chain,
  with explicit exact-port precedence, a carefully validated packet mark
  that does not alter Android's network-id/protect bits, and per-mark
  lookup of an independently owned WireGuard routing table.
- Before live proof, inventory installed mangle/filter chains, module
  availability, current marks and policy rules, physical underlay and the
  presence of any legacy owner chains; perform ownership collision checks.
  Never flush, rename or rewrite Android's existing chains.
- All marked traffic must be isolated in BOTH address families.
  WireGuard transport packets, system resolver traffic, protected sockets,
  loopback and kernel/system UID traffic require explicit handling; an
  app's UID is not necessarily the UID used for every associated request.
- A **failed selected exit must not silently fall back** to another
  VPN or Wi-Fi/cellular. The current `ip rule` help also omits
  `unreachable`; a verified per-table terminal block or another equally
  safe enforcement mechanism is still required. No all-traffic kill switch
  activation is authorized.

## Pixel 8a registered modules + live mangle/OUTPUT inventory (2026-11-19)

Read-only ADB output from the current Android 16 Pixel 8a:

- Both `/proc/net/ip_tables_matches` and
  `/proc/net/ip6_tables_matches` list `owner`, `tcp`, `udp`,
  `mark`, `connmark`, `bpf` and `multiport`.
- Both `/proc/net/ip_tables_targets` and
  `/proc/net/ip6_tables_targets` list `MARK` and `CONNMARK`
  (alongside other existing targets). This is **registration evidence**,
  not a proof of packet-level routing or safe mark ownership.
- For both families, `iptables -t mangle -S OUTPUT` reported exactly
  `-P OUTPUT ACCEPT` and
  `-A OUTPUT -j connmark_mangle_OUTPUT`. This is a **pre-existing**
  jump; assume it is externally controlled and do **not** flush, replace,
  append to, or take ownership of the `connmark_mangle_OUTPUT` chain.
  Its internal contents and creation owner have not yet been inspected.
- Added pure `RootNetfilterKernelInventory` with a rootless regression
  test for registered extension names, missing IPv6 targets, unknown
  OUTPUT rules, and pre-existing chain preservation. This does not apply
  firewall rules and cannot authorize activation.
- **Next required read-only check**: inspect the exact v4/v6
  `connmark_mangle_OUTPUT` chains and mark-related mangle rules, plus
  Android's existing RPDB fwmark masks. Determine which fields are
  Android-reserved, and how mangle/OUTPUT might influence routing of
  locally generated TCP/UDP traffic without breaking WireGuard
  endpoint sockets. Do not select a Wonhee mark mask yet.

## Pixel 8a Android network mark collision analysis (2026-11-19)

Read-only observation from `connmark_mangle_OUTPUT`, the full mark-affecting
mangle rule inventory and the v4/v6 Android `ip rule` tables:

- Both IPv4 and IPv6 have a pre-existing
  `connmark_mangle_OUTPUT` rule that selects **connmark
  `0x0/0xfffff`**, then saves **nfmark low 20 bits** into the connmark
  with `--nfmask 0xfffff --ctmask 0xfffff`. This is stateful mark
  propagation and is not Wonhee-owned.
- Existing `routectrl_mangle_INPUT` rules use
  `MARK --set-xmark <value>/0x7fefffff`. That write/clear mask spans
  many bits beyond the Android netId range.
- Existing `bw_mangle_POSTROUTING` clears bit `0x100000`.
- Wakeup monitoring matches bit `0x80000000`. This is a *read*
  dependency, not evidence the logger sets that bit.
- Union of `0x7fefffff | 0x100000 | 0x80000000` is
  **`0xffffffff`**, spanning all 32 mark bits in both families.
  This union is **conservative mask coverage**, NOT proof that each bit
  is semantically allocated to a distinct subsystem or always written.
  We cannot infer even one safely available Wonhee bit from these
  snapshots. Prior live RPDB masks (`0xffff`, `0x1ffff`,
  `0xdffff`, `0xcffff` etc.) further demonstrate Android-owned
  network and protection identities.
- Added `RootAndroidMarkCollisionAudit` and a rootless test. The
  model extracts existing rule marks, mark write/clear masks and
  connmark transfer masks, detects complete bit coverage and **always
  refuses to allocate a packet mark**. No new `iptables`,
  `ip6tables`, `ip rule` or WireGuard command is issued.

**Architecture decision:** Do NOT hardcode a new `MARK --set-xmark`
selector or assume the prior proposed UID/port policy is runnable.
Investigate safe UID-only per-app routing as an incremental validation
step, and separately investigate netlink `fib_rule` L4 capabilities or a
kernel classifier integration that cooperates with netd. Neither may be
activated until mark ownership, selected-exit blocking, DNS attribution,
WireGuard protected transport sockets, and exact Safe Stop ownership
are demonstrably preserved. Android Private DNS stays OFF.

## Next two-exit controlled pilot — preflight, not activation

- Existing `RootMultiKernelSession.connect` calls `WgQuickBackend` or
  `wg-quick` for each selected profile, and
  `RootMultiTunnelPlan.validate` explicitly rejects two overlapping
  Internet default routes. Those routines must **not** simply have their
  conflict guard removed: `wg-quick` can mutate the device's ordinary
  routing and existing Android netd policy.
- Added `RootMultiTunnelPlan.validateIndependentInterfaceAddresses`
  and invoked it from `RootPerAppUidPolicyPlan.prepare`, so separate
  IPv4/IPv6 routing tables cannot mask overlapping WireGuard local
  interface addresses. Tests cover duplicate IPv4 host addresses,
  overlapping IPv4 subnets and IPv6 address collisions.
- A useful first **live** milestone will require a new independently
  owned tunnel bootstrap that does not install conflicting default
  routes, followed by UID-only selection of one test app per exit.
  Build it behind a separate opt-in gate with an exact ledger, physical
  underlay for WireGuard UDP, verified dual-stack no-fallback policy,
  tunnel identity checks, DNS isolation and scripted reversal.
- The device's stock `ip rule` advertises UID matching, but no
  `unreachable` action. A terminal no-fallback route mechanism needs
  an independent capability proof: the existing
  `32000: from all unreachable` RPDB rule is not enough.
- Protocol/port-specific mark routing is **not** in the first pilot:
  observed Android masks span all 32 mark bits, and no Wonhee mark
  ownership has been established. Run the UID-only experiment on a
  recoverable test environment before touching the daily phone.
- The current source **does not start more than one full Internet exit**.
  The pilot and its fail-closed implementation are not complete until
  tested and explicitly reported as such.

## Offline isolated WireGuard startup sequence (2026-11-19)

New `RootIsolatedWireGuardBootstrapPlan` compiles a non-executing
**two-full-exit + Home** kernel link setup blueprint that intentionally
does **not** use `wg-quick` or change the Android main-table default route:

1. Require independent tunnel identities, exact peer CIDRs and a dedicated
   `51000+` table for every selected profile.
2. Propose `ip link add dev wnm... type wireguard` for each tunnel, then an
   explicit **secure peer-configuration handoff** (no keys/URLs in command
   strings, logs or static previews).
3. Require host-format interface addresses (/32 or /128) for this pilot;
   non-host local addresses may create unexpected connected main-table routes.
   Use per-interface address steps and then raise the interface.
4. Propose every WireGuard peer AllowedIPs destination **only in the
   profile's private table**. Both European and American default routes are
   allowed in *different* tables; Home remains private-destination only.
5. Reverse-order rollback preview removes private routes first and the owned
   link last. Profile identity and ownership journaling MUST be verified
   before a real executor deletes anything.
6. The App Routing read-only review displays whether this bootstrap plan is
   structurally viable; failure does not edit imported VPN configurations.

The Java tests validate that command plans never use `wg-quick`, contain
no main/default table injection, never expose private WireGuard material,
refuse /24 or /64 local addresses in this pilot, refuse mismatched table
ownership, and reverse exact cleanup ordering.

**NOT DONE:** no actual kernel interface/peer executor, protected UDP
endpoint sockets, netd collaboration, IPv4/IPv6 DNS ownership, no-fallback
per-app routing, rollback journal, or live 3-tunnel test. The current
`RootMultiKernelSession.connect` is unchanged. This is NOT the 0.15.62
shipping milestone.

## Journal-first isolated link transaction controller (2026-11-19)

`RootIsolatedWireGuardTransaction` now provides a **root-independent
transaction engine** for the isolated startup plan, with explicit
`Kernel` and `Journal` interfaces. It is not wired into Android Start.

- Verifies the *entire* plan shape before any root preflight.
  No main/default-table command or unknown inverse is eligible.
- Requires a device-supplied preflight that refuses uncertain root tools,
  foreign interfaces, profile fingerprints, Android/fwmark control, physical
  UDP underlay, DNS ownership and fail-closed IPv4+IPv6 policies.
- Records **durable intent before each mutation**, then checks exact kernel
  ownership and records a committed step. A command that partially
  completes before throwing still has an in-flight journal entry.
- Rollback, Safe Stop and post-crash recovery consume the same journal in
  strict reverse order. Objects already absent can be acknowledged, but
  objects with unknown or changed identities are NEVER deleted. If any
  verification or journal write fails, the remaining journal is retained
  for an independent audit; retry is supported.
- Added `RootIsolatedWireGuardJournalCodec` and Android
  `RootIsolatedWireGuardPreferencesJournal`. Records contain only
  immutable **plan SHA-256 fingerprint + ordered step index/state**.
  WireGuard private keys, endpoints and commands are not saved in
  SharedPreferences. Sync `.commit()` writes are checked. A changed or
  damaged plan refuses adoption; the record cannot be silently reset.
- Rootless tests fault-inject failures **after mutation at each startup
  stage**, before durable writes, during rollback, with a foreign interface,
  and after a simulated process restart. CI also tests journal corruption,
  replay, identity mismatch and refused main-table command injection.

**Not yet live:** there is still no verified Android `Kernel` adapter,
device-enforced preflight or protected configuration handoff, no proof
of per-UID dual-exit fail-closed routing, and no integration with
`RootMultiKernelSession.connect`/`stopManagedStack`. App-private
SharedPreferences metadata alone does not establish live kernel
ownership; the eventual adapter must implement exact readback of every
installed object and safely handle credential changes. This is a new
recovery/control layer, NOT proof of connected Europe+America+Home.

## Implemented toward an APK candidate — protected root adapter (2026-11-19)

- Added `RootIsolatedWireGuardConfigHandoff`. It stages a canonical
  WireGuard configuration in a 0600 app-private file, uses
  **`wg-quick strip` only** to remove helper-only DNS/Address/Table fields,
  and applies peer configuration through **`wg setconf`**.
  It never calls `wg-quick up/down` or puts private keys in shell arguments.
  It deletes the staging file immediately after the operation and verifies
  the live interface and peer public keys. A crashed helper may leave an
  app-private staging file; that must be audited, not blindly overwritten.
- Added `RootIsolatedWireGuardKernelAdapter`, an injectable Android
  root adapter for the journal-first transaction. It implements LINK_CREATE,
  PEER_CONFIG, HOST_ADDRESS, LINK_UP and PRIVATE_ROUTE with exact command
  shapes, kernel readback, and read-before-delete ownership. Before a key
  exists, in-process link ownership is additionally bound to a kernel
  **ifindex** to reject name reuse. After process restart, it requires a
  matching WireGuard public identity; uncertain pre-key orphan links
  are retained for manual recovery.
- Added `RootIsolatedWireGuardKernelListing` and CI tests covering
  exact IPv4/IPv6 host addresses, Linux bare /32-/128 route aliases,
  duplicate and foreign routes, link types, and changed interface names.
- The legacy Safe Stop and update-readiness checks now **refuse** an
  isolated ownership ledger that is nonempty, missing expected values or
  unreadable. `scripts/install-wonhee-safe-update.sh` checks the
  app-private XML journal and both families' 51000–51007 private-table
  routes. New mock installer tests refuse corrupt/pending ownership.
  No existing Android netd firewall or route is modified by these checks.
- Added `RootIsolatedUidOnlyPolicyPlan` as a non-executing **first
  routing phase**: only Android-advertised `uidrange`+`fwmark`
  selectors, with separate high-metric `unreachable default` candidates
  in each private table, before installing UID rules. This avoids
  unsupported `ip rule ipproto/dport` and new arbitrary packet marks.
  The proposed Android `ip route add unreachable` syntax and real
  fail-closed packet path still require on-device verification. Any
  configured transport/port override makes this pilot inapplicable.
- App Routing's read-only review shows this narrower UID-only pilot
  separately from the advanced protocol/port plan. All activation gates
  remain **OFF**.

**Release blocker, not a formality:** the real safety gate proving
WireGuard UDP endpoint underlay, DNS ownership, full IPv4/IPv6 route
blocking during tunnel loss, and netd coexistence is **not implemented**.
No production code constructs the new KernelAdapter or invokes the
journal transaction in Start/Stop. Do NOT promote an Android CI build
to the signed release or advertise real three-exit routing until the
active path passes physical-device packet capture and Safe Stop tests.

## UID-only fail-closed policy transaction and separate recovery ledger

Added `RootIsolatedUidPolicyTransaction` for the first UID-only phase.
It is deliberately separate from the existing isolated WireGuard bootstrap
transaction: selected tunnel links/routes must be established and verified
before any UID rules are considered.

- Installs the per-table high-metric unreachable default proposal **before**
  any app UID lookup selector; on Safe Stop, removes UID rules **before**
  deleting the blocking routes. This is exact-reverse recovery only.
- Every mutation requires a durable write-ahead record, exact post-mutation
  kernel readback, and an injected `requireFailClosedPreflight()` that must
  prove DNS identity, protected physical WG transport and IPv4/IPv6
  no-fallback behavior. If any check or mutation fails, only exact-owned
  objects may be undone, and incomplete records are retained.
- `RootIsolatedUidPolicyJournalCodec` and
  `RootIsolatedUidPolicyPreferencesJournal` provide a separate
  fingerprint-bound app-private journal. The codec rejects changed UIDs,
  invalid/crashed sequences and uncommitted earlier steps. Neither stored
  shell commands nor WireGuard keys appear in the persistent record.
- `RootIsolatedUidPolicyListing` parses exact Android reserved-priority
  UID selectors and high-metric terminal routes without adopting adjacent
  foreign rules; `RootIsolatedUidPolicyKernelAdapter` provides a **dormant**
  Android root adapter with strict command whitelisting and an external,
  unimplemented proof-of-safety gate. It is **not wired** to Home Start.
- Legacy Safe Stop and update preflight block on either outstanding
  bootstrap or UID journals, and the official installer inspects both
  protected XML records and both families' reserved priorities/tables.
  Mock installer and rootless transaction, codec, and readback regressions
  cover interrupted installs, foreign resources and replays.
- Both policy and bootstrap journal decoders reject a pending earlier stage
  followed by a later stage. This prevents silently treating a damaged
  persisted log as a valid recovery plan.

**Still blocked:** real phone-side proof that UID range routing and a
private-table `unreachable default` cannot escape to Android's normal
Wi-Fi/cellular path; DNS/DoQ/DoH ownership; real WG endpoint handshakes
and protected UDP underlay; working Start/Safe Stop integration and
protocol/port selector support. This code cannot be called the signed
0.15.62 release. Private DNS must remain OFF on the Pixel 8a.

## Pixel 8a RootLab compatibility and first two-peer functional smoke path

The user ran the 0.15.62 RootLab readiness APK on the rooted Pixel 8a
(Android 16 / kernel 6.1.145). Device results:

- `ToolsInstaller.ensureToolsAvailable()` succeeds inside the app-private
  RootLab environment. `wg --version` succeeds with
  `wireguard-tools v1.0.20250521`. `wg-quick` resolves in
  `/data/user/0/com.yooshastan.wonheeproxy.rootlab01562/code_cache/bin/`.
- `wg show interfaces` is empty. Both families' `ip rule` help list
  `uidrange` and `fwmark`, **not** `ipproto`/`dport`.
  Both families' `ip route` help list `unreachable` route types.
  This command prints help with status 255; that is not a route failure.
- No reserved 12500-12999 policy rules, private 51000-51007 routes, or
  WireGuard interfaces were seen. Existing mangle OUTPUT chains contain
  `-A OUTPUT -j connmark_mangle_OUTPUT`; these are Android-owned and must
  not be flushed or rewritten. Private DNS stays **off**.
- The isolated journal reports are for the **separately installed RootLab
  package**, not the official Wonhee package. Earlier phone ADB also
  showed no private-table routing residue.

**Implemented after the device report:** `RootIsolatedTwoPeerLinkPlan`
compiles an exactly **two-peer**, rootless link-only smoke sequence. It
does not rely on a fake per-app UID assignment. Each selected WG peer
would get its own named kernel link and private table (51000/51001);
interface local addresses require /32 or /128, and each peer must permit
an IPv4 default AllowedIPs route (optional IPv6 default). Extra split
destinations and overlapping local addresses are refused. The emitted
commands contain **no Android IP rules, new fwmarks, mangle changes,
system/main routes or DNS changes**. `RootIsolatedTwoPeerHandshakeAudit`
compares read-only peer handshakes and transfer counters against their
expected public keys but exports only redacted verification, age and
byte counts. Tests cover stale/mismatched peers and independent tables.

**This is the next *functional* test architecture, not a live button yet.**
Actual activation still depends on encrypted profile import/selection,
persistently signed pilot packaging, a verified endpoint-underlay
safety gate, exact post-crash journal ownership and explicit Safe Stop.
Only after two peer handshakes are proven should app UID routing and
leak testing be turned on. Keep the released 0.15.61 package untouched.

## 0.15.62 Two-Peer Lab APK: first manually controlled kernel-link build

**New debug APK only**: `com.yooshastan.wonheeproxy.rootlab01562peers`,
versionCode **110**, versionName `0.15.62-two-peer-lab`. This has a unique
package identity so it installs alongside the official 0.15.61/versionCode
108 and the earlier RootLab readiness diagnostic without depending on the
ephemeral CI debug signing key.

- `RootlabTwoPeerActivity` provides **Import Exit A / Import Exit B** via
  Android's document picker, explicit **Start TWO independent peers**,
  **Read handshake & counters**, optional per-interface bound numeric ICMP
  probes, **Safe Stop**, and **Export redacted diagnostics (.txt)**.
- `RootlabTwoPeerSession` stores imported configurations in the separate
  lab package's AndroidKeyStore-encrypted `SecureTunnelProfileStore`;
  configs and keys never enter journals or exported logs. Remote server
  peer identities must differ; provider-reused local client keys are accepted
  only when `RootIsolatedTwoPeerLinkPlan` can establish distinct named links
  with independent interface addresses. The plan requires
  independently allocated /32-/128 interface hosts. Peer routes are
  limited to full IPv4 (optional IPv6) defaults, stored in independently
  owned private tables, with NO `ip rule` selectors.
- `RootlabTwoPeerSafetyGate` checks Private DNS **off**, no prior isolated
  ownership ledgers, a present non-VPN Android physical network, both
  families' existing routing policy for any references to the reserved
  tables and priorities, then defers to the kernel adapter's strict
  interface/route inventory. This is a *link-only* safety scope, NOT a
  production Android-app leak proof or protected peer endpoint proof.
- The debug manifest uses `RootlabApplication` instead of
  `WonheeApplication`, disables the ordinary VPN dashboard, and removes
  Android's VPN service, boot receiver, scheduled recovery services and
  quick-setting/traffic services from this standalone test package.
  There is no automatic connection, background VPN restoration, or
  untargeted system route/firewall/DNS mutation.
- Startup uses the verified `RootIsolatedWireGuardKernelAdapter` and
  `RootIsolatedWireGuardTransaction` with a durable,
  plan-fingerprint-bound, app-private journal. Stop performs exact LIFO
  inspection and rollback, including after a new Activity/process
  reconstructs the encrypted profiles. If an ambiguous object is found
  recovery **pauses** and retains the journal instead of deleting it.
- The optional numeric bound ICMP probe first checks `ip route get
  1.1.1.1 oif <named-interface>`; if the kernel does not explicitly
  report that same interface, **no probe is sent**. A packet reply is
  not a per-app routing proof. The handshake/counter report exports
  labels, verified state, age and counts only; no keys/endpoints.

**Manual test protocol:** with no existing official Wonhee tunnels and
Private DNS OFF, import two *independently provisioned* WireGuard configs,
Start both, inspect kernel link/handshake report, optionally probe, Safe
Stop, then verify both interfaces/routes removed and Stop again
(idempotence). Export the redacted report if any operation refuses or
recovery pauses. Never delete the lab app or change imported config while
ownership remains pending.

**NOT YET COMPLETE:** this live pilot must not be marketed as a multi-exit
VPN. It does not route or protect Android applications, DNS, GPS, TCP/UDP
protocol overrides or Home traffic. Release 0.15.62 still requires
real-device successful simultaneous peer handshakes, exact stop/resume
and independent UID/DNS/leak-proof safety before official release.

## RootLab two-peer PEER_CONFIG failure and direct setconf fix

User device test with `com.yooshastan.wonheeproxy.rootlab01562peersfix2`
passed `PROFILE_CHECK=READY`, reached `PEER_CONFIG`, reported
`REFUSED/FAILED; EXACT ROLLBACK COMPLETE (persistent entries=0)`
and `Own journal stages: 0/14`. No handshake or app-routing proof exists.
A separate screenshot with a generic `IllegalArgumentException` has no
sufficient context to assign it to this same failure.

`RootIsolatedWireGuardConfigHandoff` previously ran a shell
`wg-quick strip <app-private-file> | wg setconf <device> /dev/stdin`
pipeline. This was fragile on Android and the transaction hid the
underlying failure class. The updated app generates a strict **wg-only**
peer configuration in Java from `Config.toWgQuickString()`, omitting
`Address`, `DNS`, `MTU`, `Table`, app lists and all unknown commands,
then supplies its private staging path to direct
`wg setconf <interface> <private-file>`. No keys or endpoints are shell
arguments, persist in journals, or appear in exported diagnostics.
All private file cleanup remains exact-owned.

`RootIsolatedWireGuardTransaction` now reports a separate sanitized
`phase` and `reason`, including `WG_SETCONF_COMMAND_FAILED` vs
`WG_SETCONF_READBACK_MISMATCH`; it never exports shell stderr or secret
profile values. Pure-Java tests cover canonicalization, rejected unknown
fields, no DNS/route/mangle outputs and exact rollback on peer failure.

The replacement side-by-side debug package
`com.yooshastan.wonheeproxy.rootlab01562peersfix3`, versionCode 113,
versionName `0.15.62-two-peer-setconf`, is NOT a signed production update.
The old test package stays installed until phone-side inspection confirms
its ledger is empty. Before trying peer Start, ensure Private DNS OFF,
no simultaneous Android VPN, and two independently provisioned local
AirVPN identities with disjoint interface addresses.

This code change is a plausible correction to the PEER_CONFIG failure
mechanism, **not proof** that the pipeline was the sole cause, nor a
successful live handshake. Treat the next exported redacted
`stage/phase/reason` as decisive evidence.

## Mandatory unfinished engine work — blocks release

1. Start **multiple independent full Internet exits**, not only one default plus specific destination tunnels. Each must have an isolated IPv4 and IPv6 routing table, stable owned interface identity, encrypted DNS policy, correct WireGuard UDP endpoint path, and tracked kernel ownership. Avoid conflicts with Android netd and other VPN apps.
2. Enforce installed-app current UIDs and TCP/UDP destination-port overrides in actual traffic. Precedence: exact UID+transport+port, UID+transport, UID/category, device default. Never assume an old UID remains valid across reinstall/shared UID/multiuser change. Categories are not the transport enforcement engine.
3. Fail closed **for a selected app's required exit**, IPv4 and IPv6, without routing onto a different exit or the unprotected cellular/Wi-Fi path. All-traffic kill-switch (Batch F / issue #41) stays disabled until independent device tests prove safety; do not silently bypass its activation gate.
4. Verify actual handshakes, received bytes and controlled reachability for each selected WireGuard peer; an interface that is UP or a route simulation alone is not a success. Clearly distinguish endpoint IPv6 failures, server key/address mismatch and DNS startup failure (including LOCAL_DNS_TIMEOUT).
5. DNS relay and firewall ownership must be scoped and recovered consistently per exit; document any policy limitation before enabling multiple full exits. No DNS leakage on a failed required-exit path.
6. Update both Start and Safe Stop to journal every actual active/parked profile and its rule ownership. Safe Stop must clear exact DNS/routing ownership before disconnect and must tolerate a partially completed deletion. Never flush foreign firewall rules or guess who owns a route.
7. Provide direct Home presets/roles (default Internet, app-specific Internet, private destination, custom) with a simple one-screen flow and plain-language validation. No repeated port/tunnel mapping on separate screens.
8. On-device smoke tests: Europe+US+Fedora Home simultaneously connected, distinct app paths verified with packet evidence, Navidrome GET succeeds from browser, app behavior verified, cellular↔Wi-Fi transition tested, safe stop twice, reinstall and restore tested without loss of profiles. Run zero-fallback / no leaking / exact cleanup audits.

## Engineering safety: current constraints

Current RootTunnelStartSelection intentionally **parks additional full exits**. RootMultiTunnelPlan.validate rejects overlapping defaults. The persistent category/port rule editor is **planning-only**. Do not delete these guards to make the UI report three tunnels. Issue #89 tracks the actual backend implementation and #41 tracks the separate all-traffic firewall gate.

## Release / CI gates

- Java rootless routing tests, Python static UX tests, Android build and native WireGuard tests must pass.
- Never infer **real-device networking success** from CI. Explicit tests on a spare/rooted device with USB ADB recovery required.
- Independently verify H.2a **CLEAN_STOPPED**, IPv4/IPv6 reserved range 12500–12799 empty, no Wonhee kernel links, no tagged DNS firewall/relay and cleared ledgers before any official in-place install.
- Only after acceptance: raise versionCode from 108 to >=109, change versionName to 0.15.62, include the branch in signing allowlist, build with the existing official keystore, verify cert fingerprint, and use the safe installer. Do not uninstall the installed official app.

This document is a release gate, not evidence the unfinished multi-exit features work.
