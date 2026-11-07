# Wonhee Proxy 0.15.10 — Product Batch F (guided experimental root-guard testing)

Status: **test APK / opt-in prototype**. No unattended activation. No default firewall modification. Product roadmap A→I remains unchanged: F is root firewall; G handles future background coordination; H UI consolidation; I beta qualification.

## Preconditions — do not skip

1. Use your rooted Pixel 8a **with a working USB cable and `adb devices` showing `device`**. Leave the terminal and debugging authorization active for the entire experiment. Capture the current iptables/ip6tables state separately before enabling.
2. In Wonhee Multi-Tunnel Lab, disable Product D encrypted *system* DNS enforcement and verify the owned DNS ledger says **OFF**. Product E tracker policy needs to be disabled with it. Android Private DNS can be audited separately; this is **not** a system-wide encrypted-DNS guarantee.
3. Disable Product C unattended tunnel recovery. Keep the existing tested Home + AirVPN split-routing setup active, and verify the selected profiles are exactly the UP WireGuard interfaces.
4. **Do not disconnect, change or restart tunnels or reboot** between enabling and the first successful *Disable + audit* cycle. Do not enable F on a phone you cannot recover through USB ADB.
5. This implementation refuses unknown or legacy kernel tunnels; missing/hostnamed WireGuard endpoints; **unset/unsafe fwmarks or shared non-Android marks**; duplicated endpoint IP:port tuples; nonphysical or looped marked endpoint egress; mismatched route selection; conflicting preexisting guard rules; and unowned firewall chains. Android's **shared `0x20000` protected-from-VPN mark is permitted only with distinct exact numeric endpoint IP:port pairs**. This mark is *not* a socket identity. Do not force an install by removing another app's rules.

## One test cycle (phone UI)

- [ ] Install the debug APK as an update only if the installed signature matches. Record app version `0.15.10-productBatchF-guided-test-alpha` (versionCode 57).
- [ ] Multi-Tunnel Lab → select Home and AirVPN → connect/verify exactly the same chosen tunnel identities and routes.
- [ ] Open *Advanced security controls* → **Product Batch F · Fail-closed firewall prototype**. It must read **KILL SWITCH LEDGER: OFF** before any action.
- [ ] Press **Verify live IPv4/IPv6 guard + rollback ledger**. When OFF, it must check both the ledger **AND** live root firewall: **owned ledger OFF; no Wonhee OUTPUT anchors or reserved guard chains**. A missing root shell or stray guard artifact must return CHECK REQUIRED. This does not exclude third-party firewall rules.
- [ ] Press **Batch F guided preflight · read only**. It checks the selected live tunnel identities, exact endpoint marks, current physical underlay routes, per-profile routes, DNS guard/recovery status, and the absence of app-owned F rules. It sends no packets and installs nothing. If it refuses, do not enable F.
- [ ] Press **Review + enable experimental kill switch · opt in**. Read the recovery warning, including the shared-mark limitations, and explicitly confirm only while connected to USB ADB. If a gate refuses, preserve the error and stop.
- [ ] If activation reports **rolled back and verified**, preserve the new preceding **failed at** stage (family, command step, and rule number, without endpoint addresses). It indicates which iptables operation failed. Do not retry repeatedly if the stage persists. No kill switch should be active after verified rollback.
- [ ] If enabled, press **Audit**. Require two OUTPUT anchors, exact chain rules and terminal IPv4/IPv6 rejects to match the ownership ledger. Leave Home/AirVPN connected.
- [ ] Press **Batch F guided preflight** again while F is active. It must confirm the saved F plan still exactly matches the selected current kernel profiles and that both IPv4/IPv6 live rules match the plan.
- [ ] **Optional, with working USB ADB and explicit consent only:** press **Test IPv4 + IPv6 physical-underlay rejection**. It sends at most two numeric-only ICMP echo attempts, one per family, bound to the physical interface; if the guard fails, an actual packet could escape. A successful ping is **potential direct escape** and needs immediate review. A rejected ping with an increased terminal reject counter is **limited blocking evidence**, not proof of the probe's packet specifically because other packets can increment the counter. No counter increase is **inconclusive** (the ping might have failed earlier). The UI never disconnects tunnels or changes the firewall in this test.
- [ ] While F is active, check a small benign Internet request and an authorized Home-only request. Both should travel only through their chosen interfaces; *successful requests alone do not prove no leak*. Do not deliberately drop the only working underlay without additional safe rollback access.
- [ ] Press **Disable Batch F guard + verify exact rollback**. Require a positive result. Press **Audit** again: owned ledger **OFF**. Confirm no Wonhee guard chain/tag exists. Tunnel profiles remain UP.
- [ ] Only after exact cleanup is verified may you test tunnel changes, network handoffs or reboots, with F **OFF**. Re-enable F only for a separate controlled test.

Do not mark independent Home-tunnel-loss behavior, DNS fail-closed behavior, Android app traffic isolation, reboot protection, or general IPv6 leak freedom as validated by the two ICMP challenges. Those require separate packet capture and controlled failure tests with a dedicated independent recovery path.

## Read-only shell evidence: Termux on device

Run commands independently. They do not mutate routes or firewall rules:

```sh
su -c 'iptables -w -S OUTPUT | grep WN_MULTI_GUARD'
su -c 'ip6tables -w -S OUTPUT | grep WN_MULTI_GUARD'
su -c 'iptables -w -S WN_MULTI_GUARD4'
su -c 'ip6tables -w -S WN_MULTI_GUARD6'
su -c 'wg show'
```

## Read-only shell evidence: USB ADB from Fedora

```sh
adb devices -l
adb shell su -c 'iptables -w -S OUTPUT | grep WN_MULTI_GUARD'
adb shell su -c 'ip6tables -w -S OUTPUT | grep WN_MULTI_GUARD'
adb shell su -c 'iptables -w -S WN_MULTI_GUARD4'
adb shell su -c 'ip6tables -w -S WN_MULTI_GUARD6'
adb shell su -c 'wg show'
```

After a **successful disable**, the guard-tag search and guard-chain listing should report no matches/nonzero exit codes because those owned objects no longer exist. This does not mean there are no *other* firewall rules on the device. Avoid logging private WireGuard keys.

## Failure and emergency recovery

1. Prefer the app's **Disable Batch F** button, even if the WireGuard backend is offline. The app keeps a durable exact-rule ledger and removes only its own two anchors/chains. The status banner **OWNED** proves intent was recorded, not that rules are necessarily still live (e.g., following reboot).
2. If Disable reports a mismatch, **do not clear the ledger or flush OUTPUT**. Keep USB ADB attached. Record the exact four `-S` outputs above for diagnosis. An unexpected rule inside an owned chain deliberately blocks automatic cleanup.
3. **Last-resort ADB recovery only after checking the names/tags are exactly this app's:** detach the two exact owned OUTPUT jump rules **before** flushing the app-specific chains. These commands *change the firewall* and remove the kill switch; they are recovery-only, not a test step:

   ```sh
   adb shell su -c 'iptables -w -D OUTPUT -m comment --comment WN_MULTI_GUARD4_ANCHOR -j WN_MULTI_GUARD4'
   adb shell su -c 'ip6tables -w -D OUTPUT -m comment --comment WN_MULTI_GUARD6_ANCHOR -j WN_MULTI_GUARD6'
   adb shell su -c 'iptables -w -F WN_MULTI_GUARD4'
   adb shell su -c 'iptables -w -X WN_MULTI_GUARD4'
   adb shell su -c 'ip6tables -w -F WN_MULTI_GUARD6'
   adb shell su -c 'ip6tables -w -X WN_MULTI_GUARD6'
   ```

   If an unexpected rule or owner exists, stop: manual ownership review is required. Do not run `iptables -F`, `ip6tables -F`, or change the default firewall policy. After manual recovery, app ledger still requires reconciliation; do **not** assume the UI says OFF automatically.

## What Product F does and does not prove

It installs `filter/OUTPUT` chains per IP family, exact `SO_MARK` + numeric UDP endpoint exceptions, tunnel-interface allowances for their configured CIDRs, Home/split-route negative guards, and terminal rejects. It saves its rollback intent before writes and prevents tunnel/routing mutations while owned. **For the Android `0x20000` shared mark, another socket with the same mark could reach the same narrow endpoint IP:port; this is a known bypass and explicitly NOT unique per-tunnel identity.** We do not mutate Android's fwmark layout or live WireGuard marks. It **does not** prove continuous kernel identity, packet-level leak freedom, Android background service continuity, boot-time enforcement, or safe automatic reconnect. Testing restart/handoff/reboot protection is a future **Product G** task, not a claimed Product F pass.

**Acceptance for F prototype:** compile/tests pass; default OFF; guarded activation either refuses safely or installs and audits exactly; exact app-owned rollback works with USB ADB. A device-specific *fail-closed verified* claim requires later controlled on-device packet capture, negative connectivity tests, and successful recovery. Do not mark that claim complete based only on a successful app audit.
