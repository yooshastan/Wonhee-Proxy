package com.yooshastan.wonheeproxy;

import android.content.Context;

import com.wireguard.android.util.RootShell;
import com.wireguard.android.util.ToolsInstaller;
import com.wireguard.config.Config;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Debug-only manual two-peer WireGuard link experiment.
 *
 * No UID routing, system default route, firewall, IPv4/IPv6 DNS changes or
 * Android VpnService. Two imported configurations are stored in the lab
 * package's own AndroidKeyStore-encrypted profile store, NEVER in the
 * official package or the diagnostic export. It can prove that the kernel
 * holds two distinct WireGuard peer identities and can handshake, but it
 * cannot yet claim privacy protection for any Android app.
 *
 * Caller MUST serialize import, Start, Stop and Status on a single worker.
 * A crash may leave exact-owned journal entries requiring manual recovery.
 */
final class RootlabTwoPeerSession {
    static final String FIRST = "Exit A";
    static final String SECOND = "Exit B";
    static final String HOME = "Home";

    private static final String LOG_PREF = "wonhee_rootlab_two_peers_redacted_v1";
    private static final String LOG_KEY = "events";
    private static final int MAX_CONFIG = 32768;
    private final Context app;

    RootlabTwoPeerSession(Context context) {
        if (context == null) throw new IllegalArgumentException("Missing lab context.");
        app = context.getApplicationContext();
    }

    private static final class ProfileRejected extends IllegalArgumentException {
        final RootTwoPeerProfileReadiness.Reason reason;

        ProfileRejected(RootTwoPeerProfileReadiness.Reason reason) {
            super(RootTwoPeerProfileReadiness.explain(reason));
            this.reason = reason;
        }
    }

    private static final class Pair {
        final RootIsolatedWireGuardBootstrapPlan.Plan plan;
        final Map<String, Config> configurations;
        final List<RootMultiTunnelPlan.Entry> entries;

        Pair(RootIsolatedWireGuardBootstrapPlan.Plan plan,
                Map<String, Config> configurations,
                List<RootMultiTunnelPlan.Entry> entries) {
            this.plan = plan;
            this.configurations = configurations;
            this.entries = entries;
        }
    }

    boolean hasProfile(String slot) throws Exception {
        for (SecureTunnelProfileStore.Profile saved :
                new SecureTunnelProfileStore(app).load()) {
            if (slot.equals(saved.name)) return true;
        }
        return false;
    }

    String importProfile(String slot, InputStream stream) throws Exception {
        if (!FIRST.equals(slot) && !SECOND.equals(slot)
                && !HOME.equals(slot)) {
            throw new IllegalArgumentException("Unknown test slot.");
        }
        if (RootIsolatedWireGuardPreferencesJournal.pendingOrUnknown(app)
                || RootIsolatedUidPolicyPreferencesJournal.pendingOrUnknown(app)) {
            throw new IllegalStateException("A pending tunnel journal must be stopped first.");
        }
        if (stream == null) throw new IllegalArgumentException("No configuration selected.");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[2048];
        byte[] secret;
        try {
            int count;
            while ((count = stream.read(buffer)) != -1) {
                if (bytes.size() + count > MAX_CONFIG) {
                    throw new IllegalArgumentException("Configuration exceeds lab limit.");
                }
                bytes.write(buffer, 0, count);
            }
            secret = bytes.toByteArray();
        } finally {
            Arrays.fill(buffer, (byte) 0);
            stream.close();
        }
        try {
            Config config = Config.parse(new ByteArrayInputStream(secret));
            if (config.getPeers().size() != 1
                    || config.getInterface().getAddresses().isEmpty()) {
                throw new IllegalArgumentException(
                        "Use a WireGuard profile with one peer and an interface address.");
            }
            // Validate each profile independently. The second profile is
            // validated together with the first by the link-only compiler.
            RootMultiTunnelPlan.validate(Collections.singletonList(
                    entry(slot, config)));
            String configuration = new String(secret, StandardCharsets.UTF_8);
            new SecureTunnelProfileStore(app).save(
                    new SecureTunnelProfileStore.Profile(
                            slot, configuration, VpnRouteModes.PROFILE, ""));
            record("Imported encrypted " + slot + " config (no secrets logged)");
            return slot + " saved in RootLab encrypted storage.";
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    /** Explicitly disable optional Home before Start; never alter profiles
     * while a link-ownership journal may still require exact Safe Stop. */
    String removeHomeProfile() throws Exception {
        if (RootIsolatedWireGuardPreferencesJournal.pendingOrUnknown(app)
                || RootIsolatedUidPolicyPreferencesJournal.pendingOrUnknown(app)) {
            return "HOME REMOVAL REFUSED: Safe Stop must finish first. "
                    + "Do not discard recovery ownership.";
        }
        if (!hasProfile(HOME)) return "Home not imported; no change.";
        new SecureTunnelProfileStore(app).delete(HOME);
        record("Optional Home encrypted profile removed while no journal pending");
        return "Home removed from this separate RootLab profile store. "
                + "The two Internet exits are unchanged; no kernel change.";
    }

    private Pair loadPair() throws Exception {
        SecureTunnelProfileStore.Profile first = null, second = null, home = null;
        for (SecureTunnelProfileStore.Profile saved :
                new SecureTunnelProfileStore(app).load()) {
            if (FIRST.equals(saved.name)) first = saved;
            if (SECOND.equals(saved.name)) second = saved;
            if (HOME.equals(saved.name)) home = saved;
        }
        if (first == null || second == null) {
            throw new ProfileRejected(
                    RootTwoPeerProfileReadiness.Reason.NEED_TWO_PROFILES);
        }
        Map<String, Config> configs = new HashMap<>();
        List<RootMultiTunnelPlan.Entry> routes = new ArrayList<>();
        String firstEndpoint = "";
        String firstLocalKey = "";
        boolean differentEndpoints = true;
        boolean differentClientKeys = true;
        for (SecureTunnelProfileStore.Profile stored :
                Arrays.asList(first, second)) {
            byte[] clear = stored.configuration.getBytes(StandardCharsets.UTF_8);
            Config parsed;
            try { parsed = Config.parse(new ByteArrayInputStream(clear)); }
            finally { Arrays.fill(clear, (byte) 0); }
            if (parsed.getPeers().size() != 1) {
                throw new IllegalArgumentException("Each exit requires exactly one peer.");
            }
            // Verify exact canonical WireGuard-to-setconf compatibility
            // before root preflight. This read-only check would have
            // identified upstream PreSharedKey casing in the previous APK.
            // Never include the secret-bearing exception message or string
            // in diagnostics.
            try {
                RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(
                        parsed.toWgQuickString());
            } catch (IllegalArgumentException unsupported) {
                throw new ProfileRejected(
                        RootTwoPeerProfileReadiness.Reason.PEER_SETCONF_FORMAT_UNSUPPORTED);
            }
            // A provider can legitimately publish one server peer key for
            // multiple regional endpoints. Compare ENDPOINT strings and the
            // local client public identity, not the server's public key.
            // Neither string is ever persisted in the diagnostics report.
            String endpoint = parsed.getPeers().get(0)
                    .getEndpoint().map(Object::toString).orElse("");
            String localKey = parsed.getInterface().getKeyPair()
                    .getPublicKey().toBase64();
            if (endpoint.isEmpty()) {
                throw new ProfileRejected(
                        RootTwoPeerProfileReadiness.Reason.INVALID_OR_AMBIGUOUS_PLAN);
            }
            if (firstEndpoint.isEmpty()) {
                firstEndpoint = endpoint;
                firstLocalKey = localKey;
            } else {
                differentEndpoints = !firstEndpoint.equals(endpoint);
                differentClientKeys = !firstLocalKey.equals(localKey);
            }
            // The compiler separately requires disjoint provider-assigned
            // IPv4/IPv6 interface hosts. We never invent new tunnel addresses.
            RootMultiTunnelPlan.Entry entry = entry(stored.name, parsed);
            routes.add(entry);
            configs.put(entry.device, parsed);
        }
        RootTwoPeerProfileReadiness.Reason check =
                RootTwoPeerProfileReadiness.assess(
                        routes, differentEndpoints, differentClientKeys);
        if (check != RootTwoPeerProfileReadiness.Reason.READY) {
            throw new ProfileRejected(check);
        }
        if (home == null) {
            return new Pair(RootIsolatedTwoPeerLinkPlan.compile(routes), configs, routes);
        }
        // Home is OPTIONAL and never a third Internet default.
        // This is a genuine independent WireGuard config, not a Tailscale
        // control-plane identity or an invented /32 host.
        byte[] homeBytes = home.configuration.getBytes(StandardCharsets.UTF_8);
        Config homeConfig;
        try { homeConfig = Config.parse(new ByteArrayInputStream(homeBytes)); }
        finally { Arrays.fill(homeBytes, (byte) 0); }
        if (homeConfig.getPeers().size() != 1) {
            throw new ProfileRejected(
                    RootTwoPeerProfileReadiness.Reason.HOME_PRIVATE_LAN_UNSUPPORTED);
        }
        try {
            RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(
                    homeConfig.toWgQuickString());
        } catch (IllegalArgumentException unsafe) {
            throw new ProfileRejected(
                    RootTwoPeerProfileReadiness.Reason.PEER_SETCONF_FORMAT_UNSUPPORTED);
        }
        String homeEndpoint = homeConfig.getPeers().get(0)
                .getEndpoint().map(Object::toString).orElse("");
        String homeLocalKey = homeConfig.getInterface().getKeyPair()
                .getPublicKey().toBase64();
        if (homeEndpoint.isEmpty()) {
            throw new ProfileRejected(
                    RootTwoPeerProfileReadiness.Reason.HOME_PRIVATE_LAN_UNSUPPORTED);
        }
        for (Config internetConfig : configs.values()) {
            String endpoint = internetConfig.getPeers().get(0)
                    .getEndpoint().map(Object::toString).orElse("");
            String localKey = internetConfig.getInterface().getKeyPair()
                    .getPublicKey().toBase64();
            if (homeEndpoint.equals(endpoint) || homeLocalKey.equals(localKey)) {
                throw new ProfileRejected(
                        RootTwoPeerProfileReadiness.Reason.HOME_IDENTITY_CONFLICT);
            }
        }
        RootMultiTunnelPlan.Entry homeRoute = entry(HOME, homeConfig);
        RootIsolatedWireGuardBootstrapPlan.Plan triple;
        try {
            triple = RootIsolatedThreePeerLinkPlan.compile(routes, homeRoute);
        } catch (IllegalArgumentException incompatible) {
            throw new ProfileRejected(
                    RootTwoPeerProfileReadiness.Reason.HOME_PRIVATE_LAN_UNSUPPORTED);
        }
        configs.put(homeRoute.device, homeConfig);
        routes.add(homeRoute);
        return new Pair(triple, configs, routes);
    }

    private static RootMultiTunnelPlan.Entry entry(String name, Config config) {
        List<String> peers = new ArrayList<>();
        for (Peer peer : config.getPeers()) {
            for (InetNetwork subnet : peer.getAllowedIps()) {
                peers.add(subnet.toString());
            }
        }
        List<String> hosts = new ArrayList<>();
        for (InetNetwork address : config.getInterface().getAddresses()) {
            hosts.add(address.toString());
        }
        return new RootMultiTunnelPlan.Entry(name, peers, hosts);
    }

    String profileReadiness() {
        try {
            Pair checked = loadPair(); // does not request root.
            record("Profile compatibility checked: READY ("
                    + checked.plan.devices + " links); no root operation");
            return "PROFILE CHECK: READY (" + checked.plan.devices
                    + " independent WireGuard links) — "
                    + RootTwoPeerProfileReadiness.explain(
                            RootTwoPeerProfileReadiness.Reason.READY)
                    + "\nNo kernel change has been attempted by this check.";
        } catch (ProfileRejected invalid) {
            record("Profile compatibility checked: " + invalid.reason.name()
                    + "; no root operation");
            return "PROFILE CHECK: " + invalid.reason.name() + "\n"
                    + invalid.getMessage()
                    + "\nNo kernel change has been attempted by this check.";
        } catch (Exception invalid) {
            record("Profile compatibility checked: IMPORTED_CONFIG_PARSE_ERROR; "
                    + "no root operation");
            return "PROFILE CHECK: IMPORTED_CONFIG_PARSE_ERROR\n"
                    + "The saved profile could not be parsed or securely loaded. "
                    + "No keys, addresses or exception details are included. "
                    + "No kernel change was attempted by this check.";
        }
    }

    String start() throws Exception {
        record("Multi-link Start requested; validating encrypted profiles");
        try {
            return startImpl();
        } catch (ProfileRejected invalid) {
            // This refusal occurs in loadPair(), before any RootShell,
            // journal write, or kernel mutation in this Start attempt.
            record("Two-peer Start refused at PROFILE_CHECK: "
                    + invalid.reason.name() + "; no kernel operation attempted");
            return "START REFUSED — " + invalid.reason.name() + "\n"
                    + invalid.getMessage()
                    + "\nThis attempt stopped before root networking.";
        } catch (Exception failed) {
            // Never persist RootShell/parser exception messages: they could
            // accidentally include a profile line or endpoint IP.
            record("Two-peer Start exception class="
                    + failed.getClass().getSimpleName()
                    + "; check whether exact-owned journal remains");
            throw failed;
        }
    }

    private String startImpl() throws Exception {
        Pair pair = loadPair();
        record("Multi-link PROFILE_CHECK=READY; entering ownership preflight");
        RootIsolatedWireGuardPreferencesJournal journal =
                new RootIsolatedWireGuardPreferencesJournal(app, pair.plan);
        if (!journal.empty()) {
            record("Start refused: a prior isolated session still has ownership");
            return "START REFUSED: prior owned kernel stages remain. Use Safe Stop.";
        }
        if (RootIsolatedUidPolicyPreferencesJournal.pendingOrUnknown(app)) {
            return "START REFUSED: pending UID policy ownership.";
        }
        if (RootlabDetachedMokaFirewall.pendingOrUnknown(app)) {
            return "START REFUSED: detached firewall journal pending. "
                    + "Use Exact-owned Safe Stop first.";
        }
        if (RootlabMokaIpv6OutputTest.pendingOrUnknown(app)) {
            return "START REFUSED: IPv6 Moka OUTPUT hook journal pending. "
                    + "Use Exact-owned Safe Stop first.";
        }
        RootShell shell = new RootShell(app);
        RootIsolatedWireGuardKernelAdapter backend =
                new RootIsolatedWireGuardKernelAdapter(app, shell, pair.configurations,
                        new RootlabTwoPeerSafetyGate(app, shell));
        RootIsolatedWireGuardTransaction.Outcome result =
                RootIsolatedWireGuardTransaction.start(pair.plan, backend, journal);
        record("Multi-link Start: " + result.stage
                + "; phase=" + result.failurePhase
                + "; reason=" + result.failureCode
                + "; connected stages=" + result.connected
                + "; cleanup=" + result.cleanupComplete
                + "; journal=" + result.remainingJournalEntries);
        if (!result.connected) {
            // Do not drown the actual fixed failure code in two verbose
            // handshake readouts. When the journal is 0, no peer was left
            // active by this transaction. Use explicit Status for details.
            return "MULTI-LINK START REFUSED.\n" + result.summary()
                    + "\nFor diagnostics, export the redacted report. "
                    + "No app routing was activated.";
        }
        return pair.plan.devices + " WG LINKS CONFIGURED. No Android apps are routed. "
                + "Handshakes may require a bound probe.\n"
                + result.summary() + "\n" + status();
    }

    String stop() throws Exception {
        record("Two-peer Safe Stop requested");
        try {
            return stopImpl();
        } catch (Exception failed) {
            record("Two-peer Safe Stop exception class="
                    + failed.getClass().getSimpleName()
                    + "; journal must not be discarded");
            throw failed;
        }
    }

    private String stopImpl() throws Exception {
        // Revoke the Moka-only IPv6 OUTPUT hook first. Never delete the
        // referenced chain or a Home WG link while this journal is pending.
        String hookStatus = new RootlabMokaIpv6OutputTest(app).recover();
        if (RootlabMokaIpv6OutputTest.pendingOrUnknown(app)) {
            record("Safe Stop paused: IPv6 Moka OUTPUT hook uncertain");
            return "SAFE STOP PAUSED: " + hookStatus
                    + "\nDetached firewall chains and WireGuard links were "
                    + "left intact. Do not uninstall or clear app data.";
        }
        // Recover the detached, never-hooked firewall stage BEFORE removing
        // the Home WireGuard link. A foreign/changed stage must retain journal.
        String detachedStatus = new RootlabDetachedMokaFirewall(app).recover();
        if (RootlabDetachedMokaFirewall.pendingOrUnknown(app)) {
            record("Safe Stop paused: detached firewall ownership uncertain");
            return "SAFE STOP PAUSED: " + detachedStatus
                    + "\nThe WireGuard link journal was not changed. "
                    + "Do not clear app data or update RootLab.";
        }
        if (!RootIsolatedWireGuardPreferencesJournal.pendingOrUnknown(app)) {
            // A rejected profile plan cannot write a new ownership journal.
            // However no journal alone is not proof that the kernel is clean:
            // never attempt a broad name-pattern-based cleanup.
            record("Safe Stop found no owned journal steps; no kernel mutation");
            return hookStatus + "\n" + detachedStatus + "\n"
                    + "NO JOURNALED TUNNEL STAGES. No owned kernel links removed. "
                    + "Absence of a tunnel journal does NOT audit global networking.";
        }
        Pair pair = loadPair();
        RootIsolatedWireGuardPreferencesJournal journal =
                new RootIsolatedWireGuardPreferencesJournal(app, pair.plan);
        boolean stagingClean = true;
        // A process crash during wg setconf may leave a temporary private
        // config file. Never abandon those secrets when Safe Stop is called;
        // only names from the exact stored plan may be removed.
        if (!journal.empty()) {
            for (RootMultiTunnelPlan.Entry entry : pair.entries) {
                try {
                    RootIsolatedWireGuardConfigHandoff.cleanupStaleOwnedFile(
                            app, entry.device);
                } catch (Exception uncertain) {
                    stagingClean = false;
                    record("Owned staging cleanup uncertain ("
                            + uncertain.getClass().getSimpleName() + ")");
                }
            }
        }
        RootShell shell = new RootShell(app);
        shell.start();
        new ToolsInstaller(app, shell).ensureToolsAvailable();
        RootIsolatedWireGuardKernelAdapter backend =
                new RootIsolatedWireGuardKernelAdapter(app, shell, pair.configurations,
                        new RootlabTwoPeerSafetyGate(app, shell));
        RootIsolatedWireGuardTransaction.Outcome result =
                RootIsolatedWireGuardTransaction.recover(backend, journal);
        if (!stagingClean) {
            record("Staging file audit required; do not delete lab data");
        }
        record("Safe Stop: " + result.stage + "; cleanup="
                + result.cleanupComplete + "; journal=" + result.remainingJournalEntries);
        return hookStatus + "\n" + detachedStatus + "\n"
                + result.summary() + "\n"
                + (stagingClean ? "" : "STAGED PRIVATE KEY FILE NEEDS AUDIT. "
                        + "Do not uninstall this lab.\n")
                + (result.cleanupComplete
                        ? "Owned link stages stopped; ordinary Android networking untouched."
                        : "STOP PAUSED. Do not change imported profiles or uninstall RootLab. "
                        + "Copy diagnostics and investigate exact ownership.");
    }

    /**
     * Read-only first gate for future Moka -> Home TCP/4533 routing.
     * This method MUST NOT add UID rules, firewall chains, DNS, or sockets.
     * A successful inventory is NOT permission to steer application packets.
     */
    String previewMokaHomeRouting() throws Exception {
        Pair pair = loadPair();
        if (pair.entries.size() != 3) {
            return "MOKA HOME ROUTING READINESS: REFUSED — import a Home profile first. "
                    + "No app traffic was routed.";
        }
        RootMultiTunnelPlan.Entry home = pair.entries.get(2);
        if (!HOME.equals(home.name)
                || !RootTwoExitHomeRoutingPreview.permitsHomeTarget(
                        home.peerRoutes, "10.0.0.169")) {
            return "MOKA HOME ROUTING READINESS: REFUSED — selected Home profile "
                    + "does not allow the numeric Navidrome destination.";
        }
        RootIsolatedWireGuardPreferencesJournal journal =
                new RootIsolatedWireGuardPreferencesJournal(app, pair.plan);
        if (journal.snapshot().size() != pair.plan.steps.size()
                || RootIsolatedUidPolicyPreferencesJournal.pendingOrUnknown(app)) {
            return "MOKA HOME ROUTING READINESS: REFUSED — complete journaled "
                    + "three-link Start required; UID ownership must be empty.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        new ToolsInstaller(app, shell).ensureToolsAvailable();
        String device = home.device;
        String expectedKey = pair.configurations.get(device).getInterface()
                .getKeyPair().getPublicKey().toBase64();
        List<String> actualKey = readSafe(shell, "wg show " + device + " public-key");
        if (actualKey.size() != 1 || !expectedKey.equals(actualKey.get(0).trim())) {
            return "MOKA HOME ROUTING READINESS: REFUSED — Home kernel identity changed.";
        }
        String routes = String.join("\n",
                readSafe(shell, "ip -4 route show table 51002"));
        for (String network : home.peerRoutes) {
            if (network.contains(":")) continue;
            if (RootIsolatedWireGuardKernelListing.privateRoute(
                    routes, 4, network, device)
                    != RootIsolatedWireGuardKernelListing.Match.EXACT) {
                return "MOKA HOME ROUTING READINESS: REFUSED — Home route drift.";
            }
        }
        List<String> lookup = readSafe(shell,
                "ip -4 route get 10.0.0.169 oif " + device);
        if (lookup.isEmpty() || !String.join(" ", lookup).contains("dev " + device)) {
            return "MOKA HOME ROUTING READINESS: REFUSED — Home route lookup mismatch.";
        }

        // Discover the installed Moka UID rather than assuming the prior
        // phone's UID. Never export the full installed-package inventory.
        int mokaCount = 0;
        String mokaUid = "";
        for (String line : readSafe(shell, "pm list packages -U")) {
            String lower = line.toLowerCase(java.util.Locale.ROOT);
            if (!lower.startsWith("package:") || !lower.contains("moka")) continue;
            int marker = line.lastIndexOf(" uid:");
            if (marker < 0) continue;
            String parsed = line.substring(marker + 5).trim();
            if (!parsed.matches("[0-9]{4,7}")) continue;
            mokaCount++;
            mokaUid = parsed;
        }
        if (mokaCount != 1) {
            return "MOKA HOME ROUTING READINESS: REFUSED — "
                    + (mokaCount == 0 ? "Moka package/UID not visible"
                            : "ambiguous Moka package matches")
                    + ". No UID policy or network changes.";
        }

        // A route lookup alone cannot prove no-fallback under link loss,
        // IPv6 coverage, or Android fwmark ownership. Those protections
        // must have a dedicated exact-owned policy transaction before Start.
        RootMokaHomePolicySafetyCase.Gate policyGate =
                RootMokaHomePolicySafetyCase.currentLabGate(
                        Integer.parseInt(mokaUid), true);
        record("Moka Home UID inventory verified; policy gate="
                + policyGate.name() + "; PREVIEW_ONLY; no UID policy");
        return "MOKA -> HOME READ-ONLY PREFLIGHT\n"
                + "Installed Moka candidate: unique; UID " + mokaUid + "\n"
                + "Home profile, identity, exact-owned journal: VERIFIED\n"
                + "Home private table 51002 and route to 10.0.0.169: VERIFIED\n"
                + "Planned destination: TCP 10.0.0.169:4533 only\n"
                + "FAIL-CLOSED POLICY GATE: " + policyGate.name() + "\n"
                + "Failure simulations: IPv4/IPv6 deny, underlay, TCP scope, "
                + "DNS, crash recovery, Safe Stop, link loss (CI only).\n"
                + "ACTIVATION LOCKED: no exact-owned UID policy, dual-stack "
                + "fail-closed firewall, underlay protection or crash recovery "
                + "proof in this lab.\n"
                + "No Android application packets were routed or blocked. "
                + "No DNS, IPv4/IPv6 rules, firewall, or VPN configuration changed.";
    }

    /**
     * READ ONLY: inspect Android's existing dual-stack filter OUTPUT hooks
     * and compile a canonical future firewall transaction. No -N/-A/-I/-D
     * or policy routing commands execute here.
     */
    /**
     * Explicitly requested root experiment. Stage only detached filter
     * chains; never attach OUTPUT or send real application packets.
     */
    /**
     * Real IPv6-only OUTPUT hook; user expressly opts into temporary Moka
     * IPv6 blocking. Never enables IPv4 app selection or DNS/routing changes.
     */
    String attachMokaIpv6Hook() throws Exception {
        if (RootlabMokaIpv6OutputTest.pendingOrUnknown(app)) {
            return "IPv6 MOKA HOOK REFUSED: existing journal needs Safe Stop.";
        }
        String readiness = previewMokaHomeRouting();
        java.util.regex.Matcher found = java.util.regex.Pattern.compile(
                "Installed Moka candidate: unique; UID ([0-9]{4,7})")
                .matcher(readiness);
        if (!readiness.startsWith("MOKA -> HOME READ-ONLY PREFLIGHT\n")
                || !found.find()) {
            return "IPv6 MOKA HOOK REFUSED: read-only Home preflight changed.";
        }
        Pair pair = loadPair();
        int uid = Integer.parseInt(found.group(1));
        String device = pair.entries.get(2).device;
        String result = new RootlabMokaIpv6OutputTest(app).attach(uid, device);
        record("Moka IPv6 OUTPUT trial: "
                + (result.startsWith("MOKA IPv6 OUTPUT HOOK VERIFIED")
                        ? "ATTACHED_UID_IPV6_ONLY" : "REFUSED_OR_RECOVERY_REQUIRED"));
        return result;
    }

    String stageDetachedMokaFirewall() throws Exception {
        String inventory = auditMokaHomeFirewall();
        if (!inventory.contains("DEVICE PRECHECK: NO IMMEDIATE COLLISION OBSERVED")) {
            return "DETACHED FIREWALL REFUSED: read-only inspection is not clean.";
        }
        if (RootlabDetachedMokaFirewall.pendingOrUnknown(app)
                || RootIsolatedUidPolicyPreferencesJournal.pendingOrUnknown(app)) {
            return "DETACHED FIREWALL REFUSED: previous policy ownership pending.";
        }
        Pair pair = loadPair();
        String preflight = previewMokaHomeRouting();
        java.util.regex.Matcher found = java.util.regex.Pattern.compile(
                "Installed Moka candidate: unique; UID ([0-9]{4,7})")
                .matcher(preflight);
        if (!preflight.startsWith("MOKA -> HOME READ-ONLY PREFLIGHT\n")
                || !found.find()) {
            return "DETACHED FIREWALL REFUSED: Home/Moka preflight changed.";
        }
        int uid = Integer.parseInt(found.group(1));
        String device = pair.entries.get(2).device;
        String result = new RootlabDetachedMokaFirewall(app).stage(uid, device);
        record("Detached firewall stage: "
                + (result.startsWith("DETACHED FIREWALL STAGE VERIFIED")
                        ? "VERIFIED_UNHOOKED" : "REFUSED_OR_RECOVERY_REQUIRED"));
        return result + "\nNo UID routing, DNS, OUTPUT hook or packet-policy "
                + "activation was performed.";
    }

    String auditMokaHomeFirewall() throws Exception {
        Pair pair = loadPair();
        if (pair.entries.size() != 3 || !HOME.equals(pair.entries.get(2).name)) {
            return "FIREWALL PILOT REFUSED: a separate Home profile is required.";
        }
        String preliminary = previewMokaHomeRouting();
        if (!preliminary.startsWith("MOKA -> HOME READ-ONLY PREFLIGHT\n")) {
            return "FIREWALL PILOT REFUSED: Moka/Home identity or journal is not ready.";
        }
        // The earlier preflight emits the UID after checking a unique Moka
        // package match. Never silently use UID 10300 across devices.
        java.util.regex.Matcher found = java.util.regex.Pattern.compile(
                "Installed Moka candidate: unique; UID ([0-9]{4,7})")
                .matcher(preliminary);
        if (!found.find()) {
            return "FIREWALL PILOT REFUSED: cannot establish the Moka UID.";
        }
        int uid = Integer.parseInt(found.group(1));
        String device = pair.entries.get(2).device;
        RootMokaHomeFirewallPilotPlan.Plan plan =
                RootMokaHomeFirewallPilotPlan.compile(uid, device);
        RootMokaHomeFirewallPilotTransaction.validate(plan);
        RootShell shell = new RootShell(app);
        shell.start();
        StringBuilder result = new StringBuilder(
                "MOKA HOME FIREWALL DEVICE INVENTORY (READ-ONLY)\n");
        boolean complete = true;
        for (int family : new int[]{4, 6}) {
            String tool = family == 4 ? "iptables" : "ip6tables";
            String chain = family == 4
                    ? RootMokaHomeFirewallPilotPlan.CHAIN4
                    : RootMokaHomeFirewallPilotPlan.CHAIN6;
            List<String> output = new ArrayList<>();
            int outputCode = shell.run(output,
                    tool + " -w -t filter -S OUTPUT 2>/dev/null");
            boolean readable = outputCode == 0 && !output.isEmpty();
            // A stale/foreign exact-name chain must never be adopted.
            boolean reservedChainPresent =
                    shell.run(null, tool + " -w -t filter -S " + chain
                            + " >/dev/null 2>&1") == 0;
            String outputText = String.join("\n", output);
            boolean reservedOutputHook = outputText.contains(
                    family == 4 ? RootMokaHomeFirewallPilotPlan.TAG4
                            : RootMokaHomeFirewallPilotPlan.TAG6)
                    || outputText.contains(" -j " + chain);
            boolean ownerHelp = shell.run(null,
                    tool + " -m owner -h >/dev/null 2>&1") == 0;
            boolean commentHelp = shell.run(null,
                    tool + " -m comment -h >/dev/null 2>&1") == 0;
            complete &= readable && !reservedChainPresent
                    && !reservedOutputHook && ownerHelp && commentHelp;
            result.append("IPv").append(family).append(": OUTPUT ")
                    .append(readable ? "READABLE" : "UNVERIFIED")
                    .append("; reserved name ")
                    .append(reservedChainPresent || reservedOutputHook
                            ? "OCCUPIED — REFUSE" : "NOT OBSERVED")
                    .append("; owner/comment syntax ")
                    .append(ownerHelp && commentHelp ? "ADVERTISED" : "UNVERIFIED")
                    .append('\n');
        }
        result.append(plan.summary()).append('\n');
        result.append("CANONICAL WRITE-AHEAD ORDER: two chains, IPv4 Home allow, ")
                .append("dual-stack terminal reject, then two UID OUTPUT hooks.\n");
        result.append("DEVICE PRECHECK: ")
                .append(complete ? "NO IMMEDIATE COLLISION OBSERVED"
                        : "NOT READY / REQUIRES MANUAL AUDIT")
                .append(". This is NOT packet evidence or approval to apply rules.\n")
                .append("ACTIVATION LOCKED: kernel backend, durable ownership, ")
                .append("packet-level IPv4/IPv6 no-fallback, DNS and crash recovery ")
                .append("are not yet verified. No firewall/routing/DNS changes.");
        record("Moka Home firewall inventory completed; preview only; "
                + (complete ? "syntax observed" : "refusal/unknown"));
        return result.toString();
    }

    String status() throws Exception {
        Pair pair = loadPair();
        RootShell shell = new RootShell(app);
        shell.start();
        new ToolsInstaller(app, shell).ensureToolsAvailable();
        StringBuilder out = new StringBuilder();
        RootIsolatedWireGuardPreferencesJournal journal =
                new RootIsolatedWireGuardPreferencesJournal(app, pair.plan);
        out.append("Own journal stages: ").append(journal.snapshot().size())
                .append('/').append(pair.plan.steps.size()).append('\n');
        List<RootIsolatedTwoPeerHandshakeAudit.Peer> peers = new ArrayList<>();
        for (RootMultiTunnelPlan.Entry route : pair.entries) {
            String device = route.device;
            Config profile = pair.configurations.get(device);
            String publicPeer = profile.getPeers().get(0)
                    .getPublicKey().toBase64();
            List<String> hands = readSafe(shell,
                    "wg show " + device + " latest-handshakes");
            List<String> transfer = readSafe(shell,
                    "wg show " + device + " transfer");
            RootIsolatedTwoPeerHandshakeAudit.Peer parsed =
                    RootIsolatedTwoPeerHandshakeAudit.inspect(
                            route.name, publicPeer, hands, transfer,
                            System.currentTimeMillis() / 1000L, 180);
            peers.add(parsed);
            out.append(parsed.publicSummary()).append('\n');
        }
        out.append("Two recent distinct Internet peer handshakes: ")
                .append(RootIsolatedTwoPeerHandshakeAudit.twoRecentDistinct(
                        peers.get(0), peers.get(1)) ? "YES" : "NOT YET");
        if (peers.size() == 3) {
            RootIsolatedTwoPeerHandshakeAudit.Peer home = peers.get(2);
            out.append("\nHome peer handshake: ")
                    .append(home.identityMatches && home.recentHandshake
                            ? "VERIFIED" : "NOT YET");
        } else {
            out.append("\nHome: not imported (optional WireGuard .conf)");
        }
        out.append("\nNo app UID, firewall or DNS changes. "
                + "Home and Internet peer routes exist only in private tables.");

        return out.toString();
    }

    String probe() throws Exception {
        Pair pair = loadPair();
        RootIsolatedWireGuardPreferencesJournal journal =
                new RootIsolatedWireGuardPreferencesJournal(app, pair.plan);
        int activeSteps = journal.snapshot().size();
        if (activeSteps != pair.plan.steps.size()) {
            // An unconnected RootLab must never issue a bound network probe.
            // Expose the actionable prerequisite instead of a generic
            // IllegalStateException that sounds like a root malfunction.
            record("Bound probes skipped: incomplete tunnel journal stages="
                    + activeSteps + "/" + pair.plan.steps.size());
            return "PROBE SKIPPED: selected peer links are not active (journal "
                    + activeSteps + "/" + pair.plan.steps.size() + "). "
                    + "A successful link Start is required first. "
                    + "No probe packets were sent.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        new ToolsInstaller(app, shell).ensureToolsAvailable();
        // A bound numeric ICMP probe is not an Android-app routing test.
        // Verify root's route lookup explicitly selects the requested WG
        // interface rather than silently falling back to WiFi/cellular.
        StringBuilder result = new StringBuilder();
        for (RootMultiTunnelPlan.Entry route : pair.entries) {
            if (HOME.equals(route.name)) {
                // Home is split-only: never send Internet 1.1.1.1 through it.
                continue;
            }
            String dev = route.device;
            List<String> identity = readSafe(shell, "wg show " + dev + " public-key");
            String wanted = pair.configurations.get(dev).getInterface()
                    .getKeyPair().getPublicKey().toBase64();
            if (identity.size() != 1 || !wanted.equals(identity.get(0).trim())) {
                result.append(route.name).append(": peer identity changed; probe skipped.\n");
                continue;
            }
            List<String> lookup = new ArrayList<>();
            int code = shell.run(lookup,
                    "ip -4 route get 1.1.1.1 oif " + dev);
            boolean bound = code == 0;
            String output = String.join(" ", lookup);
            if (!output.matches("(?s).*\\bdev " + dev + "\\b.*")) {
                bound = false;
            }
            if (!bound) {
                result.append(route.name)
                        .append(": kernel didn't confirm bound route; probe skipped.\n");
                continue;
            }
            int pingExit = shell.run(null, "ping -n -I " + dev
                    + " -c 1 -W 2 1.1.1.1 >/dev/null 2>&1");
            result.append(route.name).append(": bound ICMP probe ")
                    .append(pingExit == 0 ? "replied" : "attempted (no ICMP reply)")
                    .append(".\n");
        }
        record("User requested explicit bound numeric ICMP probes");
        return result + status();
    }

    /**
     * Optional Home-only test against one explicitly entered, numeric
     * private-LAN host. The imported Home AllowedIPs must include that
     * address; the exact Home route must be present in private table 51002.
     * No global route or app UID selector is ever installed. A failed
     * ICMP probe is not evidence that Navidrome's TCP port is unavailable.
     */
    String probeHome(String target) throws Exception {
        Pair pair = loadPair();
        if (pair.entries.size() != 3) {
            return "HOME PROBE SKIPPED: import a separate Home WireGuard .conf. "
                    + "An existing Tailscale session cannot be used as a WG file.";
        }
        RootMultiTunnelPlan.Entry home = pair.entries.get(2);
        if (!HOME.equals(home.name)
                || !RootTwoExitHomeRoutingPreview.permitsHomeTarget(
                        home.peerRoutes, target)) {
            return "HOME PROBE REFUSED: numeric target must be inside "
                    + "the imported Home WireGuard private-LAN routes. "
                    + "No packets were sent.";
        }
        RootIsolatedWireGuardPreferencesJournal journal =
                new RootIsolatedWireGuardPreferencesJournal(app, pair.plan);
        if (journal.snapshot().size() != pair.plan.steps.size()) {
            return "HOME PROBE SKIPPED: all three owned links must be active. "
                    + "No packets were sent.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        new ToolsInstaller(app, shell).ensureToolsAvailable();
        String dev = home.device;
        String wanted = pair.configurations.get(dev).getInterface()
                .getKeyPair().getPublicKey().toBase64();
        List<String> actual = readSafe(shell,
                "wg show " + dev + " public-key");
        if (actual.size() != 1 || !wanted.equals(actual.get(0).trim())) {
            return "HOME PROBE REFUSED: owned interface identity differs.";
        }
        String routes = String.join("\n", readSafe(shell,
                "ip -4 route show table 51002"));
        boolean ownedRoute = false;
        for (String network : home.peerRoutes) {
            if (RootIsolatedWireGuardKernelListing.privateRoute(
                    routes, 4, network, dev)
                    != RootIsolatedWireGuardKernelListing.Match.EXACT) {
                return "HOME PROBE REFUSED: exact Home private routes not verified.";
            }
            ownedRoute = true;
        }
        if (!ownedRoute) return "HOME PROBE REFUSED: no owned Home route.";
        List<String> lookup = new ArrayList<>();
        int result = shell.run(lookup,
                "ip -4 route get " + target + " oif " + dev);
        if (result != 0 || !String.join(" ", lookup).matches(
                "(?s).*\\bdev " + dev + "\\b.*")) {
            return "HOME PROBE REFUSED: kernel did not verify Home output device.";
        }
        int pingExit = shell.run(null, "ping -n -I " + dev
                + " -c 1 -W 2 " + target + " >/dev/null 2>&1");
        record("Manual Home bound LAN probe: "
                + (pingExit == 0 ? "replied" : "no ICMP reply")
                + " (target not logged)");
        return "HOME bound private LAN probe "
                + (pingExit == 0 ? "replied" : "attempted (no ICMP reply)")
                + ". This does not prove TCP/HTTPS access, per-app routing "
                + "or home-tunnel no-fallback protection.\n" + status();
    }

    /**
     * Optional numeric-only HTTP(S) diagnostic, explicitly bound by curl to
     * the verified WireGuard device. Does not install Android UID selectors.
     * Curl is NOT universally available on Android; in that case refuse
     * rather than attempt an unbound socket through ordinary networking.
     */
    String probeTcp(String slot, String target) throws Exception {
        final boolean homeProbe = HOME.equals(slot);
        if (!FIRST.equals(slot) && !SECOND.equals(slot) && !homeProbe) {
            return "TCP PROBE REFUSED: unknown tunnel slot. No packets sent.";
        }
        RootTcpProbeTarget address;
        try {
            address = RootTcpProbeTarget.parse(target);
        } catch (IllegalArgumentException invalid) {
            return "TCP PROBE REFUSED: numeric IPv4:port required. No packets sent.";
        }
        // The isolated three-link lab currently has only IPv4 private-table
        // probe verification. Do not invent an IPv6 safe route.
        if (address.family != 4) {
            return "TCP PROBE REFUSED: IPv6 bound path not verified.";
        }
        Pair pair = loadPair();
        RootMultiTunnelPlan.Entry selected = null;
        for (RootMultiTunnelPlan.Entry candidate : pair.entries) {
            if (slot.equals(candidate.name)) selected = candidate;
        }
        if (selected == null || (homeProbe && pair.entries.size() != 3)) {
            return "TCP PROBE SKIPPED: selected WireGuard link not imported.";
        }
        if (homeProbe && (address.port != 4533
                || !RootTwoExitHomeRoutingPreview.permitsHomeTarget(
                        selected.peerRoutes, address.address))) {
            return "HOME TCP PROBE REFUSED: requires Home AllowedIPs and port 4533.";
        }
        // Keep the public exit diagnostic tightly scoped. Numeric IP avoids
        // Android/system DNS, and port 443 tests TCP+TLS/HTTP, not just ICMP.
        if (!homeProbe && (!"1.1.1.1".equals(address.address)
                || address.port != 443)) {
            return "EXIT TCP PROBE REFUSED: only numeric 1.1.1.1:443 allowed.";
        }
        RootIsolatedWireGuardPreferencesJournal journal =
                new RootIsolatedWireGuardPreferencesJournal(app, pair.plan);
        if (journal.snapshot().size() != pair.plan.steps.size()) {
            return "TCP PROBE SKIPPED: complete exact-owned Start required. No packets sent.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        new ToolsInstaller(app, shell).ensureToolsAvailable();
        String dev = selected.device;
        String wanted = pair.configurations.get(dev).getInterface()
                .getKeyPair().getPublicKey().toBase64();
        List<String> identity = readSafe(shell, "wg show " + dev + " public-key");
        if (identity.size() != 1 || !wanted.equals(identity.get(0).trim())) {
            return "TCP PROBE REFUSED: kernel tunnel identity mismatch.";
        }
        int table = homeProbe ? 51002 : FIRST.equals(slot) ? 51000 : 51001;
        String listing = String.join("\n", readSafe(shell,
                "ip -4 route show table " + table));
        boolean matched = false;
        for (String network : selected.peerRoutes) {
            if (network.indexOf(':') >= 0) continue; // IPv4 only in this probe.
            if (RootIsolatedWireGuardKernelListing.privateRoute(
                    listing, 4, network, dev)
                    != RootIsolatedWireGuardKernelListing.Match.EXACT) {
                return "TCP PROBE REFUSED: private-table route identity changed.";
            }
            matched = true;
        }
        if (!matched) return "TCP PROBE REFUSED: empty private routes.";
        List<String> lookup = new ArrayList<>();
        if (shell.run(lookup, "ip -4 route get " + address.address
                + " oif " + dev) != 0
                || !String.join(" ", lookup).matches(
                        "(?s).*\\bdev " + dev + "\\b.*")) {
            return "TCP PROBE REFUSED: selected output interface not confirmed.";
        }
        // Only root's curl --interface can make this bounded probe; do NOT
        // silently substitute wget, nc, raw sockets or normal app networking.
        if (shell.run(null, "command -v curl >/dev/null 2>&1") != 0) {
            return "TCP PROBE SKIPPED: curl unavailable on this Android build. "
                    + "No TCP connection attempted.";
        }
        String url = (homeProbe ? "http://" : "https://")
                + address.label() + "/";
        // All parts are fixed or validated numeric values. Never print
        // curl's stderr (network details), URL, config or peer endpoints.
        List<String> response = new ArrayList<>();
        String command = "curl --ipv4 --noproxy '*' --interface " + dev
                + " --connect-timeout 3 --max-time 6 --silent "
                + " --output /dev/null --write-out '%{http_code}\\n' "
                + "'" + url + "' 2>/dev/null";
        int code = shell.run(response, command);
        String http = String.join("", response).trim();
        boolean httpValid = http.matches("[1-5][0-9]{2}");
        String outcome;
        if (code == 0 && httpValid) {
            outcome = "TCP+HTTP response received (HTTP " + http + ")";
        } else if (code == 28) {
            outcome = "attempted; connection timed out";
        } else if (code == 7) {
            outcome = "attempted; connection refused or unreachable";
        } else if (code == 60) {
            outcome = "TCP reached TLS validation; certificate verification failed";
        } else {
            outcome = "attempted; no verified HTTP response (curl code " + code + ")";
        }
        record(slot + " optional interface-bound TCP diagnostic: "
                + (code == 0 && httpValid ? "HTTP_RESPONSE" : "NO_HTTP_PROOF"));
        return slot + ": " + outcome + ". No Android app UID, DNS or "
                + "firewall changes. This does not prove per-app routing, "
                + "dual-stack no-fallback or kill-switch safety.\n" + status();
    }

    private static List<String> readSafe(RootShell shell, String command)
            throws Exception {
        List<String> lines = new ArrayList<>();
        if (shell.run(lines, command) != 0) return Collections.emptyList();
        return lines;
    }

    private synchronized void record(String safeMessage) {
        // Never put config, shell failures, keys, endpoint hosts or public
        // peer identity into this exportable log.
        String old = app.getSharedPreferences(LOG_PREF, Context.MODE_PRIVATE)
                .getString(LOG_KEY, "");
        String line = System.currentTimeMillis() + " " + safeMessage + "\n";
        String recent = old == null ? "" : old;
        if (recent.length() > 7500) {
            recent = recent.substring(recent.length() - 6000);
        }
        app.getSharedPreferences(LOG_PREF, Context.MODE_PRIVATE)
                .edit().putString(LOG_KEY, recent + line).commit();
    }

    String diagnostics() {
        String text = app.getSharedPreferences(LOG_PREF, Context.MODE_PRIVATE)
                .getString(LOG_KEY, "");
        return "Wonhee 0.15.68 · TWO EXITS + OPTIONAL HOME LAB (redacted)\n"
                + "Package: " + app.getPackageName() + "\n"
                + "Android Private DNS: must remain OFF\n"
                + "No app traffic is steered by this lab.\n"
                + (text == null ? "" : text);
    }
}
