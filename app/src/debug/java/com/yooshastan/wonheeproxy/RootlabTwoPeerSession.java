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
        if (!FIRST.equals(slot) && !SECOND.equals(slot)) {
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

    private Pair loadPair() throws Exception {
        SecureTunnelProfileStore.Profile first = null, second = null;
        for (SecureTunnelProfileStore.Profile saved :
                new SecureTunnelProfileStore(app).load()) {
            if (FIRST.equals(saved.name)) first = saved;
            if (SECOND.equals(saved.name)) second = saved;
        }
        if (first == null || second == null) {
            throw new ProfileRejected(
                    RootTwoPeerProfileReadiness.Reason.NEED_TWO_PROFILES);
        }
        Map<String, Config> configs = new HashMap<>();
        List<RootMultiTunnelPlan.Entry> routes = new ArrayList<>();
        String firstPeer = "";
        for (SecureTunnelProfileStore.Profile stored :
                Arrays.asList(first, second)) {
            byte[] clear = stored.configuration.getBytes(StandardCharsets.UTF_8);
            Config parsed;
            try { parsed = Config.parse(new ByteArrayInputStream(clear)); }
            finally { Arrays.fill(clear, (byte) 0); }
            if (parsed.getPeers().size() != 1) {
                throw new IllegalArgumentException("Each exit requires exactly one peer.");
            }
            String publicPeer = parsed.getPeers().get(0)
                    .getPublicKey().toBase64();
            if (!firstPeer.isEmpty() && firstPeer.equals(publicPeer)) {
                throw new ProfileRejected(
                        RootTwoPeerProfileReadiness.Reason.SAME_SERVER_PEER);
            }
            if (firstPeer.isEmpty()) {
                firstPeer = publicPeer;
            }
            // Many VPN providers intentionally reuse a client's local key
            // across regions. This is okay for two separate named links,
            // provided the remote peer and interface host addresses differ.
            // The link-only compiler enforces non-overlapping local addresses.
            RootMultiTunnelPlan.Entry entry = entry(stored.name, parsed);
            routes.add(entry);
            configs.put(entry.device, parsed);
        }
        RootTwoPeerProfileReadiness.Reason check =
                RootTwoPeerProfileReadiness.assess(routes, true);
        if (check != RootTwoPeerProfileReadiness.Reason.READY) {
            throw new ProfileRejected(check);
        }
        return new Pair(RootIsolatedTwoPeerLinkPlan.compile(routes), configs, routes);
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
            loadPair(); // parses profile metadata, does NOT request root.
            return "PROFILE CHECK: READY — "
                    + RootTwoPeerProfileReadiness.explain(
                            RootTwoPeerProfileReadiness.Reason.READY)
                    + "\nNo kernel change has been attempted by this check.";
        } catch (ProfileRejected invalid) {
            return "PROFILE CHECK: " + invalid.reason.name() + "\n"
                    + invalid.getMessage()
                    + "\nNo kernel change has been attempted by this check.";
        } catch (Exception invalid) {
            return "PROFILE CHECK: IMPORTED_CONFIG_PARSE_ERROR\n"
                    + "The saved profile could not be parsed or securely loaded. "
                    + "No keys, addresses or exception details are included. "
                    + "No kernel change was attempted by this check.";
        }
    }

    String start() throws Exception {
        record("Two-peer Start requested; validating encrypted profiles");
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
        record("Two-peer PROFILE_CHECK=READY; entering ownership preflight");
        RootIsolatedWireGuardPreferencesJournal journal =
                new RootIsolatedWireGuardPreferencesJournal(app, pair.plan);
        if (!journal.empty()) {
            record("Start refused: a prior isolated session still has ownership");
            return "START REFUSED: prior owned kernel stages remain. Use Safe Stop.";
        }
        if (RootIsolatedUidPolicyPreferencesJournal.pendingOrUnknown(app)) {
            return "START REFUSED: pending UID policy ownership.";
        }
        RootShell shell = new RootShell(app);
        RootIsolatedWireGuardKernelAdapter backend =
                new RootIsolatedWireGuardKernelAdapter(app, shell, pair.configurations,
                        new RootlabTwoPeerSafetyGate(app, shell));
        RootIsolatedWireGuardTransaction.Outcome result =
                RootIsolatedWireGuardTransaction.start(pair.plan, backend, journal);
        record("Two-peer Start: " + result.stage + "; connected stages="
                + result.connected + "; cleanup=" + result.cleanupComplete
                + "; journal=" + result.remainingJournalEntries);
        return (result.connected
                ? "TWO PEER LINKS CONFIGURED. No Android apps are routed. "
                + "Handshakes may require a bound probe.\n"
                : "TWO PEER START REFUSED.\n")
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
        return result.summary() + "\n"
                + (stagingClean ? "" : "STAGED PRIVATE KEY FILE NEEDS AUDIT. "
                        + "Do not uninstall this lab.\n")
                + (result.cleanupComplete
                        ? "Owned link stages stopped; ordinary Android networking untouched."
                        : "STOP PAUSED. Do not change imported profiles or uninstall RootLab. "
                        + "Copy diagnostics and investigate exact ownership.");
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
        out.append("Two recent distinct peer handshakes: ")
                .append(RootIsolatedTwoPeerHandshakeAudit.twoRecentDistinct(
                        peers.get(0), peers.get(1)) ? "YES" : "NOT YET")
                .append("\nNo app UID, firewall or DNS changes. "
                        + "Default peer routes are restricted to private tables.");
        return out.toString();
    }

    String probe() throws Exception {
        Pair pair = loadPair();
        RootIsolatedWireGuardPreferencesJournal journal =
                new RootIsolatedWireGuardPreferencesJournal(app, pair.plan);
        if (journal.snapshot().size() != pair.plan.steps.size()) {
            throw new IllegalStateException(
                    "Both links must be fully journaled before bound traffic probes.");
        }
        RootShell shell = new RootShell(app);
        shell.start();
        new ToolsInstaller(app, shell).ensureToolsAvailable();
        // A bound numeric ICMP probe is not an Android-app routing test.
        // Verify root's route lookup explicitly selects the requested WG
        // interface rather than silently falling back to WiFi/cellular.
        StringBuilder result = new StringBuilder();
        for (RootMultiTunnelPlan.Entry route : pair.entries) {
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
        return "Wonhee 0.15.62 · TWO PEER LAB (redacted)\n"
                + "Package: " + app.getPackageName() + "\n"
                + "Android Private DNS: must remain OFF\n"
                + "No app traffic is steered by this lab.\n"
                + (text == null ? "" : text);
    }
}
