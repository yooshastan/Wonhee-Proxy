package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

import com.wireguard.android.backend.Tunnel;
import com.wireguard.android.backend.WgQuickBackend;
import com.wireguard.android.util.RootShell;
import com.wireguard.android.util.ToolsInstaller;
import com.wireguard.config.Config;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Opt-in, rooted multi-tunnel experiment. Existing wnhome0/wnair0 control and
 * the Android VpnService backend are intentionally untouched. Every mutation
 * checks kernel identities and never installs a firewall or kill switch.
 */
final class RootMultiKernelSession {
    interface Callback { void completed(boolean ok, String message); }

    private static RootMultiKernelSession instance;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final File appCacheDir;
    private final RootShell shell;
    private final ToolsInstaller tools;
    private final WgQuickBackend backend;
    private final SharedPreferences routeLedger;
    private static final String ROUTE_LEDGER_KEY = "pending_or_installed_rules_v1";
    // Only links started and identity-verified by this process are in this map.
    private final Map<String, Active> managed = new LinkedHashMap<>();
    private volatile boolean busy;
    private boolean missingVersionNode;

    private static final class NamedTunnel implements Tunnel {
        private final String name;
        NamedTunnel(String name) { this.name = name; }
        @Override public String getName() { return name; }
        @Override public void onStateChange(State state) { }
    }

    private static final class Active {
        final String profileName;
        final String device;
        final Config configuration;
        final RootMultiTunnelPlan.Entry routes;
        Active(String profileName, Config configuration) {
            this.profileName = profileName;
            this.configuration = configuration;
            device = RootMultiTunnelPlan.interfaceName(profileName);
            List<String> destinations = new ArrayList<>();
            for (Peer peer : configuration.getPeers()) {
                for (InetNetwork route : peer.getAllowedIps()) destinations.add(route.toString());
            }
            List<String> addresses = new ArrayList<>();
            for (InetNetwork address : configuration.getInterface().getAddresses()) {
                addresses.add(address.toString());
            }
            routes = new RootMultiTunnelPlan.Entry(profileName, destinations, addresses);
        }
    }

    private RootMultiKernelSession(Context context) {
        Context app = context.getApplicationContext();
        appCacheDir = app.getCacheDir();
        shell = new RootShell(app);
        tools = new ToolsInstaller(app, shell);
        backend = new WgQuickBackend(app, shell, tools);
        backend.setMultipleTunnels(true);
        routeLedger = app.getSharedPreferences("wonhee_owned_split_routes", Context.MODE_PRIVATE);
    }

    static synchronized RootMultiKernelSession get(Context context) {
        if (instance == null) instance = new RootMultiKernelSession(context);
        return instance;
    }

    boolean isBusy() { return busy; }

    private synchronized boolean begin(Callback callback) {
        if (busy) {
            main.post(() -> callback.completed(false, "A kernel operation is already running."));
            return false;
        }
        busy = true;
        return true;
    }

    private void finish(Callback callback, boolean ok, String result) {
        busy = false;
        main.post(() -> callback.completed(ok, result));
    }

    private void rootReady() throws Exception {
        if (!WgQuickBackend.hasKernelSupport()) {
            throw new IllegalStateException("Kernel WireGuard support not detected.");
        }
        shell.start();
        tools.ensureToolsAvailable();
        missingVersionNode = shell.run(null, "test -r /sys/module/wireguard/version") != 0;
        if (shell.run(null, "wg --version >/dev/null 2>&1") != 0) {
            throw new IllegalStateException("Bundled WireGuard tools are unavailable.");
        }
    }

    private static Active load(SecureTunnelProfileStore.Profile profile) throws Exception {
        byte[] clear = profile.configuration.getBytes(StandardCharsets.UTF_8);
        Config raw;
        try { raw = Config.parse(new ByteArrayInputStream(clear)); }
        finally { Arrays.fill(clear, (byte) 0); }
        if (raw.getPeers().size() != 1 || raw.getInterface().getAddresses().isEmpty()) {
            throw new IllegalArgumentException("Multi-kernel alpha requires one peer and an interface address per profile.");
        }
        Config configured = VpnRouteModes.prepare(raw, profile.routeMode, profile.homeRoutes);
        Config withDns = VpnDnsOverride.prepare(configured, profile.homeDnsEnabled,
                profile.homeDnsServer);
        return new Active(profile.name, withDns);
    }

    private static List<Active> loadAll(List<SecureTunnelProfileStore.Profile> selected)
            throws Exception {
        List<Active> candidates = new ArrayList<>();
        for (SecureTunnelProfileStore.Profile profile : selected) candidates.add(load(profile));
        return candidates;
    }

    private static void validate(List<Active> candidates) {
        List<RootMultiTunnelPlan.Entry> entries = new ArrayList<>();
        for (Active candidate : candidates) entries.add(candidate.routes);
        RootMultiTunnelPlan.validate(entries);
    }

    private static List<RootMultiTunnelPlan.Entry> routeEntries(List<Active> candidates) {
        List<RootMultiTunnelPlan.Entry> entries = new ArrayList<>();
        for (Active active : candidates) entries.add(active.routes);
        return entries;
    }

    private String savedRules() {
        return routeLedger.getString(ROUTE_LEDGER_KEY, "");
    }

    private void saveRules(String value) {
        if (!routeLedger.edit().putString(ROUTE_LEDGER_KEY, value).commit()) {
            throw new IllegalStateException("Unable to persist the routing rollback ledger.");
        }
    }

    /** Previews all selected and in-process managed routes, without root writes. */
    void preview(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                List<Active> selected = loadAll(profiles);
                List<RootMultiTunnelPlan.Entry> entries = new ArrayList<>();
                for (Active active : selected) entries.add(active.routes);
                result = RootMultiTunnelPlan.preview(entries);
                ok = true;
            } catch (IllegalArgumentException invalid) {
                result = "Route preview refused: " + safeReason(invalid)
                        + " No network configuration changed.";
            } catch (Exception | LinkageError ignored) {
                result = "Unable to parse the selected encrypted profiles. "
                        + "No network configuration changed; secrets are not shown.";
            }
            finish(callback, ok, result);
        });
    }

    void inspect(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                rootReady();
                Set<String> running = backend.getRunningTunnelNames();
                StringBuilder text = new StringBuilder("READ-ONLY KERNEL TUNNELS\n");
                for (SecureTunnelProfileStore.Profile profile : profiles) {
                    String name = RootMultiTunnelPlan.interfaceName(profile.name);
                    boolean present = running.contains(name);
                    boolean ours = managed.containsKey(name);
                    String identity = "not checked";
                    if (present) {
                        try { identity = matches(new NamedTunnel(name), load(profile))
                                ? "MATCH" : "MISMATCH — NOT CONTROLLED"; }
                        catch (Exception | LinkageError ignored) { identity = "UNKNOWN — NOT CONTROLLED"; }
                    }
                    text.append(profile.name).append(" (").append(name).append("): ")
                            .append(present ? "UP" : "DOWN").append("; identity ")
                            .append(identity).append(ours ? "; managed here" : "; not managed here")
                            .append('\n');
                }
                text.append("Legacy Home/AirVPN links: ")
                        .append(running.contains("wnhome0") || running.contains("wnair0")
                                ? "present (managed by the original Control Center)"
                                : "not detected")
                        .append(". A present tunnel is never adopted automatically. "
                                + "This does not test app traffic, DNS, firewall or leaks.");
                result = text.toString();
                ok = true;
            } catch (Exception | LinkageError ignored) {
                result = "Could not inspect kernel interfaces. Check root and tools. "
                        + "No network configuration changed.";
            }
            finish(callback, ok, result);
        });
    }

    /** Read-only root route observations; does not promise app traffic isolation. */
    void auditRouting(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                List<Active> selected = loadAll(profiles);
                List<RootSplitRouteRules.Rule> planned = RootSplitRouteRules.plan(routeEntries(selected));
                rootReady();
                StringBuilder report = new StringBuilder("READ-ONLY ROOT ROUTE AUDIT\n");
                report.append(RootSplitRouteRules.preview(planned)).append('\n');
                List<RootSplitRouteRules.Rule> stored = RootSplitRouteRules.decode(savedRules());
                report.append("Wonhee rollback ledger: ").append(stored.isEmpty()
                        ? "EMPTY" : stored.size() + " proposed/installed rule(s)").append('\n');
                int reserved = countReservedRules();
                report.append("Live reserved-priority rules: ").append(reserved).append('\n');
                if (stored.isEmpty() && reserved > 0) {
                    report.append("WARNING — UNTRACKED ROUTING RULES: policy priorities "
                            + "12500–12799 exist, but Wonhee has no rollback ledger. "
                            + "Do not disconnect tunnels. Use Verify + recover matching "
                            + "rules before normal cleanup; ownership is not assumed.\n");
                } else if (!stored.isEmpty() && reserved != stored.size()) {
                    report.append("WARNING — RULE COUNT DIFFERS FROM ROLLBACK LEDGER. "
                            + "Inspect before changing tunnels.\n");
                }
                int matched = 0;
                for (RootSplitRouteRules.Rule rule : planned) {
                    String actual = routeDevice(rule.family, rule.probe);
                    boolean correct = rule.device.equals(actual);
                    if (correct) matched++;
                    report.append("IPv").append(rule.family).append(" ")
                            .append(rule.destination).append(" → ").append(actual.isEmpty()
                                    ? "NO ROUTE" : actual)
                            .append(correct ? " · MATCH" : " · MISMATCH")
                            .append('\n');
                }
                for (Active active : selected) {
                    for (String cidr : active.routes.peerRoutes) {
                        if (cidr.equals("0.0.0.0/0") || cidr.equals("::/0")) {
                            int family = cidr.contains(":") ? 6 : 4;
                            String probe = family == 6 ? "2606:4700:4700::1111" : "1.1.1.1";
                            String device = routeDevice(family, probe);
                            report.append("Public IPv").append(family).append(" → ")
                                    .append(device.isEmpty() ? "NO ROUTE" : device)
                                    .append(device.equals(active.device) ? " · MATCH" : " · MISMATCH")
                                    .append('\n');
                        }
                    }
                }
                report.append("Split-route matches: ").append(matched).append('/')
                        .append(planned.size()).append(". These are UID-0 route queries, "
                        + "NOT app traffic, DNS, endpoint, packet-capture or kill-switch tests.");
                result = report.toString();
                ok = true;
            } catch (Exception | LinkageError ignored) {
                result = "Route audit could not complete. Verify root, saved profiles, "
                        + "and any owned-rule ledger. No routes were changed.";
            }
            finish(callback, ok, result);
        });
    }

    /** Explicit, opt-in priority fix for Home-split plus Internet-default selection. */
    void applyRouting(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            boolean ledgerCommitted = false;
            try {
                if (!savedRules().isEmpty()) {
                    throw new IllegalStateException("Existing rollback ledger must be reviewed/removed first.");
                }
                List<Active> selected = loadAll(profiles);
                List<RootSplitRouteRules.Rule> rules = RootSplitRouteRules.plan(routeEntries(selected));
                if (rules.isEmpty()) {
                    throw new IllegalStateException("No conflicting default and split-route selections to correct.");
                }
                rootReady();
                Set<String> running = backend.getRunningTunnelNames();
                if (running.contains("wnhome0") || running.contains("wnair0")) {
                    throw new IllegalStateException("Legacy pair must be stopped first.");
                }
                Set<String> expected = new LinkedHashSet<>();
                for (Active active : selected) expected.add(active.device);
                for (String name : running) {
                    if (name.startsWith("wnm") && !expected.contains(name)) {
                        throw new IllegalStateException("Unselected experimental tunnel is running.");
                    }
                }
                for (Active active : selected) {
                    Tunnel link = new NamedTunnel(active.device);
                    if (!running.contains(active.device) || !matches(link, active)) {
                        throw new IllegalStateException("A selected interface is down or fails identity verification.");
                    }
                    List<String> marks = new ArrayList<>();
                    if (shell.run(marks, "wg show " + active.device + " fwmark") != 0
                            || marks.size() != 1
                            || !RootSplitRouteRules.transportBypassesRules(marks.get(0))) {
                        throw new IllegalStateException("WireGuard endpoint fwmark is not safely excluded.");
                    }
                }
                if (RootSplitRouteRules.reservedPriorityPresent(readRules(4))
                        || RootSplitRouteRules.reservedPriorityPresent(readRules(6))) {
                    throw new IllegalStateException("Priority 12500–12799 is already occupied; refusing collision.");
                }
                // Crash-safe intent record BEFORE any root mutation. Never delete rules
                // without this ledger and an exact kernel listing match.
                saveRules(RootSplitRouteRules.encode(rules));
                ledgerCommitted = true;
                for (RootSplitRouteRules.Rule rule : rules) {
                    if (shell.run(null, rule.add()) != 0 || !rulePresent(rule)) {
                        throw new IllegalStateException("Owned rule install/verification failed.");
                    }
                }
                for (RootSplitRouteRules.Rule rule : rules) {
                    if (!rule.device.equals(routeDevice(rule.family, rule.probe))) {
                        throw new IllegalStateException("Post-install route selection is still incorrect.");
                    }
                }
                ok = true;
                result = "Installed " + rules.size() + " Wonhee-owned split priority rule(s), "
                        + "verified against UID-0 route lookups. Android app routes, encrypted "
                        + "DNS, real packet paths and fail-closed behavior remain UNVERIFIED. "
                        + "Use Remove routing overrides before changing tunnels. No kill switch.";
            } catch (Exception | LinkageError ignored) {
                if (ledgerCommitted) {
                    try {
                        removeOwnedRules();
                        result = "Routing fix refused/failed. All owned rules were removed and "
                                + "the rollback ledger cleared. Kernel tunnels were left intact.";
                    } catch (Exception | LinkageError cleanupFailed) {
                        result = "ROUTING ROLLBACK INCOMPLETE: pending owned-rule ledger retained. "
                                + "Use Remove routing overrides or inspect with USB ADB. "
                                + "Do not change tunnels until recovered.";
                    }
                } else {
                    result = "Routing preflight refused. No routing rules changed. "
                            + "Confirm live selected identities, endpoint marks, and an empty "
                            + "reserved priority range before retrying.";
                }
            }
            finish(callback, ok, result);
        });
    }

    void removeRouting(List<SecureTunnelProfileStore.Profile> ignored, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                rootReady();
                int count = RootSplitRouteRules.decode(savedRules()).size();
                if (count == 0 && countReservedRules() > 0) {
                    throw new IllegalStateException("Untracked reserved-priority rules need recovery first.");
                }
                removeOwnedRules();
                ok = true;
                result = "Removed/verified " + count + " Wonhee-owned routing override(s). "
                        + "No tunnel was disconnected and no unknown routing rules were changed.";
            } catch (Exception | LinkageError ignoredFailure) {
                result = "ROUTING CLEANUP REFUSED/NOT VERIFIED. If the ledger is empty "
                        + "while priority-12500+ rules are present, select the matching "
                        + "profiles and use Verify + recover matching rules first. "
                        + "No unknown rule was intentionally removed.";
            }
            finish(callback, ok, result);
        });
    }

    /**
     * Explicit recovery of exact Wonhee-shaped rules after a lost app ledger.
     * A matching interface name alone is never enough: both WireGuard public
     * identities, selected CIDRs, every live priority and rule flags must agree.
     * No kernel route is created, deleted or changed by this action.
     */
    void recoverRouting(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                if (!savedRules().isEmpty()) {
                    throw new IllegalStateException("Existing rollback record requires normal removal.");
                }
                List<Active> selected = loadAll(profiles);
                List<RootSplitRouteRules.Rule> expected = RootSplitRouteRules.plan(routeEntries(selected));
                if (expected.isEmpty()) {
                    throw new IllegalStateException("Selection has no split-route priority rules.");
                }
                rootReady();
                Set<String> running = backend.getRunningTunnelNames();
                for (Active active : selected) {
                    if (!running.contains(active.device)
                            || !matches(new NamedTunnel(active.device), active)) {
                        throw new IllegalStateException("Selected interface identity is unverified.");
                    }
                }
                // Refuse adoption if ANY extra reserved rule exists, even if it
                // happens to share a destination or interface with this plan.
                if (countReservedRules() != expected.size()) {
                    throw new IllegalStateException("Unknown rules occupy the reserved priority range.");
                }
                for (RootSplitRouteRules.Rule rule : expected) {
                    if (!rulePresent(rule)) {
                        throw new IllegalStateException("An expected rule does not match the live kernel.");
                    }
                }
                saveRules(RootSplitRouteRules.encode(expected));
                ok = true;
                result = "Recovered rollback ownership record for " + expected.size()
                        + " exact matching kernel rule(s), after verifying both "
                        + "WireGuard public identities per selected profile. "
                        + "NO kernel rule or tunnel changed. The existing routes remain "
                        + "active; Remove Wonhee routing overrides is now available "
                        + "for explicit cleanup.";
            } catch (Exception | LinkageError ignored) {
                result = "Recovery refused: live priorities, selected encrypted "
                        + "profiles, or kernel identities did not match exactly. "
                        + "Nothing was adopted or changed. Keep USB ADB available.";
            }
            finish(callback, ok, result);
        });
    }

    private List<String> readRules(int family) throws Exception {
        List<String> output = new ArrayList<>();
        if (shell.run(output, "ip -" + family + " rule show") != 0) {
            throw new IllegalStateException("Cannot inspect policy rules.");
        }
        return output;
    }

    private int countReservedRules() throws Exception {
        int count = 0;
        for (int family : new int[] {4, 6}) {
            for (String line : readRules(family)) {
                int priority = RootSplitRouteRules.parsePriority(line);
                if (priority >= RootSplitRouteRules.FIRST_PRIORITY
                        && priority <= RootSplitRouteRules.LAST_PRIORITY) count++;
            }
        }
        return count;
    }

    private boolean rulePresent(RootSplitRouteRules.Rule rule) throws Exception {
        int matches = 0;
        for (String line : readRules(rule.family)) {
            if (RootSplitRouteRules.parsePriority(line) == rule.priority) {
                if (!rule.matchesListing(line)) {
                    throw new IllegalStateException("Policy rule priority is owned by another rule.");
                }
                matches++;
            }
        }
        if (matches > 1) throw new IllegalStateException("Ambiguous duplicate policy rule.");
        return matches == 1;
    }

    private String routeDevice(int family, String address) throws Exception {
        List<String> output = new ArrayList<>();
        if (shell.run(output, "ip -" + family + " route get " + address) != 0) return "";
        return RootKernelRouteAudit.selectedDevice(output);
    }

    private void removeOwnedRules() throws Exception {
        List<RootSplitRouteRules.Rule> rules = RootSplitRouteRules.decode(savedRules());
        for (int i = rules.size() - 1; i >= 0; i--) {
            RootSplitRouteRules.Rule rule = rules.get(i);
            if (rulePresent(rule)) {
                if (shell.run(null, rule.delete()) != 0 || rulePresent(rule)) {
                    throw new IllegalStateException("Owned rule removal could not be verified.");
                }
            }
        }
        saveRules("");
    }

    void connect(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            List<Active> started = new ArrayList<>();
            String stage = "profile validation";
            boolean success = false;
            String result;
            try {
                if (!savedRules().isEmpty()) {
                    throw new IllegalStateException("Remove owned routing overrides before connecting more tunnels.");
                }
                List<Active> requested = loadAll(profiles);
                List<Active> combined = new ArrayList<>(managed.values());
                Set<String> selectedNames = new LinkedHashSet<>();
                List<Active> newOnes = new ArrayList<>();
                for (Active active : requested) {
                    if (!selectedNames.add(active.device)) {
                        throw new IllegalArgumentException("Select each profile only once.");
                    }
                    if (!managed.containsKey(active.device)) newOnes.add(active);
                    else if (!sameIdentity(managed.get(active.device), active)) {
                        throw new IllegalArgumentException("Saved profile changed while its tunnel is managed. Disconnect first.");
                    }
                }
                combined.addAll(newOnes);
                validate(combined);
                stage = "root preflight";
                rootReady();
                if (countReservedRules() != 0) {
                    throw new IllegalStateException("Reserved policy rules are present; inspect ownership first.");
                }
                Set<String> running = backend.getRunningTunnelNames();
                if (running.contains("wnhome0") || running.contains("wnair0")) {
                    throw new IllegalStateException("Stop the legacy Home + AirVPN test first. Nothing was changed.");
                }
                for (String name : running) {
                    if (name.startsWith("wnm") && !managed.containsKey(name)) {
                        throw new IllegalStateException("Unmanaged multi-kernel interface exists. Inspect/recover it first.");
                    }
                }
                for (Active active : managed.values()) {
                    if (!running.contains(active.device) || !matches(new NamedTunnel(active.device), active)) {
                        throw new IllegalStateException("Managed kernel identity changed. Inspect before connecting.");
                    }
                }
                if (newOnes.isEmpty()) {
                    result = "Selected tunnels are already managed. No changes made.";
                    success = true;
                } else {
                    for (Active active : newOnes) {
                        stage = "starting " + active.device;
                        Tunnel link = new NamedTunnel(active.device);
                        // Refuse to overwrite a name that another process already uses.
                        if (running.contains(active.device)) {
                            throw new IllegalStateException("Selected interface already exists. Inspect before connecting.");
                        }
                        try {
                            setState(link, Tunnel.State.UP, active.configuration);
                            if (backend.getState(link) != Tunnel.State.UP || !matches(link, active)) {
                                throw new IllegalStateException("Kernel identity/state verification failed.");
                            }
                            managed.put(active.device, active);
                            started.add(active);
                        } catch (Exception | LinkageError problem) {
                            // wg-quick can leave a partial interface even when it reports failure.
                            if (backend.getRunningTunnelNames().contains(active.device)
                                    && matches(link, active)) {
                                managed.put(active.device, active);
                                started.add(active);
                            }
                            throw problem;
                        }
                    }
                    success = true;
                    result = "Connected " + started.size() + " verified multi-kernel tunnel(s). "
                            + "Independently test destinations, IPv4/IPv6, Android app routing, "
                            + "DNS and connectivity. No kill switch is installed.";
                }
            } catch (IllegalArgumentException invalid) {
                result = "Connection refused at " + stage + ": " + safeReason(invalid)
                        + ". No new configuration should remain active.";
            } catch (Exception | LinkageError ignored) {
                result = "Multi-tunnel connect failed at " + stage + ". "
                        + "Check root access, interface collisions and your selected routes. "
                        + "A partial interface may remain; inspect kernel status before retrying. "
                        + "Private configuration is not logged.";
            }
            if (!success && !started.isEmpty()) {
                boolean cleaned = rollback(started);
                result += cleaned ? " Started links were rolled back and checked."
                        : " ROLLBACK INCOMPLETE: inspect kernel links before retrying.";
            }
            finish(callback, success, result);
        });
    }

    /** Verify identities of every selected present link BEFORE disconnecting any. */
    void disconnect(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean success = false;
            String result;
            try {
                if (!savedRules().isEmpty()) {
                    finish(callback, false, "Remove Wonhee routing overrides before disconnecting "
                            + "tunnels. This avoids leaving policy rules pointing at stopped links.");
                    return;
                }
                List<Active> selected = loadAll(profiles);
                if (selected.isEmpty()) throw new IllegalArgumentException("Select a tunnel.");
                Set<String> seen = new LinkedHashSet<>();
                for (Active active : selected) {
                    if (!seen.add(active.device)) {
                        throw new IllegalArgumentException("Duplicate interface selection.");
                    }
                }
                rootReady();
                if (countReservedRules() != 0) {
                    finish(callback, false, "Reserved routing priority rules are still present. "
                            + "Removing tunnels now could strand Home routes. "
                            + "Verify/recover owned rules and remove them before disconnecting.");
                    return;
                }
                Set<String> running = backend.getRunningTunnelNames();
                for (Active active : selected) {
                    if (running.contains(active.device)
                            && !matches(new NamedTunnel(active.device), active)) {
                        throw new IllegalStateException("One selected interface has a different public identity.");
                    }
                }
                int stopped = 0;
                List<String> failed = new ArrayList<>();
                for (Active active : selected) {
                    Tunnel link = new NamedTunnel(active.device);
                    if (running.contains(active.device)) {
                        try {
                            setState(link, Tunnel.State.DOWN, active.configuration);
                        } catch (Exception | LinkageError ignored) { /* verify actual state below */ }
                    }
                    if (backend.getState(link) == Tunnel.State.DOWN) {
                        managed.remove(active.device);
                        stopped++;
                    } else failed.add(active.device);
                }
                success = failed.isEmpty();
                result = success
                        ? "Verified disconnect complete for " + stopped + " selected tunnel(s). "
                            + "Normal Wi-Fi/cellular connectivity remains possible. No kill switch installed."
                        : "Some links remain active: " + String.join(", ", failed)
                            + ". Review live status and retry; other interfaces were not touched.";
            } catch (Exception | LinkageError ignored) {
                result = "Disconnect refused: couldn't verify every selected interface or "
                        + "parse the matching encrypted profiles. Unknown links were not changed.";
            }
            finish(callback, success, result);
        });
    }

    private boolean rollback(List<Active> started) {
        boolean clean = true;
        for (int i = started.size() - 1; i >= 0; i--) {
            Active active = started.get(i);
            Tunnel link = new NamedTunnel(active.device);
            try {
                if (backend.getState(link) == Tunnel.State.UP) {
                    if (!matches(link, active)) { clean = false; continue; }
                    setState(link, Tunnel.State.DOWN, active.configuration);
                }
                if (backend.getState(link) == Tunnel.State.DOWN) managed.remove(active.device);
                else clean = false;
            } catch (Exception | LinkageError ignored) { clean = false; }
        }
        return clean;
    }

    private boolean sameIdentity(Active left, Active right) {
        // Saved DNS/routes may have changed without changing WireGuard keys;
        // do not quietly treat a changed runtime configuration as already live.
        return left.configuration.toWgQuickString().equals(right.configuration.toWgQuickString());
    }

    private boolean matches(Tunnel link, Active expected) throws Exception {
        List<String> interfaceKey = new ArrayList<>();
        List<String> peers = new ArrayList<>();
        // link name is strictly generated SHA-256 hex, never user shell input.
        if (shell.run(interfaceKey, "wg show " + link.getName() + " public-key") != 0
                || shell.run(peers, "wg show " + link.getName() + " peers") != 0
                || interfaceKey.size() != 1 || peers.size() != 1) return false;
        return expected.configuration.getInterface().getKeyPair().getPublicKey().toBase64()
                .equals(interfaceKey.get(0).trim())
                && expected.configuration.getPeers().get(0).getPublicKey().toBase64()
                .equals(peers.get(0).trim());
    }

    private void setState(Tunnel tunnel, Tunnel.State state, Config configuration) throws Exception {
        if (!missingVersionNode) {
            backend.setState(tunnel, state, configuration);
            return;
        }
        File tmp = new File(appCacheDir, "tmp");
        if (!tmp.isDirectory() && !tmp.mkdir()) {
            throw new IllegalStateException("Cannot create secure temporary WireGuard directory.");
        }
        File config = new File(tmp, tunnel.getName() + ".conf");
        try {
            try (FileOutputStream out = new FileOutputStream(config, false)) {
                out.write(configuration.toWgQuickString().getBytes(StandardCharsets.UTF_8));
            }
            int exit = shell.run(null, "wg-quick " + (state == Tunnel.State.UP ? "up " : "down ")
                    + "'" + config.getAbsolutePath() + "'");
            if (exit != 0) throw new IllegalStateException("wg-quick command failed.");
        } finally {
            //noinspection ResultOfMethodCallIgnored
            config.delete();
        }
    }

    private static String safeReason(IllegalArgumentException invalid) {
        // Errors from the WireGuard configuration parser may include secrets.
        // Only approved, static preflight text is returned to the screen.
        String reason = invalid.getMessage();
        if (reason == null) return "Invalid profile or route policy";
        if (reason.startsWith("Overlapping tunnel destinations:")
                || reason.startsWith("Overlapping tunnel interface networks:")
                || reason.equals("Selected profiles need unique names and interfaces.")
                || reason.equals("Select at least one tunnel.")
                || reason.equals("Too many selected profiles for this alpha.")
                || reason.equals("Every tunnel needs routes and an interface address.")
                || reason.equals("Routes and interface addresses must be numeric CIDRs.")
                || reason.equals("Select each profile only once.")) return reason;
        return "Invalid or changed profile configuration (details hidden)";
    }
}
