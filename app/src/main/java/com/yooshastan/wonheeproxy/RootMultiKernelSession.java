package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;

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
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

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
    private final Context appContext;
    private final RootShell shell;
    private final ToolsInstaller tools;
    private final WgQuickBackend backend;
    private final SharedPreferences routeLedger;
    private final RootMultiRecoveryPreferences recovery;
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
        appContext = app;
        appCacheDir = app.getCacheDir();
        shell = new RootShell(app);
        tools = new ToolsInstaller(app, shell);
        backend = new WgQuickBackend(app, shell, tools);
        backend.setMultipleTunnels(true);
        routeLedger = app.getSharedPreferences("wonhee_owned_split_routes", Context.MODE_PRIVATE);
        recovery = new RootMultiRecoveryPreferences(app);
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

    String recoveryStatus() { return recovery.summary(); }

    private static String configDigest(Active active) throws Exception {
        // Include keys, routes and DNS overrides without persisting plaintext.
        byte[] bytes = active.configuration.toWgQuickString().getBytes(StandardCharsets.UTF_8);
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder hex = new StringBuilder(64);
            for (byte b : hash) hex.append(String.format(java.util.Locale.ROOT, "%02x", b & 0xff));
            return hex.toString();
        } finally { Arrays.fill(bytes, (byte) 0); }
    }

    private void verifyRecoveryRules() throws Exception {
        List<RootSplitRouteRules.Rule> owned = RootSplitRouteRules.decode(savedRules());
        if (countReservedRules() != owned.size()) {
            throw new IllegalStateException("Reserved policy rules do not match the owned ledger.");
        }
        for (RootSplitRouteRules.Rule rule : owned) {
            if (!rulePresent(rule)) {
                throw new IllegalStateException("Owned kernel route missing or changed.");
            }
        }
    }

    /** Explicit opt-in for the exact set of presently connected root profiles. */
    void enableAutomaticRecovery(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                List<Active> selected = loadAll(profiles);
                validate(selected);
                rootReady();
                verifyRecoveryRules();
                Set<String> running = backend.getRunningTunnelNames();
                if (running.contains("wnhome0") || running.contains("wnair0")) {
                    throw new IllegalStateException("Legacy tunnel pair is still present.");
                }
                Set<String> expected = new LinkedHashSet<>();
                List<RootMultiRecoveryPreferences.Entry> entries = new ArrayList<>();
                for (Active active : selected) {
                    if (!expected.add(active.device) || !running.contains(active.device)
                            || !matches(new NamedTunnel(active.device), active)
                            || backend.getState(new NamedTunnel(active.device)) != Tunnel.State.UP) {
                        throw new IllegalStateException("One selected link is absent or mismatched.");
                    }
                    entries.add(new RootMultiRecoveryPreferences.Entry(active.profileName,
                            configDigest(active)));
                }
                for (String iface : running) {
                    if (iface.startsWith("wnm") && !expected.contains(iface)) {
                        throw new IllegalStateException("Unknown or unselected root multi link present.");
                    }
                }
                for (Active active : selected) managed.put(active.device, active);
                recovery.enable(entries);
                RootMultiRecoveryScheduler.update(appContext);
                RootMultiRecoveryMonitor.update(appContext);
                ok = true;
                result = "PRODUCT BATCH C — OPTED IN for " + entries.size()
                        + " identity-verified currently UP tunnel(s). Recovery is best effort "
                        + "at network handoff, after process restart and via deferred Android jobs. "
                        + "If routes or saved profiles change, recovery refuses. Manual stop wins. "
                        + "NO kill switch; unprotected traffic remains possible.";
            } catch (Exception | LinkageError problem) {
                result = "Recovery opt-in REFUSED: selected tunnels, saved routing ledger "
                        + "or identities could not be verified. No recovery consent was added; "
                        + "no kernel change was made.";
            }
            finish(callback, ok, result);
        });
    }

    void disableAutomaticRecovery(Callback callback) {
        if (!recovery.disable()) {
            main.post(() -> callback.completed(false, "Could not persist recovery disable request."));
            return;
        }
        RootMultiRecoveryScheduler.update(appContext);
        RootMultiRecoveryMonitor.update(appContext);
        main.post(() -> callback.completed(true,
                "PRODUCT BATCH C recovery disabled. Running tunnels and routes were NOT changed. "
                        + "No kill switch is installed."));
    }

    /** Serialize root work; restore only consented, cryptographically identified links. */
    void recoverSavedIfDesired(Callback callback) {
        recoverSavedIfDesired(callback, () -> false);
    }

    void recoverSavedIfDesired(Callback callback, BooleanSupplier cancelled) {
        if (!recovery.canAttempt(System.currentTimeMillis())) {
            main.post(() -> callback.completed(false,
                    "Recovery is off, manually stopped, backing off, or exhausted. "
                            + recovery.summary()));
            return;
        }
        if (!begin(callback)) return;
        worker.execute(() -> {
            List<Active> started = new ArrayList<>();
            boolean ok = false;
            String result;
            try {
                if (cancelled.getAsBoolean()
                        || !recovery.canAttempt(System.currentTimeMillis())) {
                    throw new IllegalStateException("Recovery intent changed.");
                }
                List<RootMultiRecoveryPreferences.Entry> approved = recovery.selection();
                Map<String, SecureTunnelProfileStore.Profile> saved = new LinkedHashMap<>();
                for (SecureTunnelProfileStore.Profile profile :
                        new SecureTunnelProfileStore(appContext).load()) {
                    saved.put(profile.name, profile);
                }
                List<Active> expected = new ArrayList<>();
                Set<String> devices = new LinkedHashSet<>();
                for (RootMultiRecoveryPreferences.Entry entry : approved) {
                    SecureTunnelProfileStore.Profile profile = saved.get(entry.name);
                    if (profile == null) throw new IllegalStateException("Profile removed.");
                    Active active = load(profile);
                    if (!entry.digest.equals(configDigest(active)) || !devices.add(active.device)) {
                        throw new IllegalStateException("Approved profile edited or duplicated.");
                    }
                    expected.add(active);
                }
                validate(expected);
                rootReady();
                verifyRecoveryRules();
                Set<String> running = backend.getRunningTunnelNames();
                if (running.contains("wnhome0") || running.contains("wnair0")) {
                    throw new IllegalStateException("Legacy root pair present.");
                }
                for (String iface : running) {
                    if (iface.startsWith("wnm") && !devices.contains(iface)) {
                        throw new IllegalStateException("Unknown kernel interface present.");
                    }
                }
                for (Active active : expected) {
                    if (running.contains(active.device)) {
                        Tunnel link = new NamedTunnel(active.device);
                        if (backend.getState(link) != Tunnel.State.UP || !matches(link, active)) {
                            throw new IllegalStateException("Running link identity changed.");
                        }
                        Active prior = managed.get(active.device);
                        if (prior != null && !sameIdentity(prior, active)) {
                            throw new IllegalStateException("Managed profile identity changed.");
                        }
                    }
                }
                for (Active active : expected) {
                    if (running.contains(active.device)) {
                        managed.put(active.device, active);
                        continue;
                    }
                    if (cancelled.getAsBoolean()
                            || !recovery.canAttempt(System.currentTimeMillis())) {
                        throw new IllegalStateException("Recovery cancelled by user.");
                    }
                    if (backend.getRunningTunnelNames().contains(active.device)) {
                        throw new IllegalStateException("Kernel interface appeared during recovery.");
                    }
                    verifyRecoveryRules();
                    Tunnel link = new NamedTunnel(active.device);
                    try {
                        setState(link, Tunnel.State.UP, active.configuration);
                        if (backend.getState(link) != Tunnel.State.UP || !matches(link, active)) {
                            throw new IllegalStateException("Restored link failed identity check.");
                        }
                        managed.put(active.device, active);
                        started.add(active);
                    } catch (Exception | LinkageError failure) {
                        if (backend.getRunningTunnelNames().contains(active.device)
                                && matches(link, active) && !started.contains(active)) {
                            started.add(active);
                            managed.put(active.device, active);
                        }
                        throw failure;
                    }
                    if (cancelled.getAsBoolean()) {
                        throw new IllegalStateException("Background job stopped by Android.");
                    }
                }
                if (cancelled.getAsBoolean()
                        || !recovery.canAttempt(System.currentTimeMillis())) {
                    throw new IllegalStateException("Recovery cancelled by user.");
                }
                recovery.success(!started.isEmpty());
                ok = true;
                result = "PRODUCT BATCH C: " + started.size() + " missing identity-verified "
                        + "link(s) restored; " + expected.size() + " selected tunnel(s) UP. "
                        + "No firewall/routing/DNS changes. NOT proof of end-to-end connectivity "
                        + "or leak-free protection; kill switch remains OFF.";
            } catch (Exception | LinkageError ignored) {
                boolean clean = rollback(started);
                if (!cancelled.getAsBoolean() && recovery.enabled() && recovery.desired()
                        && !recovery.manuallyStopped()) {
                    recovery.failure(System.currentTimeMillis());
                }
                result = "PRODUCT BATCH C recovery refused/failed: profile fingerprint, "
                        + "kernel identity, route ledger, or runtime precondition changed. "
                        + (clean ? "Newly started links rolled back if needed. "
                                : "ROLLBACK INCOMPLETE: inspect links manually. ")
                        + "No unapproved interfaces were touched; kill switch OFF.";
            }
            RootMultiRecoveryScheduler.afterAttempt(appContext);
            RootMultiRecoveryMonitor.update(appContext);
            finish(callback, ok, result);
        });
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

    /**
     * Batch C: collect a multi-profile guard readiness snapshot without adding
     * iptables, ip6tables, DNS interception or a VPN lockdown rule. This is a
     * development gate, not a protection enable button.
     */
    void auditProtection(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean inspected = false;
            String result;
            try {
                List<Active> selected = loadAll(profiles);
                List<RootMultiTunnelPlan.Entry> entries = routeEntries(selected);
                RootMultiTunnelPlan.validate(entries);
                List<RootSplitRouteRules.Rule> split = RootSplitRouteRules.plan(entries);
                rootReady();
                Set<String> running = backend.getRunningTunnelNames();
                boolean allMatched = true;
                boolean allEndpoints = true;
                boolean transportBypass = true;
                boolean distinctMarks = true;
                Set<Long> observedMarks = new LinkedHashSet<>();
                StringBuilder report = new StringBuilder("BATCH C — READ-ONLY NETWORK PROTECTION GATE\n");
                report.append("Selected independent tunnels: ").append(selected.size()).append('\n');
                for (Active active : selected) {
                    Tunnel link = new NamedTunnel(active.device);
                    boolean identity = running.contains(active.device) && matches(link, active);
                    allMatched &= identity;
                    List<String> markOutput = new ArrayList<>();
                    boolean markRead = identity && shell.run(markOutput,
                            "wg show " + active.device + " fwmark") == 0;
                    long mark = markRead ? RootFirewallMark.parse(markOutput) : 0;
                    boolean exempt = mark > 0 && (mark & RootSplitRouteRules.MARK_MASK) != 0;
                    transportBypass &= exempt;
                    if (mark == 0 || !observedMarks.add(mark)) distinctMarks = false;
                    List<String> endpointOutput = new ArrayList<>();
                    boolean numericEndpoint = identity && shell.run(endpointOutput,
                            "wg show " + active.device + " endpoints") == 0
                            && RootWireGuardEndpoint.hasSingleNumericEndpoint(endpointOutput);
                    allEndpoints &= numericEndpoint;
                    report.append(active.profileName).append(" (" + active.device + "): ")
                            .append(identity ? "UP / PUBLIC IDENTITY MATCH" : "DOWN OR IDENTITY UNVERIFIED")
                            .append("; UDP mark ").append(RootFirewallMark.display(mark))
                            .append("; endpoint ").append(numericEndpoint ? "NUMERIC" : "UNVERIFIED")
                            .append("; last handshake ").append(identity
                                    ? handshakeAge(active.device) : "unavailable").append('\n');
                }
                boolean extra = false;
                for (String name : running) {
                    if (name.startsWith("wnm")) {
                        boolean selectedName = false;
                        for (Active active : selected) selectedName |= active.device.equals(name);
                        if (!selectedName) extra = true;
                    }
                }
                report.append("Unselected experimental interfaces present: ")
                        .append(extra ? "YES" : "NO").append('\n');
                int routeMatches = 0;
                for (RootSplitRouteRules.Rule rule : split) {
                    if (rule.device.equals(routeDevice(rule.family, rule.probe))) routeMatches++;
                }
                report.append("Home/private split root routes: ").append(routeMatches)
                        .append('/').append(split.size()).append(" matched\n");
                for (int family : new int[] {4, 6}) {
                    String address = family == 4 ? "1.1.1.1" : "2606:4700:4700::1111";
                    String expected = RootProtectionPolicy.expectedDevice(entries, address);
                    String selectedDevice = routeDevice(family, address);
                    report.append("Public IPv").append(family).append(" default: ")
                            .append(RootProtectionPolicy.hasInternetDefault(entries, family)
                                    ? expected.equals(selectedDevice) ? "MATCH" : "MISMATCH"
                                    : "NOT CONFIGURED — leak/fallback risk")
                            .append('\n');
                }
                boolean firewall4 = shell.run(null,
                        "iptables -w -L OUTPUT -n >/dev/null 2>&1") == 0;
                boolean firewall6 = shell.run(null,
                        "ip6tables -w -L OUTPUT -n >/dev/null 2>&1") == 0;
                boolean mark4 = shell.run(null,
                        "iptables -m mark -h >/dev/null 2>&1") == 0;
                boolean mark6 = shell.run(null,
                        "ip6tables -m mark -h >/dev/null 2>&1") == 0;
                boolean occupied = shell.run(null,
                        "iptables -w -S WN_MULTI_GUARD4 >/dev/null 2>&1") == 0
                        || shell.run(null,
                        "ip6tables -w -S WN_MULTI_GUARD6 >/dev/null 2>&1") == 0;
                List<RootSplitRouteRules.Rule> ledger = RootSplitRouteRules.decode(savedRules());
                boolean consistent = countReservedRules() == ledger.size();
                for (RootSplitRouteRules.Rule rule : ledger) consistent &= rulePresent(rule);
                report.append("IPv4/IPv6 firewall OUTPUT inspection: ")
                        .append(firewall4 && firewall6 ? "AVAILABLE" : "INCOMPLETE")
                        .append("; mark matching: ").append(mark4 && mark6 ? "AVAILABLE" : "INCOMPLETE")
                        .append('\n');
                report.append("Reserved guard-chain collision: ")
                        .append(occupied ? "YES" : "NO").append('\n');
                report.append("Owned routing ledger matches live priority rules: ")
                        .append(consistent ? "YES" : "NO — recover before any mutation")
                        .append('\n');
                report.append("Transport marks exclude unmarked route rules: ")
                        .append(transportBypass ? "YES (routing only)" : "NOT PROVEN")
                        .append("; distinct nonzero marks: ")
                        .append(distinctMarks ? "YES" : "NO/UNVERIFIED")
                        .append("; all numeric UDP endpoints: ")
                        .append(allEndpoints ? "YES" : "NO/UNVERIFIED")
                        .append('\n');
                if (!distinctMarks) report.append("Shared or missing transport marks "
                        + "cannot identify individual tunnel exceptions safely. "
                        + "This does NOT mean the tunnels are disconnected.\n");
                boolean prerequisites = allMatched && !extra && consistent
                        && !occupied && firewall4 && firewall6 && mark4 && mark6
                        && routeMatches == split.size()
                        && RootProtectionPolicy.hasInternetDefault(entries, 4)
                        && RootProtectionPolicy.hasInternetDefault(entries, 6)
                        && transportBypass && distinctMarks && allEndpoints;
                report.append("Protection design preconditions: ")
                        .append(prerequisites ? "PARTIAL PASS" : "INCOMPLETE")
                        .append(". Even a partial pass is NOT safe to arm.\n")
                        .append("ACTUAL KILL SWITCH: OFF — NO RULES INSTALLED. ")
                        .append("Endpoint UDP exceptions, app fwmarks, DNS/DoH/DoQ, ")
                        .append("IPv6 leak paths, crash/reboot and network handoff remain ")
                        .append("unverified. Never infer fail-closed behavior from this audit.");
                result = report.toString();
                inspected = true;
            } catch (Exception | LinkageError ignored) {
                result = "Could not complete the read-only protection gate. "
                        + "Check root tools, selected profile identities, and the "
                        + "routing ledger. No firewall or DNS rules changed.";
            }
            finish(callback, inspected, result);
        });
    }

    /** Inspect configured resolver destinations, not Android's actual DNS packets. */
    void auditResolverRoutes(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean inspected = false;
            String result;
            try {
                List<Active> selected = loadAll(profiles);
                List<RootMultiTunnelPlan.Entry> entries = routeEntries(selected);
                RootMultiTunnelPlan.validate(entries);
                rootReady();
                int total = 0;
                int matched = 0;
                StringBuilder report = new StringBuilder("READ-ONLY DNS DESTINATION ROUTE AUDIT\n");
                for (Active active : selected) {
                    Set<InetAddress> servers = active.configuration.getInterface().getDnsServers();
                    report.append(active.profileName).append(": ")
                            .append(servers.isEmpty() ? "NO CONFIGURED RESOLVERS\n" : "\n");
                    for (InetAddress server : servers) {
                        total++;
                        String host = server.getHostAddress();
                        int family = server.getAddress().length == 4 ? 4 : 6;
                        String expected = RootProtectionPolicy.expectedDevice(entries, host);
                        String actual = routeDevice(family, host);
                        boolean pass = !expected.isEmpty() && expected.equals(actual);
                        if (pass) matched++;
                        report.append("IPv").append(family).append(" resolver ")
                                .append(host).append(" → ")
                                .append(actual.isEmpty() ? "NO ROOT ROUTE" : actual)
                                .append(pass ? " · MATCH" : " · MISMATCH/UNROUTED")
                                .append('\n');
                    }
                }
                report.append("Configured resolver root-route matches: ")
                        .append(matched).append('/').append(total).append('\n');
                report.append("Android Private DNS status, per-app resolver sockets, "
                        + "DoH/DoQ, DNS cache, and DNS fallback are NOT observed here. "
                        + "No DNS settings or firewall rules changed.");
                result = report.toString();
                inspected = true;
            } catch (Exception | LinkageError ignored) {
                result = "Could not audit selected configured resolver routes. "
                        + "No DNS settings or policy rules changed.";
            }
            finish(callback, inspected, result);
        });
    }

    /** Per-profile WireGuard UDP endpoint egress and Android DNS-mode inventory. */
    void auditTransportPaths(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean inspected = false;
            String result;
            try {
                List<Active> selected = loadAll(profiles);
                List<RootMultiTunnelPlan.Entry> entries = routeEntries(selected);
                RootMultiTunnelPlan.validate(entries);
                rootReady();
                Set<String> running = backend.getRunningTunnelNames();
                List<String> selectedDevices = new ArrayList<>();
                for (Active active : selected) selectedDevices.add(active.device);
                StringBuilder report = new StringBuilder("BATCH D — READ-ONLY TRANSPORT PATH GATE\n");
                report.append("Independent selected profiles: ").append(selected.size()).append('\n');
                Set<Long> marks = new LinkedHashSet<>();
                boolean shared = false;
                int resolved = 0;
                int potentialLoops = 0;
                for (Active active : selected) {
                    boolean identity = running.contains(active.device)
                            && matches(new NamedTunnel(active.device), active);
                    report.append(active.profileName).append(" (").append(active.device).append("): ");
                    if (!identity) {
                        report.append("NOT IDENTITY-VERIFIED — endpoint not inspected\n");
                        continue;
                    }
                    List<String> markLines = new ArrayList<>();
                    long mark = shell.run(markLines, "wg show " + active.device + " fwmark") == 0
                            ? RootFirewallMark.parse(markLines) : 0;
                    if (mark != 0 && !marks.add(mark)) shared = true;
                    List<String> endpoints = new ArrayList<>();
                    RootTcpProbeTarget endpoint = shell.run(endpoints,
                            "wg show " + active.device + " endpoints") == 0
                            ? RootWireGuardEndpoint.numericTarget(endpoints) : null;
                    if (endpoint == null || mark == 0) {
                        report.append("numeric endpoint or mark UNVERIFIED\n");
                        continue;
                    }
                    String egress = routeDeviceMarked(endpoint.family, endpoint.address, mark);
                    if (!egress.isEmpty()) resolved++;
                    if (RootTransportRoute.isPotentialLoop(egress, selectedDevices)) potentialLoops++;
                    report.append("IPv").append(endpoint.family).append(" endpoint; UDP mark ")
                            .append(RootFirewallMark.display(mark))
                            .append("; marked root egress ")
                            .append(RootTransportRoute.classifiedDevice(egress, selectedDevices))
                            .append('\n');
                }
                report.append("Marked endpoint root routes resolved: ").append(resolved)
                        .append('/').append(selected.size())
                        .append("; selected-tunnel loops flagged: ").append(potentialLoops)
                        .append("; shared nonzero marks: ").append(shared ? "YES" : "NO OBSERVED")
                        .append('\n');
                report.append("Shared Android protected-from-VPN marks are not "
                        + "per-tunnel identities. Even a non-tunnel endpoint route "
                        + "is only an underlay candidate, not proof of real UDP delivery.\n");
                String mode = null;
                try { mode = Settings.Global.getString(appContext.getContentResolver(),
                        "private_dns_mode"); }
                catch (SecurityException ignored) { /* not available on this device */ }
                report.append("Android configured Private DNS mode: ")
                        .append(mode == null || mode.isEmpty() ? "UNREPORTED" :
                                mode.matches("[a-z_]{1,32}") ? mode : "CUSTOM/UNVERIFIED")
                        .append(" (setting only, no DNS traffic observed)\n");
                appendActiveDnsNetwork(report, entries);
                for (int family : new int[] {4, 6}) {
                    report.append("Configured public IPv").append(family).append(" default: ")
                            .append(RootProtectionPolicy.hasInternetDefault(entries, family)
                                    ? "PRESENT" : "MISSING — fallback must be investigated")
                            .append('\n');
                }
                report.append("ACTUAL KILL SWITCH: OFF. No endpoint exception, "
                        + "firewall rule or DNS configuration was installed. "
                        + "App fwmarks, actual UDP packets, encrypted DNS, "
                        + "IPv6 escapes and crash/handoff behavior remain unverified. "
                        + "Never arm based solely on this route snapshot.");
                result = report.toString();
                inspected = true;
            } catch (Exception | LinkageError ignored) {
                result = "Transport path audit could not verify the selected profiles "
                        + "and root tools. No routing or firewall settings changed.";
            }
            finish(callback, inspected, result);
        });
    }

    /** Active Android network DNS metadata only, with IPs and hostnames redacted. */
    private void appendActiveDnsNetwork(StringBuilder report,
                                        List<RootMultiTunnelPlan.Entry> entries) {
        try {
            ConnectivityManager cm = (ConnectivityManager) appContext.getSystemService(
                    Context.CONNECTIVITY_SERVICE);
            Network active = cm == null ? null : cm.getActiveNetwork();
            LinkProperties properties = active == null ? null : cm.getLinkProperties(active);
            if (properties == null) {
                report.append("Active Android network DNS: UNAVAILABLE\n");
                return;
            }
            if (Build.VERSION.SDK_INT >= 28) {
                report.append("Active network Private DNS: ")
                        .append(properties.isPrivateDnsActive() ? "ACTIVE" : "NOT REPORTED ACTIVE")
                        .append(properties.getPrivateDnsServerName() == null
                                ? "; provider hostname: NOT REPORTED"
                                : "; provider hostname: PRESENT (redacted)")
                        .append('\n');
            }
            List<InetAddress> activeDns = properties.getDnsServers();
            report.append("Active Android network DNS destinations: ")
                    .append(activeDns.size()).append(" (addresses redacted)\n");
            for (InetAddress resolver : activeDns) {
                int family = resolver.getAddress().length == 4 ? 4 : 6;
                String ip = resolver.getHostAddress();
                String expected = RootProtectionPolicy.expectedDevice(entries, ip);
                String actual;
                try { actual = routeDevice(family, ip); }
                catch (Exception | LinkageError failed) { actual = ""; }
                report.append("  IPv").append(family).append(" resolver root route: ")
                        .append(actual.isEmpty() ? "UNAVAILABLE" : actual)
                        .append(expected.isEmpty() ? " · NOT SELECTED BY PROFILES"
                                : expected.equals(actual) ? " · EXPECTED DEVICE MATCH"
                                : " · DIFFERENT FROM PROFILE EXPECTATION")
                        .append('\n');
            }
            report.append("These are active LinkProperties and UID-0 lookup results, "
                    + "not observed Android resolver packets.\n");
        } catch (RuntimeException | LinkageError ignored) {
            report.append("Active Android network DNS: UNAVAILABLE\n");
        }
    }

    /** Explicit opt-in: four-second filtered TCP summaries per tunnel. */
    void observeTcpPacketPaths(List<SecureTunnelProfileStore.Profile> profiles,
                               String rawTarget, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean completed = false;
            String result;
            ExecutorService captureWorker = Executors.newSingleThreadExecutor();
            try {
                RootTcpProbeTarget target = RootTcpProbeTarget.parse(rawTarget);
                List<Active> selected = loadAll(profiles);
                List<RootMultiTunnelPlan.Entry> entries = routeEntries(selected);
                RootMultiTunnelPlan.validate(entries);
                rootReady();
                Set<String> running = backend.getRunningTunnelNames();
                for (Active active : selected) {
                    if (!running.contains(active.device)
                            || !matches(new NamedTunnel(active.device), active)) {
                        throw new IllegalStateException("Selected interface is not identity-verified.");
                    }
                }
                boolean toolsAvailable = shell.run(null,
                        "command -v tcpdump >/dev/null 2>&1") == 0
                        && shell.run(null, "command -v timeout >/dev/null 2>&1") == 0;
                StringBuilder report = new StringBuilder(
                        "BATCH E — EXPLICIT SCOPED TCP PACKET OBSERVATION\n");
                report.append("Numeric target: ").append(target.label()).append('\n')
                        .append("Selected profiles: ").append(selected.size()).append('\n');
                if (!toolsAvailable) {
                    report.append("Root tcpdump/timeout: UNAVAILABLE. No capture "
                            + "attempted, no tools installed and no device settings changed. ")
                            .append("App TCP and interface byte-counter tests remain available.");
                } else {
                    report.append("One 4-second narrowly filtered TCP summary per selected interface; "
                            + "no payload output or pcap files retained.\n");
                    for (Active active : selected) {
                        // Device names are SHA-derived and the numeric IP/port
                        // are strictly parsed: never interpolate profile text.
                        String command = "timeout 4 tcpdump -p -tt -n -l -q -s 80 -c 16 -i "
                                + active.device + " 'tcp and host " + target.address
                                + " and port " + target.port + "' 2>/dev/null";
                        Future<CaptureSample> pending = captureWorker.submit(() -> {
                            List<String> packetHeaders = new ArrayList<>();
                            int code = shell.run(packetHeaders, command);
                            // Reduce to a count before returning to the app's
                            // main worker. Never report or journal raw lines.
                            return new CaptureSample(code,
                                    RootPacketEvidence.packetLines(packetHeaders));
                        });
                        Thread.sleep(400); // let the bounded capture attach first
                        String connect = tcpConnectResult(target);
                        CaptureSample sample;
                        try { sample = pending.get(7, TimeUnit.SECONDS); }
                        catch (Exception failed) {
                            pending.cancel(true);
                            sample = new CaptureSample(-1, 0);
                        }
                        boolean toolFinished = sample.code == 0 || sample.code == 124;
                        report.append(active.profileName).append(": ")
                                .append(RootPacketEvidence.interpretation(sample.packets,
                                        toolFinished))
                                .append("; app TCP ").append(connect).append('\n');
                    }
                    report.append("A matching packet summary on a specific interface "
                            + "is stronger evidence than route prediction, but does "
                            + "not identify the originating UID or prove fail-closed behavior. ")
                            .append("Zero packets can result from timing or capture limits. ")
                            .append("Only the selected numeric TCP target and port were "
                                    + "included in the capture filter.");
                }
                report.append("\nACTUAL KILL SWITCH: OFF. No firewall, route, "
                        + "DNS, tunnel or network configuration changed.");
                result = report.toString();
                completed = true;
            } catch (IllegalArgumentException invalid) {
                result = "Scoped capture refused: " + invalid.getMessage()
                        + " No device settings changed.";
            } catch (Exception | LinkageError ignored) {
                result = "Scoped capture could not validate its selected identities "
                        + "or root tooling. No device settings changed.";
            } finally {
                captureWorker.shutdownNow();
            }
            finish(callback, completed, result);
        });
    }

    private static final class CaptureSample {
        final int code;
        final int packets;
        CaptureSample(int code, int packets) {
            this.code = code;
            this.packets = packets;
        }
    }

    private static String tcpConnectResult(RootTcpProbeTarget target) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(InetAddress.getByName(target.address),
                    target.port), 3000);
            return "CONNECTED";
        } catch (IOException | SecurityException unavailable) { return "NOT CONNECTED"; }
    }

    /** Pure hypothetical failure routing: no iptables/rules are produced. */
    void previewFailClosedModel(List<SecureTunnelProfileStore.Profile> profiles,
                                 String rawTarget, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            String result;
            try {
                RootTcpProbeTarget target = RootTcpProbeTarget.parse(rawTarget);
                List<RootMultiTunnelPlan.Entry> entries = routeEntries(loadAll(profiles));
                RootMultiTunnelPlan.validate(entries);
                Set<String> hypotheticallyUp = new LinkedHashSet<>();
                for (RootMultiTunnelPlan.Entry entry : entries) hypotheticallyUp.add(entry.device);
                String required = RootGuardDryRun.requiredTunnel(entries, target.address);
                String normal = RootGuardDryRun.modelDecision(entries, target.address,
                        hypotheticallyUp);
                if (!required.isEmpty()) hypotheticallyUp.remove(required);
                String failed = RootGuardDryRun.modelDecision(entries, target.address,
                        hypotheticallyUp);
                StringBuilder report = new StringBuilder("BATCH E — NON-ENFORCING GUARD MODEL\n");
                report.append("Selected independent profiles: ").append(entries.size()).append('\n')
                        .append("Numeric target: ").append(target.label()).append('\n')
                        .append("Expected selected tunnel: ")
                        .append(required.isEmpty() ? "NO SELECTED POLICY" : required).append('\n')
                        .append("Hypothetical all-tunnels-up decision: ").append(normal).append('\n')
                        .append("Hypothetical required-tunnel-down decision: ").append(failed)
                        .append('\n')
                        .append("Model constraints: default/fallback deny when required "
                                + "tunnel is absent; protect only verified endpoint "
                                + "transport underlay; keep unrelated Android rules intact; "
                                + "persistent exact-match rollback; verify DNS/IPv6 and handoffs.\n")
                        .append("NOT APPLIED: zero firewall rules, endpoint exceptions, "
                                + "routing changes or DNS settings generated. A paper "
                                + "decision is NOT device fail-closed behavior.");
                result = report.toString();
                ok = true;
            } catch (IllegalArgumentException invalid) {
                result = "Guard model refused: " + safeReason(invalid)
                        + ". No device settings changed.";
            } catch (Exception | LinkageError ignored) {
                result = "Guard model could not validate selected encrypted profiles. "
                        + "No device settings changed.";
            }
            finish(callback, ok, result);
        });
    }

    /** App-UID TCP connect plus an independently labeled UID-0 route prediction. */
    void probeService(List<SecureTunnelProfileStore.Profile> profiles, String rawTarget,
                      Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean inspected = false;
            String result;
            try {
                RootTcpProbeTarget target = RootTcpProbeTarget.parse(rawTarget);
                List<Active> selected = loadAll(profiles);
                List<RootMultiTunnelPlan.Entry> entries = routeEntries(selected);
                RootMultiTunnelPlan.validate(entries);
                String expected = RootProtectionPolicy.expectedDevice(entries, target.address);
                String rootRoute = "UNAVAILABLE";
                Map<String, RootTunnelTransfer> before = new LinkedHashMap<>();
                Set<String> verifiedForCounters = new LinkedHashSet<>();
                try {
                    rootReady();
                    String selectedDevice = routeDevice(target.family, target.address);
                    rootRoute = selectedDevice.isEmpty() ? "NO ROOT ROUTE" : selectedDevice;
                    Set<String> running = backend.getRunningTunnelNames();
                    for (Active active : selected) {
                        if (running.contains(active.device)
                                && matches(new NamedTunnel(active.device), active)) {
                            verifiedForCounters.add(active.device);
                            before.put(active.device, readTransfer(active.device));
                        }
                    }
                } catch (Exception | LinkageError ignored) {
                    // App socket reachability is still informative if su starts slowly.
                }
                String tcpResult;
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(InetAddress.getByName(target.address),
                            target.port), 3500);
                    tcpResult = "CONNECTED (TCP handshake only)";
                } catch (SocketTimeoutException timeout) {
                    tcpResult = "TIMED OUT (host, firewall, or path may be blocking)";
                } catch (ConnectException refused) {
                    tcpResult = "CONNECTION REFUSED (no accepting service or active reject)";
                } catch (NoRouteToHostException missing) {
                    tcpResult = "NO ROUTE TO HOST";
                } catch (SecurityException denied) {
                    tcpResult = "APP SOCKET DENIED";
                } catch (IOException invalid) {
                    tcpResult = "SOCKET FAILED (network or remote endpoint error)";
                }
                StringBuilder report = new StringBuilder("READ-ONLY APP SERVICE PATH PROBE\n");
                report.append("Target: ").append(target.label()).append('\n')
                        .append("Profiles used for expected routing: ").append(selected.size()).append('\n')
                        .append("Expected selected tunnel: ")
                        .append(expected.isEmpty() ? "NONE IN SELECTION" : expected).append('\n')
                        .append("UID-0 kernel route lookup: ").append(rootRoute).append('\n')
                        .append("Wonhee app-UID TCP socket: ").append(tcpResult).append('\n')
                        .append("WireGuard byte-counter deltas during this probe:\n");
                for (Active active : selected) {
                    RootTunnelTransfer after = null;
                    if (verifiedForCounters.contains(active.device)) {
                        try { after = readTransfer(active.device); }
                        catch (Exception | LinkageError ignored) { /* report unavailable */ }
                    }
                    report.append(active.profileName).append(": ")
                            .append(RootTunnelTransfer.delta(before.get(active.device), after))
                            .append('\n');
                }
                report.append("Counter changes can include background traffic, "
                        + "handshakes and keepalives. A positive delta is NOT "
                        + "packet-path proof.\n")
                        .append("No HTTP request, credentials, or DNS lookup were sent. ")
                        .append("A TCP success does not prove the socket used the expected ")
                        .append("tunnel, and it does not prove HTTP works. An IP target ")
                        .append("does not test DNS. App fwmarks, packet path, ")
                        .append("firewall leaks and kill switch are unverified. ")
                        .append("No device routing or firewall configuration changed.");
                result = report.toString();
                inspected = true;
            } catch (IllegalArgumentException invalid) {
                result = "Path probe refused: " + invalid.getMessage()
                        + " No device settings changed.";
            } catch (Exception | LinkageError ignored) {
                result = "Could not run the app service path probe with selected "
                        + "profile definitions. No device settings changed.";
            }
            finish(callback, inspected, result);
        });
    }

    private String handshakeAge(String device) {
        try {
            List<String> lines = new ArrayList<>();
            if (shell.run(lines, "wg show " + device + " latest-handshakes") != 0
                    || lines.size() != 1) return "unknown";
            String[] fields = lines.get(0).trim().split("\\s+");
            if (fields.length != 2) return "unknown";
            long epoch = Long.parseLong(fields[1]);
            if (epoch <= 0) return "none observed";
            long age = Math.max(0, System.currentTimeMillis() / 1000 - epoch);
            return age < 180 ? age + "s ago" : age + "s ago (may be idle)";
        } catch (Exception | LinkageError invalid) { return "unknown"; }
    }

    private RootTunnelTransfer readTransfer(String device) throws Exception {
        List<String> lines = new ArrayList<>();
        return shell.run(lines, "wg show " + device + " transfer") == 0
                ? RootTunnelTransfer.parse(lines) : null;
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

    private String routeDeviceMarked(int family, String address, long mark) throws Exception {
        if (mark <= 0 || mark > 0xffffffffL) return "";
        // The endpoint literal comes from numeric-only validation, and the
        // mark comes from strict parsing of `wg show IFACE fwmark`.
        List<String> output = new ArrayList<>();
        if (shell.run(output, "ip -" + family + " route get " + address
                + " mark 0x" + Long.toHexString(mark)) != 0) return "";
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
        // Persist manual stop even if a root worker is busy or owned routing
        // rules block the disconnect. Future recoveries must not race the user.
        if (!recovery.manualStop()) {
            main.post(() -> callback.completed(false,
                    "Manual stop could not be persisted; recovery intent unchanged."));
            return;
        }
        RootMultiRecoveryScheduler.update(appContext);
        RootMultiRecoveryMonitor.update(appContext);
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
