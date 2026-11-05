package com.yooshastan.wonheeproxy;

import android.content.Context;
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

    void connect(List<SecureTunnelProfileStore.Profile> profiles, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            List<Active> started = new ArrayList<>();
            String stage = "profile validation";
            boolean success = false;
            String result;
            try {
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
                List<Active> selected = loadAll(profiles);
                if (selected.isEmpty()) throw new IllegalArgumentException("Select a tunnel.");
                Set<String> seen = new LinkedHashSet<>();
                for (Active active : selected) {
                    if (!seen.add(active.device)) {
                        throw new IllegalArgumentException("Duplicate interface selection.");
                    }
                }
                rootReady();
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
