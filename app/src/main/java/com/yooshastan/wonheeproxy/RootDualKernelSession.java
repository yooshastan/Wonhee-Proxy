package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.android.backend.WgQuickBackend;
import com.wireguard.android.util.RootShell;
import com.wireguard.android.util.ToolsInstaller;
import com.wireguard.config.Config;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Explicit, rooted-only experiment. Does not create a VpnService and does not
 * change the original GoBackend/Always-on connection. Every root call is off
 * the UI thread. The two kernel interfaces have distinct WireGuard identities.
 *
 * No fail-closed or reboot persistence claim: a kernel interface may outlive
 * the app process, and a partially configured route is a test failure.
 */
final class RootDualKernelSession {
    interface Callback { void completed(boolean success, String message); }
    interface StatusCallback { void completed(String message); }

    private static RootDualKernelSession instance;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final File appCacheDir;
    private final RootShell rootShell;
    private final ToolsInstaller tools;
    private final WgQuickBackend backend;
    private final Tunnel home = new NamedTunnel("wnhome0");
    private final Tunnel europe = new NamedTunnel("wnair0");
    private volatile boolean busy;
    private volatile boolean managing;
    private volatile boolean missingKernelVersionNode;
    private volatile String lastPreflightStep = "kernel support";
    private Config startedHome;
    private Config startedEurope;

    private static final class KernelCommandException extends Exception {
        final int exitCode;
        KernelCommandException(int exitCode) { this.exitCode = exitCode; }
    }

    private static final class NamedTunnel implements Tunnel {
        private final String name;
        NamedTunnel(String name) { this.name = name; }
        @Override public String getName() { return name; }
        @Override public void onStateChange(State state) { }
    }

    private RootDualKernelSession(Context context) {
        Context app = context.getApplicationContext();
        appCacheDir = app.getCacheDir();
        rootShell = new RootShell(app);
        tools = new ToolsInstaller(app, rootShell);
        backend = new WgQuickBackend(app, rootShell, tools);
        backend.setMultipleTunnels(true);
    }

    static synchronized RootDualKernelSession get(Context context) {
        if (instance == null) instance = new RootDualKernelSession(context);
        return instance;
    }

    boolean isBusy() { return busy; }
    boolean isManagingPair() { return managing; }

    private boolean begin(Callback callback) {
        synchronized (this) {
            if (busy) {
                main.post(() -> callback.completed(false, "Root experiment is already busy."));
                return false;
            }
            busy = true;
            return true;
        }
    }

    private void finish(Callback callback, boolean success, String message) {
        busy = false;
        main.post(() -> callback.completed(success, message));
    }

    private void prepareRoot() throws Exception {
        lastPreflightStep = "kernel support";
        if (!WgQuickBackend.hasKernelSupport()) {
            throw new IllegalStateException("Kernel WireGuard support was not detected.");
        }
        lastPreflightStep = "Magisk root grant";
        rootShell.start(); // Magisk must explicitly grant Wonhee root access.
        lastPreflightStep = "bundled WireGuard tools";
        tools.ensureToolsAvailable();
        // Some Android builds provide WireGuard built into the kernel without
        // /sys/module/wireguard/version. The upstream WgQuickBackend insists on
        // `cat .../version && wg-quick up`; if the version file is absent,
        // invoke the same bundled wg-quick directly instead of failing early.
        missingKernelVersionNode = rootShell.run(null,
                "test -r /sys/module/wireguard/version") != 0;
        lastPreflightStep = "wg executable";
        if (rootShell.run(null, "wg --version >/dev/null 2>&1") != 0) {
            throw new IllegalStateException("Bundled wg executable could not run.");
        }
        lastPreflightStep = "ready";
    }

    /** Use upstream kernel backend when possible; bypass only its version-file gate. */
    private void setKernelState(Tunnel tunnel, Tunnel.State state, Config config) throws Exception {
        if (!missingKernelVersionNode) {
            backend.setState(tunnel, state, config);
            return;
        }
        if (config == null) throw new IllegalStateException("Missing test configuration.");
        File configFile = new File(new File(appCacheDir, "tmp"),
                tunnel.getName() + ".conf");
        // The app-private cache parent is mode 0700; the temporary file is
        // removed after the root command, whether that command succeeds or not.
        try {
            try (FileOutputStream stream = new FileOutputStream(configFile, false)) {
                stream.write(config.toWgQuickString().getBytes(StandardCharsets.UTF_8));
            }
            final String operation = state == Tunnel.State.UP ? "up" : "down";
            final String path = configFile.getAbsolutePath();
            if (path.contains("'")) throw new IllegalStateException("Unsafe file path.");
            int result = rootShell.run(null, "wg-quick " + operation + " '" + path + "'");
            if (result != 0) throw new KernelCommandException(result);
        } finally {
            //noinspection ResultOfMethodCallIgnored
            configFile.delete();
        }
    }


    void checkRoot(Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean ok = false;
            try {
                prepareRoot();
                ok = true;
            } catch (Exception | LinkageError ignored) {
                // Never return exception text: root commands can contain config data.
            }
            finish(callback, ok, ok
                    ? "Root and tools ready; kernel mode: "
                        + (missingKernelVersionNode ? "built-in compatibility" : "upstream wg-quick")
                        + ". Routing not yet tested."
                    : "Root preflight failed at: " + lastPreflightStep
                        + ". Check the Magisk grant and bundled tools.");
        });
    }

    void startPair(SecureTunnelProfileStore.Profile homeProfile,
                   SecureTunnelProfileStore.Profile airProfile, Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            boolean started = false;
            String result = "Could not start both kernel interfaces. Check Magisk and the profiles.";
            boolean homeRaised = false;
            boolean airRaised = false;
            boolean ownsAttempt = false;
            Config localHome = null;
            Config localAir = null;
            String stage = "profile parsing";
            try {
                if (managing) throw new IllegalStateException("pair already managed");
                localHome = parseRuntime(homeProfile);
                localAir = parseRuntime(airProfile);
                stage = "route validation";
                validatePair(localHome, localAir);
                stage = "root preflight";
                prepareRoot();

                // Refuse to take over kernel interfaces left by another process.
                stage = "interface collision check";
                Set<String> existing = backend.getRunningTunnelNames();
                if (existing.contains(home.getName()) || existing.contains(europe.getName())) {
                    result = "Wonhee test interface already exists. Stop it before another test.";
                    throw new IllegalStateException("existing tunnel");
                }
                ownsAttempt = true;

                stage = "HOME wg-quick up";
                setKernelState(home, Tunnel.State.UP, localHome);
                homeRaised = true;
                stage = "HOME interface verification";
                if (backend.getState(home) != Tunnel.State.UP) throw new IllegalStateException("home did not start");
                startedHome = localHome;
                managing = true;

                stage = "AIRVPN wg-quick up";
                startedEurope = localAir;
                setKernelState(europe, Tunnel.State.UP, localAir);
                airRaised = true;
                stage = "both interfaces verification";
                if (backend.getState(europe) != Tunnel.State.UP || backend.getState(home) != Tunnel.State.UP) {
                    throw new IllegalStateException("both were not active");
                }
                started = true;
                result = "Both kernel interfaces are UP. Verify fresh handshakes, routing, DNS and IPv6.";
            } catch (IllegalArgumentException invalid) {
                // Route-policy failures are our own fixed, non-secret strings.
                // Preserve their actionable reason instead of hiding it behind
                // a generic message. Parsing errors can contain configuration
                // details and must remain redacted.
                if ("route validation".equals(stage)) {
                    result = "Route validation failed: " + invalid.getMessage();
                } else {
                    result = "Failed at " + stage + ". Check the selected profile "
                            + "and its routing/DNS options; private configuration is hidden.";
                }
            } catch (KernelCommandException command) {
                result = "Failed at " + stage + ": wg-quick exit code " + command.exitCode
                        + ". No private configuration was included in this message.";
            } catch (Exception | LinkageError ignored) {
                // No logging of private keys, tunnel configs, DNS or peer endpoints.
                result = "Failed at " + stage + ("root preflight".equals(stage)
                        ? " (step: " + lastPreflightStep + ")" : "")
                        + ". Report this stage; no keys are needed.";
            } finally {
                if (!started) {
                    // Best-effort transactional rollback: never intentionally leave only HOME up.
                    try {
                        if (ownsAttempt && localAir != null &&
                                (airRaised || backend.getState(europe) == Tunnel.State.UP)) {
                            setKernelState(europe, Tunnel.State.DOWN, localAir);
                        }
                    } catch (Exception | LinkageError ignored) { }
                    try {
                        if (ownsAttempt && localHome != null &&
                                (homeRaised || backend.getState(home) == Tunnel.State.UP)) {
                            setKernelState(home, Tunnel.State.DOWN, localHome);
                        }
                    } catch (Exception | LinkageError ignored) { }
                    try {
                        boolean leftover = ownsAttempt &&
                                (backend.getState(home) == Tunnel.State.UP ||
                                 backend.getState(europe) == Tunnel.State.UP);
                        managing = leftover;
                        if (!leftover) { startedHome = null; startedEurope = null; }
                        else result = "Start failed; a test interface may remain UP. Use Stop both.";
                    } catch (Exception | LinkageError ignored) { }
                }
                finish(callback, started, result);
            }
        });
    }

    void stopPair(Callback callback) {
        if (!begin(callback)) return;
        worker.execute(() -> {
            if (!managing) {
                finish(callback, false, "No pair owned by this Wonhee process. No interfaces changed.");
                return;
            }
            boolean airDown = false;
            boolean homeDown = false;
            try {
                prepareRoot();
                if (backend.getState(europe) == Tunnel.State.UP) {
                    setKernelState(europe, Tunnel.State.DOWN, startedEurope);
                }
                airDown = backend.getState(europe) == Tunnel.State.DOWN;
                if (backend.getState(home) == Tunnel.State.UP) {
                    setKernelState(home, Tunnel.State.DOWN, startedHome);
                }
                homeDown = backend.getState(home) == Tunnel.State.DOWN;
            } catch (Exception | LinkageError ignored) {
                // Try the other interface even if stopping Air failed.
                try {
                    if (backend.getState(home) == Tunnel.State.UP) {
                        setKernelState(home, Tunnel.State.DOWN, startedHome);
                    }
                    homeDown = backend.getState(home) == Tunnel.State.DOWN;
                } catch (Exception | LinkageError alsoIgnored) { }
            }
            boolean stopped = airDown && homeDown;
            if (stopped) {
                managing = false;
                startedHome = null;
                startedEurope = null;
            }
            finish(callback, stopped, stopped ? "Both Wonhee kernel interfaces stopped."
                    : "Stop incomplete. Check each kernel interface and retry Stop both.");
        });
    }

    void readStatus(StatusCallback callback) {
        if (!managing || busy) {
            main.post(() -> callback.completed(managing ? "Kernel pair operation in progress."
                    : "Root dual-tunnel experiment is idle."));
            return;
        }
        worker.execute(() -> {
            String status;
            try {
                status = summarize("Home", home) + "\n" + summarize("AirVPN Europe", europe);
            } catch (Exception | LinkageError ignored) {
                status = "Could not read kernel tunnel status; check Magisk root access.";
            }
            String safe = status;
            main.post(() -> callback.completed(safe));
        });
    }

    private String summarize(String label, Tunnel tunnel) throws Exception {
        if (backend.getState(tunnel) != Tunnel.State.UP) return label + ": DOWN";
        Statistics stats = backend.getStatistics(tunnel);
        long recent = 0;
        for (Key peer : stats.peers()) {
            Statistics.PeerStats peerStats = stats.peer(peer);
            if (peerStats != null) recent = Math.max(recent, peerStats.latestHandshakeEpochMillis());
        }
        return label + ": UP | RX " + stats.totalRx() + " B | TX "
                + stats.totalTx() + " B | handshake "
                + (recent > 0 ? "observed" : "not observed");
    }

    private static Config parseRuntime(SecureTunnelProfileStore.Profile profile) throws Exception {
        byte[] bytes = profile.configuration.getBytes(StandardCharsets.UTF_8);
        Config raw;
        try { raw = Config.parse(new ByteArrayInputStream(bytes)); }
        finally { Arrays.fill(bytes, (byte) 0); }
        if (raw.getPeers().size() != 1 || raw.getInterface().getAddresses().isEmpty()) {
            throw new IllegalArgumentException("Each kernel test profile needs one peer and an interface address.");
        }
        Config routed = VpnRouteModes.prepare(raw, profile.routeMode, profile.homeRoutes);
        return VpnDnsOverride.prepare(routed, profile.homeDnsEnabled, profile.homeDnsServer);
    }

    private static void validatePair(Config home, Config air) {
        List<String> homeRoutes = routes(home.getPeers().get(0));
        List<String> airRoutes = routes(air.getPeers().get(0));
        RootDualRoutePolicy.validate(homeRoutes, airRoutes);
        for (InetNetwork h : home.getInterface().getAddresses()) {
            for (InetNetwork a : air.getInterface().getAddresses()) {
                if (h.equals(a)) {
                    throw new IllegalArgumentException("The two tunnel interface addresses must differ.");
                }
            }
        }
    }

    private static List<String> routes(Peer peer) {
        List<String> result = new ArrayList<>();
        for (InetNetwork route : peer.getAllowedIps()) result.add(route.toString());
        return result;
    }
}
