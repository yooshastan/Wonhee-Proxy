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
    private final RootShell rootShell;
    private final ToolsInstaller tools;
    private final WgQuickBackend backend;
    private final Tunnel home = new NamedTunnel("wnhome0");
    private final Tunnel europe = new NamedTunnel("wnair0");
    private volatile boolean busy;
    private volatile boolean managing;
    private Config startedHome;
    private Config startedEurope;

    private static final class NamedTunnel implements Tunnel {
        private final String name;
        NamedTunnel(String name) { this.name = name; }
        @Override public String getName() { return name; }
        @Override public void onStateChange(State state) { }
    }

    private RootDualKernelSession(Context context) {
        Context app = context.getApplicationContext();
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
        if (!WgQuickBackend.hasKernelSupport()) {
            throw new IllegalStateException("Kernel WireGuard support was not detected.");
        }
        rootShell.start(); // Magisk must explicitly grant Wonhee root access.
        tools.ensureToolsAvailable();
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
                    ? "Kernel backend and WireGuard tools ready. This does not test routing."
                    : "Kernel tools or root unavailable. Grant Wonhee root in Magisk and retry.");
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
            Config localHome = null;
            Config localAir = null;
            try {
                if (managing) throw new IllegalStateException("pair already managed");
                localHome = parseRuntime(homeProfile);
                localAir = parseRuntime(airProfile);
                validatePair(localHome, localAir);
                prepareRoot();

                // Refuse to take over kernel interfaces left by another process.
                Set<String> existing = backend.getRunningTunnelNames();
                if (existing.contains(home.getName()) || existing.contains(europe.getName())) {
                    result = "Wonhee test interface already exists. Stop it before another test.";
                    throw new IllegalStateException("existing tunnel");
                }

                backend.setState(home, Tunnel.State.UP, localHome);
                homeRaised = true;
                if (backend.getState(home) != Tunnel.State.UP) throw new IllegalStateException("home did not start");
                startedHome = localHome;
                managing = true;

                startedEurope = localAir;
                backend.setState(europe, Tunnel.State.UP, localAir);
                airRaised = true;
                if (backend.getState(europe) != Tunnel.State.UP || backend.getState(home) != Tunnel.State.UP) {
                    throw new IllegalStateException("both were not active");
                }
                started = true;
                result = "Both kernel interfaces are UP. Verify fresh handshakes, routing, DNS and IPv6.";
            } catch (IllegalArgumentException invalid) {
                result = "Invalid pair: Home needs split routes; AirVPN needs both defaults. "
                        + "Check profile addresses and DNS.";
            } catch (Exception | LinkageError ignored) {
                // No logging of private keys, tunnel configs, DNS or peer endpoints.
            } finally {
                if (!started) {
                    // Best-effort transactional rollback: never intentionally leave only HOME up.
                    try {
                        if (airRaised || backend.getState(europe) == Tunnel.State.UP) {
                            backend.setState(europe, Tunnel.State.DOWN, localAir);
                        }
                    } catch (Exception | LinkageError ignored) { }
                    try {
                        if (homeRaised || (managing && backend.getState(home) == Tunnel.State.UP)) {
                            backend.setState(home, Tunnel.State.DOWN, localHome);
                        }
                    } catch (Exception | LinkageError ignored) { }
                    try {
                        boolean leftover = managing &&
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
                    backend.setState(europe, Tunnel.State.DOWN, startedEurope);
                }
                airDown = backend.getState(europe) == Tunnel.State.DOWN;
                if (backend.getState(home) == Tunnel.State.UP) {
                    backend.setState(home, Tunnel.State.DOWN, startedHome);
                }
                homeDown = backend.getState(home) == Tunnel.State.DOWN;
            } catch (Exception | LinkageError ignored) {
                // Try the other interface even if stopping Air failed.
                try {
                    if (backend.getState(home) == Tunnel.State.UP) {
                        backend.setState(home, Tunnel.State.DOWN, startedHome);
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
