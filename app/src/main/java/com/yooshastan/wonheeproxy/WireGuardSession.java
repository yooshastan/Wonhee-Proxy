package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;

import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;
import com.wireguard.crypto.Key;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Single process-local WireGuard tunnel. All mutating backend calls and
 * statistics reads use one executor to avoid reading during transition.
 * The system VPN service is provided by the official WireGuard library.
 */
final class WireGuardSession {
    interface Completion {
        void finished(boolean success, String message);
    }

    interface StatsCallback {
        void finished(StatusSnapshot snapshot);
    }

    static final class StatusSnapshot {
        final boolean interfaceUp;
        final boolean statisticsAvailable;
        final long receivedBytes;
        final long transmittedBytes;
        final long lastHandshakeEpochMillis;
        final int peers;

        StatusSnapshot(boolean up, boolean available, long rx, long tx, long handshake, int peers) {
            interfaceUp = up;
            statisticsAvailable = available;
            receivedBytes = rx;
            transmittedBytes = tx;
            lastHandshakeEpochMillis = handshake;
            this.peers = peers;
        }
    }

    private static WireGuardSession instance;
    private final Context appContext;
    private final GoBackend backend;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Tunnel tunnel = new Tunnel() {
        @Override public String getName() { return "WonheeHome"; }
        @Override public void onStateChange(State state) { }
    };
    private boolean operationPending;
    private volatile boolean manualStopRequested;

    private WireGuardSession(Context context) {
        appContext = context.getApplicationContext();
        backend = new GoBackend(appContext);
    }

    static synchronized WireGuardSession get(Context context) {
        if (instance == null) instance = new WireGuardSession(context);
        return instance;
    }

    synchronized boolean isConnected() {
        return backend.getState(tunnel) == Tunnel.State.UP;
    }

    synchronized boolean isBusy() {
        return operationPending;
    }

    boolean isAlwaysOn() {
        try {
            return backend.isAlwaysOn();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception | LinkageError unavailable) {
            return false;
        }
    }

    boolean isLockdownEnabled() {
        try {
            return backend.isLockdownEnabled();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception | LinkageError unavailable) {
            return false;
        }
    }

    /**
     * Invoked only from the WireGuard library's system Always-on callback.
     * Restore the most recently selected encrypted profile on the serialized
     * backend executor, preserving the same single tunnel used by the UI.
     * Do not start from the ordinary app launch or after a user chose Off.
     */
    void restoreSavedProfileForAlwaysOn() {
        if (manualStopRequested || new VpnRecoveryPreferences(appContext).manuallyStopped()) return;
        synchronized (this) {
            if (operationPending) return;
            operationPending = true;
        }
        executor.execute(() -> {
            try {
                if (manualStopRequested || new VpnRecoveryPreferences(appContext).manuallyStopped()) return;
                if (backend.getState(tunnel) == Tunnel.State.UP) return;
                Config runtime = loadSavedRuntimeConfig();
                if (runtime == null) return;
                if (VpnService.prepare(appContext) != null) return;
                backend.setState(tunnel, Tunnel.State.UP, runtime);
                if (backend.getState(tunnel) == Tunnel.State.UP) {
                    new VpnRecoveryPreferences(appContext).systemRestoredConnection();
                    VpnRecoveryScheduler.update(appContext);
                    VpnTrafficNotificationService.startIfPossible(appContext);
                }
            } catch (Exception | LinkageError ignored) {
                // Do not disclose saved WireGuard configuration or secrets.
                // The system may enforce lockdown while the tunnel is unavailable.
            } finally {
                synchronized (WireGuardSession.this) {
                    operationPending = false;
                }
            }
        });
    }

    /** Retry only when the tunnel is DOWN, opt-in, and Android Always-on remains enabled. */
    void recoverSavedProfileIfDesired(Completion callback) {
        VpnRecoveryPreferences prefs = new VpnRecoveryPreferences(appContext);
        if (manualStopRequested || !prefs.canRetry(isAlwaysOn())) {
            main.post(() -> callback.finished(false,
                    "Auto-reconnect is off, manually stopped, or Android Always-on is disabled."));
            return;
        }
        synchronized (this) {
            if (operationPending) {
                main.post(() -> callback.finished(false, "A VPN operation is already running."));
                return;
            }
            operationPending = true;
        }
        executor.execute(() -> {
            boolean success = false;
            String message = "Could not restart the saved WireGuard tunnel.";
            try {
                if (!manualStopRequested && prefs.canRetry(isAlwaysOn())) {
                    if (backend.getState(tunnel) == Tunnel.State.UP) {
                        success = true;
                    } else if (VpnService.prepare(appContext) != null) {
                        prefs.userRequestedDisconnect();
                        message = "Android VPN permission unavailable. Reconnect manually.";
                    } else {
                        Config runtime = loadSavedRuntimeConfig();
                        if (runtime == null) {
                            prefs.userRequestedDisconnect();
                            message = "Saved VPN profile missing. Reconnect manually.";
                        } else {
                            backend.setState(tunnel, Tunnel.State.UP, runtime);
                            success = backend.getState(tunnel) == Tunnel.State.UP;
                        }
                    }
                } else {
                    message = "Auto-reconnect was disabled while attempting recovery.";
                }
            } catch (IllegalArgumentException invalidProfile) {
                prefs.userRequestedDisconnect();
                message = "Saved routing or DNS is invalid. Reconnect manually.";
            } catch (SecurityException permission) {
                prefs.userRequestedDisconnect();
                message = "Android denied VPN access. Reconnect manually.";
            } catch (Exception | LinkageError failure) {
                // Never echo WireGuard keys, gateway addresses or native exceptions.
            } finally {
                synchronized (WireGuardSession.this) {
                    operationPending = false;
                }
            }
            if (success) VpnTrafficNotificationService.startIfPossible(appContext);
            final boolean done = success;
            final String safeMessage = success
                    ? "WireGuard interface restored. Peer handshake is not yet verified."
                    : message;
            main.post(() -> callback.finished(done, safeMessage));
        });
    }

    private Config loadSavedRuntimeConfig() throws Exception {
        SecureTunnelProfileStore store = new SecureTunnelProfileStore(appContext);
        List<SecureTunnelProfileStore.Profile> saved = store.load();
        int selected = store.preferredIndex(saved.size());
        if (selected < 0) return null;
        SecureTunnelProfileStore.Profile profile = saved.get(selected);
        byte[] bytes = profile.configuration.getBytes(StandardCharsets.UTF_8);
        Config original;
        try {
            original = Config.parse(new ByteArrayInputStream(bytes));
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
        if (original.getPeers().isEmpty()
                || original.getInterface().getAddresses().isEmpty()) return null;
        Config routed = VpnRouteModes.prepare(original, profile.routeMode,
                profile.homeRoutes);
        return VpnDnsOverride.prepare(routed, profile.homeDnsEnabled,
                profile.homeDnsServer);
    }

    void connect(Config config, Completion completion) {
        dispatch(true, config, completion);
    }

    void disconnect(Completion completion) {
        dispatch(false, null, completion);
    }

    void readStatistics(StatsCallback callback) {
        executor.execute(() -> {
            boolean up = false;
            boolean available = false;
            long rx = 0L;
            long tx = 0L;
            long recentHandshake = 0L;
            int peerCount = 0;
            try {
                up = backend.getState(tunnel) == Tunnel.State.UP;
                if (up) {
                    Statistics statistics = backend.getStatistics(tunnel);
                    rx = statistics.totalRx();
                    tx = statistics.totalTx();
                    Key[] keys = statistics.peers();
                    peerCount = keys.length;
                    for (Key key : keys) {
                        Statistics.PeerStats peer = statistics.peer(key);
                        if (peer != null) {
                            recentHandshake = Math.max(
                                    recentHandshake, peer.latestHandshakeEpochMillis());
                        }
                    }
                    available = true;
                }
            } catch (Exception | LinkageError ignored) {
                // Native exceptions and config values are never logged or echoed.
            }
            StatusSnapshot result = new StatusSnapshot(
                    up, available, rx, tx, recentHandshake, peerCount);
            main.post(() -> callback.finished(result));
        });
    }

    private void dispatch(boolean connect, Config config, Completion callback) {
        synchronized (this) {
            if (operationPending) {
                main.post(() -> callback.finished(false, "A VPN operation is already running."));
                return;
            }
            operationPending = true;
            if (!connect) {
                manualStopRequested = true;
                new VpnRecoveryPreferences(appContext).userRequestedDisconnect();
            }
        }
        if (!connect) VpnRecoveryScheduler.update(appContext);
        executor.execute(() -> {
            boolean success = false;
            String failure = "VPN operation failed. Check the tunnel, Android VPN permission and gateway.";
            try {
                Tunnel.State desired = connect ? Tunnel.State.UP : Tunnel.State.DOWN;
                backend.setState(tunnel, desired, config);
                success = backend.getState(tunnel) == desired;
                if (!success) failure = "VPN backend did not reach the requested state.";
            } catch (SecurityException permission) {
                failure = "Android denied VPN access. Check system VPN permission and Always-on settings.";
            } catch (IllegalArgumentException invalidConfig) {
                failure = "WireGuard rejected the runtime configuration. Check the selected routes and DNS.";
            } catch (Exception | LinkageError unavailable) {
                // Do not echo backend exceptions, private WireGuard keys or endpoint data.
            }
            synchronized (WireGuardSession.this) {
                operationPending = false;
            }
            final boolean done = success;
            if (done) {
                if (connect) {
                    manualStopRequested = false;
                    new VpnRecoveryPreferences(appContext).userConnected();
                    VpnRecoveryScheduler.update(appContext);
                    VpnTrafficNotificationService.startIfPossible(appContext);
                } else {
                    VpnTrafficNotificationService.stop(appContext);
                }
            }
            final String safeFailure = failure;
            main.post(() -> callback.finished(done, done
                    ? (connect
                        ? "VPN interface started. Waiting for peer handshake verification."
                        : "VPN interface stopped.")
                    : safeFailure));
        });
    }
}
