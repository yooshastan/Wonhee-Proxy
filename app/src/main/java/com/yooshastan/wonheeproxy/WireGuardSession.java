package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;
import com.wireguard.crypto.Key;

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
    private final GoBackend backend;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Tunnel tunnel = new Tunnel() {
        @Override public String getName() { return "WonheeHome"; }
        @Override public void onStateChange(State state) { }
    };
    private boolean operationPending;

    private WireGuardSession(Context context) {
        backend = new GoBackend(context.getApplicationContext());
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
        }
        executor.execute(() -> {
            boolean success = false;
            try {
                Tunnel.State desired = connect ? Tunnel.State.UP : Tunnel.State.DOWN;
                backend.setState(tunnel, desired, config);
                success = backend.getState(tunnel) == desired;
            } catch (Exception | LinkageError ignored) {
                // Do not leak private WireGuard configuration via diagnostics.
            }
            synchronized (WireGuardSession.this) {
                operationPending = false;
            }
            final boolean done = success;
            main.post(() -> callback.finished(done, done
                    ? (connect
                        ? "VPN interface started. Waiting for peer handshake verification."
                        : "VPN interface stopped.")
                    : "VPN operation failed. Check permission, configuration and the gateway."));
        });
    }
}
