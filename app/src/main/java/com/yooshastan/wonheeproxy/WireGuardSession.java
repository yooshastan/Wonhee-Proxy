package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Process-local experimental WireGuard session. The system VPN service is
 * supplied by the official WireGuard tunnel library. No credentials are
 * persisted by this class. Always-on is intentionally unsupported in Alpha 0.4.
 */
final class WireGuardSession {
    interface Completion {
        void finished(boolean success, String message);
    }

    private static WireGuardSession instance;
    private final GoBackend backend;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Tunnel tunnel = new Tunnel() {
        @Override public String getName() { return "WonheeHome"; }
        @Override public void onStateChange(State newState) { }
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

    void connect(Config config, Completion callback) {
        dispatch(true, config, callback);
    }

    void disconnect(Completion callback) {
        dispatch(false, null, callback);
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
                backend.setState(tunnel, connect ? Tunnel.State.UP : Tunnel.State.DOWN, config);
                success = backend.getState(tunnel) ==
                        (connect ? Tunnel.State.UP : Tunnel.State.DOWN);
            } catch (Exception | LinkageError error) {
                // Backend exception text could include a config value. Do not
                // expose it through logs, UI, crash telemetry, or the clipboard.
            }
            synchronized (WireGuardSession.this) {
                operationPending = false;
            }
            final boolean done = success;
            main.post(() -> callback.finished(done, done
                    ? (connect ? "WireGuard interface started. A successful handshake "
                       + "and internet access are NOT yet verified."
                       : "WireGuard interface stopped.")
                    : "WireGuard operation failed. Verify the private configuration, "
                      + "VPN permission, gateway and device compatibility."));
        });
    }
}
