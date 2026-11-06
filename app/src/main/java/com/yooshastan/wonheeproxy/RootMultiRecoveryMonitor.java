package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.os.Handler;
import android.os.Looper;

/** Process-lifetime network-handoff hint; jobs cover process death/reboot. */
final class RootMultiRecoveryMonitor {
    private static ConnectivityManager manager;
    private static ConnectivityManager.NetworkCallback callback;
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static Runnable pending;

    private RootMultiRecoveryMonitor() { }

    static synchronized void update(Context context) {
        Context app = context.getApplicationContext();
        RootMultiRecoveryPreferences prefs = new RootMultiRecoveryPreferences(app);
        if (!prefs.enabled() || !prefs.desired() || prefs.manuallyStopped()
                || prefs.failures() >= RootMultiRecoveryPolicy.MAX_FAILURES) {
            if (pending != null) MAIN.removeCallbacks(pending);
            pending = null;
            if (manager != null && callback != null) {
                try { manager.unregisterNetworkCallback(callback); }
                catch (RuntimeException ignored) { }
            }
            manager = null;
            callback = null;
            return;
        }
        if (callback != null) return;
        try {
            ConnectivityManager network = (ConnectivityManager) app.getSystemService(
                    Context.CONNECTIVITY_SERVICE);
            if (network == null) return;
            ConnectivityManager.NetworkCallback monitor = new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) {
                    synchronized (RootMultiRecoveryMonitor.class) {
                        if (pending != null) MAIN.removeCallbacks(pending);
                        pending = () -> {
                            RootMultiRecoveryPreferences current =
                                    new RootMultiRecoveryPreferences(app);
                            RootMultiKernelSession session = RootMultiKernelSession.get(app);
                            if (current.canAttempt(System.currentTimeMillis()) && !session.isBusy()) {
                                session.recoverSavedIfDesired((ok, status) -> { });
                            }
                        };
                        MAIN.postDelayed(pending, 7_000L);
                    }
                }
            };
            network.registerDefaultNetworkCallback(monitor);
            manager = network;
            callback = monitor;
        } catch (RuntimeException | LinkageError unavailable) {
            // Background callback may be unavailable on a restricted Android build.
        }
    }
}
