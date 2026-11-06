package com.yooshastan.wonheeproxy;

import android.app.Application;

import com.wireguard.android.backend.GoBackend;

/**
 * Install WireGuard's system Always-on callback before Android creates its VPN
 * service. No unprompted connection happens on ordinary app startup.
 */
public final class WonheeApplication extends Application {
    @Override public void onCreate() {
        super.onCreate();
        GoBackend.setAlwaysOnCallback(() -> {
            try {
                if (!RootDualKernelSession.get(this).isManagingPair()) {
                    WireGuardSession.get(this).restoreSavedProfileForAlwaysOn();
                }
            } catch (RuntimeException | LinkageError unavailable) {
                // Never log a saved WireGuard configuration or private key.
                // Android lockdown, when enabled, blocks traffic if VPN is down.
            }
        });
        // Only restores root multi-kernel links after explicit Product Batch C
        // opt-in. No root operation is performed merely by app startup.
        RootMultiRecoveryScheduler.update(this);
        RootMultiRecoveryMonitor.update(this);
    }
}
