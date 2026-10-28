package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Opt-in, nonsecret recovery intent. Never persists WireGuard configuration.
 * Android Always-on remains required for unattended retry.
 */
final class VpnRecoveryPreferences {
    private static final String FILE = "wonhee_vpn_recovery_v1";
    private static final String ENABLED = "enabled";
    private static final String DESIRED = "connection_desired";
    private static final String USER_STOPPED = "user_explicitly_stopped";
    private final SharedPreferences preferences;

    VpnRecoveryPreferences(Context context) {
        preferences = context.getApplicationContext()
                .getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    boolean enabled() {
        return preferences.getBoolean(ENABLED, false);
    }

    boolean desiredOn() {
        return preferences.getBoolean(DESIRED, false);
    }

    boolean manuallyStopped() {
        return preferences.getBoolean(USER_STOPPED, false);
    }

    void setEnabled(boolean enable, boolean currentlyConnected) {
        preferences.edit().putBoolean(ENABLED, enable)
                .putBoolean(DESIRED, enable && currentlyConnected)
                .apply();
    }

    void userConnected() {
        preferences.edit().putBoolean(USER_STOPPED, false)
                .putBoolean(DESIRED, enabled()).commit();
    }

    void userRequestedDisconnect() {
        // Synchronous write before backend changes avoids races with callbacks.
        preferences.edit().putBoolean(DESIRED, false)
                .putBoolean(USER_STOPPED, true).commit();
    }

    void systemRestoredConnection() {
        if (enabled() && !manuallyStopped()) {
            preferences.edit().putBoolean(DESIRED, true).apply();
        }
    }

    boolean canRetry(boolean androidAlwaysOn) {
        return androidAlwaysOn && enabled() && desiredOn() && !manuallyStopped();
    }
}
