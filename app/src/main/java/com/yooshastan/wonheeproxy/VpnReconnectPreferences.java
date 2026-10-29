package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;

/** Only opt-in/desired-state flags; WireGuard profiles remain encrypted elsewhere. */
final class VpnReconnectPreferences {
    private static final String FILE = "wonhee_reconnect_preferences";
    private static final String ENABLED = "retry_enabled";
    private static final String DESIRED_UP = "user_requested_up";

    private VpnReconnectPreferences() { }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext()
                .getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    static boolean enabled(Context context) {
        return prefs(context).getBoolean(ENABLED, false);
    }

    static boolean shouldReconnect(Context context) {
        SharedPreferences p = prefs(context);
        return p.getBoolean(ENABLED, false) && p.getBoolean(DESIRED_UP, false);
    }

    static void setEnabled(Context context, boolean enabled, boolean isCurrentlyConnected) {
        prefs(context).edit()
                .putBoolean(ENABLED, enabled)
                .putBoolean(DESIRED_UP, enabled && isCurrentlyConnected)
                .commit();
    }

    static void userConnected(Context context) {
        prefs(context).edit().putBoolean(DESIRED_UP, true).commit();
    }

    static void userDisconnected(Context context) {
        // Commit before backend shutdown so a pending background retry cannot undo Off.
        prefs(context).edit().putBoolean(DESIRED_UP, false).commit();
    }
}
