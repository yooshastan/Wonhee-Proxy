package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Stores only root lab UI selections and redacted diagnostic text.
 * WireGuard configuration and keys remain in the encrypted profile store.
 */
final class RootLabPreferences {
    private static final String FILE = "wonhee_root_lab_ui_v1";
    private static final String HOME = "selected_home_profile";
    private static final String INTERNET = "selected_internet_profile";
    private static final String LAST_RESULT = "last_diagnostic_result";
    private static final String LAST_RESULT_AT = "last_diagnostic_at";
    private static final int MAX_RESULT_LENGTH = 6000;

    private final SharedPreferences prefs;

    RootLabPreferences(Context context) {
        prefs = context.getApplicationContext().getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    void savePair(String homeName, String internetName) {
        if (homeName == null || internetName == null || homeName.isEmpty()
                || internetName.isEmpty() || homeName.equals(internetName)) {
            throw new IllegalArgumentException("Choose two different named profiles.");
        }
        prefs.edit().putString(HOME, homeName).putString(INTERNET, internetName).apply();
    }

    String homeName() { return prefs.getString(HOME, ""); }
    String internetName() { return prefs.getString(INTERNET, ""); }

    void saveDiagnostic(String redactedResult) {
        if (redactedResult == null) return;
        String bounded = redactedResult.length() > MAX_RESULT_LENGTH
                ? redactedResult.substring(0, MAX_RESULT_LENGTH) : redactedResult;
        prefs.edit().putString(LAST_RESULT, bounded)
                .putLong(LAST_RESULT_AT, System.currentTimeMillis()).apply();
    }

    String lastDiagnostic() { return prefs.getString(LAST_RESULT, ""); }
    long lastDiagnosticTime() { return prefs.getLong(LAST_RESULT_AT, 0L); }

    void clearDiagnostic() {
        prefs.edit().remove(LAST_RESULT).remove(LAST_RESULT_AT).apply();
    }
}
