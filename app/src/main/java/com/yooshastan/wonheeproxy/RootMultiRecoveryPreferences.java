package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Product Batch C intent. Saves names and configuration digests, NEVER private
 * keys, plaintext WireGuard files or credentials. Disabled by default.
 */
final class RootMultiRecoveryPreferences {
    private static final String FILE = "wonhee_root_multi_recovery_v1";
    private static final String ENABLED = "enabled";
    private static final String DESIRED = "desired";
    private static final String MANUALLY_STOPPED = "manually_stopped";
    private static final String SELECTION = "selection_v1";
    private static final String FAILURES = "failures";
    private static final String NEXT = "next_attempt";
    private static final String STATUS = "last_status";

    static final class Entry {
        final String name;
        final String digest;

        Entry(String name, String digest) {
            this.name = name;
            this.digest = digest;
        }
    }

    private final SharedPreferences prefs;

    RootMultiRecoveryPreferences(Context context) {
        prefs = context.getApplicationContext().getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    synchronized boolean enabled() { return prefs.getBoolean(ENABLED, false); }
    synchronized boolean desired() { return prefs.getBoolean(DESIRED, false); }
    synchronized boolean manuallyStopped() { return prefs.getBoolean(MANUALLY_STOPPED, true); }
    synchronized int failures() { return prefs.getInt(FAILURES, 0); }
    synchronized long nextAttemptAtMillis() { return prefs.getLong(NEXT, 0L); }

    synchronized boolean canAttempt(long nowMillis) {
        return RootMultiRecoveryPolicy.permitted(enabled(), desired(), manuallyStopped(),
                failures(), prefs.getLong(NEXT, 0L), nowMillis);
    }

    synchronized String summary() {
        if (!enabled()) return "OFF — recovery does not run in the background.";
        if (manuallyStopped() || !desired()) return "PAUSED — manual disconnect was requested.";
        if (failures() >= RootMultiRecoveryPolicy.MAX_FAILURES) {
            return "PAUSED — retry limit reached; review the kernel status and enable again.";
        }
        return "OPTED IN — periodic and handoff checks are best effort. "
                + "Last result: " + prefs.getString(STATUS, "not yet checked")
                + ". No kill switch.";
    }

    synchronized List<Entry> selection() throws Exception {
        String serialized = prefs.getString(SELECTION, "");
        if (serialized.length() > 4096 || serialized.isEmpty()) {
            throw new IllegalStateException("Recovery selection missing or invalid.");
        }
        JSONArray array = new JSONArray(serialized);
        if (array.length() < 1 || array.length() > SecureTunnelProfileStore.MAX_PROFILES) {
            throw new IllegalStateException("Recovery selection count invalid.");
        }
        List<Entry> selected = new ArrayList<>();
        Set<String> names = new LinkedHashSet<>();
        for (int i = 0; i < array.length(); i++) {
            JSONObject item = array.getJSONObject(i);
            String name = item.getString("name");
            String digest = item.getString("sha256");
            if (name.isEmpty() || name.length() > 64 || !names.add(name)
                    || !digest.matches("[0-9a-f]{64}")) {
                throw new IllegalStateException("Recovery selection identity invalid.");
            }
            selected.add(new Entry(name, digest));
        }
        return selected;
    }

    synchronized void enable(List<Entry> selected) throws Exception {
        if (selected.isEmpty() || selected.size() > SecureTunnelProfileStore.MAX_PROFILES) {
            throw new IllegalArgumentException("Choose connected tunnels for recovery.");
        }
        Set<String> names = new LinkedHashSet<>();
        JSONArray array = new JSONArray();
        for (Entry entry : selected) {
            if (entry.name.isEmpty() || entry.name.length() > 64
                    || !entry.digest.matches("[0-9a-f]{64}") || !names.add(entry.name)) {
                throw new IllegalArgumentException("Invalid or duplicate recovery identity.");
            }
            JSONObject item = new JSONObject();
            item.put("name", entry.name);
            item.put("sha256", entry.digest);
            array.put(item);
        }
        if (!prefs.edit().putString(SELECTION, array.toString())
                .putBoolean(ENABLED, true).putBoolean(DESIRED, true)
                .putBoolean(MANUALLY_STOPPED, false).putInt(FAILURES, 0)
                .putLong(NEXT, 0L).putString(STATUS, "awaiting first check").commit()) {
            throw new IllegalStateException("Cannot persist recovery consent.");
        }
    }

    synchronized boolean manualStop() {
        // Synchronous intent change must precede any root disconnect.
        return prefs.edit().putBoolean(DESIRED, false)
                .putBoolean(MANUALLY_STOPPED, true).commit();
    }

    synchronized boolean disable() {
        return prefs.edit().putBoolean(ENABLED, false).putBoolean(DESIRED, false)
                .putBoolean(MANUALLY_STOPPED, true).remove(SELECTION)
                .putInt(FAILURES, 0).putLong(NEXT, 0L)
                .putString(STATUS, "disabled by user").commit();
    }

    synchronized void success(boolean restored) {
        prefs.edit().putInt(FAILURES, 0).putLong(NEXT, 0L)
                .putString(STATUS, restored ? "identity-verified link restored"
                        : "selected links identity-verified UP").commit();
    }

    synchronized void failure(long nowMillis) {
        int failures = Math.min(RootMultiRecoveryPolicy.MAX_FAILURES, failures() + 1);
        prefs.edit().putInt(FAILURES, failures)
                .putLong(NEXT, RootMultiRecoveryPolicy.nextAttemptAt(nowMillis, failures))
                .putString(STATUS, "check failed (" + failures + "/"
                        + RootMultiRecoveryPolicy.MAX_FAILURES + ")").commit();
    }
}
