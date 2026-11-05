package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.DateFormat;
import java.util.Date;
import java.util.UUID;
import java.util.regex.Pattern;

/** A small, local support journal. Never reads or stores imported WireGuard configuration. */
final class RootSessionJournal {
    private static final String PREFS = "wonhee_root_support_session";
    private static final String ID = "id";
    private static final String STARTED = "started";
    private static final String EVENTS = "events";
    private static final int MAX_EVENTS = 160;
    private static final int MAX_EVENT_CHARS = 3200;
    private static final Pattern SENSITIVE_FIELD = Pattern.compile(
            "(?i)\\b(private[-_ ]?key|preshared[-_ ]?key|password|passwd|secret|"
                    + "access[-_ ]?token|authorization)\\s*[:=]\\s*[^\\r\\n,;]+"
    );
    private static final Pattern BEARER_TOKEN = Pattern.compile(
            "(?i)\\bbearer\\s+[a-z0-9._~+/-]+={0,2}");

    private final SharedPreferences prefs;

    RootSessionJournal(Context context) {
        prefs = context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        if (prefs.getString(ID, "").isEmpty()) newSession();
    }

    synchronized void newSession() {
        String id = UUID.randomUUID().toString().substring(0, 8).toUpperCase(java.util.Locale.ROOT);
        prefs.edit().putString(ID, id).putLong(STARTED, System.currentTimeMillis())
                .putString(EVENTS, "[]").commit();
        record("SESSION", "New diagnostic session started");
    }

    synchronized void record(String kind, String detail) {
        JSONArray entries = readEntries();
        JSONObject event = new JSONObject();
        try {
            event.put("time", System.currentTimeMillis());
            event.put("kind", clean(kind, 30));
            event.put("detail", clean(detail, MAX_EVENT_CHARS));
            entries.put(event);
            JSONArray bounded = new JSONArray();
            int first = Math.max(0, entries.length() - MAX_EVENTS);
            for (int i = first; i < entries.length(); i++) bounded.put(entries.get(i));
            prefs.edit().putString(EVENTS, bounded.toString()).commit();
        } catch (JSONException ignored) { /* Never interrupt a tunnel operation to log it. */ }
    }

    synchronized String title() {
        return "Session " + prefs.getString(ID, "unknown") + " · "
                + readEntries().length() + " recorded events";
    }

    synchronized String id() { return prefs.getString(ID, "unknown"); }

    synchronized String report(String homeName, String internetName,
                               String liveSummary, String lastDiagnostic) {
        StringBuilder text = new StringBuilder(16000);
        text.append("WONHEE PROXY — ROOT SESSION REPORT\n");
        text.append("Session ID: ").append(id()).append('\n');
        text.append("Started: ").append(timestamp(prefs.getLong(STARTED, 0L))).append('\n');
        text.append("Exported: ").append(timestamp(System.currentTimeMillis())).append('\n');
        text.append("Device: ").append(clean(Build.MANUFACTURER + " " + Build.MODEL, 120))
                .append(" · Android ").append(Build.VERSION.RELEASE).append("\n\n");
        text.append("Selected Home profile: ").append(clean(homeName, 180)).append('\n');
        text.append("Selected Internet profile: ").append(clean(internetName, 180)).append('\n');
        text.append("Kill switch: OFF / not validated\n");
        text.append("DNS, IPv6, app DNS and fail-closed behavior: not independently verified\n\n");
        JSONArray entries = readEntries();
        text.append("SESSION EVENTS (oldest to newest; most recent ")
                .append(MAX_EVENTS).append(" retained)\n");
        for (int i = 0; i < entries.length(); i++) {
            JSONObject event = entries.optJSONObject(i);
            if (event == null) continue;
            text.append('\n').append(i + 1).append(". [")
                    .append(timestamp(event.optLong("time", 0L))).append("] ")
                    .append(clean(event.optString("kind", "EVENT"), 30))
                    .append("\n").append(clean(event.optString("detail", ""), MAX_EVENT_CHARS))
                    .append('\n');
        }
        text.append("\nLIVE INTERFACE SNAPSHOT (last viewed)\n")
                .append(clean(liveSummary, 9000)).append('\n');
        text.append("\nLAST SAVED DIAGNOSTIC\n")
                .append(clean(lastDiagnostic, 9000)).append('\n');
        text.append("\nThis report is local device evidence, not a DNS/leak/privacy audit. ")
                .append("Endpoints, addresses and profile names may identify your network. ")
                .append("Review before sharing. Sensitive key/token field values are redacted.\n");
        return text.toString();
    }

    private JSONArray readEntries() {
        try { return new JSONArray(prefs.getString(EVENTS, "[]")); }
        catch (JSONException ignored) { return new JSONArray(); }
    }

    private static String clean(String value, int maximum) {
        if (value == null) return "";
        String redacted = SENSITIVE_FIELD.matcher(value).replaceAll("[REDACTED FIELD]");
        redacted = BEARER_TOKEN.matcher(redacted).replaceAll("Bearer [REDACTED]");
        return redacted.length() > maximum ? redacted.substring(0, maximum) + " [truncated]" : redacted;
    }

    private static String timestamp(long time) {
        if (time <= 0L) return "unknown";
        return DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM)
                .format(new Date(time));
    }
}
