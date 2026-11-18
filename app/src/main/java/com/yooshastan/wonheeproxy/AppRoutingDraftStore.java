package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Private, on-device ONLY assignment drafts.
 *
 * These strings are NOT applied to netd, ip rules, BPF, iptables, WireGuard,
 * DNS, or the Android VPN. No private keys, IPs or queries are stored here.
 * Future enforcement requires a separately validated, fail-closed engine.
 */
final class AppRoutingDraftStore {
    private static final String PREFS = "wonhee_app_routing_draft_v1";
    private static final String APPS = "app_category_assignments";
    private static final String TUNNELS = "category_tunnel_assignments";
    private static final int MAX_APP_OVERRIDES = 512;
    private static final int MAX_STRING_BYTES = 65000;
    private final SharedPreferences prefs;

    AppRoutingDraftStore(Context context) {
        prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private JSONObject read(String key) {
        String text = prefs.getString(key, "{}");
        if (text == null || text.length() > MAX_STRING_BYTES) {
            throw new IllegalStateException("Routing draft storage is invalid.");
        }
        try {
            return new JSONObject(text);
        } catch (JSONException invalid) {
            throw new IllegalStateException("Routing draft storage could not be read.");
        }
    }

    synchronized Map<String, Integer> appCategories() {
        JSONObject json = read(APPS);
        Map<String, Integer> result = new HashMap<>();
        java.util.Iterator<String> names = json.keys();
        while (names.hasNext()) {
            String pkg = names.next();
            int value = json.optInt(pkg, -1);
            if (AppUseCategories.validPackageName(pkg)
                    && AppUseCategories.valid(value)
                    && value != AppUseCategories.EVERYDAY) result.put(pkg, value);
        }
        return Collections.unmodifiableMap(result);
    }

    synchronized int appCategory(String packageName) {
        if (!AppUseCategories.validPackageName(packageName)) {
            return AppUseCategories.EVERYDAY;
        }
        int value = read(APPS).optInt(packageName, AppUseCategories.EVERYDAY);
        return AppUseCategories.safe(value);
    }

    synchronized void setAppCategory(String packageName, int category) {
        if (!AppUseCategories.validPackageName(packageName)
                || !AppUseCategories.valid(category)) {
            throw new IllegalArgumentException("Invalid app/category assignment.");
        }
        JSONObject data = read(APPS);
        try {
            if (category == AppUseCategories.EVERYDAY) data.remove(packageName);
            else data.put(packageName, category);
            if (data.length() > MAX_APP_OVERRIDES) {
                throw new IllegalArgumentException("Too many saved app assignments.");
            }
        } catch (JSONException invalid) {
            throw new IllegalStateException("Could not update app assignment.");
        }
        String encoded = data.toString();
        if (encoded.length() > MAX_STRING_BYTES) {
            throw new IllegalArgumentException("App assignment storage is full.");
        }
        if (!prefs.edit().putString(APPS, encoded).commit()) {
            throw new IllegalStateException("Could not persist app assignment.");
        }
    }

    synchronized String categoryTunnel(int category) {
        if (!AppUseCategories.valid(category)) return "";
        String name = read(TUNNELS).optString(Integer.toString(category), "");
        return name.length() <= 64 ? name : "";
    }

    synchronized void setCategoryTunnel(int category, String profileName) {
        if (!AppUseCategories.valid(category) || profileName == null
                || profileName.length() > 64) {
            throw new IllegalArgumentException("Invalid category tunnel.");
        }
        JSONObject data = read(TUNNELS);
        try {
            if (profileName.isEmpty()) data.remove(Integer.toString(category));
            else data.put(Integer.toString(category), profileName);
        } catch (JSONException invalid) {
            throw new IllegalStateException("Could not update category tunnel.");
        }
        String encoded = data.toString();
        if (encoded.length() > MAX_STRING_BYTES) {
            throw new IllegalArgumentException("Category tunnel storage is full.");
        }
        if (!prefs.edit().putString(TUNNELS, encoded).commit()) {
            throw new IllegalStateException("Could not persist category tunnel.");
        }
    }
}
