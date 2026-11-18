package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
    private static final String PROTOCOLS = "app_protocol_overrides";
    private static final String CATEGORY_PROTOCOLS = "global_category_protocol_overrides";
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

    /** Local, explicit TCP/UDP + destination-port drafts. No packet rules. */
    synchronized List<RootProtocolRouteDraft.Override> protocolRules(String packageName) {
        if (!AppUseCategories.validPackageName(packageName)) {
            throw new IllegalArgumentException("Invalid app package.");
        }
        JSONArray raw = read(PROTOCOLS).optJSONArray(packageName);
        if (raw == null) return Collections.emptyList();
        List<RootProtocolRouteDraft.Override> parsed = new ArrayList<>();
        for (int i = 0; i < raw.length(); i++) {
            JSONObject rule = raw.optJSONObject(i);
            if (rule == null) {
                throw new IllegalStateException("Saved protocol rule is invalid.");
            }
            parsed.add(new RootProtocolRouteDraft.Override(packageName,
                    rule.optInt("transport", -1),
                    rule.optInt("destinationPort", -1),
                    rule.optString("tunnel", "")));
        }
        return RootProtocolRouteDraft.validateAndSort(parsed);
    }

    synchronized List<RootProtocolRouteDraft.Override> allProtocolRules() {
        JSONObject json = read(PROTOCOLS);
        List<RootProtocolRouteDraft.Override> all = new ArrayList<>();
        java.util.Iterator<String> packages = json.keys();
        while (packages.hasNext()) {
            all.addAll(protocolRules(packages.next()));
        }
        return RootProtocolRouteDraft.validateAndSort(all);
    }

    synchronized void putProtocolRule(RootProtocolRouteDraft.Override override) {
        if (override == null) {
            throw new IllegalArgumentException("Missing transport rule.");
        }
        List<RootProtocolRouteDraft.Override> existing =
                new ArrayList<>(protocolRules(override.packageName));
        for (int i = 0; i < existing.size(); i++) {
            RootProtocolRouteDraft.Override entry = existing.get(i);
            if (entry.transport == override.transport
                    && entry.destinationPort == override.destinationPort) {
                existing.remove(i);
                break;
            }
        }
        existing.add(override);
        saveProtocolRules(override.packageName,
                RootProtocolRouteDraft.validateAndSort(existing));
    }

    synchronized void removeProtocolRule(String packageName, int transport, int port) {
        List<RootProtocolRouteDraft.Override> remaining = new ArrayList<>();
        for (RootProtocolRouteDraft.Override rule : protocolRules(packageName)) {
            if (rule.transport != transport || rule.destinationPort != port) {
                remaining.add(rule);
            }
        }
        saveProtocolRules(packageName, remaining);
    }

    private void saveProtocolRules(String packageName,
            List<RootProtocolRouteDraft.Override> overrides) {
        if (!AppUseCategories.validPackageName(packageName)) {
            throw new IllegalArgumentException("Invalid app package.");
        }
        JSONObject json = read(PROTOCOLS);
        JSONArray rules = new JSONArray();
        try {
            for (RootProtocolRouteDraft.Override override : overrides) {
                JSONObject row = new JSONObject();
                row.put("transport", override.transport);
                row.put("destinationPort", override.destinationPort);
                row.put("tunnel", override.tunnelName);
                rules.put(row);
            }
            if (rules.length() == 0) json.remove(packageName);
            else json.put(packageName, rules);
        } catch (JSONException invalid) {
            throw new IllegalStateException("Unable to save protocol rule.");
        }
        int total = 0;
        java.util.Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            String pkg = keys.next();
            JSONArray rows = json.optJSONArray(pkg);
            if (!AppUseCategories.validPackageName(pkg) || rows == null) {
                throw new IllegalStateException("Saved protocol-rule group is invalid.");
            }
            total += rows.length();
            if (rows.length() > RootProtocolRouteDraft.MAX_OVERRIDES_PER_APP
                    || total > RootProtocolRouteDraft.MAX_OVERRIDES_TOTAL) {
                throw new IllegalArgumentException("Too many saved transport rules.");
            }
        }
        String encoded = json.toString();
        if (encoded.length() > MAX_STRING_BYTES) {
            throw new IllegalArgumentException("Transport rule storage is full.");
        }
        if (!prefs.edit().putString(PROTOCOLS, encoded).commit()) {
            throw new IllegalStateException("Unable to persist transport rules.");
        }
    }

    /** Global transport selectors → category, stored as app-private drafts. */
    synchronized List<RootCategoryProtocolRule.Rule> categoryProtocolRules() {
        JSONObject storage = read(CATEGORY_PROTOCOLS);
        JSONArray rows = storage.optJSONArray("rules");
        if (rows == null) {
            if (storage.has("rules")) {
                throw new IllegalStateException("Saved category protocol rules are invalid.");
            }
            return Collections.emptyList();
        }
        List<RootCategoryProtocolRule.Rule> out = new ArrayList<>();
        for (int i = 0; i < rows.length(); i++) {
            JSONObject entry = rows.optJSONObject(i);
            if (entry == null) {
                throw new IllegalStateException("Saved global protocol selector is invalid.");
            }
            out.add(new RootCategoryProtocolRule.Rule(
                    entry.optInt("transport", -1),
                    entry.optInt("destinationPort", -1),
                    entry.optInt("category", -1)));
        }
        return RootCategoryProtocolRule.validateAndSort(out);
    }

    synchronized void putCategoryProtocolRule(RootCategoryProtocolRule.Rule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("Missing category protocol selector.");
        }
        List<RootCategoryProtocolRule.Rule> chosen =
                new ArrayList<>(categoryProtocolRules());
        for (int i = 0; i < chosen.size(); i++) {
            RootCategoryProtocolRule.Rule previous = chosen.get(i);
            if (previous.transport == rule.transport
                    && previous.destinationPort == rule.destinationPort) {
                chosen.remove(i);
                break;
            }
        }
        chosen.add(rule);
        saveCategoryProtocolRules(RootCategoryProtocolRule.validateAndSort(chosen));
    }

    synchronized void removeCategoryProtocolRule(int protocol, int destinationPort) {
        List<RootCategoryProtocolRule.Rule> remaining = new ArrayList<>();
        for (RootCategoryProtocolRule.Rule rule : categoryProtocolRules()) {
            if (rule.transport != protocol || rule.destinationPort != destinationPort) {
                remaining.add(rule);
            }
        }
        saveCategoryProtocolRules(remaining);
    }

    private void saveCategoryProtocolRules(List<RootCategoryProtocolRule.Rule> rules) {
        List<RootCategoryProtocolRule.Rule> reviewed =
                RootCategoryProtocolRule.validateAndSort(rules);
        JSONArray values = new JSONArray();
        JSONObject document = new JSONObject();
        try {
            for (RootCategoryProtocolRule.Rule rule : reviewed) {
                JSONObject row = new JSONObject();
                row.put("transport", rule.transport);
                row.put("destinationPort", rule.destinationPort);
                row.put("category", rule.category);
                values.put(row);
            }
            document.put("rules", values);
        } catch (JSONException invalid) {
            throw new IllegalStateException("Unable to encode category protocol policy.");
        }
        String encoded = document.toString();
        if (encoded.length() > MAX_STRING_BYTES ||
                !prefs.edit().putString(CATEGORY_PROTOCOLS, encoded).commit()) {
            throw new IllegalStateException("Unable to persist category protocol policy.");
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
