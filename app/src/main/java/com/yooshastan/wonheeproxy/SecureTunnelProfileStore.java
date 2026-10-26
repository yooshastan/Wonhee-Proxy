package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * WireGuard profiles are sealed with AES-256-GCM and a non-exportable Android
 * Keystore key. A valid import is saved immediately; Save updates options.
 * No plaintext configuration, Android backup or profile telemetry is used.
 * The selected profile is remembered by index (no key or name in preferences).
 */
final class SecureTunnelProfileStore {
    static final int MAX_PROFILES = 8;
    static final int MAX_CONFIG_BYTES = 65536;
    private static final String FILE = "wonhee_vpn_profiles_v1";
    private static final String FIELD = "sealed_vpn_profiles";
    private static final String SELECTED_INDEX = "selected_profile_index";
    private static final String KEY_ALIAS = "wonhee_vpn_profiles_aes_v1";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private final SharedPreferences prefs;

    static final class Profile {
        final String name;
        final String configuration;
        final int routeMode;
        final String homeRoutes;
        final boolean homeDnsEnabled;
        final String homeDnsServer;

        Profile(String name, String configuration) {
            this(name, configuration, VpnRouteModes.PROFILE, "");
        }

        Profile(String name, String configuration, int routeMode, String homeRoutes) {
            this(name, configuration, routeMode, homeRoutes, false, "");
        }

        Profile(String name, String configuration, int routeMode, String homeRoutes,
                boolean homeDnsEnabled, String homeDnsServer) {
            this.name = name == null ? "" : name.trim();
            this.configuration = configuration == null ? "" : configuration;
            this.routeMode = routeMode;
            this.homeRoutes = homeRoutes == null ? "" : homeRoutes.trim();
            this.homeDnsEnabled = homeDnsEnabled;
            this.homeDnsServer = homeDnsServer == null ? "" : homeDnsServer.trim();
            if (this.homeDnsServer.length() > 45) {
                throw new IllegalArgumentException("Home DNS address is too long.");
            }
            if (routeMode < VpnRouteModes.PROFILE || routeMode > VpnRouteModes.ALL) {
                throw new IllegalArgumentException("Invalid VPN routing mode.");
            }
            if (this.homeRoutes.length() > 512) {
                throw new IllegalArgumentException("Home routes exceed 512 characters.");
            }
            if (this.name.isEmpty() || this.name.length() > 64
                    || this.name.chars().anyMatch(c -> Character.isISOControl((char) c))) {
                throw new IllegalArgumentException("Use a profile name of 1–64 printable characters.");
            }
            if (this.configuration.isEmpty()
                    || this.configuration.getBytes(StandardCharsets.UTF_8).length > MAX_CONFIG_BYTES) {
                throw new IllegalArgumentException("WireGuard configuration is empty or too large.");
            }
        }

        JSONObject asJson() throws Exception {
            JSONObject result = new JSONObject();
            result.put("name", name);
            result.put("configuration", configuration);
            result.put("routeMode", routeMode);
            result.put("homeRoutes", homeRoutes);
            result.put("homeDnsEnabled", homeDnsEnabled);
            result.put("homeDnsServer", homeDnsServer);
            return result;
        }

        static Profile fromJson(JSONObject value) throws Exception {
            // Alpha 0.5 profiles contain only name + config; migrate safely in place.
            return new Profile(value.getString("name"), value.getString("configuration"),
                    value.optInt("routeMode", VpnRouteModes.PROFILE),
                    value.optString("homeRoutes", ""),
                    value.optBoolean("homeDnsEnabled", false),
                    value.optString("homeDnsServer", ""));
        }
    }

    SecureTunnelProfileStore(Context context) {
        prefs = context.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    synchronized List<Profile> load() throws Exception {
        String stored = prefs.getString(FIELD, null);
        List<Profile> result = new ArrayList<>();
        if (stored == null) return result;
        if (stored.length() > 1024 * 1024) {
            throw new IllegalStateException("Encrypted profile data exceeds the limit.");
        }
        byte[] packet = Base64.decode(stored, Base64.NO_WRAP);
        if (packet.length < 1 + IV_BYTES + 16 || packet[0] != 1) {
            throw new IllegalStateException("Unsupported encrypted VPN profile format.");
        }
        byte[] iv = Arrays.copyOfRange(packet, 1, 1 + IV_BYTES);
        byte[] encrypted = Arrays.copyOfRange(packet, 1 + IV_BYTES, packet.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, getKey(), new GCMParameterSpec(TAG_BITS, iv));
        byte[] plaintext = cipher.doFinal(encrypted);
        try {
            JSONObject document = new JSONObject(new String(plaintext, StandardCharsets.UTF_8));
            if (document.getInt("version") != 1) {
                throw new IllegalStateException("Unsupported VPN profile document version.");
            }
            JSONArray profiles = document.getJSONArray("profiles");
            if (profiles.length() > MAX_PROFILES) {
                throw new IllegalStateException("Too many encrypted VPN profiles.");
            }
            for (int i = 0; i < profiles.length(); i++) {
                result.add(Profile.fromJson(profiles.getJSONObject(i)));
            }
            return result;
        } finally {
            Arrays.fill(plaintext, (byte) 0);
            Arrays.fill(encrypted, (byte) 0);
        }
    }

    synchronized int preferredIndex(int size) {
        if (size <= 0) return -1;
        int index = prefs.getInt(SELECTED_INDEX, 0);
        return index >= 0 && index < size ? index : 0;
    }

    synchronized void rememberSelectedIndex(int index) throws Exception {
        SharedPreferences.Editor edit = prefs.edit();
        if (index < 0) edit.remove(SELECTED_INDEX);
        else edit.putInt(SELECTED_INDEX, index);
        if (!edit.commit()) {
            throw new IllegalStateException("Selected VPN profile was not remembered.");
        }
    }

    synchronized void save(Profile updated) throws Exception {
        List<Profile> profiles = load(); // Decryption failure must NOT overwrite data.
        int replaceIndex = -1;
        for (int i = 0; i < profiles.size(); i++) {
            if (profiles.get(i).name.equalsIgnoreCase(updated.name)) {
                replaceIndex = i;
                break;
            }
        }
        if (replaceIndex >= 0) {
            profiles.set(replaceIndex, updated);
        } else {
            if (profiles.size() >= MAX_PROFILES) {
                throw new IllegalArgumentException("Maximum of 8 VPN profiles reached.");
            }
            profiles.add(updated);
        }
        write(profiles);
    }

    synchronized void delete(String name) throws Exception {
        List<Profile> profiles = load();
        int removed = -1;
        for (int i = 0; i < profiles.size(); i++) {
            if (profiles.get(i).name.equalsIgnoreCase(name)) {
                removed = i;
                break;
            }
        }
        if (removed < 0) throw new IllegalArgumentException("Choose an existing VPN profile.");
        int oldSelection = preferredIndex(profiles.size());
        profiles.remove(removed);
        write(profiles);
        int nextSelection = profiles.isEmpty() ? -1
                : oldSelection > removed ? oldSelection - 1
                : Math.min(oldSelection, profiles.size() - 1);
        rememberSelectedIndex(nextSelection);
    }

    private void write(List<Profile> profiles) throws Exception {
        JSONObject document = new JSONObject();
        document.put("version", 1);
        JSONArray items = new JSONArray();
        for (Profile profile : profiles) items.put(profile.asJson());
        document.put("profiles", items);
        byte[] cleartext = document.toString().getBytes(StandardCharsets.UTF_8);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, getKey());
            byte[] iv = cipher.getIV();
            if (iv == null || iv.length != IV_BYTES) {
                throw new IllegalStateException("Unexpected AES-GCM IV length.");
            }
            byte[] sealed = cipher.doFinal(cleartext);
            byte[] output = new byte[1 + IV_BYTES + sealed.length];
            output[0] = 1;
            System.arraycopy(iv, 0, output, 1, IV_BYTES);
            System.arraycopy(sealed, 0, output, 1 + IV_BYTES, sealed.length);
            if (!prefs.edit().putString(FIELD, Base64.encodeToString(output, Base64.NO_WRAP)).commit()) {
                throw new IllegalStateException("Encrypted VPN profiles were not saved.");
            }
            Arrays.fill(sealed, (byte) 0);
            Arrays.fill(output, (byte) 0);
        } finally {
            Arrays.fill(cleartext, (byte) 0);
        }
    }

    private static SecretKey getKey() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        SecretKey existing = (SecretKey) store.getKey(KEY_ALIAS, null);
        if (existing != null) return existing;
        KeyGenerator generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).build());
        return generator.generateKey();
    }
}
