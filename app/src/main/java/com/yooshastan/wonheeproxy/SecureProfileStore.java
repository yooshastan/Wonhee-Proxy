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
 * Explicitly saved proxy profiles. The entire JSON document is AES-256-GCM
 * encrypted with a non-exportable Android Keystore key before storage.
 * No plaintext fallback, cloud backup, logs, or background network access.
 */
public final class SecureProfileStore {
    public static final int MAX_PROFILES = 16;
    private static final String FILE = "wonhee_secure_profiles_v1";
    private static final String FIELD = "encrypted_profiles";
    private static final String KEY_ALIAS = "wonhee_proxy_profiles_aes_v1";
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    public static final class Profile {
        public final String name;
        public final String protocol;
        public final String mode;
        public final String publicHost;
        public final String lanHost;
        public final int port;
        public final String secret;
        public final String username;
        public final String password;

        public Profile(String name, String protocol, String mode,
                       String publicHost, String lanHost, int port,
                       String secret, String username, String password) {
            this.name = name == null ? "" : name.trim();
            this.protocol = protocol == null ? "" : protocol;
            this.mode = mode == null ? "" : mode;
            this.publicHost = publicHost == null ? "" : publicHost.trim();
            this.lanHost = lanHost == null ? "" : lanHost.trim();
            this.port = port;
            this.secret = secret == null ? "" : secret;
            this.username = username == null ? "" : username;
            this.password = password == null ? "" : password;
            if (this.name.isEmpty() || this.name.length() > 64
                    || this.name.chars().anyMatch(c -> Character.isISOControl((char) c))) {
                throw new IllegalArgumentException("Profile name must be 1–64 printable characters.");
            }
        }

        JSONObject toJson() throws Exception {
            JSONObject obj = new JSONObject();
            obj.put("name", name);
            obj.put("protocol", protocol);
            obj.put("mode", mode);
            obj.put("publicHost", publicHost);
            obj.put("lanHost", lanHost);
            obj.put("port", port);
            obj.put("secret", secret);
            obj.put("username", username);
            obj.put("password", password);
            return obj;
        }

        static Profile fromJson(JSONObject obj) throws Exception {
            return new Profile(obj.getString("name"), obj.getString("protocol"),
                    obj.getString("mode"), obj.getString("publicHost"),
                    obj.optString("lanHost", ""), obj.getInt("port"),
                    obj.optString("secret", ""), obj.optString("username", ""),
                    obj.optString("password", ""));
        }
    }

    private final SharedPreferences prefs;

    public SecureProfileStore(Context context) {
        prefs = context.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    public synchronized List<Profile> load() throws Exception {
        String wrapped = prefs.getString(FIELD, null);
        List<Profile> profiles = new ArrayList<>();
        if (wrapped == null) return profiles;
        byte[] bytes = Base64.decode(wrapped, Base64.NO_WRAP);
        if (bytes.length < 1 + IV_BYTES + 16 || bytes[0] != 1) {
            throw new IllegalStateException("Unsupported secure profile format");
        }
        byte[] iv = Arrays.copyOfRange(bytes, 1, 1 + IV_BYTES);
        byte[] sealed = Arrays.copyOfRange(bytes, 1 + IV_BYTES, bytes.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(GCM_TAG_BITS, iv));
        JSONObject document = new JSONObject(new String(
                cipher.doFinal(sealed), StandardCharsets.UTF_8));
        if (document.getInt("version") != 1) {
            throw new IllegalStateException("Unsupported secure profile version");
        }
        JSONArray list = document.getJSONArray("profiles");
        if (list.length() > MAX_PROFILES) {
            throw new IllegalStateException("Too many stored profiles");
        }
        for (int i = 0; i < list.length(); i++) {
            profiles.add(Profile.fromJson(list.getJSONObject(i)));
        }
        return profiles;
    }

    public synchronized void save(Profile profile) throws Exception {
        List<Profile> profiles = load();
        int index = -1;
        for (int i = 0; i < profiles.size(); i++) {
            if (profiles.get(i).name.equalsIgnoreCase(profile.name)) {
                index = i;
                break;
            }
        }
        if (index >= 0) {
            profiles.set(index, profile);
        } else {
            if (profiles.size() >= MAX_PROFILES) {
                throw new IllegalArgumentException("Maximum of 16 saved profiles reached.");
            }
            profiles.add(profile);
        }
        write(profiles);
    }

    public synchronized void delete(String name) throws Exception {
        List<Profile> profiles = load();
        boolean found = profiles.removeIf(p -> p.name.equalsIgnoreCase(name));
        if (!found) throw new IllegalArgumentException("Select a saved profile.");
        write(profiles);
    }

    private void write(List<Profile> profiles) throws Exception {
        JSONObject document = new JSONObject();
        document.put("version", 1);
        JSONArray list = new JSONArray();
        for (Profile item : profiles) list.put(item.toJson());
        document.put("profiles", list);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key());
        byte[] iv = cipher.getIV();
        if (iv == null || iv.length != IV_BYTES) {
            throw new IllegalStateException("Unsupported GCM IV size");
        }
        byte[] sealed = cipher.doFinal(document.toString()
                .getBytes(StandardCharsets.UTF_8));
        byte[] output = new byte[1 + IV_BYTES + sealed.length];
        output[0] = 1;
        System.arraycopy(iv, 0, output, 1, IV_BYTES);
        System.arraycopy(sealed, 0, output, 1 + IV_BYTES, sealed.length);
        if (!prefs.edit().putString(FIELD,
                Base64.encodeToString(output, Base64.NO_WRAP)).commit()) {
            throw new IllegalStateException("Encrypted profile could not be saved");
        }
    }

    private static SecretKey key() throws Exception {
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
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }
}
