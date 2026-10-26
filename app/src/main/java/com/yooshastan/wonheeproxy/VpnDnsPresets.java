package com.yooshastan.wonheeproxy;

/** Preset addresses only; DNS is transported inside the configured WireGuard tunnel. */
final class VpnDnsPresets {
    static final int IMPORTED = 0;
    static final int CLOUDFLARE = 1;
    static final int QUAD9 = 2;
    static final int ADGUARD = 3;
    static final int GOOGLE = 4;
    static final int CUSTOM = 5;

    static final String[] LABELS = {
            "Use imported profile DNS",
            "Cloudflare (1.1.1.1)",
            "Quad9 (malware filtering)",
            "AdGuard (ads and trackers)",
            "Google Public DNS",
            "Custom DNS addresses"
    };

    private static final String[] ADDRESSES = {
            "",
            "1.1.1.1, 1.0.0.1",
            "9.9.9.9, 149.112.112.112",
            "94.140.14.14, 94.140.15.15",
            "8.8.8.8, 8.8.4.4",
            ""
    };

    private VpnDnsPresets() { }

    static boolean isOverride(int choice) {
        return choice > IMPORTED && choice <= CUSTOM;
    }

    static String addresses(int choice, String custom) {
        if (choice < IMPORTED || choice > CUSTOM) {
            throw new IllegalArgumentException("Choose a valid DNS preset.");
        }
        return choice == CUSTOM ? (custom == null ? "" : custom.trim()) : ADDRESSES[choice];
    }

    /** Old single-IP custom values remain custom instead of silently gaining a backup. */
    static int choiceForSaved(boolean enabled, String stored) {
        if (!enabled) return IMPORTED;
        String address = stored == null ? "" : stored.trim();
        for (int i = CLOUDFLARE; i <= GOOGLE; i++) {
            if (ADDRESSES[i].equals(address)) return i;
        }
        return CUSTOM;
    }
}
