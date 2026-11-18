package com.yooshastan.wonheeproxy;

/**
 * User-facing purpose labels for saved tunnel profiles.
 *
 * A category is metadata ONLY. It MUST NOT change AllowedIPs, routing, DNS,
 * firewall rules, app UIDs, WireGuard peers, country or public IP. Actual
 * routing always comes from validated WireGuard profile routes.
 */
final class TunnelUseCategories {
    static final int GENERAL = 0;
    static final int PRIVACY = 1;
    static final int REGIONAL = 2;
    static final int PRIVATE_NETWORK = 3;
    static final int WORK = 4;
    static final int MEDIA = 5;
    static final String[] LABELS = {
            "General Internet",
            "Privacy / everyday browsing",
            "Regional / local services",
            "Home & private network",
            "Work & trusted services",
            "Media & streaming"
    };

    private TunnelUseCategories() { }

    static boolean valid(int category) {
        return category >= GENERAL && category < LABELS.length;
    }

    static String label(int category) {
        return valid(category) ? LABELS[category] : LABELS[GENERAL];
    }

    static int migratedCategory(int legacyRole) {
        // Older installs have no category: never infer a country or claim
        // that a generic Internet exit was chosen for anonymity.
        return legacyRole == 1 ? PRIVATE_NETWORK : GENERAL;
    }

    static String routingLabel(int routeMode) {
        switch (routeMode) {
            case 1: return "Specific destinations";
            case 2: return "Full Internet exit — one active default";
            default: return "Imported WireGuard routes — review before combining";
        }
    }
}
