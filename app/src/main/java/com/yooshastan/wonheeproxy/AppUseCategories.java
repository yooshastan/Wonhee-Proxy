package com.yooshastan.wonheeproxy;

/**
 * User-controlled classification of apps by purpose.
 *
 * Category assignments are local planning metadata and DO NOT implement UID
 * routing, firewall enforcement, DNS isolation or anonymous identities.
 */
final class AppUseCategories {
    static final int EVERYDAY = 0;
    static final int PRIVATE = 1;
    static final int REGIONAL = 2;
    static final int FINANCE = 3;
    static final int HOME = 4;
    static final int WORK = 5;
    static final int MEDIA = 6;
    static final int SYSTEM = 7;
    static final String[] LABELS = {
            "Everyday",
            "Private",
            "Regional",
            "Finance",
            "Home",
            "Work",
            "Media",
            "System"
    };

    static final String[] EXPLANATIONS = {
            "Ordinary apps and browsing",
            "Private chats and privacy-sensitive browsing",
            "Regional shopping, ordering and local services",
            "Financial accounts and payments: keep a stable exit",
            "Private home services and trusted local devices",
            "Employer services and trusted business networks",
            "Streaming, downloads and entertainment",
            "Android and essential network services (later)"
    };

    private AppUseCategories() { }

    static boolean valid(int category) {
        return category >= EVERYDAY && category < LABELS.length;
    }

    static int safe(int category) {
        return valid(category) ? category : EVERYDAY;
    }

    static String label(int category) {
        return LABELS[safe(category)];
    }

    static boolean validPackageName(String packageName) {
        if (packageName == null || packageName.length() > 240) return false;
        return packageName.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+");
    }
}
