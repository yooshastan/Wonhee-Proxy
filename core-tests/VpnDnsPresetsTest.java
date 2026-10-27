package com.yooshastan.wonheeproxy;

public final class VpnDnsPresetsTest {
    private static void check(boolean value, String reason) {
        if (!value) throw new AssertionError(reason);
    }

    public static void main(String[] args) {
        check(!VpnDnsPresets.isOverride(VpnDnsPresets.IMPORTED), "imported DNS must be unchanged");
        check(VpnDnsPresets.addresses(VpnDnsPresets.CLOUDFLARE, "").equals(
                "1.1.1.1, 1.0.0.1"), "Cloudflare addresses");
        check(VpnDnsPresets.addresses(VpnDnsPresets.QUAD9, "").equals(
                "9.9.9.9, 149.112.112.112"), "Quad9 addresses");
        check(VpnDnsPresets.addresses(VpnDnsPresets.ADGUARD, "").equals(
                "94.140.14.14, 94.140.15.15"), "AdGuard addresses");
        check(VpnDnsPresets.addresses(VpnDnsPresets.GOOGLE, "").equals(
                "8.8.8.8, 8.8.4.4"), "Google addresses");
        check(VpnDnsPresets.addresses(VpnDnsPresets.CUSTOM, " 10.77.0.1 ").equals(
                "10.77.0.1"), "custom address trim");
        check(VpnDnsPresets.choiceForSaved(true, "1.1.1.1, 1.0.0.1")
                == VpnDnsPresets.CLOUDFLARE, "preset restores");
        check(VpnDnsPresets.choiceForSaved(true, "1.1.1.1")
                == VpnDnsPresets.CUSTOM, "old single-IP choice stays custom");
        check(VpnDnsPresets.choiceForSaved(false, "1.1.1.1")
                == VpnDnsPresets.IMPORTED, "disabled setting stays disabled");
        try {
            VpnDnsPresets.addresses(99, "");
            throw new AssertionError("invalid preset accepted");
        } catch (IllegalArgumentException expected) { }
        System.out.println("Wonhee DNS preset mapping passed");
    }
}
