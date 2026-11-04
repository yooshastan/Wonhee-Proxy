package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class TunnelProfileNamingTest {
    private static void eq(String expected, String actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected [" + expected + "] but got [" + actual + "]");
        }
    }

    public static void main(String[] args) {
        eq("AirVPN Amsterdam", TunnelProfileNaming.fromFilename("AirVPN Amsterdam.conf"));
        eq("HomeVPN", TunnelProfileNaming.fromFilename("folder/HomeVPN.CONF"));
        eq("WireGuard tunnel", TunnelProfileNaming.fromFilename(null));
        eq("WireGuard tunnel", TunnelProfileNaming.fromFilename("  .conf "));
        eq("Home VPN", TunnelProfileNaming.fromFilename("Home\nVPN.conf"));
        eq("AirVPN Amsterdam (2)", TunnelProfileNaming.unique("AirVPN Amsterdam.conf",
                Collections.singletonList("airvpn amsterdam")));
        eq("Home (3)", TunnelProfileNaming.unique("Home",
                Arrays.asList("Home", "Home (2)")));
        String sixtyFour = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB";
        if (sixtyFour.length() != 64) throw new AssertionError("Bad fixture.");
        eq(sixtyFour, TunnelProfileNaming.fromFilename(sixtyFour + ".conf"));
        String duplicateLong = TunnelProfileNaming.unique(sixtyFour,
                Collections.singletonList(sixtyFour));
        if (duplicateLong.length() > 64 || !duplicateLong.endsWith(" (2)")) {
            throw new AssertionError("Duplicate name exceeds length limit.");
        }
        System.out.println("PASS TunnelProfileNamingTest");
    }
}
