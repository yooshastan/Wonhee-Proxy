package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class RootProtectionPolicyTest {
    private static void check(boolean yes, String message) {
        if (!yes) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry home = new RootMultiTunnelPlan.Entry("Home",
                Arrays.asList("10.0.0.0/24", "10.6.0.0/24", "10.77.0.0/24"),
                Collections.singletonList("10.88.0.2/32"));
        RootMultiTunnelPlan.Entry alternatePrivate = new RootMultiTunnelPlan.Entry("Research",
                Arrays.asList("172.20.0.0/16", "fd00:20::/64"),
                Collections.singletonList("172.31.100.1/32"));
        RootMultiTunnelPlan.Entry exit = new RootMultiTunnelPlan.Entry("AirVPNEurope",
                Arrays.asList("0.0.0.0/0", "::/0"),
                Arrays.asList("10.159.187.150/32", "fd7d:76ee::1/128"));
        List<RootMultiTunnelPlan.Entry> all = Arrays.asList(home, alternatePrivate, exit);
        RootMultiTunnelPlan.validate(all);
        check(home.device.equals(RootProtectionPolicy.expectedDevice(all, "10.0.0.169")),
                "Navidrome must use Home, not the default VPN");
        check(home.device.equals(RootProtectionPolicy.expectedDevice(all, "10.77.0.1")),
                "Home DNS must remain inside Home");
        check(alternatePrivate.device.equals(RootProtectionPolicy.expectedDevice(all, "172.20.9.4")),
                "A third private tunnel must not assume the fixed Home/AirVPN pair");
        check(alternatePrivate.device.equals(RootProtectionPolicy.expectedDevice(all, "fd00:20::53")),
                "IPv6 private routes must also use longest-prefix expectations");
        check(exit.device.equals(RootProtectionPolicy.expectedDevice(all, "1.1.1.1")),
                "Public IPv4 must use the default exit");
        check(exit.device.equals(RootProtectionPolicy.expectedDevice(all,
                "2606:4700:4700::1111")), "Public IPv6 must use the default exit");
        check(RootProtectionPolicy.expectedDevice(all, "malicious.domain.example").isEmpty(),
                "No hostname resolution in root audit preflight");
        check(RootProtectionPolicy.hasInternetDefault(all, 4), "IPv4 default expected");
        check(RootProtectionPolicy.hasInternetDefault(all, 6), "IPv6 default expected");
        check(!RootProtectionPolicy.hasInternetDefault(
                Collections.singletonList(home), 6), "No IPv6 default means no safety claim");
        check(RootProtectionPolicy.expectedDevice(
                Collections.singletonList(home), "1.1.1.1").isEmpty(),
                "Never invent an Internet route when a split-only profile is selected");
        System.out.println("RootProtectionPolicyTest passed");
    }
}
