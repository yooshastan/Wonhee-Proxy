package com.yooshastan.wonheeproxy;

import java.util.Arrays;

public final class RootFailClosedFirewallPlanTest {
    private static void check(boolean ok, String message) {if (!ok) throw new AssertionError(message);}

    public static void main(String[] args) {
        RootFailClosedFirewallPlan.Tunnel home = new RootFailClosedFirewallPlan.Tunnel(
                "wnma292ddb4b6da", "192.0.2.1", 51820, 0x20000,
                Arrays.asList("10.0.0.0/24", "10.6.0.0/24", "10.77.0.0/24"));
        RootFailClosedFirewallPlan.Tunnel air = new RootFailClosedFirewallPlan.Tunnel(
                "wnm68fe81200daa", "2001:db8::1", 1637, 0x40000,
                Arrays.asList("0.0.0.0/0", "::/0"));
        RootFailClosedFirewallPlan.Plan plan = RootFailClosedFirewallPlan.build(Arrays.asList(home,air));
        String encoded = plan.encode();
        check(encoded.equals(RootFailClosedFirewallPlan.decode(encoded).encode()), "ledger roundtrip");
        check(encoded.contains("-d 10.0.0.0/24 ! -o wnma292ddb4b6da -j REJECT"), "home bypass guard");
        check(encoded.contains("--mark 0x20000/0xffffffff"), "exact transport exception");
        check(encoded.contains("--mark 0x40000/0xffffffff"), "IPv6 endpoint exception");
        check(plan.family(4).get(plan.family(4).size()-1).args.equals("-j REJECT"), "v4 deny");
        check(plan.family(6).get(plan.family(6).size()-1).args.equals("-j REJECT"), "v6 deny");
        check(!encoded.contains("-m mark -j RETURN"), "no broad mark allow");
        RootFailClosedFirewallPlan.Tunnel sharedMarkInternet = new RootFailClosedFirewallPlan.Tunnel(
                "wnm68fe81200daa", "2001:db8::1", 1637, 0x20000,
                Arrays.asList("0.0.0.0/0", "::/0"));
        RootFailClosedFirewallPlan.Plan sharedMarkPlan = RootFailClosedFirewallPlan.build(
                Arrays.asList(home, sharedMarkInternet));
        check(sharedMarkPlan.encode().contains("--mark 0x20000/0xffffffff"),
                "shared Android protected mark has exact endpoint-pinned rules");
        check(!sharedMarkPlan.encode().contains("-m mark -j RETURN"),
                "shared mark cannot be a broad underlay bypass");
        try {RootFailClosedFirewallPlan.build(Arrays.asList(home,
                new RootFailClosedFirewallPlan.Tunnel("wnm68fe81200daa", "192.0.2.1", 51820,
                        0x20000, Arrays.asList("0.0.0.0/0"))));
            throw new AssertionError("accepted identical shared-mark endpoint");}
        catch (IllegalArgumentException expected) { }
        try {RootFailClosedFirewallPlan.build(Arrays.asList(air,
                new RootFailClosedFirewallPlan.Tunnel("wnmfedcba987654", "192.0.2.2", 1637,
                        0x40000, Arrays.asList("10.99.0.0/16"))));
            throw new AssertionError("accepted shared non-Android mark");}
        catch (IllegalArgumentException expected) { }
        try {RootFailClosedFirewallPlan.decode("bad\n");throw new AssertionError("accepted unknown ledger");}
        catch (IllegalArgumentException expected) { }
        try {RootFailClosedFirewallPlan.build(Arrays.asList(home,home));throw new AssertionError("accepted duplicate");}
        catch (IllegalArgumentException expected) { }
        try {RootFailClosedFirewallPlan.decode(encoded.replace("-j REJECT",
                "-j ACCEPT"));throw new AssertionError("accepted unowned firewall grammar");}
        catch (IllegalArgumentException expected) { }
        try {RootFailClosedFirewallPlan.decode(encoded.replace("-j REJECT\n",
                "-j REJECT\n4|-o lo -j RETURN\n"));
            throw new AssertionError("accepted rules after a terminal reject");}
        catch (IllegalArgumentException expected) { }
        System.out.println("RootFailClosedFirewallPlanTest PASS");
    }
}
