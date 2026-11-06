package com.yooshastan.wonheeproxy;

import java.util.HashSet;
import java.util.Set;

public final class RootDnsFirewallPlanTest {
    private static void require(boolean value) { if (!value) throw new AssertionError(); }

    public static void main(String[] ignored) {
        Set<String> tags = new HashSet<>();
        int v4Nat = 0, v6Drop = 0;
        for (RootDnsFirewallPlan.Rule rule : RootDnsFirewallPlan.rules()) {
            require(tags.add(rule.tag));
            require(rule.add().startsWith(rule.commandPrefix() + " -I OUTPUT "));
            require(rule.delete().startsWith(rule.commandPrefix() + " -D OUTPUT "));
            require(rule.exists().startsWith(rule.commandPrefix() + " -C OUTPUT "));
            require(rule.matchesListing("-A OUTPUT " + rule.args));
            require(rule.matchesListing("-A OUTPUT " + rule.args.replace(
                    rule.tag, "\"" + rule.tag + "\"")));
            require(!rule.matchesListing("-A OUTPUT " + rule.args.replace(rule.tag,
                    "SOMEONE_ELSE")));
            require(!rule.matchesListing("-A INPUT " + rule.args));
            if (rule.nat) {
                v4Nat++;
                require(!rule.ipv6 && rule.args.contains("--to-ports 53535"));
            }
            if (rule.ipv6) v6Drop++;
        }
        require(tags.size() == 8 && v4Nat == 2 && v6Drop == 4);
        require(RootDnsFirewallPlan.validIntent(RootDnsFirewallPlan.serializedIntent()));
        require(!RootDnsFirewallPlan.validIntent(""));
        System.out.println("RootDnsFirewallPlanTest passed");
    }
}
